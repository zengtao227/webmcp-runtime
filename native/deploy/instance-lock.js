import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';

export class InstanceLockError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'InstanceLockError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new InstanceLockError(message, code, options);
}

function lockOwnerAlive(pid, killImpl = process.kill) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    killImpl(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    if (error?.code === 'EPERM') return true;
    return null;
  }
}

function parseLockOwner(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail('Instance lifecycle lock is unreadable; refusing to guess ownership.', 'INSTANCE_LOCK_UNVERIFIED', { cause: error });
  }
  const keys = Object.keys(value ?? {}).sort();
  const validLegacyShape = JSON.stringify(keys) === JSON.stringify(['createdAt', 'pid']);
  const validCurrentShape = JSON.stringify(keys) === JSON.stringify(['createdAt', 'generation', 'pid']);
  if (
    (!validLegacyShape && !validCurrentShape)
    || !Number.isSafeInteger(value.pid)
    || value.pid <= 0
    || typeof value.createdAt !== 'string'
    || Number.isNaN(Date.parse(value.createdAt))
    || (validCurrentShape && (typeof value.generation !== 'string' || !/^[0-9a-f]{32}$/i.test(value.generation)))
  ) {
    fail('Instance lifecycle lock has an invalid shape.', 'INSTANCE_LOCK_UNVERIFIED');
  }
  const generation = validCurrentShape
    ? value.generation
    : createHash('sha256').update(text).digest('hex').slice(0, 32);
  return Object.freeze({ ...value, generation, text });
}

function parseReclaimContender(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail('Instance lifecycle reclaim contender is unreadable.', 'INSTANCE_LOCK_UNVERIFIED', { cause: error });
  }
  const keys = Object.keys(value ?? {}).sort();
  if (
    JSON.stringify(keys) !== JSON.stringify(['createdAt', 'lockGeneration', 'pid', 'token'])
    || !Number.isSafeInteger(value.pid)
    || value.pid <= 0
    || typeof value.createdAt !== 'string'
    || Number.isNaN(Date.parse(value.createdAt))
    || typeof value.lockGeneration !== 'string'
    || !/^[0-9a-f]{32}$/i.test(value.lockGeneration)
    || typeof value.token !== 'string'
    || !/^[0-9a-f]{32}$/i.test(value.token)
  ) {
    fail('Instance lifecycle reclaim contender has an invalid shape.', 'INSTANCE_LOCK_UNVERIFIED');
  }
  return Object.freeze(value);
}

async function reclaimStaleLock(filePath, {
  killImpl = process.kill,
  openImpl = open,
  mkdirImpl = mkdir,
  rmImpl = rm,
} = {}) {
  let owner;
  try {
    owner = parseLockOwner(await readFile(filePath, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
  const alive = lockOwnerAlive(owner.pid, killImpl);
  if (alive === null) fail('Instance lifecycle lock owner cannot be verified.', 'INSTANCE_LOCK_UNVERIFIED');
  if (alive) return false;

  const contenderDirectory = `${filePath}.reclaim`;
  await mkdirImpl(contenderDirectory, { recursive: true, mode: 0o700 });
  const token = randomBytes(16).toString('hex');
  const stagingPath = path.join(contenderDirectory, `${token}.tmp`);
  const contenderPath = path.join(contenderDirectory, `${token}.json`);
  try {
    const contenderHandle = await openImpl(stagingPath, 'wx', 0o600);
    try {
      await contenderHandle.writeFile(`${JSON.stringify({
        pid: process.pid,
        createdAt: new Date().toISOString(),
        lockGeneration: owner.generation,
        token,
      })}\n`, 'utf8');
    } finally {
      await contenderHandle.close().catch(() => {});
    }
    // Publish only a complete record. A crashed writer may leave a .tmp file,
    // but it cannot enter the election or block later stale-lock recovery.
    await rename(stagingPath, contenderPath);
  } catch (error) {
    await rmImpl(stagingPath, { force: true }).catch(() => {});
    throw error;
  }

  try {
    const liveContenders = [];
    for (const name of await readdir(contenderDirectory)) {
      if (/^[0-9a-f]{32}\.tmp$/i.test(name)) continue;
      if (!/^[0-9a-f]{32}\.json$/i.test(name)) {
        fail('Instance lifecycle reclaim directory contains an unexpected entry.', 'INSTANCE_LOCK_UNVERIFIED');
      }
      const candidatePath = path.join(contenderDirectory, name);
      let candidate;
      try {
        candidate = parseReclaimContender(await readFile(candidatePath, 'utf8'));
      } catch (error) {
        if (error?.code === 'ENOENT') continue;
        throw error;
      }
      if (`${candidate.token}.json` !== name) {
        fail('Instance lifecycle reclaim contender identity does not match its path.', 'INSTANCE_LOCK_UNVERIFIED');
      }
      const candidateAlive = lockOwnerAlive(candidate.pid, killImpl);
      if (candidateAlive === null) {
        fail('Instance lifecycle reclaim contender owner cannot be verified.', 'INSTANCE_LOCK_UNVERIFIED');
      }
      if (!candidateAlive) {
        await rmImpl(candidatePath, { force: true }).catch(() => {});
        continue;
      }
      liveContenders.push(candidate);
    }

    const winner = liveContenders
      .filter((candidate) => candidate.lockGeneration === owner.generation)
      .sort((left, right) => left.token.localeCompare(right.token))[0];
    if (!winner || winner.token !== token) return false;
    if (liveContenders.some((candidate) => candidate.lockGeneration !== owner.generation)) return false;

    let current;
    try {
      current = parseLockOwner(await readFile(filePath, 'utf8'));
    } catch (error) {
      if (error?.code === 'ENOENT') return true;
      throw error;
    }
    if (current.generation !== owner.generation) return false;
    const stillAlive = lockOwnerAlive(current.pid, killImpl);
    if (stillAlive === null) fail('Instance lifecycle lock owner cannot be verified.', 'INSTANCE_LOCK_UNVERIFIED');
    if (stillAlive) return false;
    try {
      await rmImpl(filePath);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    return true;
  } finally {
    await rmImpl(contenderPath, { force: true }).catch(() => {});
  }
}

export async function withInstanceLifecycleLock(context, operation, {
  openImpl = open,
  mkdirImpl = mkdir,
  rmImpl = rm,
  killImpl = process.kill,
} = {}) {
  if (!context || typeof context.lifecycleLock !== 'string' || !path.isAbsolute(context.lifecycleLock)) {
    fail('Instance lifecycle lock requires a trusted instance context.', 'INVALID_INSTANCE_LOCK_CONTEXT');
  }
  if (typeof operation !== 'function') fail('Instance lifecycle operation is required.', 'INVALID_INSTANCE_LOCK_OPERATION');

  await mkdirImpl(path.dirname(context.lifecycleLock), { recursive: true, mode: 0o700 });

  let handle;
  const generation = randomBytes(16).toString('hex');
  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        handle = await openImpl(context.lifecycleLock, 'wx', 0o600);
        break;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        const reclaimed = await reclaimStaleLock(context.lifecycleLock, {
          killImpl,
          openImpl,
          mkdirImpl,
          rmImpl,
        });
        if (!reclaimed) fail('Instance lifecycle is already being changed.', 'INSTANCE_BUSY');
      }
    }
    if (!handle) fail('Instance lifecycle is already being changed.', 'INSTANCE_BUSY');
    await handle.writeFile(`${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString(), generation })}\n`, 'utf8');
  } catch (error) {
    if (handle) {
      await handle.close().catch(() => {});
      await rmImpl(context.lifecycleLock, { force: true }).catch(() => {});
    }
    if (error instanceof InstanceLockError) throw error;
    fail('Unable to acquire the instance lifecycle lock.', 'INSTANCE_LOCK_FAILED', { cause: error });
  }

  try {
    return await operation();
  } finally {
    await handle.close().catch(() => {});
    try {
      const current = parseLockOwner(await readFile(context.lifecycleLock, 'utf8'));
      if (current.pid === process.pid && current.generation === generation) {
        await rmImpl(context.lifecycleLock, { force: true }).catch(() => {});
      }
    } catch (error) {
      if (error?.code !== 'ENOENT' && !(error instanceof InstanceLockError)) throw error;
    }
  }
}
