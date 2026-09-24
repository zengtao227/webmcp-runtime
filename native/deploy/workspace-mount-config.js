import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ownerHome, protectedHomePaths } from './control-plane-paths.js';
import {
  buildControlPlaneMaskPlan,
  buildWorkspaceMountArgs,
  canonicalizeHostRoot,
} from './workspace-config.js';

export const WORKSPACE_MOUNT_CONFIG_VERSION = 1;
export const CONTAINER_MOUNTS_ROOT = '/workspace/mounts';

const MOUNT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,47}$/;

export class WorkspaceMountConfigError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'WorkspaceMountConfigError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new WorkspaceMountConfigError(message, code, options);
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail(`${label} contains unsupported key: ${key}`, 'INVALID_WORKSPACE_MOUNT_CONFIG');
    }
  }
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function resolveFuturePath(candidate) {
  let ancestor = candidate;
  while (true) {
    try {
      return path.join(await realpath(ancestor), path.relative(ancestor, candidate));
    } catch (error) {
      if (error?.code !== 'ENOENT' || ancestor === path.dirname(ancestor)) throw error;
      ancestor = path.dirname(ancestor);
    }
  }
}

export function workspaceMountContainerPath(id) {
  if (typeof id !== 'string' || !MOUNT_ID_PATTERN.test(id)) {
    fail('Mounted folder id is invalid.', 'INVALID_WORKSPACE_MOUNT_ID');
  }
  return `${CONTAINER_MOUNTS_ROOT}/${id}`;
}

export function normalizeWorkspaceMount(value) {
  if (!isPlainObject(value)) {
    fail('Mounted folder must be an object.', 'INVALID_WORKSPACE_MOUNT');
  }
  assertExactKeys(value, new Set(['id', 'hostPath', 'writeEnabled', 'containerPath']), 'Mounted folder');

  if (typeof value.id !== 'string' || !MOUNT_ID_PATTERN.test(value.id)) {
    fail('Mounted folder id must contain only lowercase letters, digits and hyphens.', 'INVALID_WORKSPACE_MOUNT_ID');
  }
  if (
    typeof value.hostPath !== 'string'
    || value.hostPath.length === 0
    || !path.isAbsolute(value.hostPath)
    || value.hostPath.includes('\0')
  ) {
    fail('Mounted folder hostPath must be a non-empty absolute path.', 'INVALID_WORKSPACE_MOUNT_PATH');
  }

  const writeEnabled = value.writeEnabled ?? false;
  if (typeof writeEnabled !== 'boolean') {
    fail('Mounted folder writeEnabled must be boolean.', 'INVALID_WORKSPACE_MOUNT_WRITE_POLICY');
  }
  const containerPath = workspaceMountContainerPath(value.id);
  if (value.containerPath !== undefined && value.containerPath !== containerPath) {
    fail('Mounted folder containerPath must match its stable id-derived path.', 'INVALID_WORKSPACE_MOUNT_DESTINATION');
  }

  return Object.freeze({
    id: value.id,
    hostPath: path.resolve(value.hostPath),
    writeEnabled,
    containerPath,
  });
}

export function normalizeWorkspaceMountConfig(value) {
  if (!isPlainObject(value)) {
    fail('Workspace mount config must be an object.', 'INVALID_WORKSPACE_MOUNT_CONFIG');
  }
  assertExactKeys(value, new Set(['version', 'mounts']), 'Workspace mount config');
  if (value.version !== WORKSPACE_MOUNT_CONFIG_VERSION) {
    fail(
      `Workspace mount config version must be ${WORKSPACE_MOUNT_CONFIG_VERSION}.`,
      'INVALID_WORKSPACE_MOUNT_CONFIG',
    );
  }
  if (!Array.isArray(value.mounts)) {
    fail('Workspace mount config mounts must be an array.', 'INVALID_WORKSPACE_MOUNT_CONFIG');
  }

  const mounts = value.mounts.map(normalizeWorkspaceMount);
  const ids = new Set();
  for (const mount of mounts) {
    if (ids.has(mount.id)) {
      fail(`Mounted folder id is duplicated: ${mount.id}`, 'DUPLICATE_WORKSPACE_MOUNT_ID');
    }
    ids.add(mount.id);
  }

  return Object.freeze({
    version: WORKSPACE_MOUNT_CONFIG_VERSION,
    mounts: Object.freeze(mounts),
  });
}

export async function loadWorkspaceMountConfig(configPath) {
  let text;
  try {
    text = await readFile(configPath, 'utf8');
  } catch (error) {
    fail(`Unable to read workspace mount config: ${configPath}`, 'WORKSPACE_MOUNT_CONFIG_UNAVAILABLE', { cause: error });
  }
  try {
    return normalizeWorkspaceMountConfig(JSON.parse(text));
  } catch (error) {
    if (error instanceof WorkspaceMountConfigError) throw error;
    fail('Workspace mount config is not valid JSON.', 'INVALID_WORKSPACE_MOUNT_CONFIG', { cause: error });
  }
}

export async function persistWorkspaceMountConfig(configPath, value) {
  const normalized = normalizeWorkspaceMountConfig(value);
  const directory = path.dirname(configPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    directory,
    `.${path.basename(configPath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temporary, configPath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    fail(`Unable to persist workspace mount config: ${configPath}`, 'WORKSPACE_MOUNT_CONFIG_WRITE_FAILED', { cause: error });
  }
  return normalized;
}

export async function canonicalizeWorkspaceMountConfig(value, {
  platform = process.platform,
  home = ownerHome(),
  canonicalizeHostRootImpl = canonicalizeHostRoot,
} = {}) {
  const normalized = normalizeWorkspaceMountConfig(value);
  const mounts = [];
  const canonicalHome = await realpath(home);

  for (const mount of normalized.mounts) {
    let canonical;
    try {
      canonical = await canonicalizeHostRootImpl(mount.hostPath, { platform });
    } catch (error) {
      if (error instanceof WorkspaceMountConfigError) throw error;
      fail(
        `Mounted folder cannot be resolved: ${mount.hostPath}`,
        'INVALID_WORKSPACE_MOUNT_PATH',
        { cause: error },
      );
    }
    if (isWithin(canonical, canonicalHome)) {
      fail('Mounted folders cannot contain the owner home directory.', 'SENSITIVE_WORKSPACE_MOUNT');
    }
    for (const candidate of protectedHomePaths({ home: canonicalHome, platform })) {
      const sensitive = await resolveFuturePath(candidate);
      if (isWithin(canonical, sensitive) || isWithin(sensitive, canonical)) {
        fail(`Mounted folder overlaps protected host state: ${candidate}`, 'SENSITIVE_WORKSPACE_MOUNT');
      }
    }
    mounts.push(Object.freeze({
      ...mount,
      hostPath: canonical,
    }));
  }

  for (let left = 0; left < mounts.length; left += 1) {
    for (let right = left + 1; right < mounts.length; right += 1) {
      const a = mounts[left];
      const b = mounts[right];
      if (isWithin(a.hostPath, b.hostPath) || isWithin(b.hostPath, a.hostPath)) {
        fail(
          `Mounted folders must not duplicate or overlap: ${a.id} and ${b.id}`,
          'WORKSPACE_MOUNT_OVERLAP',
        );
      }
    }
  }

  return Object.freeze({
    version: WORKSPACE_MOUNT_CONFIG_VERSION,
    mounts: Object.freeze(mounts),
  });
}

export function workspaceMountIdForPath(hostPath) {
  if (typeof hostPath !== 'string' || !path.isAbsolute(hostPath)) {
    fail('Mounted folder path must be absolute before deriving its id.', 'INVALID_WORKSPACE_MOUNT_PATH');
  }
  const basename = path.basename(path.resolve(hostPath))
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 28) || 'mount';
  const suffix = createHash('sha256').update(path.resolve(hostPath)).digest('hex').slice(0, 12);
  return `${basename}-${suffix}`;
}

export async function addWorkspaceMount(config, { hostPath, platform = process.platform, home = ownerHome() } = {}) {
  const current = normalizeWorkspaceMountConfig(config);
  const canonicalPath = await canonicalizeHostRoot(hostPath, { platform });
  const id = workspaceMountIdForPath(canonicalPath);
  const next = {
    version: WORKSPACE_MOUNT_CONFIG_VERSION,
    mounts: [
      ...current.mounts,
      { id, hostPath: canonicalPath, writeEnabled: false },
    ],
  };
  return canonicalizeWorkspaceMountConfig(next, { platform, home });
}

export function removeWorkspaceMount(config, id) {
  const current = normalizeWorkspaceMountConfig(config);
  const nextMounts = current.mounts.filter((mount) => mount.id !== id);
  if (nextMounts.length === current.mounts.length) {
    fail(`Mounted folder does not exist: ${id}`, 'WORKSPACE_MOUNT_NOT_FOUND');
  }
  return normalizeWorkspaceMountConfig({
    version: WORKSPACE_MOUNT_CONFIG_VERSION,
    mounts: nextMounts,
  });
}

export function setWorkspaceMountWrite(config, id, writeEnabled) {
  if (typeof writeEnabled !== 'boolean') {
    fail('writeEnabled must be boolean.', 'INVALID_WORKSPACE_MOUNT_WRITE_POLICY');
  }
  const current = normalizeWorkspaceMountConfig(config);
  let found = false;
  const mounts = current.mounts.map((mount) => {
    if (mount.id !== id) return mount;
    found = true;
    return { ...mount, writeEnabled };
  });
  if (!found) {
    fail(`Mounted folder does not exist: ${id}`, 'WORKSPACE_MOUNT_NOT_FOUND');
  }
  return normalizeWorkspaceMountConfig({ version: WORKSPACE_MOUNT_CONFIG_VERSION, mounts });
}

export function narrowsWorkspaceWriteAuthority(previousConfig, nextConfig) {
  const previous = normalizeWorkspaceMountConfig(previousConfig);
  const next = normalizeWorkspaceMountConfig(nextConfig);
  const nextById = new Map(next.mounts.map((mount) => [mount.id, mount]));
  return previous.mounts.some((mount) => {
    if (!mount.writeEnabled) return false;
    const candidate = nextById.get(mount.id);
    return !candidate
      || candidate.hostPath !== mount.hostPath
      || candidate.containerPath !== mount.containerPath
      || candidate.writeEnabled !== true;
  });
}

export function buildWorkspaceMountSetArgs(mountConfig) {
  const normalized = normalizeWorkspaceMountConfig(mountConfig);
  return Object.freeze(normalized.mounts.flatMap((mount) => buildWorkspaceMountArgs(
    mount.hostPath,
    {
      destination: mount.containerPath,
      readOnly: !mount.writeEnabled,
    },
  )));
}

export async function buildWorkspaceMountMaskPlan({
  mountConfig,
  protectedPaths = [],
} = {}) {
  const normalized = normalizeWorkspaceMountConfig(mountConfig);
  const plan = [];

  for (const mount of normalized.mounts) {
    const legacyPlan = await buildControlPlaneMaskPlan({
      hostRoot: mount.hostPath,
      protectedPaths,
    });
    for (const item of legacyPlan) {
      const relative = item.destination.slice('/workspace'.length);
      plan.push(Object.freeze({
        ...item,
        mountId: mount.id,
        destination: `${mount.containerPath}${relative}`,
      }));
    }
  }

  return Object.freeze(plan);
}

export function migrateLegacyWorkspaceConfig(value, { mountId } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Legacy workspace config is required.', 'INVALID_LEGACY_WORKSPACE_CONFIG');
  }
  if (typeof value.hostRoot !== 'string' || !path.isAbsolute(value.hostRoot)) {
    fail('Legacy workspace config requires an absolute hostRoot.', 'INVALID_LEGACY_WORKSPACE_CONFIG');
  }
  if (typeof value.readOnly !== 'boolean') {
    fail('Legacy workspace config requires an explicit readOnly state.', 'INVALID_LEGACY_WORKSPACE_CONFIG');
  }

  return normalizeWorkspaceMountConfig({
    version: WORKSPACE_MOUNT_CONFIG_VERSION,
    mounts: [{
      id: mountId,
      hostPath: value.hostRoot,
      writeEnabled: !value.readOnly,
    }],
  });
}
