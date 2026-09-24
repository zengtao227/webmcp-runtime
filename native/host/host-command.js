import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, lstat, stat } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getBootSessionId,
  getLoginSessionId,
  loadElevatedLease,
} from '../deploy/elevated-access.js';
import { loadWorkspaceConfig } from '../deploy/workspace-config.js';

const MAX_COMMAND_BYTES = 16 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_COMMAND_MS = 300 * 1000;
const SESSION_ID_PATTERN = /^[0-9a-f]{24}$/;
const SESSION_WORKER = fileURLToPath(new URL('./host-command-session-worker.js', import.meta.url));

export const HOST_COMMAND_TOOL = Object.freeze({
  name: 'host_command',
  description: 'Run or manage a command on the real Mac as the current user. Use action=start for a tracked background command, then action=read or cancel with its sessionId. Requires locally approved Temporary Full Host Access — High Trust. Unlike bash, this is not Docker-isolated.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      command: { type: 'string', minLength: 1, maxLength: MAX_COMMAND_BYTES },
      workingDirectory: { type: 'string' },
      timeout: { type: 'number', exclusiveMinimum: 0, maximum: 300 },
      action: { type: 'string', enum: ['run', 'start', 'read', 'cancel'] },
      sessionId: { type: 'string', pattern: '^[0-9a-f]{24}$' },
      stdoutOffset: { type: 'integer', minimum: 0 },
      stderrOffset: { type: 'integer', minimum: 0 },
    },
  },
});

function result(payload, isError = false) {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
    ...(isError ? { isError: true } : {}),
  };
}

function validateArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Arguments must be an object.');
  if (Object.keys(args).some((key) => !['action', 'command', 'workingDirectory', 'timeout', 'sessionId', 'stdoutOffset', 'stderrOffset'].includes(key))) {
    throw new Error('Unsupported host command argument.');
  }
  const action = args.action ?? 'run';
  if (!['run', 'start', 'read', 'cancel'].includes(action)) throw new Error('Unsupported host command action.');
  if (action === 'read' || action === 'cancel') {
    if (!SESSION_ID_PATTERN.test(args.sessionId ?? '') || Object.keys(args).some((key) => !['action', 'sessionId', 'stdoutOffset', 'stderrOffset'].includes(key))) {
      throw new Error('Session action requires only a valid sessionId and optional output offsets.');
    }
    if (action === 'cancel' && (args.stdoutOffset !== undefined || args.stderrOffset !== undefined)) throw new Error('Cancel does not accept output offsets.');
    for (const offset of [args.stdoutOffset, args.stderrOffset]) {
      if (offset !== undefined && (!Number.isSafeInteger(offset) || offset < 0 || offset > MAX_OUTPUT_BYTES)) throw new Error('Invalid output offset.');
    }
    return action;
  }
  if (args.sessionId !== undefined || args.stdoutOffset !== undefined || args.stderrOffset !== undefined) throw new Error('Command action cannot select a session.');
  if (typeof args.command !== 'string' || !args.command.trim() || Buffer.byteLength(args.command) > MAX_COMMAND_BYTES || args.command.includes('\0')) {
    throw new Error('Host command must contain 1–16384 UTF-8 bytes and no NUL.');
  }
  if (args.workingDirectory !== undefined && (typeof args.workingDirectory !== 'string' || !path.isAbsolute(args.workingDirectory) || args.workingDirectory.includes('\0'))) {
    throw new Error('Host working directory must be an absolute path.');
  }
  if (args.timeout !== undefined && (typeof args.timeout !== 'number' || !Number.isFinite(args.timeout) || args.timeout <= 0 || args.timeout > 300)) {
    throw new Error('Host timeout must be greater than zero and at most 300 seconds.');
  }
  return action;
}

async function sessionDirectory(leasePath) {
  const directory = path.join(path.dirname(leasePath), 'host-commands');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || info.uid !== process.getuid()) {
    throw new Error('Host command session directory is not owner-private.');
  }
  return directory;
}

function sessionSocket(directory, sessionId) {
  return path.join(directory, `${sessionId}.sock`);
}

function sessionRequest(socketPath, message, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks = [];
    let bytes = 0;
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error('Host command session did not respond.')));
    socket.on('connect', () => socket.write(`${JSON.stringify(message)}\n`));
    socket.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES * 2 + 4096) socket.destroy(new Error('Host command session response is too large.'));
      else chunks.push(chunk);
    });
    socket.on('error', reject);
    socket.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Invalid host command session response.')); }
    });
  });
}

async function startSession({ leasePath, configPath, home, instanceId, lease, args }) {
  const directory = await sessionDirectory(leasePath);
  const sessionId = randomBytes(12).toString('hex');
  const socketPath = sessionSocket(directory, sessionId);
  if (Buffer.byteLength(socketPath) > 100) throw new Error('Host command session path is too long for a Unix socket.');
  // A separate lease-bound worker survives a provider connection ending.
  // It is not a service: it exits at lease expiry and owns exactly one command.
  const child = spawn(process.execPath, [SESSION_WORKER], {
    detached: true,
    stdio: ['pipe', 'pipe', 'ignore'],
    env: hostEnvironment(home),
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout.destroy();
      child.stdin.destroy();
      child.unref();
      if (error) reject(error);
      else resolve({ sessionId, running: true, stdout: '', stderr: '', stdoutOffset: 0, stderrOffset: 0 });
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(new Error('Host command session failed to start.')); }, 5000);
    child.on('error', (error) => finish(error));
    child.on('exit', () => finish(new Error('Host command session exited before ready.')));
    child.stdout.once('data', (chunk) => {
      if (chunk.toString('utf8') !== 'READY\n') {
        child.kill('SIGKILL');
        finish(new Error('Host command session returned invalid readiness.'));
      } else finish();
    });
    child.stdin.end(`${JSON.stringify({ socketPath, leasePath, configPath, home, instanceId, leaseId: lease.id, expiresAt: lease.expiresAt, args })}\n`);
  });
}

function hostEnvironment(home) {
  return {
    HOME: home,
    USER: os.userInfo().username,
    LOGNAME: os.userInfo().username,
    PATH: process.env.PATH ?? '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: process.env.LANG ?? 'en_US.UTF-8',
    TMPDIR: process.env.TMPDIR ?? '/tmp',
  };
}

export function createHostCommandHandler({
  leasePath,
  configPath,
  expectedLeaseId = null,
  instanceId = 'default',
  home = os.homedir(),
  platform = process.platform,
  spawnImpl = spawn,
  pollMs = 250,
  getBootSessionIdImpl = getBootSessionId,
  getLoginSessionIdImpl = getLoginSessionId,
} = {}) {
  const active = new Map();
  const stopping = new WeakMap();
  let sessionPromise = null;
  let busy = false;

  function terminate(child) {
    if (!child || !Number.isInteger(child.pid) || stopping.has(child)) return;
    try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill?.('SIGTERM'); }
    const force = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill?.('SIGKILL'); }
    }, 1500);
    force.unref?.();
    stopping.set(child, force);
  }

  async function verifiedLease() {
    if (platform !== 'darwin' || expectedLeaseId === null) return null;
    sessionPromise ??= Promise.all([
      getBootSessionIdImpl({ platform }),
      getLoginSessionIdImpl({ platform }),
    ]);
    const [normalConfig, [bootSessionId, loginSessionId]] = await Promise.all([
      loadWorkspaceConfig(configPath, { platform }),
      sessionPromise,
    ]);
    const state = await loadElevatedLease(leasePath, { normalConfig, bootSessionId, loginSessionId, platform, instanceId });
    if (state.state !== 'active' || state.lease.id !== expectedLeaseId || state.lease.accessLevel !== 'full-host') return null;
    return state.lease;
  }

  async function run(args, { onOutput = null } = {}) {
    let action;
    try { action = validateArgs(args); } catch (error) {
      return result({ error: 'INVALID_HOST_COMMAND', message: error.message }, true);
    }
    let lease;
    try { lease = await verifiedLease(); } catch { lease = null; }
    if (!lease) return result({ error: 'HOST_ACCESS_NOT_GRANTED', message: 'Temporary Full Host Access is not verified for this instance.' }, true);

    if (action === 'read' || action === 'cancel') {
      try {
        const directory = await sessionDirectory(leasePath);
        const payload = await sessionRequest(sessionSocket(directory, args.sessionId), {
          action, leaseId: lease.id,
          stdoutOffset: args.stdoutOffset ?? 0,
          stderrOffset: args.stderrOffset ?? 0,
        });
        if (payload.leaseId !== lease.id) throw new Error('Session belongs to another lease.');
        delete payload.leaseId;
        return result(payload, Boolean(payload.error));
      } catch {
        return result({ error: 'HOST_SESSION_UNAVAILABLE', message: 'Tracked host command session is unavailable.' }, true);
      }
    }

    const cwd = args.workingDirectory ?? home;
    try {
      const info = await stat(cwd);
      if (!info.isDirectory()) throw new Error('not a directory');
    } catch {
      return result({ error: 'INVALID_HOST_DIRECTORY', message: 'Host working directory is unavailable.' }, true);
    }

    const requestedMs = Math.ceil((args.timeout ?? 300) * 1000);
    const timeoutMs = Math.min(requestedMs, MAX_COMMAND_MS, lease.expiresAt - Date.now());
    if (timeoutMs <= 0) return result({ error: 'HOST_ACCESS_EXPIRED', message: 'Full Host Access expired before command start.' }, true);

    if (action === 'start') {
      try {
        return result(await startSession({ leasePath, configPath, home, instanceId, lease, args: { command: args.command, workingDirectory: cwd, timeout: timeoutMs / 1000 } }));
      } catch {
        return result({ error: 'HOST_COMMAND_START_FAILED', message: 'Unable to start tracked host command.' }, true);
      }
    }

    return new Promise((resolve) => {
      let child;
      try {
        child = spawnImpl('/bin/bash', ['--noprofile', '--norc', '-c', args.command], {
          cwd,
          env: hostEnvironment(home),
          stdio: ['ignore', 'pipe', 'pipe'],
          detached: true,
        });
      } catch {
        resolve(result({ error: 'HOST_COMMAND_START_FAILED', message: 'Unable to start host command.' }, true));
        return;
      }

      const stdout = [];
      const stderr = [];
      let bytes = 0;
      let failure = null;
      let settled = false;
      const stop = (reason) => {
        if (failure === null) failure = reason;
        terminate(child);
      };
      active.set(child, stop);
      const deadline = setTimeout(() => stop('HOST_COMMAND_TIMEOUT'), timeoutMs);
      const poll = setInterval(() => {
        void verifiedLease().then((current) => {
          if (!current || current.id !== lease.id) stop('HOST_ACCESS_REVOKED');
        }).catch(() => stop('HOST_ACCESS_UNVERIFIED'));
      }, pollMs);
      const append = (target, chunk) => {
        bytes += chunk.byteLength;
        if (bytes > MAX_OUTPUT_BYTES) {
          stop('HOST_OUTPUT_TOO_LARGE');
          return;
        }
        target.push(Buffer.from(chunk));
        onOutput?.(target === stdout ? 'stdout' : 'stderr', Buffer.from(chunk));
      };
      child.stdout.on('data', (chunk) => append(stdout, chunk));
      child.stderr.on('data', (chunk) => append(stderr, chunk));
      child.on('error', () => { failure = 'HOST_COMMAND_START_FAILED'; });
      child.on('close', (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        clearInterval(poll);
        clearTimeout(stopping.get(child));
        active.delete(child);
        resolve(result({
          exitCode: code,
          signal,
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          ...(failure ? { error: failure } : {}),
        }, Boolean(failure) || code !== 0));
      });
    });
  }

  return {
    currentLease: verifiedLease,
    async call(args, options) {
      if (busy) return result({ error: 'HOST_COMMAND_BUSY', message: 'A host command is already running for this instance.' }, true);
      busy = true;
      try { return await run(args, options); } finally { busy = false; }
    },
    cancelAll(reason = 'HOST_COMMAND_CANCELLED') { for (const stop of active.values()) stop(reason); },
  };
}
