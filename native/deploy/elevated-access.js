import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { normalizeWorkspaceConfig } from './workspace-config.js';

const execFileAsync = promisify(execFile);

// The one lease WebMCP grants is Host Access (High Trust): it authorizes host_command and never
// changes the container. Version 1 leases (Full Working Access, removed) no longer parse.
export const HOST_ACCESS_LEASE_VERSION = 2;
export const FULL_HOST_ACCESS_LEVEL = 'full-host';
export const MAX_ELEVATED_LEASE_MS = 60 * 60 * 1000;
const LEASE_ID_PATTERN = /^[0-9a-f]{64}$/;
const INSTANCE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;

export class ElevatedAccessError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'ElevatedAccessError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new ElevatedAccessError(message, code, options);
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail(`Elevated lease contains unsupported key: ${key}`, 'INVALID_ELEVATED_LEASE');
    }
  }
}

export function defaultElevatedLeasePath(home = os.homedir()) {
  return path.join(home, '.local', 'share', 'webmcp', 'elevated-lease.json');
}

export function parseElevatedDuration(value = '60m') {
  if (typeof value !== 'string') {
    fail('Elevated duration must be expressed as minutes or hours, for example 30m or 1h.', 'INVALID_ELEVATED_DURATION');
  }
  const match = /^(\d+)(m|h)$/.exec(value.trim());
  if (!match) {
    fail('Elevated duration must be expressed as minutes or hours, for example 30m or 1h.', 'INVALID_ELEVATED_DURATION');
  }
  const amount = Number(match[1]);
  const durationMs = amount * (match[2] === 'h' ? 60 * 60 * 1000 : 60 * 1000);
  if (!Number.isSafeInteger(durationMs) || durationMs <= 0 || durationMs > MAX_ELEVATED_LEASE_MS) {
    fail('Elevated duration must be greater than zero and no longer than 1 hour.', 'INVALID_ELEVATED_DURATION');
  }
  return durationMs;
}

export async function getBootSessionId({
  platform = process.platform,
  execFileImpl = execFileAsync,
} = {}) {
  if (platform !== 'darwin') {
    fail('Temporary elevated access is currently supported only on macOS.', 'UNSUPPORTED_ELEVATION_PLATFORM');
  }
  let stdout;
  try {
    ({ stdout } = await execFileImpl('sysctl', ['-n', 'kern.boottime'], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
    }));
  } catch (error) {
    fail('Unable to determine the current macOS boot session.', 'BOOT_SESSION_UNAVAILABLE', { cause: error });
  }
  const match = /sec\s*=\s*(\d+)\s*,\s*usec\s*=\s*(\d+)/.exec(String(stdout));
  if (!match) {
    fail('macOS returned an unrecognized boot-session value.', 'BOOT_SESSION_UNAVAILABLE');
  }
  return createHash('sha256').update(`darwin:${match[1]}:${match[2]}`).digest('hex');
}

export async function getLoginSessionId({
  platform = process.platform,
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  execFileImpl = execFileAsync,
} = {}) {
  if (platform !== 'darwin' || !Number.isInteger(uid) || uid <= 0) {
    fail('Temporary elevated access requires a normal macOS GUI user session.', 'LOGIN_SESSION_UNAVAILABLE');
  }
  let stdout;
  try {
    ({ stdout } = await execFileImpl('launchctl', ['print', `gui/${uid}`], {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    }));
  } catch (error) {
    fail('Unable to inspect the current macOS GUI login session.', 'LOGIN_SESSION_UNAVAILABLE', { cause: error });
  }
  const asids = new Set([...String(stdout).matchAll(/\basid\s*=\s*(\d+)\b/g)].map((match) => match[1]));
  if (asids.size !== 1) {
    fail('macOS returned an unrecognized GUI login-session identity.', 'LOGIN_SESSION_UNAVAILABLE');
  }
  return createHash('sha256').update(`darwin-login:${uid}:${[...asids][0]}`).digest('hex');
}

export function createElevatedLease({
  normalConfig,
  elevatedRoot,
  bootSessionId,
  loginSessionId,
  durationMs = MAX_ELEVATED_LEASE_MS,
  now = Date.now(),
  leaseId = randomBytes(32).toString('hex'),
  platform = process.platform,
  instanceId = 'default',
} = {}) {
  const normalizedNormal = normalizeWorkspaceConfig(normalConfig, { platform });
  if (typeof elevatedRoot !== 'string' || !path.isAbsolute(elevatedRoot) || elevatedRoot.includes('\0')) {
    fail('Host Access lease root is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  if (typeof bootSessionId !== 'string' || !LEASE_ID_PATTERN.test(bootSessionId)) {
    fail('Boot-session identity is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  if (typeof loginSessionId !== 'string' || !LEASE_ID_PATTERN.test(loginSessionId)) {
    fail('Login-session identity is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  if (!LEASE_ID_PATTERN.test(leaseId)) {
    fail('Elevated lease identity is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  if (!Number.isSafeInteger(now) || now <= 0) {
    fail('Elevated lease issue time is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  if (!Number.isSafeInteger(durationMs) || durationMs <= 0 || durationMs > MAX_ELEVATED_LEASE_MS) {
    fail('Elevated lease lifetime must be greater than zero and no longer than 1 hour.', 'INVALID_ELEVATED_DURATION');
  }
  if (!INSTANCE_ID_PATTERN.test(instanceId)) {
    fail('Full Host lease instance identity is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  return Object.freeze({
    version: HOST_ACCESS_LEASE_VERSION,
    accessLevel: FULL_HOST_ACCESS_LEVEL,
    instanceId,
    id: leaseId,
    bootSessionId,
    loginSessionId,
    normalRoot: normalizedNormal.hostRoot,
    elevatedRoot: path.resolve(elevatedRoot),
    issuedAt: now,
    expiresAt: now + durationMs,
  });
}

export function parseElevatedLease(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail('Elevated lease is not valid JSON.', 'INVALID_ELEVATED_LEASE', { cause: error });
  }
  if (!isPlainObject(value)) {
    fail('Elevated lease must be an object.', 'INVALID_ELEVATED_LEASE');
  }
  assertExactKeys(value, new Set([
    'version',
    'accessLevel',
    'instanceId',
    'id',
    'bootSessionId',
    'loginSessionId',
    'normalRoot',
    'elevatedRoot',
    'issuedAt',
    'expiresAt',
  ]));
  if (
    value.version !== HOST_ACCESS_LEASE_VERSION
    || value.accessLevel !== FULL_HOST_ACCESS_LEVEL
    || typeof value.instanceId !== 'string' || !INSTANCE_ID_PATTERN.test(value.instanceId)
    || !LEASE_ID_PATTERN.test(value.id ?? '')
    || !LEASE_ID_PATTERN.test(value.bootSessionId ?? '')
    || !LEASE_ID_PATTERN.test(value.loginSessionId ?? '')
  ) {
    fail('Elevated lease identity/version is invalid.', 'INVALID_ELEVATED_LEASE');
  }
  for (const key of ['normalRoot', 'elevatedRoot']) {
    if (typeof value[key] !== 'string' || !path.isAbsolute(value[key]) || value[key].includes('\0')) {
      fail(`Elevated lease ${key} is invalid.`, 'INVALID_ELEVATED_LEASE');
    }
  }
  for (const key of ['issuedAt', 'expiresAt']) {
    if (!Number.isSafeInteger(value[key]) || value[key] <= 0) {
      fail(`Elevated lease ${key} is invalid.`, 'INVALID_ELEVATED_LEASE');
    }
  }
  if (
    value.expiresAt <= value.issuedAt
    || value.expiresAt - value.issuedAt > MAX_ELEVATED_LEASE_MS
  ) {
    fail('Elevated lease time bounds are invalid.', 'INVALID_ELEVATED_LEASE');
  }
  return Object.freeze({ ...value });
}

export function evaluateElevatedLease(lease, {
  normalConfig,
  bootSessionId,
  loginSessionId,
  now = Date.now(),
  platform = process.platform,
  instanceId = 'default',
} = {}) {
  let normalizedNormal;
  try {
    normalizedNormal = normalizeWorkspaceConfig(normalConfig, { platform });
  } catch (error) {
    return Object.freeze({ state: 'invalid', reason: error.message });
  }
  if (lease.bootSessionId !== bootSessionId) {
    return Object.freeze({ state: 'rebooted', reason: 'Elevated lease belongs to a different boot session.' });
  }
  if (lease.loginSessionId !== loginSessionId) {
    return Object.freeze({ state: 'login_restarted', reason: 'Elevated lease belongs to a different GUI login session.' });
  }
  if (lease.normalRoot !== normalizedNormal.hostRoot) {
    return Object.freeze({ state: 'config_changed', reason: 'Normal workspace root changed after lease creation.' });
  }
  if (lease.instanceId !== instanceId) {
    return Object.freeze({ state: 'instance_changed', reason: 'Full Host lease belongs to another WebMCP instance.' });
  }
  if (!Number.isSafeInteger(now) || now < lease.issuedAt) {
    return Object.freeze({ state: 'invalid', reason: 'Current time is inconsistent with the lease issue time.' });
  }
  if (now >= lease.expiresAt) {
    return Object.freeze({ state: 'expired', reason: 'Elevated lease reached its absolute expiry.' });
  }
  return Object.freeze({ state: 'active', lease });
}

async function assertLeaseFile(filePath) {
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o600) {
    fail('Elevated lease file must be a regular mode-0600 file.', 'INVALID_ELEVATED_LEASE_FILE');
  }
}

export async function loadElevatedLease(filePath, options = {}) {
  try {
    await assertLeaseFile(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return Object.freeze({ state: 'absent' });
    }
    if (error instanceof ElevatedAccessError) {
      return Object.freeze({ state: 'invalid', reason: error.message });
    }
    return Object.freeze({ state: 'invalid', reason: 'Elevated lease file cannot be inspected.' });
  }
  let lease;
  try {
    lease = parseElevatedLease(await readFile(filePath, 'utf8'));
  } catch (error) {
    return Object.freeze({ state: 'invalid', reason: error.message });
  }
  return evaluateElevatedLease(lease, options);
}

export async function persistElevatedLease(filePath, lease) {
  parseElevatedLease(JSON.stringify(lease));
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(directory, `.${path.basename(filePath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(lease, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(temporary, filePath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    fail('Unable to persist elevated lease state.', 'ELEVATED_LEASE_WRITE_FAILED', { cause: error });
  }
  return lease;
}

export async function clearElevatedLease(filePath) {
  await rm(filePath, { force: true });
}

export function elevatedLeasePublicStatus(state, { now = Date.now() } = {}) {
  if (state.state !== 'active') {
    return Object.freeze({ mode: 'normal', leaseState: state.state, ...(state.reason ? { reason: state.reason } : {}) });
  }
  return Object.freeze({
    mode: 'elevated',
    accessLevel: state.lease.accessLevel,
    selectedRoot: state.lease.elevatedRoot,
    expiresAt: new Date(state.lease.expiresAt).toISOString(),
    remainingMs: Math.max(0, state.lease.expiresAt - now),
    maxDurationMs: MAX_ELEVATED_LEASE_MS,
  });
}
