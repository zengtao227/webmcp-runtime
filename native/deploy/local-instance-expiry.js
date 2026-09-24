#!/usr/bin/env node
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createInstanceContext, normalizeInstanceId } from './instance-context.js';

const LEASE_ID_PATTERN = /^[0-9a-f]{64}$/;
const WORKER_PATH = fileURLToPath(import.meta.url);

function fail(message, code = 'INVALID_LOCAL_EXPIRY_ARGUMENTS') {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export function parseLocalExpiryWorkerArgs(argv) {
  const options = {};
  const allowed = new Set(['--instance', '--home', '--lease-id', '--expires-at']);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!allowed.has(arg)) fail(`Unknown local expiry option: ${arg}`);
    index += 1;
    if (index >= argv.length) fail(`Missing value for ${arg}`);
    const value = argv[index];
    if (arg === '--instance') options.instanceId = normalizeInstanceId(value);
    else if (arg === '--home') options.home = value;
    else if (arg === '--lease-id') options.leaseId = value;
    else if (arg === '--expires-at') options.expiresAt = Number(value);
  }
  if (!options.instanceId || options.instanceId === 'default') fail('Expiry worker requires a non-default instance.');
  if (typeof options.home !== 'string' || !path.isAbsolute(options.home) || options.home.includes('\0')) fail('Expiry worker home must be absolute.');
  if (!LEASE_ID_PATTERN.test(options.leaseId ?? '')) fail('Expiry worker lease id is invalid.');
  if (!Number.isSafeInteger(options.expiresAt) || options.expiresAt <= 0) fail('Expiry worker deadline is invalid.');
  return Object.freeze(options);
}

export function armLocalInstanceExpiry({
  context,
  lease,
  spawnImpl = spawn,
  execPath = process.execPath,
  workerPath = WORKER_PATH,
} = {}) {
  if (!context || context.isDefault !== false || typeof context.instanceId !== 'string') {
    fail('Expiry worker requires a trusted non-default instance context.', 'INVALID_LOCAL_EXPIRY_CONTEXT');
  }
  if (!lease || !LEASE_ID_PATTERN.test(lease.id ?? '') || !Number.isSafeInteger(lease.expiresAt) || lease.expiresAt <= 0) {
    fail('Expiry worker requires a valid elevated lease.', 'INVALID_LOCAL_EXPIRY_LEASE');
  }
  const child = spawnImpl(execPath, [
    workerPath,
    '--instance', context.instanceId,
    '--home', context.home,
    '--lease-id', lease.id,
    '--expires-at', String(lease.expiresAt),
  ], {
    detached: true,
    stdio: 'ignore',
    env: process.env,
  });
  if (!child || typeof child.unref !== 'function') {
    fail('Unable to start the local expiry worker.', 'LOCAL_EXPIRY_WORKER_START_FAILED');
  }
  child.unref();
  return Object.freeze({ armed: true, pid: Number.isInteger(child.pid) ? child.pid : null });
}

export async function waitUntil(deadline, { now = Date.now, setTimeoutImpl = setTimeout } = {}) {
  for (;;) {
    const remaining = deadline - now();
    if (remaining <= 0) return;
    await new Promise((resolve) => setTimeoutImpl(resolve, remaining));
  }
}

export async function runLocalExpiryWorker(options, {
  now = Date.now,
  setTimeoutImpl = setTimeout,
  revokeImpl = null,
} = {}) {
  await waitUntil(options.expiresAt, { now, setTimeoutImpl });
  const context = createInstanceContext({ instanceId: options.instanceId, home: options.home });
  const revoke = revokeImpl ?? (await import('./local-instance-controller.js')).revokeLocalInstanceAccess;
  return revoke({ context, expectedLeaseId: options.leaseId });
}

const invoked = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invoked === pathToFileURL(WORKER_PATH).href) {
  void (async () => {
    const options = parseLocalExpiryWorkerArgs(process.argv.slice(2));
    await runLocalExpiryWorker(options);
  })().catch((error) => {
    process.stderr.write(`WebMCP local expiry worker failed [${error?.code ?? 'UNEXPECTED_LOCAL_EXPIRY_ERROR'}]: ${error.message}\n`);
    process.exitCode = 1;
  });
}
