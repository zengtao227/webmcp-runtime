import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createElevatedLease, persistElevatedLease, clearElevatedLease, getBootSessionId, getLoginSessionId } from '../native/deploy/elevated-access.js';
import { persistWorkspaceConfig } from '../native/deploy/workspace-config.js';
import { createHostCommandHandler } from '../native/host/host-command.js';

const BOOT = 'b'.repeat(64);
const LOGIN = 'c'.repeat(64);

// `legacyVersion1` writes the old Full Working Access lease (version 1, no accessLevel), which
// createElevatedLease no longer produces.
async function fixture({ legacyVersion1 = false, durationMs = 60_000 } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-host-command-'));
  const configPath = path.join(root, 'workspace.json');
  const leasePath = path.join(root, 'lease.json');
  const normalConfig = await persistWorkspaceConfig(configPath, {
    version: 1,
    hostRoot: root,
    mode: 'workspace',
  }, { platform: 'darwin' });
  const lease = createElevatedLease({
    normalConfig,
    elevatedRoot: root,
    bootSessionId: BOOT,
    loginSessionId: LOGIN,
    durationMs,
    platform: 'darwin',
  });
  if (legacyVersion1) {
    const { accessLevel: _level, instanceId: _instance, ...rest } = lease;
    await writeFile(leasePath, JSON.stringify({ ...rest, version: 1 }), { mode: 0o600 });
  } else {
    await persistElevatedLease(leasePath, lease);
  }
  const handler = createHostCommandHandler({
    leasePath,
    configPath,
    expectedLeaseId: lease.id,
    home: root,
    platform: 'darwin',
    pollMs: 50,
    getBootSessionIdImpl: async () => BOOT,
    getLoginSessionIdImpl: async () => LOGIN,
  });
  return { root, configPath, leasePath, lease, handler, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test('host command refuses normal and legacy Docker-only grants', async () => {
  const legacy = await fixture({ legacyVersion1: true });
  try {
    const denied = await legacy.handler.call({ command: 'echo forbidden' });
    assert.equal(denied.structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
  } finally { await legacy.cleanup(); }

  const host = await fixture();
  try {
    await clearElevatedLease(host.leasePath);
    const denied = await host.handler.call({ command: 'echo forbidden' });
    assert.equal(denied.structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
  } finally { await host.cleanup(); }
});

test('approved host command executes as the current user and revoke stops the tracked foreground group', async () => {
  const host = await fixture();
  try {
    const target = path.join(host.root, 'result.txt');
    const done = await host.handler.call({ command: `printf approved > ${JSON.stringify(target)} && id -un`, workingDirectory: host.root });
    assert.equal(done.structuredContent.exitCode, 0);
    assert.match(done.structuredContent.stdout, new RegExp(os.userInfo().username));
    assert.equal(done.isError, undefined);

    const running = host.handler.call({ command: 'sleep 30', timeout: 30 });
    await new Promise((resolve) => setTimeout(resolve, 150));
    const concurrent = await host.handler.call({ command: 'echo should-not-run' });
    assert.equal(concurrent.structuredContent.error, 'HOST_COMMAND_BUSY');
    await clearElevatedLease(host.leasePath);
    const stopped = await running;
    assert.equal(stopped.structuredContent.error, 'HOST_ACCESS_REVOKED');
  } finally { host.handler.cancelAll(); await host.cleanup(); }
});

test('wrong-instance lease identity, expired lease, and malformed arguments never spawn host work', async () => {
  const host = await fixture();
  try {
    const wrongInstance = createHostCommandHandler({
      leasePath: host.leasePath,
      configPath: host.configPath,
      expectedLeaseId: 'f'.repeat(64),
      home: host.root,
      platform: 'darwin',
      getBootSessionIdImpl: async () => BOOT,
      getLoginSessionIdImpl: async () => LOGIN,
    });
    assert.equal((await wrongInstance.call({ command: 'pwd' })).structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
    const wrongName = createHostCommandHandler({
      leasePath: host.leasePath,
      configPath: host.configPath,
      expectedLeaseId: host.lease.id,
      instanceId: 'adapter',
      home: host.root,
      platform: 'darwin',
      getBootSessionIdImpl: async () => BOOT,
      getLoginSessionIdImpl: async () => LOGIN,
    });
    assert.equal((await wrongName.call({ command: 'pwd' })).structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
    assert.equal((await host.handler.call({ command: 'pwd', timeout: 301 })).structuredContent.error, 'INVALID_HOST_COMMAND');
    assert.equal((await host.handler.call({ command: 'pwd', workingDirectory: 'relative' })).structuredContent.error, 'INVALID_HOST_COMMAND');
    assert.equal((await host.handler.call({ command: 'pwd', instanceId: 'default' })).structuredContent.error, 'INVALID_HOST_COMMAND');
    await clearElevatedLease(host.leasePath);
    assert.equal((await host.handler.call({ command: 'pwd' })).structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
  } finally { await host.cleanup(); }
});

test('cancelling an active foreground host command returns a bounded cancellation result', async () => {
  const host = await fixture();
  try {
    const running = host.handler.call({ command: 'sleep 30', timeout: 30 });
    await new Promise((resolve) => setTimeout(resolve, 100));
    host.handler.cancelAll();
    const cancelled = await running;
    assert.equal(cancelled.structuredContent.error, 'HOST_COMMAND_CANCELLED');
    assert.equal(cancelled.isError, true);
  } finally { host.handler.cancelAll(); await host.cleanup(); }
});

test('tracked background command survives a one-shot caller, yields incremental output, and can be cancelled', { skip: process.platform !== 'darwin' }, async () => {
  const root = await mkdtemp('/tmp/webmcp-host-session-');
  const configPath = path.join(root, 'workspace.json');
  const leasePath = path.join(root, 'lease.json');
  try {
    const normalConfig = await persistWorkspaceConfig(configPath, { version: 1, hostRoot: root, mode: 'workspace' }, { platform: 'darwin' });
    const lease = createElevatedLease({
      normalConfig, elevatedRoot: root,
      bootSessionId: await getBootSessionId(),
      loginSessionId: await getLoginSessionId(),
      durationMs: 60_000, accessLevel: 'full-host', platform: 'darwin',
    });
    await persistElevatedLease(leasePath, lease);
    const makeHandler = () => createHostCommandHandler({ leasePath, configPath, expectedLeaseId: lease.id, home: root, platform: 'darwin' });
    const started = await makeHandler().call({ action: 'start', command: 'printf first; sleep 30', timeout: 30 });
    assert.equal(started.isError, undefined, JSON.stringify(started.structuredContent));
    const sessionId = started.structuredContent.sessionId;
    let observed;
    for (let i = 0; i < 30; i += 1) {
      observed = await makeHandler().call({ action: 'read', sessionId });
      if (observed.structuredContent.stdout.includes('first')) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(observed.structuredContent.stdout, 'first');
    assert.equal(observed.structuredContent.running, true);
    const offset = observed.structuredContent.stdoutOffset;
    const cancelled = await makeHandler().call({ action: 'cancel', sessionId });
    assert.equal(cancelled.isError, undefined, JSON.stringify(cancelled.structuredContent));
    let finished;
    for (let i = 0; i < 30; i += 1) {
      finished = await makeHandler().call({ action: 'read', sessionId, stdoutOffset: offset });
      if (!finished.structuredContent.running) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(finished.structuredContent.running, false);
    assert.equal(finished.structuredContent.error, 'HOST_COMMAND_CANCELLED');
    const chunked = await makeHandler().call({ action: 'start', command: "printf '%070000d' 0", timeout: 5 });
    assert.equal(chunked.isError, undefined);
    let firstChunk;
    for (let i = 0; i < 30; i += 1) {
      firstChunk = await makeHandler().call({ action: 'read', sessionId: chunked.structuredContent.sessionId });
      if (firstChunk.structuredContent.hasMoreOutput) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(firstChunk.structuredContent.stdout.length, 32 * 1024);
    assert.equal(firstChunk.structuredContent.hasMoreOutput, true);
    const secondChunk = await makeHandler().call({ action: 'read', sessionId: chunked.structuredContent.sessionId, stdoutOffset: firstChunk.structuredContent.stdoutOffset });
    assert.equal(secondChunk.structuredContent.stdout.length, 32 * 1024);
    const marker = path.join(root, 'should-not-appear');
    const next = await makeHandler().call({ action: 'start', command: `sleep 0.5; printf escaped > ${JSON.stringify(marker)}`, timeout: 5 });
    assert.equal(next.isError, undefined);
    await clearElevatedLease(leasePath);
    assert.equal((await makeHandler().call({ action: 'read', sessionId })).structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
    await new Promise((resolve) => setTimeout(resolve, 750));
    assert.equal(await stat(marker).then(() => true, () => false), false);

    const expiring = createElevatedLease({
      normalConfig, elevatedRoot: root,
      bootSessionId: lease.bootSessionId, loginSessionId: lease.loginSessionId,
      durationMs: 1000, accessLevel: 'full-host', platform: 'darwin',
    });
    await persistElevatedLease(leasePath, expiring);
    const expiryHandler = createHostCommandHandler({ leasePath, configPath, expectedLeaseId: expiring.id, home: root, platform: 'darwin' });
    const expiryMarker = path.join(root, 'should-not-appear-after-expiry');
    const expiringCall = await expiryHandler.call({ action: 'start', command: `sleep 1.5; printf escaped > ${JSON.stringify(expiryMarker)}`, timeout: 2 });
    assert.equal(expiringCall.isError, undefined);
    await new Promise((resolve) => setTimeout(resolve, 1800));
    assert.equal(await stat(expiryMarker).then(() => true, () => false), false);
    assert.equal((await expiryHandler.call({ action: 'read', sessionId: expiringCall.structuredContent.sessionId })).structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('lease expiry stops a running host command', async () => {
  const host = await fixture({ durationMs: 1500 });
  try {
    const started = Date.now();
    const stopped = await host.handler.call({ command: 'sleep 30', timeout: 30 });
    assert.ok(Date.now() - started < 10_000, 'the command must not outlive the lease');
    assert.ok(['HOST_COMMAND_TIMEOUT', 'HOST_ACCESS_REVOKED'].includes(stopped.structuredContent.error), JSON.stringify(stopped.structuredContent));
    const after = await host.handler.call({ command: 'echo late' });
    assert.equal(after.structuredContent.error, 'HOST_ACCESS_NOT_GRANTED');
  } finally { host.handler.cancelAll(); await host.cleanup(); }
});
