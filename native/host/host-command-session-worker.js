#!/usr/bin/env node
import net from 'node:net';
import { chmod, lstat, unlink } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { createHostCommandHandler } from './host-command.js';

const MAX_OUTPUT_BYTES = 256 * 1024;
const READ_CHUNK_CHARS = 32 * 1024;

async function readInitialization() {
  return new Promise((resolve, reject) => {
    let text = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      text += chunk;
      if (text.length > 20_000) reject(new Error('Oversized session initialization.'));
    });
    process.stdin.on('end', () => {
      try { resolve(JSON.parse(text)); } catch (error) { reject(error); }
    });
    process.stdin.on('error', reject);
  });
}

const init = await readInitialization();
const handler = createHostCommandHandler({
  leasePath: init.leasePath,
  configPath: init.configPath,
  expectedLeaseId: init.leaseId,
  instanceId: init.instanceId,
  home: init.home,
});
const lease = await handler.currentLease();
if (!lease || lease.id !== init.leaseId || init.expiresAt !== lease.expiresAt) process.exit(1);

let stdout = '';
let stderr = '';
let outputBytes = 0;
const stdoutDecoder = new StringDecoder('utf8');
const stderrDecoder = new StringDecoder('utf8');
let outcome = null;
let commandPromise = null;
let closing = false;
let postCompletePoll = null;
const sockets = new Set();

async function close() {
  if (closing) return;
  closing = true;
  if (postCompletePoll) clearInterval(postCompletePoll);
  handler.cancelAll('HOST_COMMAND_CANCELLED');
  if (commandPromise) {
    await Promise.race([
      commandPromise,
      new Promise((resolve) => setTimeout(resolve, 2000)),
    ]);
  }
  for (const socket of sockets) socket.destroy();
  server.close();
  await unlink(init.socketPath).catch(() => {});
  process.exit(0);
}

function response(message) {
  if (message.action === 'cancel') {
    handler.cancelAll('HOST_COMMAND_CANCELLED');
  }
  const stdoutOffset = message.stdoutOffset ?? 0;
  const stderrOffset = message.stderrOffset ?? 0;
  if (!Number.isSafeInteger(stdoutOffset) || !Number.isSafeInteger(stderrOffset)
      || stdoutOffset < 0 || stderrOffset < 0 || stdoutOffset > stdout.length || stderrOffset > stderr.length) {
    return { leaseId: init.leaseId, error: 'INVALID_HOST_OUTPUT_OFFSET' };
  }
  const nextStdoutOffset = Math.min(stdout.length, stdoutOffset + READ_CHUNK_CHARS);
  const nextStderrOffset = Math.min(stderr.length, stderrOffset + READ_CHUNK_CHARS);
  return {
    leaseId: init.leaseId,
    running: outcome === null,
    stdout: stdout.slice(stdoutOffset, nextStdoutOffset),
    stderr: stderr.slice(stderrOffset, nextStderrOffset),
    stdoutOffset: nextStdoutOffset,
    stderrOffset: nextStderrOffset,
    hasMoreOutput: nextStdoutOffset < stdout.length || nextStderrOffset < stderr.length,
    ...(outcome ? {
      exitCode: outcome.exitCode,
      signal: outcome.signal,
      ...(outcome.error ? { error: outcome.error } : {}),
    } : {}),
  };
}

const server = net.createServer((socket) => {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
  let request = '';
  socket.setTimeout(5000, () => socket.destroy());
  socket.on('data', async (chunk) => {
    request += chunk.toString('utf8');
    if (request.length > 4096) { socket.destroy(); return; }
    if (!request.includes('\n')) return;
    socket.removeAllListeners('data');
    let message;
    try { message = JSON.parse(request.slice(0, request.indexOf('\n'))); } catch { socket.destroy(); return; }
    if (!['read', 'cancel'].includes(message.action) || message.leaseId !== init.leaseId) { socket.destroy(); return; }
    const current = await handler.currentLease().catch(() => null);
    if (!current || current.id !== init.leaseId) { void close(); return; }
    socket.end(JSON.stringify(response(message)));
  });
});

const socketInfo = await lstat(init.socketPath).catch(() => null);
if (socketInfo) process.exit(1);
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(init.socketPath, resolve);
});
await chmod(init.socketPath, 0o600);
process.stdout.write('READY\n');
process.stdout.end();
const expiryTimer = setTimeout(() => { void close(); }, Math.max(0, lease.expiresAt - Date.now()));
process.on('SIGTERM', () => { void close(); });
process.on('SIGINT', () => { void close(); });
commandPromise = handler.call(init.args, {
  onOutput(stream, chunk) {
    outputBytes += chunk.length;
    if (outputBytes > MAX_OUTPUT_BYTES) return;
    if (stream === 'stdout') stdout += stdoutDecoder.write(chunk);
    else stderr += stderrDecoder.write(chunk);
  },
});
const result = await commandPromise;
stdout += stdoutDecoder.end();
stderr += stderrDecoder.end();
outcome = result.structuredContent;
if (!await handler.currentLease().catch(() => null)) {
  await close();
}
postCompletePoll = setInterval(() => {
  void handler.currentLease().then((current) => {
    if (!current || current.id !== init.leaseId) void close();
  }).catch(() => { void close(); });
}, 1000);
const retentionMs = Math.min(10 * 60_000, Math.max(0, lease.expiresAt - Date.now()));
clearTimeout(expiryTimer);
setTimeout(() => { void close(); }, retentionMs);
