import { spawn } from 'node:child_process';
import { sanitizeJsonRpcEnvelope, sanitizeLogText } from './firewall.js';
import { buildHostErrorResponse, createRequestLedger } from './request-ledger.js';
import { HOST_COMMAND_TOOL } from './host-command.js';

const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_LOG_RECORD_BYTES = 64 * 1024;
const PRIVATE_KEY_MARKER = /-----(BEGIN|END) ((?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----/gi;
const PRIVATE_KEY_MARKER_TAIL_BYTES = 64;
const DEFAULT_CONTAINER = 'webmcp-native';
const DEFAULT_ENTRYPOINT = '/opt/webmcp/native/bin/start.js';
const TOKENIZED_RUNTIME_BOOTSTRAP = [
  "import * as serverModule from 'file:///opt/webmcp/native/src/server.js';",
  "import * as stdioModule from 'file:///opt/webmcp/native/src/stdio.js';",
  "import * as workspaceModule from 'file:///opt/webmcp/native/src/workspace.js';",
  "const runtimeToken = process.env.WEBMCP_RUNTIME_TOKEN;",
  "if (!runtimeToken) { process.stderr.write('WEBMCP_RUNTIME_TOKEN is required.\\n'); process.exit(2); }",
  "const mountPolicies = typeof workspaceModule.decodeRuntimeMountPolicy === 'function' ? workspaceModule.decodeRuntimeMountPolicy(process.env.WEBMCP_MOUNT_POLICY) : null;",
  "const runtime = workspaceModule.createWorkspaceRuntime({ root: workspaceModule.NATIVE_WORKSPACE_ROOT || '/workspace', runtimeToken, readOnly: process.env.WEBMCP_READ_ONLY === '1', mountPolicies });",
  "const server = serverModule.createNativeMcpServer(runtime);",
  "stdioModule.createNativeStdioServer(server).start();",
].join('\n');

function writeLine(stream, payload) {
  stream.write(`${JSON.stringify(payload)}\n`);
}

export function nativeDockerExecCommand({
  containerName = DEFAULT_CONTAINER,
  entrypoint = DEFAULT_ENTRYPOINT,
  runtimeToken = null,
} = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(containerName)) {
    throw new Error('Invalid Native container name.');
  }
  if (typeof entrypoint !== 'string' || !entrypoint.startsWith('/') || entrypoint.includes('\0')) {
    throw new Error('Invalid Native entrypoint.');
  }
  if (runtimeToken !== null && !/^[0-9a-f]{64}$/i.test(runtimeToken)) {
    throw new Error('Invalid Native runtime token.');
  }
  if (runtimeToken === null) {
    return ['docker', 'exec', '-i', containerName, 'node', entrypoint];
  }
  return [
    'docker', 'exec', '-i',
    '-e', `WEBMCP_RUNTIME_TOKEN=${runtimeToken}`,
    containerName,
    'node', '--input-type=module', '--eval', TOKENIZED_RUNTIME_BOOTSTRAP,
  ];
}

export function createHostRelay({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  spawnImpl = spawn,
  command = nativeDockerExecCommand(),
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  deadlineAt = null,
  onDeadline = null,
  hostCommandHandler = null,
} = {}) {
  if (!Array.isArray(command) || command.length < 2 || command.some((part) => typeof part !== 'string' || part.length === 0)) {
    throw new Error('Host relay command must be a non-empty argv array.');
  }
  if (deadlineAt !== null && (!Number.isSafeInteger(deadlineAt) || deadlineAt <= 0 || typeof onDeadline !== 'function')) {
    throw new Error('Host relay deadline requires a positive timestamp and revocation callback.');
  }

  let child = null;
  const ledger = createRequestLedger();
  let buffer = Buffer.alloc(0);
  let stderrBuffer = Buffer.alloc(0);
  let stderrMarkerTail = '';
  let stderrOversized = false;
  let privateKeyLabel = null;
  let stderrRecordPrivate = false;
  let stderrRecordPrivateBegin = false;
  let closed = false;
  let failed = false;
  let stdinEnded = false;
  let deadlineTriggered = false;
  let inputBuffer = Buffer.alloc(0);
  const pendingToolLists = new Set();
  const activeHostRequests = new Set();
  const requestKey = (id) => `${typeof id}:${id}`;

  function writeDiagnostic(reason) {
    try {
      stderr.write(sanitizeLogText(`${reason}\n`));
    } catch {
      stderr.write('[REDACTED:HOST_FIREWALL_LOG_FAILURE]\n');
    }
  }

  // An unanswered request is indistinguishable from a slow one: the upstream transport
  // holds it until its own deadline and then drops it without posting a response,
  // which the Web UI shows as a turn that never ends. Fail-closed still terminates
  // the host process; it just refuses the outstanding requests first.
  function refuseOutstanding(reason) {
    const ids = ledger.drain();
    if (ids.length === 0) {
      return;
    }
    const message = `Native WebMCP host boundary failed closed: ${reason}`;
    for (const id of ids) {
      try {
        writeLine(stdout, buildHostErrorResponse(id, message));
      } catch {
        writeDiagnostic('Unable to refuse an outstanding request before failing closed.');
      }
    }
  }

  function failClosed(reason) {
    if (failed || closed) {
      return;
    }
    failed = true;
    writeDiagnostic(reason);
    refuseOutstanding(reason);
    process.exitCode = 1;
    stdin.pause();
    stdin.unref?.();
    child?.kill('SIGKILL');
    hostCommandHandler?.cancelAll();
  }

  function processResponseLine(lineBytes) {
    if (lineBytes.byteLength > maxResponseBytes) {
      failClosed('Native runtime response exceeded the host boundary limit.');
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(lineBytes.toString('utf8'));
    } catch {
      failClosed('Native runtime returned malformed JSON.');
      return;
    }

    if (hostCommandHandler && pendingToolLists.delete(requestKey(parsed?.id))) {
      if (!Array.isArray(parsed?.result?.tools)) {
        failClosed('Native runtime returned an invalid tool list.');
        return;
      }
      parsed.result.tools.push(HOST_COMMAND_TOOL);
    }
    try {
      writeLine(stdout, sanitizeJsonRpcEnvelope(parsed));
    } catch {
      failClosed('Native runtime response was blocked by host policy.');
      return;
    }
    ledger.settle(parsed?.id);
  }

  function onChildStdout(chunk) {
    if (failed || closed) {
      return;
    }
    buffer = Buffer.concat([buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8')]);
    let newline = buffer.indexOf(0x0a);
    while (newline !== -1) {
      const line = buffer.subarray(0, newline);
      buffer = buffer.subarray(newline + 1);
      if (line.byteLength > 0) {
        processResponseLine(line);
      }
      if (failed) {
        return;
      }
      newline = buffer.indexOf(0x0a);
    }
    if (buffer.byteLength > maxResponseBytes) {
      failClosed('Native runtime response exceeded the host boundary limit.');
    }
  }

  function scanPrivateKeyMarkers(segment) {
    const probe = `${stderrMarkerTail}${segment.toString('utf8')}`;
    PRIVATE_KEY_MARKER.lastIndex = 0;
    for (let match = PRIVATE_KEY_MARKER.exec(probe); match; match = PRIVATE_KEY_MARKER.exec(probe)) {
      const kind = match[1].toUpperCase();
      const label = match[2].toUpperCase();
      if (kind === 'BEGIN' && privateKeyLabel === null) {
        privateKeyLabel = label;
        stderrRecordPrivate = true;
        stderrRecordPrivateBegin = true;
      } else if (kind === 'END' && privateKeyLabel === label) {
        stderrRecordPrivate = true;
        privateKeyLabel = null;
      }
    }
    stderrMarkerTail = probe.slice(-PRIVATE_KEY_MARKER_TAIL_BYTES);
  }

  function finishStderrRecord({ newline = true } = {}) {
    if (stderrOversized) {
      stderr.write(`[REDACTED:HOST_LOG_RECORD_TOO_LARGE]${newline ? '\n' : ''}`);
    } else if (stderrRecordPrivate) {
      if (stderrRecordPrivateBegin) {
        stderr.write(`[REDACTED:PRIVATE_KEY]${newline ? '\n' : ''}`);
      }
    } else if (stderrBuffer.byteLength > 0) {
      try {
        stderr.write(sanitizeLogText(stderrBuffer.toString('utf8')));
        if (newline) stderr.write('\n');
      } catch {
        stderr.write('[REDACTED:HOST_FIREWALL_LOG_FAILURE]\n');
      }
    } else if (newline) {
      stderr.write('\n');
    }

    stderrBuffer = Buffer.alloc(0);
    stderrMarkerTail = '';
    stderrOversized = false;
    stderrRecordPrivate = privateKeyLabel !== null;
    stderrRecordPrivateBegin = false;
  }

  function onChildStderr(chunk) {
    if (closed) {
      return;
    }
    const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
    let offset = 0;

    while (offset < piece.byteLength) {
      const newline = piece.indexOf(0x0a, offset);
      const end = newline === -1 ? piece.byteLength : newline;
      const segment = piece.subarray(offset, end);

      if (privateKeyLabel !== null) {
        stderrRecordPrivate = true;
      }
      scanPrivateKeyMarkers(segment);

      if (!stderrOversized) {
        if (stderrBuffer.byteLength + segment.byteLength > MAX_LOG_RECORD_BYTES) {
          stderrBuffer = Buffer.alloc(0);
          stderrOversized = true;
        } else if (segment.byteLength > 0) {
          stderrBuffer = Buffer.concat([stderrBuffer, segment]);
        }
      }

      if (newline === -1) {
        return;
      }
      finishStderrRecord();
      offset = newline + 1;
    }
  }

  function flushChildStderr() {
    if (
      stderrOversized
      || stderrBuffer.byteLength > 0
      || stderrRecordPrivate
      || stderrRecordPrivateBegin
    ) {
      finishStderrRecord({ newline: false });
    }
  }

  function onStdinData(chunk) {
    if (closed || failed || deadlineTriggered) {
      return;
    }
    if (deadlineAt !== null && Date.now() >= deadlineAt) {
      deadlineTriggered = true;
      stdin.pause();
      // The chunk is never forwarded, so its requests can only be answered here.
      ledger.observe(chunk);
      refuseOutstanding('temporary elevated access expired');
      onDeadline();
      return;
    }
    if (!hostCommandHandler) {
      ledger.observe(chunk);
      child.stdin.write(chunk);
      return;
    }
    inputBuffer = Buffer.concat([inputBuffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8')]);
    let newline = inputBuffer.indexOf(0x0a);
    while (newline !== -1) {
      const line = inputBuffer.subarray(0, newline);
      inputBuffer = inputBuffer.subarray(newline + 1);
      if (line.byteLength > 0) routeRequestLine(line);
      if (failed) return;
      newline = inputBuffer.indexOf(0x0a);
    }
    if (inputBuffer.byteLength > 1024 * 1024) failClosed('Native request exceeded the host boundary limit.');
  }

  function routeRequestLine(line) {
    if (line.byteLength > 1024 * 1024) {
      failClosed('Native request exceeded the host boundary limit.');
      return;
    }
    const framed = Buffer.concat([line, Buffer.from('\n')]);
    ledger.observe(framed);
    let request;
    try { request = JSON.parse(line.toString('utf8')); } catch {
      child.stdin.write(framed);
      return;
    }
    const id = request?.id;
    if (request?.method === 'notifications/cancelled') {
      const cancelledKey = requestKey(request?.params?.requestId);
      if (activeHostRequests.has(cancelledKey)) {
        hostCommandHandler.cancelAll('HOST_COMMAND_CANCELLED');
        return;
      }
    }
    if (request?.method === 'tools/list' && (typeof id === 'string' || typeof id === 'number')) {
      pendingToolLists.add(requestKey(id));
    }
    if (request?.method !== 'tools/call' || request?.params?.name !== 'host_command') {
      child.stdin.write(framed);
      return;
    }
    if (request?.jsonrpc !== '2.0' || (typeof id !== 'string' && typeof id !== 'number')) {
      failClosed('Invalid host command request envelope.');
      return;
    }
    activeHostRequests.add(requestKey(id));
    void hostCommandHandler.call(request.params.arguments).then((result) => {
      if (closed || failed) return;
      const safe = sanitizeJsonRpcEnvelope({ jsonrpc: '2.0', id, result });
      const encoded = JSON.stringify(safe);
      if (Buffer.byteLength(encoded) > maxResponseBytes) {
        throw new Error('Host command response exceeded the host boundary limit.');
      }
      stdout.write(`${encoded}\n`);
      ledger.settle(id);
    }).catch(() => {
      if (closed || failed) return;
      writeLine(stdout, buildHostErrorResponse(id, 'Host command failed closed.'));
      ledger.settle(id);
    }).finally(() => {
      activeHostRequests.delete(requestKey(id));
    });
  }

  function onStdinEnd() {
    if (closed) return;
    if (inputBuffer.byteLength > 0) {
      failClosed('Incomplete Native request frame.');
      return;
    }
    stdinEnded = true;
    child.stdin.end();
  }

  return {
    start() {
      child = spawnImpl(command[0], command.slice(1), {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: process.env,
      });

      child.stdout.on('data', onChildStdout);
      child.stderr.on('data', onChildStderr);
      child.stderr.on('end', flushChildStderr);
      child.on('error', () => failClosed('Unable to start the Native runtime container process.'));
      child.on('exit', (code, signal) => {
        if (closed || failed) {
          return;
        }
        if (code !== 0 || !stdinEnded) {
          failClosed(`Native runtime exited unexpectedly (${signal ?? code ?? 'unknown'}).`);
        }
      });

      // Request bytes remain opaque to the host boundary. Elevated mode adds
      // only an absolute pre-forward deadline gate; request parsing and tool
      // semantics remain inside the verified Native container.
      stdin.on('data', onStdinData);
      stdin.on('end', onStdinEnd);
      stdin.resume?.();

      return {
        close: async () => {
          refuseOutstanding('host relay closed');
          closed = true;
          stdin.off('data', onStdinData);
          stdin.off('end', onStdinEnd);
          stdin.pause();
          child?.kill('SIGTERM');
          hostCommandHandler?.cancelAll();
        },
      };
    },
  };
}
