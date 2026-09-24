const DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024;

function writeLine(stream, payload) {
  stream.write(`${JSON.stringify(payload)}\n`);
}

export function createNativeStdioServer(server, {
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
} = {}) {
  if (!server || typeof server.handle !== 'function') {
    throw new Error('createNativeStdioServer requires a Native MCP server.');
  }

  let buffer = Buffer.alloc(0);
  let discardingOversizedLine = false;
  let closed = false;
  let pending = Promise.resolve();

  function log(event, fields = {}) {
    stderr.write(`${JSON.stringify({ event, ...fields })}\n`);
  }

  async function processLine(line) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      return;
    }

    let payload;
    try {
      payload = JSON.parse(trimmed);
    } catch {
      writeLine(stdout, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
      return;
    }

    const response = await server.handle(payload);
    if (response !== null && response !== undefined) {
      writeLine(stdout, response);
    }
  }

  function enqueue(line) {
    pending = pending
      .then(() => (closed ? undefined : processLine(line)))
      .catch(() => {
        if (!closed) {
          writeLine(stdout, {
            jsonrpc: '2.0',
            id: null,
            error: { code: -32603, message: 'Internal error' },
          });
        }
      });
  }

  function onData(chunk) {
    let piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');

    if (discardingOversizedLine) {
      const newline = piece.indexOf(0x0a);
      if (newline === -1) {
        return;
      }
      discardingOversizedLine = false;
      piece = piece.subarray(newline + 1);
    }

    buffer = Buffer.concat([buffer, piece]);
    let newline = buffer.indexOf(0x0a);
    while (newline !== -1) {
      const line = buffer.subarray(0, newline);
      buffer = buffer.subarray(newline + 1);
      if (line.byteLength > maxRequestBytes) {
        log('native_stdio_request_too_large');
        writeLine(stdout, {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'Request too large' },
        });
      } else {
        enqueue(line.toString('utf8'));
      }
      newline = buffer.indexOf(0x0a);
    }

    if (buffer.byteLength > maxRequestBytes) {
      buffer = Buffer.alloc(0);
      discardingOversizedLine = true;
      log('native_stdio_request_too_large');
      writeLine(stdout, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Request too large' },
      });
    }
  }

  return {
    start() {
      stdin.on('data', onData);
      log('webmcp_native_stdio_ready');
      return {
        close: async () => {
          closed = true;
          stdin.pause();
          await pending;
        },
      };
    },
  };
}
