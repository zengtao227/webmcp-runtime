const DEFAULT_MAX_LINE_BYTES = 1024 * 1024;
const DEFAULT_MAX_PENDING = 64;

// the upstream transport drops a forwarded command it never gets a response for
// ("command response deadline reached; dropping without posting a response"),
// and the Web UI then shows a turn that never ends. The host boundary therefore
// tracks which JSON-RPC request ids are still unanswered so that a fail-closed
// exit can refuse them explicitly instead of going silent. Request bytes are
// still forwarded verbatim; this observation adds no authority over them.
export function buildHostErrorResponse(id, message, code = -32001) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export function createRequestLedger({
  maxLineBytes = DEFAULT_MAX_LINE_BYTES,
  maxPending = DEFAULT_MAX_PENDING,
} = {}) {
  let buffer = Buffer.alloc(0);
  let discardingOversizedLine = false;
  const pending = new Map();

  function keyFor(id) {
    return `${typeof id}:${id}`;
  }

  function isRequestId(id) {
    return typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
  }

  function observeLine(line) {
    let parsed;
    try {
      parsed = JSON.parse(line.toString('utf8'));
    } catch {
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
    // A notification carries a method and no id; it needs no response.
    if (typeof parsed.method !== 'string' || !isRequestId(parsed.id)) return;
    if (pending.size >= maxPending) return;
    pending.set(keyFor(parsed.id), parsed.id);
  }

  return {
    observe(chunk) {
      let piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');

      if (discardingOversizedLine) {
        const newline = piece.indexOf(0x0a);
        if (newline === -1) return;
        discardingOversizedLine = false;
        piece = piece.subarray(newline + 1);
      }

      buffer = Buffer.concat([buffer, piece]);
      let newline = buffer.indexOf(0x0a);
      while (newline !== -1) {
        const line = buffer.subarray(0, newline);
        buffer = buffer.subarray(newline + 1);
        if (line.byteLength > 0) {
          observeLine(line);
        }
        newline = buffer.indexOf(0x0a);
      }

      if (buffer.byteLength > maxLineBytes) {
        buffer = Buffer.alloc(0);
        discardingOversizedLine = true;
      }
    },
    settle(id) {
      if (isRequestId(id)) {
        pending.delete(keyFor(id));
      }
    },
    drain() {
      const ids = [...pending.values()];
      pending.clear();
      return ids;
    },
  };
}
