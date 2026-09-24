import { sanitizeLogText } from './firewall.js';
import { buildHostErrorResponse, createRequestLedger } from './request-ledger.js';

// the upstream transport keeps the host stdin open for the whole session, so a degraded
// boundary waits a bounded window for the caller's next request rather than
// staying up forever. Exiting afterwards is what re-runs the container checks,
// which is how the boundary recovers once the host is healthy again.
const DEFAULT_GRACE_MS = 30_000;

// The host boundary could not verify its container, so no tool may run. Exiting
// silently leaves the upstream transport holding the request until its own deadline, which
// it then drops without posting any response at all — the caller sees a turn that
// never ends. Refusing explicitly is still fail-closed: nothing is started here
// and the process still terminates non-zero.
export function respondUnavailable(reason, {
  stdin = process.stdin,
  stdout = process.stdout,
  graceMs = DEFAULT_GRACE_MS,
} = {}) {
  const message = `Native WebMCP host boundary is unavailable: ${sanitizeLogText(String(reason))}`;
  const ledger = createRequestLedger();
  let stopped = false;

  function stop() {
    if (stopped) return;
    stopped = true;
    clearTimeout(graceTimer);
    stdin.off('data', onData);
    stdin.off('end', stop);
    stdin.pause();
    // The listener above holds a reference to an stdin that the caller keeps open.
    stdin.unref?.();
  }

  function onData(chunk) {
    if (stopped) return;
    ledger.observe(chunk);
    const ids = ledger.drain();
    if (ids.length === 0) return;
    for (const id of ids) {
      stdout.write(`${JSON.stringify(buildHostErrorResponse(id, message))}\n`);
    }
    stop();
  }

  const graceTimer = setTimeout(stop, graceMs);
  stdin.on('data', onData);
  stdin.on('end', stop);
  stdin.resume?.();
}
