import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { protectedHomePaths } from '../native/deploy/control-plane-paths.js';

// Every WebMCP provider's control state must be masked from every workspace, so a
// workspace that includes the home folder cannot read or rewrite another provider's
// tunnel identity, lease or settings.
const PROVIDER_STATE = ['.config/tunnel-client', '.local/share/prism-webmcp', '.prism-webmcp', '.deepseek-webmcp', '.chatgpt-embedded-panel'];

test('provider control state is protected on macOS', () => {
  const home = '/Users/owner';
  const protectedPaths = new Set(protectedHomePaths({ home, platform: 'darwin' }));
  for (const relative of [...PROVIDER_STATE, 'Library/Application Support/tunnel-client']) {
    assert.ok(protectedPaths.has(path.join(home, relative)), relative);
  }
});

test('provider control state is protected on Linux (including WSL)', () => {
  const home = '/home/owner';
  const protectedPaths = new Set(protectedHomePaths({ home, platform: 'linux' }));
  for (const relative of PROVIDER_STATE) {
    assert.ok(protectedPaths.has(path.join(home, relative)), relative);
  }
});
