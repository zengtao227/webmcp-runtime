import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NATIVE_HOST_ENTRYPOINT,
  NATIVE_HOST_RUNTIME_PAYLOAD,
} from '../native/deploy/deploy-host-boundary.js';

test('immutable shared host payload is dependency-complete for the host entrypoint', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-shared-host-entry-'));
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  try {
    for (const relativePath of NATIVE_HOST_RUNTIME_PAYLOAD) {
      const destination = path.join(root, relativePath);
      await mkdir(path.dirname(destination), { recursive: true });
      await copyFile(path.join(repo, relativePath), destination);
    }

    const child = spawn(process.execPath, [path.join(root, NATIVE_HOST_ENTRYPOINT)], {
      env: {
        ...process.env,
        WEBMCP_WORKSPACE_CONFIG: path.join(root, 'missing-workspace.json'),
        WEBMCP_NATIVE_IMAGE_PIN: path.join(root, 'missing-image.json'),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.stdin.end();
    const code = await new Promise((resolve) => child.on('close', resolve));

    assert.equal(code, 1);
    assert.doesNotMatch(stderr, /ERR_MODULE_NOT_FOUND|Cannot find module/);
    assert.match(stderr, /Native WebMCP host boundary failed:/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

