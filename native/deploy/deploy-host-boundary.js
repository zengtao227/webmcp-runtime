#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  deployHostRuntime,
  verifyCurrent,
} from '../../adapter/deploy/deploy-host-runtime.js';

export const NATIVE_HOST_ENTRYPOINT = 'native/host/start.js';
export const NATIVE_HOST_RUNTIME_PAYLOAD = Object.freeze([
  'package.json',
  'adapter/deploy/deploy-host-runtime.js',
  'gateway/secret-scanner/index.js',
  'native/host/start.js',
  'native/host/relay.js',
  'native/host/host-command.js',
  'native/host/host-command-session-worker.js',
  'native/host/firewall.js',
  'native/host/request-ledger.js',
  'native/host/unavailable-responder.js',
  'native/deploy/deploy-host-boundary.js',
  'native/deploy/container-controller.js',
  'native/deploy/container-policy.js',
  'native/deploy/control-plane-paths.js',
  'native/deploy/elevated-access.js',
  'native/deploy/host-platform.js',
  'native/deploy/image-pin.js',
  'native/deploy/instance-attachment.js',
  'native/deploy/instance-context.js',
  'native/deploy/instance-lock.js',
  'native/deploy/instance-release.js',
  'native/deploy/installer-error.js',
  'native/deploy/local-approval.js',
  'native/deploy/instance-transition.js',
  'native/deploy/workspace-config.js',
  'native/deploy/workspace-mount-config.js',
  // The image source ships in the same release so one pinned artifact id also fixes
  // the Docker image an installer builds, without a Git checkout on the tester machine.
  'native/deploy/build-image.js',
  'native/deploy/runtime-payload.js',
  'native/Dockerfile',
  'native/bin/start.js',
  'native/src/server.js',
  'native/src/stdio.js',
  'native/src/workspace.js',
  'gateway/path-policy/index.js',
]);

export function defaultNativeHostRuntimeRoot(home = os.homedir()) {
  return path.join(home, '.local', 'share', 'webmcp', 'host-runtime');
}

export async function deployNativeHostBoundary({
  sourceRoot,
  runtimeRoot = defaultNativeHostRuntimeRoot(),
  activate = true,
} = {}) {
  if (typeof sourceRoot !== 'string' || !path.isAbsolute(sourceRoot)) {
    throw new Error('sourceRoot must be the absolute repository root.');
  }
  return deployHostRuntime({
    sourceRoot,
    runtimeRoot,
    // The generic deployer also checks sourceRoot independently. Reusing it as
    // the default writable boundary avoids assuming every user owns ~/Doc/My code.
    defaultWritableRoot: sourceRoot,
    payloadPaths: NATIVE_HOST_RUNTIME_PAYLOAD,
    entrypoint: NATIVE_HOST_ENTRYPOINT,
    activate,
  });
}

export function verifyNativeHostBoundary(runtimeRoot = defaultNativeHostRuntimeRoot()) {
  return verifyCurrent(runtimeRoot, { entrypoint: NATIVE_HOST_ENTRYPOINT });
}

async function main() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../..');
  const argv = process.argv.slice(2);
  let sourceRoot = repo;
  let runtimeRoot = defaultNativeHostRuntimeRoot();
  let verifyOnly = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--verify-current') {
      verifyOnly = true;
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for ${arg}`);
    }
    if (arg === '--source-root') {
      sourceRoot = path.resolve(value);
    } else if (arg === '--runtime-root') {
      runtimeRoot = path.resolve(value);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
    index += 1;
  }

  if (verifyOnly) {
    const current = await verifyNativeHostBoundary(runtimeRoot);
    if (!current) {
      throw new Error('Native host boundary is not deployed.');
    }
    process.stdout.write(`${JSON.stringify(current)}\n`);
    return;
  }

  const result = await deployNativeHostBoundary({ sourceRoot, runtimeRoot });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const invoked = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invoked === pathToFileURL(fileURLToPath(import.meta.url)).href) {
  main().catch((error) => {
    process.stderr.write(`Native host boundary deployment failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
