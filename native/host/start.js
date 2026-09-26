#!/usr/bin/env node
import { lstat } from 'node:fs/promises';
import { createHostRelay, nativeDockerExecCommand } from './relay.js';
import { createHostCommandHandler } from './host-command.js';
import { respondUnavailable } from './unavailable-responder.js';
import { ensureNativeContainer } from '../deploy/container-controller.js';
import {
  clearElevatedLease,
  getBootSessionId,
  getLoginSessionId,
  loadElevatedLease,
} from '../deploy/elevated-access.js';
import { loadImagePin } from '../deploy/image-pin.js';
import { createInstanceContext } from '../deploy/instance-context.js';
import { withInstanceLifecycleLock } from '../deploy/instance-lock.js';
import { loadWorkspaceConfig } from '../deploy/workspace-config.js';
import { loadWorkspaceMountConfig } from '../deploy/workspace-mount-config.js';

const instanceId = process.env.WEBMCP_INSTANCE_ID ?? 'default';
const defaultContext = createInstanceContext({ instanceId });
const configPath = process.env.WEBMCP_WORKSPACE_CONFIG ?? defaultContext.workspaceConfig;
const mountConfigPath = process.env.WEBMCP_WORKSPACE_MOUNT_CONFIG ?? defaultContext.workspaceMountConfig;
const imagePinPath = process.env.WEBMCP_NATIVE_IMAGE_PIN ?? defaultContext.imagePin;
const leasePath = process.env.WEBMCP_ELEVATED_LEASE ?? defaultContext.elevatedLease;
const containerName = process.env.WEBMCP_NATIVE_CONTAINER ?? defaultContext.containerName;
const lifecycleLockPath = process.env.WEBMCP_LIFECYCLE_LOCK || defaultContext.lifecycleLock;
const runtimeToken = process.env.WEBMCP_RUNTIME_TOKEN || null;
const containerOptions = {
  home: process.env.WEBMCP_OWNER_HOME ?? defaultContext.home,
  configPath,
  imagePinPath,
  containerName,
  gitCredentialPath: process.env.WEBMCP_GIT_CREDENTIAL || null,
  gitKnownHostsPath: process.env.WEBMCP_GIT_KNOWN_HOSTS || null,
};

let relayControl = null;

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    void relayControl?.close();
    process.exitCode = 0;
  });
}

function startRelay({ expectedLeaseId = null, ...options } = {}) {
  return createHostRelay({
    ...options,
    command: nativeDockerExecCommand({ containerName, runtimeToken }),
    hostCommandHandler: process.platform === 'darwin' ? createHostCommandHandler({
      leasePath,
      configPath,
      expectedLeaseId,
      instanceId,
      home: process.env.WEBMCP_OWNER_HOME ?? defaultContext.home,
    }) : null,
  }).start();
}

function withLifecycleLock(operation) {
  return withInstanceLifecycleLock({ lifecycleLock: lifecycleLockPath }, operation);
}

function safeDiagnostic(message) {
  process.stderr.write(`${String(message).replace(/[\r\n]+/g, ' ')}\n`);
}

async function loadOptionalMountConfig() {
  if (mountConfigPath === null) return null;
  try {
    await lstat(mountConfigPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  return loadWorkspaceMountConfig(mountConfigPath);
}

// Host Access never changes the container: it only names the lease that host_command may honour.
// A lease that can no longer be honoured (rebooted, expired, another instance's, …) is cleared.
async function loadAndEnsureRuntime() {
  const [normalConfig, workspaceMountConfig] = await Promise.all([
    loadWorkspaceConfig(configPath),
    loadOptionalMountConfig(),
  ]);
  let leasePresent = true;
  try {
    await lstat(leasePath);
  } catch (error) {
    if (error?.code === 'ENOENT') leasePresent = false;
    else throw error;
  }

  let leaseState = Object.freeze({ state: 'absent' });
  if (leasePresent) {
    const bootSessionId = await getBootSessionId();
    const loginSessionId = await getLoginSessionId();
    leaseState = await loadElevatedLease(leasePath, {
      normalConfig,
      bootSessionId,
      loginSessionId,
      instanceId,
    });
  }

  // Preserve the established default-host failure order: verify the owner-home image
  // pin before asking Docker about container state.
  await loadImagePin(imagePinPath);
  if (!['absent', 'active'].includes(leaseState.state)) {
    await clearElevatedLease(leasePath);
  }
  await ensureNativeContainer({ ...containerOptions, workspaceMountConfig });
  return leaseState;
}

try {
  const leaseState = await withLifecycleLock(loadAndEnsureRuntime);
  relayControl = startRelay({ expectedLeaseId: leaseState.state === 'active' ? leaseState.lease.id : null });
} catch (error) {
  safeDiagnostic(`Native WebMCP host boundary failed: ${error.message}`);
  process.exitCode = 1;
  respondUnavailable(error.message);
}
