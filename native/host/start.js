#!/usr/bin/env node
import { lstat } from 'node:fs/promises';
import { createHostRelay, nativeDockerExecCommand } from './relay.js';
import { createHostCommandHandler } from './host-command.js';
import { respondUnavailable } from './unavailable-responder.js';
import {
  ensureNativeContainer,
  inspectNativeContainer,
  removeStaleElevatedContainer,
} from '../deploy/container-controller.js';
import { NATIVE_ELEVATED_LEASE_LABEL } from '../deploy/container-policy.js';
import {
  buildElevatedWorkspaceConfig,
  clearElevatedLease,
  getBootSessionId,
  getLoginSessionId,
  loadElevatedLease,
} from '../deploy/elevated-access.js';
import { loadImagePin } from '../deploy/image-pin.js';
import { bumpInstanceAttachmentGeneration } from '../deploy/instance-attachment.js';
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
const attachmentGenerationPath = process.env.WEBMCP_ATTACHMENT_GENERATION || null;
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
let expiryTimer = null;
let reverting = false;

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    if (expiryTimer) clearTimeout(expiryTimer);
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

async function bumpAttachmentGeneration() {
  if (attachmentGenerationPath === null) return null;
  return bumpInstanceAttachmentGeneration({ attachmentGeneration: attachmentGenerationPath });
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

  if (leaseState.state !== 'active') {
    // Preserve the established default-host failure order: verify the owner-home image
    // pin before asking Docker about container state. Non-default instances get the same
    // fail-closed ordering without changing the default LaunchAgent contract.
    await loadImagePin(imagePinPath);
    // A missing, stale, rebooted, expired or malformed lease can never preserve
    // an elevated mount. Recovery is scoped to this host's named container.
    const existing = await inspectNativeContainer({ containerRef: containerName });
    const staleElevatedContainer = Boolean(existing?.Config?.Labels?.[NATIVE_ELEVATED_LEASE_LABEL]);
    if (leaseState.state !== 'absent' || staleElevatedContainer) {
      await bumpAttachmentGeneration();
    }
    await removeStaleElevatedContainer({ imagePinPath, containerName });
    if (leaseState.state !== 'absent') {
      await clearElevatedLease(leasePath);
    }
    await ensureNativeContainer({ ...containerOptions, workspaceMountConfig });
    return Object.freeze({ normalConfig, workspaceMountConfig, leaseState });
  }

  const elevatedConfig = buildElevatedWorkspaceConfig(normalConfig, leaseState.lease.elevatedRoot);
  await ensureNativeContainer({
    ...containerOptions,
    workspaceConfig: elevatedConfig,
    workspaceMountConfig: null,
    gitCredentialPath: null,
    gitKnownHostsPath: null,
    elevationLeaseId: leaseState.lease.id,
  });
  return Object.freeze({ normalConfig, leaseState });
}

try {
  const { leaseState } = await withLifecycleLock(loadAndEnsureRuntime);

  if (leaseState.state !== 'active') {
    relayControl = startRelay();
  } else {
    const restoreNormal = async (reason) => {
      if (reverting) return;
      reverting = true;
      if (expiryTimer) clearTimeout(expiryTimer);

      // Stop accepting/forwarding elevated work before contending for lifecycle state.
      // If another owner operation holds the lock, this host remains fail-closed.
      await relayControl?.close();
      try {
        await withLifecycleLock(async () => {
          // Invalidate the planner attachment before the root changes. A failed
          // restore may force a reattach, but can never reuse the old id on a new root.
          await bumpAttachmentGeneration();
          // Invalidate authority before container cleanup. A restarted host cannot
          // re-expose the elevated root once the absolute lease has ended.
          await clearElevatedLease(leasePath);
          await removeStaleElevatedContainer({
            imagePinPath,
            expectedLeaseId: leaseState.lease.id,
            containerName,
          });
          const workspaceMountConfig = await loadOptionalMountConfig();
          await ensureNativeContainer({ ...containerOptions, workspaceMountConfig });
        });
        relayControl = startRelay();
        safeDiagnostic(`Temporary elevated access ended: ${reason}. Normal /workspace policy restored.`);
      } catch (error) {
        safeDiagnostic(`Temporary elevated access failed closed during restore: ${error.message}`);
        process.exitCode = 1;
      }
    };

    const delay = Math.max(0, leaseState.lease.expiresAt - Date.now());
    expiryTimer = setTimeout(() => {
      void restoreNormal('absolute lease expiry');
    }, delay);
    expiryTimer.unref?.();

    relayControl = startRelay({
      expectedLeaseId: leaseState.lease.id,
      deadlineAt: leaseState.lease.expiresAt,
      onDeadline: () => { void restoreNormal('absolute lease expiry'); },
    });
  }
} catch (error) {
  safeDiagnostic(`Native WebMCP host boundary failed: ${error.message}`);
  process.exitCode = 1;
  respondUnavailable(error.message);
}
