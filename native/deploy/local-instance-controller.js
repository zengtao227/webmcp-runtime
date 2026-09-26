import { execFile } from 'node:child_process';
import { lstat, realpath, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  ensureNativeContainer,
  inspectNativeContainerState,
  inspectNativeRuntimeVerification,
  prepareNativeContainerPolicyTransition,
  removeNativeContainer,
  removeNativeContainerForPolicyTransition,
} from './container-controller.js';
import { configureWorkspace } from './configure-workspace.js';
import { defaultProtectedPaths } from './control-plane-paths.js';
import {
  clearElevatedLease,
  createElevatedLease,
  elevatedLeasePublicStatus,
  getBootSessionId,
  getLoginSessionId,
  loadElevatedLease,
  MAX_ELEVATED_LEASE_MS,
  parseElevatedDuration,
  persistElevatedLease,
} from './elevated-access.js';
import { loadImagePin, persistImagePin } from './image-pin.js';
import { bumpInstanceAttachmentGeneration } from './instance-attachment.js';
import { createInstanceContext, DEFAULT_INSTANCE_ID, normalizeInstanceId } from './instance-context.js';
import { withInstanceLifecycleLock } from './instance-lock.js';
import { pinInstanceToCurrentRelease, pinInstanceToRelease, verifyPinnedInstanceRelease } from './instance-release.js';
import {
  applyContainerPolicyTransition,
  removeCreatedNativeContainer,
} from './instance-transition.js';
import { requestLocalElevationApproval } from './local-approval.js';
import {
  loadWorkspaceConfig,
  persistWorkspaceConfig,
  verifyWorkspaceMount,
} from './workspace-config.js';
import {
  addWorkspaceMount,
  loadWorkspaceMountConfig,
  migrateLegacyWorkspaceConfig,
  normalizeWorkspaceMountConfig,
  persistWorkspaceMountConfig,
  removeWorkspaceMount,
  setWorkspaceMountWrite,
} from './workspace-mount-config.js';
import { applyWorkspaceMountTransition } from './workspace-mount-transition.js';

const execFileAsync = promisify(execFile);

export class LocalInstanceError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'LocalInstanceError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new LocalInstanceError(message, code, options);
}

function assertLocalContext(context) {
  if (!context || context.isDefault !== false || typeof context.containerName !== 'string') {
    fail('Local instance control requires a trusted non-default instance context.', 'INVALID_LOCAL_INSTANCE_CONTEXT');
  }
}

async function leaseExists(context) {
  try {
    await lstat(context.elevatedLease);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function containerOptions(context, execFileImpl, platform, workspaceMountConfig = undefined) {
  return {
    home: context.home,
    configPath: context.workspaceConfig,
    ...(workspaceMountConfig === undefined ? {} : { workspaceMountConfig }),
    imagePinPath: context.imagePin,
    containerName: context.containerName,
    execFileImpl,
    platform,
  };
}

async function loadLocalMountConfig(context) {
  try {
    await lstat(context.workspaceMountConfig);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  return loadWorkspaceMountConfig(context.workspaceMountConfig);
}

async function localLeaseState(context, normalConfig, {
  execFileImpl,
  platform,
  now,
  getBootSessionIdImpl = getBootSessionId,
  getLoginSessionIdImpl = getLoginSessionId,
} = {}) {
  if (!(await leaseExists(context))) return Object.freeze({ state: 'absent' });
  const [bootSessionId, loginSessionId] = await Promise.all([
    getBootSessionIdImpl({ platform, execFileImpl }),
    getLoginSessionIdImpl({ platform, execFileImpl }),
  ]);
  return loadElevatedLease(context.elevatedLease, {
    normalConfig,
    bootSessionId,
    loginSessionId,
    now,
    platform,
    instanceId: context.instanceId,
  });
}

export async function provisionLocalInstance({
  context,
  root,
  defaultImagePinPath,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  networkEnabled = false,
  releaseArtifactId = null,
  pinInstanceReleaseImpl = pinInstanceToCurrentRelease,
  pinSpecificReleaseImpl = pinInstanceToRelease,
} = {}) {
  assertLocalContext(context);
  if (typeof defaultImagePinPath !== 'string') {
    fail('Provisioning requires the installed default Native image pin.', 'DEFAULT_IMAGE_PIN_REQUIRED');
  }

  return withInstanceLifecycleLock(context, async () => {
    if (await loadLocalMountConfig(context)) {
      fail('Provisioning cannot replace an instance while mounted-folder control is active.', 'MULTI_MOUNT_CONTROL_ACTIVE');
    }
    const attachmentGeneration = await bumpInstanceAttachmentGeneration(context);
    const imagePin = await loadImagePin(defaultImagePinPath);
    const protectedPaths = await defaultProtectedPaths({
      home: context.home,
      configPath: context.workspaceConfig,
      platform,
    });
    const config = await configureWorkspace({
      root,
      mode: 'workspace',
      networkEnabled,
      probeImage: imagePin.image,
      configPath: context.workspaceConfig,
      protectedPaths,
      platform,
      verifyMount: (options) => verifyWorkspaceMount({ ...options, execFileImpl }),
    });

    await persistImagePin(context.imagePin, imagePin);
    const release = releaseArtifactId === null
      ? await pinInstanceReleaseImpl(context)
      : await pinSpecificReleaseImpl(context, releaseArtifactId);
    const runtime = await ensureNativeContainer(containerOptions(context, execFileImpl, platform));
    return Object.freeze({
      action: 'provisioned',
      instanceId: context.instanceId,
      root: config.hostRoot,
      containerName: context.containerName,
      artifactId: release.artifactId,
      runtimeAction: runtime.action,
      attachmentGeneration,
      attachmentChanged: true,
    });
  });
}

// Host Access is a lease for host_command only; the container always runs with the instance's own
// folders. An expired lease reads as normal: it grants nothing and a new grant replaces it.
function leaseMode(leaseState) {
  if (leaseState.state === 'active') return 'elevated';
  if (['absent', 'expired'].includes(leaseState.state)) return 'normal';
  return 'stale';
}

export async function localInstanceStatus({
  context,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  now = Date.now(),
  verifyPinnedReleaseImpl = verifyPinnedInstanceRelease,
  getBootSessionIdImpl = getBootSessionId,
  getLoginSessionIdImpl = getLoginSessionId,
} = {}) {
  assertLocalContext(context);
  const [config, release, workspaceMountConfig] = await Promise.all([
    loadWorkspaceConfig(context.workspaceConfig, { platform }),
    verifyPinnedReleaseImpl(context),
    loadLocalMountConfig(context),
  ]);
  const leaseState = await localLeaseState(context, config, {
    execFileImpl,
    platform,
    now,
    getBootSessionIdImpl,
    getLoginSessionIdImpl,
  });
  const runtime = await inspectNativeRuntimeVerification(containerOptions(context, execFileImpl, platform, workspaceMountConfig));
  return Object.freeze({
    instanceId: context.instanceId,
    ...elevatedLeasePublicStatus(leaseState, { now }),
    mode: leaseMode(leaseState),
    root: config.hostRoot,
    normalRoot: config.hostRoot,
    containerName: context.containerName,
    artifactId: release.artifactId,
    ...runtime,
    attachmentChanged: false,
    ...(workspaceMountConfig === null ? {} : { mounts: workspaceMountConfig.mounts }),
  });
}

export async function grantLocalInstanceAccess({
  context,
  durationMs = MAX_ELEVATED_LEASE_MS,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  now = null,
  verifyPinnedReleaseImpl = verifyPinnedInstanceRelease,
  getBootSessionIdImpl = getBootSessionId,
  getLoginSessionIdImpl = getLoginSessionId,
  requestApprovalImpl = requestLocalElevationApproval,
} = {}) {
  assertLocalContext(context);
  return withInstanceLifecycleLock(context, async () => {
    const normalConfig = await loadWorkspaceConfig(context.workspaceConfig, { platform });
    await verifyPinnedReleaseImpl(context);
    const existing = await localLeaseState(context, normalConfig, {
      execFileImpl,
      platform,
      now: now ?? Date.now(),
      getBootSessionIdImpl,
      getLoginSessionIdImpl,
    });
    if (existing.state === 'active') {
      fail('Host Access is already active for this instance.', 'INSTANCE_ELEVATION_ALREADY_ACTIVE');
    }
    if (leaseMode(existing) === 'stale') {
      fail('A Host Access lease that can no longer be verified must be revoked before a new grant.', 'INSTANCE_ELEVATION_STATE_REQUIRES_REVOKE');
    }

    const [bootSessionId, loginSessionId, ownerHome] = await Promise.all([
      getBootSessionIdImpl({ platform, execFileImpl }),
      getLoginSessionIdImpl({ platform, execFileImpl }),
      realpath(context.home),
    ]);
    await requestApprovalImpl({
      durationMs,
      instanceLabel: context.instanceId,
      execFileImpl,
    });
    const approvedAt = now ?? Date.now();
    const lease = createElevatedLease({
      normalConfig,
      elevatedRoot: ownerHome,
      bootSessionId,
      loginSessionId,
      durationMs,
      now: approvedAt,
      platform,
      instanceId: context.instanceId,
    });
    await persistElevatedLease(context.elevatedLease, lease);
    return Object.freeze({
      action: 'elevated',
      instanceId: context.instanceId,
      mode: 'elevated',
      accessLevel: lease.accessLevel,
      root: normalConfig.hostRoot,
      expiresAt: new Date(lease.expiresAt).toISOString(),
      hostUserAuthority: true,
      attachmentChanged: false,
    });
  });
}

// Revoking only lowers authority, so it needs neither Docker nor a verified release: host_command
// reads the lease on every call and stops a running command once the lease is gone.
export async function revokeLocalInstanceAccess({ context } = {}) {
  assertLocalContext(context);
  return withInstanceLifecycleLock(context, async () => {
    if (!(await leaseExists(context))) {
      return Object.freeze({ action: 'unchanged', instanceId: context.instanceId, mode: 'normal', attachmentChanged: false });
    }
    await clearElevatedLease(context.elevatedLease);
    return Object.freeze({ action: 'revoked', instanceId: context.instanceId, mode: 'normal', attachmentChanged: false });
  });
}

export async function reconfigureLocalInstance({
  context,
  root,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  verifyPinnedReleaseImpl = verifyPinnedInstanceRelease,
} = {}) {
  assertLocalContext(context);
  return withInstanceLifecycleLock(context, async () => {
    // The Host Access lease is bound to this root.
    if (await leaseExists(context)) {
      fail('Revoke Host Access before changing this instance workspace.', 'INSTANCE_ELEVATION_ACTIVE');
    }
    if (await loadLocalMountConfig(context)) {
      fail('Workspace reconfigure is unavailable while mounted-folder control is active.', 'MULTI_MOUNT_CONTROL_ACTIVE');
    }

    const previousConfig = await loadWorkspaceConfig(context.workspaceConfig, { platform });
    const imagePin = await loadImagePin(context.imagePin);
    await verifyPinnedReleaseImpl(context);
    const protectedPaths = await defaultProtectedPaths({
      home: context.home,
      configPath: context.workspaceConfig,
      platform,
    });
    const verified = await verifyWorkspaceMount({
      hostRoot: root,
      image: imagePin.image,
      protectedPaths,
      platform,
      execFileImpl,
    });
    const nextConfig = Object.freeze({ ...previousConfig, hostRoot: verified.canonicalRoot });
    if (nextConfig.hostRoot === previousConfig.hostRoot) {
      return Object.freeze({
        action: 'unchanged',
        instanceId: context.instanceId,
        root: previousConfig.hostRoot,
        attachmentChanged: false,
      });
    }

    const attachmentGeneration = await bumpInstanceAttachmentGeneration(context);
    const options = containerOptions(context, execFileImpl, platform);
    await applyContainerPolicyTransition({
      rollbackFailure: {
        code: 'INSTANCE_RECONFIGURE_ROLLBACK_FAILED',
        prefix: 'Local instance workspace change failed and rollback did not restore the previous runtime',
      },
      stopService: async () => {},
      removeCurrentContainer: () => removeNativeContainer(options),
      persistConfig: () => persistWorkspaceConfig(context.workspaceConfig, nextConfig, { platform }),
      createContainer: () => ensureNativeContainer(options),
      startService: async () => {},
      verifyInstalled: async () => {
        const state = await inspectNativeContainerState(options);
        if (!state.present || !state.running || state.canonicalRoot !== nextConfig.hostRoot) {
          fail('Local instance runtime did not adopt the new workspace.', 'INSTANCE_RECONFIGURE_VERIFY_FAILED');
        }
      },
      removeCreatedContainer: (containerId) => removeCreatedNativeContainer(containerId, execFileImpl),
      restorePreviousConfig: () => persistWorkspaceConfig(context.workspaceConfig, previousConfig, { platform }),
      ensurePreviousContainer: () => ensureNativeContainer(options),
    });

    return Object.freeze({
      action: 'reconfigured',
      instanceId: context.instanceId,
      root: nextConfig.hostRoot,
      attachmentGeneration,
      attachmentChanged: true,
    });
  });
}

function publicLocalMountState(context, mountConfig, extra = {}) {
  const hasRuntime = typeof extra.runtimeVerified === 'boolean' && typeof extra.runtimeState === 'string';
  const effective = extra.runtimeVerified === true && extra.runtimeState === 'running';
  return Object.freeze({
    instanceId: context.instanceId,
    mode: 'multi-mount',
    mounts: Object.freeze(mountConfig.mounts.map(({ id, hostPath, containerPath, writeEnabled }) => Object.freeze({
      id,
      hostPath,
      containerPath,
      writeEnabled,
      ...(hasRuntime ? { effectiveWriteEnabled: effective ? writeEnabled : null } : {}),
    }))),
    ...extra,
  });
}

export async function localInstanceMountedFolders({
  context,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  verifyPinnedReleaseImpl = verifyPinnedInstanceRelease,
} = {}) {
  assertLocalContext(context);
  await verifyPinnedReleaseImpl(context);
  const [normalConfig, mountConfig] = await Promise.all([
    loadWorkspaceConfig(context.workspaceConfig, { platform }),
    loadLocalMountConfig(context),
  ]);
  if (mountConfig === null) {
    return Object.freeze({
      instanceId: context.instanceId,
      mode: 'legacy',
      legacyRoot: normalConfig.hostRoot,
      legacyReadOnly: normalConfig.readOnly,
      mounts: Object.freeze([]),
    });
  }
  const runtime = await inspectNativeRuntimeVerification(
    containerOptions(context, execFileImpl, platform, mountConfig),
  );
  return publicLocalMountState(context, mountConfig, runtime);
}

async function changeLocalInstanceMountedFolders({
  context,
  mutate,
  execFileImpl = execFileAsync,
  platform = 'darwin',
  verifyPinnedReleaseImpl = verifyPinnedInstanceRelease,
} = {}) {
  assertLocalContext(context);
  return withInstanceLifecycleLock(context, async () => {
    await verifyPinnedReleaseImpl(context);
    const [normalConfig, previousMountConfig] = await Promise.all([
      loadWorkspaceConfig(context.workspaceConfig, { platform }),
      loadLocalMountConfig(context),
    ]);
    const editable = previousMountConfig ?? normalizeWorkspaceMountConfig({ version: 1, mounts: [] });
    const nextMountConfig = await mutate(editable);
    const previousAuthority = previousMountConfig ?? migrateLegacyWorkspaceConfig(normalConfig, {
      mountId: 'legacy-root',
    });
    const previousOptions = containerOptions(context, execFileImpl, platform, previousMountConfig);
    const nextOptions = containerOptions(context, execFileImpl, platform, nextMountConfig);
    if (JSON.stringify(nextMountConfig) === JSON.stringify(editable)) {
      try {
        const runtime = await inspectNativeContainerState(nextOptions);
        if (runtime.present && runtime.running) {
          return publicLocalMountState(context, editable, { action: 'unchanged', attachmentChanged: false });
        }
      } catch {
        // Reconcile a fail-closed container whose persisted policy is already authoritative.
      }
    }

    const attachmentGeneration = await bumpInstanceAttachmentGeneration(context);

    await applyWorkspaceMountTransition({
      previousConfig: previousAuthority,
      nextConfig: nextMountConfig,
      stopService: () => prepareNativeContainerPolicyTransition(previousOptions),
      prepareCurrentContainer: () => prepareNativeContainerPolicyTransition(previousOptions),
      persistConfig: () => persistWorkspaceMountConfig(context.workspaceMountConfig, nextMountConfig),
      removeCurrentContainer: (expectedContainerId) => removeNativeContainerForPolicyTransition({ ...previousOptions, expectedContainerId }),
      createContainer: () => ensureNativeContainer(nextOptions),
      startService: async () => {},
      verifyInstalled: async () => {
        const state = await inspectNativeContainerState(nextOptions);
        if (!state.present || !state.running) {
          fail('Local instance runtime did not adopt mounted-folder policy.', 'INSTANCE_MOUNT_VERIFY_FAILED');
        }
      },
      removeCreatedContainer: (containerId) => removeCreatedNativeContainer(containerId, execFileImpl),
      restorePreviousConfig: () => (
        previousMountConfig === null
          ? rm(context.workspaceMountConfig, { force: true })
          : persistWorkspaceMountConfig(context.workspaceMountConfig, previousMountConfig)
      ),
      ensurePreviousContainer: () => ensureNativeContainer(previousOptions),
    });

    return publicLocalMountState(context, nextMountConfig, {
      action: 'changed',
      attachmentGeneration,
      attachmentChanged: true,
    });
  });
}

export async function addLocalInstanceMountedFolder({ context, root, ...options } = {}) {
  if (typeof root !== 'string' || root.length === 0) {
    fail('Adding a mounted folder requires an absolute root.', 'WORKSPACE_ROOT_REQUIRED');
  }
  return changeLocalInstanceMountedFolders({
    context,
    ...options,
    mutate: (current) => addWorkspaceMount(current, {
      hostPath: root,
      platform: options.platform ?? 'darwin',
      home: context.home,
    }),
  });
}

export async function removeLocalInstanceMountedFolder({ context, id, ...options } = {}) {
  if (typeof id !== 'string' || id.length === 0) {
    fail('Removing a mounted folder requires its id.', 'WORKSPACE_MOUNT_ID_REQUIRED');
  }
  return changeLocalInstanceMountedFolders({
    context,
    ...options,
    mutate: (current) => removeWorkspaceMount(current, id),
  });
}

export async function setLocalInstanceMountedFolderWrite({
  context,
  id,
  writeEnabled,
  ...options
} = {}) {
  if (typeof id !== 'string' || id.length === 0) {
    fail('Changing mounted-folder Write requires its id.', 'WORKSPACE_MOUNT_ID_REQUIRED');
  }
  if (typeof writeEnabled !== 'boolean') {
    fail('Mounted-folder Write must be explicitly on or off.', 'WORKSPACE_MOUNT_WRITE_MODE_REQUIRED');
  }
  return changeLocalInstanceMountedFolders({
    context,
    ...options,
    mutate: (current) => setWorkspaceMountWrite(current, id, writeEnabled),
  });
}

export function parseLocalInstanceControlArgs(argv) {
  const command = argv[0];
  if (!['mount-list', 'mount-add', 'mount-remove', 'mount-write', 'access-status', 'host-access-grant', 'access-revoke'].includes(command)) {
    fail(
      'Expected one command: mount-list, mount-add, mount-remove, mount-write, access-status, host-access-grant, access-revoke.',
      'INVALID_LOCAL_INSTANCE_ARGUMENTS',
    );
  }
  const allowedOptions = {
    'mount-list': new Set(['--instance']),
    'mount-add': new Set(['--instance', '--root']),
    'mount-remove': new Set(['--instance', '--id']),
    'mount-write': new Set(['--instance', '--id', '--on', '--off']),
    'access-status': new Set(['--instance']),
    'host-access-grant': new Set(['--instance', '--duration']),
    'access-revoke': new Set(['--instance']),
  }[command];
  const knownOptions = new Set(['--instance', '--root', '--id', '--on', '--off', '--duration']);
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!knownOptions.has(arg) || !allowedOptions.has(arg)) {
      fail(`Option ${arg} is not valid for ${command}.`, 'INVALID_LOCAL_INSTANCE_ARGUMENTS');
    }
    const next = () => {
      index += 1;
      if (index >= argv.length) fail(`Missing value for ${arg}.`, 'INVALID_LOCAL_INSTANCE_ARGUMENTS');
      return argv[index];
    };
    if (arg === '--instance') options.instanceId = normalizeInstanceId(next());
    else if (arg === '--root') options.root = next();
    else if (arg === '--id') options.id = next();
    else if (arg === '--duration') options.durationMs = parseElevatedDuration(next());
    else if (arg === '--on' || arg === '--off') {
      if (Object.hasOwn(options, 'writeEnabled')) {
        fail('mount-write accepts exactly one of --on or --off.', 'INVALID_LOCAL_INSTANCE_ARGUMENTS');
      }
      options.writeEnabled = arg === '--on';
    }
  }
  if (!options.instanceId || options.instanceId === DEFAULT_INSTANCE_ID) {
    fail('Local instance control requires a non-default --instance <id>.', 'INVALID_LOCAL_INSTANCE_ARGUMENTS');
  }
  return Object.freeze({ command, options: Object.freeze(options) });
}

async function localInstanceControlMain() {
  try {
    const parsed = parseLocalInstanceControlArgs(process.argv.slice(2));
    const context = createInstanceContext({ instanceId: parsed.options.instanceId });
    let result;
    if (parsed.command === 'mount-list') {
      result = await localInstanceMountedFolders({ context });
    } else if (parsed.command === 'mount-add') {
      result = await addLocalInstanceMountedFolder({ context, root: parsed.options.root });
    } else if (parsed.command === 'mount-remove') {
      result = await removeLocalInstanceMountedFolder({ context, id: parsed.options.id });
    } else if (parsed.command === 'mount-write') {
      result = await setLocalInstanceMountedFolderWrite({
        context,
        id: parsed.options.id,
        writeEnabled: parsed.options.writeEnabled,
      });
    } else if (parsed.command === 'access-status') {
      result = await localInstanceStatus({ context });
    } else if (parsed.command === 'host-access-grant') {
      result = await grantLocalInstanceAccess({
        context,
        ...(parsed.options.durationMs === undefined ? {} : { durationMs: parsed.options.durationMs }),
      });
    } else {
      result = await revokeLocalInstanceAccess({ context });
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    const code = typeof error?.code === 'string' ? error.code : 'UNEXPECTED_LOCAL_INSTANCE_ERROR';
    process.stderr.write(`WebMCP local instance control failed [${code}]: ${error.message}\n`);
    process.exitCode = 1;
  }
}

let isMain = false;
if (process.argv[1]) {
  try {
    isMain = await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url));
  } catch {
    isMain = false;
  }
}
if (isMain) {
  await localInstanceControlMain();
}
