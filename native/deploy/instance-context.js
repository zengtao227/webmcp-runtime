import os from 'node:os';
import path from 'node:path';
import { NATIVE_CONTAINER_NAME } from './container-policy.js';
import { defaultNativeHostRuntimeRoot, NATIVE_HOST_ENTRYPOINT } from './deploy-host-boundary.js';
import { defaultElevatedLeasePath } from './elevated-access.js';

export const DEFAULT_INSTANCE_ID = 'default';
const INSTANCE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RELEASE_ID_PATTERN = /^[0-9a-f]{40}-[0-9a-f]{64}$/;

export class InstanceContextError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'InstanceContextError';
    this.code = code;
  }
}

function fail(message, code) {
  throw new InstanceContextError(message, code);
}

export function normalizeInstanceId(instanceId = DEFAULT_INSTANCE_ID) {
  if (typeof instanceId !== 'string' || !INSTANCE_ID_PATTERN.test(instanceId)) {
    fail('WebMCP instance id must be 1-32 lowercase letters, digits or hyphens.', 'INVALID_INSTANCE_ID');
  }
  return instanceId;
}

function defaultInstanceHome() {
  try {
    return os.userInfo().homedir;
  } catch {
    return os.homedir();
  }
}

export function createInstanceContext({
  instanceId = DEFAULT_INSTANCE_ID,
  home = defaultInstanceHome(),
} = {}) {
  const id = normalizeInstanceId(instanceId);
  if (typeof home !== 'string' || !path.isAbsolute(home) || home.includes('\0')) {
    fail('WebMCP instance home must be an absolute path.', 'INVALID_INSTANCE_HOME');
  }

  const ownerHome = path.resolve(home);
  const isDefault = id === DEFAULT_INSTANCE_ID;
  const globalConfigRoot = path.join(ownerHome, '.config', 'webmcp');
  const globalDataRoot = path.join(ownerHome, '.local', 'share', 'webmcp');
  const configRoot = isDefault ? globalConfigRoot : path.join(globalConfigRoot, 'instances', id);
  const stateRoot = isDefault ? globalDataRoot : path.join(globalDataRoot, 'instances', id);
  // All instances may reuse the same immutable release store. Only the default
  // instance follows its mutable `current` pointer; non-default instances pin an
  // explicit artifact id in their own state and address that release directly.
  const hostRuntimeRoot = defaultNativeHostRuntimeRoot(ownerHome);

  return Object.freeze({
    instanceId: id,
    isDefault,
    home: ownerHome,

    // Global parents are already part of WebMCP's protected control plane. Keeping every
    // instance under them protects one instance's state from every model-writable runtime.
    globalConfigRoot,
    globalDataRoot,
    configRoot,
    stateRoot,

    workspaceConfig: path.join(configRoot, 'workspace.json'),
    workspaceMountConfig: path.join(configRoot, 'workspace-mounts.json'),
    imagePin: path.join(stateRoot, 'native-image.json'),
    elevatedLease: isDefault
      ? defaultElevatedLeasePath(ownerHome)
      : path.join(stateRoot, 'elevated-lease.json'),

    // Mutable lifecycle state is instance-local.
    lifecycleLock: path.join(stateRoot, 'lifecycle.lock'),
    attachmentGeneration: path.join(stateRoot, 'attachment-generation.json'),

    containerName: isDefault ? NATIVE_CONTAINER_NAME : `${NATIVE_CONTAINER_NAME}-${id}`,

    hostRuntimeRoot,

    // Backward compatibility: the production default instance still uses its existing
    // current pointer. New instances must use a pinned immutable release and never share
    // or follow the default instance's switchable current pointer.
    hostCurrentEntrypoint: isDefault
      ? path.join(hostRuntimeRoot, 'current', NATIVE_HOST_ENTRYPOINT)
      : null,
    hostReleasePin: isDefault ? null : path.join(stateRoot, 'host-release.json'),
  });
}

export function pinnedInstanceRelease(context, releaseId) {
  if (!context || typeof context !== 'object' || context.isDefault !== false) {
    fail('Pinned instance releases are required only for non-default instances.', 'PINNED_RELEASE_NOT_APPLICABLE');
  }
  if (typeof releaseId !== 'string' || !RELEASE_ID_PATTERN.test(releaseId) || releaseId === 'current') {
    fail('Pinned WebMCP release id is invalid.', 'INVALID_RELEASE_ID');
  }
  const releaseRoot = path.join(context.hostRuntimeRoot, 'releases', releaseId);
  return Object.freeze({
    releaseId,
    releaseRoot,
    hostEntrypoint: path.join(releaseRoot, NATIVE_HOST_ENTRYPOINT),
    ownerControlEntrypoint: path.join(releaseRoot, 'native', 'deploy', 'installer.js'),
  });
}
