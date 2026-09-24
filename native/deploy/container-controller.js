#!/usr/bin/env node
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import {
  buildNativeContainerRun,
  NATIVE_CONTAINER_NAME,
  NATIVE_ELEVATED_LEASE_LABEL,
  NATIVE_GIT_KEY_PATH,
  NATIVE_GIT_KNOWN_HOSTS_PATH,
} from './container-policy.js';
import { defaultProtectedPaths } from './control-plane-paths.js';
import { loadImagePin } from './image-pin.js';
import { DEFAULT_WORKSPACE_CONFIG, loadWorkspaceConfig, normalizeWorkspaceConfig } from './workspace-config.js';

const execFileAsync = promisify(execFile);
export class ContainerControllerError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'ContainerControllerError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new ContainerControllerError(message, code, options);
}

function matchesHostBindSource(actualSource, expectedSource, platform) {
  if (typeof actualSource !== 'string' || !path.isAbsolute(actualSource)) return false;
  const actual = path.resolve(actualSource);
  if (actual === expectedSource) return true;
  // Docker Desktop may report the VM-side path for a macOS host bind.
  return platform === 'darwin' && actual === `/host_mnt${expectedSource}`;
}

export async function inspectNativeImage(imagePin, { dockerBin = 'docker', execFileImpl = execFileAsync } = {}) {
  let stdout;
  try {
    ({ stdout } = await execFileImpl(dockerBin, ['image', 'inspect', imagePin.image], {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    }));
  } catch (error) {
    fail('Unable to inspect the pinned Native image.', 'NATIVE_IMAGE_UNAVAILABLE', { cause: error });
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    fail('Docker image inspect returned invalid JSON.', 'INVALID_IMAGE_INSPECT', { cause: error });
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
    fail('Docker image inspect returned an unexpected payload.', 'INVALID_IMAGE_INSPECT');
  }
  if (String(parsed[0].Id ?? '').toLowerCase() !== imagePin.image.toLowerCase()) {
    fail('Docker resolved the Native image pin to a different image ID.', 'NATIVE_IMAGE_ID_MISMATCH');
  }
  const sourceLabel = parsed[0]?.Config?.Labels?.['com.webmcp.native.source-sha256'];
  if (sourceLabel !== imagePin.sourceSha256) {
    fail('Pinned Native image does not match the reviewed source digest.', 'NATIVE_IMAGE_SOURCE_MISMATCH');
  }
  return parsed[0];
}

export async function inspectNativeContainer({
  dockerBin = 'docker',
  execFileImpl = execFileAsync,
  // Inspecting by id lets a creator look at exactly what it created, instead of whatever holds
  // the shared container name by the time it looks.
  containerRef = NATIVE_CONTAINER_NAME,
} = {}) {
  try {
    const { stdout } = await execFileImpl(dockerBin, ['inspect', containerRef], {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    });
    const parsed = JSON.parse(stdout);
    if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
      fail('Docker inspect returned an unexpected container payload.', 'INVALID_CONTAINER_INSPECT');
    }
    return parsed[0];
  } catch (error) {
    if (error instanceof ContainerControllerError) {
      throw error;
    }
    const stderr = String(error?.stderr ?? '');
    if (/No such (?:object|container)/i.test(stderr)) {
      return null;
    }
    if (error instanceof SyntaxError) {
      fail('Docker inspect returned invalid JSON.', 'INVALID_CONTAINER_INSPECT', { cause: error });
    }
    fail('Unable to inspect the Native container.', 'DOCKER_INSPECT_FAILED', { cause: error });
  }
}

export function verifyContainer(container, expected) {
  const labels = container?.Config?.Labels ?? {};
  if (labels['com.webmcp.native.policy-sha256'] !== expected.policyDigest) {
    fail('Existing Native container policy does not match the reviewed configuration.', 'CONTAINER_POLICY_MISMATCH');
  }
  if (labels['com.webmcp.native.image'] !== expected.image) {
    fail('Existing Native container image label does not match the reviewed image.', 'CONTAINER_IMAGE_MISMATCH');
  }
  if (String(container?.Image ?? '').toLowerCase() !== expected.image.toLowerCase()) {
    fail('Existing Native container actual image does not match the reviewed image.', 'CONTAINER_IMAGE_MISMATCH');
  }
  const elevatedLeaseId = labels[NATIVE_ELEVATED_LEASE_LABEL] ?? null;
  if (elevatedLeaseId !== expected.elevationLeaseId) {
    fail('Existing Native container elevation state does not match the authorized lease.', 'CONTAINER_ELEVATION_MISMATCH');
  }
  const expectedUser = `${expected.hostUid}:${expected.hostGid}`;
  if (container?.Config?.User !== expectedUser) {
    fail('Existing Native container runtime identity does not match the host owner.', 'CONTAINER_IDENTITY_MISMATCH');
  }
  if (container?.HostConfig?.Privileged === true) {
    fail('Existing Native container is unexpectedly privileged.', 'CONTAINER_HARDENING_MISMATCH');
  }
  const capAdd = container?.HostConfig?.CapAdd ?? [];
  if (!Array.isArray(capAdd) || capAdd.length > 0) {
    fail('Existing Native container has unauthorized added capabilities.', 'CONTAINER_HARDENING_MISMATCH');
  }
  const devices = container?.HostConfig?.Devices ?? [];
  if (!Array.isArray(devices) || devices.length > 0) {
    fail('Existing Native container has unauthorized device access.', 'CONTAINER_HARDENING_MISMATCH');
  }
  const capDrop = container?.HostConfig?.CapDrop ?? [];
  if (!Array.isArray(capDrop) || !capDrop.some((value) => String(value).toUpperCase() === 'ALL')) {
    fail('Existing Native container is missing the required capability drop.', 'CONTAINER_HARDENING_MISMATCH');
  }
  const securityOpt = container?.HostConfig?.SecurityOpt ?? [];
  if (!Array.isArray(securityOpt) || !securityOpt.some((value) => String(value).startsWith('no-new-privileges'))) {
    fail('Existing Native container is missing no-new-privileges.', 'CONTAINER_HARDENING_MISMATCH');
  }
  const networkMode = container?.HostConfig?.NetworkMode;
  if (expected.networkEnabled === false && networkMode !== 'none') {
    fail('Existing Native container network policy does not match the reviewed configuration.', 'CONTAINER_NETWORK_MISMATCH');
  }
  if (expected.networkEnabled === true && !['default', 'bridge'].includes(networkMode)) {
    fail('Existing Native container network policy does not match the reviewed configuration.', 'CONTAINER_NETWORK_MISMATCH');
  }
  const mounts = Array.isArray(container?.Mounts) ? container.Mounts : [];
  const env = Array.isArray(container?.Config?.Env) ? container.Config.Env : [];
  if (Array.isArray(expected.mounts)) {
    if (container?.HostConfig?.ReadonlyRootfs !== true) {
      fail('Existing Native container multi-mount root filesystem is not read-only.', 'CONTAINER_HARDENING_MISMATCH');
    }
    const tempMount = mounts.find((mount) => mount?.Destination === '/tmp');
    if (tempMount?.Type !== 'tmpfs' || tempMount.RW !== true) {
      fail('Existing Native container writable temp mount does not match the reviewed configuration.', 'CONTAINER_MOUNT_MISMATCH');
    }
    for (const expectedMount of expected.mounts) {
      const actualMount = mounts.find((mount) => mount?.Destination === expectedMount.containerPath);
      if (
        !actualMount
        || actualMount.Type !== 'bind'
        || !matchesHostBindSource(actualMount.Source, expectedMount.hostPath, expected.platform)
        || actualMount.RW !== expectedMount.writeEnabled
      ) {
        fail('Existing Native container mounted-folder policy does not match the reviewed configuration.', 'CONTAINER_WORKSPACE_MISMATCH');
      }
    }
    if (
      expected.mountPolicyMarker === null
      || !env.includes(`WEBMCP_MOUNT_POLICY=${expected.mountPolicyMarker}`)
      || env.includes('WEBMCP_READ_ONLY=1')
    ) {
      fail('Existing Native container mounted-folder marker does not match its enforced policy.', 'CONTAINER_WORKSPACE_MISMATCH');
    }
  } else {
    const workspaceMount = mounts.find((mount) => mount?.Destination === '/workspace');
    // The mount direction is checked against the reviewed configuration in both directions: a
    // read-only workspace must not be writable, and a read-write one must not have been narrowed.
    if (
      !workspaceMount
      || workspaceMount.Type !== 'bind'
      || !matchesHostBindSource(workspaceMount.Source, expected.canonicalRoot, expected.platform)
      || workspaceMount.RW !== !expected.readOnly
    ) {
      fail('Existing Native container workspace mount does not match the reviewed host root and write policy.', 'CONTAINER_WORKSPACE_MISMATCH');
    }

    // The mount is the control; the marker only tells the Native tools what to say. They must agree,
    // otherwise a read-only host would report itself as writable or the reverse.
    if (env.includes('WEBMCP_READ_ONLY=1') !== Boolean(expected.readOnly)) {
      fail('Existing Native container read-only marker does not match its workspace mount.', 'CONTAINER_WORKSPACE_MISMATCH');
    }
  }

  for (const mask of expected.maskPlan) {
    const mount = mounts.find((candidate) => candidate?.Destination === mask.destination);
    const valid = mask.type === 'file'
      ? mount?.Type === 'bind' && path.resolve(mount?.Source ?? '') === '/dev/null' && mount?.RW === false
      : mount?.Type === 'tmpfs' && mount?.RW === false;
    if (!valid) {
      fail('Existing Native container control-plane mask does not match the reviewed configuration.', 'CONTAINER_MASK_MISMATCH');
    }
  }

  for (const [destination, expectedSource] of [
    [NATIVE_GIT_KEY_PATH, expected.gitCredentialSource],
    [NATIVE_GIT_KNOWN_HOSTS_PATH, expected.gitKnownHostsSource],
  ]) {
    const mount = mounts.find((candidate) => candidate?.Destination === destination);
    if (expectedSource === null) {
      if (mount) {
        fail('Existing Native container exposes an unauthorized Git secret mount.', 'CONTAINER_GIT_MOUNT_MISMATCH');
      }
      continue;
    }
    if (mount?.Type !== 'bind' || !matchesHostBindSource(mount.Source, expectedSource, expected.platform) || mount.RW !== false) {
      fail('Existing Native container Git secret mount does not match the reviewed configuration.', 'CONTAINER_GIT_MOUNT_MISMATCH');
    }
  }

  const allowedDestinations = new Set([
    ...(Array.isArray(expected.mounts) ? ['/tmp', ...expected.mounts.map((mount) => mount.containerPath)] : ['/workspace']),
    ...expected.maskPlan.map((mask) => mask.destination),
    ...(expected.gitCredentialSource === null ? [] : [NATIVE_GIT_KEY_PATH]),
    ...(expected.gitKnownHostsSource === null ? [] : [NATIVE_GIT_KNOWN_HOSTS_PATH]),
  ]);
  if (mounts.length !== allowedDestinations.size || mounts.some((mount) => !allowedDestinations.has(mount?.Destination))) {
    fail('Existing Native container has an unauthorized mount.', 'CONTAINER_MOUNT_MISMATCH');
  }
}

function verifyManagedContainerIdentity(container, {
  image,
  hostUid,
  hostGid,
  networkEnabled,
  elevationLeaseId,
  requireStopped = false,
  errorMessage,
  errorCode,
}) {
  const labels = container?.Config?.Labels ?? {};
  const containerId = container?.Id;
  const actualLeaseId = labels[NATIVE_ELEVATED_LEASE_LABEL] ?? null;
  const capAdd = container?.HostConfig?.CapAdd ?? [];
  const capDrop = container?.HostConfig?.CapDrop ?? [];
  const devices = container?.HostConfig?.Devices ?? [];
  const securityOpt = container?.HostConfig?.SecurityOpt ?? [];
  const networkMode = container?.HostConfig?.NetworkMode;
  const networkMatches = networkEnabled === false
    ? networkMode === 'none'
    : ['default', 'bridge'].includes(networkMode);
  const safelyIdentified = /^[0-9a-f]{64}$/i.test(containerId ?? '')
    && /^[0-9a-f]{64}$/i.test(labels['com.webmcp.native.policy-sha256'] ?? '')
    && labels['com.webmcp.native.image'] === image
    && String(container?.Image ?? '').toLowerCase() === image.toLowerCase()
    && container?.Config?.User === `${hostUid}:${hostGid}`
    && container?.HostConfig?.Privileged !== true
    && Array.isArray(capAdd)
    && capAdd.length === 0
    && Array.isArray(devices)
    && devices.length === 0
    && Array.isArray(capDrop)
    && capDrop.some((value) => String(value).toUpperCase() === 'ALL')
    && Array.isArray(securityOpt)
    && securityOpt.some((value) => String(value).startsWith('no-new-privileges'))
    && networkMatches
    && actualLeaseId === elevationLeaseId
    && (!requireStopped || container?.State?.Running === false);
  if (!safelyIdentified) {
    fail(errorMessage, errorCode);
  }
  return Object.freeze({ containerId, leaseId: actualLeaseId });
}

function verifyPolicyTransitionContainer(container, expected, { allowRunningStale = false } = {}) {
  let policyState = 'exact';
  try {
    verifyContainer(container, expected);
  } catch (error) {
    if (!(error instanceof ContainerControllerError)) throw error;
    policyState = 'stale';
  }
  const identity = verifyManagedContainerIdentity(container, {
    image: expected.image,
    hostUid: expected.hostUid,
    hostGid: expected.hostGid,
    networkEnabled: expected.networkEnabled,
    elevationLeaseId: null,
    requireStopped: policyState === 'stale' && !allowRunningStale,
    errorMessage: 'Native container cannot be identified safely for mounted-folder recovery.',
    errorCode: 'CONTAINER_TRANSITION_UNVERIFIED',
  });
  return Object.freeze({ ...identity, policyState });
}

async function resolveNativeContainerPolicy({
  configPath = DEFAULT_WORKSPACE_CONFIG,
  home,
  workspaceConfig = null,
  workspaceMountConfig = null,
  imagePinPath,
  containerName = NATIVE_CONTAINER_NAME,
  gitCredentialPath = null,
  gitKnownHostsPath = null,
  protectedPaths = null,
  elevationLeaseId = null,
  dockerBin = 'docker',
  execFileImpl = execFileAsync,
  platform = process.platform,
  hostUid = typeof process.getuid === 'function' ? process.getuid() : null,
  hostGid = typeof process.getgid === 'function' ? process.getgid() : null,
} = {}) {
  if (typeof imagePinPath !== 'string' || !path.isAbsolute(imagePinPath)) {
    fail('imagePinPath must be an absolute host path.', 'IMAGE_PIN_REQUIRED');
  }

  const [config, imagePin] = await Promise.all([
    workspaceConfig === null
      ? loadWorkspaceConfig(configPath, { platform })
      : Promise.resolve(normalizeWorkspaceConfig(workspaceConfig, { platform })),
    loadImagePin(imagePinPath),
  ]);
  await inspectNativeImage(imagePin, { dockerBin, execFileImpl });
  const defaults = await defaultProtectedPaths({ home, configPath, platform });
  const effectiveProtected = [...new Set([...(protectedPaths ?? []), ...defaults, imagePinPath])];
  const policy = await buildNativeContainerRun({
    config,
    mountConfig: workspaceMountConfig,
    home,
    image: imagePin.image,
    containerName,
    protectedPaths: effectiveProtected,
    gitCredentialPath,
    gitKnownHostsPath,
    elevationLeaseId,
    platform,
    hostUid,
    hostGid,
  });
  const expected = Object.freeze({
    platform,
    image: imagePin.image,
    policyDigest: policy.policyDigest,
    canonicalRoot: policy.canonicalRoot,
    mounts: policy.mounts,
    readOnlyRootFilesystem: policy.readOnlyRootFilesystem,
    mountPolicyMarker: policy.mountPolicyMarker,
    hostUid,
    hostGid,
    networkEnabled: policy.config.networkEnabled,
    readOnly: policy.config.readOnly,
    gitCredentialSource: policy.gitCredentialSource,
    gitKnownHostsSource: policy.gitKnownHostsSource,
    maskPlan: policy.maskPlan,
    elevationLeaseId: policy.elevationLeaseId,
    containerName: policy.containerName,
  });
  return Object.freeze({ config, imagePin, policy, expected });
}

export async function inspectNativeContainerState(options = {}) {
  const resolved = await resolveNativeContainerPolicy(options);
  const container = await inspectNativeContainer({
    dockerBin: options.dockerBin,
    execFileImpl: options.execFileImpl,
    containerRef: options.containerName ?? NATIVE_CONTAINER_NAME,
  });
  if (!container) {
    return Object.freeze({
      present: false,
      running: false,
      policyDigest: resolved.policy.policyDigest,
      canonicalRoot: resolved.policy.canonicalRoot,
      elevationLeaseId: resolved.expected.elevationLeaseId,
    });
  }
  verifyContainer(container, resolved.expected);
  return Object.freeze({
    present: true,
    running: container?.State?.Running === true,
    policyDigest: resolved.policy.policyDigest,
    canonicalRoot: resolved.policy.canonicalRoot,
    elevationLeaseId: resolved.expected.elevationLeaseId,
  });
}

export async function inspectNativeRuntimeVerification(options = {}) {
  try {
    const state = await inspectNativeContainerState(options);
    if (!state.present) {
      return Object.freeze({ runtimeState: 'absent', runtimeVerified: false });
    }
    return Object.freeze({
      runtimeState: state.running ? 'running' : 'stopped',
      runtimeVerified: true,
    });
  } catch {
    return Object.freeze({ runtimeState: 'unverified', runtimeVerified: false });
  }
}

export async function removeNativeContainer(options = {}) {
  const resolved = await resolveNativeContainerPolicy(options);
  const {
    dockerBin = 'docker',
    execFileImpl = execFileAsync,
    containerName = NATIVE_CONTAINER_NAME,
  } = options;
  const container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
  if (!container) {
    return Object.freeze({ action: 'absent' });
  }
  verifyContainer(container, resolved.expected);
  try {
    await execFileImpl(dockerBin, ['rm', '-f', containerName], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    fail('Unable to remove the verified Native container.', 'CONTAINER_REMOVE_FAILED', { cause: error });
  }
  return Object.freeze({ action: 'removed' });
}

export async function prepareNativeContainerPolicyTransition(options = {}) {
  const resolved = await resolveNativeContainerPolicy(options);
  const {
    dockerBin = 'docker',
    execFileImpl = execFileAsync,
    containerName = NATIVE_CONTAINER_NAME,
  } = options;
  let container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
  if (!container) {
    return Object.freeze({ action: 'absent' });
  }

  const { containerId, policyState } = verifyPolicyTransitionContainer(
    container,
    resolved.expected,
    { allowRunningStale: true },
  );
  if (container?.State?.Running === false) {
    return Object.freeze({ action: policyState === 'stale' ? 'stale-stopped' : 'already-stopped', containerId });
  }
  if (container?.State?.Running !== true) {
    fail('Native container running state is ambiguous.', 'CONTAINER_TRANSITION_UNVERIFIED');
  }

  try {
    await execFileImpl(dockerBin, ['stop', containerId], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
  } catch {
    // A graceful stop can fail even though the managed container is still safely identifiable.
    // Fall through to exact-id verification and force termination if it remains running.
  }

  container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerId });
  if (!container) {
    return Object.freeze({ action: 'stopped-absent', containerId });
  }
  if (container?.State?.Running === true) {
    try {
      await execFileImpl(dockerBin, ['kill', containerId], {
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,
      });
    } catch {
      // Final state verification below is authoritative; a failed CLI call may still have terminated it.
    }
    container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerId });
  }
  if (!container) {
    return Object.freeze({ action: 'stopped-absent', containerId });
  }
  if (container?.State?.Running !== false) {
    fail('Native container stop could not be confirmed.', 'CONTAINER_STOP_UNCONFIRMED');
  }
  verifyPolicyTransitionContainer(container, resolved.expected);
  return Object.freeze({ action: policyState === 'stale' ? 'stopped-stale' : 'stopped', containerId });
}

export async function removeNativeContainerForPolicyTransition(options = {}) {
  const expectedContainerId = options.expectedContainerId;
  if (
    expectedContainerId !== null
    && (typeof expectedContainerId !== 'string' || !/^[0-9a-f]{64}$/i.test(expectedContainerId))
  ) {
    fail('Mounted-folder removal requires the container identity returned by prepare.', 'CONTAINER_TRANSITION_UNVERIFIED');
  }
  const resolved = await resolveNativeContainerPolicy(options);
  const {
    dockerBin = 'docker',
    execFileImpl = execFileAsync,
    containerName = NATIVE_CONTAINER_NAME,
  } = options;
  const container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
  if (!container) {
    return Object.freeze({ action: 'absent' });
  }

  if (expectedContainerId === null || container.Id !== expectedContainerId) {
    fail('Native container identity changed after mounted-folder removal was prepared.', 'CONTAINER_TRANSITION_UNVERIFIED');
  }

  const { containerId, policyState } = verifyPolicyTransitionContainer(container, resolved.expected);
  if (container?.State?.Running !== false) {
    fail('Native container must be stopped before mounted-folder recovery removal.', 'CONTAINER_TRANSITION_UNVERIFIED');
  }
  try {
    await execFileImpl(dockerBin, ['rm', containerId], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    fail('Unable to remove the verified Native container.', 'CONTAINER_REMOVE_FAILED', { cause: error });
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const remaining = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
    if (!remaining) {
      return Object.freeze({
        action: policyState === 'stale' ? 'removed-stale' : 'removed',
        containerId,
      });
    }
    if (remaining?.Id !== containerId) {
      fail('A different Native container appeared before removal could be confirmed.', 'CONTAINER_TRANSITION_UNVERIFIED');
    }
  }
  fail('Native container removal could not be confirmed.', 'CONTAINER_REMOVE_UNCONFIRMED');
}

export async function removeStaleElevatedContainer({
  imagePinPath,
  expectedLeaseId = null,
  containerName = NATIVE_CONTAINER_NAME,
  dockerBin = 'docker',
  execFileImpl = execFileAsync,
  hostUid = typeof process.getuid === 'function' ? process.getuid() : null,
  hostGid = typeof process.getgid === 'function' ? process.getgid() : null,
} = {}) {
  if (typeof imagePinPath !== 'string' || !path.isAbsolute(imagePinPath)) {
    fail('imagePinPath must be an absolute host path.', 'IMAGE_PIN_REQUIRED');
  }
  const imagePin = await loadImagePin(imagePinPath);
  await inspectNativeImage(imagePin, { dockerBin, execFileImpl });
  const container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
  if (!container) {
    return Object.freeze({ action: 'absent' });
  }
  const labels = container?.Config?.Labels ?? {};
  const leaseId = labels[NATIVE_ELEVATED_LEASE_LABEL] ?? null;
  // Rollback may arrive here after stop/remove failed before any elevated container existed.
  // A container without an elevation lease is not stale authority; ensureNormalContainer
  // performs the full normal-container verification later in the rollback sequence.
  if (leaseId === null) {
    return Object.freeze({ action: 'normal' });
  }
  if (expectedLeaseId !== null && leaseId !== expectedLeaseId) {
    fail('Elevated Native container does not match the expected lease identity.', 'ELEVATED_CONTAINER_UNVERIFIED');
  }
  const { containerId } = verifyManagedContainerIdentity(container, {
    image: imagePin.image,
    hostUid,
    hostGid,
    networkEnabled: false,
    elevationLeaseId: leaseId,
    errorMessage: 'Stale elevated Native container cannot be identified safely.',
    errorCode: 'ELEVATED_CONTAINER_UNVERIFIED',
  });
  const workspaceMount = Array.isArray(container?.Mounts)
    ? container.Mounts.find((mount) => mount?.Destination === '/workspace')
    : null;
  const gitMount = Array.isArray(container?.Mounts)
    ? container.Mounts.find((mount) => [NATIVE_GIT_KEY_PATH, NATIVE_GIT_KNOWN_HOSTS_PATH].includes(mount?.Destination))
    : null;
  const safelyIdentified = /^[0-9a-f]{64}$/i.test(leaseId)
    && workspaceMount?.RW === true
    && path.isAbsolute(workspaceMount?.Source ?? '')
    && !gitMount;
  if (!safelyIdentified) {
    fail('Stale elevated Native container cannot be identified safely.', 'ELEVATED_CONTAINER_UNVERIFIED');
  }
  try {
    await execFileImpl(dockerBin, ['rm', '-f', containerId], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    fail('Unable to remove the stale elevated Native container.', 'CONTAINER_REMOVE_FAILED', { cause: error });
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const remaining = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
    if (!remaining) {
      return Object.freeze({ action: 'removed', leaseId, containerId });
    }
    if (remaining?.Id !== containerId) {
      fail('A different Native container appeared before elevated revocation could be confirmed.', 'ELEVATED_CONTAINER_UNVERIFIED');
    }
  }
  fail('Elevated Native container removal could not be confirmed.', 'CONTAINER_REMOVE_UNCONFIRMED');
}

export async function ensureNativeContainer(options = {}) {
  const resolved = await resolveNativeContainerPolicy(options);
  const {
    dockerBin = 'docker',
    execFileImpl = execFileAsync,
    containerName = NATIVE_CONTAINER_NAME,
  } = options;

  let container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
  if (container) {
    verifyContainer(container, resolved.expected);
    if (container?.State?.Running === true) {
      return Object.freeze({ action: 'unchanged', policyDigest: resolved.policy.policyDigest, containerId: container.Id });
    }
    try {
      await execFileImpl(dockerBin, ['start', containerName], {
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,
      });
    } catch (error) {
      fail('Unable to restart the verified Native container.', 'CONTAINER_START_FAILED', { cause: error });
    }
    container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: containerName });
    if (!container || container?.State?.Running !== true) {
      fail('Native container did not become running after start.', 'CONTAINER_START_FAILED');
    }
    verifyContainer(container, resolved.expected);
    return Object.freeze({ action: 'started', policyDigest: resolved.policy.policyDigest, containerId: container.Id });
  }

  // `docker run --detach` prints the id of the container it just created. That is the only
  // statement of identity that comes from the create operation itself; any later lookup by the
  // shared name can return a container some other host operation put there.
  let createdContainerId;
  try {
    const { stdout } = await execFileImpl(resolved.policy.command, resolved.policy.args, {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    });
    createdContainerId = String(stdout ?? '').trim();
  } catch (error) {
    fail('Unable to create the Native container.', 'CONTAINER_CREATE_FAILED', { cause: error });
  }
  if (!/^[0-9a-f]{64}$/i.test(createdContainerId)) {
    fail('Docker did not report a usable id for the container it created.', 'CONTAINER_CREATE_FAILED');
  }

  // Everything from here on refers to that id. A failure now leaves a container this call owns, so
  // the id travels on the error: only the creator can prove which container is its own to remove.
  try {
    container = await inspectNativeContainer({ dockerBin, execFileImpl, containerRef: createdContainerId });
    if (!container || container?.State?.Running !== true) {
      fail('Native container was not running after creation.', 'CONTAINER_CREATE_FAILED');
    }
    verifyContainer(container, resolved.expected);
  } catch (error) {
    error.createdContainerId = createdContainerId;
    throw error;
  }
  return Object.freeze({ action: 'created', policyDigest: resolved.policy.policyDigest, containerId: createdContainerId });
}

function parseArgs(argv) {
  const options = {
    configPath: DEFAULT_WORKSPACE_CONFIG,
    imagePinPath: null,
    gitCredentialPath: null,
    gitKnownHostsPath: null,
    status: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) {
        throw new Error(`Missing value for ${arg}.`);
      }
      return argv[index];
    };
    if (arg === '--config') {
      options.configPath = next();
    } else if (arg === '--image-pin') {
      options.imagePinPath = next();
    } else if (arg === '--git-credential') {
      options.gitCredentialPath = next();
    } else if (arg === '--git-known-hosts') {
      options.gitKnownHostsPath = next();
    } else if (arg === '--status') {
      options.status = true;
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  if (!options.imagePinPath) {
    throw new Error('--image-pin is required.');
  }
  return options;
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
    return;
  }

  try {
    if (options.status) {
      const container = await inspectNativeContainer();
      process.stdout.write(`${JSON.stringify({
        present: Boolean(container),
        running: container?.State?.Running === true,
      })}\n`);
      return;
    }
    const result = await ensureNativeContainer(options);
    process.stdout.write(`Native WebMCP container: ${result.action}\n`);
  } catch (error) {
    process.stderr.write(`Native WebMCP container ensure failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (isMain) {
  await main();
}
