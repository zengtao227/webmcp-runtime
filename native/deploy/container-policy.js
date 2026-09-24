import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import {
  buildControlPlaneMaskArgs,
  buildControlPlaneMaskPlan,
  buildReadOnlyBindMountArgs,
  buildWorkspaceMountArgs,
  canonicalizeHostRoot,
  normalizeWorkspaceConfig,
} from './workspace-config.js';
import {
  buildWorkspaceMountMaskPlan,
  buildWorkspaceMountSetArgs,
  canonicalizeWorkspaceMountConfig,
} from './workspace-mount-config.js';

export const NATIVE_CONTAINER_NAME = 'webmcp-native';
export const NATIVE_GIT_KEY_PATH = '/run/secrets/webmcp-git-key';
export const NATIVE_GIT_KNOWN_HOSTS_PATH = '/run/secrets/webmcp-git-known-hosts';
export const NATIVE_ELEVATED_LEASE_LABEL = 'com.webmcp.native.elevated-lease';
const ELEVATED_LEASE_ID_PATTERN = /^[0-9a-f]{64}$/;

function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex');
}

export class ContainerPolicyError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ContainerPolicyError';
    this.code = code;
  }
}

async function canonicalRegularFile(filePath, label) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || filePath.includes('\0')) {
    throw new ContainerPolicyError(`${label} must be an absolute host path.`, 'INVALID_GIT_FILE');
  }
  try {
    const canonical = await realpath(filePath);
    const info = await lstat(canonical);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new ContainerPolicyError(`${label} must resolve to a regular file.`, 'INVALID_GIT_FILE');
    }
    return canonical;
  } catch (error) {
    if (error instanceof ContainerPolicyError) {
      throw error;
    }
    throw new ContainerPolicyError(`${label} cannot be resolved.`, 'INVALID_GIT_FILE');
  }
}

function assertImage(image) {
  if (typeof image !== 'string' || image.length === 0) {
    throw new ContainerPolicyError('Native image identity is required.', 'INVALID_NATIVE_IMAGE');
  }
  // Runtime deployments must use an immutable digest, never a mutable tag.
  if (!/@sha256:[0-9a-f]{64}$/i.test(image) && !/^sha256:[0-9a-f]{64}$/i.test(image)) {
    throw new ContainerPolicyError('Native image must be pinned by sha256 digest.', 'UNPINNED_NATIVE_IMAGE');
  }
}

export async function buildNativeContainerRun({
  config,
  mountConfig = null,
  home,
  image,
  containerName = NATIVE_CONTAINER_NAME,
  protectedPaths = [],
  gitCredentialPath = null,
  gitKnownHostsPath = null,
  elevationLeaseId = null,
  platform = process.platform,
  hostUid = typeof process.getuid === 'function' ? process.getuid() : null,
  hostGid = typeof process.getgid === 'function' ? process.getgid() : null,
} = {}) {
  assertImage(image);
  if (typeof containerName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(containerName)) {
    throw new ContainerPolicyError('Native container name is invalid.', 'INVALID_CONTAINER_NAME');
  }
  if (elevationLeaseId !== null && !ELEVATED_LEASE_ID_PATTERN.test(elevationLeaseId)) {
    throw new ContainerPolicyError('Temporary elevated container requires a valid lease identity.', 'INVALID_ELEVATION_LEASE_ID');
  }
  if (!Number.isInteger(hostUid) || hostUid <= 0 || !Number.isInteger(hostGid) || hostGid < 0) {
    throw new ContainerPolicyError(
      'Native runtime requires a non-root host owner UID/GID.',
      'INVALID_RUNTIME_IDENTITY',
    );
  }
  const normalized = normalizeWorkspaceConfig(config, { platform });
  const canonicalMountConfig = mountConfig === null
    ? null
    : await canonicalizeWorkspaceMountConfig(mountConfig, { platform, home });
  // Once multi-mount is active, hostRoot/readOnly are legacy compatibility metadata only:
  // they are not mounted and a stale/missing old hostRoot must not regain authority.
  const canonicalRoot = canonicalMountConfig === null
    ? await canonicalizeHostRoot(normalized.hostRoot, { platform })
    : path.resolve(normalized.hostRoot);
  if (canonicalMountConfig !== null && elevationLeaseId !== null) {
    throw new ContainerPolicyError(
      'Temporary elevation for multi-mount workspaces is not defined yet.',
      'MULTI_MOUNT_ELEVATION_UNSUPPORTED',
    );
  }

  let canonicalGitCredential = null;
  let canonicalGitKnownHosts = null;
  if (normalized.gitPublicationEnabled) {
    if (gitCredentialPath === null || gitKnownHostsPath === null) {
      throw new ContainerPolicyError(
        'Git publication requires both credential and known-hosts files.',
        'GIT_PUBLICATION_FILES_REQUIRED',
      );
    }
    canonicalGitCredential = await canonicalRegularFile(gitCredentialPath, 'Git credential');
    canonicalGitKnownHosts = await canonicalRegularFile(gitKnownHostsPath, 'Git known-hosts file');
  } else if (gitCredentialPath !== null || gitKnownHostsPath !== null) {
    throw new ContainerPolicyError(
      'Git credential files must not be supplied unless publication is explicitly enabled.',
      'UNAUTHORIZED_GIT_CREDENTIAL',
    );
  }

  const effectiveProtectedPaths = normalized.gitPublicationEnabled
    ? [...new Set([...protectedPaths, canonicalGitCredential, canonicalGitKnownHosts])]
    : protectedPaths;
  const maskPlan = canonicalMountConfig === null
    ? await buildControlPlaneMaskPlan({
      hostRoot: canonicalRoot,
      protectedPaths: effectiveProtectedPaths,
    })
    : await buildWorkspaceMountMaskPlan({
      mountConfig: canonicalMountConfig,
      protectedPaths: effectiveProtectedPaths,
    });
  const mountPolicyMarker = canonicalMountConfig === null
    ? null
    : Buffer.from(JSON.stringify(canonicalMountConfig.mounts.map((mount) => ({
      id: mount.id,
      path: mount.containerPath,
      writeEnabled: mount.writeEnabled,
    }))), 'utf8').toString('base64url');

  const policyDigest = sha256Text(JSON.stringify(canonicalMountConfig === null
    ? {
      version: 1,
      image,
      ...(containerName === NATIVE_CONTAINER_NAME ? {} : { containerName }),
      hostRoot: canonicalRoot,
      mode: normalized.mode,
      ...(normalized.readOnly ? { readOnly: true } : {}),
      networkEnabled: normalized.networkEnabled,
      gitPublicationEnabled: normalized.gitPublicationEnabled,
      gitUserName: normalized.gitUserName ?? null,
      gitUserEmail: normalized.gitUserEmail ?? null,
      gitCredentialSource: canonicalGitCredential,
      gitKnownHostsSource: canonicalGitKnownHosts,
      hostUid,
      hostGid,
      ...(elevationLeaseId === null ? {} : { elevationLeaseId }),
      masks: maskPlan.map(({ type, destination }) => ({ type, destination })),
    }
    : {
      version: 2,
      image,
      ...(containerName === NATIVE_CONTAINER_NAME ? {} : { containerName }),
      readOnlyRootFilesystem: true,
      writableTemp: '/tmp',
      mounts: canonicalMountConfig.mounts.map((mount) => ({
        id: mount.id,
        hostPath: mount.hostPath,
        containerPath: mount.containerPath,
        writeEnabled: mount.writeEnabled,
      })),
      mode: normalized.mode,
      networkEnabled: normalized.networkEnabled,
      gitPublicationEnabled: normalized.gitPublicationEnabled,
      gitUserName: normalized.gitUserName ?? null,
      gitUserEmail: normalized.gitUserEmail ?? null,
      gitCredentialSource: canonicalGitCredential,
      gitKnownHostsSource: canonicalGitKnownHosts,
      hostUid,
      hostGid,
      masks: maskPlan.map(({ type, destination }) => ({ type, destination })),
    }));

  const args = [
    'run',
    '--detach',
    '--name', containerName,
    '--label', `com.webmcp.native.policy-sha256=${policyDigest}`,
    '--label', `com.webmcp.native.image=${image}`,
    ...(elevationLeaseId === null ? [] : ['--label', `${NATIVE_ELEVATED_LEASE_LABEL}=${elevationLeaseId}`]),
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--user', `${hostUid}:${hostGid}`,
    '--env', 'HOME=/tmp',
    ...(canonicalMountConfig === null
      ? buildWorkspaceMountArgs(canonicalRoot, { readOnly: normalized.readOnly })
      : [
        '--read-only',
        '--mount', 'type=tmpfs,dst=/tmp,tmpfs-mode=1777',
        ...buildWorkspaceMountSetArgs(canonicalMountConfig),
      ]),
    ...buildControlPlaneMaskArgs(maskPlan),
  ];

  // The mount is the control; markers only let the Native tools describe the enforced state.
  if (canonicalMountConfig !== null) {
    args.push('--env', `WEBMCP_MOUNT_POLICY=${mountPolicyMarker}`);
  } else if (normalized.readOnly) {
    args.push('--env', 'WEBMCP_READ_ONLY=1');
  }

  if (!normalized.networkEnabled) {
    args.push('--network', 'none');
  }

  if (normalized.gitPublicationEnabled) {
    args.push(
      ...buildReadOnlyBindMountArgs(canonicalGitCredential, NATIVE_GIT_KEY_PATH),
      ...buildReadOnlyBindMountArgs(canonicalGitKnownHosts, NATIVE_GIT_KNOWN_HOSTS_PATH),
      '--env',
      `GIT_SSH_COMMAND=ssh -i ${NATIVE_GIT_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${NATIVE_GIT_KNOWN_HOSTS_PATH}`,
      '--env', `GIT_AUTHOR_NAME=${normalized.gitUserName}`,
      '--env', `GIT_AUTHOR_EMAIL=${normalized.gitUserEmail}`,
      '--env', `GIT_COMMITTER_NAME=${normalized.gitUserName}`,
      '--env', `GIT_COMMITTER_EMAIL=${normalized.gitUserEmail}`,
      '--env', 'GIT_TERMINAL_PROMPT=0',
    );
  }

  args.push(image, 'sleep', 'infinity');
  return Object.freeze({
    command: 'docker',
    args: Object.freeze(args),
    config: normalized,
    canonicalRoot,
    mounts: canonicalMountConfig?.mounts ?? null,
    readOnlyRootFilesystem: canonicalMountConfig !== null,
    mountPolicyMarker,
    maskPlan,
    policyDigest,
    gitCredentialSource: canonicalGitCredential,
    gitKnownHostsSource: canonicalGitKnownHosts,
    elevationLeaseId,
    containerName,
  });
}
