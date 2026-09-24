import path from 'node:path';
import { NATIVE_CONTAINER_NAME } from './container-policy.js';
import { fail } from './installer-error.js';

export function hostPlatform(platform) {
  if (platform === 'darwin' || platform === 'linux') return platform;
  return fail(`Unsupported execution-host platform: ${platform || 'unknown'}. Supported: macOS and Linux.`, 'UNSUPPORTED_PLATFORM');
}

export function linuxProtectedPaths(home) {
  return [
    path.join(home, '.local', 'share', 'webmcp'),
    path.join(home, '.config', 'webmcp'),
    path.join(home, '.config', 'systemd'),
    path.join(home, '.ssh'),
  ].map((candidate) => path.resolve(candidate));
}

export function hostPathEnvironment(paths) {
  return Object.freeze({
    WEBMCP_WORKSPACE_CONFIG: paths.workspaceConfig,
    ...(paths.workspaceMountConfig ? { WEBMCP_WORKSPACE_MOUNT_CONFIG: paths.workspaceMountConfig } : {}),
    WEBMCP_NATIVE_IMAGE_PIN: paths.imagePin,
    WEBMCP_ELEVATED_LEASE: paths.elevatedLease,
    WEBMCP_OWNER_HOME: paths.home,
    ...(paths.containerName && paths.containerName !== NATIVE_CONTAINER_NAME
      ? {
        WEBMCP_NATIVE_CONTAINER: paths.containerName,
        ...(paths.lifecycleLock ? { WEBMCP_LIFECYCLE_LOCK: paths.lifecycleLock } : {}),
        ...(paths.attachmentGeneration
          ? { WEBMCP_ATTACHMENT_GENERATION: paths.attachmentGeneration }
          : {}),
      }
      : {}),
  });
}
