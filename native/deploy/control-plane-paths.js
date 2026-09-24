import { lstat, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_WORKSPACE_CONFIG } from './workspace-config.js';
import { linuxProtectedPaths } from './host-platform.js';

const MACOS_BROWSER_PROFILE_ROOTS = [
  'Google/Chrome', 'Google/Chrome Beta', 'Google/Chrome Canary', 'Chromium', 'Comet',
  'Arc/User Data', 'BraveSoftware/Brave-Browser', 'Microsoft Edge', 'Vivaldi',
];

// Resolve the actual owner home even when a launcher overrides HOME.
export function ownerHome() {
  const explicit = process.env.WEBMCP_OWNER_HOME;
  if (explicit && path.isAbsolute(explicit)) return explicit;
  try {
    return os.userInfo().homedir;
  } catch {
    return os.homedir();
  }
}

export function protectedHomePaths({ home = ownerHome(), platform = process.platform } = {}) {
  const candidates = [
    // Every instance must mask the whole WebMCP config namespace, not only its own
    // config directory, or an elevated instance could mutate another instance's authority.
    path.join(home, '.config', 'webmcp'),
    path.join(home, '.local', 'share', 'webmcp'),
    // Other WebMCP providers' control state (tunnel identity, leases, settings): one
    // provider's workspace must never reach another provider's authority.
    path.join(home, '.config', 'tunnel-client'),
    path.join(home, '.local', 'share', 'prism-webmcp'),
    path.join(home, '.prism-webmcp'),
    path.join(home, '.deepseek-webmcp'),
    path.join(home, '.chatgpt-embedded-panel'),
    path.join(home, '.docker'),
    path.join(home, '.ssh'),
    path.join(home, '.aws'),
    path.join(home, '.gnupg'),
    path.join(home, '.kube'),
    path.join(home, '.config', 'gh'),
    ...['.netrc', '.git-credentials', '.npmrc', '.zshrc', '.zprofile', '.zshenv', '.zsh_history', '.bashrc', '.bash_profile', '.bash_history', '.profile']
      .map((name) => path.join(home, name)),
  ];
  if (platform === 'darwin') {
    candidates.push(
      path.join(home, 'Library', 'Application Support', 'Firefox'),
      path.join(home, 'Library', 'Application Support', 'tunnel-client'),
      ...MACOS_BROWSER_PROFILE_ROOTS.map((root) => path.join(home, 'Library', 'Application Support', root)),
      path.join(home, 'Library', 'LaunchAgents'),
      path.join(home, 'Library', 'Keychains'),
      path.join(home, 'Library', 'Safari'),
      path.join(home, 'Library', 'Cookies'),
    );
  }
  if (platform === 'linux') candidates.push(...linuxProtectedPaths(home));
  return [...new Set(candidates.map((candidate) => path.resolve(candidate)))];
}

export async function defaultProtectedPaths({
  home = ownerHome(),
  configPath = DEFAULT_WORKSPACE_CONFIG,
  platform = process.platform,
} = {}) {
  const configDirectory = path.dirname(configPath);
  await mkdir(configDirectory, { recursive: true, mode: 0o700 });
  const existing = [];
  for (const candidate of new Set([...protectedHomePaths({ home, platform }), path.resolve(configDirectory)])) {
    try {
      await lstat(candidate);
      existing.push(candidate);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  return existing;
}
