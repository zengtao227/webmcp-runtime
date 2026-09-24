import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const WORKSPACE_CONFIG_VERSION = 1;
export const DEFAULT_WORKSPACE_CONFIG = path.join(os.homedir(), '.config', 'webmcp', 'workspace.json');
export const CONTAINER_WORKSPACE_ROOT = '/workspace';
export const WORKSPACE_MODES = Object.freeze(['project', 'workspace', 'advanced']);

export class WorkspaceConfigError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'WorkspaceConfigError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new WorkspaceConfigError(message, code, options);
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function assertExactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail(`${label} contains unsupported key: ${key}`, 'INVALID_WORKSPACE_CONFIG');
    }
  }
}

// A Linux workspace is one narrow directory the owner names. The filesystem root, system directories and
// the container runtimes' state are never a workspace, whatever the owner types.
const LINUX_UNSAFE_ROOTS = Object.freeze([
  '/bin', '/boot', '/dev', '/etc', '/lib', '/lib64', '/proc', '/root', '/run', '/sbin', '/sys', '/usr',
  '/var/run', '/var/lib/docker', '/var/lib/containerd', '/var/lib/containers',
]);

function assertLinuxWorkspaceRoot(hostRoot) {
  const resolved = path.resolve(hostRoot);
  const unsafe = resolved === '/'
    || resolved === '/home'
    || LINUX_UNSAFE_ROOTS.some((root) => resolved === root || resolved.startsWith(`${root}/`));
  if (unsafe) {
    fail(`On Linux the workspace must be a narrow directory of its own, not ${resolved}. Choose a dedicated directory owned by the runtime user.`, 'LINUX_WORKSPACE_ROOT_UNSAFE');
  }
}

export function normalizeWorkspaceConfig(value, { platform = process.platform } = {}) {
  if (!isPlainObject(value)) {
    fail('Workspace config must be an object.', 'INVALID_WORKSPACE_CONFIG');
  }
  assertExactKeys(
    value,
    new Set([
      'version',
      'hostRoot',
      'mode',
      'readOnly',
      'networkEnabled',
      'gitPublicationEnabled',
      'gitUserName',
      'gitUserEmail',
    ]),
    'Workspace config',
  );

  if (value.version !== WORKSPACE_CONFIG_VERSION) {
    fail(`Workspace config version must be ${WORKSPACE_CONFIG_VERSION}.`, 'INVALID_WORKSPACE_CONFIG');
  }
  if (typeof value.hostRoot !== 'string' || value.hostRoot.length === 0 || !path.isAbsolute(value.hostRoot) || value.hostRoot.includes('\0')) {
    fail('hostRoot must be a non-empty absolute path.', 'INVALID_WORKSPACE_ROOT');
  }
  if (!WORKSPACE_MODES.includes(value.mode)) {
    fail(`mode must be one of: ${WORKSPACE_MODES.join(', ')}.`, 'INVALID_WORKSPACE_CONFIG');
  }
  if (platform === 'linux') {
    // 'advanced' is the macOS temporary-elevation shape (a wider root); Linux has no elevation, so it never applies.
    if (value.mode === 'advanced') {
      fail('Linux hosts support only a narrow owner-selected workspace; advanced (elevated) mode is not available.', 'LINUX_ADVANCED_MODE_UNSUPPORTED');
    }
    assertLinuxWorkspaceRoot(value.hostRoot);
  }
  if (platform === 'darwin' && path.resolve(value.hostRoot) === '/') {
    fail('Docker Desktop does not expose the macOS root as a faithful host filesystem root. Select /Users/<user>, /Volumes/<volume>, or another explicit host path.', 'MACOS_ROOT_UNSUPPORTED');
  }

  const defaultNetwork = value.mode !== 'advanced';
  const networkEnabled = value.networkEnabled ?? defaultNetwork;
  if (typeof networkEnabled !== 'boolean') {
    fail('networkEnabled must be boolean.', 'INVALID_WORKSPACE_CONFIG');
  }
  const readOnly = value.readOnly ?? false;
  if (typeof readOnly !== 'boolean') {
    fail('readOnly must be boolean.', 'INVALID_WORKSPACE_CONFIG');
  }
  const gitPublicationEnabled = value.gitPublicationEnabled ?? false;
  if (typeof gitPublicationEnabled !== 'boolean') {
    fail('gitPublicationEnabled must be boolean.', 'INVALID_WORKSPACE_CONFIG');
  }

  const gitUserName = value.gitUserName ?? null;
  const gitUserEmail = value.gitUserEmail ?? null;
  const validGitIdentity = (candidate) => typeof candidate === 'string'
    && candidate.length > 0
    && candidate.length <= 256
    && !/[\r\n\0]/.test(candidate);
  if (gitPublicationEnabled) {
    if (!validGitIdentity(gitUserName) || !validGitIdentity(gitUserEmail)) {
      fail('Git publication requires gitUserName and gitUserEmail.', 'INVALID_GIT_IDENTITY');
    }
  } else if (gitUserName !== null || gitUserEmail !== null) {
    fail('Git identity must not be configured unless Git publication is enabled.', 'INVALID_GIT_IDENTITY');
  }

  return Object.freeze({
    version: WORKSPACE_CONFIG_VERSION,
    hostRoot: path.resolve(value.hostRoot),
    mode: value.mode,
    readOnly,
    networkEnabled,
    gitPublicationEnabled,
    ...(gitPublicationEnabled ? { gitUserName, gitUserEmail } : {}),
  });
}

export function parseWorkspaceConfig(text, options = {}) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    fail('Workspace config is not valid JSON.', 'INVALID_WORKSPACE_CONFIG', { cause: error });
  }
  return normalizeWorkspaceConfig(parsed, options);
}

export async function loadWorkspaceConfig(configPath = DEFAULT_WORKSPACE_CONFIG, options = {}) {
  let text;
  try {
    text = await readFile(configPath, 'utf8');
  } catch (error) {
    fail(`Unable to read workspace config: ${configPath}`, 'WORKSPACE_CONFIG_UNAVAILABLE', { cause: error });
  }
  return parseWorkspaceConfig(text, options);
}

export async function persistWorkspaceConfig(configPath, value, options = {}) {
  const normalized = normalizeWorkspaceConfig(value, options);
  const directory = path.dirname(configPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(directory, `.${path.basename(configPath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(temporary, configPath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    fail(`Unable to persist workspace config: ${configPath}`, 'WORKSPACE_CONFIG_WRITE_FAILED', { cause: error });
  }
  return normalized;
}

export async function canonicalizeHostRoot(hostRoot, { platform = process.platform } = {}) {
  const draft = normalizeWorkspaceConfig({
    version: WORKSPACE_CONFIG_VERSION,
    hostRoot,
    mode: 'workspace',
  }, { platform });

  let canonical;
  let info;
  try {
    canonical = await realpath(draft.hostRoot);
    info = await lstat(canonical);
  } catch (error) {
    fail(`Workspace root cannot be resolved: ${draft.hostRoot}`, 'INVALID_WORKSPACE_ROOT', { cause: error });
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    fail('Workspace root must resolve to a real directory.', 'INVALID_WORKSPACE_ROOT');
  }
  if (platform === 'linux') {
    // The container runs as the runtime user's uid:gid, so the workspace must belong to that user. Nothing is
    // chmod'ed or ACL'ed to make another owner work; a directory owned by someone else is refused.
    assertLinuxWorkspaceRoot(canonical);
    if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
      fail('On Linux the workspace directory must be owned by the runtime user.', 'LINUX_WORKSPACE_NOT_OWNED');
    }
  }
  return canonical;
}

function assertDockerMountValue(value, label) {
  if (typeof value !== 'string' || value.length === 0 || /[,\n\r\0]/.test(value)) {
    fail(`${label} contains a character that cannot be represented safely in Docker --mount syntax.`, 'UNSUPPORTED_MOUNT_PATH');
  }
}

function dockerBindSpec(source, destination, { readonly = false, recursive = true } = {}) {
  assertDockerMountValue(source, 'Docker mount source');
  assertDockerMountValue(destination, 'Docker mount destination');
  const parts = [
    'type=bind',
    `src=${source}`,
    `dst=${destination}`,
  ];
  if (!recursive) {
    parts.push('bind-recursive=disabled');
  }
  if (readonly) {
    parts.push('readonly');
  }
  return parts.join(',');
}

export function buildWorkspaceMountArgs(hostRoot, {
  readOnly = false,
  destination = CONTAINER_WORKSPACE_ROOT,
} = {}) {
  if (typeof hostRoot !== 'string' || !path.isAbsolute(hostRoot) || hostRoot.includes('\0')) {
    fail('Workspace mount source must be an absolute path.', 'INVALID_WORKSPACE_ROOT');
  }
  if (typeof destination !== 'string' || !path.posix.isAbsolute(destination) || destination.includes('\0')) {
    fail('Workspace mount destination must be an absolute container path.', 'INVALID_WORKSPACE_MOUNT_DESTINATION');
  }
  // Read-only is enforced by the kernel through this mount, not by tool-level checks.
  return ['--mount', dockerBindSpec(hostRoot, destination, { recursive: false, readonly: readOnly })];
}

export function buildReadOnlyBindMountArgs(source, destination) {
  return ['--mount', dockerBindSpec(source, destination, { readonly: true })];
}

export async function buildControlPlaneMaskPlan({ hostRoot, protectedPaths = [] }) {
  if (!path.isAbsolute(hostRoot)) {
    fail('hostRoot must be absolute.', 'INVALID_WORKSPACE_ROOT');
  }

  let canonicalRoot;
  try {
    canonicalRoot = await realpath(hostRoot);
  } catch (error) {
    fail(`Unable to canonicalize workspace root: ${hostRoot}`, 'INVALID_WORKSPACE_ROOT', { cause: error });
  }

  const plan = [];
  for (const protectedPath of protectedPaths) {
    if (typeof protectedPath !== 'string' || !path.isAbsolute(protectedPath)) {
      fail('Protected control-plane paths must be absolute.', 'INVALID_CONTROL_PLANE_PATH');
    }

    let canonicalProtected;
    let info;
    try {
      canonicalProtected = await realpath(protectedPath);
      info = await lstat(canonicalProtected);
    } catch (error) {
      fail(`Unable to canonicalize protected control-plane path: ${protectedPath}`, 'CONTROL_PLANE_PATH_UNAVAILABLE', { cause: error });
    }

    if (isWithin(canonicalProtected, canonicalRoot)) {
      fail('Workspace root must not be the WebMCP control-plane root.', 'CONTROL_PLANE_ROOT_CONFLICT');
    }
    if (!isWithin(canonicalRoot, canonicalProtected)) {
      continue;
    }

    const relative = path.relative(canonicalRoot, canonicalProtected).split(path.sep).join('/');
    const destination = `${CONTAINER_WORKSPACE_ROOT}/${relative}`;
    if (info.isDirectory() && !info.isSymbolicLink()) {
      plan.push(Object.freeze({ type: 'directory', source: canonicalProtected, destination }));
    } else if (info.isFile() && !info.isSymbolicLink()) {
      plan.push(Object.freeze({ type: 'file', source: canonicalProtected, destination }));
    } else {
      fail(`Protected control-plane path must resolve to a regular file or directory: ${protectedPath}`, 'INVALID_CONTROL_PLANE_PATH');
    }
  }
  return Object.freeze(plan.filter((item) => !plan.some((other) => (
    other !== item && other.type === 'directory' && isWithin(other.source, item.source)
  ))));
}

export function buildControlPlaneMaskArgs(maskPlan) {
  const args = [];
  for (const item of maskPlan) {
    if (item.type === 'file') {
      args.push('--mount', dockerBindSpec('/dev/null', item.destination, { readonly: true }));
      continue;
    }
    if (item.type === 'directory') {
      args.push('--mount', `type=tmpfs,dst=${item.destination},readonly,tmpfs-mode=000`);
      continue;
    }
    fail(`Unsupported control-plane mask type: ${item.type}`, 'INVALID_CONTROL_PLANE_MASK');
  }
  return args;
}

function probeScript() {
  return String.raw`
const fs = require('fs');
const path = require('path');
const sentinel = process.argv[1];
const nonce = process.argv[2];
const masks = JSON.parse(Buffer.from(process.argv[3], 'base64url').toString('utf8'));
const actual = fs.readFileSync(path.join('/workspace', sentinel), 'utf8');
if (actual !== nonce) process.exit(41);
for (const mask of masks) {
  if (mask.type === 'file') {
    let value = '';
    try { value = fs.readFileSync(mask.destination, 'utf8'); } catch {}
    if (value.length !== 0) process.exit(42);
  } else if (mask.type === 'directory') {
    let entries = [];
    try { entries = fs.readdirSync(mask.destination); } catch {}
    if (entries.length !== 0) process.exit(43);
  }
}
process.stdout.write('verified');
`;
}

export async function verifyWorkspaceMount({
  hostRoot,
  image,
  protectedPaths = [],
  dockerBin = 'docker',
  execFileImpl = execFileAsync,
  platform = process.platform,
} = {}) {
  if (
    typeof image !== 'string'
    || (!/@sha256:[0-9a-f]{64}$/i.test(image) && !/^sha256:[0-9a-f]{64}$/i.test(image))
  ) {
    fail('A probe image pinned by sha256 digest is required.', 'INVALID_PROBE_IMAGE');
  }
  const canonicalRoot = await canonicalizeHostRoot(hostRoot, { platform });
  const maskPlan = await buildControlPlaneMaskPlan({ hostRoot: canonicalRoot, protectedPaths });
  const sentinelName = `.webmcp-mount-probe-${randomBytes(12).toString('hex')}`;
  const nonce = randomBytes(24).toString('base64url');
  const sentinelPath = path.join(canonicalRoot, sentinelName);
  let handle;

  try {
    handle = await open(sentinelPath, 'wx', 0o600);
    await handle.writeFile(nonce, 'utf8');
    await handle.close();
    handle = null;

    const args = [
      'run',
      '--rm',
      '--read-only',
      '--network', 'none',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      // On Linux the sentinel is a 0600 file owned by the runtime user and bind mounts are not uid-mapped, so
      // the probe must run as that same user (as the runtime container does) or it cannot read it.
      ...(platform === 'linux' ? ['--user', `${process.getuid()}:${process.getgid()}`] : []),
      ...buildWorkspaceMountArgs(canonicalRoot),
      ...buildControlPlaneMaskArgs(maskPlan),
      image,
      'node',
      '-e',
      probeScript(),
      sentinelName,
      nonce,
      Buffer.from(JSON.stringify(maskPlan.map(({ type, destination }) => ({ type, destination }))), 'utf8').toString('base64url'),
    ];

    let stdout;
    try {
      ({ stdout } = await execFileImpl(dockerBin, args, {
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,
      }));
    } catch (error) {
      fail('Workspace mount identity/control-plane probe failed.', 'WORKSPACE_PROBE_FAILED', { cause: error });
    }
    if (stdout !== 'verified') {
      fail('Workspace mount probe returned an unexpected result.', 'WORKSPACE_PROBE_FAILED');
    }
    return Object.freeze({ canonicalRoot, maskPlan });
  } finally {
    await handle?.close().catch(() => {});
    await rm(sentinelPath, { force: true }).catch(() => {});
  }
}
