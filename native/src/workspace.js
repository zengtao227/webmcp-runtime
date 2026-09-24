import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { mkdir, open, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { assertPathAllowed } from '../../gateway/path-policy/index.js';

export const NATIVE_WORKSPACE_ROOT = '/workspace';

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_MAX_COMMAND_BYTES = 64 * 1024;
const DEFAULT_MAX_TIMEOUT_MS = 300_000;
const BASH_TERMINATION_FALLBACK_MS = 1000;
const DEFAULT_READ_LINES = 200;
const MAX_READ_LINES = 5_000;
const SHELL_ENV_KEYS = Object.freeze([
  'HOME',
  'PATH',
  'LANG',
  'LC_ALL',
  'GIT_SSH_COMMAND',
  'GIT_AUTHOR_NAME',
  'GIT_AUTHOR_EMAIL',
  'GIT_COMMITTER_NAME',
  'GIT_COMMITTER_EMAIL',
  'GIT_TERMINAL_PROMPT',
]);

export class NativeWorkspaceError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'NativeWorkspaceError';
    this.code = code;
    this.details = details;
  }
}

function ensureString(value, name, { allowEmpty = false } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    throw new NativeWorkspaceError(`${name} must be a ${allowEmpty ? '' : 'non-empty '}string.`, 'invalid_argument');
  }
  return value;
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function normalizeRuntimeMountPolicies(root, value) {
  if (value === null) return null;
  if (!Array.isArray(value)) {
    throw new NativeWorkspaceError('Mounted-folder policy must be an array.', 'invalid_mount_policy');
  }
  const ids = new Set();
  const paths = new Set();
  const mounts = value.map((mount) => {
    if (!mount || typeof mount !== 'object' || Array.isArray(mount)) {
      throw new NativeWorkspaceError('Mounted-folder policy entry must be an object.', 'invalid_mount_policy');
    }
    const { id, path: mountPath, writeEnabled } = mount;
    if (typeof id !== 'string' || id.length === 0 || ids.has(id)) {
      throw new NativeWorkspaceError('Mounted-folder policy id is invalid or duplicated.', 'invalid_mount_policy');
    }
    if (typeof mountPath !== 'string' || !path.isAbsolute(mountPath)) {
      throw new NativeWorkspaceError('Mounted-folder policy path must be absolute.', 'invalid_mount_policy');
    }
    const resolvedPath = path.resolve(mountPath);
    const resolvedRoot = path.resolve(root);
    if (resolvedPath === resolvedRoot || !within(resolvedRoot, resolvedPath) || paths.has(resolvedPath)) {
      throw new NativeWorkspaceError('Mounted-folder policy path must be unique and below the workspace root.', 'invalid_mount_policy');
    }
    if (typeof writeEnabled !== 'boolean') {
      throw new NativeWorkspaceError('Mounted-folder writeEnabled must be boolean.', 'invalid_mount_policy');
    }
    ids.add(id);
    paths.add(resolvedPath);
    return Object.freeze({ id, path: resolvedPath, writeEnabled });
  });
  for (let left = 0; left < mounts.length; left += 1) {
    for (let right = left + 1; right < mounts.length; right += 1) {
      if (within(mounts[left].path, mounts[right].path) || within(mounts[right].path, mounts[left].path)) {
        throw new NativeWorkspaceError('Mounted-folder policy paths must not overlap.', 'invalid_mount_policy');
      }
    }
  }
  return Object.freeze(mounts);
}

export function decodeRuntimeMountPolicy(value) {
  if (value === undefined || value === null || value === '') return null;
  try {
    const decoded = Buffer.from(value, 'base64url').toString('utf8');
    const parsed = JSON.parse(decoded);
    if (!Array.isArray(parsed)) throw new Error('policy must be an array');
    return parsed;
  } catch (error) {
    throw new NativeWorkspaceError('Mounted-folder policy marker is invalid.', 'invalid_mount_policy', { cause: error?.message });
  }
}

function lineCount(text) {
  if (text.length === 0) {
    return 0;
  }
  return text.split('\n').length;
}

function countOccurrences(haystack, needle) {
  let count = 0;
  let offset = 0;
  for (;;) {
    const index = haystack.indexOf(needle, offset);
    if (index === -1) {
      return count;
    }
    count += 1;
    offset = index + Math.max(needle.length, 1);
  }
}

function buildShellEnvironment(source = process.env) {
  const env = {};
  for (const key of SHELL_ENV_KEYS) {
    if (typeof source[key] === 'string' && source[key].length > 0) {
      env[key] = source[key];
    }
  }
  env.HOME ??= '/tmp';
  env.PATH ??= '/usr/local/bin:/usr/bin:/bin';
  return env;
}

function applyExactEdits(source, edits) {
  if (!Array.isArray(edits) || edits.length === 0) {
    throw new NativeWorkspaceError('edits must contain at least one replacement.', 'invalid_edits');
  }

  const located = edits.map((edit, index) => {
    if (!edit || typeof edit !== 'object' || Array.isArray(edit)) {
      throw new NativeWorkspaceError(`edit ${index} must be an object.`, 'invalid_edits');
    }
    const oldText = ensureString(edit.oldText, `edits[${index}].oldText`);
    const newText = ensureString(edit.newText, `edits[${index}].newText`, { allowEmpty: true });
    const occurrences = countOccurrences(source, oldText);
    if (occurrences === 0) {
      throw new NativeWorkspaceError(`edit ${index} oldText was not found.`, 'edit_no_match');
    }
    if (occurrences !== 1) {
      throw new NativeWorkspaceError(`edit ${index} oldText must match exactly once.`, 'edit_non_unique');
    }
    const start = source.indexOf(oldText);
    return { start, end: start + oldText.length, oldText, newText };
  });

  const ordered = [...located].sort((a, b) => a.start - b.start);
  for (let index = 1; index < ordered.length; index += 1) {
    if (ordered[index].start < ordered[index - 1].end) {
      throw new NativeWorkspaceError('edit regions must not overlap.', 'edit_overlap');
    }
  }

  let output = source;
  for (const edit of [...located].sort((a, b) => b.start - a.start)) {
    output = `${output.slice(0, edit.start)}${edit.newText}${output.slice(edit.end)}`;
  }
  return output;
}

export function createWorkspaceRuntime({
  root = NATIVE_WORKSPACE_ROOT,
  maxFileBytes = DEFAULT_MAX_FILE_BYTES,
  maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
  maxCommandBytes = DEFAULT_MAX_COMMAND_BYTES,
  maxTimeoutMs = DEFAULT_MAX_TIMEOUT_MS,
  spawnImpl = spawn,
  realpathImpl = realpath,
  runtimeToken = randomBytes(18).toString('base64url'),
  readOnly = false,
  mountPolicies = null,
} = {}) {
  if (!path.isAbsolute(root)) {
    throw new NativeWorkspaceError('Workspace root must be absolute.', 'invalid_workspace_root');
  }
  const normalizedMountPolicies = normalizeRuntimeMountPolicies(root, mountPolicies);
  if (readOnly && normalizedMountPolicies !== null) {
    throw new NativeWorkspaceError('Legacy read-only and mounted-folder write policy cannot be active together.', 'invalid_mount_policy');
  }
  const workspaceId = `ws_${runtimeToken}`;
  let canonicalRootPromise = null;

  async function canonicalRoot() {
    if (!canonicalRootPromise) {
      canonicalRootPromise = realpathImpl(root).catch((error) => {
        canonicalRootPromise = null;
        throw new NativeWorkspaceError('Workspace root is unavailable.', 'workspace_unavailable', { cause: error?.code });
      });
    }
    return canonicalRootPromise;
  }

  // Docker mounts are the real authority boundary. These checks make tool errors describe the
  // owner-approved policy instead of surfacing only a bare EROFS that could be mistaken for a path bug.
  function assertWritablePath(candidate) {
    if (readOnly) {
      throw new NativeWorkspaceError(
        'This host is owner-protected and the workspace is mounted read-only. Ask the owner to switch this host back to read-write; do not write this content to a different host instead.',
        'workspace_read_only',
      );
    }
    if (normalizedMountPolicies === null) return;
    const mount = normalizedMountPolicies.find((entry) => within(entry.path, candidate));
    if (!mount) {
      throw new NativeWorkspaceError(
        'The requested write is outside every owner-mounted folder.',
        'workspace_write_not_mounted',
      );
    }
    if (!mount.writeEnabled) {
      throw new NativeWorkspaceError(
        `Write is disabled for mounted folder ${mount.id}.`,
        'workspace_write_disabled',
        { mountId: mount.id },
      );
    }
  }

  function assertWorkspaceId(candidate) {
    if (candidate !== workspaceId) {
      throw new NativeWorkspaceError('Workspace id is stale or invalid.', 'invalid_workspace_id');
    }
  }

  function assertWorkspacePathAllowed(policyPath) {
    try {
      assertPathAllowed(policyPath || '.');
    } catch (error) {
      throw new NativeWorkspaceError('Path denied by workspace policy.', error?.code ?? 'path_denied');
    }
  }

  async function resolveLexical(requestedPath, { allowRoot = false } = {}) {
    const value = ensureString(requestedPath, 'path');
    const rootReal = await canonicalRoot();

    let lexical;
    let policyPath;
    if (path.isAbsolute(value)) {
      lexical = path.resolve(value);
      if (!within(rootReal, lexical)) {
        throw new NativeWorkspaceError('Path escapes the workspace.', 'path_escape');
      }
      policyPath = path.relative(rootReal, lexical);
    } else {
      policyPath = value;
      lexical = path.resolve(rootReal, value);
      if (!within(rootReal, lexical)) {
        throw new NativeWorkspaceError('Path escapes the workspace.', 'path_escape');
      }
    }

    if (!allowRoot && lexical === rootReal) {
      throw new NativeWorkspaceError('A file path is required.', 'invalid_path');
    }

    assertWorkspacePathAllowed(policyPath);

    return { rootReal, lexical, relative: path.relative(rootReal, lexical) || '.' };
  }

  async function resolveExisting(requestedPath, options = {}) {
    const resolved = await resolveLexical(requestedPath, options);
    let actual;
    try {
      actual = await realpathImpl(resolved.lexical);
    } catch (error) {
      throw new NativeWorkspaceError('Path does not exist.', 'path_not_found', { cause: error?.code });
    }
    if (!within(resolved.rootReal, actual)) {
      throw new NativeWorkspaceError('Resolved path escapes the workspace.', 'path_escape');
    }
    assertWorkspacePathAllowed(path.relative(resolved.rootReal, actual));
    return { ...resolved, actual };
  }

  async function readTextFile(requestedPath) {
    const resolved = await resolveExisting(requestedPath);
    let handle;
    try {
      // `actual` has already been realpath-validated under the workspace. Open
      // that symlink-free target so legitimate in-workspace read symlinks work,
      // while O_NOFOLLOW still rejects a post-validation leaf swap.
      handle = await open(resolved.actual, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      const info = await handle.stat();
      if (!info.isFile()) {
        throw new NativeWorkspaceError('Path is not a regular file.', 'not_regular_file');
      }
      if (info.size > maxFileBytes) {
        throw new NativeWorkspaceError('File exceeds the Native read limit.', 'file_too_large');
      }
      return await handle.readFile({ encoding: 'utf8' });
    } catch (error) {
      if (error instanceof NativeWorkspaceError) {
        throw error;
      }
      throw new NativeWorkspaceError('Unable to read file.', 'read_failed', { cause: error?.code });
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  async function writeTextFile(requestedPath, content) {
    const text = ensureString(content, 'content', { allowEmpty: true });
    if (Buffer.byteLength(text, 'utf8') > maxFileBytes) {
      throw new NativeWorkspaceError('Content exceeds the Native write limit.', 'content_too_large');
    }

    const resolved = await resolveLexical(requestedPath);
    const parent = path.dirname(resolved.lexical);
    let parentReal;
    try {
      parentReal = await realpathImpl(parent);
    } catch (error) {
      throw new NativeWorkspaceError('Parent directory does not exist.', 'parent_not_found', { cause: error?.code });
    }
    if (!within(resolved.rootReal, parentReal)) {
      throw new NativeWorkspaceError('Parent directory escapes the workspace.', 'path_escape');
    }
    const canonicalDestination = path.join(parentReal, path.basename(resolved.lexical));
    assertWorkspacePathAllowed(path.relative(resolved.rootReal, canonicalDestination));
    assertWritablePath(canonicalDestination);

    let handle;
    try {
      handle = await open(
        canonicalDestination,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW,
        0o644,
      );
      await handle.writeFile(text, { encoding: 'utf8' });
    } catch (error) {
      throw new NativeWorkspaceError('Unable to write file.', 'write_failed', { cause: error?.code });
    } finally {
      await handle?.close().catch(() => {});
    }
    return Buffer.byteLength(text, 'utf8');
  }

  async function resolveWorkingDirectory(requestedDirectory) {
    if (requestedDirectory === undefined || requestedDirectory === null || requestedDirectory === '') {
      return canonicalRoot();
    }
    const resolved = await resolveExisting(requestedDirectory, { allowRoot: true });
    const info = await stat(resolved.actual);
    if (!info.isDirectory()) {
      throw new NativeWorkspaceError('workingDirectory must be a directory.', 'invalid_working_directory');
    }
    return resolved.actual;
  }

  async function runBash(command, { workingDirectory, timeout } = {}) {
    const script = ensureString(command, 'command');
    if (Buffer.byteLength(script, 'utf8') > maxCommandBytes) {
      throw new NativeWorkspaceError('Command exceeds the Native command limit.', 'command_too_large');
    }

    const timeoutSeconds = timeout === undefined ? 30 : Number(timeout);
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > maxTimeoutMs / 1000) {
      throw new NativeWorkspaceError(`timeout must be between 0 and ${maxTimeoutMs / 1000} seconds.`, 'invalid_timeout');
    }
    const cwd = await resolveWorkingDirectory(workingDirectory);

    return new Promise((resolve, reject) => {
      const child = spawnImpl('/bin/bash', ['-c', script], {
        cwd,
        env: buildShellEnvironment(process.env),
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true,
      });
      const chunks = [];
      let size = 0;
      let settled = false;
      let timer = null;
      let terminationFallback = null;
      let cancellationError = null;

      const finish = (fn, value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        clearTimeout(terminationFallback);
        fn(value);
      };

      const terminateProcessGroup = (error) => {
        if (settled || cancellationError) return;
        cancellationError = error;
        clearTimeout(timer);
        try {
          if (Number.isInteger(child.pid) && child.pid > 0) {
            process.kill(-child.pid, 'SIGKILL');
          } else {
            child.kill('SIGKILL');
          }
        } catch (killError) {
          if (killError?.code !== 'ESRCH') {
            try {
              child.kill('SIGKILL');
            } catch {
              // The bounded fallback below prevents an inherited pipe from
              // keeping the tool call pending forever if settlement never arrives.
            }
          }
        }
        terminationFallback = setTimeout(() => {
          finish(reject, cancellationError);
        }, BASH_TERMINATION_FALLBACK_MS);
      };

      const collect = (chunk) => {
        if (cancellationError) return;
        const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += piece.byteLength;
        if (size > maxOutputBytes) {
          terminateProcessGroup(new NativeWorkspaceError('Command output exceeded the Native limit.', 'output_too_large'));
          return;
        }
        chunks.push(piece);
      };

      child.stdout?.on('data', collect);
      child.stderr?.on('data', collect);
      child.on('error', (error) => {
        finish(reject, new NativeWorkspaceError('Unable to start bash.', 'bash_start_failed', { cause: error?.code }));
      });
      child.on('close', (code, signal) => {
        if (cancellationError) {
          finish(reject, cancellationError);
          return;
        }
        const result = Buffer.concat(chunks).toString('utf8');
        finish(resolve, { result, exitCode: code ?? 1, signal: signal ?? null });
      });

      timer = setTimeout(() => {
        terminateProcessGroup(new NativeWorkspaceError('Command timed out.', 'bash_timeout'));
      }, timeoutSeconds * 1000);
    });
  }

  return {
    root,
    workspaceId,
    async openWorkspace(requestedRoot) {
      if (requestedRoot !== NATIVE_WORKSPACE_ROOT) {
        throw new NativeWorkspaceError(`open_workspace accepts only ${NATIVE_WORKSPACE_ROOT}.`, 'invalid_workspace_root');
      }
      await canonicalRoot();
      if (normalizedMountPolicies !== null) {
        return {
          workspaceId,
          root: NATIVE_WORKSPACE_ROOT,
          mode: 'multi-mount',
          mounts: normalizedMountPolicies.map(({ id, path: mountPath, writeEnabled }) => ({
            id,
            path: mountPath,
            writeEnabled,
          })),
          instruction: 'Workspace opened with multiple owner-mounted folders. Reading is not disabled by the Write switches. Writes are allowed only inside mounted folders whose Write policy is ON; folders with Write OFF are also mounted read-only at the filesystem layer. Do not redirect a rejected write to another mounted folder or another host.',
        };
      }
      if (readOnly) {
        return {
          workspaceId,
          root: NATIVE_WORKSPACE_ROOT,
          mode: 'read-only',
          instruction: 'Workspace opened read-only. The /workspace mount on this host is read-only: reading and inspection work, and every write into /workspace fails at the filesystem layer. Paths outside /workspace, such as the container temp directory, are not covered by it. Do not create or refresh the workspace-owned semantic checkpoint and do not update /workspace/WEBMCP-RESUME.md; the resume protocol applies only before a modification, and no modification is possible here. Prefer read-only Git invocations such as `git --no-optional-locks status`, because ordinary Git commands may try to refresh the index and fail. If the task requires a write, stop and ask the owner to switch this host back to read-write; never write the content to a different host instead.',
        };
      }
      return {
        workspaceId,
        root: NATIVE_WORKSPACE_ROOT,
        mode: 'checkout',
        instruction: 'Workspace opened. Before the first modification for a task: locate the target project, read its AGENTS.md, apply the WebMCP resume protocol, create or refresh the workspace-owned semantic checkpoint under /workspace/.webmcp/resumes/, and update /workspace/WEBMCP-RESUME.md as a pointer only. During recovery, read the referenced checkpoint and inspect Git/filesystem state; actual Git/filesystem state is authoritative.',
      };
    },
    async read({ workspaceId: candidate, path: requestedPath, offset = 1, limit = DEFAULT_READ_LINES }) {
      assertWorkspaceId(candidate);
      const firstLine = Number(offset);
      const lineLimit = Number(limit);
      if (!Number.isInteger(firstLine) || firstLine < 1) {
        throw new NativeWorkspaceError('offset must be a positive integer.', 'invalid_offset');
      }
      if (!Number.isInteger(lineLimit) || lineLimit < 1 || lineLimit > MAX_READ_LINES) {
        throw new NativeWorkspaceError(`limit must be between 1 and ${MAX_READ_LINES}.`, 'invalid_limit');
      }
      const text = await readTextFile(requestedPath);
      const lines = text.split('\n');
      const selected = lines.slice(firstLine - 1, firstLine - 1 + lineLimit).join('\n');
      const hasMore = firstLine - 1 + lineLimit < lines.length;
      return {
        result: selected,
        nextOffset: hasMore ? firstLine + lineLimit : null,
      };
    },
    async write({ workspaceId: candidate, path: requestedPath, content }) {
      assertWorkspaceId(candidate);
      const bytes = await writeTextFile(requestedPath, content);
      return { result: `Successfully wrote ${bytes} bytes to ${requestedPath}` };
    },
    async edit({ workspaceId: candidate, path: requestedPath, edits }) {
      assertWorkspaceId(candidate);
      const before = await readTextFile(requestedPath);
      const after = applyExactEdits(before, edits);
      await writeTextFile(requestedPath, after);
      const added = Math.max(0, lineCount(after) - lineCount(before));
      const removed = Math.max(0, lineCount(before) - lineCount(after));
      return {
        status: 'applied',
        result: `Edited ${requestedPath} (+${added} -${removed}).`,
      };
    },
    async bash({ workspaceId: candidate, command, workingDirectory, timeout }) {
      assertWorkspaceId(candidate);
      const completed = await runBash(command, { workingDirectory, timeout });
      if (completed.exitCode !== 0) {
        throw new NativeWorkspaceError(
          completed.result || `Command exited with status ${completed.exitCode}.`,
          'bash_failed',
          { exitCode: completed.exitCode, signal: completed.signal },
        );
      }
      return { result: completed.result };
    },
  };
}
