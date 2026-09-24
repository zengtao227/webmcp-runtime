#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const MANIFEST_NAME = 'manifest.json';
const MANIFEST_SCHEMA_VERSION = 1;

export class HostRuntimeError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'HostRuntimeError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new HostRuntimeError(message, code, options);
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function normalizePayloadPaths(payloadPaths, entrypoint) {
  if (!Array.isArray(payloadPaths) || payloadPaths.length === 0) {
    fail('Host runtime payload must contain at least one file.', 'INVALID_PAYLOAD');
  }
  if (
    typeof entrypoint !== 'string'
    || entrypoint.length === 0
    || path.isAbsolute(entrypoint)
    || entrypoint.includes('\0')
    || entrypoint.split(/[\\/]/).includes('..')
  ) {
    fail('Host runtime entrypoint must be a safe relative payload path.', 'INVALID_PAYLOAD');
  }
  const normalized = [...new Set(payloadPaths)].sort();
  if (normalized.length !== payloadPaths.length) {
    fail('Host runtime payload contains duplicate paths.', 'INVALID_PAYLOAD');
  }
  for (const relativePath of normalized) {
    if (
      typeof relativePath !== 'string'
      || relativePath.length === 0
      || path.isAbsolute(relativePath)
      || relativePath.includes('\0')
      || relativePath.split(/[\\/]/).includes('..')
    ) {
      fail(`Invalid host runtime payload path: ${String(relativePath)}`, 'INVALID_PAYLOAD');
    }
  }
  if (!normalized.includes(entrypoint)) {
    fail(`Host runtime payload must include ${entrypoint}.`, 'INVALID_PAYLOAD');
  }
  return normalized;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function runGitText(sourceRoot, args) {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd: sourceRoot,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    return stdout;
  } catch (error) {
    fail(`Git verification failed: git ${args.join(' ')}`, 'GIT_VERIFICATION_FAILED', { cause: error });
  }
}

async function runGitBuffer(sourceRoot, args) {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd: sourceRoot,
      encoding: 'buffer',
      maxBuffer: 16 * 1024 * 1024,
    });
    return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  } catch (error) {
    fail(`Git payload read failed: git ${args.join(' ')}`, 'GIT_PAYLOAD_READ_FAILED', { cause: error });
  }
}

function outputMode(relativePath, entrypoint) {
  return relativePath === entrypoint ? 0o700 : 0o600;
}

function payloadDigest(files) {
  const digest = createHash('sha256');
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    digest.update(file.path);
    digest.update('\0');
    digest.update(file.sha256);
    digest.update('\0');
    digest.update(String(file.size));
    digest.update('\0');
    digest.update(file.mode);
    digest.update('\n');
  }
  return digest.digest('hex');
}

async function resolveWritableBoundary(root, label) {
  let absolute;
  let canonical;
  let canonicalStat;
  try {
    absolute = path.resolve(root);
    canonical = await realpath(absolute);
    canonicalStat = await lstat(canonical);
  } catch (error) {
    fail(`Unable to verify ${label}: ${String(root)}`, 'UNSAFE_WRITABLE_ROOT', { cause: error });
  }
  if (!canonicalStat.isDirectory() || canonicalStat.isSymbolicLink()) {
    fail(`${label} must resolve to a real directory: ${absolute}`, 'UNSAFE_WRITABLE_ROOT');
  }
  return Object.freeze({ absolute, canonical });
}

async function ensureHostOnlyRoot({
  sourceRoot,
  runtimeRoot,
  defaultWritableRoot,
  additionalWritableRoots,
}) {
  const declaredBoundaries = [
    ['source root', sourceRoot],
    ['default writable root', defaultWritableRoot],
    ...additionalWritableRoots.map((root, index) => [`additional writable root ${index + 1}`, root]),
  ];
  const boundaries = [];
  const seen = new Set();
  for (const [label, root] of declaredBoundaries) {
    const boundary = await resolveWritableBoundary(root, label);
    for (const candidate of [boundary.absolute, boundary.canonical]) {
      if (!seen.has(candidate)) {
        seen.add(candidate);
        boundaries.push(candidate);
      }
    }
  }

  const runtimeResolved = path.resolve(runtimeRoot);
  if (boundaries.some((boundary) => isWithin(boundary, runtimeResolved))) {
    fail('Host runtime root must be outside every WebMCP-writable root.', 'UNSAFE_RUNTIME_ROOT');
  }

  try {
    await mkdir(runtimeResolved, { recursive: true, mode: 0o700 });
  } catch (error) {
    fail('Unable to create the host runtime root safely.', 'UNSAFE_RUNTIME_ROOT', { cause: error });
  }

  let runtimeStat;
  let runtimeReal;
  try {
    runtimeStat = await lstat(runtimeResolved);
    runtimeReal = await realpath(runtimeResolved);
  } catch (error) {
    fail('Unable to verify the host runtime root safely.', 'UNSAFE_RUNTIME_ROOT', { cause: error });
  }
  if (runtimeStat.isSymbolicLink() || !runtimeStat.isDirectory()) {
    fail('Host runtime root must be a real directory, not a symlink.', 'UNSAFE_RUNTIME_ROOT');
  }
  if (boundaries.some((boundary) => isWithin(boundary, runtimeReal))) {
    fail('Host runtime root must be outside every WebMCP-writable root.', 'UNSAFE_RUNTIME_ROOT');
  }
  return Object.freeze({ runtimeReal, writableBoundaries: boundaries });
}

export async function inspectSource({
  sourceRoot,
  payloadPaths,
  entrypoint,
}) {
  const normalizedPayload = normalizePayloadPaths(payloadPaths, entrypoint);
  const sourceAbsolute = path.resolve(sourceRoot);
  const sourceReal = await realpath(sourceAbsolute);
  const gitRoot = (await runGitText(sourceReal, ['rev-parse', '--show-toplevel'])).trim();
  const gitRootReal = await realpath(gitRoot);
  if (gitRootReal !== sourceReal) {
    fail('Source root must be the Git repository root.', 'INVALID_SOURCE_ROOT');
  }
  const gitCommit = (await runGitText(sourceReal, ['rev-parse', 'HEAD'])).trim();
  if (!/^[0-9a-f]{40}$/.test(gitCommit)) {
    fail('Unable to resolve an exact Git commit for the runtime source.', 'INVALID_GIT_COMMIT');
  }

  // Validate the declared source objects before the dirty check so missing or
  // malformed tracked files fail with a precise source-integrity error.
  for (const relativePath of normalizedPayload) {
    const sourcePath = path.join(sourceReal, relativePath);
    let sourceStat;
    try {
      sourceStat = await lstat(sourcePath);
    } catch (error) {
      fail(`Required runtime source is missing: ${relativePath}`, 'MISSING_RUNTIME_SOURCE', { cause: error });
    }
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
      fail(`Runtime source must be a regular non-symlink file: ${relativePath}`, 'MALFORMED_RUNTIME_SOURCE');
    }
    const treeLine = (await runGitText(sourceReal, ['ls-tree', 'HEAD', '--', relativePath])).trim();
    const match = treeLine.match(/^([0-7]{6})\s+blob\s+[0-9a-f]{40}\t(.+)$/);
    if (!match) {
      const untracked = (await runGitText(sourceReal, [
        'ls-files',
        '--others',
        '--exclude-standard',
        '--',
        relativePath,
      ])).trim();
      if (untracked === relativePath) {
        fail(`Runtime payload path is untracked: ${relativePath}`, 'DIRTY_RUNTIME_SOURCE');
      }
      fail(`Runtime source is not a tracked Git blob: ${relativePath}`, 'MALFORMED_RUNTIME_SOURCE');
    }
    if (match[2] !== relativePath || match[1] === '120000') {
      fail(`Runtime source is not a regular tracked Git blob: ${relativePath}`, 'MALFORMED_RUNTIME_SOURCE');
    }
  }

  const dirty = await runGitText(sourceReal, [
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
    '--',
    ...normalizedPayload,
  ]);
  if (dirty.trim().length > 0) {
    fail('Runtime payload source is dirty or contains an untracked payload file.', 'DIRTY_RUNTIME_SOURCE');
  }

  const files = [];
  for (const relativePath of normalizedPayload) {
    const sourcePath = path.join(sourceReal, relativePath);
    const [headBytes, workingBytes] = await Promise.all([
      runGitBuffer(sourceReal, ['show', `HEAD:${relativePath}`]),
      readFile(sourcePath),
    ]);
    if (!headBytes.equals(workingBytes)) {
      fail(`Runtime source differs from HEAD: ${relativePath}`, 'DIRTY_RUNTIME_SOURCE');
    }

    // Defense in depth: reject literal absolute backreferences to either the
    // lexical checkout path or its canonical realpath. This catches filesystem
    // aliases such as macOS /var/... -> /private/var/..., but does not claim to
    // recognize every dynamically constructed path.
    const repositoryBackreferences = [...new Set([sourceAbsolute, sourceReal])];
    if (repositoryBackreferences.some((candidate) => headBytes.includes(Buffer.from(candidate, 'utf8')))) {
      fail(`Runtime payload contains an absolute backreference to the writable repository: ${relativePath}`, 'REPOSITORY_BACKREFERENCE');
    }

    files.push(Object.freeze({
      path: relativePath,
      bytes: headBytes,
      sha256: sha256(headBytes),
      size: headBytes.length,
      mode: outputMode(relativePath, entrypoint).toString(8).padStart(4, '0'),
    }));
  }

  const digest = payloadDigest(files);
  const artifactId = `${gitCommit}-${digest}`;
  return Object.freeze({
    gitCommit,
    artifactId,
    payloadSha256: digest,
    files: Object.freeze(files),
  });
}

async function listReleaseFiles(root, current = '') {
  const directory = path.join(root, current);
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relativePath = current ? path.join(current, entry.name) : entry.name;
    const absolutePath = path.join(root, relativePath);
    const stat = await lstat(absolutePath);
    if (stat.isSymbolicLink()) {
      fail(`Runtime snapshot contains a symlink: ${relativePath}`, 'RUNTIME_SYMLINK_DETECTED');
    }
    if (stat.isDirectory()) {
      files.push(...await listReleaseFiles(root, relativePath));
      continue;
    }
    if (!stat.isFile()) {
      fail(`Runtime snapshot contains an unsupported filesystem object: ${relativePath}`, 'MALFORMED_RELEASE');
    }
    files.push(relativePath.split(path.sep).join('/'));
  }
  return files.sort();
}

export async function verifyRelease(releaseDir, {
  expectedArtifactId = null,
  expectedPayloadSha256 = null,
  entrypoint,
} = {}) {
  const releaseStat = await lstat(releaseDir);
  if (!releaseStat.isDirectory() || releaseStat.isSymbolicLink()) {
    fail('Runtime release must be a real directory.', 'MALFORMED_RELEASE');
  }

  let manifest;
  try {
    manifest = JSON.parse(await readFile(path.join(releaseDir, MANIFEST_NAME), 'utf8'));
  } catch (error) {
    fail('Runtime manifest is missing or invalid JSON.', 'INVALID_RUNTIME_MANIFEST', { cause: error });
  }
  if (
    manifest?.schemaVersion !== MANIFEST_SCHEMA_VERSION
    || typeof manifest.artifactId !== 'string'
    || !/^[0-9a-f]{40}-[0-9a-f]{64}$/.test(manifest.artifactId)
    || typeof manifest.gitCommit !== 'string'
    || !/^[0-9a-f]{40}$/.test(manifest.gitCommit)
    || typeof manifest.payloadSha256 !== 'string'
    || !/^[0-9a-f]{64}$/.test(manifest.payloadSha256)
    || typeof manifest.createdAt !== 'string'
    || Number.isNaN(Date.parse(manifest.createdAt))
    || manifest.entrypoint !== entrypoint
    || !Array.isArray(manifest.files)
  ) {
    fail('Runtime manifest shape is invalid.', 'INVALID_RUNTIME_MANIFEST');
  }
  if (expectedArtifactId && manifest.artifactId !== expectedArtifactId) {
    fail('Runtime artifact ID does not match the expected release.', 'RUNTIME_MANIFEST_MISMATCH');
  }
  if (expectedPayloadSha256 && manifest.payloadSha256 !== expectedPayloadSha256) {
    fail('Runtime payload digest does not match the expected release.', 'RUNTIME_MANIFEST_MISMATCH');
  }

  const seen = new Set();
  const actualFiles = [];
  for (const file of manifest.files) {
    if (
      !file
      || typeof file.path !== 'string'
      || path.isAbsolute(file.path)
      || file.path.split(/[\\/]/).includes('..')
      || seen.has(file.path)
      || typeof file.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(file.sha256)
      || !Number.isInteger(file.size)
      || file.size < 0
      || !/^(0600|0700)$/.test(file.mode)
    ) {
      fail('Runtime manifest file entry is invalid.', 'INVALID_RUNTIME_MANIFEST');
    }
    seen.add(file.path);
    const absolutePath = path.join(releaseDir, file.path);
    const stat = await lstat(absolutePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      fail(`Runtime payload file is missing or not regular: ${file.path}`, 'RUNTIME_MANIFEST_MISMATCH');
    }
    const actualMode = stat.mode & 0o777;
    const expectedMode = Number.parseInt(file.mode, 8);
    if (actualMode !== expectedMode) {
      fail(`Runtime payload file mode mismatch: ${file.path}`, 'RUNTIME_MANIFEST_MISMATCH');
    }
    const bytes = await readFile(absolutePath);
    if (bytes.length !== file.size || sha256(bytes) !== file.sha256) {
      fail(`Runtime payload file digest mismatch: ${file.path}`, 'RUNTIME_MANIFEST_MISMATCH');
    }
    actualFiles.push({ ...file });
  }

  const diskFiles = await listReleaseFiles(releaseDir);
  const expectedDiskFiles = [...seen, MANIFEST_NAME].sort();
  if (JSON.stringify(diskFiles) !== JSON.stringify(expectedDiskFiles)) {
    fail('Runtime release contains missing or unexpected files.', 'RUNTIME_MANIFEST_MISMATCH');
  }
  const digest = payloadDigest(actualFiles);
  if (digest !== manifest.payloadSha256) {
    fail('Runtime payload aggregate digest does not match the manifest.', 'RUNTIME_MANIFEST_MISMATCH');
  }
  const expectedArtifactFromManifest = `${manifest.gitCommit}-${digest}`;
  if (manifest.artifactId !== expectedArtifactFromManifest) {
    fail('Runtime artifact ID is inconsistent with its manifest.', 'RUNTIME_MANIFEST_MISMATCH');
  }

  const verifiedEntrypoint = path.join(releaseDir, entrypoint);
  return Object.freeze({ manifest, entrypoint: verifiedEntrypoint });
}

export async function verifyCurrent(runtimeRoot, { entrypoint } = {}) {
  const rootReal = await realpath(runtimeRoot);
  const currentPath = path.join(rootReal, 'current');
  let currentStat;
  try {
    currentStat = await lstat(currentPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!currentStat.isSymbolicLink()) {
    fail('Host runtime current pointer must be a symlink.', 'INVALID_CURRENT_POINTER');
  }
  const target = await readlink(currentPath);
  const resolvedTarget = path.resolve(rootReal, target);
  const releasesRoot = path.join(rootReal, 'releases');
  if (!isWithin(releasesRoot, resolvedTarget)) {
    fail('Host runtime current pointer escapes the releases directory.', 'INVALID_CURRENT_POINTER');
  }
  const verified = await verifyRelease(resolvedTarget, { entrypoint });
  return Object.freeze({
    artifactId: verified.manifest.artifactId,
    releaseDir: resolvedTarget,
    entrypoint: path.join(currentPath, entrypoint),
  });
}

async function defaultWritePayloadFile(_sourcePath, destinationPath, file) {
  await writeFile(destinationPath, file.bytes, { mode: Number.parseInt(file.mode, 8) });
}

export async function deployHostRuntime({
  sourceRoot,
  runtimeRoot,
  projectRoot = null,
  writableRoots = [],
  defaultWritableRoot,
  payloadPaths,
  entrypoint,
  now = () => new Date(),
  id = () => randomUUID(),
  writePayloadFile = defaultWritePayloadFile,
  replaceCurrent = rename,
} = {}) {
  if (!sourceRoot || !runtimeRoot || !defaultWritableRoot) {
    fail('sourceRoot, runtimeRoot, and defaultWritableRoot are required.', 'INVALID_DEPLOY_OPTIONS');
  }
  if (!Array.isArray(writableRoots)) {
    fail('writableRoots must be an array of absolute or resolvable paths.', 'INVALID_DEPLOY_OPTIONS');
  }
  const sourceAbsolute = path.resolve(sourceRoot);
  const runtimeAbsolute = path.resolve(runtimeRoot);
  const additionalWritableRoots = [
    ...(projectRoot ? [projectRoot] : []),
    ...writableRoots,
  ].map((root) => path.resolve(root));
  await ensureHostOnlyRoot({
    sourceRoot: sourceAbsolute,
    runtimeRoot: runtimeAbsolute,
    defaultWritableRoot: path.resolve(defaultWritableRoot),
    additionalWritableRoots,
  });

  const existingCurrent = await verifyCurrent(runtimeAbsolute, { entrypoint });
  const source = await inspectSource({ sourceRoot: sourceAbsolute, payloadPaths, entrypoint });
  const releasesDir = path.join(runtimeAbsolute, 'releases');
  await mkdir(releasesDir, { recursive: true, mode: 0o700 });

  const finalRelease = path.join(releasesDir, source.artifactId);
  const staging = path.join(runtimeAbsolute, `.staging-${id()}`);
  let stagingExists = false;
  try {
    let finalExists = false;
    try {
      const finalStat = await lstat(finalRelease);
      finalExists = true;
      if (!finalStat.isDirectory() || finalStat.isSymbolicLink()) {
        fail('Existing runtime artifact path is not a valid release directory.', 'MALFORMED_RELEASE');
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }

    if (!finalExists) {
      await mkdir(staging, { mode: 0o700 });
      stagingExists = true;
      for (const file of source.files) {
        const destination = path.join(staging, file.path);
        await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
        await writePayloadFile(path.join(sourceAbsolute, file.path), destination, file);
      }
      const createdAt = now();
      const createdAtIso = createdAt instanceof Date ? createdAt.toISOString() : new Date(createdAt).toISOString();
      const manifest = {
        schemaVersion: MANIFEST_SCHEMA_VERSION,
        artifactId: source.artifactId,
        gitCommit: source.gitCommit,
        payloadSha256: source.payloadSha256,
        createdAt: createdAtIso,
        entrypoint,
        files: source.files.map(({ path: filePath, sha256: digest, size, mode }) => ({
          path: filePath,
          sha256: digest,
          size,
          mode,
        })),
      };
      await writeFile(path.join(staging, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
      await verifyRelease(staging, {
        expectedArtifactId: source.artifactId,
        expectedPayloadSha256: source.payloadSha256,
        entrypoint,
      });
      await rename(staging, finalRelease);
      stagingExists = false;
    }

    await verifyRelease(finalRelease, {
      expectedArtifactId: source.artifactId,
      expectedPayloadSha256: source.payloadSha256,
      entrypoint,
    });

    const currentPath = path.join(runtimeAbsolute, 'current');
    const temporaryCurrent = path.join(runtimeAbsolute, `.current-${id()}`);
    const relativeTarget = path.join('releases', source.artifactId);
    await symlink(relativeTarget, temporaryCurrent, 'dir');
    try {
      await replaceCurrent(temporaryCurrent, currentPath);
    } catch (error) {
      await rm(temporaryCurrent, { force: true });
      throw error;
    }

    const current = await verifyCurrent(runtimeAbsolute, { entrypoint });
    let currentTarget;
    try {
      currentTarget = await readlink(currentPath);
    } catch (error) {
      fail('Atomic current switch did not leave a readable current symlink.', 'CURRENT_SWITCH_FAILED', { cause: error });
    }
    if (
      !current
      || current.artifactId !== source.artifactId
      || currentTarget !== relativeTarget
    ) {
      fail('Atomic current switch did not resolve to the canonical verified release.', 'CURRENT_SWITCH_FAILED');
    }
    return Object.freeze({
      artifactId: source.artifactId,
      gitCommit: source.gitCommit,
      payloadSha256: source.payloadSha256,
      releaseDir: finalRelease,
      current: currentPath,
      entrypoint: current.entrypoint,
      previousArtifactId: existingCurrent?.artifactId ?? null,
    });
  } catch (error) {
    if (error instanceof HostRuntimeError) throw error;
    fail('Host runtime deployment failed before activation.', 'HOST_RUNTIME_DEPLOY_FAILED', { cause: error });
  } finally {
    if (stagingExists) {
      await rm(staging, { recursive: true, force: true });
    }
  }
}
