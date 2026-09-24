import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { deployNativeHostBoundary, NATIVE_HOST_RUNTIME_PAYLOAD } from '../native/deploy/deploy-host-boundary.js';
import { buildNativeImageFromRelease, DEFAULT_NATIVE_BASE_IMAGE } from '../native/deploy/build-image.js';
import { DEFAULT_IMAGE_PIN } from '../native/deploy/image-pin.js';
import { aggregateSourceDigest, NATIVE_RUNTIME_PAYLOAD } from '../native/deploy/runtime-payload.js';

const execFileAsync = promisify(execFile);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const IMAGE_ID = `sha256:${'e'.repeat(64)}`;

// A committed copy of the current release payload, so the test does not depend on the
// working tree of this repository being clean.
async function withRelease(run) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-build-image-'));
  try {
    const source = path.join(root, 'source');
    for (const file of NATIVE_HOST_RUNTIME_PAYLOAD) {
      await mkdir(path.dirname(path.join(source, file)), { recursive: true });
      await copyFile(path.join(repo, file), path.join(source, file));
    }
    const git = (args) => execFileAsync('git', args, { cwd: source });
    await git(['init', '-q']);
    await git(['add', '.']);
    await git(['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture']);
    const release = await deployNativeHostBoundary({ sourceRoot: source, runtimeRoot: path.join(root, 'host-runtime'), activate: false });
    await run({ root, release });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function fakeDocker(expectedLabel, calls) {
  return async (command, args) => {
    calls.push([command, ...args]);
    if (args[0] === 'build') return { stdout: '' };
    if (args[0] === 'image' && args[1] === 'inspect') {
      return { stdout: JSON.stringify([{ Id: IMAGE_ID, Config: { User: '65532:65532', Labels: { 'com.webmcp.native.source-sha256': expectedLabel } } }]) };
    }
    throw new Error(`unexpected docker call ${args.join(' ')}`);
  };
}

test('an instance builds its image from a verified release with its own pin and tag', async () => {
  await withRelease(async ({ root, release }) => {
    const manifest = JSON.parse(await readFile(path.join(release.releaseDir, 'manifest.json'), 'utf8'));
    const label = aggregateSourceDigest(manifest.files.filter((file) => NATIVE_RUNTIME_PAYLOAD.includes(file.path)));
    const calls = [];
    const outputPin = path.join(root, 'deepseek', 'native-image.json');
    const result = await buildNativeImageFromRelease({
      releaseDir: release.releaseDir,
      expectedArtifactId: release.artifactId,
      baseImage: DEFAULT_NATIVE_BASE_IMAGE,
      outputPin,
      tag: 'webmcp-native:deepseek',
      execFileImpl: fakeDocker(label, calls),
    });
    assert.equal(result.image, IMAGE_ID);
    assert.equal(result.sourceSha256, label);
    assert.equal(result.gitCommit, manifest.gitCommit);
    const build = calls.find((call) => call[1] === 'build');
    assert.ok(build.includes(`WEBMCP_SOURCE_SHA256=${label}`));
    assert.ok(build.includes(`WEBMCP_NODE_IMAGE=${DEFAULT_NATIVE_BASE_IMAGE}`));
    assert.ok(build.includes('webmcp-native:deepseek'));
    assert.equal(JSON.parse(await readFile(outputPin, 'utf8')).image, IMAGE_ID);
  });
});

test('a release build refuses the default instance pin and tag, and a tampered release', async () => {
  await withRelease(async ({ root, release }) => {
    const base = {
      releaseDir: release.releaseDir,
      expectedArtifactId: release.artifactId,
      baseImage: DEFAULT_NATIVE_BASE_IMAGE,
      execFileImpl: async () => assert.fail('docker must not run'),
    };
    const ownPin = path.join(root, 'own.json');
    await assert.rejects(buildNativeImageFromRelease({ ...base, outputPin: DEFAULT_IMAGE_PIN, tag: 'webmcp-native:deepseek' }), { code: 'INVALID_IMAGE_PIN_PATH' });
    await assert.rejects(buildNativeImageFromRelease({ ...base, outputPin: ownPin, tag: 'webmcp-native:reviewed' }), { code: 'INVALID_IMAGE_TAG' });
    await assert.rejects(buildNativeImageFromRelease({ ...base, outputPin: ownPin, tag: 'webmcp-native:deepseek', baseImage: 'node:22-bookworm-slim' }), { code: 'UNPINNED_BASE_IMAGE' });
    await writeFile(path.join(release.releaseDir, 'native/src/workspace.js'), 'tampered\n', { mode: 0o600 });
    await assert.rejects(buildNativeImageFromRelease({ ...base, outputPin: ownPin, tag: 'webmcp-native:deepseek' }), { code: 'RUNTIME_MANIFEST_MISMATCH' });
  });
});
