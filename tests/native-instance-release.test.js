import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createInstanceContext } from '../native/deploy/instance-context.js';
import {
  INSTANCE_RELEASE_PIN_VERSION,
  loadInstanceReleasePin,
  parseInstanceReleasePin,
  persistInstanceReleasePin,
  pinInstanceToCurrentRelease,
  pinInstanceToRelease,
  verifyPinnedInstanceRelease,
} from '../native/deploy/instance-release.js';
import { NATIVE_HOST_ENTRYPOINT } from '../native/deploy/deploy-host-boundary.js';

const ARTIFACT = `${'a'.repeat(40)}-${'b'.repeat(64)}`;

test('instance release pin is minimal, validated and private-state friendly', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-release-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    await persistInstanceReleasePin(adapter.hostReleasePin, {
      version: INSTANCE_RELEASE_PIN_VERSION,
      artifactId: ARTIFACT,
    });
    assert.deepEqual(await loadInstanceReleasePin(adapter.hostReleasePin), {
      version: 1,
      artifactId: ARTIFACT,
    });
    assert.deepEqual(parseInstanceReleasePin(await readFile(adapter.hostReleasePin, 'utf8')), {
      version: 1,
      artifactId: ARTIFACT,
    });
    assert.throws(
      () => parseInstanceReleasePin(JSON.stringify({ version: 1, artifactId: ARTIFACT, current: true })),
      /only version and artifactId/,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('a non-default instance pins one exact immutable release id', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-release-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    let verifiedRoot = null;
    const pinned = await pinInstanceToRelease(adapter, ARTIFACT, {
      verifyReleaseImpl: async (releaseRoot, options) => {
        verifiedRoot = releaseRoot;
        assert.equal(options.expectedArtifactId, ARTIFACT);
        assert.equal(options.entrypoint, NATIVE_HOST_ENTRYPOINT);
        return { entrypoint: path.join(releaseRoot, NATIVE_HOST_ENTRYPOINT) };
      },
    });

    assert.equal(verifiedRoot, path.join(adapter.hostRuntimeRoot, 'releases', ARTIFACT));
    assert.equal(pinned.artifactId, ARTIFACT);
    assert.equal((await loadInstanceReleasePin(adapter.hostReleasePin)).artifactId, ARTIFACT);
    assert.doesNotMatch(pinned.hostEntrypoint, /\/current\//);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('setup captures the currently verified artifact id without making the instance follow current', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-release-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    let seenRoot = null;
    const result = await pinInstanceToCurrentRelease(adapter, {
      verifyCurrentImpl: async (runtimeRoot, options) => {
        seenRoot = runtimeRoot;
        assert.equal(options.entrypoint, NATIVE_HOST_ENTRYPOINT);
        return { artifactId: ARTIFACT, entrypoint: path.join(runtimeRoot, 'current', NATIVE_HOST_ENTRYPOINT) };
      },
    });
    assert.equal(seenRoot, adapter.hostRuntimeRoot);
    assert.equal(result.artifactId, ARTIFACT);
    assert.equal((await loadInstanceReleasePin(adapter.hostReleasePin)).artifactId, ARTIFACT);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('runtime resolves the pinned immutable release directly and never through current', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-release-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    await persistInstanceReleasePin(adapter.hostReleasePin, {
      version: 1,
      artifactId: ARTIFACT,
    });

    let verifiedPath = null;
    const result = await verifyPinnedInstanceRelease(adapter, {
      verifyReleaseImpl: async (releaseRoot, options) => {
        verifiedPath = releaseRoot;
        assert.equal(options.expectedArtifactId, ARTIFACT);
        assert.equal(options.entrypoint, NATIVE_HOST_ENTRYPOINT);
        return { entrypoint: path.join(releaseRoot, NATIVE_HOST_ENTRYPOINT) };
      },
    });

    assert.equal(verifiedPath, path.join(adapter.hostRuntimeRoot, 'releases', ARTIFACT));
    assert.doesNotMatch(result.hostEntrypoint, /\/current\//);
    assert.equal(result.artifactId, ARTIFACT);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('default production instance cannot accidentally acquire a separate release pin', async () => {
  const base = createInstanceContext({ home: '/Users/example' });
  await assert.rejects(
    pinInstanceToCurrentRelease(base, { verifyCurrentImpl: async () => ({ artifactId: ARTIFACT }) }),
    /non-default instance context/,
  );
  await assert.rejects(
    verifyPinnedInstanceRelease(base, { loadPinImpl: async () => ({ version: 1, artifactId: ARTIFACT }) }),
    /non-default instance context/,
  );
});
