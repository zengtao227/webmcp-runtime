import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  deployHostRuntime,
  HostRuntimeError,
  inspectSource,
  verifyCurrent,
  verifyRelease,
} from '../adapter/deploy/deploy-host-runtime.js';

const execFileAsync = promisify(execFile);
const PAYLOAD = Object.freeze([
  'package.json',
  'runtime/start.js',
]);
const ENTRYPOINT = 'runtime/start.js';

async function git(cwd, args) {
  const { stdout = '' } = await execFileAsync('git', args, { cwd, encoding: 'utf8' });
  return stdout;
}

async function withTempDir(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-host-runtime-test-'));
  try {
    return await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function createFixture(root) {
  const projectRoot = path.join(root, 'project');
  const sourceRoot = path.join(projectRoot, 'repo');
  const runtimeRoot = path.join(root, 'host-runtime');
  await mkdir(path.join(sourceRoot, 'runtime'), { recursive: true });
  await writeFile(path.join(sourceRoot, 'package.json'), '{"type":"module"}\n');
  await writeFile(path.join(sourceRoot, ENTRYPOINT), '#!/usr/bin/env node\nprocess.stdin.resume();\n');
  await chmod(path.join(sourceRoot, ENTRYPOINT), 0o755);
  await git(sourceRoot, ['init', '-q']);
  await git(sourceRoot, ['add', '.']);
  await git(sourceRoot, [
    '-c', 'user.name=Host Runtime Test',
    '-c', 'user.email=host-runtime@example.invalid',
    'commit', '-qm', 'fixture',
  ]);
  return { projectRoot, sourceRoot, runtimeRoot };
}

function assertHostRuntimeCode(code) {
  return (error) => {
    assert.ok(error instanceof HostRuntimeError);
    assert.equal(error.code, code);
    return true;
  };
}

async function deployFixture(fixture, overrides = {}) {
  return deployHostRuntime({
    sourceRoot: fixture.sourceRoot,
    runtimeRoot: fixture.runtimeRoot,
    defaultWritableRoot: fixture.projectRoot,
    payloadPaths: PAYLOAD,
    entrypoint: ENTRYPOINT,
    ...overrides,
  });
}

test('generic host snapshot deploys only the declared reviewed payload', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const result = await deployFixture(fixture);
    const current = await verifyCurrent(fixture.runtimeRoot, { entrypoint: ENTRYPOINT });
    const verified = await verifyRelease(result.releaseDir, {
      expectedArtifactId: result.artifactId,
      expectedPayloadSha256: result.payloadSha256,
      entrypoint: ENTRYPOINT,
    });

    assert.equal(current.artifactId, result.artifactId);
    assert.equal(await readlink(path.join(fixture.runtimeRoot, 'current')), path.join('releases', result.artifactId));
    assert.deepEqual(verified.manifest.files.map((file) => file.path).sort(), [...PAYLOAD].sort());
    assert.equal(verified.manifest.entrypoint, ENTRYPOINT);

    for (const file of verified.manifest.files) {
      const stat = await lstat(path.join(result.releaseDir, file.path));
      assert.equal(stat.isSymbolicLink(), false);
      assert.equal(stat.mode & 0o777, file.path === ENTRYPOINT ? 0o700 : 0o600);
    }
  });
});

test('source gate rejects dirty, missing, symlink, and untracked payload files', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const inspect = () => inspectSource({
      sourceRoot: fixture.sourceRoot,
      payloadPaths: PAYLOAD,
      entrypoint: ENTRYPOINT,
    });

    await writeFile(path.join(fixture.sourceRoot, 'package.json'), '{"type":"commonjs"}\n');
    await assert.rejects(inspect(), assertHostRuntimeCode('DIRTY_RUNTIME_SOURCE'));
    await git(fixture.sourceRoot, ['checkout', '--', 'package.json']);

    await rm(path.join(fixture.sourceRoot, 'package.json'));
    await assert.rejects(inspect(), assertHostRuntimeCode('MISSING_RUNTIME_SOURCE'));
    await git(fixture.sourceRoot, ['checkout', '--', 'package.json']);

    const startPath = path.join(fixture.sourceRoot, ENTRYPOINT);
    await rm(startPath);
    await symlink('/dev/null', startPath);
    await assert.rejects(inspect(), assertHostRuntimeCode('MALFORMED_RUNTIME_SOURCE'));
    await rm(startPath);
    await git(fixture.sourceRoot, ['checkout', '--', ENTRYPOINT]);

    const untracked = 'runtime/untracked.js';
    await writeFile(path.join(fixture.sourceRoot, untracked), 'export {};\n');
    await assert.rejects(
      inspectSource({
        sourceRoot: fixture.sourceRoot,
        payloadPaths: [...PAYLOAD, untracked],
        entrypoint: ENTRYPOINT,
      }),
      assertHostRuntimeCode('DIRTY_RUNTIME_SOURCE'),
    );
  });
});

test('source gate rejects lexical and canonical repository backreferences', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const aliasRoot = path.join(root, 'repo-alias');
    await symlink(fixture.sourceRoot, aliasRoot, 'dir');

    const commitBackreference = async (absolutePath, message) => {
      await writeFile(
        path.join(fixture.sourceRoot, ENTRYPOINT),
        `#!/usr/bin/env node\nconst unsafe = ${JSON.stringify(absolutePath)};\nprocess.stdin.resume();\n`,
      );
      await chmod(path.join(fixture.sourceRoot, ENTRYPOINT), 0o755);
      await git(fixture.sourceRoot, ['add', ENTRYPOINT]);
      await git(fixture.sourceRoot, [
        '-c', 'user.name=Host Runtime Test',
        '-c', 'user.email=host-runtime@example.invalid',
        'commit', '-qm', message,
      ]);
    };

    await commitBackreference(aliasRoot, 'lexical alias backreference');
    await assert.rejects(
      inspectSource({ sourceRoot: aliasRoot, payloadPaths: PAYLOAD, entrypoint: ENTRYPOINT }),
      assertHostRuntimeCode('REPOSITORY_BACKREFERENCE'),
    );

    await commitBackreference(await realpath(aliasRoot), 'canonical backreference');
    await assert.rejects(
      inspectSource({ sourceRoot: aliasRoot, payloadPaths: PAYLOAD, entrypoint: ENTRYPOINT }),
      assertHostRuntimeCode('REPOSITORY_BACKREFERENCE'),
    );
  });
});

test('runtime snapshot root must stay outside every declared writable boundary', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    await assert.rejects(
      deployFixture(fixture, { runtimeRoot: path.join(fixture.projectRoot, 'runtime') }),
      assertHostRuntimeCode('UNSAFE_RUNTIME_ROOT'),
    );

    await assert.rejects(
      deployFixture(fixture, { defaultWritableRoot: path.join(root, 'missing-root') }),
      assertHostRuntimeCode('UNSAFE_WRITABLE_ROOT'),
    );

    const fileRoot = path.join(root, 'not-a-directory');
    await writeFile(fileRoot, 'not a directory\n');
    await assert.rejects(
      deployFixture(fixture, { writableRoots: [fileRoot] }),
      assertHostRuntimeCode('UNSAFE_WRITABLE_ROOT'),
    );
  });
});

test('failed snapshot build leaves the existing current release unchanged', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const first = await deployFixture(fixture);
    const currentBefore = await readlink(path.join(fixture.runtimeRoot, 'current'));

    await writeFile(path.join(fixture.sourceRoot, ENTRYPOINT), '#!/usr/bin/env node\nprocess.stdin.resume();\n// v2\n');
    await git(fixture.sourceRoot, ['add', ENTRYPOINT]);
    await git(fixture.sourceRoot, [
      '-c', 'user.name=Host Runtime Test',
      '-c', 'user.email=host-runtime@example.invalid',
      'commit', '-qm', 'v2',
    ]);

    let writes = 0;
    await assert.rejects(
      deployFixture(fixture, {
        writePayloadFile: async (_sourcePath, destinationPath, file) => {
          writes += 1;
          if (writes === 2) throw new Error('simulated copy failure');
          await writeFile(destinationPath, file.bytes, { mode: Number.parseInt(file.mode, 8) });
        },
      }),
      assertHostRuntimeCode('HOST_RUNTIME_DEPLOY_FAILED'),
    );

    assert.equal(await readlink(path.join(fixture.runtimeRoot, 'current')), currentBefore);
    assert.equal((await verifyCurrent(fixture.runtimeRoot, { entrypoint: ENTRYPOINT })).artifactId, first.artifactId);
  });
});

test('current pointer switches atomically to a verified release and keeps the previous release', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const first = await deployFixture(fixture);

    await writeFile(path.join(fixture.sourceRoot, ENTRYPOINT), '#!/usr/bin/env node\nprocess.stdin.resume();\n// second\n');
    await git(fixture.sourceRoot, ['add', ENTRYPOINT]);
    await git(fixture.sourceRoot, [
      '-c', 'user.name=Host Runtime Test',
      '-c', 'user.email=host-runtime@example.invalid',
      'commit', '-qm', 'second',
    ]);

    const oldTarget = await readlink(path.join(fixture.runtimeRoot, 'current'));
    let replacementObserved = false;
    const second = await deployFixture(fixture, {
      replaceCurrent: async (temporaryCurrent, currentPath) => {
        assert.equal(await readlink(currentPath), oldTarget);
        replacementObserved = true;
        await rename(temporaryCurrent, currentPath);
      },
    });

    assert.equal(replacementObserved, true);
    assert.notEqual(second.artifactId, first.artifactId);
    assert.equal(second.previousArtifactId, first.artifactId);
    assert.equal((await verifyCurrent(fixture.runtimeRoot, { entrypoint: ENTRYPOINT })).artifactId, second.artifactId);
    await verifyRelease(first.releaseDir, { entrypoint: ENTRYPOINT });
    await verifyRelease(second.releaseDir, { entrypoint: ENTRYPOINT });
  });
});

test('current switch rejects a non-canonical alias even when artifact identity matches', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const first = await deployFixture(fixture);
    const currentPath = path.join(fixture.runtimeRoot, 'current');
    const aliasRelease = path.join(fixture.runtimeRoot, 'releases', 'previous');
    await rename(first.releaseDir, aliasRelease);
    await rm(currentPath);
    await symlink(path.join('releases', 'previous'), currentPath, 'dir');
    assert.equal((await verifyCurrent(fixture.runtimeRoot, { entrypoint: ENTRYPOINT })).artifactId, first.artifactId);

    await assert.rejects(
      deployFixture(fixture, {
        replaceCurrent: async (temporaryCurrent) => {
          await rm(temporaryCurrent);
        },
      }),
      assertHostRuntimeCode('CURRENT_SWITCH_FAILED'),
    );
    assert.equal(await readlink(currentPath), path.join('releases', 'previous'));
  });
});

test('release verification rejects payload tampering and mode drift', async () => {
  await withTempDir(async (root) => {
    const fixture = await createFixture(root);
    const result = await deployFixture(fixture);
    const packagePath = path.join(result.releaseDir, 'package.json');

    await chmod(packagePath, 0o644);
    await assert.rejects(
      verifyRelease(result.releaseDir, { entrypoint: ENTRYPOINT }),
      assertHostRuntimeCode('RUNTIME_MANIFEST_MISMATCH'),
    );

    await chmod(packagePath, 0o600);
    await writeFile(packagePath, '{"tampered":true}\n');
    await assert.rejects(
      verifyRelease(result.releaseDir, { entrypoint: ENTRYPOINT }),
      assertHostRuntimeCode('RUNTIME_MANIFEST_MISMATCH'),
    );
  });
});
