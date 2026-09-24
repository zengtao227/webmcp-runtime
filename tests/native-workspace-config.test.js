import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildControlPlaneMaskArgs,
  buildControlPlaneMaskPlan,
  buildWorkspaceMountArgs,
  loadWorkspaceConfig,
  normalizeWorkspaceConfig,
  persistWorkspaceConfig,
  verifyWorkspaceMount,
} from '../native/deploy/workspace-config.js';

async function withTempRoot(run) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-config-'));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('workspace config defaults network by mode and keeps Git publication opt-in', () => {
  const project = normalizeWorkspaceConfig({ version: 1, hostRoot: '/tmp/project', mode: 'project' }, { platform: 'darwin' });
  assert.equal(project.networkEnabled, true);
  assert.equal(project.gitPublicationEnabled, false);

  const advanced = normalizeWorkspaceConfig({ version: 1, hostRoot: '/tmp/all', mode: 'advanced' }, { platform: 'darwin' });
  assert.equal(advanced.networkEnabled, false);
  assert.equal(advanced.gitPublicationEnabled, false);

  const trusted = normalizeWorkspaceConfig({
    version: 1,
    hostRoot: '/tmp/all',
    mode: 'advanced',
    networkEnabled: true,
    gitPublicationEnabled: true,
    gitUserName: 'WebMCP Test',
    gitUserEmail: 'webmcp-test@example.invalid',
  }, { platform: 'darwin' });
  assert.equal(trusted.networkEnabled, true);
  assert.equal(trusted.gitPublicationEnabled, true);
  assert.equal(trusted.gitUserName, 'WebMCP Test');
  assert.equal(trusted.gitUserEmail, 'webmcp-test@example.invalid');
});

test('workspace config rejects unknown keys, relative roots, and literal macOS root', () => {
  assert.throws(() => normalizeWorkspaceConfig({
    version: 1,
    hostRoot: '/tmp/work',
    mode: 'workspace',
    extra: true,
  }, { platform: 'linux' }), /unsupported key/);
  assert.throws(() => normalizeWorkspaceConfig({
    version: 1,
    hostRoot: 'relative',
    mode: 'workspace',
  }, { platform: 'linux' }), /absolute path/);
  assert.throws(() => normalizeWorkspaceConfig({
    version: 1,
    hostRoot: '/',
    mode: 'advanced',
  }, { platform: 'darwin' }), /Docker Desktop/);
  // Linux hosts only ever expose a narrow owner-selected workspace: the filesystem root is refused in every mode.
  assert.throws(() => normalizeWorkspaceConfig({
    version: 1,
    hostRoot: '/',
    mode: 'advanced',
  }, { platform: 'linux' }), (error) => error.code === 'LINUX_ADVANCED_MODE_UNSUPPORTED');
  assert.throws(() => normalizeWorkspaceConfig({
    version: 1,
    hostRoot: '/',
    mode: 'workspace',
  }, { platform: 'linux' }), (error) => error.code === 'LINUX_WORKSPACE_ROOT_UNSAFE');
});

test('workspace config persists atomically and reloads strict normalized values', async () => {
  await withTempRoot(async (root) => {
    const configPath = path.join(root, 'host', 'workspace.json');
    await persistWorkspaceConfig(configPath, {
      version: 1,
      hostRoot: root,
      mode: 'workspace',
    }, { platform: 'linux' });
    const loaded = await loadWorkspaceConfig(configPath, { platform: 'linux' });
    assert.equal(loaded.hostRoot, root);
    assert.equal(loaded.networkEnabled, true);
    assert.equal(loaded.gitPublicationEnabled, false);
    assert.match(await readFile(configPath, 'utf8'), /"version": 1/);
  });
});

test('workspace mount always disables recursive submount inheritance and rejects ambiguous mount paths', () => {
  assert.deepEqual(buildWorkspaceMountArgs('/tmp/workspace'), [
    '--mount',
    'type=bind,src=/tmp/workspace,dst=/workspace,bind-recursive=disabled',
  ]);
  assert.throws(() => buildWorkspaceMountArgs('/tmp/path,with-comma'), /cannot be represented safely/);
});

test('control-plane paths beneath the selected root become explicit file/directory masks', async () => {
  await withTempRoot(async (root) => {
    const control = path.join(root, 'control');
    const runtimeDir = path.join(control, 'runtime');
    const configFile = path.join(control, 'workspace.json');
    const outside = await mkdtemp(path.join(os.tmpdir(), 'webmcp-outside-control-'));
    await mkdir(runtimeDir, { recursive: true });
    await writeFile(configFile, 'secret-policy', 'utf8');

    const plan = await buildControlPlaneMaskPlan({
      hostRoot: root,
      protectedPaths: [runtimeDir, configFile, outside],
    });
    assert.deepEqual(plan.map(({ type, destination }) => ({ type, destination })), [
      { type: 'directory', destination: '/workspace/control/runtime' },
      { type: 'file', destination: '/workspace/control/workspace.json' },
    ]);

    const args = buildControlPlaneMaskArgs(plan);
    assert.ok(args.includes('type=tmpfs,dst=/workspace/control/runtime,readonly,tmpfs-mode=000'));
    assert.ok(args.includes('type=bind,src=/dev/null,dst=/workspace/control/workspace.json,readonly'));
    await rm(outside, { recursive: true, force: true });
  });
});

test('control-plane masking canonicalizes both root and protected paths and fails closed on unresolved paths', async () => {
  await withTempRoot(async (root) => {
    const canonicalControl = path.join(root, 'control');
    const protectedFile = path.join(canonicalControl, 'policy.json');
    const aliasRoot = path.join(path.dirname(root), `${path.basename(root)}-alias`);
    await mkdir(canonicalControl);
    await writeFile(protectedFile, 'policy', 'utf8');
    await import('node:fs/promises').then(({ symlink }) => symlink(root, aliasRoot, 'dir'));
    try {
      const aliasedProtected = path.join(aliasRoot, 'control', 'policy.json');
      const plan = await buildControlPlaneMaskPlan({
        hostRoot: root,
        protectedPaths: [aliasedProtected],
      });
      assert.deepEqual(plan.map(({ type, destination }) => ({ type, destination })), [
        { type: 'file', destination: '/workspace/control/policy.json' },
      ]);

      await assert.rejects(buildControlPlaneMaskPlan({
        hostRoot: path.join(root, 'control'),
        protectedPaths: [root],
      }), { code: 'CONTROL_PLANE_ROOT_CONFLICT' });

      await assert.rejects(buildControlPlaneMaskPlan({
        hostRoot: root,
        protectedPaths: [path.join(root, 'missing-control-plane')],
      }), /Unable to canonicalize protected control-plane path/);
    } finally {
      await rm(aliasRoot, { force: true });
    }
  });
});

test('sentinel probe uses exact hardened production mount semantics and always cleans up', async () => {
  await withTempRoot(async (root) => {
    const control = path.join(root, 'control');
    const protectedFile = path.join(control, 'policy.json');
    await mkdir(control);
    await writeFile(protectedFile, 'policy', 'utf8');

    let observedArgs = null;
    let sentinelDuringProbe = null;
    const fakeExec = async (command, args) => {
      assert.equal(command, 'docker');
      observedArgs = args;
      const nodeIndex = args.indexOf('node');
      const sentinelName = args[nodeIndex + 3];
      sentinelDuringProbe = path.join(root, sentinelName);
      assert.equal(await readFile(sentinelDuringProbe, 'utf8'), args[nodeIndex + 4]);
      return { stdout: 'verified', stderr: '' };
    };

    const result = await verifyWorkspaceMount({
      hostRoot: root,
      image: 'example/webmcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      protectedPaths: [protectedFile],
      execFileImpl: fakeExec,
      platform: 'linux',
    });

    assert.equal(result.canonicalRoot, await realpath(root));
    assert.ok(observedArgs.includes('--read-only'));
    assert.equal(observedArgs[observedArgs.indexOf('--user') + 1], `${process.getuid()}:${process.getgid()}`, 'the Linux probe runs as the runtime user so it can read its own 0600 sentinel');
    assert.ok(observedArgs.includes('none'));
    assert.ok(observedArgs.includes('ALL'));
    assert.ok(observedArgs.some((arg) => arg.includes('bind-recursive=disabled')));
    assert.ok(observedArgs.some((arg) => arg.includes('/workspace/control/policy.json')));
    await assert.rejects(readFile(sentinelDuringProbe, 'utf8'));
  });
});

test('sentinel probe fails closed and still removes the temporary file', async () => {
  await withTempRoot(async (root) => {
    let sentinelPath;
    const fakeExec = async (_command, args) => {
      const nodeIndex = args.indexOf('node');
      sentinelPath = path.join(root, args[nodeIndex + 3]);
      throw new Error('docker rejected bind-recursive');
    };
    await assert.rejects(
      verifyWorkspaceMount({
        hostRoot: root,
        image: 'example/webmcp@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        execFileImpl: fakeExec,
        platform: 'linux',
      }),
      /probe failed/,
    );
    await assert.rejects(readFile(sentinelPath, 'utf8'));
  });
});

test('readOnly defaults to false, must be boolean, and drives the workspace mount flag', () => {
  const base = { version: 1, hostRoot: '/tmp/workspace', mode: 'workspace' };
  assert.equal(normalizeWorkspaceConfig(base, { platform: 'linux' }).readOnly, false);
  assert.equal(normalizeWorkspaceConfig({ ...base, readOnly: true }, { platform: 'linux' }).readOnly, true);
  assert.throws(
    () => normalizeWorkspaceConfig({ ...base, readOnly: 'yes' }, { platform: 'linux' }),
    /readOnly must be boolean/,
  );

  assert.deepEqual(buildWorkspaceMountArgs('/tmp/workspace', { readOnly: true }), [
    '--mount',
    'type=bind,src=/tmp/workspace,dst=/workspace,bind-recursive=disabled,readonly',
  ]);
  assert.deepEqual(
    buildWorkspaceMountArgs('/tmp/workspace', { readOnly: false }),
    buildWorkspaceMountArgs('/tmp/workspace'),
  );
});
