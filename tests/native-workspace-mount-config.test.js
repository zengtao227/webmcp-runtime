import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  addWorkspaceMount,
  buildWorkspaceMountMaskPlan,
  buildWorkspaceMountSetArgs,
  canonicalizeWorkspaceMountConfig,
  loadWorkspaceMountConfig,
  migrateLegacyWorkspaceConfig,
  narrowsWorkspaceWriteAuthority,
  normalizeWorkspaceMountConfig,
  persistWorkspaceMountConfig,
  removeWorkspaceMount,
  setWorkspaceMountWrite,
  workspaceMountContainerPath,
  workspaceMountIdForPath,
} from '../native/deploy/workspace-mount-config.js';

test('mounted folders default Write OFF and keep stable container paths independent of list order', () => {
  const first = normalizeWorkspaceMountConfig({
    version: 1,
    mounts: [
      { id: 'project-a', hostPath: '/tmp/project-a', writeEnabled: true },
      { id: 'project-b', hostPath: '/tmp/project-b' },
    ],
  });
  const reordered = normalizeWorkspaceMountConfig({
    version: 1,
    mounts: [
      { id: 'project-b', hostPath: '/tmp/project-b' },
      { id: 'project-a', hostPath: '/tmp/project-a', writeEnabled: true },
    ],
  });

  assert.equal(first.mounts[0].writeEnabled, true);
  assert.equal(first.mounts[1].writeEnabled, false);
  assert.equal(first.mounts[0].containerPath, '/workspace/mounts/project-a');
  assert.equal(first.mounts[1].containerPath, '/workspace/mounts/project-b');
  assert.equal(
    reordered.mounts.find((mount) => mount.id === 'project-a').containerPath,
    first.mounts.find((mount) => mount.id === 'project-a').containerPath,
  );
  assert.equal(workspaceMountContainerPath('project-b'), '/workspace/mounts/project-b');
});

test('mounted-folder policy rejects Home and sensitive host roots before Write can be enabled', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-sensitive-mount-'));
  try {
    const project = path.join(home, 'Projects', 'app');
    const ssh = path.join(home, '.ssh');
    const launchAgents = path.join(home, 'Library', 'LaunchAgents');
    const webmcp = path.join(home, '.config', 'webmcp');
    for (const directory of [project, ssh, launchAgents, webmcp]) {
      await mkdir(directory, { recursive: true });
    }
    const alias = path.join(home, 'ssh-alias');
    await symlink(ssh, alias, 'dir');
    for (const root of [home, ssh, alias, launchAgents, webmcp, path.join(home, 'Library')]) {
      await assert.rejects(
        addWorkspaceMount({ version: 1, mounts: [] }, { hostPath: root, home, platform: 'darwin' }),
        (error) => error.code === 'SENSITIVE_WORKSPACE_MOUNT',
        root,
      );
    }
    await assert.rejects(
      canonicalizeWorkspaceMountConfig({ version: 1, mounts: [{ id: 'unsafe', hostPath: ssh, writeEnabled: true }] }, { home, platform: 'darwin' }),
      (error) => error.code === 'SENSITIVE_WORKSPACE_MOUNT',
      'persisted policy cannot bypass mount-add',
    );
    const safe = await addWorkspaceMount({ version: 1, mounts: [] }, { hostPath: project, home, platform: 'darwin' });
    assert.equal(safe.mounts[0].writeEnabled, false);
    assert.equal(setWorkspaceMountWrite(safe, safe.mounts[0].id, true).mounts[0].writeEnabled, true);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('mounted-folder policy follows a symlinked parent even before protected state exists', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-sensitive-link-home-'));
  const shared = await mkdtemp(path.join(os.tmpdir(), 'webmcp-sensitive-link-shared-'));
  try {
    await symlink(shared, path.join(home, '.config'), 'dir');
    await assert.rejects(
      addWorkspaceMount({ version: 1, mounts: [] }, { hostPath: shared, home, platform: 'darwin' }),
      (error) => error.code === 'SENSITIVE_WORKSPACE_MOUNT',
    );
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(shared, { recursive: true, force: true });
  }
});

test('mounted folder ids are strict and unique', () => {
  assert.throws(
    () => normalizeWorkspaceMountConfig({
      version: 1,
      mounts: [{ id: 'Project A', hostPath: '/tmp/a' }],
    }),
    (error) => error.code === 'INVALID_WORKSPACE_MOUNT_ID',
  );

  assert.throws(
    () => normalizeWorkspaceMountConfig({
      version: 1,
      mounts: [
        { id: 'same', hostPath: '/tmp/a' },
        { id: 'same', hostPath: '/tmp/b' },
      ],
    }),
    (error) => error.code === 'DUPLICATE_WORKSPACE_MOUNT_ID',
  );
});

test('canonical mount validation rejects duplicate real paths including symlink aliases', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-alias-'));
  const project = path.join(root, 'project');
  const alias = path.join(root, 'project-alias');
  try {
    await mkdir(project);
    await symlink(project, alias, 'dir');

    await assert.rejects(
      canonicalizeWorkspaceMountConfig({
        version: 1,
        mounts: [
          { id: 'project', hostPath: project },
          { id: 'alias', hostPath: alias },
        ],
      }, { platform: 'darwin' }),
      (error) => error.code === 'WORKSPACE_MOUNT_OVERLAP',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('canonical mount validation rejects parent and child mounts', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-overlap-'));
  const parent = path.join(root, 'parent');
  const child = path.join(parent, 'child');
  try {
    await mkdir(child, { recursive: true });

    await assert.rejects(
      canonicalizeWorkspaceMountConfig({
        version: 1,
        mounts: [
          { id: 'parent', hostPath: parent, writeEnabled: true },
          { id: 'child', hostPath: child, writeEnabled: false },
        ],
      }, { platform: 'darwin' }),
      (error) => error.code === 'WORKSPACE_MOUNT_OVERLAP',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('canonical mount validation allows independent sibling folders with independent Write state', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-siblings-')));
  const projectA = path.join(root, 'a');
  const projectB = path.join(root, 'b');
  try {
    await mkdir(projectA);
    await mkdir(projectB);

    const config = await canonicalizeWorkspaceMountConfig({
      version: 1,
      mounts: [
        { id: 'a', hostPath: projectA, writeEnabled: true },
        { id: 'b', hostPath: projectB },
      ],
    }, { platform: 'darwin' });

    assert.equal(config.mounts[0].hostPath, projectA);
    assert.equal(config.mounts[0].writeEnabled, true);
    assert.equal(config.mounts[1].hostPath, projectB);
    assert.equal(config.mounts[1].writeEnabled, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('mount args enforce each folder write policy independently', () => {
  const args = buildWorkspaceMountSetArgs({
    version: 1,
    mounts: [
      { id: 'writable', hostPath: '/tmp/writable', writeEnabled: true },
      { id: 'protected', hostPath: '/tmp/protected', writeEnabled: false },
    ],
  });

  assert.deepEqual(args, [
    '--mount',
    'type=bind,src=/tmp/writable,dst=/workspace/mounts/writable,bind-recursive=disabled',
    '--mount',
    'type=bind,src=/tmp/protected,dst=/workspace/mounts/protected,bind-recursive=disabled,readonly',
  ]);
});

test('control-plane masks are remapped beneath the owning mounted folder', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-mask-'));
  const projectA = path.join(root, 'a');
  const projectB = path.join(root, 'b');
  const protectedDir = path.join(projectB, '.webmcp');
  try {
    await mkdir(projectA);
    await mkdir(protectedDir, { recursive: true });

    const config = await canonicalizeWorkspaceMountConfig({
      version: 1,
      mounts: [
        { id: 'a', hostPath: projectA, writeEnabled: true },
        { id: 'b', hostPath: projectB, writeEnabled: false },
      ],
    }, { platform: 'darwin' });
    const plan = await buildWorkspaceMountMaskPlan({
      mountConfig: config,
      protectedPaths: [protectedDir],
    });

    assert.deepEqual(
      plan.map(({ mountId, type, destination }) => ({ mountId, type, destination })),
      [{
        mountId: 'b',
        type: 'directory',
        destination: '/workspace/mounts/b/.webmcp',
      }],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('add/remove/write operations keep folder identity stable and default new folders Write OFF', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-ops-'));
  const projectA = path.join(root, 'Project A');
  const projectB = path.join(root, 'Project B');
  try {
    await mkdir(projectA);
    await mkdir(projectB);
    const empty = normalizeWorkspaceMountConfig({ version: 1, mounts: [] });
    const withA = await addWorkspaceMount(empty, { hostPath: projectA, platform: 'darwin' });
    assert.equal(withA.mounts.length, 1);
    assert.equal(withA.mounts[0].writeEnabled, false);
    assert.equal(withA.mounts[0].id, workspaceMountIdForPath(await realpath(projectA)));

    const writableA = setWorkspaceMountWrite(withA, withA.mounts[0].id, true);
    assert.equal(writableA.mounts[0].writeEnabled, true);
    const withB = await addWorkspaceMount(writableA, { hostPath: projectB, platform: 'darwin' });
    assert.equal(withB.mounts[0].id, writableA.mounts[0].id);
    assert.equal(withB.mounts[1].writeEnabled, false);

    const removedA = removeWorkspaceMount(withB, withB.mounts[0].id);
    assert.deepEqual(removedA.mounts.map((mount) => mount.id), [withB.mounts[1].id]);
    const emptyAgain = removeWorkspaceMount(removedA, removedA.mounts[0].id);
    assert.deepEqual(emptyAgain.mounts, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('workspace mount config persists atomically and reloads normalized state', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-mount-persist-'));
  try {
    const configPath = path.join(root, 'state', 'workspace-mounts.json');
    const saved = await persistWorkspaceMountConfig(configPath, {
      version: 1,
      mounts: [{ id: 'project', hostPath: '/tmp/project', writeEnabled: false }],
    });
    assert.equal(saved.mounts[0].containerPath, '/workspace/mounts/project');
    const loaded = await loadWorkspaceMountConfig(configPath);
    assert.deepEqual(loaded, saved);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('write-authority narrowing detects Write OFF and removal of writable folders only', () => {
  const base = normalizeWorkspaceMountConfig({
    version: 1,
    mounts: [
      { id: 'a', hostPath: '/tmp/a', writeEnabled: true },
      { id: 'b', hostPath: '/tmp/b', writeEnabled: false },
    ],
  });
  assert.equal(narrowsWorkspaceWriteAuthority(base, setWorkspaceMountWrite(base, 'a', false)), true);
  assert.equal(narrowsWorkspaceWriteAuthority(base, removeWorkspaceMount(base, 'a')), true);
  assert.equal(narrowsWorkspaceWriteAuthority(base, setWorkspaceMountWrite(base, 'b', true)), false);
  assert.equal(narrowsWorkspaceWriteAuthority(base, removeWorkspaceMount(base, 'b')), false);
});

test('legacy single-root configuration migrates without changing its effective write permission', () => {
  const writable = migrateLegacyWorkspaceConfig({
    version: 1,
    hostRoot: '/tmp/project',
    mode: 'workspace',
    readOnly: false,
  }, { mountId: 'legacy-main' });
  assert.deepEqual(writable.mounts[0], {
    id: 'legacy-main',
    hostPath: '/tmp/project',
    writeEnabled: true,
    containerPath: '/workspace/mounts/legacy-main',
  });

  const protectedConfig = migrateLegacyWorkspaceConfig({
    version: 1,
    hostRoot: '/tmp/project',
    mode: 'workspace',
    readOnly: true,
  }, { mountId: 'legacy-main' });
  assert.equal(protectedConfig.mounts[0].writeEnabled, false);
});
