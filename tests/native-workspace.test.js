import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { PassThrough } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import {
  createWorkspaceRuntime,
  decodeRuntimeMountPolicy,
  NativeWorkspaceError,
  NATIVE_WORKSPACE_ROOT,
} from '../native/src/workspace.js';

async function withRuntime(run, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-workspace-'));
  const runtime = createWorkspaceRuntime({ root, runtimeToken: 'test-runtime', ...options });
  try {
    await run({ root, runtime, workspaceId: runtime.workspaceId });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof NativeWorkspaceError);
    assert.equal(error.code, code);
    return true;
  });
}

test('open_workspace exposes only the fixed Native root and returns a runtime-bound id', async () => {
  await withRuntime(async ({ runtime }) => {
    const opened = await runtime.openWorkspace(NATIVE_WORKSPACE_ROOT);
    assert.equal(opened.root, '/workspace');
    assert.equal(opened.workspaceId, 'ws_test-runtime');
    assert.match(opened.instruction, /AGENTS\.md/);
    assert.match(opened.instruction, /workspace-owned semantic checkpoint/);
    assert.match(opened.instruction, /\/workspace\/\.webmcp\/resumes\//);
    assert.match(opened.instruction, /\/workspace\/WEBMCP-RESUME\.md as a pointer only/);
    assert.match(opened.instruction, /Git\/filesystem state is authoritative/);
    await expectCode(runtime.openWorkspace('/tmp'), 'invalid_workspace_root');
  });
});

test('an adapter supplies its own checkout instruction without changing the default', async () => {
  const instruction = 'Workspace opened for bounded adapter coding. Remain inside /workspace.';
  await withRuntime(async ({ runtime }) => {
    const opened = await runtime.openWorkspace(NATIVE_WORKSPACE_ROOT);
    assert.equal(opened.mode, 'checkout');
    assert.equal(opened.instruction, instruction);
  }, { checkoutInstruction: instruction });
  assert.throws(() => createWorkspaceRuntime({ root: '/workspace', checkoutInstruction: '' }), /checkout instruction/i);
});

test('read, write, and edit operate only through the active workspace id', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await writeFile(path.join(root, 'note.txt'), 'alpha\nbeta\n', 'utf8');

    const first = await runtime.read({ workspaceId, path: 'note.txt', offset: 1, limit: 1 });
    assert.equal(first.result, 'alpha');
    assert.equal(first.nextOffset, 2);

    const written = await runtime.write({ workspaceId, path: 'created.txt', content: 'one\ntwo\n' });
    assert.match(written.result, /Successfully wrote/);
    assert.equal(await readFile(path.join(root, 'created.txt'), 'utf8'), 'one\ntwo\n');

    const edited = await runtime.edit({
      workspaceId,
      path: 'note.txt',
      edits: [{ oldText: 'beta', newText: 'gamma' }],
    });
    assert.equal(edited.status, 'applied');
    assert.equal(await readFile(path.join(root, 'note.txt'), 'utf8'), 'alpha\ngamma\n');

    await expectCode(runtime.read({ workspaceId: 'ws_stale', path: 'note.txt' }), 'invalid_workspace_id');
  });
});

test('multi-mount runtime keeps reads available and enforces Write per mounted folder', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-multi-workspace-')));
  const mountA = path.join(root, 'mounts', 'a');
  const mountB = path.join(root, 'mounts', 'b');
  try {
    await mkdir(mountA, { recursive: true });
    await mkdir(mountB, { recursive: true });
    await writeFile(path.join(mountA, 'a.txt'), 'a', 'utf8');
    await writeFile(path.join(mountB, 'b.txt'), 'b', 'utf8');
    await symlink(mountB, path.join(mountA, 'to-b'), 'dir');

    const runtime = createWorkspaceRuntime({
      root,
      runtimeToken: 'multi-runtime',
      mountPolicies: [
        { id: 'a', path: mountA, writeEnabled: true },
        { id: 'b', path: mountB, writeEnabled: false },
      ],
    });
    const workspaceId = runtime.workspaceId;
    const opened = await runtime.openWorkspace(NATIVE_WORKSPACE_ROOT);
    assert.equal(opened.mode, 'multi-mount');
    assert.deepEqual(opened.mounts.map(({ id, writeEnabled }) => ({ id, writeEnabled })), [
      { id: 'a', writeEnabled: true },
      { id: 'b', writeEnabled: false },
    ]);

    assert.equal((await runtime.read({ workspaceId, path: 'mounts/b/b.txt' })).result, 'b');
    await runtime.write({ workspaceId, path: 'mounts/a/new.txt', content: 'ok' });
    assert.equal(await readFile(path.join(mountA, 'new.txt'), 'utf8'), 'ok');

    await expectCode(
      runtime.write({ workspaceId, path: 'mounts/b/new.txt', content: 'blocked' }),
      'workspace_write_disabled',
    );
    await expectCode(
      runtime.edit({ workspaceId, path: 'mounts/b/b.txt', edits: [{ oldText: 'b', newText: 'changed' }] }),
      'workspace_write_disabled',
    );
    assert.equal(await readFile(path.join(mountB, 'b.txt'), 'utf8'), 'b');

    await expectCode(
      runtime.write({ workspaceId, path: 'outside.txt', content: 'blocked' }),
      'workspace_write_not_mounted',
    );
    await expectCode(
      runtime.write({ workspaceId, path: 'mounts/a/to-b/escaped.txt', content: 'blocked' }),
      'workspace_write_disabled',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runtime mount policy marker decoding fails closed on malformed input', () => {
  const marker = Buffer.from(JSON.stringify([
    { id: 'a', path: '/workspace/mounts/a', writeEnabled: true },
  ]), 'utf8').toString('base64url');
  assert.deepEqual(decodeRuntimeMountPolicy(marker), [
    { id: 'a', path: '/workspace/mounts/a', writeEnabled: true },
  ]);
  assert.equal(decodeRuntimeMountPolicy(undefined), null);
  assert.throws(() => decodeRuntimeMountPolicy('not-json'), (error) => error.code === 'invalid_mount_policy');
});

test('edit rejects missing, non-unique, and overlapping exact replacements', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await writeFile(path.join(root, 'edit.txt'), 'abc abc xyz', 'utf8');

    await expectCode(runtime.edit({
      workspaceId,
      path: 'edit.txt',
      edits: [{ oldText: 'missing', newText: 'x' }],
    }), 'edit_no_match');

    await expectCode(runtime.edit({
      workspaceId,
      path: 'edit.txt',
      edits: [{ oldText: 'abc', newText: 'x' }],
    }), 'edit_non_unique');

    await writeFile(path.join(root, 'edit.txt'), 'abcdef', 'utf8');
    await expectCode(runtime.edit({
      workspaceId,
      path: 'edit.txt',
      edits: [
        { oldText: 'abcd', newText: '1' },
        { oldText: 'cdef', newText: '2' },
      ],
    }), 'edit_overlap');
  });
});

test('path policy rejects traversal and sensitive credential paths before file access', async () => {
  const outside = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-outside-'));
  try {
    await writeFile(path.join(outside, 'outside.txt'), 'outside', 'utf8');
    await withRuntime(async ({ root, runtime, workspaceId }) => {
      await writeFile(path.join(root, '.env'), 'SECRET=value', 'utf8');
      await expectCode(runtime.read({ workspaceId, path: '../outside.txt' }), 'path_escape');
      await expectCode(runtime.read({ workspaceId, path: '.env' }), 'blocked_sensitive_filename');
      await expectCode(runtime.write({ workspaceId, path: '.ssh/id_ed25519', content: 'x' }), 'blocked_sensitive_directory');
    });
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test('path policy is re-applied to canonical in-workspace symlink targets', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await writeFile(path.join(root, '.env'), 'SECRET=hidden', 'utf8');
    await symlink(path.join(root, '.env'), path.join(root, 'ordinary.txt'));
    await expectCode(runtime.read({ workspaceId, path: 'ordinary.txt' }), 'blocked_sensitive_filename');

    await mkdir(path.join(root, '.ssh'));
    await symlink(path.join(root, '.ssh'), path.join(root, 'ordinary-dir'), 'dir');
    await expectCode(
      runtime.write({ workspaceId, path: 'ordinary-dir/config', content: 'blocked' }),
      'blocked_sensitive_directory',
    );
  });
});

test('write uses the validated canonical parent if the lexical directory alias is replaced', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-write-race-'));
  try {
    const safeDir = path.join(root, 'safe');
    const sensitiveDir = path.join(root, '.ssh');
    const alias = path.join(root, 'alias');
    await mkdir(safeDir);
    await mkdir(sensitiveDir);
    await symlink(safeDir, alias, 'dir');

    let aliasReplaced = false;
    const realpathImpl = async (candidate) => {
      const actual = await realpath(candidate);
      if (!aliasReplaced && path.resolve(candidate) === alias) {
        aliasReplaced = true;
        await rm(alias, { force: true });
        await symlink(sensitiveDir, alias, 'dir');
      }
      return actual;
    };
    const runtime = createWorkspaceRuntime({ root, runtimeToken: 'race', realpathImpl });

    await runtime.write({ workspaceId: runtime.workspaceId, path: 'alias/config', content: 'safe' });
    assert.equal(await readFile(path.join(safeDir, 'config'), 'utf8'), 'safe');
    await assert.rejects(readFile(path.join(sensitiveDir, 'config'), 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('symlinks cannot make read/write silently follow an out-of-workspace target', async () => {
  const outside = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-symlink-outside-'));
  try {
    await writeFile(path.join(outside, 'secret.txt'), 'outside', 'utf8');
    await withRuntime(async ({ root, runtime, workspaceId }) => {
      await symlink(path.join(outside, 'secret.txt'), path.join(root, 'escape.txt'));
      await expectCode(runtime.read({ workspaceId, path: 'escape.txt' }), 'path_escape');
      await expectCode(runtime.write({ workspaceId, path: 'escape.txt', content: 'replace' }), 'write_failed');
    });
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test('read follows a validated in-workspace symlink but write/edit never write through it', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await writeFile(path.join(root, 'target.txt'), 'safe', 'utf8');
    await symlink(path.join(root, 'target.txt'), path.join(root, 'link.txt'));
    const read = await runtime.read({ workspaceId, path: 'link.txt' });
    assert.equal(read.result, 'safe');
    await expectCode(runtime.write({ workspaceId, path: 'link.txt', content: 'changed' }), 'write_failed');
    await expectCode(runtime.edit({
      workspaceId,
      path: 'link.txt',
      edits: [{ oldText: 'safe', newText: 'changed' }],
    }), 'write_failed');
    assert.equal(await readFile(path.join(root, 'target.txt'), 'utf8'), 'safe');
  });
});

test('bash runs inside the workspace and rejects stale ids and escaped working directories', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await mkdir(path.join(root, 'child'));
    const pwd = await runtime.bash({ workspaceId, command: 'printf %s "$PWD"', workingDirectory: 'child' });
    assert.equal(pwd.result, path.join(await realpath(root), 'child'));

    await expectCode(runtime.bash({ workspaceId: 'ws_old', command: 'true' }), 'invalid_workspace_id');
    await expectCode(runtime.bash({ workspaceId, command: 'true', workingDirectory: '..' }), 'path_escape');
  });
});

test('bash receives only the explicit runtime environment allowlist', async () => {
  const previous = process.env.WEBMCP_TEST_UNTRUSTED_ENV;
  process.env.WEBMCP_TEST_UNTRUSTED_ENV = 'must-not-cross';
  try {
    await withRuntime(async ({ runtime, workspaceId }) => {
      const result = await runtime.bash({
        workspaceId,
        command: 'printf %s "${WEBMCP_TEST_UNTRUSTED_ENV-unset}"',
      });
      assert.equal(result.result, 'unset');
    });
  } finally {
    if (previous === undefined) delete process.env.WEBMCP_TEST_UNTRUSTED_ENV;
    else process.env.WEBMCP_TEST_UNTRUSTED_ENV = previous;
  }
});

test('bash enforces timeout and output bounds', async () => {
  await withRuntime(async ({ runtime, workspaceId }) => {
    await expectCode(runtime.bash({ workspaceId, command: 'sleep 1', timeout: 0.05 }), 'bash_timeout');
  });

  await withRuntime(async ({ runtime, workspaceId }) => {
    await expectCode(
      runtime.bash({ workspaceId, command: "printf '1234567890'" }),
      'output_too_large',
    );
  }, { maxOutputBytes: 5 });
});

test('bash timeout terminates descendants in the detached process group before close settlement', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await expectCode(runtime.bash({
      workspaceId,
      command: 'sleep 30 & echo $! > descendant.pid; wait',
      timeout: 0.1,
    }), 'bash_timeout');

    const descendantPid = Number((await readFile(path.join(root, 'descendant.pid'), 'utf8')).trim());
    assert.ok(Number.isInteger(descendantPid) && descendantPid > 0);
    const status = await runtime.bash({
      workspaceId,
      command: `ps -o stat= -p ${descendantPid} 2>/dev/null || true`,
    });
    assert.ok(
      status.result.trim() === '' || /^Z/.test(status.result.trim()),
      `descendant must be terminated, got process state: ${status.result.trim()}`,
    );
  });
});

test('bash cancellation has a bounded fallback when close never arrives', async () => {
  const child = new EventEmitter();
  child.pid = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;

  await withRuntime(async ({ runtime, workspaceId }) => {
    const startedAt = Date.now();
    await expectCode(runtime.bash({ workspaceId, command: 'sleep forever', timeout: 0.01 }), 'bash_timeout');
    assert.ok(Date.now() - startedAt < 2000, 'cancellation fallback must settle within a fixed bound');
  }, { spawnImpl: () => child });
});

test('a read-only workspace names its state, drops the checkpoint duty, and refuses writes without redirecting them', async () => {
  await withRuntime(async ({ root, runtime, workspaceId }) => {
    await writeFile(path.join(root, 'note.txt'), 'alpha\n', 'utf8');
    const opened = await runtime.openWorkspace(NATIVE_WORKSPACE_ROOT);

    assert.equal(opened.mode, 'read-only');
    // The resume protocol fires "before the first modification"; a read-only host has none,
    // so the instruction must not send the model into a write it cannot perform.
    assert.match(opened.instruction, /Do not create or refresh the workspace-owned semantic checkpoint/);
    assert.match(opened.instruction, /do not update \/workspace\/WEBMCP-RESUME\.md/);
    assert.match(opened.instruction, /never write the content to a different host instead/);
    assert.match(opened.instruction, /--no-optional-locks/);
    // The claim must stay scoped to the mount: /tmp inside the container is still writable.
    assert.match(opened.instruction, /every write into \/workspace fails/);
    assert.match(opened.instruction, /container temp directory, are not covered/);

    assert.equal((await runtime.read({ workspaceId, path: 'note.txt' })).result, 'alpha\n');

    await expectCode(runtime.write({ workspaceId, path: 'note.txt', content: 'beta\n' }), 'workspace_read_only');
    await expectCode(
      runtime.edit({ workspaceId, path: 'note.txt', edits: [{ oldText: 'alpha', newText: 'beta' }] }),
      'workspace_read_only',
    );
    assert.equal(await readFile(path.join(root, 'note.txt'), 'utf8'), 'alpha\n');
  }, { readOnly: true });
});
