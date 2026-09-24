import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyWorkspaceMountTransition,
  WorkspaceMountTransitionError,
} from '../native/deploy/workspace-mount-transition.js';

const PREVIOUS = Object.freeze({
  version: 1,
  mounts: Object.freeze([
    Object.freeze({
      id: 'a',
      hostPath: '/tmp/a',
      containerPath: '/workspace/mounts/a',
      writeEnabled: true,
    }),
    Object.freeze({
      id: 'b',
      hostPath: '/tmp/b',
      containerPath: '/workspace/mounts/b',
      writeEnabled: false,
    }),
  ]),
});

function changedWrite(id, writeEnabled) {
  return {
    version: 1,
    mounts: PREVIOUS.mounts.map((mount) => (
      mount.id === id ? { ...mount, writeEnabled } : mount
    )),
  };
}

function harness({ failAt = null } = {}) {
  const calls = [];
  const fail = (stage) => {
    if (failAt === stage) throw new Error(`failed at ${stage}`);
  };
  return {
    calls,
    stopService: async () => { calls.push('stopService'); fail('stopService'); },
    prepareCurrentContainer: async () => { calls.push('prepareCurrentContainer'); fail('prepareCurrentContainer'); return { action: 'absent' }; },
    removeCurrentContainer: async () => { calls.push('removeCurrentContainer'); fail('removeCurrentContainer'); },
    persistConfig: async () => { calls.push('persistConfig'); fail('persistConfig'); },
    createContainer: async () => {
      calls.push('createContainer');
      fail('createContainer');
      return { action: 'created', containerId: 'a'.repeat(64) };
    },
    startService: async () => { calls.push('startService'); fail('startService'); },
    verifyInstalled: async () => { calls.push('verifyInstalled'); fail('verifyInstalled'); },
    removeCreatedContainer: async (id) => { calls.push(`removeCreatedContainer:${id ?? 'null'}`); fail('removeCreatedContainer'); },
    restorePreviousConfig: async () => { calls.push('restorePreviousConfig'); fail('restorePreviousConfig'); },
    ensurePreviousContainer: async () => { calls.push('ensurePreviousContainer'); fail('ensurePreviousContainer'); },
  };
}

test('successful Write transition runs one serialized stop/swap/start/verify sequence', async () => {
  const spy = harness();
  const result = await applyWorkspaceMountTransition({
    previousConfig: PREVIOUS,
    nextConfig: changedWrite('b', true),
    ...spy,
  });

  assert.deepEqual(result, { action: 'changed', tightening: false });
  assert.deepEqual(spy.calls, [
    'stopService',
    'prepareCurrentContainer',
    'persistConfig',
    'removeCurrentContainer',
    'createContainer',
    'startService',
    'verifyInstalled',
  ]);
});

test('failed Write ON rolls back to the previous safer policy and restarts it', async () => {
  const spy = harness({ failAt: 'verifyInstalled' });

  await assert.rejects(
    applyWorkspaceMountTransition({
      previousConfig: PREVIOUS,
      nextConfig: changedWrite('b', true),
      ...spy,
    }),
    /failed at verifyInstalled/,
  );

  assert.deepEqual(spy.calls, [
    'stopService',
    'prepareCurrentContainer',
    'persistConfig',
    'removeCurrentContainer',
    'createContainer',
    'startService',
    'verifyInstalled',
    'stopService',
    `removeCreatedContainer:${'a'.repeat(64)}`,
    'restorePreviousConfig',
    'ensurePreviousContainer',
    'startService',
  ]);
});

test('failed Write OFF never restores previous writable authority and leaves service stopped', async () => {
  const spy = harness({ failAt: 'verifyInstalled' });

  await assert.rejects(
    applyWorkspaceMountTransition({
      previousConfig: PREVIOUS,
      nextConfig: changedWrite('a', false),
      ...spy,
    }),
    (error) => {
      assert.ok(error instanceof WorkspaceMountTransitionError);
      assert.equal(error.code, 'WORKSPACE_MOUNT_TIGHTENING_FAILED');
      return true;
    },
  );

  assert.deepEqual(spy.calls, [
    'stopService',
    'prepareCurrentContainer',
    'persistConfig',
    'removeCurrentContainer',
    'createContainer',
    'startService',
    'verifyInstalled',
    'stopService',
    `removeCreatedContainer:${'a'.repeat(64)}`,
  ]);
  assert.equal(spy.calls.includes('restorePreviousConfig'), false);
  assert.equal(spy.calls.includes('ensurePreviousContainer'), false);
});

test('removing a writable mount is also tightening and fails closed', async () => {
  const spy = harness({ failAt: 'createContainer' });
  const nextConfig = {
    version: 1,
    mounts: PREVIOUS.mounts.filter((mount) => mount.id !== 'a'),
  };

  await assert.rejects(
    applyWorkspaceMountTransition({
      previousConfig: PREVIOUS,
      nextConfig,
      ...spy,
    }),
    (error) => error.code === 'WORKSPACE_MOUNT_TIGHTENING_FAILED',
  );
  assert.equal(spy.calls.includes('restorePreviousConfig'), false);
  assert.equal(spy.calls.at(-1), 'removeCreatedContainer:null');
});

test('failed rollback is reported and attempts to leave the service stopped', async () => {
  const spy = harness({ failAt: 'restorePreviousConfig' });
  let stopCount = 0;
  spy.stopService = async () => {
    stopCount += 1;
    spy.calls.push('stopService');
  };
  spy.verifyInstalled = async () => {
    spy.calls.push('verifyInstalled');
    throw new Error('verification failed');
  };

  await assert.rejects(
    applyWorkspaceMountTransition({
      previousConfig: PREVIOUS,
      nextConfig: changedWrite('b', true),
      ...spy,
    }),
    (error) => {
      assert.equal(error.code, 'WORKSPACE_MOUNT_ROLLBACK_FAILED');
      return true;
    },
  );
  assert.equal(stopCount, 3);
});

for (const stage of ['stopService', 'prepareCurrentContainer', 'persistConfig', 'createContainer', 'startService', 'verifyInstalled']) {
  test(`Write OFF keeps persisted authority narrow after a transient ${stage} failure`, async () => {
    const spy = harness();
    let persisted = PREVIOUS;
    let stopped = false;
    const steps = {
      ...spy,
      stopService: async () => { stopped = true; },
      startService: async () => { stopped = false; },
      persistConfig: async (config) => { persisted = config; },
    };
    const original = steps[stage];
    let failed = false;
    steps[stage] = async (...args) => {
      if (!failed) {
        failed = true;
        throw new Error(`transient ${stage}`);
      }
      return original(...args);
    };
    await assert.rejects(applyWorkspaceMountTransition({
      ...steps,
      previousConfig: PREVIOUS,
      nextConfig: changedWrite('a', false),
    }), (error) => error.code === 'WORKSPACE_MOUNT_TIGHTENING_FAILED');
    assert.equal(persisted.mounts.find((mount) => mount.id === 'a').writeEnabled, false);
    assert.equal(stopped, true);
    assert.equal(spy.calls.includes('restorePreviousConfig'), false);
  });
}

test('unpersistable OFF reports a storage failure instead of promising restart safety', async () => {
  const spy = harness({ failAt: 'persistConfig' });
  await assert.rejects(applyWorkspaceMountTransition({
    ...spy,
    previousConfig: PREVIOUS,
    nextConfig: changedWrite('a', false),
  }), (error) => error.code === 'WORKSPACE_MOUNT_PERSIST_FAILED' && /Do not restart/.test(error.message));
  assert.equal(spy.calls.includes('restorePreviousConfig'), false);
  assert.equal(spy.calls.includes('startService'), false);
});
