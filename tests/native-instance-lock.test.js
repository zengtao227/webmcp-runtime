import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createInstanceContext } from '../native/deploy/instance-context.js';
import { withInstanceLifecycleLock } from '../native/deploy/instance-lock.js';

test('instance lifecycle lock serializes one instance without touching sibling state', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-lock-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    const other = createInstanceContext({ home, instanceId: 'review' });
    let inside = false;

    const result = await withInstanceLifecycleLock(adapter, async () => {
      inside = true;
      assert.notEqual(adapter.lifecycleLock, other.lifecycleLock);
      await assert.rejects(
        withInstanceLifecycleLock(adapter, async () => {}),
        (error) => error?.code === 'INSTANCE_BUSY',
      );
      return 'ok';
    });

    assert.equal(inside, true);
    assert.equal(result, 'ok');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('concurrent stale-lock reclaim admits only one lifecycle owner', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-lock-race-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    await mkdir(path.dirname(adapter.lifecycleLock), { recursive: true });
    await writeFile(adapter.lifecycleLock, JSON.stringify({ pid: 999999, createdAt: new Date().toISOString() }));

    let releaseWinnerResolve;
    const releaseWinner = new Promise((resolve) => { releaseWinnerResolve = resolve; });
    let winnerEnteredResolve;
    const winnerEntered = new Promise((resolve) => { winnerEnteredResolve = resolve; });
    let entered = 0;
    const options = {
      killImpl: (pid) => {
        if (pid === process.pid) return;
        const error = new Error('gone');
        error.code = 'ESRCH';
        throw error;
      },
    };
    const contender = () => withInstanceLifecycleLock(adapter, async () => {
      entered += 1;
      winnerEnteredResolve();
      await releaseWinner;
      return 'winner';
    }, options);

    const first = contender();
    const second = contender();
    const observe = (promise) => promise.then(
      (value) => ({ status: 'fulfilled', value }),
      (reason) => ({ status: 'rejected', reason }),
    );
    const firstObserved = observe(first);
    const secondObserved = observe(second);
    await winnerEntered;
    const settledBeforeRelease = await Promise.race([
      firstObserved,
      secondObserved,
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 1000)),
    ]);
    assert.notEqual(settledBeforeRelease, 'timeout', 'one contender must be rejected while the winner still holds the lock');
    assert.equal(settledBeforeRelease?.status, 'rejected');
    assert.equal(settledBeforeRelease?.reason?.code, 'INSTANCE_BUSY');
    assert.equal(entered, 1);

    releaseWinnerResolve();
    const results = await Promise.allSettled([first, second]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(results.filter((result) => result.status === 'rejected').length, 1);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('orphaned reclaim contenders from a crashed reclaimer do not block stale-lock recovery', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-lock-orphan-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    const lockGeneration = 'a'.repeat(32);
    const deadToken = 'b'.repeat(32);
    const reclaimDirectory = `${adapter.lifecycleLock}.reclaim`;
    await mkdir(reclaimDirectory, { recursive: true });
    await writeFile(adapter.lifecycleLock, JSON.stringify({
      pid: 999999,
      createdAt: new Date().toISOString(),
      generation: lockGeneration,
    }));
    await writeFile(path.join(reclaimDirectory, `${deadToken}.json`), JSON.stringify({
      pid: 888888,
      createdAt: new Date().toISOString(),
      lockGeneration,
      token: deadToken,
    }));
    // Intermediate pre-fix guard artifacts are ignored by the contender-based reclaim scheme.
    await writeFile(`${adapter.lifecycleLock}.reclaim-${lockGeneration}`, '');

    const result = await withInstanceLifecycleLock(adapter, async () => 'recovered', {
      killImpl: (pid) => {
        if (pid === process.pid) return;
        const error = new Error('gone');
        error.code = 'ESRCH';
        throw error;
      },
    });

    assert.equal(result, 'recovered');
    assert.deepEqual(await readdir(reclaimDirectory), []);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('an interrupted contender publication does not block stale-lock recovery', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-lock-partial-'));
  try {
    const context = createInstanceContext({ home, instanceId: 'adapter' });
    const contenderDirectory = `${context.lifecycleLock}.reclaim`;
    await mkdir(contenderDirectory, { recursive: true });
    await writeFile(context.lifecycleLock, JSON.stringify({
      pid: 999999,
      createdAt: new Date().toISOString(),
      generation: 'a'.repeat(32),
    }));
    await writeFile(path.join(contenderDirectory, `${'b'.repeat(32)}.tmp`), '');

    const result = await withInstanceLifecycleLock(context, async () => 'recovered', {
      killImpl: (pid) => {
        if (pid === process.pid) return;
        const error = new Error('gone');
        error.code = 'ESRCH';
        throw error;
      },
    });
    assert.equal(result, 'recovered');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('a lock owned by a dead process is reclaimed, while malformed ownership fails closed', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'webmcp-instance-lock-'));
  try {
    const adapter = createInstanceContext({ home, instanceId: 'adapter' });
    await mkdir(path.dirname(adapter.lifecycleLock), { recursive: true });
    await writeFile(adapter.lifecycleLock, JSON.stringify({ pid: 999999, createdAt: new Date().toISOString() }));

    const result = await withInstanceLifecycleLock(
      adapter,
      async () => 'reclaimed',
      {
        killImpl: (pid) => {
          if (pid === process.pid) return;
          const error = new Error('gone');
          error.code = 'ESRCH';
          throw error;
        },
      },
    );
    assert.equal(result, 'reclaimed');

    await writeFile(adapter.lifecycleLock, 'not-json');
    await assert.rejects(
      withInstanceLifecycleLock(adapter, async () => {}),
      (error) => error?.code === 'INSTANCE_LOCK_UNVERIFIED',
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
