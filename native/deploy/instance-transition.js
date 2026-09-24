import { fail } from './installer-error.js';

export async function applyElevatedTransition({
  stopService,
  removeNormalContainer,
  persistLease,
  ensureElevatedContainer,
  startService,
  verifyElevated = async () => {},
  clearLease,
  removeElevatedContainer,
  ensureNormalContainer,
} = {}) {
  try {
    await stopService();
    await removeNormalContainer();
    await persistLease();
    await ensureElevatedContainer();
    await startService();
    await verifyElevated();
  } catch (error) {
    try {
      await stopService();
      await clearLease();
      await removeElevatedContainer();
      await ensureNormalContainer();
      await startService();
    } catch (rollbackError) {
      let stopped = true;
      try {
        await stopService();
      } catch {
        stopped = false;
      }
      const state = stopped
        ? 'The Native service was stopped.'
        : 'The Native service could not be confirmed stopped.';
      fail(`Elevated transition failed and normal-mode rollback also failed: ${rollbackError.message} ${state}`, 'ELEVATION_ROLLBACK_FAILED', { cause: error });
    }
    throw error;
  }
}

export async function applyElevationRevoke({
  stopService,
  clearLease,
  removeElevatedContainer,
  ensureNormalContainer,
  startService,
} = {}) {
  await stopService();
  try {
    await clearLease();
    await removeElevatedContainer();
    await ensureNormalContainer();
    await startService();
  } catch (error) {
    fail(`Elevated access revoke failed closed with the Native service stopped: ${error.message}`, 'ELEVATION_REVOKE_FAILED', { cause: error });
  }
}

export async function removeCreatedNativeContainer(createdContainerId, execFileImpl) {
  if (createdContainerId === null) return;
  if (!/^[0-9a-f]{64}$/i.test(createdContainerId)) {
    fail('The container created by this command could not be identified during rollback; it was left untouched.', 'ROLLBACK_CONTAINER_UNVERIFIED');
  }
  await execFileImpl('docker', ['rm', '-f', createdContainerId], { encoding: 'utf8', maxBuffer: 1024 * 1024 });
}

export async function applyContainerPolicyTransition({
  stopService,
  removeCurrentContainer,
  persistConfig,
  createContainer,
  startService,
  verifyInstalled = async () => {},
  removeCreatedContainer,
  restorePreviousConfig,
  ensurePreviousContainer,
  rollbackFailure,
} = {}) {
  let createdContainerId = null;
  try {
    await stopService();
    await removeCurrentContainer();
    await persistConfig();
    try {
      const created = await createContainer();
      createdContainerId = created?.action === 'created' ? created.containerId : null;
    } catch (error) {
      createdContainerId = typeof error?.createdContainerId === 'string' ? error.createdContainerId : null;
      throw error;
    }
    await startService();
    await verifyInstalled();
  } catch (error) {
    try {
      await stopService();
      await removeCreatedContainer(createdContainerId);
      await restorePreviousConfig();
      await ensurePreviousContainer();
      await startService();
    } catch (rollbackError) {
      let stopped = true;
      try {
        await stopService();
      } catch {
        stopped = false;
      }
      const state = stopped
        ? 'The Native service was stopped.'
        : 'The Native service could not be confirmed stopped.';
      fail(`${rollbackFailure.prefix}: ${rollbackError.message} ${state}`, rollbackFailure.code, { cause: error });
    }
    throw error;
  }
}
