import { narrowsWorkspaceWriteAuthority } from './workspace-mount-config.js';

export class WorkspaceMountTransitionError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'WorkspaceMountTransitionError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new WorkspaceMountTransitionError(message, code, options);
}

export async function applyWorkspaceMountTransition({
  previousConfig,
  nextConfig,
  stopService,
  prepareCurrentContainer,
  removeCurrentContainer,
  persistConfig,
  createContainer,
  startService,
  verifyInstalled = async () => {},
  removeCreatedContainer,
  restorePreviousConfig,
  ensurePreviousContainer,
} = {}) {
  const tightening = narrowsWorkspaceWriteAuthority(previousConfig, nextConfig);
  let createdContainerId = null;
  let configPersisted = false;

  try {
    await stopService();
    const prepared = await prepareCurrentContainer();
    // Persist the requested authority before replacing the old container. If cleanup or recreation
    // fails, any later host restart sees the new policy and fails closed on an old-container mismatch.
    await persistConfig(nextConfig);
    configPersisted = true;
    await removeCurrentContainer(prepared.containerId ?? null);
    try {
      const created = await createContainer(nextConfig);
      createdContainerId = created?.action === 'created' ? created.containerId : null;
    } catch (error) {
      createdContainerId = typeof error?.createdContainerId === 'string'
        ? error.createdContainerId
        : null;
      throw error;
    }
    await startService();
    await verifyInstalled(nextConfig);
    return Object.freeze({ action: 'changed', tightening });
  } catch (error) {
    let stopFailure = null;
    try {
      await stopService();
    } catch (stopError) {
      stopFailure = stopError;
    }

    // Even a failure before the normal persist step must not leave a restart
    // authorized by the old ON configuration. Stop uncertainty is reported below.
    if (tightening && !configPersisted) {
      try {
        await persistConfig(nextConfig);
      } catch (persistError) {
        const state = stopFailure === null
          ? 'The Native runtime is stopped.'
          : 'The Native runtime could not be confirmed stopped.';
        fail(
          `Write restriction could not be persisted: ${persistError.message} ${state} Do not restart until the persisted policy is repaired.`,
          'WORKSPACE_MOUNT_PERSIST_FAILED',
          { cause: error },
        );
      }
    }
    if (stopFailure !== null) {
      fail(
        `Workspace mount transition failed and the Native runtime could not be confirmed stopped: ${stopFailure.message}`,
        'WORKSPACE_MOUNT_STOP_UNCONFIRMED',
        { cause: error },
      );
    }

    try {
      await removeCreatedContainer(createdContainerId);
    } catch (cleanupError) {
      fail(
        `Workspace mount transition failed; the Native service is stopped but the newly created container could not be removed: ${cleanupError.message}`,
        'WORKSPACE_MOUNT_CLEANUP_FAILED',
        { cause: error },
      );
    }

    if (tightening) {
      fail(
        'Workspace mount Write restriction could not be applied. The Native service remains stopped; previous writable authority was not restored.',
        'WORKSPACE_MOUNT_TIGHTENING_FAILED',
        { cause: error },
      );
    }

    try {
      await restorePreviousConfig(previousConfig);
      await ensurePreviousContainer(previousConfig);
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
      fail(
        `Workspace mount transition failed and rollback also failed: ${rollbackError.message} ${state}`,
        'WORKSPACE_MOUNT_ROLLBACK_FAILED',
        { cause: error },
      );
    }

    throw error;
  }
}
