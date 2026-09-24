import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { verifyCurrent, verifyRelease } from '../../adapter/deploy/deploy-host-runtime.js';
import { NATIVE_HOST_ENTRYPOINT } from './deploy-host-boundary.js';
import { pinnedInstanceRelease } from './instance-context.js';

export const INSTANCE_RELEASE_PIN_VERSION = 1;
const ARTIFACT_ID_PATTERN = /^[0-9a-f]{40}-[0-9a-f]{64}$/;

export class InstanceReleaseError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'InstanceReleaseError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new InstanceReleaseError(message, code, options);
}

function normalizePin(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Instance release pin must be an object.', 'INVALID_INSTANCE_RELEASE_PIN');
  }
  const keys = Object.keys(value).sort();
  if (JSON.stringify(keys) !== JSON.stringify(['artifactId', 'version'])) {
    fail('Instance release pin must contain only version and artifactId.', 'INVALID_INSTANCE_RELEASE_PIN');
  }
  if (value.version !== INSTANCE_RELEASE_PIN_VERSION || !ARTIFACT_ID_PATTERN.test(value.artifactId)) {
    fail('Instance release pin is invalid.', 'INVALID_INSTANCE_RELEASE_PIN');
  }
  return Object.freeze({
    version: INSTANCE_RELEASE_PIN_VERSION,
    artifactId: value.artifactId,
  });
}

export function parseInstanceReleasePin(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail('Instance release pin is not valid JSON.', 'INVALID_INSTANCE_RELEASE_PIN', { cause: error });
  }
  return normalizePin(value);
}

export async function loadInstanceReleasePin(filePath) {
  try {
    return parseInstanceReleasePin(await readFile(filePath, 'utf8'));
  } catch (error) {
    if (error instanceof InstanceReleaseError) throw error;
    fail('Unable to read instance release pin.', 'INSTANCE_RELEASE_PIN_UNAVAILABLE', { cause: error });
  }
}

export async function persistInstanceReleasePin(filePath, value) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) {
    fail('Instance release pin path must be absolute.', 'INVALID_INSTANCE_RELEASE_PIN_PATH');
  }
  const normalized = normalizePin(value);
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temporary, filePath);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    fail('Unable to persist instance release pin.', 'INSTANCE_RELEASE_PIN_WRITE_FAILED', { cause: error });
  }
  return normalized;
}

function assertNonDefault(context) {
  if (!context || context.isDefault !== false || typeof context.hostReleasePin !== 'string') {
    fail('Instance release pinning requires a non-default instance context.', 'INSTANCE_RELEASE_PIN_NOT_APPLICABLE');
  }
}

export async function pinInstanceToRelease(context, artifactId, {
  verifyReleaseImpl = verifyRelease,
  persistPinImpl = persistInstanceReleasePin,
} = {}) {
  assertNonDefault(context);
  const release = pinnedInstanceRelease(context, artifactId);
  const verified = await verifyReleaseImpl(release.releaseRoot, {
    expectedArtifactId: artifactId,
    entrypoint: NATIVE_HOST_ENTRYPOINT,
  });
  await persistPinImpl(context.hostReleasePin, {
    version: INSTANCE_RELEASE_PIN_VERSION,
    artifactId,
  });
  return Object.freeze({
    artifactId,
    releaseRoot: release.releaseRoot,
    hostEntrypoint: verified.entrypoint,
  });
}

export async function pinInstanceToCurrentRelease(context, {
  verifyCurrentImpl = verifyCurrent,
  persistPinImpl = persistInstanceReleasePin,
} = {}) {
  assertNonDefault(context);
  const current = await verifyCurrentImpl(context.hostRuntimeRoot, { entrypoint: NATIVE_HOST_ENTRYPOINT });
  if (!current) {
    fail('No verified Native host release is currently installed.', 'INSTANCE_RELEASE_UNAVAILABLE');
  }
  await persistPinImpl(context.hostReleasePin, {
    version: INSTANCE_RELEASE_PIN_VERSION,
    artifactId: current.artifactId,
  });
  return Object.freeze({ artifactId: current.artifactId });
}

export async function verifyPinnedInstanceRelease(context, {
  loadPinImpl = loadInstanceReleasePin,
  verifyReleaseImpl = verifyRelease,
} = {}) {
  assertNonDefault(context);
  const pin = await loadPinImpl(context.hostReleasePin);
  const release = pinnedInstanceRelease(context, pin.artifactId);
  const verified = await verifyReleaseImpl(release.releaseRoot, {
    expectedArtifactId: pin.artifactId,
    entrypoint: NATIVE_HOST_ENTRYPOINT,
  });
  return Object.freeze({
    artifactId: pin.artifactId,
    releaseRoot: release.releaseRoot,
    hostEntrypoint: verified.entrypoint,
  });
}
