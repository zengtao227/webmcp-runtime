import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const IMAGE_PIN_VERSION = 2;
export const DEFAULT_IMAGE_PIN = path.join(os.homedir(), '.local', 'share', 'webmcp', 'native-image.json');

export class ImagePinError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'ImagePinError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new ImagePinError(message, code, options);
}

function normalizeImagePin(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Native image pin must be an object.', 'INVALID_IMAGE_PIN');
  }
  const keys = Object.keys(value).sort();
  if (JSON.stringify(keys) !== JSON.stringify(['image', 'sourceSha256', 'version'])) {
    fail('Native image pin must contain only version, image, and sourceSha256.', 'INVALID_IMAGE_PIN');
  }
  if (value.version !== IMAGE_PIN_VERSION) {
    fail(`Native image pin version must be ${IMAGE_PIN_VERSION}.`, 'INVALID_IMAGE_PIN');
  }
  if (
    typeof value.image !== 'string'
    || (!/@sha256:[0-9a-f]{64}$/i.test(value.image) && !/^sha256:[0-9a-f]{64}$/i.test(value.image))
  ) {
    fail('Native image pin must use an immutable sha256 digest.', 'INVALID_IMAGE_PIN');
  }
  if (typeof value.sourceSha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(value.sourceSha256)) {
    fail('Native image pin sourceSha256 must be a 64-character sha256 digest.', 'INVALID_IMAGE_PIN');
  }
  return Object.freeze({
    version: IMAGE_PIN_VERSION,
    image: value.image,
    sourceSha256: value.sourceSha256.toLowerCase(),
  });
}

export function parseImagePin(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    fail('Native image pin is not valid JSON.', 'INVALID_IMAGE_PIN', { cause: error });
  }
  return normalizeImagePin(parsed);
}

export async function loadImagePin(filePath) {
  let text;
  try {
    text = await readFile(filePath, 'utf8');
  } catch (error) {
    fail(`Unable to read Native image pin: ${filePath}`, 'IMAGE_PIN_UNAVAILABLE', { cause: error });
  }
  return parseImagePin(text);
}

export async function persistImagePin(filePath, value) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) {
    fail('Native image pin path must be absolute.', 'INVALID_IMAGE_PIN_PATH');
  }
  const normalized = normalizeImagePin(value);
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
    fail(`Unable to persist Native image pin: ${filePath}`, 'IMAGE_PIN_WRITE_FAILED', { cause: error });
  }
  return normalized;
}
