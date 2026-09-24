import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const ATTACHMENT_GENERATION_VERSION = 1;

export class AttachmentGenerationError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'AttachmentGenerationError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new AttachmentGenerationError(message, code, options);
}

function assertContext(context) {
  if (!context || typeof context.attachmentGeneration !== 'string' || !path.isAbsolute(context.attachmentGeneration)) {
    fail('Attachment generation requires a trusted instance context.', 'INVALID_ATTACHMENT_GENERATION_CONTEXT');
  }
}

function parseGeneration(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail('Attachment generation state is not valid JSON.', 'INVALID_ATTACHMENT_GENERATION', { cause: error });
  }
  const keys = Object.keys(value ?? {}).sort();
  if (
    JSON.stringify(keys) !== JSON.stringify(['generation', 'version'])
    || value.version !== ATTACHMENT_GENERATION_VERSION
    || !Number.isSafeInteger(value.generation)
    || value.generation < 0
  ) {
    fail('Attachment generation state is invalid.', 'INVALID_ATTACHMENT_GENERATION');
  }
  return value.generation;
}

export async function readInstanceAttachmentGeneration(context) {
  assertContext(context);
  try {
    return parseGeneration(await readFile(context.attachmentGeneration, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return 0;
    if (error instanceof AttachmentGenerationError) throw error;
    fail('Unable to read attachment generation state.', 'ATTACHMENT_GENERATION_UNAVAILABLE', { cause: error });
  }
}

async function persistGeneration(context, generation) {
  const directory = path.dirname(context.attachmentGeneration);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    directory,
    `.${path.basename(context.attachmentGeneration)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify({
      version: ATTACHMENT_GENERATION_VERSION,
      generation,
    }, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temporary, context.attachmentGeneration);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    fail('Unable to persist attachment generation state.', 'ATTACHMENT_GENERATION_WRITE_FAILED', { cause: error });
  }
  return generation;
}

export async function bumpInstanceAttachmentGeneration(context) {
  assertContext(context);
  const current = await readInstanceAttachmentGeneration(context);
  if (current >= Number.MAX_SAFE_INTEGER) {
    fail('Attachment generation is exhausted.', 'ATTACHMENT_GENERATION_EXHAUSTED');
  }
  return persistGeneration(context, current + 1);
}
