#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { inspectSource } from '../../adapter/deploy/deploy-host-runtime.js';
import { DEFAULT_IMAGE_PIN, IMAGE_PIN_VERSION, persistImagePin } from './image-pin.js';
import {
  aggregateSourceDigest,
  NATIVE_RUNTIME_ENTRYPOINT,
  NATIVE_RUNTIME_PAYLOAD,
} from './runtime-payload.js';

const execFileAsync = promisify(execFile);
const DEFAULT_TAG = 'webmcp-native:reviewed';

export class NativeImageBuildError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'NativeImageBuildError';
    this.code = code;
  }
}

function fail(message, code, options = {}) {
  throw new NativeImageBuildError(message, code, options);
}

function assertPinnedBaseImage(image) {
  if (typeof image !== 'string' || !/@sha256:[0-9a-f]{64}$/i.test(image)) {
    fail('Native base image must be an explicit name@sha256:digest reference.', 'UNPINNED_BASE_IMAGE');
  }
}

async function assertCleanRepository(sourceRoot, execFileImpl = execFileAsync) {
  let stdout;
  try {
    ({ stdout } = await execFileImpl('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
      cwd: sourceRoot,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    }));
  } catch (error) {
    fail('Unable to verify a clean Git source before Native image build.', 'GIT_VERIFICATION_FAILED', { cause: error });
  }
  if (stdout.trim().length > 0) {
    fail('Native release image builds require a completely clean Git working tree.', 'DIRTY_IMAGE_SOURCE');
  }
}

async function materializeReviewedContext(source, contextRoot) {
  for (const file of source.files) {
    const destination = path.join(contextRoot, file.path);
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await writeFile(destination, file.bytes, { mode: 0o644 });
  }
}

function parseImageInspect(text, expectedSourceSha256) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    fail('Docker image inspect returned invalid JSON.', 'INVALID_IMAGE_INSPECT', { cause: error });
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
    fail('Docker image inspect returned an unexpected payload.', 'INVALID_IMAGE_INSPECT');
  }
  const image = parsed[0];
  if (typeof image.Id !== 'string' || !/^sha256:[0-9a-f]{64}$/i.test(image.Id)) {
    fail('Built Native image does not have an immutable sha256 image ID.', 'INVALID_IMAGE_ID');
  }
  const sourceLabel = image?.Config?.Labels?.['com.webmcp.native.source-sha256'];
  if (sourceLabel !== expectedSourceSha256) {
    fail('Built Native image source label does not match the reviewed payload.', 'IMAGE_SOURCE_MISMATCH');
  }
  if (image?.Config?.User !== '65532:65532') {
    fail('Built Native image must remain non-root by default.', 'IMAGE_RUNTIME_IDENTITY_MISMATCH');
  }
  return image.Id.toLowerCase();
}

export async function buildNativeImage({
  sourceRoot,
  baseImage,
  outputPin = DEFAULT_IMAGE_PIN,
  tag = DEFAULT_TAG,
  dockerBin = 'docker',
  execFileImpl = execFileAsync,
  inspectSourceImpl = inspectSource,
  assertCleanImpl = assertCleanRepository,
} = {}) {
  if (typeof sourceRoot !== 'string' || !path.isAbsolute(sourceRoot)) {
    fail('sourceRoot must be an absolute Git repository path.', 'INVALID_SOURCE_ROOT');
  }
  if (typeof outputPin !== 'string' || !path.isAbsolute(outputPin)) {
    fail('outputPin must be an absolute host path.', 'INVALID_IMAGE_PIN_PATH');
  }
  if (typeof tag !== 'string' || tag.length === 0 || /[\r\n\0]/.test(tag)) {
    fail('Native image tag is invalid.', 'INVALID_IMAGE_TAG');
  }
  assertPinnedBaseImage(baseImage);

  await assertCleanImpl(sourceRoot, execFileImpl);
  const source = await inspectSourceImpl({
    sourceRoot,
    payloadPaths: NATIVE_RUNTIME_PAYLOAD,
    entrypoint: NATIVE_RUNTIME_ENTRYPOINT,
  });

  const runtimeSourceSha256 = aggregateSourceDigest(source.files);
  const contextRoot = await mkdtemp(path.join(os.tmpdir(), 'webmcp-native-image-'));
  try {
    await materializeReviewedContext(source, contextRoot);
    const dockerfile = path.join(contextRoot, 'native', 'Dockerfile');
    try {
      await execFileImpl(dockerBin, [
        'build',
        '--file', dockerfile,
        '--build-arg', `WEBMCP_NODE_IMAGE=${baseImage}`,
        '--build-arg', `WEBMCP_SOURCE_SHA256=${runtimeSourceSha256}`,
        '--tag', tag,
        contextRoot,
      ], {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (error) {
      fail('Docker failed to build the reviewed Native image.', 'IMAGE_BUILD_FAILED', { cause: error });
    }

    let inspect;
    try {
      inspect = await execFileImpl(dockerBin, ['image', 'inspect', tag], {
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
      });
    } catch (error) {
      fail('Unable to inspect the built Native image.', 'IMAGE_INSPECT_FAILED', { cause: error });
    }
    const image = parseImageInspect(inspect.stdout, runtimeSourceSha256);
    const pin = await persistImagePin(outputPin, {
      version: IMAGE_PIN_VERSION,
      image,
      sourceSha256: runtimeSourceSha256,
    });
    return Object.freeze({ ...pin, gitCommit: source.gitCommit, tag });
  } finally {
    await rm(contextRoot, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  const options = { sourceRoot: null, baseImage: null, outputPin: DEFAULT_IMAGE_PIN, tag: DEFAULT_TAG };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) throw new Error(`Missing value for ${arg}.`);
      return argv[index];
    };
    if (arg === '--source-root') options.sourceRoot = path.resolve(next());
    else if (arg === '--base-image') options.baseImage = next();
    else if (arg === '--output-pin') options.outputPin = path.resolve(next());
    else if (arg === '--tag') options.tag = next();
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (!options.baseImage) throw new Error('--base-image is required.');
  return options;
}

async function main() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../..');
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = await buildNativeImage({ ...options, sourceRoot: options.sourceRoot ?? repo });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`Native image build failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (isMain) {
  await main();
}
