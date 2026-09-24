import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { NATIVE_HOST_RUNTIME_PAYLOAD } from '../native/deploy/deploy-host-boundary.js';
import { aggregateSourceDigest, NATIVE_RUNTIME_PAYLOAD } from '../native/deploy/runtime-payload.js';

const ROOT = process.cwd();
const OUTPUT = path.join(ROOT, 'dist', 'native');

const RUNTIME_PAYLOAD = NATIVE_RUNTIME_PAYLOAD;
const HOST_PAYLOAD = NATIVE_HOST_RUNTIME_PAYLOAD;
const DEPLOY_PAYLOAD = Object.freeze([
  'adapter/deploy/deploy-host-runtime.js',
  'native/deploy/build-image.js',
  'native/deploy/configure-workspace.js',
  'native/deploy/container-controller.js',
  'native/deploy/container-policy.js',
  'native/deploy/control-plane-paths.js',
  'native/deploy/elevated-access.js',
  'native/deploy/host-platform.js',
  'native/deploy/deploy-host-boundary.js',
  'native/deploy/image-pin.js',
  'native/deploy/instance-attachment.js',
  'native/deploy/instance-context.js',
  'native/deploy/instance-lock.js',
  'native/deploy/instance-release.js',
  'native/deploy/local-approval.js',
  'native/deploy/instance-transition.js',
  'native/deploy/local-instance-controller.js',
  'native/deploy/local-instance-expiry.js',
  'native/deploy/runtime-payload.js',
  'native/deploy/workspace-config.js',
  'native/deploy/workspace-mount-config.js',
  'native/deploy/workspace-mount-transition.js',
]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function copyPayload(relativePath) {
  const source = path.join(ROOT, relativePath);
  const destination = path.join(OUTPUT, 'package', relativePath);
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { force: true, preserveTimestamps: false });
  const [bytes, copiedBytes] = await Promise.all([readFile(source), readFile(destination)]);
  if (!bytes.equals(copiedBytes)) {
    throw new Error(`Native build copy verification failed: ${relativePath}`);
  }
  return Object.freeze({
    path: relativePath,
    size: bytes.length,
    sha256: sha256(bytes),
  });
}

const groups = {
  runtime: RUNTIME_PAYLOAD,
  host: HOST_PAYLOAD,
  deploy: DEPLOY_PAYLOAD,
};
const uniquePayload = [...new Set(Object.values(groups).flat())].sort();

await rm(OUTPUT, { recursive: true, force: true });
await mkdir(path.join(OUTPUT, 'package'), { recursive: true });
const files = [];
for (const relativePath of uniquePayload) {
  files.push(await copyPayload(relativePath));
}

const byPath = new Map(files.map((file) => [file.path, file]));
const groupSha256 = Object.fromEntries(Object.entries(groups).map(([name, members]) => [
  name,
  aggregateSourceDigest(members.map((member) => byPath.get(member))),
]));

const manifest = {
  schemaVersion: 1,
  product: 'webmcp-native',
  runtimeEntrypoint: 'native/bin/start.js',
  hostEntrypoint: 'native/host/start.js',
  containerWorkspaceRoot: '/workspace',
  groups,
  groupSha256,
  payloadSha256: aggregateSourceDigest(files),
  files,
};
await writeFile(
  path.join(OUTPUT, 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
  'utf8',
);

console.log(`Built dist/native with ${files.length} source file(s), payload ${manifest.payloadSha256}.`);
