import { createHash } from 'node:crypto';

export const NATIVE_RUNTIME_ENTRYPOINT = 'native/bin/start.js';

export function aggregateSourceDigest(files) {
  const digest = createHash('sha256');
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    digest.update(file.path);
    digest.update('\0');
    digest.update(file.sha256);
    digest.update('\0');
    digest.update(String(file.size));
    digest.update('\n');
  }
  return digest.digest('hex');
}

// Exact source set consumed by native/Dockerfile. Image builds materialize only
// these reviewed Git blobs into the Docker build context.
export const NATIVE_RUNTIME_PAYLOAD = Object.freeze([
  'package.json',
  'native/Dockerfile',
  'native/bin/start.js',
  'native/src/server.js',
  'native/src/stdio.js',
  'native/src/workspace.js',
  'gateway/path-policy/index.js',
]);
