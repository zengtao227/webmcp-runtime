import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assertPathAllowed,
  evaluatePath,
  normalizePath,
} from '../gateway/path-policy/index.js';

const blockedPaths = [
  '.env',
  '.env.local',
  'config/.env.production',
  'certs/client.pem',
  'certs/client.key',
  'keys/id_rsa',
  'keys/id_ed25519.pub',
  '.ssh/id_ed25519',
  '/Users/example/.aws/credentials',
  '.gnupg/private-keys-v1.d/key',
  '.kube/config',
  'kubeconfig',
  'config/credentials.json',
  'wallet',
  'wallet.json',
  'wallet/seed.json',
  'keystore/account.json',
  'prod.p12',
  'prod.pfx',
  'prod.jks',
  'prod.keystore',
];

test('blocks default sensitive paths', () => {
  for (const path of blockedPaths) {
    const decision = evaluatePath(path);
    assert.equal(decision.allowed, false, path);
  }
});

test('normalizes traversal and Windows separators before policy checks', () => {
  assert.equal(evaluatePath('src/../.env').allowed, false);
  assert.equal(evaluatePath('src\\..\\.ssh\\id_rsa').allowed, false);
  assert.equal(evaluatePath('src//config/./client.pem').allowed, false);
});

test('decodes simple encoded path bypass attempts', () => {
  assert.equal(evaluatePath('%2eenv').allowed, false);
  assert.equal(evaluatePath('src/%2e%2e/.env').allowed, false);
  assert.equal(evaluatePath('%252eenv').allowed, false);
});

test('fails closed when traversal escapes the supplied root', () => {
  const decision = evaluatePath('../../src/index.js');
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'path_escape');
});

test('fails closed for malformed or unsafe path input', () => {
  assert.equal(evaluatePath('').allowed, false);
  assert.equal(evaluatePath('%E0%A4%A').reason, 'malformed_path_encoding');
  assert.equal(evaluatePath('safe\0file.js').reason, 'nul_byte');
});

test('allows ordinary project files and near misses', () => {
  const allowedPaths = [
    'src/index.js',
    'docs/environment.md',
    'src/wallet-utils.js',
    'src/keystore-reader.js',
    'fixtures/credentials-parser.test.js',
    'keys/public.pem.txt',
  ];

  for (const path of allowedPaths) {
    const decision = evaluatePath(path);
    assert.equal(decision.allowed, true, path);
  }
});

test('normalization returns a stable path without dot segments', () => {
  const result = normalizePath('./src/a/../b.js');
  assert.deepEqual(result, {
    ok: true,
    normalizedPath: 'src/b.js',
    segments: ['src', 'b.js'],
    escapedRoot: false,
  });
});

test('assertPathAllowed throws without exposing file contents', () => {
  assert.throws(
    () => assertPathAllowed('.env'),
    (error) => error.name === 'PathPolicyError' && error.code === 'blocked_sensitive_filename',
  );
});
