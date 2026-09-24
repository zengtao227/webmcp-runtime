import test from 'node:test';
import assert from 'node:assert/strict';

import {
  compileCustomPatterns,
  redactSecrets,
} from '../gateway/secret-scanner/index.js';

test('redacts named secrets in env, JSON, YAML, and code-like assignments', () => {
  const input = [
    'API_KEY="FAKE-API-KEY-VALUE"',
    'password: fake-password-value',
    '"private_key": "fake-private-key-value",',
    "const accessToken = 'fake-access-token-value';",
    'db_passphrase=fake-passphrase-value',
  ].join('\n');

  const result = redactSecrets(input);

  assert.equal(result.redacted, true);
  assert.equal(result.text.includes('FAKE-API-KEY-VALUE'), false);
  assert.equal(result.text.includes('fake-password-value'), false);
  assert.equal(result.text.includes('fake-private-key-value'), false);
  assert.equal(result.text.includes('fake-access-token-value'), false);
  assert.equal(result.text.includes('fake-passphrase-value'), false);
  assert.match(result.text, /API_KEY="\[REDACTED\]"/);
  assert.match(result.text, /password: \[REDACTED\]/);
});

test('redacts a fake private key block as one secret', () => {
  const fakeKey = [
    '-----BEGIN PRIVATE KEY-----',
    'FAKEFAKEFAKEFAKEFAKEFAKE',
    '-----END PRIVATE KEY-----',
  ].join('\n');

  const result = redactSecrets(`before\n${fakeKey}\nafter`);

  assert.equal(result.text.includes('FAKEFAKEFAKE'), false);
  assert.match(result.text, /\[REDACTED:PRIVATE_KEY\]/);
  assert.deepEqual(result.redactions, [{ reason: 'private-key', count: 1 }]);
});

test('redacts bearer, GitHub, AWS, and JWT-shaped fake credentials', () => {
  const fakeGithub = 'ghp_FAKEFAKEFAKEFAKEFAKE1234';
  const fakeAws = 'AKIAFAKEFAKEFAKE1234';
  const fakeJwt = 'eyJFAKEFAKE.eyJFAKEFAKE.SIGNATUREFAKE';
  const input = [
    'Authorization: Bearer FAKE_BEARER_1234567890',
    `github=${fakeGithub}`,
    `aws=${fakeAws}`,
    `jwt=${fakeJwt}`,
  ].join('\n');

  const result = redactSecrets(input);

  assert.equal(result.text.includes('FAKE_BEARER_1234567890'), false);
  assert.equal(result.text.includes(fakeGithub), false);
  assert.equal(result.text.includes(fakeAws), false);
  assert.equal(result.text.includes(fakeJwt), false);
  assert.match(result.text, /Authorization: Bearer \[REDACTED\]/);

  const reasons = new Set(result.redactions.map(({ reason }) => reason));
  assert.equal(reasons.has('bearer-token'), true);
  assert.equal(reasons.has('github-token'), true);
  assert.equal(reasons.has('aws-access-key'), true);
  assert.equal(reasons.has('jwt'), true);
});

test('redacts a high-confidence high-entropy quoted fake token', () => {
  const fakeHighEntropy = 'FAKE_9zQv2+Lm7/Nx4-Pt8_Rs3=Wk6Yh1AbC';
  const result = redactSecrets(`value="${fakeHighEntropy}"`);

  assert.equal(result.text.includes(fakeHighEntropy), false);
  assert.deepEqual(result.redactions, [{ reason: 'high-entropy-token', count: 1 }]);
});

test('does not redact ordinary text or a hexadecimal commit-like hash', () => {
  const hash = '5dd404bfe9422f56008b36f57df75737c86f2aa8';
  const input = `commit="${hash}"\nmessage="hello world"\nwallet-utils.js`;
  const result = redactSecrets(input);

  assert.equal(result.redacted, false);
  assert.equal(result.text, input);
  assert.deepEqual(result.redactions, []);
});

test('supports validated user-defined regex redaction', () => {
  const fakeCustom = 'FAKE-CUSTOM-A1B2C3D4';
  const result = redactSecrets(`header=${fakeCustom}`, {
    customPatterns: [
      {
        name: 'internal-fixture',
        source: 'FAKE-CUSTOM-[A-Z0-9]{8}',
      },
    ],
  });

  assert.equal(result.text.includes(fakeCustom), false);
  assert.deepEqual(result.redactions, [{ reason: 'custom:internal-fixture', count: 1 }]);
});

test('rejects malformed custom patterns instead of silently weakening policy', () => {
  assert.throws(
    () => compileCustomPatterns([{ name: 'bad', source: '[', flags: '' }]),
    /is invalid/,
  );
  assert.throws(
    () => compileCustomPatterns([{ name: 'bad', source: 'secret', flags: 's' }]),
    /unsupported flags/,
  );
  assert.throws(
    () => compileCustomPatterns([{ name: 'bad', source: 'x'.repeat(257) }]),
    /invalid source/,
  );
});

test('redaction metadata never contains the original secret value', () => {
  const fakeSecret = 'FAKE-SUPER-SECRET-VALUE-123456789';
  const result = redactSecrets(`API_SECRET=${fakeSecret}`);
  const metadata = JSON.stringify(result.redactions);

  assert.equal(metadata.includes(fakeSecret), false);
  assert.equal(result.text.includes(fakeSecret), false);
});
