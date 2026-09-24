import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeJsonRpcEnvelope, sanitizeLogText } from '../native/host/firewall.js';

const FAKE_GITHUB_TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz123456';
const FAKE_AWS_SECRET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd';

test('host firewall redacts secrets from Native JSON-RPC results', () => {
  const payload = {
    jsonrpc: '2.0',
    id: 1,
    result: {
      content: [{ type: 'text', text: `token=${FAKE_GITHUB_TOKEN}` }],
      structuredContent: { result: `AWS_SECRET_ACCESS_KEY=${FAKE_AWS_SECRET}` },
    },
  };

  const sanitized = sanitizeJsonRpcEnvelope(payload);
  const serialized = JSON.stringify(sanitized);
  assert.doesNotMatch(serialized, new RegExp(FAKE_GITHUB_TOKEN));
  assert.doesNotMatch(serialized, new RegExp(FAKE_AWS_SECRET));
  assert.match(serialized, /REDACTED/);
});

test('host firewall redacts known secret-key fields even when the value shape is weak', () => {
  const sanitized = sanitizeJsonRpcEnvelope({
    jsonrpc: '2.0',
    id: 2,
    result: {
      token: 'short-value',
      nested: { password: 'not-high-entropy' },
    },
  });
  assert.equal(sanitized.result.token, '[REDACTED]');
  assert.equal(sanitized.result.nested.password, '[REDACTED]');
});

test('host firewall preserves JSON-RPC integer error codes while sanitizing error text', () => {
  const sanitized = sanitizeJsonRpcEnvelope({
    jsonrpc: '2.0',
    id: 3,
    error: {
      code: -32001,
      message: `Authorization: Bearer ${FAKE_GITHUB_TOKEN}`,
    },
  });
  assert.equal(sanitized.error.code, -32001);
  assert.doesNotMatch(sanitized.error.message, new RegExp(FAKE_GITHUB_TOKEN));
});

test('host firewall rejects unclassified or non-JSON-RPC output', () => {
  assert.throws(() => sanitizeJsonRpcEnvelope({ hello: 'world' }), /non-JSON-RPC/);
  assert.throws(() => sanitizeJsonRpcEnvelope({ jsonrpc: '2.0', id: 1 }), /unclassified/);
});

test('host log sanitizer uses the same content scanner', () => {
  const sanitized = sanitizeLogText(`Authorization: Bearer ${FAKE_GITHUB_TOKEN}\n`);
  assert.doesNotMatch(sanitized, new RegExp(FAKE_GITHUB_TOKEN));
  assert.match(sanitized, /REDACTED/);
});
