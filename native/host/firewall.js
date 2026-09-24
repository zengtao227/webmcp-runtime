import { redactSecrets } from '../../gateway/secret-scanner/index.js';

const REDACTED = '[REDACTED]';
const SENSITIVE_KEYS = new Set([
  'access_token',
  'refresh_token',
  'client_secret',
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'private_key',
  'secret',
  'token',
]);

export class HostFirewallError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'HostFirewallError';
    this.code = code;
  }
}

function sanitizeString(value) {
  try {
    return redactSecrets(value).text;
  } catch {
    throw new HostFirewallError('Secret Firewall failed.', 'secret_firewall_failure');
  }
}

function walk(value, { preserveJsonRpcErrorCode = false } = {}) {
  if (typeof value === 'string') {
    return sanitizeString(value);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => walk(entry));
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }

  const out = {};
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase();
    if (key === 'error' && value.jsonrpc === '2.0' && child && typeof child === 'object') {
      out[key] = walk(child, { preserveJsonRpcErrorCode: true });
      continue;
    }
    if (lower === 'code' && preserveJsonRpcErrorCode && Number.isInteger(child)) {
      out[key] = child;
      continue;
    }
    if (SENSITIVE_KEYS.has(lower)) {
      out[key] = REDACTED;
      continue;
    }
    out[key] = walk(child);
  }
  return out;
}

export function sanitizeJsonRpcEnvelope(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.jsonrpc !== '2.0') {
    throw new HostFirewallError('Container returned a non-JSON-RPC payload.', 'invalid_jsonrpc_response');
  }
  if (!Object.hasOwn(payload, 'result') && !Object.hasOwn(payload, 'error')) {
    throw new HostFirewallError('Container returned an unclassified JSON-RPC payload.', 'invalid_jsonrpc_response');
  }
  return walk(payload);
}

export function sanitizeLogText(text) {
  if (typeof text !== 'string') {
    throw new HostFirewallError('Log text must be a string.', 'invalid_log_text');
  }
  return sanitizeString(text);
}
