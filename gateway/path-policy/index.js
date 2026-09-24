const BLOCKED_DIRECTORY_SEGMENTS = new Set([
  '.ssh',
  '.aws',
  '.gnupg',
  '.kube',
  'wallet',
  'wallets',
  'keystore',
  'keystores',
]);

const BLOCKED_EXACT_BASENAMES = new Set([
  '.env',
  'id_rsa',
  'id_ed25519',
  'kubeconfig',
  'credentials',
]);

const BLOCKED_BASENAME_PATTERNS = [
  /^\.env\..+/i,
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  /^id_(?:rsa|ed25519)(?:\..+)?$/i,
  /^credentials(?:\..+)?$/i,
  /^wallet(?:\..+)?$/i,
  /^keystore(?:\..+)?$/i,
];

function decodePath(value) {
  let decoded = value;

  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (!decoded.includes('%')) {
      break;
    }

    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) {
        break;
      }
      decoded = next;
    } catch {
      return { ok: false, reason: 'malformed_path_encoding' };
    }
  }

  return { ok: true, value: decoded };
}

export function normalizePath(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return { ok: false, reason: 'invalid_path' };
  }

  if (input.includes('\0')) {
    return { ok: false, reason: 'nul_byte' };
  }

  const decoded = decodePath(input);
  if (!decoded.ok) {
    return decoded;
  }

  const slashNormalized = decoded.value.replaceAll('\\', '/');
  const segments = [];
  let escapedRoot = false;

  for (const rawSegment of slashNormalized.split('/')) {
    if (!rawSegment || rawSegment === '.') {
      continue;
    }

    if (rawSegment === '..') {
      if (segments.length === 0) {
        escapedRoot = true;
      } else {
        segments.pop();
      }
      continue;
    }

    segments.push(rawSegment);
  }

  return {
    ok: true,
    normalizedPath: segments.join('/'),
    segments,
    escapedRoot,
  };
}

function blockedBasenameReason(basename) {
  const lower = basename.toLowerCase();

  if (BLOCKED_EXACT_BASENAMES.has(lower)) {
    return 'blocked_sensitive_filename';
  }

  if (BLOCKED_BASENAME_PATTERNS.some((pattern) => pattern.test(basename))) {
    return 'blocked_sensitive_filename';
  }

  return null;
}

export function evaluatePath(input) {
  const normalized = normalizePath(input);

  if (!normalized.ok) {
    return {
      allowed: false,
      reason: normalized.reason,
      normalizedPath: null,
    };
  }

  if (normalized.escapedRoot) {
    return {
      allowed: false,
      reason: 'path_escape',
      normalizedPath: normalized.normalizedPath,
    };
  }

  for (const segment of normalized.segments) {
    if (BLOCKED_DIRECTORY_SEGMENTS.has(segment.toLowerCase())) {
      return {
        allowed: false,
        reason: 'blocked_sensitive_directory',
        normalizedPath: normalized.normalizedPath,
      };
    }
  }

  const basename = normalized.segments.at(-1) ?? '';
  const basenameReason = blockedBasenameReason(basename);

  if (basenameReason) {
    return {
      allowed: false,
      reason: basenameReason,
      normalizedPath: normalized.normalizedPath,
    };
  }

  return {
    allowed: true,
    reason: 'allowed',
    normalizedPath: normalized.normalizedPath,
  };
}

export function assertPathAllowed(input) {
  const decision = evaluatePath(input);

  if (!decision.allowed) {
    const error = new Error(`Path denied by Secret Firewall: ${decision.reason}`);
    error.name = 'PathPolicyError';
    error.code = decision.reason;
    throw error;
  }

  return decision;
}
