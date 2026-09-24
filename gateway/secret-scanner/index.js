const REDACTION = '[REDACTED]';
const SECRET_NAME_PARTS = [
  'TOKEN',
  'SECRET',
  'PASSWORD',
  'PRIVATEKEY',
  'APIKEY',
  'PASSPHRASE',
];

function normalizeSecretName(name) {
  return name.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function isSecretName(name) {
  const normalized = normalizeSecretName(name);
  return SECRET_NAME_PARTS.some((part) => normalized.includes(part));
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

function looksHighEntropy(value) {
  if (value.length < 32 || value.length > 512) {
    return false;
  }

  if (/^[a-f0-9]{32,}$/i.test(value)) {
    return false;
  }

  if (/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(value)) {
    return false;
  }

  const classes = [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /[0-9]/.test(value),
    /[^A-Za-z0-9]/.test(value),
  ].filter(Boolean).length;

  return classes >= 3 && shannonEntropy(value) >= 4.0;
}

function makeReporter() {
  const counts = new Map();

  return {
    record(reason) {
      counts.set(reason, (counts.get(reason) ?? 0) + 1);
    },
    result() {
      return [...counts.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([reason, count]) => ({ reason, count }));
    },
  };
}

function replacePattern(text, pattern, reason, reporter, replacement = REDACTION) {
  return text.replace(pattern, (...args) => {
    reporter.record(reason);
    const groups = args.at(-1);

    if (groups && typeof groups === 'object' && 'prefix' in groups) {
      return `${groups.prefix}${replacement}`;
    }

    return replacement;
  });
}

function redactNamedAssignments(text, reporter) {
  const quoted = /(?<prefix>(?<quote>["']?)(?<name>[A-Za-z_][A-Za-z0-9_.-]{0,80})\k<quote>\s*(?:=|:)\s*)(?<valueQuote>["'])(?<value>[^\r\n]*?)\k<valueQuote>/g;

  let output = text.replace(quoted, (...args) => {
    const groups = args.at(-1);
    if (!isSecretName(groups.name) || groups.value.startsWith('[REDACTED')) {
      return args[0];
    }

    reporter.record('named-secret');
    return `${groups.prefix}${groups.valueQuote}${REDACTION}${groups.valueQuote}`;
  });

  const unquoted = /(?<prefix>(?<quote>["']?)(?<name>[A-Za-z_][A-Za-z0-9_.-]{0,80})\k<quote>\s*(?:=|:)\s*)(?<value>(?!["'])[^\s,;}#]+)/g;

  output = output.replace(unquoted, (...args) => {
    const groups = args.at(-1);
    if (!isSecretName(groups.name) || groups.value.startsWith('[REDACTED')) {
      return args[0];
    }

    reporter.record('named-secret');
    return `${groups.prefix}${REDACTION}`;
  });

  return output;
}

function redactHighEntropyLiterals(text, reporter) {
  const quotedLiteral = /(?<quote>["'])(?<value>[A-Za-z0-9_~+/.=-]{32,512})\k<quote>/g;

  return text.replace(quotedLiteral, (...args) => {
    const groups = args.at(-1);
    if (!looksHighEntropy(groups.value)) {
      return args[0];
    }

    reporter.record('high-entropy-token');
    return `${groups.quote}${REDACTION}${groups.quote}`;
  });
}

export function redactSecrets(input) {
  if (typeof input !== 'string') {
    throw new TypeError('Secret scanner input must be a string');
  }

  const reporter = makeReporter();
  let text = input;

  text = replacePattern(
    text,
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gi,
    'private-key',
    reporter,
    '[REDACTED:PRIVATE_KEY]',
  );

  text = replacePattern(
    text,
    /(?<prefix>\bAuthorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+\/-]{8,}={0,2}/gi,
    'bearer-token',
    reporter,
  );

  text = replacePattern(
    text,
    /\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b/g,
    'github-token',
    reporter,
  );

  text = replacePattern(
    text,
    /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    'aws-access-key',
    reporter,
  );

  text = replacePattern(
    text,
    /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
    'jwt',
    reporter,
  );

  text = redactNamedAssignments(text, reporter);
  text = redactHighEntropyLiterals(text, reporter);

  return {
    text,
    redacted: reporter.result().length > 0,
    redactions: reporter.result(),
  };
}
