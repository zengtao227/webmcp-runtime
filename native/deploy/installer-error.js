export class InstallerError extends Error {
  constructor(message, code, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'InstallerError';
    this.code = code;
  }
}

export function fail(message, code, options = {}) {
  throw new InstallerError(message, code, options);
}
