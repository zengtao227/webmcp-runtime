import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';
import { InstallerError } from './installer-error.js';

const execFileAsync = promisify(execFile);
const MAX_ELEVATED_LEASE_MS = 60 * 60 * 1000;

function fail(message, code, options = {}) {
  throw new InstallerError(message, code, options);
}

// The only temporary grant is Host Access (High Trust).
export async function requestLocalElevationApproval({
  durationMs,
  instanceLabel = 'WebMCP',
  execFileImpl = execFileAsync,
} = {}) {
  if (!Number.isSafeInteger(durationMs) || durationMs <= 0 || durationMs > MAX_ELEVATED_LEASE_MS) {
    fail('Local elevation approval requires a bounded duration.', 'LOCAL_ELEVATION_APPROVAL_REQUIRED');
  }
  const durationMinutes = Math.ceil(durationMs / 60000);
  const script = [
    'set requestedDuration to system attribute "WEBMCP_ELEVATE_DURATION"',
    'set instanceLabel to system attribute "WEBMCP_INSTANCE_LABEL"',
    'try',
    '  set dialogResult to display dialog ("WebMCP requests TEMPORARY FULL HOST ACCESS — HIGH TRUST.\\n\\nInstance: " & instanceLabel & "\\nMaximum duration: " & requestedDuration & "\\n\\nCommands run as your current Mac user. They can access files, credentials, Docker, network, processes, and WebMCP control files. Revoke/expiry blocks new WebMCP host commands and stops tracked foreground work; completed changes or detached processes may remain. Approve only if you initiated this request locally.") buttons {"Cancel", "GRANT HOST ACCESS"} default button "Cancel" cancel button "Cancel" with icon caution giving up after 120',
    '  if gave up of dialogResult then return "TIMEOUT"',
    '  return button returned of dialogResult',
    'on error number -128',
    '  return "CANCEL"',
    'end try',
  ].join('\\n');

  let stdout;
  try {
    ({ stdout } = await execFileImpl('/usr/bin/osascript', ['-e', script], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
      env: {
        HOME: os.homedir(),
        LANG: process.env.LANG ?? 'en_US.UTF-8',
        WEBMCP_ELEVATE_DURATION: `${durationMinutes} minute${durationMinutes === 1 ? '' : 's'}`,
        WEBMCP_INSTANCE_LABEL: instanceLabel,
      },
    }));
  } catch (error) {
    fail('Local macOS approval dialog could not be completed.', 'LOCAL_ELEVATION_APPROVAL_REQUIRED', { cause: error });
  }
  if (String(stdout).trim() !== 'GRANT HOST ACCESS') {
    fail('Temporary elevated access was not approved in the local macOS session.', 'LOCAL_ELEVATION_APPROVAL_REQUIRED');
  }
}
