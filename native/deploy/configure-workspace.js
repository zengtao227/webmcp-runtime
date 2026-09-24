#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  DEFAULT_WORKSPACE_CONFIG,
  persistWorkspaceConfig,
  verifyWorkspaceMount,
} from './workspace-config.js';
import { defaultProtectedPaths } from './control-plane-paths.js';

function usage() {
  return [
    'Usage:',
    '  node native/deploy/configure-workspace.js --root <absolute-path> --mode <project|workspace|advanced> --probe-image <image@sha256:digest> [options]',
    '',
    'Options:',
    '  --config <path>              Host workspace config path.',
    '  --network <on|off>           Override the mode network default.',
    '  --git-publication <on|off>   Persist the optional Git publication capability flag.',
    '  --git-user-name <name>       Required commit identity when Git publication is enabled.',
    '  --git-user-email <email>     Required commit identity when Git publication is enabled.',
    '  --ack-high-trust             Required when Advanced mode explicitly enables network or Git publication.',
  ].join('\n');
}

function parseOnOff(value, label) {
  if (value === 'on') {
    return true;
  }
  if (value === 'off') {
    return false;
  }
  throw new Error(`${label} must be on or off.`);
}

export function parseConfigureArgs(argv) {
  const options = {
    root: null,
    mode: null,
    probeImage: null,
    configPath: DEFAULT_WORKSPACE_CONFIG,
    networkEnabled: undefined,
    gitPublicationEnabled: undefined,
    gitUserName: undefined,
    gitUserEmail: undefined,
    ackHighTrust: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) {
        throw new Error(`Missing value for ${arg}.`);
      }
      return argv[index];
    };
    switch (arg) {
      case '--root':
        options.root = next();
        break;
      case '--mode':
        options.mode = next();
        break;
      case '--probe-image':
        options.probeImage = next();
        break;
      case '--config':
        options.configPath = next();
        break;
      case '--network':
        options.networkEnabled = parseOnOff(next(), '--network');
        break;
      case '--git-publication':
        options.gitPublicationEnabled = parseOnOff(next(), '--git-publication');
        break;
      case '--git-user-name':
        options.gitUserName = next();
        break;
      case '--git-user-email':
        options.gitUserEmail = next();
        break;
      case '--ack-high-trust':
        options.ackHighTrust = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (!options.help && (!options.root || !options.mode || !options.probeImage)) {
    throw new Error('root, mode, and probe-image are required.');
  }
  if (
    !options.help
    && options.mode === 'advanced'
    && (options.networkEnabled === true || options.gitPublicationEnabled === true)
    && !options.ackHighTrust
  ) {
    throw new Error('Advanced mode with network or Git publication requires --ack-high-trust.');
  }
  if (!options.help && options.gitPublicationEnabled === true && (!options.gitUserName || !options.gitUserEmail)) {
    throw new Error('Git publication requires --git-user-name and --git-user-email.');
  }
  if (!options.help && options.gitPublicationEnabled !== true && (options.gitUserName || options.gitUserEmail)) {
    throw new Error('Git identity requires --git-publication on.');
  }
  return options;
}

export async function configureWorkspace({
  root,
  mode,
  probeImage,
  configPath = DEFAULT_WORKSPACE_CONFIG,
  networkEnabled,
  gitPublicationEnabled,
  gitUserName,
  gitUserEmail,
  protectedPaths = null,
  platform = process.platform,
  verifyMount = verifyWorkspaceMount,
} = {}) {
  const config = {
    version: 1,
    hostRoot: root,
    mode,
    ...(networkEnabled === undefined ? {} : { networkEnabled }),
    ...(gitPublicationEnabled === undefined ? {} : { gitPublicationEnabled }),
    ...(gitUserName === undefined ? {} : { gitUserName }),
    ...(gitUserEmail === undefined ? {} : { gitUserEmail }),
  };
  const effectiveProtected = protectedPaths ?? await defaultProtectedPaths({ configPath, platform });

  const verified = await verifyMount({
    hostRoot: root,
    image: probeImage,
    protectedPaths: effectiveProtected,
    platform,
  });

  return persistWorkspaceConfig(configPath, {
    ...config,
    hostRoot: verified.canonicalRoot,
  }, { platform });
}

async function main() {
  let options;
  try {
    options = parseConfigureArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}\n`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  try {
    const saved = await configureWorkspace({
      root: options.root,
      mode: options.mode,
      probeImage: options.probeImage,
      configPath: options.configPath,
      networkEnabled: options.networkEnabled,
      gitPublicationEnabled: options.gitPublicationEnabled,
      gitUserName: options.gitUserName,
      gitUserEmail: options.gitUserEmail,
    });
    process.stdout.write(`WebMCP workspace configured: ${saved.hostRoot} → /workspace (${saved.mode})\n`);
  } catch (error) {
    process.stderr.write(`WebMCP workspace configuration failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (isMain) {
  await main();
}
