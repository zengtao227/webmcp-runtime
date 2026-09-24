import { NativeWorkspaceError, NATIVE_WORKSPACE_ROOT } from './workspace.js';

const PROTOCOL_VERSION = '2025-06-18';

const TOOLS = [
  {
    name: 'open_workspace',
    description: 'Open the single owner-authorized WebMCP workspace root. Child projects are located after the root is opened.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', enum: [NATIVE_WORKSPACE_ROOT] },
      },
      required: ['path'],
    },
  },
  {
    name: 'read',
    description: 'Read UTF-8 text from a file inside the open workspace. Paths are relative to the workspace root unless an absolute in-workspace path is supplied.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspaceId: { type: 'string', minLength: 1 },
        path: { type: 'string', minLength: 1 },
        offset: { type: 'integer', minimum: 1 },
        limit: { type: 'integer', minimum: 1, maximum: 5000 },
      },
      required: ['workspaceId', 'path'],
    },
  },
  {
    name: 'write',
    description: 'Create or completely overwrite one UTF-8 text file inside the open workspace.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspaceId: { type: 'string', minLength: 1 },
        path: { type: 'string', minLength: 1 },
        content: { type: 'string' },
      },
      required: ['workspaceId', 'path', 'content'],
    },
  },
  {
    name: 'edit',
    description: 'Apply bounded exact text replacements to one UTF-8 text file. Each oldText must match exactly once and edit regions must not overlap.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspaceId: { type: 'string', minLength: 1 },
        path: { type: 'string', minLength: 1 },
        edits: {
          type: 'array',
          minItems: 1,
          maxItems: 100,
          items: {
            type: 'object',
            additionalProperties: false,
            properties: {
              oldText: { type: 'string', minLength: 1 },
              newText: { type: 'string' },
            },
            required: ['oldText', 'newText'],
          },
        },
      },
      required: ['workspaceId', 'path', 'edits'],
    },
  },
  {
    name: 'bash',
    description: 'Run a bounded bash command inside the isolated WebMCP runtime container. This never executes a shell directly as the host user.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspaceId: { type: 'string', minLength: 1 },
        command: { type: 'string', minLength: 1 },
        workingDirectory: { type: 'string' },
        timeout: { type: 'number', exclusiveMinimum: 0, maximum: 300 },
      },
      required: ['workspaceId', 'command'],
    },
  },
];

const TOOL_ARGUMENT_KEYS = new Map(TOOLS.map(({ name, inputSchema }) => [
  name,
  new Set(Object.keys(inputSchema.properties ?? {})),
]));

function jsonRpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) {
    error.data = data;
  }
  return { jsonrpc: '2.0', id: id ?? null, error };
}

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function toolResult(payload, { isError = false } = {}) {
  const text = typeof payload?.result === 'string'
    ? payload.result
    : JSON.stringify(payload);
  return {
    content: [{ type: 'text', text }],
    structuredContent: payload,
    ...(isError ? { isError: true } : {}),
  };
}

function validateEnvelope(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return false;
  }
  if (payload.jsonrpc !== '2.0' || typeof payload.method !== 'string' || payload.method.length === 0) {
    return false;
  }
  return true;
}

function validateToolArguments(name, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new NativeWorkspaceError('Tool arguments must be an object.', 'invalid_arguments');
  }

  const allowed = TOOL_ARGUMENT_KEYS.get(name);

  if (!allowed) {
    throw new NativeWorkspaceError('Unknown tool.', 'unknown_tool');
  }
  for (const key of Object.keys(args)) {
    if (key === '__proto__' || key === 'prototype' || key === 'constructor' || !allowed.has(key)) {
      throw new NativeWorkspaceError(`Unsupported tool argument: ${key}`, 'invalid_arguments');
    }
  }
}

export function createNativeMcpServer(workspaceRuntime, { serverVersion = '0.1.0' } = {}) {
  if (!workspaceRuntime) {
    throw new Error('createNativeMcpServer requires a workspace runtime.');
  }

  async function callTool(name, args) {
    validateToolArguments(name, args);
    switch (name) {
      case 'open_workspace':
        return workspaceRuntime.openWorkspace(args.path);
      case 'read':
        return workspaceRuntime.read(args);
      case 'write':
        return workspaceRuntime.write(args);
      case 'edit':
        return workspaceRuntime.edit(args);
      case 'bash':
        return workspaceRuntime.bash(args);
      default:
        throw new NativeWorkspaceError('Unknown tool.', 'unknown_tool');
    }
  }

  return {
    tools: TOOLS,
    async handle(payload) {
      if (!validateEnvelope(payload)) {
        return jsonRpcError(payload?.id ?? null, -32600, 'Invalid Request');
      }

      const notification = !Object.hasOwn(payload, 'id');
      if (notification) {
        return null;
      }

      if (payload.method === 'server/discover') {
        // Some transports probe a newer stateless revision before
        // falling back to initialize-based MCP. Keep the compatibility reply
        // in-container; the host boundary does not need protocol business logic.
        return jsonRpcError(payload.id, -32601, 'Method not found');
      }

      if (payload.method === 'initialize') {
        return jsonRpcResult(payload.id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'webmcp-native', version: serverVersion },
        });
      }

      if (payload.method === 'ping') {
        return jsonRpcResult(payload.id, {});
      }

      if (payload.method === 'tools/list') {
        return jsonRpcResult(payload.id, { tools: TOOLS });
      }

      if (payload.method !== 'tools/call') {
        return jsonRpcError(payload.id, -32601, 'Method not found');
      }

      const name = payload.params?.name;
      const args = payload.params?.arguments;
      if (typeof name !== 'string') {
        return jsonRpcError(payload.id, -32602, 'Invalid params');
      }

      try {
        const result = await callTool(name, args);
        return jsonRpcResult(payload.id, toolResult(result));
      } catch (error) {
        if (error instanceof NativeWorkspaceError) {
          return jsonRpcResult(payload.id, toolResult({
            error: error.code,
            message: error.message,
            ...(Object.keys(error.details ?? {}).length > 0 ? { details: error.details } : {}),
          }, { isError: true }));
        }
        return jsonRpcError(payload.id, -32603, 'Internal error');
      }
    },
  };
}

export { PROTOCOL_VERSION };
