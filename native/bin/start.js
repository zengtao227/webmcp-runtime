#!/usr/bin/env node
import { createNativeMcpServer } from '../src/server.js';
import { createNativeStdioServer } from '../src/stdio.js';
import { createWorkspaceRuntime, decodeRuntimeMountPolicy, NATIVE_WORKSPACE_ROOT } from '../src/workspace.js';

const runtime = createWorkspaceRuntime({
  root: NATIVE_WORKSPACE_ROOT,
  runtimeToken: process.env.WEBMCP_RUNTIME_TOKEN || undefined,
  readOnly: process.env.WEBMCP_READ_ONLY === '1',
  mountPolicies: decodeRuntimeMountPolicy(process.env.WEBMCP_MOUNT_POLICY),
});
const server = createNativeMcpServer(runtime);
const stdio = createNativeStdioServer(server);

stdio.start();
