import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import dgram from 'node:dgram';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

async function freeUdpPort() {
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

async function sendTzsp(port) {
  const socket = dgram.createSocket('udp4');
  const ethernet = Buffer.from('00112233445566778899aabb0800', 'hex');
  const header = Buffer.from([1, 0, 0, 1, 1]); // TZSP v1, receive, Ethernet, tag end
  const datagram = Buffer.concat([header, ethernet]);
  try {
    await new Promise((resolve, reject) => socket.send(datagram, port, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  } finally {
    await new Promise((resolve) => socket.close(resolve));
  }
}

async function waitForCapture(client, predicate, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const response = await client.callTool({ name: 'tzsp_capture_status', arguments: {} });
    assert.equal(response.isError, undefined, response.content?.[0]?.text);
    const status = JSON.parse(response.content[0].text);
    if (predicate(status)) return status;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('Timed out waiting for the MCP TZSP capture state.');
}

test('MCP TZSP tools require exact confirmation and gates, receive allowlisted frames, and manage PCAP files', async (t) => {
  const port = await freeUdpPort();
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tzsp-mcp-integration-'));
  await fs.chmod(dataDir, 0o700);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['src/server.js'],
    cwd: process.cwd(),
    env: {
      ...process.env,
      MIKROTIK_HOST: '192.0.2.1',
      MIKROTIK_PORT: '8728',
      MIKROTIK_TLS: 'false',
      MIKROTIK_USERNAME: 'capture-test',
      MIKROTIK_PASSWORD: 'test-only',
      MIKROTIK_ROUTERS_JSON: '',
      MIKROTIK_DEFAULT_DEVICE: 'default',
      MIKROTIK_DATA_DIR: dataDir,
      MIKROTIK_DASHBOARD_ENABLED: 'false',
      MIKROTIK_ALERT_SERVICE_ENABLED: 'false',
      MIKROTIK_TZSP_RECEIVER_ENABLED: 'true',
      MIKROTIK_TZSP_BIND_ADDRESS: '127.0.0.1',
      MIKROTIK_TZSP_PORT: String(port),
      MIKROTIK_TZSP_ALLOWED_SOURCES: '127.0.0.1',
      MIKROTIK_TZSP_MAX_DURATION_SECONDS: '60',
      MIKROTIK_ALLOW_WRITES: 'true',
      MIKROTIK_ALLOW_HIGH_RISK_WRITES: 'true',
      MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS: 'true',
      MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS: 'true',
      MIKROTIK_SSH_USERNAME: '',
      MIKROTIK_SSH_PASSWORD: '',
      MIKROTIK_SSH_HOST_KEY_SHA256: '',
    },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'tzsp-integration-client', version: '1.0.0' });
  t.after(async () => {
    await client.close().catch(() => {});
    await fs.rm(dataDir, { recursive: true, force: true });
  });
  await client.connect(transport);

  const wrongConfirmation = await client.callTool({ name: 'start_tzsp_capture_receiver', arguments: {
    device: 'default', name: 'test', durationSeconds: 30, confirmation: 'START CAPTURE',
  } });
  assert.equal(wrongConfirmation.isError, true);
  assert.match(wrongConfirmation.content[0].text, /Exact operation confirmation required/);

  const confirmation = `START TZSP CAPTURE default test 30s 127.0.0.1 UDP ${port}`;
  const startResult = await client.callTool({ name: 'start_tzsp_capture_receiver', arguments: {
    device: 'default', name: 'test', durationSeconds: 30, confirmation,
  } });
  assert.equal(startResult.isError, undefined, startResult.content?.[0]?.text);
  const started = JSON.parse(startResult.content[0].text);
  assert.equal(started.state, 'active');
  assert.equal(started.boundPort, port);
  assert.equal(started.routerConfigurationNotChanged, true);
  assert.match(started.suggestedRouterCommands[0], /filter-stream=yes/);

  await sendTzsp(port);
  const observed = await waitForCapture(client, (status) => status.activeCapture?.packets === 1);
  assert.equal(observed.activeCapture.payloadBytes, 14);
  assert.equal(JSON.stringify(observed).includes('001122334455'), false);

  const stopResult = await client.callTool({ name: 'stop_tzsp_capture_receiver', arguments: {
    captureId: started.id, confirmation: `STOP TZSP CAPTURE ${started.id}`,
  } });
  assert.equal(stopResult.isError, undefined, stopResult.content?.[0]?.text);
  const stopped = JSON.parse(stopResult.content[0].text);
  assert.equal(stopped.state, 'completed');
  assert.equal(stopped.routerSnifferStopped, false);

  const listResult = await client.callTool({ name: 'list_tzsp_captures', arguments: {} });
  assert.equal(listResult.isError, undefined);
  const captures = JSON.parse(listResult.content[0].text).captures;
  assert.equal(captures.length, 1);
  assert.equal(captures[0].id, started.id);
  const stat = await fs.stat(captures[0].filePath);
  assert.equal(stat.mode & 0o077, 0);

  const deleteResult = await client.callTool({ name: 'delete_tzsp_capture', arguments: {
    captureId: started.id, confirmation: `DELETE TZSP CAPTURE ${started.id}`,
  } });
  assert.equal(deleteResult.isError, undefined, deleteResult.content?.[0]?.text);
  assert.deepEqual(JSON.parse(deleteResult.content[0].text), { id: started.id, deleted: true });
});
