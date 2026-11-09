import test from 'node:test';
import assert from 'node:assert/strict';
import { runRouterSnifferCapture } from '../src/sniffer-workflow.js';

function makeCaptureManager(events) {
  return {
    async start(input) { events.push(['capture-start', input]); return { id: 'capture-id', state: 'active' }; },
    async stop(id) { events.push(['capture-stop', id]); return { id, state: 'completed' }; },
  };
}
function makeClient(events, state = { running: 'no', 'streaming-enabled': 'no', 'streaming-server': '192.0.2.90', 'streaming-port': '37009', 'filter-stream': 'no' }, failures = {}) {
  return {
    async print(path, properties) {
      events.push(['print', path, properties]);
      if (path === '/tool/sniffer') return [state];
      if (path === '/system/resource') return [{ version: '7.16' }];
      throw new Error(`unexpected read ${path}`);
    },
    async command(path, attributes = {}) {
      events.push(['command', path, attributes]);
      if (failures[path]) throw new Error(failures[path]);
      return [];
    },
  };
}
function input(events, overrides = {}) {
  let clock = 1000;
  return {
    device: 'edge-1', name: 'smoke-test', durationSeconds: 5, bindAddress: '192.0.2.5', port: 37008,
    captureManager: makeCaptureManager(events),
    withRouter: async (device, operation) => { events.push(['router-open', device]); return operation(makeClient(events, overrides.state, overrides.failures)); },
    now: () => clock,
    waitFn: async (ms) => { events.push(['wait', ms]); clock += ms; },
    keepAliveIntervalMs: 3000,
    ...overrides,
  };
}

test('starts local receiver first, runs bounded remote capture, then stops and restores prior settings', async () => {
  const events = [];
  const result = await runRouterSnifferCapture(input(events));
  assert.equal(result.routerSnifferStarted, true);
  assert.equal(result.routerSettingsRestored, true);
  assert.equal(result.capture.state, 'completed');
  assert.equal(events[0][0], 'capture-start');
  assert.deepEqual(events.find((item) => item[0] === 'command' && item[1] === '/tool/sniffer/set')[2], {
    'streaming-enabled': 'yes', 'streaming-server': '192.0.2.5', 'streaming-port': '37008', 'filter-stream': 'yes',
  });
  const commands = events.filter((item) => item[0] === 'command');
  assert.equal(commands[1][1], '/tool/sniffer/start');
  assert.equal(commands.at(-2)[1], '/tool/sniffer/stop');
  assert.deepEqual(commands.at(-1)[2], { 'streaming-server': '192.0.2.90', 'streaming-port': '37009', 'filter-stream': 'no' });
  assert.equal(events.at(-1)[0], 'capture-stop');
});

test('refuses to disturb an already running sniffer and stops only the local receiver', async () => {
  const events = [];
  await assert.rejects(runRouterSnifferCapture(input(events, { state: { running: 'yes', 'streaming-enabled': 'no' } })), /already active/);
  assert.equal(events.some((item) => item[0] === 'command'), false);
  assert.deepEqual(events.at(-1), ['capture-stop', 'capture-id']);
});

test('attempts stop and settings restoration after a start command fails', async () => {
  const events = [];
  await assert.rejects(runRouterSnifferCapture(input(events, { failures: { '/tool/sniffer/start': 'mock start error' } })), /stop and prior settings restoration succeeded/);
  const commands = events.filter((item) => item[0] === 'command');
  assert.ok(commands.some((item) => item[1] === '/tool/sniffer/stop'));
  assert.deepEqual(commands.at(-1)[2], { 'streaming-server': '192.0.2.90', 'streaming-port': '37009', 'filter-stream': 'no' });
  assert.deepEqual(events.at(-1), ['capture-stop', 'capture-id']);
});

test('reports cleanup uncertainty when router stop fails', async () => {
  const events = [];
  await assert.rejects(runRouterSnifferCapture(input(events, { failures: { '/tool/sniffer/stop': 'mock stop failure' } })), /cleanup uncertainty.*inspect RouterOS \/tool\/sniffer/i);
  assert.ok(events.some((item) => item[0] === 'command' && item[1] === '/tool/sniffer/set' && item[2]['streaming-server'] === '192.0.2.90'));
});

test('enforces a hard managed-capture duration cap', async () => {
  const events = [];
  await assert.rejects(runRouterSnifferCapture(input(events, { durationSeconds: 61 })), /from 1 to 60/);
  assert.equal(events.length, 0);
});
