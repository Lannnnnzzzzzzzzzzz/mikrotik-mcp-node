import test from 'node:test';
import assert from 'node:assert/strict';
import { createAlertWorker } from '../src/alert-worker.js';

function fakeTimers() {
  let nextId = 1;
  const timers = new Map();
  const scheduled = [];
  const cleared = [];
  return {
    timers,
    scheduled,
    cleared,
    setTimeoutFn(callback, delay) {
      const timer = { id: nextId++, callback, delay };
      timers.set(timer.id, timer);
      scheduled.push(timer);
      return timer.id;
    },
    clearTimeoutFn(id) {
      cleared.push(id);
      timers.delete(id);
    },
    fire(id) {
      const timer = timers.get(id);
      assert.ok(timer, `expected timer ${id} to be scheduled`);
      timers.delete(id);
      timer.callback();
    },
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function makeWorker(overrides = {}) {
  const clock = { value: new Date('2026-01-01T00:00:00.000Z') };
  const timers = fakeTimers();
  const worker = createAlertWorker({
    listDevices: async () => [],
    listRules: async () => [],
    collect: async () => ({}),
    record: async () => {},
    now: () => clock.value,
    setTimeoutFn: timers.setTimeoutFn,
    clearTimeoutFn: timers.clearTimeoutFn,
    minIntervalMs: 10,
    maxIntervalMs: 100,
    ...overrides,
  });
  return { worker, clock, timers };
}

test('start validates inclusive interval bounds and rejects invalid intervals', async () => {
  let calls = 0;
  const { worker } = makeWorker({ listDevices: async () => { calls += 1; return []; } });

  await assert.rejects(worker.start(9), RangeError);
  await assert.rejects(worker.start(101), RangeError);
  await assert.rejects(worker.start(10.5), RangeError);
  assert.equal(calls, 0);

  await worker.start(10);
  assert.equal(worker.status().intervalMs, 10);
  await worker.stop();
  await worker.start(100);
  assert.equal(worker.status().intervalMs, 100);
  await worker.stop();
});

test('start performs one immediate poll and rejects a second start while running', async () => {
  let polls = 0;
  const { worker, timers } = makeWorker({ listDevices: async () => { polls += 1; return []; } });

  const result = await worker.start(25);
  assert.equal(polls, 1);
  assert.equal(result.running, true);
  assert.equal(result.pollCount, 1);
  assert.equal(result.startedAt, '2026-01-01T00:00:00.000Z');
  assert.equal(timers.scheduled.length, 1);
  assert.equal(timers.scheduled[0].delay, 25);
  await assert.rejects(worker.start(25), /already running/);
  assert.equal(polls, 1);
  await worker.stop();
});

test('polls devices sequentially, only processes devices with enabled rules, and passes metrics through unchanged', async () => {
  const events = [];
  const devices = [{ id: 'edge-a' }, { id: 'edge-b' }, { id: 'edge-c' }];
  const missingMetricValues = { cpuUsedPercent: undefined };
  const { worker } = makeWorker({
    listDevices: async () => devices,
    listRules: async (device) => {
      events.push(`rules:${device.id}`);
      if (device.id === 'edge-b') return [{ enabled: false, metric: 'cpuUsedPercent' }];
      return [{ enabled: true, metric: 'cpuUsedPercent' }];
    },
    collect: async (device, rules) => {
      events.push(`collect:${device.id}:${rules.length}`);
      return device.id === 'edge-a' ? missingMetricValues : { cpuUsedPercent: 42 };
    },
    record: async (device, values) => { events.push(`record:${device.id}`); if (device.id === 'edge-a') assert.equal(values, missingMetricValues); },
  });

  const result = await worker.pollOnce();
  assert.deepEqual(events, [
    'rules:edge-a', 'collect:edge-a:1', 'record:edge-a',
    'rules:edge-b',
    'rules:edge-c', 'collect:edge-c:1', 'record:edge-c',
  ]);
  assert.equal(result.success, true);
  assert.equal(worker.status().pollCount, 1);
});

test('a device failure is isolated and later devices are still processed', async () => {
  const recorded = [];
  const { worker } = makeWorker({
    listDevices: async () => [{ id: 'bad' }, { id: 'good' }],
    listRules: async () => [{ enabled: true }],
    collect: async (device) => {
      if (device.id === 'bad') throw new Error('collection failed');
      return { memoryUsedPercent: 80 };
    },
    record: async (device, values) => recorded.push([device.id, values]),
  });

  const result = await worker.pollOnce();
  assert.deepEqual(recorded, [['good', { memoryUsedPercent: 80 }]]);
  assert.equal(result.success, false);
  assert.deepEqual(result.errors, ['bad: collection failed']);
  assert.equal(worker.status().lastError, 'bad: collection failed');
  assert.equal(worker.status().lastSuccessAt, null);
});

test('concurrent pollOnce calls share the active poll rather than overlapping', async () => {
  const gate = deferred();
  let listCalls = 0;
  const { worker } = makeWorker({
    listDevices: async () => { listCalls += 1; await gate.promise; return []; },
  });

  const first = worker.pollOnce();
  const second = worker.pollOnce();
  assert.equal(worker.status().inFlight, true);
  assert.equal(listCalls, 1);
  gate.resolve();
  assert.equal(await first, await second);
  assert.equal(worker.status().inFlight, false);
  assert.equal(worker.status().pollCount, 1);
});

test('stop is idempotent, clears its timer, and awaits an active poll', async () => {
  const gate = deferred();
  const { worker, timers } = makeWorker({
    listDevices: async () => { await gate.promise; return []; },
  });

  const starting = worker.start(30);
  assert.equal(worker.status().inFlight, true);
  const stopping = worker.stop();
  assert.equal(worker.status().running, false);
  assert.equal(timers.timers.size, 0);
  assert.equal(worker.status().inFlight, true);
  gate.resolve();
  await Promise.all([starting, stopping]);
  const stopped = await worker.stop();
  assert.equal(stopped.running, false);
  assert.equal(stopped.inFlight, false);
  assert.equal(timers.cleared.length, 0);
});

test('a fired recurring timer does not schedule another timer after stop', async () => {
  const gate = deferred();
  let pollCalls = 0;
  const { worker, timers } = makeWorker({
    listDevices: async () => { pollCalls += 1; if (pollCalls > 1) await gate.promise; return []; },
  });

  await worker.start(40);
  const firstTimerId = timers.scheduled[0].id;
  timers.fire(firstTimerId);
  assert.equal(worker.status().inFlight, true);
  const stopping = worker.stop();
  gate.resolve();
  await stopping;

  assert.equal(pollCalls, 2);
  assert.equal(timers.timers.size, 0);
  assert.equal(timers.scheduled.length, 1);
});
