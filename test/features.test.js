import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RESOURCE_CATALOG, RESOURCE_BY_KEY } from '../src/catalog.js';
import { cancelPlan, redactFields, stagePlan, stageTransaction, takePlan, validateChangeInput } from '../src/change-planner.js';
import { createSnapshot, deleteSnapshot, diffSnapshots, getSnapshot, listSnapshots } from '../src/snapshot-store.js';

test('catalog covers many RouterOS resources with fixed paths and unique keys', () => {
  assert.ok(RESOURCE_CATALOG.length >= 100);
  assert.equal(new Set(RESOURCE_CATALOG.map((item) => item.key)).size, RESOURCE_CATALOG.length);
  for (const item of RESOURCE_CATALOG) {
    assert.match(item.path, /^\/[a-z0-9/-]+$/);
    assert.ok(Array.isArray(item.properties));
    assert.ok(Array.isArray(item.writeFields));
    assert.ok(['high', 'read-only'].includes(item.risk));
    for (const field of item.writeFields) assert.equal(typeof field, 'string');
  }
});

test('change plans enforce allowlisted fields, target IDs, and redact credentials', () => {
  const route = RESOURCE_BY_KEY.get('routes');
  validateChangeInput(route, 'add', { 'dst-address': '0.0.0.0/0', gateway: '192.0.2.1' });
  assert.throws(() => validateChangeInput(route, 'add', { command: '/system/reboot' }), /not writable/);
  assert.throws(() => validateChangeInput(route, 'set', { distance: '2' }, '0'), /internal item ID/);
  assert.deepEqual(redactFields({ password: 'hidden', 'ipsec-secret': 'hidden', name: 'safe' }), {
    password: '[redacted]', 'ipsec-secret': '[redacted]', name: 'safe',
  });
});

test('single plans are single-use and transaction plans cannot be consumed by the wrong tool', () => {
  const plan = stagePlan({ resourceKey: 'routes', action: 'add', device: 'r1', fields: { 'dst-address': '203.0.113.0/24', gateway: '192.0.2.1' } });
  assert.match(plan.confirmation, new RegExp(`^APPLY ${plan.id}$`));
  assert.throws(() => takePlan(plan.id, 'APPLY wrong'), /Exact confirmation/);
  assert.equal(takePlan(plan.id, plan.confirmation).resourceKey, 'routes');
  assert.throws(() => takePlan(plan.id, plan.confirmation), /not found/);
  const transaction = stageTransaction([{ resourceKey: 'routes', action: 'add', device: 'r1', fields: { gateway: '192.0.2.1' } }]);
  assert.throws(() => takePlan(transaction.id, transaction.confirmation), /matching apply tool/);
  assert.equal(takePlan(transaction.id, transaction.confirmation, 'transaction').steps.length, 1);
  const unused = stagePlan({ resourceKey: 'routes', action: 'remove', device: 'r1', targetId: '*3', fields: {} });
  assert.equal(cancelPlan(unused.id), true);
  assert.equal(cancelPlan(unused.id), false);
});

test('snapshot store persists private inventory metadata and diffs config while ignoring volatile values', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mikrotik-snapshot-test-'));
  const previous = process.env.MIKROTIK_DATA_DIR;
  process.env.MIKROTIK_DATA_DIR = directory;
  t.after(async () => {
    if (previous === undefined) delete process.env.MIKROTIK_DATA_DIR;
    else process.env.MIKROTIK_DATA_DIR = previous;
    await rm(directory, { recursive: true, force: true });
  });
  const base = await createSnapshot({
    device: 'r1', host: '192.0.2.1', version: '7.16',
    resources: [{ name: 'routes', path: '/ip/route', records: [{ '.id': '*1', 'dst-address': '0.0.0.0/0', gateway: '192.0.2.1', packets: '3' }] }],
  });
  const current = await createSnapshot({
    device: 'r1', host: '192.0.2.1', version: '7.16',
    resources: [{ name: 'routes', path: '/ip/route', records: [
      { '.id': '*1', 'dst-address': '0.0.0.0/0', gateway: '192.0.2.254', packets: '99' },
      { '.id': '*2', 'dst-address': '203.0.113.0/24', gateway: '192.0.2.1' },
    ] }],
  });
  assert.equal(base.resourceCount, 1);
  assert.equal(base.recordCount, 1);
  assert.match(base.note, /not a restorable/);
  const loaded = await getSnapshot(base.id);
  assert.equal(loaded.resources[0].records[0].gateway, '192.0.2.1');
  const list = await listSnapshots();
  assert.equal(list.length, 2);
  const diff = await diffSnapshots(base.id, current.id);
  assert.equal(diff.totals.recordsAdded, 1);
  assert.equal(diff.totals.recordsChanged, 1);
  assert.equal(diff.resources[0].changed[0].after.packets, '99');
  const fileInfo = await stat(join(directory, `${base.id}.json`));
  assert.equal(fileInfo.mode & 0o077, 0);
  assert.equal((await deleteSnapshot(base.id)).deleted, true);
  await assert.rejects(() => getSnapshot(base.id), /not found/);
});
