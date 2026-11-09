import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createRouterSupportBundle } from '../src/support-bundle.js';

async function privateDirectory(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-support-bundle-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

test('writes one gzip JSON bundle privately and returns only artifact metadata', async (t) => {
  const dataDir = await privateDirectory(t);
  const bundle = await createRouterSupportBundle({
    device: 'branch-1',
    generatedAt: '2026-11-09T00:00:00.000Z',
    router: { endpoint: '192.0.2.1', identity: { name: 'test-router' }, resources: { version: '7.16' } },
    resources: [{ key: 'interfaces', status: 'available', records: [{ name: 'ether1' }], total: 1, truncated: false }],
    dataDir,
  });
  assert.equal(bundle.device, 'branch-1');
  assert.equal(bundle.filePermissions, '0600');
  assert.equal(bundle.resourceEntries, 1);
  assert.equal(bundle.records, 1);
  assert.match(bundle.sha256, /^[a-f0-9]{64}$/);
  const stat = await fs.stat(bundle.localPath);
  assert.equal(stat.mode & 0o777, 0o600);
  const document = JSON.parse(gunzipSync(await fs.readFile(bundle.localPath)).toString('utf8'));
  assert.equal(document.schemaVersion, 1);
  assert.equal(document.format, 'Allowlisted, redacted RouterOS resource inventory; not a restorable backup or full CLI export.');
  assert.equal(document.resources[0].records[0].name, 'ether1');
  assert.equal(JSON.stringify(bundle).includes('ether1'), false);
});

test('rejects non-private roots and oversized serialized bundles without creating an artifact', async (t) => {
  const dataDir = await privateDirectory(t);
  const publicRoot = path.join(dataDir, 'public-root');
  await fs.mkdir(publicRoot, { mode: 0o755 });
  await fs.chmod(publicRoot, 0o755);
  const input = { device: 'edge', resources: [{ key: 'x', records: [{ long: 'z'.repeat(5000) }] }] };
  await assert.rejects(createRouterSupportBundle({ ...input, dataDir: publicRoot }), /private regular directory/);
  await assert.rejects(createRouterSupportBundle({ ...input, dataDir, maxUncompressedBytes: 1024 }), /exceeds the/);
  await assert.rejects(fs.stat(path.join(dataDir, 'support-bundles')), { code: 'ENOENT' });
});

test('rejects invalid router IDs and malformed support inputs', async (t) => {
  const dataDir = await privateDirectory(t);
  await assert.rejects(createRouterSupportBundle({ device: '../escape', resources: [{ records: [] }], dataDir }), /configured router ID/);
  await assert.rejects(createRouterSupportBundle({ device: 'edge', resources: [], dataDir }), /1–500 catalog entries/);
});
