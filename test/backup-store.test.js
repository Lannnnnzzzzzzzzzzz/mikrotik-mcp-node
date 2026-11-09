import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  backupFilePath,
  createPendingBackup,
  deleteLocalBackup,
  getBackupRecord,
  listBackupRecords,
  markBackupDownloaded,
} from '../src/backup-store.js';

async function withDataDirectory(t) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-backup-test-'));
  const dataDirectory = path.join(parent, 'private-data');
  const previous = process.env.MIKROTIK_DATA_DIR;
  process.env.MIKROTIK_DATA_DIR = dataDirectory;
  t.after(async () => {
    if (previous === undefined) delete process.env.MIKROTIK_DATA_DIR;
    else process.env.MIKROTIK_DATA_DIR = previous;
    await fs.rm(parent, { recursive: true, force: true });
  });
  return { parent, dataDirectory, backupsDirectory: path.join(dataDirectory, 'backups') };
}

const input = (overrides = {}) => ({
  device: 'edge_a-1',
  host: '192.0.2.10',
  routerFile: 'edge_a-1-2026.backup',
  ...overrides,
});

test('creates private directories and manifest with a minimal pending record', async (t) => {
  const { dataDirectory, backupsDirectory } = await withDataDirectory(t);
  const record = await createPendingBackup(input({ password: 'must-not-persist', apiKey: 'also-secret' }));

  assert.match(record.id, /^[0-9a-f-]{36}$/);
  assert.equal(record.encrypted, true);
  assert.equal(record.status, 'on-router');
  assert.equal(record.device, 'edge_a-1');
  assert.equal(record.host, '192.0.2.10');
  assert.equal(record.routerFile, 'edge_a-1-2026.backup');
  assert.equal(Object.hasOwn(record, 'password'), false);
  assert.equal(Object.hasOwn(record, 'apiKey'), false);
  assert.deepEqual(Object.keys(record).sort(), ['createdAt', 'device', 'encrypted', 'host', 'id', 'routerFile', 'status']);

  const rootStat = await fs.stat(dataDirectory);
  const backupsStat = await fs.stat(backupsDirectory);
  const manifestStat = await fs.stat(path.join(backupsDirectory, 'index.json'));
  assert.equal(rootStat.mode & 0o777, 0o700);
  assert.equal(backupsStat.mode & 0o777, 0o700);
  assert.equal(manifestStat.mode & 0o777, 0o600);
  const rawManifest = await fs.readFile(path.join(backupsDirectory, 'index.json'), 'utf8');
  assert.doesNotMatch(rawManifest, /must-not-persist|also-secret/);
});

test('gets, lists, filters, and updates downloaded metadata with strict size/hash validation', async (t) => {
  await withDataDirectory(t);
  const first = await createPendingBackup(input());
  const second = await createPendingBackup(input({ device: 'edge-b', routerFile: 'second.backup' }));
  assert.deepEqual(await getBackupRecord(first.id), first);
  assert.deepEqual((await listBackupRecords({ device: 'edge-b' })).map((record) => record.id), [second.id]);
  assert.equal((await listBackupRecords()).length, 2);
  assert.equal(backupFilePath(first.id), path.join(process.env.MIKROTIK_DATA_DIR, 'backups', `${first.id}.backup`));

  const hash = 'a'.repeat(64);
  await assert.rejects(markBackupDownloaded(first.id, { size: 0, sha256: hash }), /positive safe integer/);
  await assert.rejects(markBackupDownloaded(first.id, { size: Number.MAX_SAFE_INTEGER + 1, sha256: hash }), /positive safe integer/);
  await assert.rejects(markBackupDownloaded(first.id, { size: 1, sha256: 'A'.repeat(64) }), /lowercase hexadecimal/);
  await assert.rejects(markBackupDownloaded(first.id, { size: 1, sha256: 'abc' }), /lowercase hexadecimal/);
  await assert.rejects(markBackupDownloaded(first.id, { size: 1234, sha256: hash }), /file must exist/);
  await fs.writeFile(backupFilePath(first.id), Buffer.alloc(1234, 7), { mode: 0o600 });

  const downloaded = await markBackupDownloaded(first.id, { size: 1234, sha256: hash });
  assert.equal(downloaded.status, 'downloaded');
  assert.equal(downloaded.localFile, `${first.id}.backup`);
  assert.equal(downloaded.size, 1234);
  assert.equal(downloaded.sha256, hash);
  assert.ok(Number.isFinite(Date.parse(downloaded.downloadedAt)));
  assert.deepEqual(await getBackupRecord(first.id), downloaded);
  await assert.rejects(markBackupDownloaded(first.id, { size: 5, sha256: hash }), /not pending/);
});

test('rejects invalid device, router filenames, and UUID path traversal', async (t) => {
  await withDataDirectory(t);
  for (const device of ['../edge', 'a/b', '', 'x'.repeat(49)]) {
    await assert.rejects(createPendingBackup(input({ device })), /device must match/);
  }
  for (const routerFile of ['../x.backup', 'folder/x.backup', '/tmp/x.backup', '.hidden.backup', 'x.txt', 'x.backup/../y.backup']) {
    await assert.rejects(createPendingBackup(input({ routerFile })), /safe \.backup basename/);
  }
  assert.throws(() => backupFilePath('../../index.json'), /valid UUID/);
  await assert.rejects(getBackupRecord('../../index.json'), /valid UUID/);
});

test('rejects symlinked and overly broad existing directories, manifest, and local files', async (t) => {
  const { parent, dataDirectory, backupsDirectory } = await withDataDirectory(t);
  await fs.mkdir(dataDirectory, { mode: 0o700 });
  await fs.chmod(dataDirectory, 0o750);
  await assert.rejects(createPendingBackup(input()), /group\/other permissions/);
  await fs.chmod(dataDirectory, 0o700);

  await fs.mkdir(backupsDirectory, { mode: 0o700 });
  await fs.chmod(backupsDirectory, 0o755);
  await assert.rejects(createPendingBackup(input()), /group\/other permissions/);
  await fs.chmod(backupsDirectory, 0o700);

  const record = await createPendingBackup(input());
  const manifest = path.join(backupsDirectory, 'index.json');
  await fs.chmod(manifest, 0o640);
  await assert.rejects(getBackupRecord(record.id), /group\/other access|mode 0600/);
  await fs.chmod(manifest, 0o600);

  const localFile = backupFilePath(record.id);
  const outsideFile = path.join(parent, 'outside.backup');
  await fs.writeFile(outsideFile, 'router backup', { mode: 0o600 });
  await fs.symlink(outsideFile, localFile);
  await assert.rejects(markBackupDownloaded(record.id, { size: 12, sha256: 'b'.repeat(64) }), /regular file, not a symlink/);
  assert.equal(await fs.readFile(outsideFile, 'utf8'), 'router backup');
  await fs.unlink(localFile);

  await fs.writeFile(localFile, Buffer.alloc(12), { mode: 0o600 });
  await markBackupDownloaded(record.id, { size: 12, sha256: 'b'.repeat(64) });
  await fs.unlink(localFile);
  await fs.symlink(outsideFile, localFile);
  await assert.rejects(deleteLocalBackup(record.id), /regular file, not a symlink/);
  assert.equal(await fs.readFile(outsideFile, 'utf8'), 'router backup');
});

test('rejects symlinked data roots, backup directories, and manifest files', async (t) => {
  const { parent, dataDirectory, backupsDirectory } = await withDataDirectory(t);
  await fs.mkdir(path.join(parent, 'real'), { mode: 0o700 });
  await fs.symlink(path.join(parent, 'real'), dataDirectory);
  await assert.rejects(createPendingBackup(input()), /symlink/);
  await fs.unlink(dataDirectory);

  await fs.mkdir(dataDirectory, { mode: 0o700 });
  await fs.mkdir(path.join(parent, 'real-backups'), { mode: 0o700 });
  await fs.symlink(path.join(parent, 'real-backups'), backupsDirectory);
  await assert.rejects(createPendingBackup(input()), /symlink/);
  await fs.unlink(backupsDirectory);

  await fs.mkdir(backupsDirectory, { mode: 0o700 });
  const target = path.join(parent, 'manifest-target');
  await fs.writeFile(target, '[]', { mode: 0o600 });
  await fs.symlink(target, path.join(backupsDirectory, 'index.json'));
  await assert.rejects(createPendingBackup(input()), /symlink/);
});

test('serializes concurrent insertions and persists all entries', async (t) => {
  await withDataDirectory(t);
  const records = await Promise.all(Array.from({ length: 40 }, (_, index) => createPendingBackup(input({
    device: `edge-${index}`,
    routerFile: `router-${index}.backup`,
  }))));
  assert.equal(new Set(records.map((record) => record.id)).size, 40);
  const listed = await listBackupRecords();
  assert.equal(listed.length, 40);
  assert.deepEqual(new Set(listed.map((record) => record.id)), new Set(records.map((record) => record.id)));
});

test('only deletes a downloaded local copy, never a router-side filename', async (t) => {
  const { dataDirectory } = await withDataDirectory(t);
  const pending = await createPendingBackup(input({ routerFile: 'important-router-backup.backup' }));
  const routerSideFixture = path.join(dataDirectory, pending.routerFile);
  await fs.writeFile(routerSideFixture, 'router-side data', { mode: 0o600 });
  await assert.rejects(deleteLocalBackup(pending.id), /Only a downloaded local backup/);
  assert.equal(await fs.readFile(routerSideFixture, 'utf8'), 'router-side data');
  assert.deepEqual(await getBackupRecord(pending.id), pending);

  const localPath = backupFilePath(pending.id);
  await fs.writeFile(localPath, 'downloaded local copy', { mode: 0o600 });
  const downloaded = await markBackupDownloaded(pending.id, { size: 21, sha256: 'c'.repeat(64) });
  assert.equal(downloaded.status, 'downloaded');
  assert.deepEqual(await deleteLocalBackup(pending.id), { id: pending.id, deleted: true });
  await assert.rejects(fs.lstat(localPath), { code: 'ENOENT' });
  await assert.rejects(getBackupRecord(pending.id), /Backup not found/);
  assert.equal(await fs.readFile(routerSideFixture, 'utf8'), 'router-side data');
});
