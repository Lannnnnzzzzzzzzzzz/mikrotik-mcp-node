import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEVICE_PATTERN = /^[A-Za-z0-9_-]{1,48}$/;
const ROUTER_FILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.backup$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const MAX_RECORDS = 500;
let mutationQueue = Promise.resolve();

function storageRoot() {
  if (process.env.MIKROTIK_DATA_DIR !== undefined) {
    if (!process.env.MIKROTIK_DATA_DIR) throw new Error('MIKROTIK_DATA_DIR must not be empty.');
    return path.resolve(process.env.MIKROTIK_DATA_DIR);
  }
  return path.resolve(process.cwd(), '.data');
}

function storageDirectory() {
  return path.join(storageRoot(), 'backups');
}

function assertPrivateDirectoryStat(info, directory) {
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`Backup storage path must be a regular directory, not a symlink: ${directory}`);
  }
  if ((info.mode & 0o077) !== 0) {
    throw new Error(`Backup storage directory must be private (no group/other permissions): ${directory}`);
  }
}

async function ensureDirectory() {
  const root = storageRoot();
  const directory = path.join(root, 'backups');

  // Reject symlinked path components as well as symlinked storage directories.
  // Only the vault root and backups directory are required to be private; their
  // existing ancestors are checked for path substitution but not permissions.
  const absoluteComponents = [];
  let current = path.parse(root).root;
  for (const component of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    absoluteComponents.push(current);
  }
  for (const component of absoluteComponents) {
    try {
      const info = await fs.lstat(component);
      if (info.isSymbolicLink() || !info.isDirectory()) {
        throw new Error(`Backup storage path component must be a regular directory, not a symlink: ${component}`);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const rootInfo = await fs.lstat(root);
  assertPrivateDirectoryStat(rootInfo, root);
  try {
    await fs.mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const directoryInfo = await fs.lstat(directory);
  assertPrivateDirectoryStat(directoryInfo, directory);
  return directory;
}

function validateId(id) {
  if (typeof id !== 'string' || !UUID_PATTERN.test(id)) {
    throw new Error('Backup ID must be a valid UUID.');
  }
  return id.toLowerCase();
}

function validateDevice(device) {
  if (typeof device !== 'string' || !DEVICE_PATTERN.test(device)) {
    throw new Error('device must match /^[A-Za-z0-9_-]{1,48}$/.');
  }
  return device;
}

function validateRouterFile(routerFile) {
  if (typeof routerFile !== 'string' || !ROUTER_FILE_PATTERN.test(routerFile) || routerFile === '.' || routerFile === '..') {
    throw new Error('routerFile must be a single safe .backup basename.');
  }
  return routerFile;
}

function backupPath(directory, id) {
  return path.join(directory, `${validateId(id)}.backup`);
}

function manifestPath(directory) {
  return path.join(directory, 'index.json');
}

function assertPrivateRegularFile(info, label) {
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error(`${label} must be a regular file, not a symlink.`);
  }
  if ((info.mode & 0o077) !== 0 || (info.mode & 0o100) !== 0) {
    throw new Error(`${label} must not grant group/other access or owner execute permission.`);
  }
}

function validateRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('Backup manifest contains an invalid record.');
  }
  const pendingKeys = ['id', 'device', 'host', 'routerFile', 'encrypted', 'status', 'createdAt'];
  const downloadedKeys = [...pendingKeys, 'localFile', 'downloadedAt', 'size', 'sha256'];
  const expectedKeys = record.status === 'downloaded' ? downloadedKeys : pendingKeys;
  const actualKeys = Object.keys(record).sort();
  if (record.status !== 'on-router' && record.status !== 'downloaded') {
    throw new Error('Backup manifest contains an invalid status.');
  }
  if (actualKeys.join('\0') !== [...expectedKeys].sort().join('\0')) {
    throw new Error('Backup manifest contains unexpected or missing metadata fields.');
  }
  validateId(record.id);
  validateDevice(record.device);
  validateRouterFile(record.routerFile);
  if (typeof record.host !== 'string' || record.host.length < 1 || record.host.length > 255 || /[\u0000-\u001f\u007f]/.test(record.host)) {
    throw new Error('Backup manifest contains an invalid host.');
  }
  if (record.encrypted !== true || typeof record.createdAt !== 'string' || !Number.isFinite(Date.parse(record.createdAt))) {
    throw new Error('Backup manifest contains invalid backup metadata.');
  }
  if (record.status === 'downloaded') {
    if (record.localFile !== `${record.id}.backup` || typeof record.downloadedAt !== 'string' || !Number.isFinite(Date.parse(record.downloadedAt))) {
      throw new Error('Backup manifest contains invalid download metadata.');
    }
    if (!Number.isSafeInteger(record.size) || record.size <= 0 || typeof record.sha256 !== 'string' || !SHA256_PATTERN.test(record.sha256)) {
      throw new Error('Backup manifest contains an invalid size or SHA-256 hash.');
    }
  }
  return record;
}

async function readManifest(directory) {
  const target = manifestPath(directory);
  try {
    const info = await fs.lstat(target);
    assertPrivateRegularFile(info, 'Backup manifest');
    if ((info.mode & 0o777) !== 0o600) throw new Error('Backup manifest must have mode 0600.');
    const records = JSON.parse(await fs.readFile(target, 'utf8'));
    if (!Array.isArray(records)) throw new Error('Backup manifest must contain a JSON array.');
    if (records.length > MAX_RECORDS) throw new Error(`Backup manifest cannot exceed ${MAX_RECORDS} records.`);
    const ids = new Set();
    for (const record of records) {
      validateRecord(record);
      if (ids.has(record.id)) throw new Error('Backup manifest contains duplicate IDs.');
      ids.add(record.id);
    }
    return records;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error(`Unable to read backup manifest: ${error.message}`);
  }
}

async function writeManifest(directory, records) {
  if (records.length > MAX_RECORDS) throw new Error(`Backup manifest cannot exceed ${MAX_RECORDS} records.`);
  for (const record of records) validateRecord(record);
  const target = manifestPath(directory);
  const temporary = path.join(directory, `.index.${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    try {
      const existing = await fs.lstat(target);
      assertPrivateRegularFile(existing, 'Backup manifest');
      if ((existing.mode & 0o777) !== 0o600) throw new Error('Backup manifest must have mode 0600.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(records), 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
    const directoryHandle = await fs.open(directory, 'r');
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw new Error(`Unable to persist backup manifest: ${error.message}`);
  }
}

function serializeMutation(operation) {
  const pending = mutationQueue.then(operation, operation);
  mutationQueue = pending.catch(() => {});
  return pending;
}

function publicRecord(record) {
  return { ...record };
}

async function createPendingBackup({ device, host, routerFile } = {}) {
  validateDevice(device);
  validateRouterFile(routerFile);
  if (typeof host !== 'string' || host.length < 1 || host.length > 255 || /[\u0000-\u001f\u007f]/.test(host)) {
    throw new Error('host must be a non-empty hostname or address of at most 255 characters.');
  }
  return serializeMutation(async () => {
    const directory = await ensureDirectory();
    const records = await readManifest(directory);
    if (records.length >= MAX_RECORDS) throw new Error(`Backup manifest cannot exceed ${MAX_RECORDS} records.`);
    const record = {
      id: crypto.randomUUID(),
      device,
      host,
      routerFile,
      encrypted: true,
      status: 'on-router',
      createdAt: new Date().toISOString(),
    };
    await writeManifest(directory, [...records, record]);
    return publicRecord(record);
  });
}

async function getBackupRecord(id) {
  const normalizedId = validateId(id);
  const directory = await ensureDirectory();
  const record = (await readManifest(directory)).find((item) => item.id === normalizedId);
  if (!record) throw new Error(`Backup not found: ${normalizedId}`);
  return publicRecord(record);
}

async function listBackupRecords({ device } = {}) {
  if (device !== undefined) validateDevice(device);
  const directory = await ensureDirectory();
  const records = await readManifest(directory);
  return records
    .filter((record) => device === undefined || record.device === device)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt) || a.id.localeCompare(b.id))
    .map(publicRecord);
}

function backupFilePath(id) {
  return backupPath(storageDirectory(), id);
}

async function assertSafeBackupFile(target) {
  try {
    const info = await fs.lstat(target);
    assertPrivateRegularFile(info, 'Local backup file');
    return info;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function markBackupDownloaded(id, { size, sha256 } = {}) {
  const normalizedId = validateId(id);
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error('size must be a positive safe integer.');
  if (typeof sha256 !== 'string' || !SHA256_PATTERN.test(sha256)) throw new Error('sha256 must be 64 lowercase hexadecimal characters.');
  return serializeMutation(async () => {
    const directory = await ensureDirectory();
    const records = await readManifest(directory);
    const index = records.findIndex((record) => record.id === normalizedId);
    if (index === -1) throw new Error(`Backup not found: ${normalizedId}`);
    if (records[index].status !== 'on-router') throw new Error(`Backup is not pending download: ${normalizedId}`);
    const localFileInfo = await assertSafeBackupFile(backupPath(directory, normalizedId));
    if (!localFileInfo) throw new Error('The private local backup file must exist before recording a completed download.');
    if (localFileInfo.size !== size) throw new Error('The private local backup file size does not match the completed transfer size.');
    const updated = {
      ...records[index],
      status: 'downloaded',
      localFile: `${normalizedId}.backup`,
      downloadedAt: new Date().toISOString(),
      size,
      sha256,
    };
    records[index] = updated;
    await writeManifest(directory, records);
    return publicRecord(updated);
  });
}

async function deleteLocalBackup(id) {
  const normalizedId = validateId(id);
  return serializeMutation(async () => {
    const directory = await ensureDirectory();
    const records = await readManifest(directory);
    const index = records.findIndex((record) => record.id === normalizedId);
    if (index === -1) throw new Error(`Backup not found: ${normalizedId}`);
    if (records[index].status !== 'downloaded') throw new Error('Only a downloaded local backup can be deleted.');

    const localPath = backupPath(directory, normalizedId);
    const exists = await assertSafeBackupFile(localPath);
    if (exists) await fs.unlink(localPath);
    records.splice(index, 1);
    await writeManifest(directory, records);
    return { id: normalizedId, deleted: true };
  });
}

export {
  createPendingBackup,
  getBackupRecord,
  listBackupRecords,
  backupFilePath,
  markBackupDownloaded,
  deleteLocalBackup,
};
