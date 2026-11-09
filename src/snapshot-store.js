import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const INVENTORY_NOTE = 'Inventory snapshot only; this is not a restorable RouterOS backup.';
const RECORD_FIELDS = ['records', 'items', 'entries', 'data'];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VOLATILE_KEY_PATTERN = /(?:counter|uptime|timestamp|createdat|updatedat|lastupdated|lastseen|lastlinkup|lastlinkdown|lastdown|lastup|lastactivity|status|dynamic|running|rxbyte|txbyte|rxpacket|txpacket|bytes|packets|traffic|age|elapsed|since|cpuload|memoryused|freememory|freehddspace)/;

function snapshotDirectory() {
  const configured = process.env.MIKROTIK_DATA_DIR;
  return configured
    ? path.resolve(configured)
    : path.resolve(__dirname, '..', '.data', 'snapshots');
}

async function ensureDirectory() {
  const directory = snapshotDirectory();
  await fs.mkdir(path.dirname(directory), { recursive: true, mode: 0o700 });
  try {
    await fs.mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const info = await fs.lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`Snapshot storage path is not a safe directory: ${directory}`);
  }
  if ((info.mode & 0o077) !== 0) throw new Error('Snapshot storage directory must be private (mode 0700 or stricter).');
  return directory;
}

function validateId(id) {
  if (typeof id !== 'string' || !UUID_PATTERN.test(id)) {
    throw new Error('Snapshot ID must be a valid UUID.');
  }
  return id.toLowerCase();
}

function filePath(directory, id) {
  return path.join(directory, `${validateId(id)}.json`);
}

function countRecords(resources) {
  return resources.reduce((count, resource) => {
    if (resource && typeof resource === 'object' && !Array.isArray(resource)) {
      for (const field of RECORD_FIELDS) {
        if (Array.isArray(resource[field])) return count + resource[field].length;
      }
    }
    return count;
  }, 0);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key]);
    return result;
  }
  return value;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!VOLATILE_KEY_PATTERN.test(normalizedKey)) result[key] = stableValue(value[key]);
    }
    return result;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function stableJson(value) {
  return JSON.stringify(canonicalize(stableValue(value)));
}

function getRecords(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return [];
  for (const field of RECORD_FIELDS) {
    if (Array.isArray(resource[field])) return resource[field];
  }
  return [];
}

function getRecordField(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return null;
  return RECORD_FIELDS.find((field) => Array.isArray(resource[field])) || null;
}

function withoutRecords(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return resource;
  const result = {};
  for (const [key, value] of Object.entries(resource)) {
    if (!RECORD_FIELDS.includes(key) || !Array.isArray(value)) result[key] = value;
  }
  return result;
}

function identityKey(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const id = value['.id'] ?? value.id;
    if (id !== undefined && id !== null) return `id:${canonicalJson(id)}`;
  }
  return `json:${stableJson(value)}`;
}

function resourceIdentityKey(resource) {
  if (resource && typeof resource === 'object' && !Array.isArray(resource)) {
    const id = resource.id ?? resource.name ?? resource.resource ?? resource.path;
    if (id !== undefined && id !== null) return `id:${canonicalJson(id)}`;
  }
  // Use a resource descriptor, excluding its records, so record changes remain
  // diffable within the same resource rather than replacing the whole resource.
  return `json:${stableJson(withoutRecords(resource))}`;
}

function displayResourceName(resource, index) {
  if (resource && typeof resource === 'object' && !Array.isArray(resource)) {
    for (const key of ['name', 'resource', 'path', 'id']) {
      if (resource[key] !== undefined && resource[key] !== null) return String(resource[key]);
    }
  }
  return `Resource ${index + 1}`;
}

function bucketByKey(items, keyFunction) {
  const result = new Map();
  for (const item of items) {
    const key = keyFunction(item);
    const queue = result.get(key) || [];
    queue.push(item);
    result.set(key, queue);
  }
  return result;
}

function compareRecords(beforeRecords, afterRecords) {
  const beforeBuckets = bucketByKey(beforeRecords, identityKey);
  const afterBuckets = bucketByKey(afterRecords, identityKey);
  const added = [];
  const removed = [];
  const changed = [];
  const keys = new Set([...beforeBuckets.keys(), ...afterBuckets.keys()]);

  for (const key of keys) {
    const beforeQueue = beforeBuckets.get(key) || [];
    const afterQueue = afterBuckets.get(key) || [];
    const paired = Math.min(beforeQueue.length, afterQueue.length);
    for (let i = 0; i < paired; i += 1) {
      const before = beforeQueue[i];
      const after = afterQueue[i];
      if (stableJson(before) !== stableJson(after)) changed.push({ before, after });
    }
    for (let i = paired; i < beforeQueue.length; i += 1) removed.push(beforeQueue[i]);
    for (let i = paired; i < afterQueue.length; i += 1) added.push(afterQueue[i]);
  }
  return { added, removed, changed };
}

function validateSnapshotInput({ device, host, version, resources }) {
  if (typeof device !== 'string' || device.length === 0) {
    throw new Error('Snapshot device must be a non-empty string.');
  }
  if (typeof host !== 'string' || host.length === 0) {
    throw new Error('Snapshot host must be a non-empty string.');
  }
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('Snapshot version must be a non-empty string.');
  }
  if (!Array.isArray(resources)) {
    throw new Error('Snapshot resources must be an array.');
  }
  let serialized;
  try {
    serialized = JSON.stringify(resources);
  } catch (error) {
    throw new Error(`Snapshot resources must be JSON-serializable: ${error.message}`);
  }
  if (serialized === undefined) {
    throw new Error('Snapshot resources must be JSON-serializable.');
  }
  return serialized;
}

async function writeAtomically(directory, id, content) {
  const target = filePath(directory, id);
  const temporary = path.join(directory, `.${id}.${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw new Error(`Unable to persist snapshot: ${error.message}`);
  }
}

async function readSnapshotFile(id) {
  const normalizedId = validateId(id);
  const directory = await ensureDirectory();
  const target = filePath(directory, normalizedId);
  let contents;
  try {
    const info = await fs.lstat(target);
    if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o077) !== 0) throw new Error('Snapshot file is not a private regular file.');
    contents = await fs.readFile(target, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`Snapshot not found: ${normalizedId}`);
    throw new Error(`Unable to read snapshot ${normalizedId}: ${error.message}`);
  }
  try {
    return JSON.parse(contents);
  } catch (error) {
    throw new Error(`Snapshot ${normalizedId} contains invalid JSON: ${error.message}`);
  }
}

function publicMetadata(snapshot) {
  const { id, createdAt, device, host, version, resourceCount, recordCount, hash } = snapshot;
  return { id, createdAt, device, host, version, resourceCount, recordCount, hash, note: INVENTORY_NOTE };
}

async function createSnapshot({ device, host, version, resources } = {}) {
  validateSnapshotInput({ device, host, version, resources });
  const createdAt = new Date().toISOString();
  const id = crypto.randomUUID();
  let resourcesJson;
  try {
    resourcesJson = JSON.stringify(resources);
  } catch (error) {
    throw new Error(`Snapshot resources must be JSON-serializable: ${error.message}`);
  }
  const resourceCopy = JSON.parse(resourcesJson);
  const payload = { device, host, version, resources: resourceCopy };
  const payloadJson = JSON.stringify(payload);
  const hash = crypto.createHash('sha256').update(payloadJson).digest('hex');
  const snapshot = {
    id,
    createdAt,
    device,
    host,
    version,
    resourceCount: resourceCopy.length,
    recordCount: countRecords(resourceCopy),
    hash,
    note: INVENTORY_NOTE,
    resources: resourceCopy,
  };
  const content = JSON.stringify(snapshot);
  const contentSize = Buffer.byteLength(content, 'utf8');
  if (contentSize > MAX_PAYLOAD_BYTES) {
    throw new Error(`Serialized snapshot exceeds the 10 MiB limit (${contentSize} bytes).`);
  }
  const directory = await ensureDirectory();
  await writeAtomically(directory, id, content);
  return publicMetadata(snapshot);
}

async function listSnapshots() {
  const directory = await ensureDirectory();
  let names;
  try {
    names = await fs.readdir(directory);
  } catch (error) {
    throw new Error(`Unable to list snapshots: ${error.message}`);
  }
  const ids = names
    .filter((name) => name.endsWith('.json') && UUID_PATTERN.test(name.slice(0, -5)))
    .map((name) => name.slice(0, -5).toLowerCase())
    .sort();
  const snapshots = await Promise.all(ids.map((id) => readSnapshotFile(id)));
  return snapshots.map(publicMetadata).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
}

async function getSnapshot(id) {
  const snapshot = await readSnapshotFile(id);
  return { ...publicMetadata(snapshot), resources: snapshot.resources };
}

async function deleteSnapshot(id) {
  const normalizedId = validateId(id);
  const directory = await ensureDirectory();
  try {
    await fs.unlink(filePath(directory, normalizedId));
    return { id: normalizedId, deleted: true };
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`Snapshot not found: ${normalizedId}`);
    throw new Error(`Unable to delete snapshot ${normalizedId}: ${error.message}`);
  }
}

async function diffSnapshots(baseId, currentId) {
  const [base, current] = await Promise.all([
    readSnapshotFile(baseId),
    readSnapshotFile(currentId),
  ]);
  const baseBuckets = bucketByKey(base.resources || [], resourceIdentityKey);
  const currentBuckets = bucketByKey(current.resources || [], resourceIdentityKey);
  const keys = new Set([...baseBuckets.keys(), ...currentBuckets.keys()]);
  const resourceDiffs = [];
  const totals = {
    resourcesAdded: 0,
    resourcesRemoved: 0,
    resourcesChanged: 0,
    recordsAdded: 0,
    recordsRemoved: 0,
    recordsChanged: 0,
  };

  for (const key of keys) {
    const beforeQueue = baseBuckets.get(key) || [];
    const afterQueue = currentBuckets.get(key) || [];
    const paired = Math.min(beforeQueue.length, afterQueue.length);
    for (let i = paired; i < beforeQueue.length; i += 1) {
      const before = beforeQueue[i];
      resourceDiffs.push({
        resource: displayResourceName(before, i),
        status: 'removed',
        before,
        after: null,
        added: [], removed: getRecords(before), changed: [],
      });
      totals.resourcesRemoved += 1;
      totals.recordsRemoved += getRecords(before).length;
    }
    for (let i = paired; i < afterQueue.length; i += 1) {
      const after = afterQueue[i];
      resourceDiffs.push({
        resource: displayResourceName(after, i),
        status: 'added',
        before: null,
        after,
        added: getRecords(after), removed: [], changed: [],
      });
      totals.resourcesAdded += 1;
      totals.recordsAdded += getRecords(after).length;
    }
    for (let i = 0; i < paired; i += 1) {
      const before = beforeQueue[i];
      const after = afterQueue[i];
      const recordDiff = compareRecords(getRecords(before), getRecords(after));
      const descriptorChanged = stableJson(withoutRecords(before)) !== stableJson(withoutRecords(after));
      const status = descriptorChanged || recordDiff.added.length || recordDiff.removed.length || recordDiff.changed.length
        ? 'changed'
        : 'unchanged';
      if (status !== 'unchanged') {
        resourceDiffs.push({
          resource: displayResourceName(after, i),
          status,
          before,
          after,
          resourceChanged: descriptorChanged ? { before: withoutRecords(before), after: withoutRecords(after) } : null,
          added: recordDiff.added,
          removed: recordDiff.removed,
          changed: recordDiff.changed,
        });
      }
      totals.recordsAdded += recordDiff.added.length;
      totals.recordsRemoved += recordDiff.removed.length;
      totals.recordsChanged += recordDiff.changed.length;
      if (descriptorChanged) totals.resourcesChanged += 1;
    }
  }
  return {
    baseId: validateId(baseId),
    currentId: validateId(currentId),
    resources: resourceDiffs,
    totals,
    note: INVENTORY_NOTE,
  };
}

export { createSnapshot, listSnapshots, getSnapshot, deleteSnapshot, diffSnapshots };
