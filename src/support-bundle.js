import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { gzipSync } from 'node:zlib';

const DEVICE_ID = /^[A-Za-z0-9_-]{1,48}$/;
const DEFAULT_MAX_BYTES = 25 * 1024 * 1024;

function dataRoot(dataDir) {
  if (dataDir !== undefined) {
    if (typeof dataDir !== 'string' || dataDir.length === 0) throw new TypeError('dataDir must be a non-empty path when supplied.');
    return path.resolve(dataDir);
  }
  return process.env.MIKROTIK_DATA_DIR
    ? path.resolve(process.env.MIKROTIK_DATA_DIR)
    : path.resolve(process.cwd(), '.data');
}

async function ensurePrivateDirectory(root) {
  const directory = path.join(root, 'support-bundles');
  let current = path.parse(root).root;
  for (const part of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const info = await fs.lstat(current);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`Support bundle path component must be a regular directory, not a symlink: ${current}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const rootInfo = await fs.lstat(root);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory() || (rootInfo.mode & 0o077) !== 0) {
    throw new Error(`Support bundle data root must be a private regular directory (mode 0700 or stricter): ${root}`);
  }
  try {
    await fs.mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const info = await fs.lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory() || (info.mode & 0o077) !== 0) {
    throw new Error('Support bundle storage must be a private regular directory (mode 0700 or stricter).');
  }
  return directory;
}

/** Save an allowlisted resource inventory as a private gzip JSON artifact. */
export async function createRouterSupportBundle({
  device,
  generatedAt = new Date().toISOString(),
  router = {},
  resources,
  dataDir,
  maxUncompressedBytes = DEFAULT_MAX_BYTES,
} = {}) {
  if (typeof device !== 'string' || !DEVICE_ID.test(device)) throw new TypeError('device must be a configured router ID.');
  if (typeof generatedAt !== 'string' || !Number.isFinite(Date.parse(generatedAt))) throw new TypeError('generatedAt must be a valid ISO date string.');
  if (!Array.isArray(resources) || resources.length < 1 || resources.length > 500) throw new TypeError('resources must contain 1–500 catalog entries.');
  if (!Number.isSafeInteger(maxUncompressedBytes) || maxUncompressedBytes < 1024 || maxUncompressedBytes > 100 * 1024 * 1024) {
    throw new RangeError('maxUncompressedBytes must be from 1 KiB to 100 MiB.');
  }
  const bundle = {
    schemaVersion: 1,
    generatedAt,
    device,
    router: {
      endpoint: typeof router.endpoint === 'string' ? router.endpoint.slice(0, 253) : undefined,
      identity: router.identity && typeof router.identity === 'object' ? router.identity : null,
      resources: router.resources && typeof router.resources === 'object' ? router.resources : null,
    },
    format: 'Allowlisted, redacted RouterOS resource inventory; not a restorable backup or full CLI export.',
    resources,
  };
  const json = Buffer.from(JSON.stringify(bundle));
  if (json.length > maxUncompressedBytes) throw new RangeError(`Support bundle exceeds the ${maxUncompressedBytes}-byte uncompressed size limit.`);
  const compressed = gzipSync(json, { level: 6, mtime: 0 });
  const directory = await ensurePrivateDirectory(dataRoot(dataDir));
  const id = crypto.randomUUID();
  const target = path.join(directory, `${id}.json.gz`);
  const temporary = path.join(directory, `.${id}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(compressed);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
    await fs.chmod(target, 0o600);
    const directoryHandle = await fs.open(directory, 'r');
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    await fs.unlink(target).catch(() => {});
    throw new Error(`Unable to write private support bundle: ${error.message}`);
  }
  const info = await fs.lstat(target);
  if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o777) !== 0o600 || (info.mode & 0o111) !== 0) {
    await fs.unlink(target).catch(() => {});
    throw new Error('Completed support bundle failed private-file verification.');
  }
  return {
    id,
    device,
    generatedAt,
    localPath: target,
    compressedBytes: info.size,
    uncompressedBytes: json.length,
    sha256: crypto.createHash('sha256').update(compressed).digest('hex'),
    resourceEntries: resources.length,
    records: resources.reduce((sum, item) => sum + (Array.isArray(item.records) ? item.records.length : 0), 0),
    filePermissions: '0600',
    note: 'Contains allowlisted router inventory which may include private addresses and configuration details. Keep the file private; it is not a restorable backup or a complete RouterOS CLI export.',
  };
}

export { DEFAULT_MAX_BYTES as SUPPORT_BUNDLE_MAX_UNCOMPRESSED_BYTES };
