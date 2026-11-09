import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import { DeleteObjectCommand, ListObjectVersionsCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { backupFilePath, getBackupRecord } from './backup-store.js';

const MAX_BACKUP_BYTES = 100 * 1024 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEVICE_PATTERN = /^[A-Za-z0-9_-]{1,48}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UNSUPPORTED_ENDPOINT_ENV = ['MIKROTIK_S3_ENDPOINT', 'S3_ENDPOINT', 'AWS_ENDPOINT_URL', 'AWS_ENDPOINT_URL_S3'];

function validatePrefix(prefix) {
  if (typeof prefix !== 'string' || prefix.length < 1 || prefix.length > 512
    || prefix.startsWith('/') || prefix.endsWith('/')
    || prefix.split('/').some((part) => !/^[A-Za-z0-9._-]+$/.test(part) || part === '.' || part === '..')) {
    throw new Error('MIKROTIK_S3_PREFIX must be a safe, non-empty slash-separated S3 key prefix.');
  }
  return prefix;
}

function validateBucket(bucket) {
  if (typeof bucket !== 'string' || bucket.length < 3 || bucket.length > 63
    || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(bucket)
    || bucket.includes('..') || bucket.includes('.-') || bucket.includes('-.')
    || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(bucket)) {
    throw new Error('MIKROTIK_S3_BUCKET must be a valid standard S3 bucket name.');
  }
  return bucket;
}

function validateRegion(region) {
  if (typeof region !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)+-\d$/.test(region)) {
    throw new Error('MIKROTIK_S3_REGION must be a valid AWS region identifier.');
  }
  return region;
}

function optInFlag(env, name) {
  const value = env[name];
  if (value === undefined || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error(`${name} must be exactly "true" or "false".`);
}

/** Pure environment-to-configuration conversion. No credential material is read or returned. */
function getS3BackupConfiguration(env = process.env) {
  if (!env || typeof env !== 'object') throw new Error('S3 backup environment must be an object.');
  for (const name of UNSUPPORTED_ENDPOINT_ENV) {
    if (env[name] !== undefined && env[name] !== '') {
      throw new Error(`Custom S3 endpoints are not supported (${name}).`);
    }
  }

  const enabledValue = env.MIKROTIK_S3_ENABLED;
  if (enabledValue !== undefined && enabledValue !== 'true' && enabledValue !== 'false') {
    throw new Error('MIKROTIK_S3_ENABLED must be exactly "true" or "false".');
  }
  const allowListing = optInFlag(env, 'MIKROTIK_S3_ALLOW_LISTING');
  const allowDelete = optInFlag(env, 'MIKROTIK_S3_ALLOW_DELETE');
  const allowVersionPurge = optInFlag(env, 'MIKROTIK_S3_ALLOW_VERSION_PURGE');
  if (enabledValue !== 'true') return { enabled: false };

  const bucket = validateBucket(env.MIKROTIK_S3_BUCKET);
  const region = validateRegion(env.MIKROTIK_S3_REGION);
  const expectedBucketOwner = env.MIKROTIK_S3_EXPECTED_BUCKET_OWNER;
  if (typeof expectedBucketOwner !== 'string' || !/^\d{12}$/.test(expectedBucketOwner)) {
    throw new Error('MIKROTIK_S3_EXPECTED_BUCKET_OWNER is required and must contain exactly 12 digits.');
  }
  const prefix = validatePrefix(env.MIKROTIK_S3_PREFIX === undefined ? 'mikrotik-backups' : env.MIKROTIK_S3_PREFIX);
  const serverSideEncryption = env.MIKROTIK_S3_SERVER_SIDE_ENCRYPTION === undefined
    ? 'AES256'
    : env.MIKROTIK_S3_SERVER_SIDE_ENCRYPTION;
  if (serverSideEncryption !== 'AES256' && serverSideEncryption !== 'aws:kms') {
    throw new Error('MIKROTIK_S3_SERVER_SIDE_ENCRYPTION must be AES256 or aws:kms.');
  }
  const kmsKeyId = env.MIKROTIK_S3_KMS_KEY_ID;
  if (serverSideEncryption === 'aws:kms' && (typeof kmsKeyId !== 'string' || kmsKeyId.trim() === '')) {
    throw new Error('MIKROTIK_S3_KMS_KEY_ID is required when using aws:kms encryption.');
  }

  return {
    enabled: true,
    bucket,
    region,
    expectedBucketOwner,
    prefix,
    serverSideEncryption,
    allowListing,
    allowDelete,
    allowVersionPurge,
    ...(serverSideEncryption === 'aws:kms' ? { kmsKeyId } : {}),
  };
}

/** Pure immutable destination derivation; callers cannot supply or override bucket/key. */
function getS3BackupTarget(record, config) {
  if (!config || config.enabled !== true) throw new Error('S3 backup is not enabled.');
  if (!record || typeof record !== 'object' || record.status !== 'downloaded') {
    throw new Error('Only a downloaded backup can be uploaded to S3.');
  }
  if (typeof record.id !== 'string' || !UUID_PATTERN.test(record.id)) throw new Error('Backup record has an invalid ID.');
  if (typeof record.device !== 'string' || !DEVICE_PATTERN.test(record.device)) throw new Error('Backup record has an invalid device.');
  const bucket = validateBucket(config.bucket);
  const prefix = validatePrefix(config.prefix);
  const region = validateRegion(config.region);
  return { bucket, key: `${prefix}/${record.device}/${record.id.toLowerCase()}.backup`, region };
}

function assertPrivateRegularFile(info) {
  if (!info.isFile()) throw new Error('Local backup must be a regular file, not a symlink or special file.');
  const mode = typeof info.mode === 'bigint' ? info.mode : BigInt(info.mode);
  if ((mode & 0o077n) !== 0n || (mode & 0o100n) !== 0n) {
    throw new Error('Local backup file must have private permissions (no group/other access or owner execute permission).');
  }
  if (info.size <= 0 || info.size > MAX_BACKUP_BYTES) {
    throw new Error('Local backup size must be between 1 byte and 100 MiB.');
  }
}

function sameFileSnapshot(first, second) {
  return first.dev === second.dev && first.ino === second.ino && first.size === second.size
    && first.mode === second.mode && first.mtimeNs === second.mtimeNs && first.ctimeNs === second.ctimeNs;
}

async function hashOpenFile(handle, size) {
  const hash = crypto.createHash('sha256');
  const chunk = Buffer.allocUnsafe(128 * 1024);
  let position = 0;
  while (position < size) {
    const { bytesRead } = await handle.read(chunk, 0, Math.min(chunk.length, size - position), position);
    if (bytesRead === 0) throw new Error('Local backup changed or ended while being verified.');
    hash.update(chunk.subarray(0, bytesRead));
    position += bytesRead;
  }
  return hash.digest('hex');
}

async function openVerifiedBackup(filePath, record) {
  let linkStat;
  try {
    linkStat = await fsp.lstat(filePath, { bigint: true });
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('Downloaded local backup file is missing.');
    throw error;
  }
  assertPrivateRegularFile(linkStat);

  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
  const handle = await fsp.open(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    assertPrivateRegularFile(opened);
    if (linkStat.dev !== opened.dev || linkStat.ino !== opened.ino) {
      throw new Error('Local backup file changed while it was being opened.');
    }
    if (opened.size !== BigInt(record.size)) throw new Error('Local backup size does not match its manifest.');
    const digest = await hashOpenFile(handle, Number(opened.size));
    const afterHash = await handle.stat({ bigint: true });
    if (!sameFileSnapshot(opened, afterHash)) throw new Error('Local backup changed while its checksum was verified.');
    if (digest !== record.sha256) throw new Error('Local backup SHA-256 does not match its manifest.');

    // On platforms without O_NOFOLLOW, also compare the path after opening; the
    // handle remains pinned to the verified inode for hashing and the S3 stream.
    if (noFollow === 0) {
      const finalPathStat = await fsp.lstat(filePath, { bigint: true });
      if (finalPathStat.dev !== opened.dev || finalPathStat.ino !== opened.ino || !finalPathStat.isFile()) {
        throw new Error('Local backup path changed during verification.');
      }
    }
    return { handle, size: Number(opened.size), sha256: digest };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

function safeS3Error(error) {
  const status = error?.$metadata?.httpStatusCode;
  const name = error?.name;
  if (status === 412 || name === 'PreconditionFailed') {
    const result = new Error('S3 object already exists; refusing to overwrite it.');
    result.code = 'S3_OBJECT_EXISTS';
    return result;
  }
  if (status === undefined && (error?.code || error?.name === 'TimeoutError' || error?.name === 'NetworkingError')) {
    const result = new Error('S3 upload outcome is ambiguous; verify the destination object before retrying.');
    result.code = 'S3_UPLOAD_OUTCOME_UNKNOWN';
    return result;
  }
  const result = new Error(status ? `S3 upload failed (HTTP ${status}).` : 'S3 upload failed.');
  result.code = 'S3_UPLOAD_FAILED';
  return result;
}

/** Upload a downloaded, RouterOS-encrypted backup to its derived S3 key. */
async function uploadEncryptedBackupToS3({ backupId, env = process.env, clientFactory = (options) => new S3Client(options) } = {}) {
  const config = getS3BackupConfiguration(env);
  if (!config.enabled) throw new Error('S3 backup upload is disabled.');
  const record = await getBackupRecord(backupId);
  if (record.status !== 'downloaded') throw new Error('Only a downloaded backup can be uploaded to S3.');
  if (record.encrypted !== true) throw new Error('Only RouterOS-encrypted backups can be uploaded to S3.');
  if (!Number.isSafeInteger(record.size) || record.size <= 0 || record.size > MAX_BACKUP_BYTES
    || typeof record.sha256 !== 'string' || !SHA256_PATTERN.test(record.sha256)) {
    throw new Error('Downloaded backup manifest has invalid size or SHA-256 metadata.');
  }
  const target = getS3BackupTarget(record, config);
  const verified = await openVerifiedBackup(backupFilePath(record.id), record);
  let client;
  let body;
  try {
    client = clientFactory({ region: config.region, maxAttempts: 1 });
    if (!client || typeof client.send !== 'function') throw new Error('S3 client factory did not return a compatible client.');
    body = verified.handle.createReadStream({ start: 0, autoClose: false });
    const command = new PutObjectCommand({
      Bucket: target.bucket,
      Key: target.key,
      Body: body,
      ContentLength: verified.size,
      ContentType: 'application/octet-stream',
      ExpectedBucketOwner: config.expectedBucketOwner,
      IfNoneMatch: '*',
      ChecksumSHA256: Buffer.from(verified.sha256, 'hex').toString('base64'),
      ServerSideEncryption: config.serverSideEncryption,
      ...(config.serverSideEncryption === 'aws:kms' ? { SSEKMSKeyId: config.kmsKeyId } : {}),
    });
    let response;
    try {
      response = await client.send(command);
    } catch (error) {
      throw safeS3Error(error);
    }
    return {
      bucket: target.bucket,
      key: target.key,
      region: target.region,
      size: verified.size,
      sha256: verified.sha256,
      serverSideEncryption: config.serverSideEncryption,
      ...(response?.ETag ? { etag: response.ETag } : {}),
      ...(response?.VersionId ? { versionId: response.VersionId } : {}),
      ...(response?.$metadata?.requestId ? { requestId: response.$metadata.requestId } : {}),
    };
  } finally {
    if (body && !body.destroyed) body.destroy();
    if (client && typeof client.destroy === 'function') client.destroy();
    await verified.handle.close().catch(() => {});
  }
}

function s3BackupKey(config, device, backupId) {
  if (typeof device !== 'string' || !DEVICE_PATTERN.test(device)) throw new Error('Router device ID is invalid.');
  if (typeof backupId !== 'string' || !UUID_PATTERN.test(backupId)) throw new Error('Backup ID must be a UUID.');
  return `${validatePrefix(config.prefix)}/${device}/${backupId.toLowerCase()}.backup`;
}

function ensureS3Enabled(config) {
  if (!config.enabled) throw new Error('S3 backup is disabled.');
}

function safeContinuationToken(token) {
  if (token === undefined || token === '') return undefined;
  if (typeof token !== 'string' || token.length > 2048 || /[\u0000-\u001f\u007f]/.test(token)) {
    throw new Error('continuationToken must be a valid S3 continuation token no longer than 2048 characters.');
  }
  return token;
}

async function listEncryptedRouterBackupsInS3({ device, continuationToken, env = process.env, clientFactory = (options) => new S3Client(options) } = {}) {
  const config = getS3BackupConfiguration(env);
  ensureS3Enabled(config);
  if (!config.allowListing) throw new Error('S3 listing is disabled; set MIKROTIK_S3_ALLOW_LISTING=true after granting prefix-scoped s3:ListBucket permission.');
  if (typeof device !== 'string' || !DEVICE_PATTERN.test(device)) throw new Error('Router device ID is invalid.');
  const token = safeContinuationToken(continuationToken);
  const prefix = `${config.prefix}/${device}/`;
  let client;
  try {
    client = clientFactory({ region: config.region, maxAttempts: 1 });
    if (!client || typeof client.send !== 'function') throw new Error('S3 client factory did not return a compatible client.');
    let response;
    try {
      response = await client.send(new ListObjectsV2Command({
        Bucket: config.bucket,
        Prefix: prefix,
        ExpectedBucketOwner: config.expectedBucketOwner,
        MaxKeys: 100,
        ...(token ? { ContinuationToken: token } : {}),
      }));
    } catch (error) {
      throw safeS3Error(error);
    }
    const objects = (Array.isArray(response?.Contents) ? response.Contents : [])
      .filter((item) => typeof item?.Key === 'string'
        && item.Key.startsWith(prefix)
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.backup$/i.test(item.Key.slice(prefix.length)))
      .map((item) => ({
        key: item.Key,
        ...(Number.isSafeInteger(item.Size) ? { size: item.Size } : {}),
        ...(item.LastModified instanceof Date && Number.isFinite(item.LastModified.valueOf()) ? { lastModified: item.LastModified.toISOString() } : {}),
        ...(typeof item.ETag === 'string' ? { etag: item.ETag } : {}),
      }));
    const result = {
      bucket: config.bucket,
      region: config.region,
      prefix,
      maxKeys: 100,
      objects,
      isTruncated: response?.IsTruncated === true,
    };
    if (result.isTruncated && typeof response?.NextContinuationToken === 'string') {
      result.nextContinuationToken = safeContinuationToken(response.NextContinuationToken);
    }
    return result;
  } finally {
    if (client && typeof client.destroy === 'function') client.destroy();
  }
}

function validOpaqueS3Value(value) {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= 1024
    && !/[\u0000-\u001f\u007f]/.test(value)
    && value.trim() !== '';
}

function decodeVersionCursor(token, prefix) {
  if (token === undefined || token === '') return undefined;
  if (typeof token !== 'string' || token.length > 4096 || !/^v1\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error('continuationToken is invalid for S3 object-version listing.');
  }
  try {
    const cursor = JSON.parse(Buffer.from(token.slice(3), 'base64url').toString('utf8'));
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)
      || Object.keys(cursor).some((key) => key !== 'keyMarker' && key !== 'versionIdMarker')
      || typeof cursor.keyMarker !== 'string'
      || cursor.keyMarker.length > 1024
      || /[\u0000-\u001f\u007f]/.test(cursor.keyMarker)
      || !cursor.keyMarker.startsWith(prefix)
      || (cursor.versionIdMarker !== undefined && !validOpaqueS3Value(cursor.versionIdMarker))) {
      throw new Error('invalid cursor');
    }
    return cursor;
  } catch {
    throw new Error('continuationToken is invalid for S3 object-version listing.');
  }
}

function encodeVersionCursor(keyMarker, versionIdMarker, prefix) {
  if (typeof keyMarker !== 'string' || keyMarker.length > 1024
    || /[\u0000-\u001f\u007f]/.test(keyMarker) || !keyMarker.startsWith(prefix)
    || (versionIdMarker !== undefined && !validOpaqueS3Value(versionIdMarker))) {
    throw new Error('S3 returned an invalid object-version pagination marker.');
  }
  const cursor = { keyMarker, ...(versionIdMarker === undefined ? {} : { versionIdMarker }) };
  return `v1.${Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url')}`;
}

function safeVersionS3Error(error, operation) {
  const status = error?.$metadata?.httpStatusCode;
  const result = new Error(status
    ? `S3 object-version ${operation} failed (HTTP ${status}).`
    : `S3 object-version ${operation} failed.`);
  result.code = operation === 'listing' ? 'S3_VERSION_LIST_FAILED' : 'S3_VERSION_DELETE_FAILED';
  return result;
}

/** List only exact UUID backup versions under one derived router prefix. */
async function listEncryptedRouterBackupVersionsInS3({ device, continuationToken, env = process.env, clientFactory = (options) => new S3Client(options) } = {}) {
  const config = getS3BackupConfiguration(env);
  ensureS3Enabled(config);
  if (!config.allowListing) throw new Error('S3 listing is disabled; set MIKROTIK_S3_ALLOW_LISTING=true after granting prefix-scoped s3:ListBucket permission.');
  if (typeof device !== 'string' || !DEVICE_PATTERN.test(device)) throw new Error('Router device ID is invalid.');
  const prefix = `${validatePrefix(config.prefix)}/${device}/`;
  const cursor = decodeVersionCursor(continuationToken, prefix);
  let client;
  try {
    client = clientFactory({ region: config.region, maxAttempts: 1 });
    if (!client || typeof client.send !== 'function') throw new Error('S3 client factory did not return a compatible client.');
    let response;
    try {
      response = await client.send(new ListObjectVersionsCommand({
        Bucket: config.bucket,
        Prefix: prefix,
        ExpectedBucketOwner: config.expectedBucketOwner,
        MaxKeys: 100,
        ...(cursor ? { KeyMarker: cursor.keyMarker } : {}),
        ...(cursor?.versionIdMarker === undefined ? {} : { VersionIdMarker: cursor.versionIdMarker }),
      }));
    } catch (error) {
      throw safeVersionS3Error(error, 'listing');
    }
    const versions = (Array.isArray(response?.Versions) ? response.Versions : [])
      .filter((item) => typeof item?.Key === 'string'
        && item.Key.startsWith(prefix)
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.backup$/i.test(item.Key.slice(prefix.length))
        && validOpaqueS3Value(item.VersionId))
      .map((item) => ({
        key: item.Key,
        versionId: item.VersionId,
        ...(typeof item.IsLatest === 'boolean' ? { isLatest: item.IsLatest } : {}),
        ...(Number.isSafeInteger(item.Size) ? { size: item.Size } : {}),
        ...(item.LastModified instanceof Date && Number.isFinite(item.LastModified.valueOf()) ? { lastModified: item.LastModified.toISOString() } : {}),
        ...(typeof item.ETag === 'string' ? { etag: item.ETag } : {}),
      }));
    const result = {
      bucket: config.bucket,
      region: config.region,
      prefix,
      maxKeys: 100,
      versions,
      isTruncated: response?.IsTruncated === true,
    };
    if (result.isTruncated) {
      const nextToken = encodeVersionCursor(response?.NextKeyMarker, response?.NextVersionIdMarker, prefix);
      if (nextToken === continuationToken) throw new Error('S3 returned a non-advancing object-version pagination marker.');
      result.nextContinuationToken = nextToken;
    }
    return result;
  } finally {
    if (client && typeof client.destroy === 'function') client.destroy();
  }
}

async function deleteEncryptedRouterBackupFromS3({ device, backupId, env = process.env, clientFactory = (options) => new S3Client(options) } = {}) {
  const config = getS3BackupConfiguration(env);
  ensureS3Enabled(config);
  if (!config.allowDelete) throw new Error('S3 deletion is disabled; set MIKROTIK_S3_ALLOW_DELETE=true only after reviewing the effect on bucket versioning and retention.');
  const target = {
    bucket: config.bucket,
    key: s3BackupKey(config, device, backupId),
    region: config.region,
  };
  let client;
  try {
    client = clientFactory({ region: config.region, maxAttempts: 1 });
    if (!client || typeof client.send !== 'function') throw new Error('S3 client factory did not return a compatible client.');
    let response;
    try {
      response = await client.send(new DeleteObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
        ExpectedBucketOwner: config.expectedBucketOwner,
      }));
    } catch (error) {
      throw safeS3Error(error);
    }
    return {
      ...target,
      deleteRequestAccepted: true,
      ...(typeof response?.DeleteMarker === 'boolean' ? { deleteMarker: response.DeleteMarker } : {}),
      ...(typeof response?.VersionId === 'string' ? { versionId: response.VersionId } : {}),
      note: 'This deletes only the current key. In a versioned bucket, previous object versions remain; object lock or retention policies may prevent deletion.',
    };
  } finally {
    if (client && typeof client.destroy === 'function') client.destroy();
  }
}

/** Request deletion of exactly one caller-selected version of a derived backup key. */
async function deleteEncryptedRouterBackupVersionFromS3({ device, backupId, versionId, env = process.env, clientFactory = (options) => new S3Client(options) } = {}) {
  const config = getS3BackupConfiguration(env);
  ensureS3Enabled(config);
  if (!config.allowDelete) throw new Error('S3 deletion is disabled; set MIKROTIK_S3_ALLOW_DELETE=true only after reviewing the effect on bucket versioning and retention.');
  if (!config.allowVersionPurge) throw new Error('S3 object-version deletion is disabled; set MIKROTIK_S3_ALLOW_VERSION_PURGE=true only after review and explicit authorization.');
  if (!validOpaqueS3Value(versionId)) throw new Error('S3 version ID must be a non-empty opaque value no longer than 1024 UTF-8 bytes.');
  const target = {
    bucket: config.bucket,
    key: s3BackupKey(config, device, backupId),
    region: config.region,
  };
  let client;
  try {
    client = clientFactory({ region: config.region, maxAttempts: 1 });
    if (!client || typeof client.send !== 'function') throw new Error('S3 client factory did not return a compatible client.');
    let response;
    try {
      response = await client.send(new DeleteObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
        VersionId: versionId,
        ExpectedBucketOwner: config.expectedBucketOwner,
      }));
    } catch (error) {
      throw safeVersionS3Error(error, 'deletion');
    }
    return {
      ...target,
      versionId,
      versionDeleteRequestAccepted: true,
      ...(response?.$metadata?.requestId ? { requestId: response.$metadata.requestId } : {}),
      note: 'S3 accepted the request; this response does not verify permanent removal. Object Lock or retention policies may prevent deletion.',
    };
  } finally {
    if (client && typeof client.destroy === 'function') client.destroy();
  }
}

export {
  getS3BackupConfiguration,
  getS3BackupTarget,
  uploadEncryptedBackupToS3,
  listEncryptedRouterBackupsInS3,
  listEncryptedRouterBackupVersionsInS3,
  deleteEncryptedRouterBackupFromS3,
  deleteEncryptedRouterBackupVersionFromS3,
};
