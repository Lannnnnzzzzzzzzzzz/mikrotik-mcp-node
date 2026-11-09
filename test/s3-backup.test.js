import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  backupFilePath,
  createPendingBackup,
  markBackupDownloaded,
} from '../src/backup-store.js';
import {
  deleteEncryptedRouterBackupFromS3,
  deleteEncryptedRouterBackupVersionFromS3,
  getS3BackupConfiguration,
  getS3BackupTarget,
  listEncryptedRouterBackupsInS3,
  listEncryptedRouterBackupVersionsInS3,
  uploadEncryptedBackupToS3,
} from '../src/s3-backup.js';

const BASE_ENV = {
  MIKROTIK_S3_ENABLED: 'true',
  MIKROTIK_S3_BUCKET: 'router-archive-example',
  MIKROTIK_S3_REGION: 'us-west-2',
  MIKROTIK_S3_EXPECTED_BUCKET_OWNER: '123456789012',
};
const CONTENT = Buffer.from('RouterOS encrypted backup fixture\0\x01\x02', 'binary');

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function withDownloadedBackup(t, content = CONTENT) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-s3-test-'));
  const previous = process.env.MIKROTIK_DATA_DIR;
  process.env.MIKROTIK_DATA_DIR = path.join(parent, 'private-data');
  t.after(async () => {
    if (previous === undefined) delete process.env.MIKROTIK_DATA_DIR;
    else process.env.MIKROTIK_DATA_DIR = previous;
    await fs.rm(parent, { recursive: true, force: true });
  });

  const pending = await createPendingBackup({
    device: 'edge_a-1',
    host: '192.0.2.40',
    routerFile: 'router-export.backup',
  });
  const file = backupFilePath(pending.id);
  await fs.writeFile(file, content, { mode: 0o600 });
  const record = await markBackupDownloaded(pending.id, { size: content.length, sha256: sha256(content) });
  return { record, file, content };
}

function fakeClient(send) {
  let destroyed = false;
  return {
    client: {
      async send(command) {
        return send(command);
      },
      destroy() {
        destroyed = true;
      },
    },
    isDestroyed: () => destroyed,
  };
}

function streamBody(command) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    command.input.Body.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    command.input.Body.once('error', reject);
    command.input.Body.once('end', () => resolve(Buffer.concat(chunks)));
  });
}

test('S3 backup is disabled by default and enable parsing is exact', () => {
  assert.deepEqual(getS3BackupConfiguration({}), { enabled: false });
  assert.deepEqual(getS3BackupConfiguration({ MIKROTIK_S3_ENABLED: 'false' }), { enabled: false });
  assert.throws(() => getS3BackupConfiguration({ MIKROTIK_S3_ENABLED: 'TRUE' }), /exactly "true" or "false"/);
});

test('strict S3 configuration and immutable target derivation', () => {
  const config = getS3BackupConfiguration(BASE_ENV);
  assert.equal(config.enabled, true);
  assert.equal(config.prefix, 'mikrotik-backups');
  assert.equal(config.serverSideEncryption, 'AES256');
  assert.equal(config.allowVersionPurge, false);
  assert.equal(Object.hasOwn(config, 'credentials'), false);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, AWS_ENDPOINT_URL: 'http://127.0.0.1:9000' }), /Custom S3 endpoints/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_BUCKET: 'Bad_Bucket' }), /valid standard S3 bucket/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_EXPECTED_BUCKET_OWNER: '1234' }), /exactly 12 digits/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_PREFIX: '../unsafe' }), /safe.*prefix/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_SERVER_SIDE_ENCRYPTION: 'none' }), /must be AES256 or aws:kms/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_ALLOW_VERSION_PURGE: 'TRUE' }), /MIKROTIK_S3_ALLOW_VERSION_PURGE must be exactly/);
  assert.throws(() => getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_SERVER_SIDE_ENCRYPTION: 'aws:kms' }), /KMS_KEY_ID is required/);
  const kms = getS3BackupConfiguration({ ...BASE_ENV, MIKROTIK_S3_SERVER_SIDE_ENCRYPTION: 'aws:kms', MIKROTIK_S3_KMS_KEY_ID: 'arn:aws:kms:us-west-2:123456789012:key/example' });
  assert.equal(kms.kmsKeyId, 'arn:aws:kms:us-west-2:123456789012:key/example');

  const record = { id: 'A1B2C3D4-E5F6-4789-8ABC-0123456789AB', device: 'edge_a-1', status: 'downloaded' };
  assert.deepEqual(getS3BackupTarget(record, config), {
    bucket: 'router-archive-example',
    key: `mikrotik-backups/edge_a-1/${record.id.toLowerCase()}.backup`,
    region: 'us-west-2',
  });
  assert.throws(() => getS3BackupTarget({ ...record, status: 'on-router' }, config), /Only a downloaded backup/);
  assert.throws(() => getS3BackupTarget({ ...record, device: '../other' }, config), /invalid device/);
});

test('uploads verified file as a stream with immutable destination and required S3 protections', async (t) => {
  const { record, content } = await withDownloadedBackup(t);
  let commandSeen;
  let clientDestroyed = false;
  let factoryOptions;
  const result = await uploadEncryptedBackupToS3({
    backupId: record.id,
    env: { ...BASE_ENV, MIKROTIK_S3_PREFIX: 'org/site' },
    clientFactory(options) {
      factoryOptions = options;
      const mock = fakeClient(async (command) => {
        commandSeen = command;
        assert.equal(await streamBody(command).then((body) => body.equals(content)), true);
        return { ETag: '"fixture-etag"', VersionId: 'version-1', $metadata: { requestId: 'request-1' } };
      });
      const originalDestroy = mock.client.destroy;
      mock.client.destroy = () => { originalDestroy(); clientDestroyed = true; };
      return mock.client;
    },
  });

  assert.deepEqual(factoryOptions, { region: 'us-west-2', maxAttempts: 1 });
  assert.equal(commandSeen.constructor.name, 'PutObjectCommand');
  assert.equal(commandSeen.input.Bucket, 'router-archive-example');
  assert.equal(commandSeen.input.Key, `org/site/edge_a-1/${record.id}.backup`);
  assert.equal(commandSeen.input.ContentLength, content.length);
  assert.equal(commandSeen.input.ContentType, 'application/octet-stream');
  assert.equal(commandSeen.input.ExpectedBucketOwner, '123456789012');
  assert.equal(commandSeen.input.IfNoneMatch, '*');
  assert.equal(commandSeen.input.ChecksumSHA256, Buffer.from(sha256(content), 'hex').toString('base64'));
  assert.equal(commandSeen.input.ServerSideEncryption, 'AES256');
  assert.equal(Object.hasOwn(commandSeen.input, 'SSEKMSKeyId'), false);
  assert.equal(Object.hasOwn(commandSeen.input, 'ACL'), false);
  assert.equal(clientDestroyed, true);
  assert.deepEqual(result, {
    bucket: 'router-archive-example',
    key: `org/site/edge_a-1/${record.id}.backup`,
    region: 'us-west-2',
    size: content.length,
    sha256: sha256(content),
    serverSideEncryption: 'AES256',
    etag: '"fixture-etag"',
    versionId: 'version-1',
    requestId: 'request-1',
  });
  assert.equal(Object.values(result).includes(content.toString()), false);
});

test('KMS configuration becomes required encryption parameters on PutObject', async (t) => {
  const { record } = await withDownloadedBackup(t);
  const kmsKeyId = 'arn:aws:kms:us-west-2:123456789012:key/example';
  let input;
  await uploadEncryptedBackupToS3({
    backupId: record.id,
    env: { ...BASE_ENV, MIKROTIK_S3_SERVER_SIDE_ENCRYPTION: 'aws:kms', MIKROTIK_S3_KMS_KEY_ID: kmsKeyId },
    clientFactory: () => ({ async send(command) { input = command.input; for await (const _chunk of input.Body) { /* consume upload stream */ } return {}; }, destroy() {} }),
  });
  assert.equal(input.ServerSideEncryption, 'aws:kms');
  assert.equal(input.SSEKMSKeyId, kmsKeyId);
});

test('rejects manifest-ineligible, tampered, symlinked, and size-mismatched backups before client creation', async (t) => {
  const { record, file, content } = await withDownloadedBackup(t);
  let factoryCalls = 0;
  const clientFactory = () => { factoryCalls += 1; return fakeClient(async () => ({})).client; };
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: { MIKROTIK_S3_ENABLED: 'false' }, clientFactory }), /disabled/);
  assert.equal(factoryCalls, 0);

  await fs.writeFile(file, Buffer.from('tampered data'), { mode: 0o600 });
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory }), /size does not match its manifest/);
  assert.equal(factoryCalls, 0);

  await fs.writeFile(file, content, { mode: 0o600 });
  await fs.chmod(file, 0o640);
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory }), /private permissions/);
  await fs.chmod(file, 0o600);
  await fs.unlink(file);
  const outside = path.join(path.dirname(file), 'outside.backup');
  await fs.writeFile(outside, content, { mode: 0o600 });
  await fs.symlink(outside, file);
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory }), /symlink|too many symbolic links/i);
  assert.equal(factoryCalls, 0);
});

test('rejects a same-size checksum mismatch and files larger than 100 MiB', async (t) => {
  const { record, file, content } = await withDownloadedBackup(t);
  await fs.writeFile(file, Buffer.alloc(content.length, 0x42), { mode: 0o600 });
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory: () => { throw new Error('must not create'); } }), /SHA-256 does not match/);

  await fs.writeFile(file, Buffer.alloc(100 * 1024 * 1024 + 1), { mode: 0o600 });
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory: () => { throw new Error('must not create'); } }), /between 1 byte and 100 MiB/);
});

test('surfaces existing-key and ambiguous SDK errors safely without retrying', async (t) => {
  const { record } = await withDownloadedBackup(t);
  let calls = 0;
  const existingClient = fakeClient(async () => {
    calls += 1;
    const error = new Error('sensitive internal details');
    error.name = 'PreconditionFailed';
    error.$metadata = { httpStatusCode: 412 };
    throw error;
  });
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory: () => existingClient.client }), (error) => {
    assert.equal(error.code, 'S3_OBJECT_EXISTS');
    assert.match(error.message, /refusing to overwrite/);
    assert.doesNotMatch(error.message, /sensitive/);
    return true;
  });
  assert.equal(calls, 1);
  assert.equal(existingClient.isDestroyed(), true);

  const ambiguousClient = fakeClient(async () => {
    const error = new Error('network reset');
    error.code = 'ECONNRESET';
    throw error;
  });
  await assert.rejects(uploadEncryptedBackupToS3({ backupId: record.id, env: BASE_ENV, clientFactory: () => ambiguousClient.client }), (error) => {
    assert.equal(error.code, 'S3_UPLOAD_OUTCOME_UNKNOWN');
    assert.match(error.message, /ambiguous/);
    return true;
  });
  assert.equal(ambiguousClient.isDestroyed(), true);
});

test('S3 listing is opt-in, device-prefix scoped, paged, and filters non-backup objects', async () => {
  const backupId = 'a1b2c3d4-e5f6-4789-8abc-0123456789ab';
  let commandSeen;
  let destroyed = false;
  const result = await listEncryptedRouterBackupsInS3({
    device: 'edge_a-1',
    continuationToken: 'opaque-token-1',
    env: { ...BASE_ENV, MIKROTIK_S3_PREFIX: 'org/archive', MIKROTIK_S3_ALLOW_LISTING: 'true' },
    clientFactory(options) {
      assert.deepEqual(options, { region: 'us-west-2', maxAttempts: 1 });
      return {
        async send(command) {
          commandSeen = command;
          return {
            Contents: [
              { Key: `org/archive/edge_a-1/${backupId}.backup`, Size: 321, LastModified: new Date('2026-11-08T00:00:00Z'), ETag: '"tag"' },
              { Key: 'org/archive/edge_a-1/notes.txt', Size: 44 },
              { Key: `org/archive/other-router/${backupId}.backup`, Size: 321 },
            ],
            IsTruncated: true,
            NextContinuationToken: 'opaque-token-2',
          };
        },
        destroy() { destroyed = true; },
      };
    },
  });
  assert.equal(commandSeen.constructor.name, 'ListObjectsV2Command');
  assert.deepEqual(commandSeen.input, {
    Bucket: 'router-archive-example',
    Prefix: 'org/archive/edge_a-1/',
    ExpectedBucketOwner: '123456789012',
    MaxKeys: 100,
    ContinuationToken: 'opaque-token-1',
  });
  assert.equal(result.objects.length, 1);
  assert.deepEqual(result.objects[0], {
    key: `org/archive/edge_a-1/${backupId}.backup`,
    size: 321,
    lastModified: '2026-11-08T00:00:00.000Z',
    etag: '"tag"',
  });
  assert.equal(result.isTruncated, true);
  assert.equal(result.nextContinuationToken, 'opaque-token-2');
  assert.equal(destroyed, true);
  let calls = 0;
  await assert.rejects(listEncryptedRouterBackupsInS3({
    device: 'edge_a-1', env: BASE_ENV,
    clientFactory: () => { calls += 1; throw new Error('must not create'); },
  }), /S3 listing is disabled/);
  assert.equal(calls, 0);
});

test('S3 deletion is doubly opt-in at the feature layer and affects only a derived key', async () => {
  const backupId = 'A1B2C3D4-E5F6-4789-8ABC-0123456789AB';
  let commandSeen;
  let destroyed = false;
  const result = await deleteEncryptedRouterBackupFromS3({
    device: 'edge_a-1',
    backupId,
    env: { ...BASE_ENV, MIKROTIK_S3_PREFIX: 'org/archive', MIKROTIK_S3_ALLOW_DELETE: 'true' },
    clientFactory(options) {
      assert.deepEqual(options, { region: 'us-west-2', maxAttempts: 1 });
      return {
        async send(command) {
          commandSeen = command;
          return { DeleteMarker: true, VersionId: 'delete-marker-version' };
        },
        destroy() { destroyed = true; },
      };
    },
  });
  assert.equal(commandSeen.constructor.name, 'DeleteObjectCommand');
  assert.deepEqual(commandSeen.input, {
    Bucket: 'router-archive-example',
    Key: `org/archive/edge_a-1/${backupId.toLowerCase()}.backup`,
    ExpectedBucketOwner: '123456789012',
  });
  assert.equal(result.deleteRequestAccepted, true);
  assert.equal(result.deleteMarker, true);
  assert.equal(result.versionId, 'delete-marker-version');
  assert.match(result.note, /previous object versions remain/);
  assert.equal(destroyed, true);

  let calls = 0;
  await assert.rejects(deleteEncryptedRouterBackupFromS3({
    device: 'edge_a-1', backupId, env: BASE_ENV,
    clientFactory: () => { calls += 1; throw new Error('must not create'); },
  }), /S3 deletion is disabled/);
  assert.equal(calls, 0);
});

test('object-version listing is scoped, paginates by the AWS marker pair, and emits only exact backup keys', async () => {
  const backupId = 'a1b2c3d4-e5f6-4789-8abc-0123456789ab';
  const env = { ...BASE_ENV, MIKROTIK_S3_PREFIX: 'org/archive', MIKROTIK_S3_ALLOW_LISTING: 'true' };
  const firstKey = `org/archive/edge_a-1/${backupId}.backup`;
  const nextKey = 'org/archive/edge_a-1/notes.txt';
  const cursorTokenHolder = {};
  let page = 0;
  const first = await listEncryptedRouterBackupVersionsInS3({
    device: 'edge_a-1', env,
    clientFactory: () => ({
      async send(command) {
        page += 1;
        assert.equal(command.constructor.name, 'ListObjectVersionsCommand');
        assert.deepEqual(command.input, {
          Bucket: 'router-archive-example', Prefix: 'org/archive/edge_a-1/',
          ExpectedBucketOwner: '123456789012', MaxKeys: 100,
        });
        return {
          Versions: [
            { Key: firstKey, VersionId: 'ver-old', IsLatest: false, Size: 100, LastModified: new Date('2026-11-08T00:00:00Z') },
            { Key: firstKey, VersionId: 'ver-current', IsLatest: true, Size: 110 },
            { Key: 'org/archive/edge_a-1/notes.txt', VersionId: 'ignore-file', Size: 1 },
            { Key: `org/archive/edge_a-1/${backupId}.backup.extra`, VersionId: 'ignore-suffix' },
            { Key: `org/archive/other-router/${backupId}.backup`, VersionId: 'ignore-router' },
          ],
          DeleteMarkers: [{ Key: firstKey, VersionId: 'do-not-list-marker' }],
          IsTruncated: true,
          NextKeyMarker: nextKey,
          NextVersionIdMarker: 'marker-1',
        };
      },
      destroy() {},
    }),
  });
  assert.equal(page, 1);
  assert.equal(first.versions.length, 2);
  assert.deepEqual(first.versions[0], {
    key: firstKey, versionId: 'ver-old', isLatest: false, size: 100,
    lastModified: '2026-11-08T00:00:00.000Z',
  });
  assert.deepEqual(first.versions[1], { key: firstKey, versionId: 'ver-current', isLatest: true, size: 110 });
  assert.equal(first.isTruncated, true);
  cursorTokenHolder.value = first.nextContinuationToken;
  assert.match(cursorTokenHolder.value, /^v1\./);

  const second = await listEncryptedRouterBackupVersionsInS3({
    device: 'edge_a-1', continuationToken: cursorTokenHolder.value, env,
    clientFactory: () => ({
      async send(command) {
        page += 1;
        assert.deepEqual(command.input, {
          Bucket: 'router-archive-example', Prefix: 'org/archive/edge_a-1/',
          ExpectedBucketOwner: '123456789012', MaxKeys: 100,
          KeyMarker: nextKey, VersionIdMarker: 'marker-1',
        });
        return {
          Versions: [{ Key: firstKey, VersionId: 'ver-later', IsLatest: true }],
          IsTruncated: false,
        };
      },
      destroy() {},
    }),
  });
  assert.equal(page, 2);
  assert.equal(second.versions[0].versionId, 'ver-later');
  assert.equal(second.isTruncated, false);

  let factoryCalls = 0;
  await assert.rejects(listEncryptedRouterBackupVersionsInS3({
    device: 'edge_a-1', continuationToken: `v1.${Buffer.from(JSON.stringify({ keyMarker: 'outside/prefix' })).toString('base64url')}`,
    env, clientFactory: () => { factoryCalls += 1; throw new Error('must not create'); },
  }), /continuationToken is invalid/);
  await assert.rejects(listEncryptedRouterBackupVersionsInS3({
    device: 'edge_a-1', env: BASE_ENV,
    clientFactory: () => { factoryCalls += 1; throw new Error('must not create'); },
  }), /S3 listing is disabled/);
  assert.equal(factoryCalls, 0);
});

test('single-version deletion requires both opt-ins, validates input, and targets only the derived key and selected version', async () => {
  const backupId = 'A1B2C3D4-E5F6-4789-8ABC-0123456789AB';
  const versionId = 'selected-version/opaque+id';
  const env = {
    ...BASE_ENV, MIKROTIK_S3_PREFIX: 'org/archive',
    MIKROTIK_S3_ALLOW_DELETE: 'true', MIKROTIK_S3_ALLOW_VERSION_PURGE: 'true',
  };
  let commandSeen;
  let destroyed = false;
  const result = await deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId, versionId, env,
    clientFactory(options) {
      assert.deepEqual(options, { region: 'us-west-2', maxAttempts: 1 });
      return {
        async send(command) {
          commandSeen = command;
          return { $metadata: { requestId: 'request-version-delete' } };
        },
        destroy() { destroyed = true; },
      };
    },
  });
  assert.equal(commandSeen.constructor.name, 'DeleteObjectCommand');
  assert.deepEqual(commandSeen.input, {
    Bucket: 'router-archive-example',
    Key: `org/archive/edge_a-1/${backupId.toLowerCase()}.backup`,
    VersionId: versionId,
    ExpectedBucketOwner: '123456789012',
  });
  assert.deepEqual(result, {
    bucket: 'router-archive-example',
    key: `org/archive/edge_a-1/${backupId.toLowerCase()}.backup`,
    region: 'us-west-2',
    versionId,
    versionDeleteRequestAccepted: true,
    requestId: 'request-version-delete',
    note: 'S3 accepted the request; this response does not verify permanent removal. Object Lock or retention policies may prevent deletion.',
  });
  assert.match(result.note, /does not verify permanent removal/);
  assert.equal(destroyed, true);

  let calls = 0;
  const noClient = () => { calls += 1; throw new Error('must not create'); };
  await assert.rejects(deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId, versionId, env: BASE_ENV, clientFactory: noClient,
  }), /S3 deletion is disabled/);
  await assert.rejects(deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId, versionId,
    env: { ...BASE_ENV, MIKROTIK_S3_ALLOW_DELETE: 'true' }, clientFactory: noClient,
  }), /MIKROTIK_S3_ALLOW_VERSION_PURGE=true/);
  await assert.rejects(deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId, versionId: ' \n', env, clientFactory: noClient,
  }), /version ID must be/);
  await assert.rejects(deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId: '../other', versionId, env, clientFactory: noClient,
  }), /Backup ID must be a UUID/);
  assert.equal(calls, 0);
});

test('version operations sanitize AWS failures and preserve request-accepted semantics', async () => {
  const error = new Error('credential=secret internal body');
  error.$metadata = { httpStatusCode: 403 };
  await assert.rejects(listEncryptedRouterBackupVersionsInS3({
    device: 'edge_a-1', env: { ...BASE_ENV, MIKROTIK_S3_ALLOW_LISTING: 'true' },
    clientFactory: () => ({ async send() { throw error; }, destroy() {} }),
  }), (caught) => {
    assert.equal(caught.code, 'S3_VERSION_LIST_FAILED');
    assert.match(caught.message, /HTTP 403/);
    assert.doesNotMatch(caught.message, /credential|secret|internal/);
    return true;
  });
  await assert.rejects(deleteEncryptedRouterBackupVersionFromS3({
    device: 'edge_a-1', backupId: 'a1b2c3d4-e5f6-4789-8abc-0123456789ab', versionId: 'version-1',
    env: { ...BASE_ENV, MIKROTIK_S3_ALLOW_DELETE: 'true', MIKROTIK_S3_ALLOW_VERSION_PURGE: 'true' },
    clientFactory: () => ({ async send() { throw error; }, destroy() {} }),
  }), (caught) => {
    assert.equal(caught.code, 'S3_VERSION_DELETE_FAILED');
    assert.match(caught.message, /HTTP 403/);
    assert.doesNotMatch(caught.message, /credential|secret|internal/);
    return true;
  });
});
