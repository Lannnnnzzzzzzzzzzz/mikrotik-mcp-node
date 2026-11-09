import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { Writable } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  downloadRouterBackup,
  fingerprintHostKey,
  normalizeSha256Fingerprint,
  uploadRouterBackup,
  validateRouterBackupFilename,
} from '../src/ssh-sftp.js';

const hostKey = Buffer.from('simulated-router-ssh-public-host-key');
const fingerprint = fingerprintHostKey(hostKey);

function fakeClientClass({ data = Buffer.from('encrypted router backup'), stats = {}, key = hostKey } = {}) {
  const instances = [];
  class FakeClient extends EventEmitter {
    constructor() {
      super();
      this.ended = false;
      instances.push(this);
    }
    connect(options) {
      this.options = options;
      queueMicrotask(() => {
        try {
          if (!options.hostVerifier(key)) throw new Error('SSH host-key verification failed.');
          this.emit('ready');
        } catch (error) {
          this.emit('error', error);
        }
      });
    }
    sftp(callback) {
      this.sftpApi = {
        stat(remotePath, done) {
          this.lastStatPath = remotePath;
          done(null, { size: data.length, mode: 0o100600, ...stats });
        },
        createReadStream(remotePath) {
          this.lastReadPath = remotePath;
          return Readable.from([data]);
        },
      };
      callback(null, this.sftpApi);
    }
    end() { this.ended = true; }
  }
  FakeClient.instances = instances;
  return FakeClient;
}

function router(overrides = {}) {
  return {
    host: 'router.example', sshPort: 22, sshUsername: 'ssh-user', sshPassword: 'ssh-password',
    sshHostKeyFingerprint: fingerprint, timeoutMs: 8000, ...overrides,
  };
}

async function makeVault(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-sftp-test-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

test('fingerprints use OpenSSH SHA256 format and canonicalize optional padding', () => {
  assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
  assert.equal(normalizeSha256Fingerprint(`${fingerprint}=`), fingerprint);
  assert.equal(normalizeSha256Fingerprint(fingerprint), fingerprint);
  assert.throws(() => normalizeSha256Fingerprint('md5:abc'), /OpenSSH SHA256/);
  assert.throws(() => normalizeSha256Fingerprint(undefined), /required/);
  assert.equal(fingerprintHostKey(hostKey), fingerprint);
  assert.throws(() => fingerprintHostKey('not-a-buffer'), /Buffer/);
});

test('RouterOS backup names reject path traversal and accept only .backup basenames', () => {
  assert.equal(validateRouterBackupFilename('edge-1-2026.backup'), 'edge-1-2026.backup');
  for (const name of ['../secret.backup', '/tmp/file.backup', 'dir/file.backup', 'file.txt', '.hidden.backup', '']) {
    assert.throws(() => validateRouterBackupFilename(name), /safe \.backup basename/);
  }
});

test('downloads a pinned-host-key backup to a private UUID file and returns only size and digest', async (t) => {
  const directory = await makeVault(t);
  const data = Buffer.from('encrypted fixture bytes');
  const ClientClass = fakeClientClass({ data });
  const id = crypto.randomUUID();
  const destination = path.join(directory, `${id}.backup`);
  const result = await downloadRouterBackup(router(), 'edge-1.backup', destination, { ClientClass, maxBytes: 1024 });

  assert.equal(result.filename, 'edge-1.backup');
  assert.equal(result.size, data.length);
  assert.equal(result.sha256, crypto.createHash('sha256').update(data).digest('hex'));
  assert.equal(await fs.readFile(destination, 'utf8'), 'encrypted fixture bytes');
  const stat = await fs.stat(destination);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(ClientClass.instances[0].options.host, 'router.example');
  assert.equal(ClientClass.instances[0].options.username, 'ssh-user');
  assert.equal(ClientClass.instances[0].options.hostHash, undefined);
  assert.equal(ClientClass.instances[0].ended, true);
  assert.equal(ClientClass.instances[0].sftpApi.lastStatPath, '/edge-1.backup');
  assert.equal(ClientClass.instances[0].sftpApi.lastReadPath, '/edge-1.backup');
});

test('rejects missing host-key pins and a mismatched router key without leaving a file', async (t) => {
  const directory = await makeVault(t);
  const destination = path.join(directory, `${crypto.randomUUID()}.backup`);
  const ClientClass = fakeClientClass({ key: Buffer.from('untrusted-key') });
  await assert.rejects(downloadRouterBackup(router({ sshHostKeyFingerprint: undefined }), 'edge.backup', destination, { ClientClass }), /fingerprint is required/);
  await assert.rejects(downloadRouterBackup(router(), 'edge.backup', destination, { ClientClass }), /host-key verification failed/);
  await assert.rejects(fs.lstat(destination), { code: 'ENOENT' });
  assert.equal(ClientClass.instances[0].ended, true);
});

test('enforces transfer size, regular-file checks, exact transfer size and cleanup on failure', async (t) => {
  const directory = await makeVault(t);
  const largeData = Buffer.alloc(64, 1);
  const tooLargeDestination = path.join(directory, `${crypto.randomUUID()}.backup`);
  await assert.rejects(downloadRouterBackup(router(), 'edge.backup', tooLargeDestination, {
    ClientClass: fakeClientClass({ data: largeData }), maxBytes: 32,
  }), /exceeds the configured/);
  await assert.rejects(fs.lstat(tooLargeDestination), { code: 'ENOENT' });

  const nonRegularDestination = path.join(directory, `${crypto.randomUUID()}.backup`);
  await assert.rejects(downloadRouterBackup(router(), 'edge.backup', nonRegularDestination, {
    ClientClass: fakeClientClass({ stats: { mode: 0o040755 } }),
  }), /not a regular file/);
  await assert.rejects(fs.lstat(nonRegularDestination), { code: 'ENOENT' });

  const wrongSizeDestination = path.join(directory, `${crypto.randomUUID()}.backup`);
  await assert.rejects(downloadRouterBackup(router(), 'edge.backup', wrongSizeDestination, {
    ClientClass: fakeClientClass({ data: Buffer.from('short'), stats: { size: 50 } }),
  }), /size mismatch/);
  await assert.rejects(fs.lstat(wrongSizeDestination), { code: 'ENOENT' });
});

test('requires a private local directory and a UUID-derived vault destination', async (t) => {
  const directory = await makeVault(t);
  const badDestinations = [path.join(directory, 'arbitrary.backup'), path.join(directory, '../escape.backup')];
  for (const destination of badDestinations) {
    await assert.rejects(downloadRouterBackup(router(), 'edge.backup', destination, { ClientClass: fakeClientClass() }), /UUID-named/);
  }

  const broadDirectory = path.join(directory, 'public');
  await fs.mkdir(broadDirectory, { mode: 0o755 });
  await fs.chmod(broadDirectory, 0o755);
  await assert.rejects(downloadRouterBackup(router(), 'edge.backup', path.join(broadDirectory, `${crypto.randomUUID()}.backup`), { ClientClass: fakeClientClass() }), /private, non-symlink/);
});

function fakeUploadClientClass({ key = hostKey, existingFiles = new Map() } = {}) {
  const instances = [];
  class FakeClient extends EventEmitter {
    constructor() { super(); this.ended = false; this.files = new Map(existingFiles); instances.push(this); }
    connect(options) {
      this.options = options;
      queueMicrotask(() => {
        try {
          if (!options.hostVerifier(key)) throw new Error('SSH host-key verification failed.');
          this.emit('ready');
        } catch (error) { this.emit('error', error); }
      });
    }
    sftp(callback) {
      this.sftpApi = {
        stat: (remotePath, done) => {
          const data = this.files.get(remotePath);
          if (!data) { const error = new Error('No such file'); error.code = 2; done(error); return; }
          done(null, { size: data.length, mode: 0o100600 });
        },
        createWriteStream: (remotePath, options) => {
          const owner = this;
          this.writeOptions = options;
          const chunks = [];
          return new Writable({
            write(chunk, encoding, callbackDone) { chunks.push(Buffer.from(chunk)); callbackDone(); },
            final(callbackDone) { owner.files.set(remotePath, Buffer.concat(chunks)); callbackDone(); },
          });
        },
        rename: (source, destination, done) => {
          if (this.files.has(destination)) { const error = new Error('File exists'); error.code = 11; done(error); return; }
          if (!this.files.has(source)) { const error = new Error('No such file'); error.code = 2; done(error); return; }
          this.files.set(destination, this.files.get(source));
          this.files.delete(source);
          done();
        },
        unlink: (remotePath, done) => { this.files.delete(remotePath); done(); },
      };
      callback(null, this.sftpApi);
    }
    end() { this.ended = true; }
  }
  FakeClient.instances = instances;
  return FakeClient;
}

async function makeLocalBackup(t, data) {
  const directory = await makeVault(t);
  const id = crypto.randomUUID();
  const localPath = path.join(directory, `${id}.backup`);
  await fs.writeFile(localPath, data, { mode: 0o600, flag: 'wx' });
  await fs.chmod(localPath, 0o600);
  return { localPath, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') };
}

test('uploads one local backup to a unique remote .backup path after pinned host-key and SHA-256 verification', async (t) => {
  const data = Buffer.from('encrypted bytes for restore');
  const local = await makeLocalBackup(t, data);
  const ClientClass = fakeUploadClientClass();
  const result = await uploadRouterBackup(router(), local.localPath, 'restore-unique.backup', {
    ClientClass, expectedSize: local.size, expectedSha256: local.sha256,
  });
  assert.deepEqual(result, { filename: 'restore-unique.backup', size: data.length, sha256: local.sha256 });
  assert.deepEqual(ClientClass.instances[0].files.get('/restore-unique.backup'), data);
  assert.equal(ClientClass.instances[0].options.host, 'router.example');
  assert.equal(ClientClass.instances[0].ended, true);
  assert.equal(ClientClass.instances[0].writeOptions.flags, 'wx');
  assert.equal([...ClientClass.instances[0].files.keys()].some((name) => name.includes('.partial-')), false);
});

test('refuses existing remote filenames and local checksum mismatches without leaving partial uploads', async (t) => {
  const data = Buffer.from('encrypted bytes');
  const local = await makeLocalBackup(t, data);
  const existing = new Map([['/already.backup', Buffer.from('preserve this')]]);
  const existingClient = fakeUploadClientClass({ existingFiles: existing });
  await assert.rejects(uploadRouterBackup(router(), local.localPath, 'already.backup', {
    ClientClass: existingClient, expectedSize: local.size, expectedSha256: local.sha256,
  }), /already exists/);
  assert.deepEqual(existingClient.instances[0].files.get('/already.backup'), Buffer.from('preserve this'));

  const mismatchClient = fakeUploadClientClass();
  await assert.rejects(uploadRouterBackup(router(), local.localPath, 'restore-bad-hash.backup', {
    ClientClass: mismatchClient, expectedSize: local.size, expectedSha256: '0'.repeat(64),
  }), /did not match the recorded size and SHA-256/);
  assert.equal(mismatchClient.instances[0].files.size, 0);
});

test('rejects unpinned remote hosts and non-vault local paths during upload', async (t) => {
  const data = Buffer.from('encrypted bytes');
  const local = await makeLocalBackup(t, data);
  const ClientClass = fakeUploadClientClass({ key: Buffer.from('wrong host key') });
  await assert.rejects(uploadRouterBackup(router(), local.localPath, 'restore-pinned.backup', {
    ClientClass, expectedSize: local.size, expectedSha256: local.sha256,
  }), /host-key verification failed/);
  await assert.rejects(uploadRouterBackup(router(), '/tmp/not-a-vault.backup', 'restore-pinned.backup', {
    expectedSize: local.size, expectedSha256: local.sha256,
  }), /UUID-named/);
});
