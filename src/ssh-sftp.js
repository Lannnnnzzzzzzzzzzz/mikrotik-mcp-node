import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { constants as fsConstants, createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Client } from 'ssh2';

const DEFAULT_MAX_BYTES = 100 * 1024 * 1024;
const BACKUP_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.backup$/;
const UUID_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.backup$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function normalizeSha256Fingerprint(value) {
  if (typeof value !== 'string') throw new Error('An SSH SHA-256 host-key fingerprint is required.');
  const match = /^SHA256:([A-Za-z0-9+/]{43}=?)$/.exec(value.trim());
  if (!match) throw new Error('SSH host-key fingerprint must use OpenSSH SHA256:<base64> format.');
  return `SHA256:${match[1].replace(/=+$/, '')}`;
}

export function fingerprintHostKey(key) {
  if (!Buffer.isBuffer(key)) throw new TypeError('SSH host key must be provided as a Buffer.');
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
}

export function validateRouterBackupFilename(filename) {
  if (typeof filename !== 'string' || !BACKUP_FILENAME.test(filename) || filename === '.' || filename === '..') {
    throw new Error('Router backup filename must be a single safe .backup basename.');
  }
  return filename;
}

function validateSftpConfig(router, ClientClass) {
  if (!router || typeof router.host !== 'string' || router.host.length === 0) throw new Error('Router SSH host is missing.');
  if (!Number.isInteger(router.sshPort) || router.sshPort < 1 || router.sshPort > 65535) throw new Error('A valid router SSH port is required.');
  if (typeof router.sshUsername !== 'string' || router.sshUsername.length === 0 || typeof router.sshPassword !== 'string' || router.sshPassword.length === 0) {
    throw new Error('SSH username and password must be configured separately for SFTP.');
  }
  if (typeof ClientClass !== 'function') throw new TypeError('SSH Client constructor is invalid.');
  return normalizeSha256Fingerprint(router.sshHostKeyFingerprint);
}

export function assertSftpConfiguration(router) {
  validateSftpConfig(router, Client);
  return true;
}

function waitForReady(client, config) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      client.removeListener('ready', onReady);
      client.removeListener('error', onError);
      client.removeListener('close', onClose);
    };
    const onReady = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onError = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onClose = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error('SSH connection closed before authentication completed.'));
    };
    client.once('ready', onReady);
    client.once('error', onError);
    client.once('close', onClose);
    try {
      client.connect(config);
    } catch (error) {
      onError(error);
    }
  });
}

function getSftp(client) {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => error ? reject(error) : resolve(sftp));
  });
}

function getRemoteStats(sftp, remotePath) {
  return new Promise((resolve, reject) => {
    sftp.stat(remotePath, (error, stats) => error ? reject(error) : resolve(stats));
  });
}

async function withSftp(router, { ClientClass = Client } = {}, operation) {
  const expected = validateSftpConfig(router, ClientClass);
  const client = new ClientClass();
  try {
    await waitForReady(client, {
      host: router.host,
      port: router.sshPort,
      username: router.sshUsername,
      password: router.sshPassword,
      readyTimeout: Number.isInteger(router.timeoutMs) ? Math.min(Math.max(router.timeoutMs, 1000), 120000) : 20000,
      keepaliveInterval: 5000,
      keepaliveCountMax: 2,
      hostVerifier: (key) => {
        try {
          const actual = fingerprintHostKey(key);
          const actualBytes = Buffer.from(actual);
          const expectedBytes = Buffer.from(expected);
          return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
        } catch {
          return false;
        }
      },
    });
    const sftp = await getSftp(client);
    return await operation(sftp);
  } finally {
    try { client.end(); } catch { /* best-effort socket close */ }
  }
}

function validateDestination(destination) {
  if (typeof destination !== 'string' || !UUID_FILENAME.test(path.basename(destination))) {
    throw new Error('Local SFTP destination must be a UUID-named .backup vault file.');
  }
  return path.resolve(destination);
}

function renameRemote(sftp, source, destination) {
  return new Promise((resolve, reject) => sftp.rename(source, destination, (error) => error ? reject(error) : resolve()));
}

function unlinkRemote(sftp, remotePath) {
  return new Promise((resolve, reject) => sftp.unlink(remotePath, (error) => error ? reject(error) : resolve()));
}

function remotePathDoesNotExist(error) {
  return error?.code === 'ENOENT' || error?.code === 2 || error?.code === 'SSH_FX_NO_SUCH_FILE'
    || /no such file|does not exist/i.test(String(error?.message ?? ''));
}

/** Upload one verified local encrypted backup without overwriting an existing router file. */
export async function uploadRouterBackup(router, source, filename, {
  ClientClass = Client,
  expectedSize,
  expectedSha256,
  maxBytes = DEFAULT_MAX_BYTES,
} = {}) {
  const safeFilename = validateRouterBackupFilename(filename);
  const localPath = validateDestination(source);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024 * 1024) {
    throw new RangeError('maxBytes must be a safe integer from 1 byte to 1 GiB.');
  }
  if (!Number.isSafeInteger(expectedSize) || expectedSize <= 0 || expectedSize > maxBytes) {
    throw new RangeError('expectedSize must be a positive safe integer within the configured upload limit.');
  }
  if (typeof expectedSha256 !== 'string' || !SHA256_PATTERN.test(expectedSha256)) {
    throw new TypeError('expectedSha256 must be a lowercase SHA-256 hexadecimal digest.');
  }
  let fileHandle;
  try {
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    fileHandle = await fs.open(localPath, fsConstants.O_RDONLY | noFollow);
    const localStats = await fileHandle.stat();
    if (!localStats.isFile() || localStats.size !== expectedSize || (localStats.mode & 0o077) !== 0 || (localStats.mode & 0o100) !== 0) {
      throw new Error('Local backup must be a private regular file matching the recorded size.');
    }
    return await withSftp(router, { ClientClass }, async (sftp) => {
      const finalPath = `/${safeFilename}`;
      const temporaryPath = `/${safeFilename}.partial-${crypto.randomUUID()}`;
      let temporaryCreated = false;
      let finalCreated = false;
      try {
        try {
          await getRemoteStats(sftp, finalPath);
          throw new Error('A router file already exists at the requested restore-upload path; no file was overwritten.');
        } catch (error) {
          if (error.message?.includes('already exists')) throw error;
          if (!remotePathDoesNotExist(error)) throw new Error(`Unable to establish that the router upload path is unused: ${error.message}`);
        }
        const output = sftp.createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 });
        temporaryCreated = true;
        const hash = createHash('sha256');
        let transferred = 0;
        const limiter = new Transform({
          transform(chunk, encoding, callback) {
            transferred += chunk.length;
            if (transferred > maxBytes || transferred > expectedSize) {
              callback(new Error('SFTP upload exceeded the recorded file size or configured transfer limit.'));
              return;
            }
            hash.update(chunk);
            callback(null, chunk);
          },
        });
        const input = fileHandle.createReadStream({ start: 0, autoClose: false });
        await pipeline(input, limiter, output);
        const actualSha256 = hash.digest('hex');
        if (transferred !== expectedSize || actualSha256 !== expectedSha256) {
          throw new Error('Local backup bytes did not match the recorded size and SHA-256; no restore command should be issued.');
        }
        const stagedStats = await getRemoteStats(sftp, temporaryPath);
        if (stagedStats.size !== expectedSize || (Number.isInteger(stagedStats.mode) && (stagedStats.mode & 0o170000) !== 0 && (stagedStats.mode & 0o170000) !== 0o100000)) {
          throw new Error('Uploaded router-side temporary file failed size or regular-file verification.');
        }
        await renameRemote(sftp, temporaryPath, finalPath);
        temporaryCreated = false;
        finalCreated = true;
        const finalStats = await getRemoteStats(sftp, finalPath);
        if (finalStats.size !== expectedSize || (Number.isInteger(finalStats.mode) && (finalStats.mode & 0o170000) !== 0 && (finalStats.mode & 0o170000) !== 0o100000)) {
          throw new Error('Router-side backup failed final size or regular-file verification.');
        }
        return { filename: safeFilename, size: expectedSize, sha256: actualSha256 };
      } catch (error) {
        if (temporaryCreated) await unlinkRemote(sftp, temporaryPath).catch(() => {});
        if (finalCreated) await unlinkRemote(sftp, finalPath).catch(() => {});
        throw error;
      }
    });
  } finally {
    if (fileHandle) await fileHandle.close().catch(() => {});
  }
}

/** Stream one RouterOS .backup file into a caller-owned private UUID path. */
export async function downloadRouterBackup(router, filename, destination, {
  ClientClass = Client,
  maxBytes = DEFAULT_MAX_BYTES,
} = {}) {
  const safeFilename = validateRouterBackupFilename(filename);
  const localPath = validateDestination(destination);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024 * 1024) {
    throw new RangeError('maxBytes must be a safe integer from 1 byte to 1 GiB.');
  }
  const directory = path.dirname(localPath);
  const directoryStat = await fs.lstat(directory);
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory() || (directoryStat.mode & 0o077) !== 0) {
    throw new Error('Local SFTP destination directory must be a private, non-symlink directory.');
  }

  let createdDestination = false;
  let fileHandle;
  try {
    const metadata = await withSftp(router, { ClientClass }, async (sftp) => {
      const remotePath = `/${safeFilename}`;
      const remoteStats = await getRemoteStats(sftp, remotePath);
      const expectedSize = remoteStats?.size;
      if (!Number.isSafeInteger(expectedSize) || expectedSize <= 0) throw new Error('Remote backup has an invalid or empty size.');
      if (expectedSize > maxBytes) throw new Error(`Remote backup exceeds the configured ${maxBytes}-byte transfer limit.`);
      if (Number.isInteger(remoteStats.mode) && (remoteStats.mode & 0o170000) !== 0 && (remoteStats.mode & 0o170000) !== 0o100000) {
        throw new Error('Remote SFTP path is not a regular file.');
      }

      fileHandle = await fs.open(localPath, 'wx', 0o600);
      createdDestination = true;
      const output = createWriteStream(localPath, { fd: fileHandle.fd, autoClose: false });
      const hash = createHash('sha256');
      let transferred = 0;
      const limiter = new Transform({
        transform(chunk, encoding, callback) {
          transferred += chunk.length;
          if (transferred > maxBytes || transferred > expectedSize) {
            callback(new Error('SFTP stream exceeded the verified remote file size or configured transfer limit.'));
            return;
          }
          hash.update(chunk);
          callback(null, chunk);
        },
      });
      await pipeline(sftp.createReadStream(remotePath), limiter, output);
      if (transferred !== expectedSize) throw new Error(`SFTP transfer size mismatch: expected ${expectedSize}, received ${transferred}.`);
      await fileHandle.sync();
      const sha256 = hash.digest('hex');
      await fileHandle.close();
      fileHandle = null;
      const localStats = await fs.lstat(localPath);
      if (localStats.isSymbolicLink() || !localStats.isFile() || (localStats.mode & 0o077) !== 0 || localStats.size !== expectedSize) {
        throw new Error('Completed SFTP file failed private-file verification.');
      }
      return { size: transferred, sha256 };
    });
    return { filename: safeFilename, ...metadata };
  } catch (error) {
    if (fileHandle) await fileHandle.close().catch(() => {});
    if (createdDestination) await fs.unlink(localPath).catch(() => {});
    throw error;
  }
}
