import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { summarizePcap } from './pcap-summary.js';

const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FILE_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-[A-Za-z0-9_-]+\.pcap$/i;

/** Read one completed local PCAP safely and return aggregate counts only. */
export async function summarizeLocalCapture({ captureManager, captureId, dataDir } = {}) {
  if (typeof captureId !== 'string' || !UUID_RE.test(captureId)) throw new TypeError('Capture ID must be a valid UUID.');
  if (!captureManager || typeof captureManager.list !== 'function') throw new TypeError('A compatible local capture manager is required.');
  if (typeof dataDir !== 'string' || dataDir.length === 0) throw new TypeError('A local capture data directory is required.');

  const normalizedId = captureId.toLowerCase();
  const captureDirectory = path.resolve(dataDir, 'captures');
  let captures;
  try { captures = await captureManager.list(); } catch { throw new Error('Unable to list local PCAP captures safely.'); }
  if (!Array.isArray(captures)) throw new Error('Local PCAP capture listing is malformed.');
  const record = captures.find((item) => item && typeof item === 'object' && item.id === normalizedId);
  if (!record || typeof record.filePath !== 'string') throw new Error(`Completed PCAP capture not found: ${normalizedId}`);

  const filePath = path.resolve(record.filePath);
  const match = path.basename(filePath).match(FILE_RE);
  if (!match || match[1].toLowerCase() !== normalizedId || path.dirname(filePath) !== captureDirectory) {
    throw new Error('Capture file must be a generated PCAP file inside the private capture directory.');
  }

  let directoryInfo;
  let linkInfo;
  try {
    directoryInfo = await fsp.lstat(captureDirectory);
    linkInfo = await fsp.lstat(filePath);
  } catch {
    throw new Error('Capture file is missing or unavailable.');
  }
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() || (directoryInfo.mode & 0o077) !== 0) {
    throw new Error('Capture directory is not a private regular directory.');
  }
  if (!linkInfo.isFile() || linkInfo.isSymbolicLink() || (linkInfo.mode & 0o077) !== 0) {
    throw new Error('Capture file is not a private regular file.');
  }
  if (linkInfo.size < 24 || linkInfo.size > MAX_CAPTURE_BYTES) throw new Error('Capture file size is outside the permitted PCAP bounds.');
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('This host cannot safely open capture files without following symbolic links.');

  let handle;
  try {
    handle = await fsp.open(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const openedInfo = await handle.stat();
    if (!openedInfo.isFile() || openedInfo.dev !== linkInfo.dev || openedInfo.ino !== linkInfo.ino
      || openedInfo.size !== linkInfo.size || (openedInfo.mode & 0o077) !== 0) {
      throw new Error('Capture file changed while it was being opened.');
    }
    const bytes = await handle.readFile();
    const afterRead = await handle.stat();
    if (bytes.length !== openedInfo.size || afterRead.size !== openedInfo.size
      || afterRead.dev !== openedInfo.dev || afterRead.ino !== openedInfo.ino) {
      throw new Error('Capture file changed while it was being read.');
    }
    return { captureId: normalizedId, ...summarizePcap(bytes) };
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) throw error;
    if (error?.message === 'Capture file changed while it was being opened.'
      || error?.message === 'Capture file changed while it was being read.') throw error;
    throw new Error('Capture file could not be read safely.');
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}
