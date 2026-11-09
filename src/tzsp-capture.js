import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import dgram from 'node:dgram';

const MAX_FRAME_BYTES = 65_535;
const MAX_TAGS = 128;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PCAP_MAGIC = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]);

/**
 * Parse a TZSP v1 datagram carrying Ethernet. Returns null for malformed,
 * non-data, or unsupported datagrams; packet bytes are returned only as a Buffer.
 */
export function parseTzspDatagram(input) {
  if (!Buffer.isBuffer(input) || input.length < 4) return null;
  if (input[0] !== 1 || input[1] !== 0 || input.readUInt16BE(2) !== 1) return null;

  let offset = 4;
  let originalLength;
  let foundEnd = false;
  for (let tagCount = 0; tagCount < MAX_TAGS; tagCount += 1) {
    if (offset >= input.length) return null;
    const tag = input[offset++];
    if (tag === 0) continue;
    if (tag === 1) {
      foundEnd = true;
      break;
    }
    if (offset >= input.length) return null;
    const length = input[offset++];
    if (length > input.length - offset) return null;
    if (tag === 41 && length === 2) originalLength = input.readUInt16BE(offset);
    offset += length;
  }
  if (!foundEnd) return null;
  const frameLength = input.length - offset;
  if (frameLength > MAX_FRAME_BYTES) return null;
  const frame = Buffer.from(input.subarray(offset));
  return { frame, originalLength: originalLength ?? frameLength };
}

/** Build a classic little-endian PCAP global header for Ethernet frames. */
export function buildPcapGlobalHeader() {
  const header = Buffer.alloc(24);
  PCAP_MAGIC.copy(header, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(MAX_FRAME_BYTES, 16);
  header.writeUInt32LE(1, 20);
  return header;
}

/** Build one classic PCAP record. Timestamp is milliseconds since Unix epoch. */
export function buildPcapRecord(frame, timestampMs, originalLength = frame?.length) {
  if (!Buffer.isBuffer(frame) || frame.length > MAX_FRAME_BYTES) throw new TypeError('frame must be a Buffer of at most 65535 bytes.');
  if (!Number.isFinite(timestampMs) || timestampMs < 0) throw new RangeError('timestampMs must be a non-negative finite number.');
  if (!Number.isInteger(originalLength) || originalLength < frame.length || originalLength > 0xffffffff) throw new RangeError('originalLength must be an integer at least as large as the captured frame length.');
  const wholeSeconds = Math.floor(timestampMs / 1000);
  if (wholeSeconds > 0xffffffff) throw new RangeError('timestamp is outside the classic PCAP timestamp range.');
  const microseconds = Math.floor((timestampMs - wholeSeconds * 1000) * 1000);
  const record = Buffer.allocUnsafe(16 + frame.length);
  record.writeUInt32LE(wholeSeconds, 0);
  record.writeUInt32LE(microseconds, 4);
  record.writeUInt32LE(frame.length, 8);
  record.writeUInt32LE(originalLength, 12);
  frame.copy(record, 16);
  return record;
}

function normalizeIp(address) {
  if (typeof address !== 'string') throw new TypeError('IP addresses must be strings.');
  const version = net.isIP(address);
  if (!version) throw new TypeError(`Invalid IP address: ${address}`);
  let value = address.toLowerCase();
  if (version === 6 && value.startsWith('::ffff:')) {
    const tail = value.slice(7);
    if (net.isIP(tail) === 4) return tail;
    const groups = expandIpv6(value);
    if (groups.slice(0, 5).every((part) => part === 0) && groups[5] === 0xffff) {
      return `${parseInt(groups[6].slice(0, 2), 16)}.${parseInt(groups[6].slice(2), 16)}.${parseInt(groups[7].slice(0, 2), 16)}.${parseInt(groups[7].slice(2), 16)}`;
    }
  }
  if (version === 4) return value.split('.').map((part) => String(Number(part))).join('.');
  const groups = expandIpv6(value);
  return groups.map((part) => parseInt(part, 16).toString(16)).join(':');
}

function isUnspecifiedIp(address) {
  if (net.isIP(address) === 4) return address === '0.0.0.0';
  return address.split(':').every((part) => part === '0');
}

function expandIpv6(address) {
  let source = address.toLowerCase();
  if (source.includes('.')) {
    const lastColon = source.lastIndexOf(':');
    const ipv4 = source.slice(lastColon + 1).split('.').map(Number);
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    source = `${source.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const sides = source.split('::');
  const left = sides[0] ? sides[0].split(':') : [];
  const right = sides[1] ? sides[1].split(':') : [];
  const fill = 8 - left.length - right.length;
  return [...left, ...Array(Math.max(0, fill)).fill('0'), ...right].map((part) => part.padStart(4, '0'));
}

function positiveInteger(value, label, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${label} must be an integer from ${min} to ${max}.`);
  return value;
}

function cleanLabel(value) {
  const cleaned = String(value ?? 'capture').normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return cleaned || 'capture';
}

function metadata(session) {
  const now = session.stoppedAt ?? null;
  return {
    id: session.id,
    device: session.device,
    name: session.name,
    bindAddress: session.boundAddress ?? session.bindAddress,
    boundPort: session.boundPort ?? null,
    filePath: session.filePath,
    state: session.state,
    startedAt: session.startedAt,
    stoppedAt: now,
    durationSeconds: session.durationSeconds,
    stopReason: session.stopReason,
    receivedDatagrams: session.receivedDatagrams,
    acceptedDatagrams: session.acceptedDatagrams,
    rejectedSourceDatagrams: session.rejectedSourceDatagrams,
    malformedUnsupportedDatagrams: session.malformedUnsupportedDatagrams,
    backpressureDroppedDatagrams: session.backpressureDroppedDatagrams,
    packets: session.packets,
    payloadBytes: session.payloadBytes,
    fileBytes: session.fileBytes,
  };
}

async function ensureCaptureDirectory(dataDir) {
  await fs.mkdir(dataDir, { recursive: true, mode: 0o700 });
  const rootInfo = await fs.lstat(dataDir);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) throw new Error('dataDir must resolve to a regular directory, not a symlink.');
  const directory = path.join(dataDir, 'captures');
  try {
    await fs.mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const info = await fs.lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('Capture storage must be a regular directory, not a symlink.');
  if ((info.mode & 0o077) !== 0) await fs.chmod(directory, 0o700);
  return directory;
}

function waitForSocketClose(socket) {
  return new Promise((resolve) => {
    if (!socket || !socket.address) return resolve();
    let closed = false;
    const done = () => {
      if (closed) return;
      closed = true;
      socket.removeListener('close', done);
      resolve();
    };
    socket.once('close', done);
    try {
      socket.close();
    } catch {
      done();
    }
  });
}

/** Create a standalone, bounded TZSP-over-UDP capture manager. */
export function createTzspCaptureManager({
  dataDir,
  bindAddress,
  port,
  allowedSources,
  maxDurationSeconds = 60,
  maxCaptureBytes = 64 * 1024 * 1024,
  maxPackets = 100_000,
  maxPendingBytes = 1024 * 1024,
  clock = Date.now,
} = {}) {
  if (typeof dataDir !== 'string' || dataDir.length === 0) throw new TypeError('dataDir is required.');
  const absoluteDataDir = path.resolve(dataDir);
  const normalizedBind = normalizeIp(bindAddress);
  if (isUnspecifiedIp(normalizedBind)) throw new TypeError('bindAddress must be an explicit, non-wildcard IP address.');
  positiveInteger(port, 'port', { min: 0, max: 65535 });
  if (!Array.isArray(allowedSources)) throw new TypeError('allowedSources must be an array of exact IP addresses.');
  const sourceAllowlist = new Set(allowedSources.map((address) => {
    const normalized = normalizeIp(address);
    if (isUnspecifiedIp(normalized)) throw new TypeError('allowedSources cannot contain wildcard IP addresses.');
    return normalized;
  }));
  positiveInteger(maxDurationSeconds, 'maxDurationSeconds');
  positiveInteger(maxCaptureBytes, 'maxCaptureBytes', { min: 24 });
  positiveInteger(maxPackets, 'maxPackets');
  positiveInteger(maxPendingBytes, 'maxPendingBytes');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function.');

  let active = null;
  let starting = false;
  const known = new Map();
  const captureDirectory = path.join(absoluteDataDir, 'captures');

  function requestStop(session, reason) {
    if (!session || session.stopPromise) return session?.stopPromise ?? Promise.resolve(null);
    session.accepting = false;
    session.state = 'stopping';
    session.stopReason = reason;
    clearTimeout(session.timer);
    session.stopPromise = finalize(session);
    return session.stopPromise;
  }

  async function finalize(session) {
    await waitForSocketClose(session.socket);
    if (session.writerPromise) await session.writerPromise;
    session.stoppedAt = new Date(clock()).toISOString();
    let fileError = session.fileError;
    try {
      if (session.handle) {
        if (!fileError) await session.handle.sync();
        await session.handle.close();
        session.handle = null;
      }
    } catch (error) {
      fileError = error;
    }
    if (fileError) {
      await fs.unlink(session.partialPath).catch(() => {});
      session.state = 'failed';
      session.stopReason = 'file-error';
      session.fileBytes = 0;
    } else {
      try {
        await fs.rename(session.partialPath, session.filePath);
        session.state = 'completed';
        const stat = await fs.stat(session.filePath);
        session.fileBytes = stat.size;
        known.set(session.id, metadata(session));
      } catch (error) {
        await fs.unlink(session.partialPath).catch(() => {});
        session.state = 'failed';
        session.stopReason = 'file-error';
        fileError = error;
      }
    }
    if (active === session) active = null;
    return metadata(session);
  }

  function drain(session) {
    return (async () => {
      while (session.queue.length) {
        const record = session.queue.shift();
        try {
          let offset = 0;
          while (offset < record.length) {
            const result = await session.handle.write(record, offset, record.length - offset, null);
            if (!result.bytesWritten) throw new Error('Capture file write made no progress.');
            offset += result.bytesWritten;
          }
          session.fileBytes += record.length;
        } finally {
          session.pendingBytes -= record.length;
        }
      }
    })().catch((error) => {
      session.fileError = error;
      for (const record of session.queue.splice(0)) session.pendingBytes -= record.length;
      session.pendingBytes = Math.max(0, session.pendingBytes);
      if (!session.stopPromise) requestStop(session, 'file-error').catch(() => {});
    });
  }

  async function start({ device, name = 'capture', durationSeconds = maxDurationSeconds } = {}) {
    if (active || starting) throw new Error('A capture session is already active.');
    if (typeof device !== 'string' || !/^[a-zA-Z0-9_-]{1,48}$/.test(device)) throw new TypeError('device must be a configured router ID.');
    if (typeof name !== 'string' || name.length < 1 || name.length > 100 || /[\u0000-\u001f\u007f]/.test(name)) throw new TypeError('name must be 1–100 printable characters.');
    positiveInteger(durationSeconds, 'durationSeconds');
    const cappedDuration = Math.min(durationSeconds, maxDurationSeconds);
    const directory = await ensureCaptureDirectory(absoluteDataDir);
    if (active || starting) throw new Error('A capture session is already active.');
    starting = true;
    const id = crypto.randomUUID();
    const base = `${id}-${cleanLabel(name)}`;
    const partialPath = path.join(directory, `${base}.partial`);
    const filePath = path.join(directory, `${base}.pcap`);
    const session = {
      id, device, name, partialPath, filePath, state: 'starting', accepting: false,
      bindAddress,
      startedAt: new Date(clock()).toISOString(), stoppedAt: null, durationSeconds: cappedDuration,
      stopReason: null, receivedDatagrams: 0, acceptedDatagrams: 0, rejectedSourceDatagrams: 0,
      malformedUnsupportedDatagrams: 0, backpressureDroppedDatagrams: 0, packets: 0, payloadBytes: 0,
      fileBytes: 24, pendingBytes: 0, queue: [], writerPromise: null, fileError: null,
      timer: null, socket: null, handle: null, stopPromise: null,
    };
    known.set(id, metadata(session));
    try {
      session.handle = await fs.open(partialPath, 'wx', 0o600);
      await session.handle.writeFile(buildPcapGlobalHeader());
      const family = net.isIP(bindAddress);
      session.socket = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
      session.socket.on('message', (datagram, remote) => {
        if (!session.accepting) return;
        session.receivedDatagrams += 1;
        let source;
        try { source = normalizeIp(remote.address); } catch { source = ''; }
        if (!sourceAllowlist.has(source)) {
          session.rejectedSourceDatagrams += 1;
          return;
        }
        const parsed = parseTzspDatagram(datagram);
        if (!parsed) {
          session.malformedUnsupportedDatagrams += 1;
          return;
        }
        const recordLength = 16 + parsed.frame.length;
        if (session.fileBytes + session.pendingBytes + recordLength > maxCaptureBytes) {
          requestStop(session, 'byte-limit').catch(() => {});
          return;
        }
        if (recordLength > maxPendingBytes || session.pendingBytes + recordLength > maxPendingBytes) {
          session.backpressureDroppedDatagrams += 1;
          return;
        }
        let record;
        try {
          record = buildPcapRecord(parsed.frame, clock(), parsed.originalLength);
        } catch {
          session.malformedUnsupportedDatagrams += 1;
          return;
        }
        session.queue.push(record);
        session.pendingBytes += record.length;
        session.acceptedDatagrams += 1;
        session.packets += 1;
        session.payloadBytes += parsed.frame.length;
        if (!session.writerPromise) {
          session.writerPromise = drain(session).finally(() => { session.writerPromise = null; });
        }
        if (session.packets >= maxPackets) requestStop(session, 'packet-limit').catch(() => {});
        else if (session.fileBytes + session.pendingBytes >= maxCaptureBytes) requestStop(session, 'byte-limit').catch(() => {});
      });
      session.socket.on('error', () => {
        if (session.accepting) requestStop(session, 'socket-error').catch(() => {});
      });
      await new Promise((resolve, reject) => {
        const onListening = () => { cleanup(); resolve(); };
        const onError = (error) => { cleanup(); reject(error); };
        const cleanup = () => {
          session.socket.removeListener('listening', onListening);
          session.socket.removeListener('error', onError);
        };
        session.socket.once('listening', onListening);
        session.socket.once('error', onError);
        session.socket.bind({ address: bindAddress, port });
      });
      const endpoint = session.socket.address();
      session.boundAddress = endpoint.address;
      session.boundPort = endpoint.port;
      session.state = 'active';
      session.accepting = true;
      active = session;
      starting = false;
      known.set(id, metadata(session));
      session.timer = setTimeout(() => { requestStop(session, 'duration-limit').catch(() => {}); }, cappedDuration * 1000);
      session.timer.unref?.();
      return metadata(session);
    } catch (error) {
      session.accepting = false;
      await waitForSocketClose(session.socket);
      if (session.handle) await session.handle.close().catch(() => {});
      await fs.unlink(partialPath).catch(() => {});
      known.delete(id);
      if (active === session) active = null;
      starting = false;
      throw new Error(`Unable to start TZSP capture: ${error.message}`);
    }
  }

  async function stop(id) {
    if (typeof id !== 'string' || !UUID_RE.test(id)) throw new TypeError('Capture ID must be a valid UUID.');
    const normalized = id.toLowerCase();
    if (active?.id === normalized) return requestStop(active, 'requested');
    const existing = known.get(normalized);
    if (existing && existing.state !== 'starting' && existing.state !== 'active' && existing.state !== 'stopping') return { ...existing };
    throw new Error(`Active capture not found: ${normalized}`);
  }

  function status() {
    return active ? metadata(active) : null;
  }

  async function list() {
    const directory = await ensureCaptureDirectory(absoluteDataDir);
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const captures = [];
    for (const entry of entries) {
      if (!entry.name.endsWith('.pcap') || entry.isSymbolicLink()) continue;
      const match = entry.name.match(/^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-[a-zA-Z0-9_-]+\.pcap$/i);
      if (!match) continue;
      const filePath = path.join(directory, entry.name);
      let info;
      try { info = await fs.lstat(filePath); } catch { continue; }
      if (info.isSymbolicLink() || !info.isFile()) continue;
      const id = match[1].toLowerCase();
      const remembered = known.get(id);
      captures.push(remembered ? { ...remembered, filePath, fileBytes: info.size } : {
        id, device: null, name: null, bindAddress: null, boundPort: null, filePath, state: 'completed', startedAt: null,
        stoppedAt: info.mtime.toISOString(), durationSeconds: null, stopReason: null,
        receivedDatagrams: null, acceptedDatagrams: null, rejectedSourceDatagrams: null,
        malformedUnsupportedDatagrams: null, backpressureDroppedDatagrams: null,
        packets: null, payloadBytes: null, fileBytes: info.size,
      });
    }
    return captures.sort((a, b) => a.startedAt && b.startedAt ? a.startedAt.localeCompare(b.startedAt) : a.id.localeCompare(b.id));
  }

  async function deleteCapture(id) {
    if (typeof id !== 'string' || !UUID_RE.test(id)) throw new TypeError('Capture ID must be a valid UUID.');
    const normalized = id.toLowerCase();
    if (active?.id === normalized) throw new Error('Cannot delete an active capture.');
    const directory = await ensureCaptureDirectory(absoluteDataDir);
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const candidate = entries.find((entry) => entry.name.startsWith(`${normalized}-`) && entry.name.endsWith('.pcap') && !entry.isSymbolicLink());
    if (!candidate) throw new Error(`Capture not found: ${normalized}`);
    const filePath = path.join(directory, candidate.name);
    const info = await fs.lstat(filePath);
    if (info.isSymbolicLink() || !info.isFile() || path.dirname(path.resolve(filePath)) !== path.resolve(directory)) throw new Error('Capture file must be a regular file inside the private capture directory.');
    await fs.unlink(filePath);
    known.delete(normalized);
    return { id: normalized, deleted: true };
  }

  async function shutdown() {
    if (!active) return null;
    return requestStop(active, 'shutdown');
  }

  return { start, stop, status, list, delete: deleteCapture, shutdown };
}
