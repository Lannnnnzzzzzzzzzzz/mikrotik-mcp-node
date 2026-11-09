import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import dgram from 'node:dgram';
import {
  buildPcapGlobalHeader,
  buildPcapRecord,
  createTzspCaptureManager,
  parseTzspDatagram,
} from '../src/tzsp-capture.js';

const ethernetFrame = Buffer.from('00112233445566778899aabb080045544553545f5041594c4f4144', 'hex');

function tzsp(frame = ethernetFrame, { version = 1, type = 0, encapsulation = 1, tags = Buffer.from([1]) } = {}) {
  const header = Buffer.alloc(4);
  header[0] = version;
  header[1] = type;
  header.writeUInt16BE(encapsulation, 2);
  return Buffer.concat([header, tags, frame]);
}

async function tempDirectory(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tzsp-capture-test-'));
  await fs.chmod(directory, 0o700);
  t.after(async () => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

async function waitFor(predicate, timeoutMs = 2500) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const result = await predicate();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Timed out waiting for capture state.');
}

function cleanupManager(t, manager) {
  t.after(async () => { await manager.shutdown().catch(() => {}); });
}

async function sendUdp(port, payload, { sourceAddress = '127.0.0.1', destinationAddress = '127.0.0.1' } = {}) {
  const socket = dgram.createSocket('udp4');
  try {
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.bind({ address: sourceAddress }, resolve);
    });
    await new Promise((resolve, reject) => socket.send(payload, port, destinationAddress, (error) => error ? reject(error) : resolve()));
  } finally {
    await new Promise((resolve) => socket.close(resolve));
  }
}

test('parses valid TZSP Ethernet and pad, unknown, and original-length tags safely', () => {
  const tagBytes = Buffer.from([
    0,                         // pad
    77, 3, 0xaa, 0xbb, 0xcc,  // unknown tag
    41, 2, 0x01, 0x23,        // original pre-slicing length: 291
    1,                         // end
  ]);
  const parsed = parseTzspDatagram(tzsp(ethernetFrame, { tags: tagBytes }));
  assert.deepEqual(parsed.frame, ethernetFrame);
  assert.equal(parsed.originalLength, 0x0123);
  assert.notEqual(parsed.frame, ethernetFrame);

  const noOriginalLength = parseTzspDatagram(tzsp(ethernetFrame));
  assert.equal(noOriginalLength.originalLength, ethernetFrame.length);
});

test('rejects malformed, truncated, unterminated, excessive-tag, and unsupported TZSP datagrams', () => {
  assert.equal(parseTzspDatagram(Buffer.alloc(3)), null);
  assert.equal(parseTzspDatagram(tzsp(ethernetFrame, { version: 2 })), null);
  assert.equal(parseTzspDatagram(tzsp(ethernetFrame, { type: 1 })), null);
  assert.equal(parseTzspDatagram(tzsp(ethernetFrame, { encapsulation: 6 })), null);
  const header = Buffer.from([1, 0, 0, 1]);
  assert.equal(parseTzspDatagram(Buffer.concat([header, Buffer.from([9])])), null); // missing length
  assert.equal(parseTzspDatagram(Buffer.concat([header, Buffer.from([9, 3, 1])])), null); // truncated content
  assert.equal(parseTzspDatagram(tzsp(ethernetFrame, { tags: Buffer.alloc(0) })), null);
  const tooManyTags = Buffer.concat([Buffer.alloc(129 * 2, 0).map((_, i) => i % 2 ? 0 : 77), Buffer.from([1])]);
  assert.equal(parseTzspDatagram(tzsp(ethernetFrame, { tags: tooManyTags })), null);
  assert.equal(parseTzspDatagram(tzsp(Buffer.alloc(65_536))), null);
});

test('builds classic little-endian PCAP global and record headers with checked bounds', () => {
  const header = buildPcapGlobalHeader();
  assert.equal(header.length, 24);
  assert.deepEqual([...header.subarray(0, 4)], [0xd4, 0xc3, 0xb2, 0xa1]);
  assert.equal(header.readUInt16LE(4), 2);
  assert.equal(header.readUInt16LE(6), 4);
  assert.equal(header.readUInt32LE(16), 65_535);
  assert.equal(header.readUInt32LE(20), 1);

  const record = buildPcapRecord(ethernetFrame, 1_234_567, ethernetFrame.length + 9);
  assert.equal(record.length, 16 + ethernetFrame.length);
  assert.equal(record.readUInt32LE(0), 1234);
  assert.equal(record.readUInt32LE(4), 567_000);
  assert.equal(record.readUInt32LE(8), ethernetFrame.length);
  assert.equal(record.readUInt32LE(12), ethernetFrame.length + 9);
  assert.deepEqual(record.subarray(16), ethernetFrame);
  assert.throws(() => buildPcapRecord('not a buffer', 0), /Buffer/);
  assert.throws(() => buildPcapRecord(ethernetFrame, -1), /timestamp/);
  assert.throws(() => buildPcapRecord(ethernetFrame, 1, ethernetFrame.length - 1), /originalLength/);
});

test('captures an allowed loopback source privately and returns metadata without packet data', async (t) => {
  const dataDir = await tempDirectory(t);
  const manager = createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'] });
  cleanupManager(t, manager);
  const started = await manager.start({ device: 'router-a', name: 'nightly / capture', durationSeconds: 10 });
  assert.equal(started.state, 'active');
  assert.ok(started.boundPort > 0);
  assert.match(started.filePath, /captures\/[0-9a-f-]+-nightly-capture\.pcap$/);
  assert.equal((await fs.stat(path.join(dataDir, 'captures'))).mode & 0o077, 0);
  assert.equal((await fs.stat(started.filePath.replace(/\.pcap$/, '.partial'))).mode & 0o077, 0);

  await sendUdp(started.boundPort, tzsp(ethernetFrame));
  await waitFor(() => manager.status()?.packets === 1);
  const whileActive = manager.status();
  assert.equal(whileActive.receivedDatagrams, 1);
  assert.equal(whileActive.acceptedDatagrams, 1);
  assert.equal(whileActive.payloadBytes, ethernetFrame.length);
  assert.equal(JSON.stringify(whileActive).includes('TEST_PAYLOAD'), false);
  assert.equal(JSON.stringify(whileActive).includes('001122334455'), false);

  const finished = await manager.stop(started.id);
  assert.equal(finished.state, 'completed');
  assert.equal(finished.stopReason, 'requested');
  assert.equal(finished.fileBytes, 24 + 16 + ethernetFrame.length);
  assert.equal(manager.status(), null);
  const file = await fs.readFile(finished.filePath);
  assert.deepEqual(file.subarray(0, 24), buildPcapGlobalHeader());
  assert.deepEqual(file.subarray(40), ethernetFrame);
  assert.equal((await fs.stat(finished.filePath)).mode & 0o077, 0);
  const listed = await manager.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].id, started.id);
  assert.equal(JSON.stringify(listed).includes('TEST_PAYLOAD'), false);
  assert.deepEqual(await manager.delete(started.id), { id: started.id, deleted: true });
  assert.deepEqual(await manager.list(), []);
});

test('rejects non-allowlisted sources and counts malformed/unsupported datagrams', async (t) => {
  const dataDir = await tempDirectory(t);
  const manager = createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'], maxDurationSeconds: 5 });
  cleanupManager(t, manager);
  const started = await manager.start({ device: 'router-a' });
  let secondLoopbackAvailable = true;
  try {
    await sendUdp(started.boundPort, tzsp(), { sourceAddress: '127.0.0.2' });
  } catch {
    secondLoopbackAvailable = false;
  }
  await sendUdp(started.boundPort, Buffer.from([1, 0, 0, 1, 9]));
  await waitFor(() => manager.status()?.receivedDatagrams >= (secondLoopbackAvailable ? 2 : 1));
  const current = manager.status();
  assert.equal(current.rejectedSourceDatagrams, secondLoopbackAvailable ? 1 : 0);
  assert.equal(current.malformedUnsupportedDatagrams, 1);
  assert.equal(current.packets, 0);
  await manager.stop(started.id);
});

test('enforces one active capture and auto-stops by packet and total file-byte limits', async (t) => {
  const dataDir = await tempDirectory(t);
  const perPacketBytes = 16 + ethernetFrame.length;
  const packetManager = createTzspCaptureManager({
    dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'], maxPackets: 1,
  });
  cleanupManager(t, packetManager);
  const attempts = await Promise.allSettled([
    packetManager.start({ device: 'router-a' }),
    packetManager.start({ device: 'router-b' }),
  ]);
  assert.equal(attempts.filter((item) => item.status === 'fulfilled').length, 1);
  assert.equal(attempts.filter((item) => item.status === 'rejected').length, 1);
  assert.match(attempts.find((item) => item.status === 'rejected').reason.message, /already active/);
  const packetSession = attempts.find((item) => item.status === 'fulfilled').value;
  await sendUdp(packetSession.boundPort, tzsp());
  await waitFor(() => packetManager.status() === null && fs.stat(packetSession.filePath).then(() => true).catch(() => false));
  const packetCapture = (await packetManager.list())[0];
  assert.equal(packetCapture.stopReason, 'packet-limit');
  assert.equal(packetCapture.packets, 1);

  const byteManager = createTzspCaptureManager({
    dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'], maxCaptureBytes: 24 + perPacketBytes,
  });
  cleanupManager(t, byteManager);
  const byteSession = await byteManager.start({ device: 'router-a' });
  await sendUdp(byteSession.boundPort, tzsp());
  await waitFor(() => byteManager.status() === null && fs.stat(byteSession.filePath).then(() => true).catch(() => false));
  const byteCapture = (await byteManager.list()).find((capture) => capture.id === byteSession.id);
  assert.equal(byteCapture.stopReason, 'byte-limit');
  assert.equal(byteCapture.fileBytes, 24 + perPacketBytes);
});

test('drops packets that would exceed the bounded pending-write queue', async (t) => {
  const dataDir = await tempDirectory(t);
  const manager = createTzspCaptureManager({
    dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'], maxPendingBytes: 1,
  });
  cleanupManager(t, manager);
  const started = await manager.start({ device: 'router-a' });
  await sendUdp(started.boundPort, tzsp());
  await waitFor(() => manager.status()?.backpressureDroppedDatagrams === 1);
  const finished = await manager.stop(started.id);
  assert.equal(finished.backpressureDroppedDatagrams, 1);
  assert.equal(finished.packets, 0);
  assert.equal(finished.fileBytes, 24);
});

test('auto-stops at duration, caps requested duration, and shutdown finalizes active capture', async (t) => {
  const dataDir = await tempDirectory(t);
  const manager = createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['127.0.0.1'], maxDurationSeconds: 1 });
  cleanupManager(t, manager);
  const started = await manager.start({ device: 'router-a', durationSeconds: 30 });
  assert.equal(started.durationSeconds, 1);
  await waitFor(() => manager.status() === null && fs.stat(started.filePath).then(() => true).catch(() => false), 3000);
  assert.equal((await manager.list())[0].stopReason, 'duration-limit');

  const active = await manager.start({ device: 'router-a' });
  const done = await manager.shutdown();
  assert.equal(done.id, active.id);
  assert.equal(done.stopReason, 'shutdown');
  assert.equal(done.state, 'completed');
  assert.equal(manager.status(), null);
});

test('validates wildcard binds, exact IP allowlists, IDs, paths, and excludes symlinks', async (t) => {
  const dataDir = await tempDirectory(t);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '0.0.0.0', port: 0, allowedSources: [] }), /non-wildcard/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '::', port: 0, allowedSources: [] }), /non-wildcard/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '0:0:0:0:0:0:0:0', port: 0, allowedSources: [] }), /non-wildcard/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['0.0.0.0'] }), /wildcard/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['::'] }), /wildcard/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: ['not-an-ip'] }), /Invalid IP/);
  assert.throws(() => createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: [], maxCaptureBytes: 23 }), /maxCaptureBytes/);

  const manager = createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: 0, allowedSources: [] });
  cleanupManager(t, manager);
  const started = await manager.start({ device: 'router-a', name: '../../private' });
  assert.equal(path.dirname(started.filePath), path.join(dataDir, 'captures'));
  await assert.rejects(manager.delete('../escape'), /UUID/);
  await manager.stop(started.id);

  const external = path.join(dataDir, 'outside.pcap');
  await fs.writeFile(external, 'not a capture');
  const linkName = `123e4567-e89b-42d3-a456-426614174000-link.pcap`;
  await fs.symlink(external, path.join(dataDir, 'captures', linkName));
  assert.equal((await manager.list()).some((item) => item.id === '123e4567-e89b-42d3-a456-426614174000'), false);
  await assert.rejects(manager.delete('123e4567-e89b-42d3-a456-426614174000'), /not found/);
  assert.equal(await fs.readFile(external, 'utf8'), 'not a capture');

  const linkDir = path.join(dataDir, 'linked-captures');
  await fs.symlink(path.join(dataDir, 'captures'), linkDir);
  const linkedRoot = path.join(dataDir, 'root-through-link');
  await fs.mkdir(linkedRoot);
  await fs.symlink(path.join(dataDir, 'captures'), path.join(linkedRoot, 'captures'));
  const linkedManager = createTzspCaptureManager({ dataDir: linkedRoot, bindAddress: '127.0.0.1', port: 0, allowedSources: [] });
  cleanupManager(t, linkedManager);
  await assert.rejects(linkedManager.start({ device: 'router-a' }), /symlink/);
});

test('bind failure removes partial file and leaves the manager inactive', async (t) => {
  const dataDir = await tempDirectory(t);
  const occupied = dgram.createSocket('udp4');
  await new Promise((resolve) => occupied.bind(0, '127.0.0.1', resolve));
  const occupiedPort = occupied.address().port;
  const manager = createTzspCaptureManager({ dataDir, bindAddress: '127.0.0.1', port: occupiedPort, allowedSources: [] });
  cleanupManager(t, manager);
  t.after(async () => { await new Promise((resolve) => occupied.close(resolve)); });
  await assert.rejects(manager.start({ device: 'router-a' }), /Unable to start TZSP capture/);
  assert.equal(manager.status(), null);
  assert.deepEqual(await manager.list(), []);
});
