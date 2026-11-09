import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizePcap } from '../src/pcap-summary.js';

function globalHeader({ linkType = 1, snapLength = 65_535 } = {}) {
  const header = Buffer.alloc(24);
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]).copy(header);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(snapLength, 16);
  header.writeUInt32LE(linkType, 20);
  return header;
}

function record(frame, { originalLength = frame.length, capturedLength = frame.length } = {}) {
  const header = Buffer.alloc(16);
  header.writeUInt32LE(1, 0);
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(capturedLength, 8);
  header.writeUInt32LE(originalLength, 12);
  return Buffer.concat([header, frame.subarray(0, capturedLength)]);
}

function ethernetIpv4(protocol, { ihl = 5, totalLength = 20 } = {}) {
  const frame = Buffer.alloc(14 + 20);
  frame.writeUInt16BE(0x0800, 12);
  frame[14] = (4 << 4) | ihl;
  frame.writeUInt16BE(totalLength, 16);
  frame[23] = protocol;
  return frame;
}

function ethernetIpv6(nextHeader) {
  const frame = Buffer.alloc(14 + 40);
  frame.writeUInt16BE(0x86dd, 12);
  frame[14] = 0x60;
  frame[20] = nextHeader;
  return frame;
}

test('summarizes Ethernet IPv4/IPv6 and transport classifications without exposing packet details', () => {
  const tcpFrame = ethernetIpv4(6);
  const udpFrame = ethernetIpv6(17);
  const icmpFrame = ethernetIpv4(1);
  const otherFrame = Buffer.alloc(14);
  otherFrame.writeUInt16BE(0x88b5, 12);
  tcpFrame.set(Buffer.from('00112233445566778899aabb', 'hex'), 0);
  tcpFrame.set(Buffer.from([192, 0, 2, 10]), 26);
  tcpFrame.set(Buffer.from([198, 51, 100, 20]), 30);
  const pcap = Buffer.concat([
    globalHeader(), record(tcpFrame), record(udpFrame), record(icmpFrame), record(otherFrame),
  ]);

  const summary = summarizePcap(pcap);
  assert.deepEqual(summary, {
    packetCount: 4,
    linkType: 1,
    ipv4Count: 2,
    ipv6Count: 1,
    tcpCount: 1,
    udpCount: 1,
    icmpCount: 1,
    otherCount: 1,
    malformedCount: 0,
    truncatedCount: 0,
    packetLimitReached: false,
  });
  const serialized = JSON.stringify(summary);
  for (const secret of ['192.0.2.10', '198.51.100.20', '001122334455', '443', 'raw']) {
    assert.equal(serialized.includes(secret), false);
  }
});

test('counts malformed packet structures, capture truncation, and partial trailing records', () => {
  const malformedIp = ethernetIpv4(6, { ihl: 4 });
  const clipped = ethernetIpv4(17);
  const goodUnknown = Buffer.alloc(14);
  const malformedPcap = Buffer.concat([
    globalHeader(),
    record(malformedIp),
    record(clipped, { originalLength: clipped.length + 8 }),
    record(goodUnknown),
    Buffer.alloc(7),
  ]);

  const summary = summarizePcap(malformedPcap);
  assert.equal(summary.packetCount, 3);
  assert.equal(summary.malformedCount, 1);
  assert.equal(summary.truncatedCount, 2);
  assert.equal(summary.otherCount, 2);
  assert.equal(summary.tcpCount, 0);
  assert.equal(summary.udpCount, 1);
});

test('rejects invalid/unsupported PCAP inputs and reports truncated record payloads safely', () => {
  assert.throws(() => summarizePcap('not a buffer'), /Buffer/);
  assert.throws(() => summarizePcap(Buffer.alloc(23)), /truncated/);
  assert.throws(() => summarizePcap(Buffer.alloc(24)), /magic/);
  const partialRecord = Buffer.concat([globalHeader(), Buffer.alloc(16), Buffer.alloc(4)]);
  partialRecord.writeUInt32LE(12, 24 + 8);
  partialRecord.writeUInt32LE(12, 24 + 12);
  const summary = summarizePcap(partialRecord);
  assert.equal(summary.packetCount, 1);
  assert.equal(summary.truncatedCount, 1);
  assert.equal(summary.otherCount, 0);

  const nonEthernet = summarizePcap(Buffer.concat([globalHeader({ linkType: 101 }), record(Buffer.alloc(8))]));
  assert.equal(nonEthernet.linkType, 101);
  assert.equal(nonEthernet.packetCount, 1);
  assert.equal(nonEthernet.otherCount, 1);
});

test('enforces the hard packet-count ceiling', () => {
  const emptyEthernet = Buffer.alloc(14);
  const pieces = [globalHeader()];
  for (let i = 0; i < 100_001; i += 1) pieces.push(record(emptyEthernet));
  const summary = summarizePcap(Buffer.concat(pieces));
  assert.equal(summary.packetCount, 100_000);
  assert.equal(summary.packetLimitReached, true);
});
