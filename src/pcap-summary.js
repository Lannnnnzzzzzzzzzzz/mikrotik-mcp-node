const MAX_PCAP_BUFFER_BYTES = 64 * 1024 * 1024;
const MAX_PCAP_PACKET_COUNT = 100_000;
const MAX_PACKET_BYTES = 65_535;
const GLOBAL_HEADER_BYTES = 24;
const RECORD_HEADER_BYTES = 16;

const PCAP_MAGICS = new Map([
  ['d4c3b2a1', { littleEndian: true, nanoseconds: false }],
  ['a1b2c3d4', { littleEndian: false, nanoseconds: false }],
  ['4d3cb2a1', { littleEndian: true, nanoseconds: true }],
  ['a1b23c4d', { littleEndian: false, nanoseconds: true }],
]);

/**
 * Summarize a classic-PCAP Buffer without returning packet data or identifiers.
 * Input is restricted to the format emitted by tzsp-capture.js: classic PCAP
 * 2.4 with at most 65,535 captured bytes per packet and an Ethernet link type.
 * Common byte orders and microsecond/nanosecond timestamp variants are accepted.
 */
export function summarizePcap(input) {
  if (!Buffer.isBuffer(input)) throw new TypeError('PCAP input must be a Buffer.');
  if (input.length > MAX_PCAP_BUFFER_BYTES) {
    throw new RangeError(`PCAP input exceeds the ${MAX_PCAP_BUFFER_BYTES}-byte limit.`);
  }
  if (input.length < GLOBAL_HEADER_BYTES) throw new TypeError('PCAP global header is truncated.');

  const magic = PCAP_MAGICS.get(input.subarray(0, 4).toString('hex'));
  if (!magic) throw new TypeError('Unsupported PCAP magic; classic PCAP is required.');
  const read32 = magic.littleEndian ? 'readUInt32LE' : 'readUInt32BE';
  const major = magic.littleEndian ? input.readUInt16LE(4) : input.readUInt16BE(4);
  const minor = magic.littleEndian ? input.readUInt16LE(6) : input.readUInt16BE(6);
  if (major !== 2 || minor !== 4) throw new TypeError('Unsupported classic PCAP version; version 2.4 is required.');
  const snapLength = input[read32](16);
  const linkType = input[read32](20);
  if (snapLength === 0 || snapLength > MAX_PACKET_BYTES) throw new TypeError('Unsupported PCAP snap length.');

  const result = {
    packetCount: 0,
    linkType,
    ipv4Count: 0,
    ipv6Count: 0,
    tcpCount: 0,
    udpCount: 0,
    icmpCount: 0,
    otherCount: 0,
    malformedCount: 0,
    truncatedCount: 0,
    packetLimitReached: false,
  };

  let offset = GLOBAL_HEADER_BYTES;
  while (offset < input.length && result.packetCount < MAX_PCAP_PACKET_COUNT) {
    const remaining = input.length - offset;
    if (remaining < RECORD_HEADER_BYTES) {
      result.truncatedCount += 1;
      break;
    }
    const capturedLength = input[read32](offset + 8);
    const originalLength = input[read32](offset + 12);
    offset += RECORD_HEADER_BYTES;

    if (capturedLength > MAX_PACKET_BYTES || capturedLength > snapLength || originalLength < capturedLength) {
      result.packetCount += 1;
      result.malformedCount += 1;
      if (capturedLength > input.length - offset) {
        result.truncatedCount += 1;
        break;
      }
      offset += capturedLength;
      continue;
    }
    if (capturedLength > input.length - offset) {
      result.packetCount += 1;
      result.truncatedCount += 1;
      break;
    }

    const packet = input.subarray(offset, offset + capturedLength);
    offset += capturedLength;
    result.packetCount += 1;
    if (capturedLength < originalLength) result.truncatedCount += 1;
    if (linkType !== 1) {
      result.otherCount += 1;
      continue;
    }

    const classification = classifyEthernet(packet);
    if (classification.ipVersion === 4) result.ipv4Count += 1;
    else if (classification.ipVersion === 6) result.ipv6Count += 1;
    if (classification.transport === 'tcp') result.tcpCount += 1;
    else if (classification.transport === 'udp') result.udpCount += 1;
    else if (classification.transport === 'icmp') result.icmpCount += 1;
    else result.otherCount += 1;
    if (classification.malformed) result.malformedCount += 1;
    if (classification.truncated && capturedLength >= originalLength) result.truncatedCount += 1;
  }

  if (result.packetCount === MAX_PCAP_PACKET_COUNT && offset < input.length) result.packetLimitReached = true;
  return result;
}

function classifyEthernet(packet) {
  if (packet.length < 14) return { malformed: false, truncated: true };
  let etherType = packet.readUInt16BE(12);
  let offset = 14;
  let vlanDepth = 0;
  while (etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100) {
    if (packet.length < offset + 4) return { malformed: false, truncated: true };
    etherType = packet.readUInt16BE(offset + 2);
    offset += 4;
    vlanDepth += 1;
    if (vlanDepth > 8) return { malformed: true };
  }
  if (etherType === 0x0800) return classifyIpv4(packet, offset);
  if (etherType === 0x86dd) return classifyIpv6(packet, offset);
  return {};
}

function classifyIpv4(packet, offset) {
  if (packet.length < offset + 20) return { ipVersion: 4, malformed: false, truncated: true };
  const versionAndLength = packet[offset];
  const version = versionAndLength >>> 4;
  const headerLength = (versionAndLength & 0x0f) * 4;
  if (version !== 4 || headerLength < 20) return { malformed: true };
  if (packet.length < offset + headerLength) return { ipVersion: 4, malformed: false, truncated: true };
  const totalLength = packet.readUInt16BE(offset + 2);
  if (totalLength < headerLength) return { ipVersion: 4, malformed: true };
  const declaredEnd = offset + totalLength;
  const protocolNumber = packet[offset + 9];
  const fragmentOffset = packet.readUInt16BE(offset + 6) & 0x1fff;
  const transport = fragmentOffset === 0 ? ipv4Transport(protocolNumber) : null;
  return {
    ipVersion: 4,
    transport,
    malformed: false,
    truncated: declaredEnd > packet.length,
  };
}

function classifyIpv6(packet, offset) {
  if (packet.length < offset + 40) return { ipVersion: 6, malformed: false, truncated: true };
  if ((packet[offset] >>> 4) !== 6) return { malformed: true };
  const payloadLength = packet.readUInt16BE(offset + 4);
  const packetEnd = Math.min(packet.length, offset + 40 + payloadLength);
  let nextHeader = packet[offset + 6];
  let cursor = offset + 40;
  let extensionCount = 0;

  while ([0, 43, 44, 51, 60].includes(nextHeader)) {
    extensionCount += 1;
    if (extensionCount > 16) return { ipVersion: 6, malformed: true };
    if (nextHeader === 44) {
      if (cursor + 8 > packetEnd) return { ipVersion: 6, malformed: false, truncated: true };
      const fragment = packet.readUInt16BE(cursor + 2);
      nextHeader = packet[cursor];
      cursor += 8;
      if ((fragment & 0xfff8) !== 0) return { ipVersion: 6, transport: null };
      continue;
    }
    if (cursor + 2 > packetEnd) return { ipVersion: 6, malformed: false, truncated: true };
    const followingHeader = packet[cursor];
    const extensionLength = nextHeader === 51 ? (packet[cursor + 1] + 2) * 4 : (packet[cursor + 1] + 1) * 8;
    if (extensionLength < 8 || cursor + extensionLength > packetEnd) {
      return { ipVersion: 6, malformed: false, truncated: true };
    }
    nextHeader = followingHeader;
    cursor += extensionLength;
  }

  return {
    ipVersion: 6,
    transport: ipv6Transport(nextHeader),
    malformed: false,
    truncated: offset + 40 + payloadLength > packet.length,
  };
}

function ipv4Transport(protocol) {
  if (protocol === 6) return 'tcp';
  if (protocol === 17) return 'udp';
  if (protocol === 1) return 'icmp';
  return null;
}

function ipv6Transport(protocol) {
  if (protocol === 6) return 'tcp';
  if (protocol === 17) return 'udp';
  if (protocol === 58) return 'icmp';
  return null;
}
