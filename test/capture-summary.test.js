import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { summarizeLocalCapture } from '../src/capture-summary.js';

const captureId = '123e4567-e89b-42d3-a456-426614174000';

function emptyPcap() {
  const header = Buffer.alloc(24);
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]).copy(header);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65_535, 16);
  header.writeUInt32LE(1, 20);
  return header;
}

async function privateDataDir(t) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'capture-summary-'));
  await fs.chmod(dataDir, 0o700);
  const captures = path.join(dataDir, 'captures');
  await fs.mkdir(captures, { mode: 0o700 });
  t.after(() => fs.rm(dataDir, { recursive: true, force: true }));
  return { dataDir, captures };
}

test('summarizes a private completed PCAP without returning its path or bytes', async (t) => {
  const { dataDir, captures } = await privateDataDir(t);
  const filePath = path.join(captures, `${captureId}-summary.pcap`);
  await fs.writeFile(filePath, emptyPcap(), { mode: 0o600 });
  const manager = { async list() { return [{ id: captureId, state: 'completed', filePath }]; } };

  const result = await summarizeLocalCapture({ captureManager: manager, captureId, dataDir });
  assert.deepEqual(result, {
    captureId, packetCount: 0, linkType: 1, ipv4Count: 0, ipv6Count: 0,
    tcpCount: 0, udpCount: 0, icmpCount: 0, otherCount: 0,
    malformedCount: 0, truncatedCount: 0, packetLimitReached: false,
  });
  assert.equal(JSON.stringify(result).includes(filePath), false);
  assert.equal(JSON.stringify(result).includes('raw'), false);
});

test('rejects symlink captures and paths outside the private capture directory', async (t) => {
  const { dataDir, captures } = await privateDataDir(t);
  const outside = path.join(dataDir, 'outside.pcap');
  await fs.writeFile(outside, emptyPcap(), { mode: 0o600 });
  const linkPath = path.join(captures, `${captureId}-link.pcap`);
  await fs.symlink(outside, linkPath);
  const manager = { async list() { return [{ id: captureId, filePath: linkPath }]; } };
  await assert.rejects(summarizeLocalCapture({ captureManager: manager, captureId, dataDir }), /private regular file/);
  assert.equal((await fs.readFile(outside)).length, 24);

  await assert.rejects(summarizeLocalCapture({
    captureManager: { async list() { return [{ id: captureId, filePath: outside }]; } }, captureId, dataDir,
  }), /inside the private capture directory/);
});

test('rejects oversized files before reading them and does not disclose filesystem paths', async (t) => {
  const { dataDir, captures } = await privateDataDir(t);
  const filePath = path.join(captures, `${captureId}-large.pcap`);
  await fs.writeFile(filePath, emptyPcap(), { mode: 0o600 });
  await fs.truncate(filePath, 64 * 1024 * 1024 + 1);
  const manager = { async list() { return [{ id: captureId, filePath }]; } };
  await assert.rejects(summarizeLocalCapture({ captureManager: manager, captureId, dataDir }), (error) => {
    assert.match(error.message, /size is outside/);
    assert.equal(error.message.includes(dataDir), false);
    return true;
  });
});

