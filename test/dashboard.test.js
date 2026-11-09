import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { startDashboard } from '../src/dashboard.js';

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve, reject) => probe.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  const { port } = probe.address();
  await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
  return port;
}

test('dashboard is read-only, localhost-bound, and returns selected-device summary', async () => {
  const port = await freePort();
  const dashboard = await startDashboard({
    host: '127.0.0.1',
    port,
    listDevices: async () => [{ id: 'router-a', name: 'Lab' }],
    readSummary: async (device) => ({ device, status: 'ok' }),
  });
  try {
    const devicesResponse = await fetch(`${dashboard.url}/api/devices`);
    assert.equal(devicesResponse.status, 200);
    assert.match(devicesResponse.headers.get('content-security-policy'), /default-src 'none'/);
    assert.deepEqual(await devicesResponse.json(), [{ id: 'router-a', name: 'Lab' }]);
    const summaryResponse = await fetch(`${dashboard.url}/api/summary?device=router-a`);
    assert.deepEqual(await summaryResponse.json(), { device: 'router-a', status: 'ok' });
    const page = await fetch(dashboard.url);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Local, read-only status view/);
    const writeResponse = await fetch(`${dashboard.url}/api/devices`, { method: 'POST' });
    assert.equal(writeResponse.status, 405);
  } finally {
    await dashboard.close();
  }
});

test('dashboard rejects non-loopback bindings and untrusted Host headers', async () => {
  await assert.rejects(() => startDashboard({ host: '0.0.0.0', port: 9090, listDevices: async () => [], readSummary: async () => ({}) }), /loopback/);
  const port = await freePort();
  const dashboard = await startDashboard({ host: '127.0.0.1', port, listDevices: async () => [], readSummary: async () => ({}) });
  try {
    const response = await new Promise((resolve, reject) => {
      http.get({ hostname: '127.0.0.1', port, headers: { Host: 'router.evil.example' } }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(body) }));
      }).on('error', reject);
    });
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'Invalid Host header.' });
  } finally {
    await dashboard.close();
  }
});
