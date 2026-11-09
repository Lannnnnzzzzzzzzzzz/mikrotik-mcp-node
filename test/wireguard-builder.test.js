import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWireguardMeshPlan } from '../src/builders.js';

const key = (byte) => Buffer.alloc(32, byte).toString('base64');
const devices = [
  { id: 'edge-a', publicKey: key(1), endpointAddress: 'edge-a.example.net', endpointPort: 13231, allowedLan: '192.168.10.0/24' },
  { id: 'edge-b', publicKey: key(2), endpointAddress: 'edge-b.example.net', endpointPort: 13231, allowedLan: '192.168.20.0/24' },
  { id: 'edge-c', publicKey: key(3), endpointAddress: '198.51.100.3', endpointPort: 13232 },
];

test('WireGuard full-mesh planner assigns deterministic addresses and peer entries without private keys', () => {
  const plan = buildWireguardMeshPlan({ devices, addressPrefix: '10.20.0.0/24', interfaceName: 'wg-mesh' });
  assert.equal(plan.steps.length, 9);
  assert.deepEqual(plan.assignments.map((item) => item.address), ['10.20.0.1/24', '10.20.0.2/24', '10.20.0.3/24']);
  const peers = plan.steps.filter((step) => step.resource === 'wireguard_peers');
  assert.equal(peers.length, 6);
  assert.equal(peers[0].fields['allowed-address'], '10.20.0.2/32,192.168.20.0/24');
  assert.equal(peers[0].fields['endpoint-port'], '13231');
  assert.ok(plan.steps.every((step) => !Object.hasOwn(step.fields, 'private-key')));
  assert.ok(plan.notes.some((note) => note.includes('non-atomic')));
});

test('WireGuard hub-spoke planner only creates hub-to-spoke peer pairs', () => {
  const plan = buildWireguardMeshPlan({ devices, addressPrefix: '10.20.0.0/24', topology: 'hub-spoke', hub: 'edge-a' });
  assert.equal(plan.steps.length, 7);
  const peers = plan.steps.filter((step) => step.resource === 'wireguard_peers');
  assert.equal(peers.length, 4);
  assert.deepEqual(peers.map((step) => step.device), ['edge-a', 'edge-a', 'edge-b', 'edge-c']);
});

test('WireGuard planner rejects invalid keys, overlapping LANs, missing endpoints and oversized plans', () => {
  assert.throws(() => buildWireguardMeshPlan({ devices: [{ ...devices[0], publicKey: 'not-a-key' }, devices[1]], addressPrefix: '10.20.0.0/24' }), /valid 32-byte/);
  assert.throws(() => buildWireguardMeshPlan({ devices: [{ ...devices[0], allowedLan: '10.20.1.0/24' }, devices[1]], addressPrefix: '10.20.0.0/16' }), /overlaps/);
  assert.throws(() => buildWireguardMeshPlan({ devices: [{ ...devices[0], endpointAddress: 'https://edge.example' }, devices[1]], addressPrefix: '10.20.0.0/24' }), /endpoint address/);
  assert.throws(() => buildWireguardMeshPlan({ devices: devices.slice(0, 2), addressPrefix: '10.20.0.0/24', topology: 'hub-spoke' }), /hub must name/);
  const four = [...devices, { id: 'edge-d', publicKey: key(4), endpointAddress: 'edge-d.example.net', endpointPort: 13231 }];
  assert.throws(() => buildWireguardMeshPlan({ devices: four, addressPrefix: '10.20.0.0/24' }), /above the 10-step/);
});
