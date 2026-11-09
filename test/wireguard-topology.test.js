import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyWireGuardTopology } from '../src/wireguard-topology.js';

const key = (byte) => Buffer.alloc(32, byte).toString('base64');

function makeRouters({
  disabledA = false,
  disabledB = false,
  disabledPeerA = false,
  disabledPeerB = false,
  omitKeyA = false,
  omitKeyB = false,
  omitAllowedA = false,
  omitAllowedB = false,
  omitPeerA = false,
  omitPeerB = false,
} = {}) {
  const aKey = key(1);
  const bKey = key(2);
  const aPeer = { '.id': '*a1', interface: 'wg-a', 'public-key': bKey, rx: 123, tx: 456, 'last-handshake': 'never', disabled: disabledPeerA };
  const bPeer = { '.id': '*b1', interface: 'wg-b', 'public-key': aKey, rx: 789, tx: 12, 'last-handshake': '1m', disabled: disabledPeerB };
  if (!omitAllowedA) aPeer['allowed-address'] = '10.0.0.2/32';
  if (!omitAllowedB) bPeer['allowed-address'] = '10.0.0.1/32';
  return {
    aKey,
    bKey,
    routers: [
      {
        id: 'router-a',
        interfaces: [{ '.id': '*w1', name: 'wg-a', 'public-key': omitKeyA ? '' : aKey, running: false, disabled: disabledA }],
        peers: omitPeerA ? [] : [aPeer],
      },
      {
        id: 'router-b',
        interfaces: [{ '.id': '*w2', name: 'wg-b', 'public-key': omitKeyB ? '' : bKey, running: false, disabled: disabledB }],
        peers: omitPeerB ? [] : [bPeer],
      },
    ],
  };
}

const links = [{ deviceA: 'router-a', interfaceA: 'wg-a', deviceB: 'router-b', interfaceB: 'wg-b' }];
const codes = (result) => result.links.flatMap((link) => link.findings.map((item) => item.code));

test('verifies reciprocal enabled peers as configuration evidence only', () => {
  const { routers, aKey, bKey } = makeRouters();
  const result = verifyWireGuardTopology({ routers, links });
  assert.equal(result.status, 'verified');
  assert.equal(result.links[0].status, 'verified');
  assert.deepEqual(result.links[0].endpoints.a, {
    routerId: 'router-a', interface: 'wg-a', publicKey: aKey, status: 'verified',
  });
  assert.deepEqual(result.links[0].endpoints.b, {
    routerId: 'router-b', interface: 'wg-b', publicKey: bKey, status: 'verified',
  });
  assert.deepEqual(result.links[0].findings, []);
});

test('reports missing and asymmetric peers explicitly', () => {
  const { routers } = makeRouters({ omitPeerA: true });
  const result = verifyWireGuardTopology({ routers, links });
  assert.equal(result.status, 'review');
  assert.ok(codes(result).includes('missing-peer-a-to-b'));
  assert.ok(!codes(result).includes('missing-peer-b-to-a'));
});

test('reports disabled endpoints and peers for review', () => {
  const endpointResult = verifyWireGuardTopology({ routers: makeRouters({ disabledA: true }).routers, links });
  assert.equal(endpointResult.links[0].endpoints.a.status, 'review');
  assert.ok(codes(endpointResult).includes('disabled-endpoint'));

  const peerResult = verifyWireGuardTopology({ routers: makeRouters({ disabledPeerB: true }).routers, links });
  assert.equal(peerResult.status, 'review');
  assert.ok(codes(peerResult).includes('disabled-peer-b-to-a'));
});

test('treats missing endpoint public keys as unknown', () => {
  const { routers } = makeRouters({ omitKeyB: true });
  const result = verifyWireGuardTopology({ routers, links });
  assert.equal(result.status, 'unknown');
  assert.equal(result.links[0].endpoints.b.publicKey, null);
  assert.ok(codes(result).includes('missing-endpoint-public-key'));
});

test('reports missing AllowedIPs without treating them as verified', () => {
  const { routers } = makeRouters({ omitAllowedA: true });
  const result = verifyWireGuardTopology({ routers, links });
  assert.equal(result.status, 'review');
  assert.ok(codes(result).includes('missing-allowed-address-a-to-b'));
  assert.ok(!codes(result).includes('missing-allowed-address-b-to-a'));
});

test('reports missing routers, interfaces, and incomplete source arrays as unknown', () => {
  const missingRouter = verifyWireGuardTopology({ routers: makeRouters().routers, links: [{ ...links[0], deviceB: 'absent' }] });
  assert.ok(codes(missingRouter).includes('missing-router'));
  assert.equal(missingRouter.status, 'unknown');

  const noInterface = verifyWireGuardTopology({
    routers: [{ id: 'router-a', interfaces: [], peers: [] }, makeRouters().routers[1]], links,
  });
  assert.ok(codes(noInterface).includes('missing-interface'));

  const incomplete = verifyWireGuardTopology({ routers: [{ id: 'router-a', interfaces: [] }], links });
  assert.equal(incomplete.status, 'unknown');
  assert.ok(incomplete.findings.some((item) => item.code === 'incomplete-router-data'));
});

test('does not claim missing interfaces or peers when their source sections are unavailable or truncated', () => {
  const unavailableInterfaces = makeRouters().routers;
  unavailableInterfaces[0].interfaces = [];
  unavailableInterfaces[0].interfacesStatus = 'unavailable-or-not-permitted';
  const interfaceResult = verifyWireGuardTopology({ routers: unavailableInterfaces, links });
  assert.ok(codes(interfaceResult).includes('interface-data-unavailable'));
  assert.ok(!codes(interfaceResult).includes('missing-interface'));
  assert.equal(interfaceResult.status, 'unknown');

  const unavailablePeers = makeRouters().routers;
  unavailablePeers[0].peers = [];
  unavailablePeers[0].peersStatus = 'error';
  const peerResult = verifyWireGuardTopology({ routers: unavailablePeers, links });
  assert.ok(codes(peerResult).includes('peer-data-unavailable'));
  assert.ok(!codes(peerResult).includes('missing-peer-a-to-b'));
  assert.equal(peerResult.status, 'unknown');

  const truncatedPeers = makeRouters().routers;
  truncatedPeers[0].peers = [];
  truncatedPeers[0].peersTruncated = true;
  const truncatedResult = verifyWireGuardTopology({ routers: truncatedPeers, links });
  assert.ok(codes(truncatedResult).includes('peer-list-truncated'));
  assert.ok(!codes(truncatedResult).includes('missing-peer-a-to-b'));
  assert.equal(truncatedResult.status, 'unknown');
});

test('validates malformed, self, and duplicate links deterministically', () => {
  const { routers } = makeRouters();
  const result = verifyWireGuardTopology({
    routers,
    links: [null, links[0], { deviceA: 'router-a', interfaceA: 'wg-a', deviceB: 'router-a', interfaceB: 'wg-a' }, { ...links[0] }],
  });
  assert.deepEqual(result.links.map((link) => link.index), [0, 1, 2, 3]);
  assert.ok(codes(result).includes('malformed-link'));
  assert.ok(codes(result).includes('self-link'));
  assert.ok(codes(result).includes('duplicate-link'));
  assert.equal(result.links[1].status, 'verified');
  assert.equal(result.links[3].status, 'review');
});

test('limits output to 32 links and marks truncation unknown', () => {
  const { routers } = makeRouters();
  const many = Array.from({ length: 40 }, () => ({ ...links[0] }));
  const result = verifyWireGuardTopology({ routers, links: many });
  assert.equal(result.links.length, 32);
  assert.deepEqual(result.links.map((link) => link.index), Array.from({ length: 32 }, (_, index) => index));
  assert.equal(result.status, 'unknown');
  assert.ok(result.findings.some((item) => item.code === 'links-truncated-at-32'));
});

test('never returns private keys, preshared keys, counters, handshakes, or unrecognized fields', () => {
  const { routers } = makeRouters();
  routers[0].interfaces[0]['private-key'] = 'SECRET_PRIVATE_INTERFACE';
  routers[1].interfaces[0].surprise = 'SECRET_UNKNOWN_INTERFACE';
  routers[0].peers[0]['private-key'] = 'SECRET_PRIVATE_PEER';
  routers[0].peers[0]['preshared-key'] = 'SECRET_PRESHARED';
  routers[0].peers[0].surprise = 'SECRET_UNKNOWN_PEER';
  const serialized = JSON.stringify(verifyWireGuardTopology({ routers, links }));
  for (const secret of ['SECRET_PRIVATE_INTERFACE', 'SECRET_PRIVATE_PEER', 'SECRET_PRESHARED', 'SECRET_UNKNOWN_INTERFACE', 'SECRET_UNKNOWN_PEER']) {
    assert.ok(!serialized.includes(secret));
  }
  for (const forbiddenField of ['private-key', 'preshared-key', 'last-handshake', '"rx"', '"tx"', '"running"', '"disabled"', '"surprise"']) {
    assert.ok(!serialized.includes(forbiddenField));
  }
});

test('marks absent top-level input unknown', () => {
  const result = verifyWireGuardTopology({});
  assert.equal(result.status, 'unknown');
  assert.deepEqual(result.links, []);
  assert.deepEqual(result.findings.map((item) => item.code), ['incomplete-routers-input', 'incomplete-links-input']);
});
