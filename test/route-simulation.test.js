import test from 'node:test';
import assert from 'node:assert/strict';
import { simulateIpv4RouteCandidates } from '../src/route-simulation.js';

const route = (id, dst, distance = 1, overrides = {}) => ({
  '.id': id,
  'dst-address': dst,
  'routing-table': 'main',
  distance,
  active: 'yes',
  disabled: 'no',
  ...overrides,
});

test('validates IPv4 destination and CIDR, then ranks by longest prefix before distance', () => {
  const result = simulateIpv4RouteCandidates({
    destination: '10.12.4.9',
    routingTable: 'main',
    routes: [
      route('*default', '0.0.0.0/0', 1),
      route('*broad', '10.0.0.0/8', 1),
      route('*narrow-expensive', '10.12.4.0/24', 30),
      route('*best', '10.12.4.0/24', '5'),
      route('*other', '192.0.2.0/24', 1),
    ],
  });

  assert.equal(result.status, 'matched');
  assert.deepEqual(result.rank, { prefixLength: 24, distance: 5 });
  assert.deepEqual(result.winners.map(({ id }) => id), ['*best']);
  assert.equal(result.uncertainty.length, 0);
});

test('preserves every equal-prefix, equal-distance winner', () => {
  const result = simulateIpv4RouteCandidates({
    destination: '192.0.2.5', routingTable: 'main',
    routes: [route('*one', '192.0.2.0/24', 10), route('*two', '192.0.2.0/24', '10')],
  });
  assert.equal(result.status, 'matched');
  assert.deepEqual(result.winners.map(({ id }) => id), ['*one', '*two']);
});

test('ignores explicitly disabled and inactive routes', () => {
  const result = simulateIpv4RouteCandidates({
    destination: '203.0.113.8', routingTable: 'main',
    routes: [
      route('*disabled', '203.0.113.0/24', 1, { disabled: 'yes' }),
      route('*inactive', '203.0.113.0/24', 1, { active: 'no' }),
      route('*usable', '203.0.113.0/24', 8),
    ],
  });
  assert.deepEqual(result.winners.map(({ id }) => id), ['*usable']);
});

test('isolates the explicitly requested routing table', () => {
  const result = simulateIpv4RouteCandidates({
    destination: '198.51.100.3', routingTable: 'main',
    routes: [route('*other-table', '198.51.100.0/24', 1, { 'routing-table': 'blue' })],
  });
  assert.equal(result.status, 'unmatched');
  assert.deepEqual(result.winners, []);
});

test('returns unknown rather than selecting when potentially relevant evidence is incomplete', () => {
  for (const badRoute of [
    route('*missing-active', '10.0.0.0/8', 1, { active: undefined }),
    route('*bad-cidr', '10.0.0.0/33', 1),
    route('*missing-distance', '10.0.0.0/8', null),
    route('*missing-table', '10.0.0.0/8', 1, { 'routing-table': undefined }),
  ]) {
    const result = simulateIpv4RouteCandidates({
      destination: '10.4.5.6', routingTable: 'main',
      routes: [route('*apparently-good', '10.4.5.0/24', 1), badRoute],
    });
    assert.equal(result.status, 'unknown');
    assert.equal(result.winners, null);
    assert.ok(result.uncertainty.length > 0);
  }
});

test('invalid query inputs and malformed route collections stay unknown', () => {
  assert.equal(simulateIpv4RouteCandidates(null).status, 'unknown');
  assert.equal(simulateIpv4RouteCandidates({ destination: '256.1.1.1', routingTable: 'main', routes: [] }).status, 'unknown');
  assert.equal(simulateIpv4RouteCandidates({ destination: '192.0.2.1/24', routingTable: 'main', routes: [] }).status, 'unknown');
  assert.equal(simulateIpv4RouteCandidates({ destination: '192.0.2.1', routes: [] }).status, 'unknown');
  assert.equal(simulateIpv4RouteCandidates({ destination: '192.0.2.1', routingTable: 'main', routes: {} }).status, 'unknown');
  assert.equal(simulateIpv4RouteCandidates({
    destination: '192.0.2.1', routingTable: 'main', routes: [route('*bad-octet', '192.0.2.999/24')],
  }).status, 'unknown');
});

test('reports an unmatched lookup only when no uncertainty exists and states key limitations', () => {
  const result = simulateIpv4RouteCandidates({ destination: '192.0.2.1', routingTable: 'main', routes: [] });
  assert.equal(result.status, 'unmatched');
  assert.deepEqual(result.winners, []);
  assert.ok(result.limitations.some((limitation) => /recursive next-hop/i.test(limitation)));
  assert.ok(result.limitations.some((limitation) => /Routing rules and VRF/.test(limitation)));
  assert.ok(result.limitations.some((limitation) => /not RouterOS-equivalent/.test(limitation)));
});
