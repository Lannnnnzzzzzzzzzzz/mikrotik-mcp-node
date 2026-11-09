import test from 'node:test';
import assert from 'node:assert/strict';
import { simulateIpv6RouteCandidates } from '../src/ipv6-route-simulation.js';

const coverage = (count) => ({ status: 'complete', recordCount: count, truncated: false });
const route = (id, dst, distance = 1, overrides = {}) => ({
  '.id': id,
  'dst-address': dst,
  'routing-table': 'main',
  distance,
  active: 'yes',
  disabled: 'no',
  ...overrides,
});
const simulate = (destination, routes, extra = {}) => simulateIpv6RouteCandidates({
  destination,
  routingTable: 'main',
  routes,
  coverage: coverage(routes.length),
  ...extra,
});

test('ranks by longest prefix before distance', () => {
  const result = simulate('2001:db8:1234::9', [
    route('*default', '::/0', 1),
    route('*broad', '2001:db8::/32', 1),
    route('*narrow-expensive', '2001:db8:1234::/48', 30),
    route('*best', '2001:db8:1234::/48', '5'),
    route('*other', '2001:db9::/32', 1),
  ]);
  assert.equal(result.status, 'matched');
  assert.deepEqual(result.rank, { prefixLength: 48, distance: 5 });
  assert.deepEqual(result.winners.map(({ id }) => id), ['*best']);
});

test('preserves every equal-cost winner', () => {
  const result = simulate('2001:db8:abcd::5', [
    route('*one', '2001:db8:abcd::/48', 10, { gateway: '2001:db8::1' }),
    route('*two', '2001:db8:abcd::/48', '10', { gateway: 'fe80::1234%ether1' }),
  ]);
  assert.equal(result.status, 'matched');
  assert.deepEqual(result.winners.map(({ id }) => id), ['*one', '*two']);
});

test('ignores explicitly disabled and inactive routes', () => {
  const result = simulate('2001:db8:1::10', [
    route('*disabled', '2001:db8:1::/48', 1, { disabled: 'yes' }),
    route('*inactive', '2001:db8:1::/48', 1, { active: 'no' }),
    route('*usable', '2001:db8:1::/48', 8),
  ]);
  assert.deepEqual(result.winners.map(({ id }) => id), ['*usable']);
});

test('isolates the requested routing table', () => {
  const result = simulate('2001:db8:55::5', [route('*other-table', '2001:db8:55::/48', 1, { 'routing-table': 'blue' })]);
  assert.equal(result.status, 'unmatched');
  assert.deepEqual(result.winners, []);
});

test('malformed IPv6 prefixes produce unknown, not partial ranking', () => {
  for (const invalidPrefix of ['2001:db8::/129', '2001:db8::/-1', '2001:db8::/024', '2001:db8::']) {
    const result = simulate('2001:db8::1', [route('*good', '2001:db8::/32'), route('*bad', invalidPrefix)]);
    assert.equal(result.status, 'unknown', invalidPrefix);
    assert.equal(result.winners, null);
  }
});

test('route list above 500 records is unknown', () => {
  const routes = Array.from({ length: 501 }, (_, index) => route(`*${index}`, '::/0'));
  const result = simulate('2001:db8::1', routes);
  assert.equal(result.status, 'unknown');
  assert.equal(result.winners, null);
  assert.match(result.uncertainty[0], /500-record/);
});

test('missing, unsupported, inconsistent, or truncated coverage is unknown', () => {
  const routes = [route('*candidate', '2001:db8::/32')];
  for (const candidateCoverage of [undefined, 'partial', { status: 'error' }, { status: 'complete', truncated: true }, { status: 'complete', recordCount: 2 }]) {
    const result = simulate('2001:db8::1', routes, { coverage: candidateCoverage });
    assert.equal(result.status, 'unknown');
    assert.equal(result.winners, null);
  }
});

test('redacts destination, route prefixes, and gateways from result', () => {
  const sensitiveAddress = '2001:db8:feed::cafe';
  const sensitiveGateway = 'fe80::dead:beef%ether1';
  const result = simulate(sensitiveAddress, [route('*opaque-route-id', `${sensitiveAddress}/128`, 1, { gateway: sensitiveGateway })]);
  const serialized = JSON.stringify(result);
  assert.equal(result.status, 'matched');
  assert.equal(result.destination, '[redacted IPv6 address]');
  assert.equal(result.winners[0].id, '*opaque-route-id');
  assert.doesNotMatch(serialized, /2001:db8:feed::cafe|fe80::dead:beef/);
  assert.ok(!('gateway' in result.winners[0]));
  assert.ok(!('dst-address' in result.winners[0]));
});

test('invalid destinations stay unknown and result never claims forwarding', () => {
  for (const destination of ['2001:db8::/64', '2001:db8::gg', '192.0.2.1']) {
    assert.equal(simulate(destination, []).status, 'unknown');
  }
  const result = simulate('2001:db8::1', []);
  assert.equal(result.status, 'unmatched');
  assert.ok(!('forwarding' in result));
  assert.ok(!('reachable' in result));
});
