import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFirewallOrderAudit } from '../src/firewall-order-audit.js';

function sections(overrides = {}) {
  return {
    firewall_filter: { status: 'available', records: [] },
    ipv6_firewall_filter: { status: 'available', records: [] },
    ...overrides,
  };
}

function rule(id, fields = {}) {
  return { '.id': id, chain: 'forward', action: 'accept', disabled: 'no', ...fields };
}

test('reports possible shadowing only when an earlier terminal rule covers a later rule in the same chain', () => {
  const report = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'available', records: [
      rule('*1', { action: 'drop', 'src-address': '192.0.2.0/24' }),
      rule('*2', { action: 'accept', 'src-address': '192.0.2.7', protocol: 'tcp', 'dst-port': '443' }),
      rule('*3', { chain: 'input', action: 'reject', 'src-address': '192.0.2.7' }),
      rule('*4', { action: 'log', 'src-address': '192.0.2.7' }),
    ] },
  }) });

  assert.equal(report.findings.length, 2);
  assert.deepEqual(report.findings.map(({ earlierRule, laterRule, chain }) => [earlierRule.index, laterRule.index, chain]), [
    [0, 1, 'forward'],
    [0, 3, 'forward'],
  ]);
  assert.equal(report.findings[0].type, 'possible-shadowing');
  assert.equal(report.indeterminate.length, 0);
  assert.ok(report.findings[0].limitation.includes('not a RouterOS packet-path simulation'));
  assert.equal(JSON.stringify(report).includes('comment-secret'), false);
});

test('does not infer shadowing across chains or when the earlier rule is narrower or has a different exact match', () => {
  const report = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'available', records: [
      rule('*1', { action: 'drop', 'src-address': '192.0.2.8', protocol: 'tcp' }),
      rule('*2', { action: 'accept', 'src-address': '192.0.2.0/24', protocol: 'tcp' }),
      rule('*3', { action: 'accept', 'src-address': '192.0.2.8', protocol: 'udp' }),
      rule('*4', { chain: 'input', action: 'accept', 'src-address': '192.0.2.8' }),
    ] },
  }) });
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.indeterminate, []);
});

test('treats unsupported, list/state-based, unknown, jump, and dynamic rules as indeterminate rather than proof', () => {
  const report = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'available', records: [
      rule('*1', { action: 'accept', 'src-address-list': 'trusted' }),
      rule('*2', { action: 'drop', 'src-address': '198.51.100.4' }),
      rule('*3', { action: 'accept', 'connection-state': 'new' }),
      rule('*4', { action: 'drop', 'src-address': '198.51.100.8' }),
      rule('*5', { action: 'jump', 'jump-target': 'custom' }),
      rule('*6', { action: 'accept', 'src-address': '198.51.100.9' }),
      rule('*7', { action: 'accept', 'src-address': '198.51.100.10', dynamic: 'yes' }),
      rule('*8', { action: 'drop', 'src-address': '198.51.100.11', 'mystery-match': 'x' }),
      rule('*9', { action: 'fasttrack-connection', 'src-address': '198.51.100.12' }),
    ] },
    ipv6_firewall_filter: { status: 'available', records: [
      rule('*v1', { 'src-address': '2001:db8::/32' }),
      rule('*v2', { 'src-address': '2001:db8::1' }),
    ] },
  }) });
  assert.deepEqual(report.findings, []);
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'unsupported-list-or-state-match'));
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'unknown-match-property'));
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'jump-or-return-semantics'));
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'dynamic-rule'));
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'unsupported-action-semantics'));
  assert.ok(report.indeterminate.some(({ reason }) => reason === 'unsupported-address-match'));
});

test('disabled rules do not shadow; unknown enabled state and unsupported later conditions are indeterminate', () => {
  const report = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'available', records: [
      rule('*1', { action: 'accept', disabled: 'yes' }),
      rule('*2', { action: 'drop', 'src-address': '203.0.113.2' }),
      rule('*3', { action: 'accept', disabled: undefined }),
      rule('*4', { action: 'drop', 'src-address': '203.0.113.3' }),
      rule('*5', { action: 'accept', 'dst-address-list': 'blocked' }),
    ] },
  }) });
  assert.deepEqual(report.findings, []);
  assert.ok(report.indeterminate.some(({ reason, earlierIndex }) => reason === 'unknown-disabled-state' && earlierIndex === 2));
  assert.ok(report.indeterminate.some(({ reason, laterIndex }) => reason === 'unsupported-list-or-state-match' && laterIndex === 4));
});

test('refuses proof for unavailable, truncated, duplicated-id, or malformed-order snapshots', () => {
  const report = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'available', truncated: true, records: [
      rule('*1', { action: 'accept' }),
      rule('*2', { action: 'drop' }),
    ] },
    ipv6_firewall_filter: { status: 'available', records: [
      rule('*v1', { action: 'accept' }),
      rule('*v1', { action: 'drop' }),
    ] },
  }) });
  assert.deepEqual(report.findings, []);
  assert.equal(report.coverage.sections.firewall_filter.completeOrder, false);
  assert.equal(report.coverage.sections.ipv6_firewall_filter.completeOrder, false);
  assert.equal(report.indeterminate.length, 2);
  assert.ok(report.indeterminate.every(({ reason }) => reason === 'incomplete-or-malformed-order'));

  const unavailable = buildFirewallOrderAudit({ sections: sections({
    firewall_filter: { status: 'unavailable-or-not-permitted' },
  }) });
  assert.equal(unavailable.coverage.sections.firewall_filter.status, 'unavailable-or-not-permitted');
  assert.deepEqual(unavailable.findings, []);
});
