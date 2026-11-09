import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRoutingProtocolAudit } from '../src/routing-audit.js';

const KEYS = ['routes', 'bgp_sessions', 'ospf_neighbors', 'rip_neighbors', 'rip_routes', 'routing_bfd_peers'];

function sections(overrides = {}) {
  return {
    ...Object.fromEntries(KEYS.map((key) => [key, { status: 'available', records: [] }])),
    ...overrides,
  };
}

test('summarizes available route and protocol rows without reporting healthy states as findings', () => {
  const report = buildRoutingProtocolAudit({
    device: { id: 'router-7', name: 'edge', password: 'must-not-pass' },
    sections: sections({
      routes: { status: 'available', records: [
        { '.id': '*1', 'dst-address': '0.0.0.0/0', active: 'yes', disabled: 'no' },
        { '.id': '*2', 'dst-address': '198.51.100.0/24', active: 'no' },
        { '.id': '*3', 'dst-address': '203.0.113.0/24' },
      ] },
      bgp_sessions: { status: 'available', records: [{ name: 'upstream', state: 'established', established: 'true' }] },
      ospf_neighbors: { status: 'available', records: [{ 'router-id': '192.0.2.2', state: 'Full' }] },
      routing_bfd_peers: { status: 'available', records: [{ 'remote-address': '192.0.2.3', state: 'Up' }] },
      rip_neighbors: { status: 'available', records: [{ address: '192.0.2.4' }] },
      rip_routes: { status: 'available', records: [{ 'dst-address': '10.0.0.0/8', metric: '2' }] },
    }),
  });

  assert.deepEqual(report.routeTotals, { active: 1, inactive: 1, unknown: 1 });
  assert.deepEqual(report.protocolCounts, {
    bgp_sessions: 1, ospf_neighbors: 1, rip_neighbors: 1, rip_routes: 1, routing_bfd_peers: 1,
  });
  assert.equal(report.coverage.counts.available, 6);
  assert.deepEqual(report.findings, []);
  assert.equal(report.device.id, 'router-7');
  assert.equal(JSON.stringify(report).includes('must-not-pass'), false);
  assert.ok(report.notes.some((note) => /does not simulate route lookup/.test(note)));
  assert.ok(report.notes.some((note) => /RIP is reported as observed/.test(note)));
});

test('reports explicitly down BGP, non-Full OSPF, and non-Up BFD with evidence and limitations', () => {
  const report = buildRoutingProtocolAudit({ sections: sections({
    bgp_sessions: { status: 'available', records: [{ '.id': '*a', name: 'peer-a', established: false, state: 'idle' }] },
    ospf_neighbors: { status: 'available', records: [{ 'router-id': '192.0.2.9', state: '2-Way' }] },
    routing_bfd_peers: { status: 'available', records: [{ 'remote-address': '192.0.2.10', state: 'Down' }] },
  }) });

  assert.deepEqual(report.findings.map(({ type, section }) => [type, section]), [
    ['bgp-not-established', 'bgp_sessions'],
    ['ospf-not-full', 'ospf_neighbors'],
    ['bfd-not-up', 'routing_bfd_peers'],
  ]);
  for (const finding of report.findings) {
    assert.ok(finding.evidence && typeof finding.evidence === 'object');
    assert.match(finding.limitation, /does not test end-to-end reachability/);
  }
});

test('unavailable sections remain unknown and are not treated as healthy or empty', () => {
  const report = buildRoutingProtocolAudit({ sections: sections({
    bgp_sessions: { status: 'unavailable-or-not-permitted' },
    routes: { status: 'unavailable-or-not-permitted', records: [] },
    ospf_neighbors: { status: 'error' },
  }) });

  assert.equal(report.coverage.counts['unavailable-or-not-permitted'], 2);
  assert.equal(report.coverage.counts.error, 1);
  assert.equal(report.coverage.sections.bgp_sessions.recordCount, null);
  assert.equal(report.protocolCounts.bgp_sessions, null);
  assert.deepEqual(report.routeTotals, { active: null, inactive: null, unknown: null });
  assert.deepEqual(report.findings, []);
});

test('missing state and route flags stay unknown rather than generating healthy findings', () => {
  const report = buildRoutingProtocolAudit({ sections: sections({
    routes: { status: 'available', records: [{ 'dst-address': '192.0.2.0/24' }] },
    bgp_sessions: { status: 'available', records: [{ name: 'state-not-collected' }] },
    ospf_neighbors: { status: 'available', records: [{ 'router-id': '192.0.2.8' }] },
    routing_bfd_peers: { status: 'available', records: [{ 'remote-address': '192.0.2.7' }] },
  }) });

  assert.deepEqual(report.routeTotals, { active: 0, inactive: 0, unknown: 1 });
  assert.deepEqual(report.findings, []);
  assert.equal(report.protocolCounts.bgp_sessions, 1);
  assert.equal(report.coverage.sections.bgp_sessions.validRecordCount, 1);
});

test('malformed top-level and section inputs are handled without throwing or implying empty health', () => {
  const emptyMalformed = buildRoutingProtocolAudit(null);
  assert.equal(emptyMalformed.coverage.counts.error, 6);
  assert.deepEqual(emptyMalformed.routeTotals, { active: null, inactive: null, unknown: null });

  const malformed = buildRoutingProtocolAudit({ sections: sections({
    routes: { status: 'available', records: { not: 'an array' } },
    bgp_sessions: { status: 'healthy', records: [] },
  }) });
  assert.equal(malformed.coverage.sections.routes.status, 'error');
  assert.equal(malformed.coverage.sections.routes.recordCount, null);
  assert.equal(malformed.coverage.sections.bgp_sessions.status, 'error');
  assert.equal(malformed.protocolCounts.bgp_sessions, null);
});

test('only allowlisted fields are projected and secret inputs never leak, including in finding evidence', () => {
  const report = buildRoutingProtocolAudit({
    device: { id: 'router-1', name: 'edge', address: '192.0.2.1', password: 'device-password' },
    sections: sections({
      bgp_sessions: { status: 'available', records: [{
        '.id': '*1', name: 'peer', 'remote.address': '198.51.100.4', state: 'idle',
        password: 'pw-value', secret: 'secret-value', 'shared-secret': 'shared-value',
        'private-key': 'private-key-value', token: 'token-value', arbitrary: 'extra-value',
      }] },
      ospf_neighbors: { status: 'available', records: [{ state: 'Down', 'private-key': 'ospf-private-value' }] },
    }),
  });
  const serialized = JSON.stringify(report).toLowerCase();

  for (const forbidden of ['device-password', 'pw-value', 'secret-value', 'shared-value', 'private-key-value', 'token-value', 'extra-value', 'ospf-private-value']) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} leaked`);
  }
  assert.deepEqual(report.findings[0].evidence, {
    '.id': '*1', name: 'peer', 'remote.address': '198.51.100.4', state: 'idle',
  });
  assert.equal(report.findings.length, 2);
  for (const finding of report.findings) assert.ok(finding.limitation);
});
