import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDhcpIntegrityAudit } from '../src/dhcp-integrity-audit.js';

const KEYS = ['dhcp_servers', 'dhcp_networks', 'ip_pools_dhcp', 'dhcp_leases'];

function sections(overrides = {}) {
  return {
    ...Object.fromEntries(KEYS.map((key) => [key, { status: 'available', records: [] }])),
    ...overrides,
  };
}

function fullSections(overrides = {}) {
  return sections({
    dhcp_servers: { status: 'available', records: [{ name: 'lan-dhcp', 'address-pool': 'lan-pool', disabled: 'no' }] },
    dhcp_networks: { status: 'available', records: [{ address: '10.20.0.0/24' }] },
    ip_pools_dhcp: { status: 'available', records: [{ name: 'lan-pool', ranges: '10.20.0.10-10.20.0.100' }] },
    dhcp_leases: { status: 'available', records: [{ address: '10.20.0.201', server: 'lan-dhcp', dynamic: 'no' }] },
    ...overrides,
  });
}

test('valid DHCP snapshot allows pool containment and a static lease outside its dynamic range', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections() });
  assert.deepEqual(report.findings, []);
  assert.equal(report.coverage.partial, false);
  assert.deepEqual(report.coverage.sections.ip_pools_dhcp, { status: 'available', recordCount: 1, complete: true });
  assert.deepEqual(report.counts, {});
});

test('reports a missing pool but does not treat a static lease outside its pool as an error', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    dhcp_servers: { status: 'available', records: [
      { name: 'lan-dhcp', 'address-pool': 'lan-pool', disabled: 'no' },
      { name: 'other-dhcp', 'address-pool': 'absent-pool', disabled: 'no' },
    ] },
    dhcp_networks: { status: 'available', records: [{ address: '10.20.0.0/24' }] },
    ip_pools_dhcp: { status: 'available', records: [{ name: 'lan-pool', ranges: '10.20.0.10-10.20.0.100' }] },
    dhcp_leases: { status: 'available', records: [{ address: '10.20.0.201', server: 'lan-dhcp', dynamic: 'no' }] },
  }) });

  assert.deepEqual(report.findings.map(({ severity, code, section, index }) => [severity, code, section, index]), [
    ['warning', 'referenced-pool-missing', 'dhcp_servers', 1],
  ]);
  assert.ok(report.findings.every(({ count }) => count === 1));
});

test('flags a static lease outside every fully observed DHCP network, not merely outside the pool', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    dhcp_leases: { status: 'available', records: [{ address: '10.21.0.201', server: 'lan-dhcp', dynamic: 'no' }] },
  }) });
  assert.ok(report.findings.some(({ code, section, index }) =>
    code === 'static-lease-outside-dhcp-network' && section === 'dhcp_leases' && index === 0));
});

test('flags pools outside every complete DHCP network and overlapping configured pool ranges', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    ip_pools_dhcp: { status: 'available', records: [
      { name: 'lan-pool', ranges: '10.20.0.10-10.20.0.100' },
      { name: 'overlap-pool', ranges: '10.20.0.90-10.20.0.150' },
      { name: 'outside-pool', ranges: '192.0.2.10-192.0.2.20' },
    ] },
  }) });
  assert.deepEqual(report.findings.map(({ code, section, index }) => [code, section, index]), [
    ['pool-outside-dhcp-network', 'ip_pools_dhcp', 2],
    ['overlapping-pool-ranges', 'ip_pools_dhcp', 1],
  ]);
});

test('unavailable and partial coverage stay indeterminate and do not prove absent pools', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    ip_pools_dhcp: { status: 'unavailable-or-not-permitted' },
    dhcp_networks: { status: 'available', truncated: true, records: [{ address: '10.20.0.0/24' }] },
  }) });
  assert.equal(report.coverage.sections.ip_pools_dhcp.status, 'unavailable-or-not-permitted');
  assert.equal(report.coverage.sections.dhcp_networks.complete, false);
  assert.equal(report.coverage.partial, true);
  assert.equal(report.findings.some(({ code }) => code === 'referenced-pool-missing'), false);
  assert.ok(report.findings.some(({ code }) => code === 'section-unavailable'));
  assert.ok(report.findings.some(({ code }) => code === 'partial-section'));
  assert.ok(report.findings.some(({ code }) => code === 'pool-reference-unverifiable'));
});

test('unknown formats, dynamic pools, duplicate references, and malformed records remain indeterminate', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    dhcp_servers: { status: 'available', records: [
      { name: 'lan-dhcp', 'address-pool': 'lan-pool', disabled: 'no' },
      { name: 'dyn-dhcp', 'address-pool': 'dynamic-pool', disabled: 'no' },
      null,
    ] },
    dhcp_networks: { status: 'available', records: [{ address: 'dhcp-network-expression' }] },
    ip_pools_dhcp: { status: 'available', records: [
      { name: 'lan-pool', ranges: '10.20.0.10-10.20.0.100' },
      { name: 'dynamic-pool', ranges: '10.30.0.2-10.30.0.80', 'next-pool': 'next' },
      { name: 'broken-pool', ranges: 'pool-range-varies' },
    ] },
    dhcp_leases: { status: 'available', records: [
      { address: '10.20.0.20', server: 'lan-dhcp', dynamic: 'yes' },
      { address: 'not-an-ip', server: 'lan-dhcp', dynamic: 'no' },
    ] },
  }) });
  const codes = report.findings.map(({ code }) => code);
  assert.ok(codes.includes('malformed-record'));
  assert.ok(codes.includes('unsupported-or-malformed-network'));
  assert.ok(codes.includes('unsupported-or-malformed-pool'));
  assert.ok(codes.includes('unsupported-referenced-pool'));
  assert.equal(codes.includes('dynamic-lease'), false);
  assert.ok(codes.includes('unsupported-or-malformed-static-lease'));
  assert.equal(codes.includes('pool-network-ipv4-overlap'), false);
});

test('every emitted finding is redacted to severity, code, section/index metadata, and count', () => {
  const report = buildDhcpIntegrityAudit({ sections: fullSections({
    dhcp_servers: { status: 'available', records: [{
      name: 'private-hostname-secret', 'address-pool': 'missing-private-pool', disabled: 'no',
      comment: 'server-comment-secret', 'mac-address': 'aa:bb:cc:dd:ee:ff',
    }] },
    dhcp_networks: { status: 'available', records: [{ address: '192.0.2.0/24', comment: 'network-comment-secret' }] },
    ip_pools_dhcp: { status: 'available', records: [] },
    dhcp_leases: { status: 'available', records: [{
      address: '192.0.2.45', server: 'private-hostname-secret', dynamic: 'no',
      'host-name': 'client-name-secret', 'mac-address': '11:22:33:44:55:66', comment: 'lease-comment-secret',
    }] },
  }) });
  const serialized = JSON.stringify(report).toLowerCase();
  for (const secret of [
    'private-hostname-secret', 'missing-private-pool', 'server-comment-secret',
    'network-comment-secret', 'client-name-secret', 'lease-comment-secret',
    'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66', '192.0.2.45',
  ]) assert.equal(serialized.includes(secret), false, `${secret} leaked`);
  for (const finding of report.findings) {
    assert.deepEqual(Object.keys(finding).sort(), ['code', 'count', 'index', 'section', 'severity']);
  }
});

test('malformed top-level and available-section shapes do not throw or imply empty coverage', () => {
  const malformedTop = buildDhcpIntegrityAudit(null);
  assert.equal(malformedTop.coverage.partial, true);
  assert.equal(malformedTop.findings.filter(({ code }) => code === 'section-error').length, 4);

  const malformedSection = buildDhcpIntegrityAudit({ sections: sections({
    dhcp_servers: { status: 'available', records: { not: 'an array' } },
    dhcp_networks: { status: 'healthy', records: [] },
  }) });
  assert.equal(malformedSection.coverage.sections.dhcp_servers.status, 'error');
  assert.equal(malformedSection.coverage.sections.dhcp_networks.status, 'error');
});

test('caps per-section record processing and total findings', () => {
  const rows = Array.from({ length: 2001 }, (_, index) => ({ name: `pool-${index}`, ranges: '10.0.0.1-10.0.0.2' }));
  const report = buildDhcpIntegrityAudit({ sections: sections({
    dhcp_networks: { status: 'available', records: [{ address: '10.0.0.0/24' }] },
    ip_pools_dhcp: { status: 'available', records: rows },
  }) });
  assert.equal(report.coverage.sections.ip_pools_dhcp.recordCount, 2001);
  assert.equal(report.coverage.sections.ip_pools_dhcp.complete, false);
  assert.ok(report.findings.some(({ code }) => code === 'record-limit-exceeded'));
  assert.ok(report.findings.length <= 500);
  assert.equal(report.findingsTruncated, true);
  assert.equal(report.limits.maxRecordsPerSection, 2000);
});
