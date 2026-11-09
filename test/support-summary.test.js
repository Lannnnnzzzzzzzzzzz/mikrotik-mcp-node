import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRouterSupportSummary } from '../src/support-summary.js';

const SECTION_KEYS = [
  'interfaces', 'ip_addresses', 'routes', 'firewall_filter', 'firewall_nat', 'dhcp_leases',
  'wireguard_peers', 'wireless_registrations', 'legacy_capsman_registrations', 'wifi_registrations',
];

function sections(overrides = {}) {
  return {
    ...Object.fromEntries(SECTION_KEYS.map((key) => [key, { status: 'available', records: [] }])),
    ...overrides,
  };
}

test('aggregates only the requested RouterOS support counts', () => {
  const report = buildRouterSupportSummary({
    device: { id: 'router-7', name: 'must-not-return' },
    identity: { name: 'edge-router', 'serial-number': 'not-allowed' },
    resources: {
      version: '7.16.2', uptime: '2d', cpu: 'ARM', 'cpu-count': '4', 'board-name': 'hAP',
      'architecture-name': 'arm', 'free-memory': '100', 'total-memory': '200', password: 'resource-secret',
    },
    sections: sections({
      interfaces: { status: 'available', records: [
        { name: 'wan-secret', running: 'yes', disabled: 'no', mac: 'aa:bb:cc' },
        { name: 'lan-secret', running: false, disabled: true },
        { name: 'unknown-flags' },
      ] },
      ip_addresses: { status: 'available', records: [
        { address: '192.0.2.10/24', disabled: 'no' },
        { address: '198.51.100.8/24', disabled: true },
        { address: '2001:db8::1/64', disabled: false },
      ] },
      routes: { status: 'available', records: [
        { 'dst-address': '0.0.0.0/0', active: 'yes', disabled: 'no', gateway: '203.0.113.1' },
        { 'dst-address': '0.0.0.0/0', active: 'no', disabled: 'yes' },
        { 'dst-address': '10.0.0.0/8', active: 'yes', disabled: 'no' },
      ] },
      firewall_filter: { status: 'available', records: [{ disabled: 'no', comment: 'filter-secret' }, { disabled: 'yes' }] },
      firewall_nat: { status: 'available', records: [{ disabled: false }] },
      dhcp_leases: { status: 'available', records: [
        { status: 'bound', 'host-name': 'client-secret' }, { status: 'waiting' }, { status: 'DECLINED' },
      ] },
      wireguard_peers: { status: 'available', records: [{ disabled: 'no', 'public-key': 'key-secret' }, { disabled: true }] },
      wireless_registrations: { status: 'available', records: [{ mac: 'wireless-mac-secret' }] },
      legacy_capsman_registrations: { status: 'available', records: [{ ssid: 'ssid-secret' }, {}] },
      wifi_registrations: { status: 'available', records: [] },
    }),
  });

  assert.equal(report.deviceId, 'router-7');
  assert.equal(report.identityName, 'edge-router');
  assert.deepEqual(report.system, {
    version: '7.16.2', uptime: '2d', cpu: 'ARM', 'cpu-count': '4', 'board-name': 'hAP',
    'architecture-name': 'arm', 'free-memory': '100', 'total-memory': '200',
  });
  assert.deepEqual(report.counts.interfaces, { total: 3, running: 1, disabled: 1, partial: true });
  assert.deepEqual(report.counts.ipv4Addresses, { total: 2, disabled: 1, partial: false });
  assert.deepEqual(report.counts.defaultIpv4Routes, { total: 2, active: 1, disabled: 1, partial: false });
  assert.deepEqual(report.counts.firewallFilterRules, { total: 2, disabled: 1, partial: false });
  assert.deepEqual(report.counts.firewallNatRules, { total: 1, disabled: 0, partial: false });
  assert.deepEqual(report.counts.dhcpLeases, {
    total: 3,
    byStatus: { bound: 1, waiting: 1, offered: 0, declined: 1, expired: 0, busy: 0, unknown: 0, other: 0 },
    partial: false,
  });
  assert.deepEqual(report.counts.wireguardPeers, { total: 2, disabled: 1, partial: false });
  assert.deepEqual(report.counts.wirelessRegistrations, {
    bySource: { wireless: 1, legacy_capsman: 2, wifi: 0 }, total: 3, partial: false,
  });
  assert.equal(report.coverage.sections.interfaces.recordCount, 3);
  assert.match(report.notes.join(' '), /not a full configuration export or support bundle/);
  assert.match(report.notes.join(' '), /contains no history/);
});

test('unavailable, missing, and truncated sections are not represented as complete healthy counts', () => {
  const report = buildRouterSupportSummary({ sections: sections({
    interfaces: { status: 'unavailable-or-not-permitted' },
    routes: { status: 'error' },
    firewall_filter: { status: 'available', records: [{ disabled: false }], truncated: true, total: 50 },
    wireless_registrations: { status: 'available', records: [{ mac: 'hidden' }], truncated: true },
    wifi_registrations: undefined,
  }) });

  assert.equal(report.coverage.sections.interfaces.status, 'unavailable-or-not-permitted');
  assert.deepEqual(report.counts.interfaces, { total: null, running: null, disabled: null, partial: true });
  assert.deepEqual(report.counts.defaultIpv4Routes, { total: null, active: null, disabled: null, partial: true });
  assert.equal(report.coverage.sections.firewall_filter.truncated, true);
  assert.equal(report.coverage.sections.firewall_filter.total, 50);
  assert.deepEqual(report.counts.firewallFilterRules, { total: 1, disabled: 0, partial: true });
  assert.equal(report.counts.wirelessRegistrations.bySource.wireless, 1);
  assert.equal(report.counts.wirelessRegistrations.bySource.legacy_capsman, 0);
  assert.equal(report.counts.wirelessRegistrations.bySource.wifi, null);
  assert.equal(report.counts.wirelessRegistrations.partial, true);
});

test('malformed rows and malformed section shapes mark results partial or error without throwing', () => {
  const report = buildRouterSupportSummary({ sections: sections({
    interfaces: { status: 'available', records: [null, 'bad-row', { running: true, disabled: false }] },
    ip_addresses: { status: 'available', records: [{ address: 'not-an-ip', disabled: false }] },
    routes: { status: 'available', records: [{ active: true, disabled: false }] },
    firewall_nat: { status: 'available', records: { not: 'an array' } },
  }) });

  assert.equal(report.coverage.sections.interfaces.status, 'available');
  assert.equal(report.coverage.sections.interfaces.validRecordCount, 1);
  assert.deepEqual(report.counts.interfaces, { total: 1, running: 1, disabled: 0, partial: true });
  assert.deepEqual(report.counts.ipv4Addresses, { total: 0, disabled: 0, partial: true });
  assert.deepEqual(report.counts.defaultIpv4Routes, { total: 0, active: 0, disabled: 0, partial: true });
  assert.equal(report.coverage.sections.firewall_nat.status, 'error');
  assert.deepEqual(report.counts.firewallNatRules, { total: null, disabled: null, partial: true });
  assert.equal(buildRouterSupportSummary(null).coverage.sections.interfaces.status, 'error');
});

test('does not serialize IPs, MACs, names, comments, keys, secrets, or unapproved input fields', () => {
  const report = buildRouterSupportSummary({
    device: { id: 'device-id', address: '192.0.2.1', password: 'device-password', arbitrary: 'device-extra' },
    identity: { name: 'safe-name', 'serial-number': 'serial-secret' },
    resources: { version: '7.1', token: 'resource-token', secret: 'resource-secret', custom: 'resource-extra' },
    sections: sections({
      interfaces: { status: 'available', records: [{ name: 'interface-secret', mac: 'mac-secret', running: true, disabled: false }] },
      ip_addresses: { status: 'available', records: [{ address: '198.51.100.8/24', interface: 'interface-secret', disabled: false }] },
      routes: { status: 'available', records: [{ 'dst-address': '0.0.0.0/0', gateway: 'gateway-secret', active: true, disabled: false }] },
      firewall_filter: { status: 'available', records: [{ comment: 'comment-secret', disabled: false }] },
      dhcp_leases: { status: 'available', records: [{ status: 'bound', 'host-name': 'hostname-secret', 'mac-address': 'lease-mac-secret' }] },
      wireguard_peers: { status: 'available', records: [{ 'private-key': 'private-key-secret', presharedKey: 'preshared-secret', disabled: false }] },
      wireless_registrations: { status: 'available', records: [{ ssid: 'ssid-secret', mac: 'radio-mac-secret' }] },
    }),
  });
  const serialized = JSON.stringify(report);
  for (const forbidden of [
    '192.0.2.1', '198.51.100.8', 'device-password', 'device-extra', 'serial-secret', 'resource-token',
    'resource-secret', 'resource-extra', 'interface-secret', 'mac-secret', 'gateway-secret', 'comment-secret',
    'hostname-secret', 'lease-mac-secret', 'private-key-secret', 'preshared-secret', 'ssid-secret', 'radio-mac-secret',
  ]) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} leaked`);
  }
  assert.deepEqual(Object.keys(report.system), ['version']);
  assert.equal(report.deviceId, 'device-id');
  assert.equal(report.identityName, 'safe-name');
});
