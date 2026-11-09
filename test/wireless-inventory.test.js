import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWirelessInventory } from '../src/wireless-inventory.js';

const available = (records = []) => ({ status: 'available', records });

function baseSections(overrides = {}) {
  return {
    legacyWireless: available(),
    legacyCapsman: available(),
    wifi: available(),
    ...overrides,
  };
}

test('projects legacy wireless, legacy CAPsMAN, and shared new WiFi registration sources', () => {
  const report = buildWirelessInventory({
    device: { id: 'router-1', name: 'edge', password: 'do-not-copy' },
    sampledAt: new Date('2026-11-09T00:00:00Z'),
    sections: baseSections({
      legacyWireless: available([{
        '.id': '*1', interface: 'wlan1', 'mac-address': '00:11:22:33:44:55', ssid: 'legacy',
        'signal-strength': '-61 dBm', 'tx-rate': '54Mbps', 'rx-rate': '48Mbps',
        uptime: '1h2m', 'last-activity': '3s',
      }]),
      legacyCapsman: available([{
        '.id': '*2', interface: 'cap-wlan2', 'mac-address': '00:11:22:33:44:66', ssid: 'managed',
        'signal-strength': -72, 'tx-rate': '150Mbps', 'rx-rate': '130Mbps',
        uptime: '2h', 'last-activity': '5s',
      }]),
      wifi: available([{
        '.id': '*3', interface: 'wifi1', 'mac-address': '00:11:22:33:44:77', ssid: 'new-wifi',
        signal: ' -48.5 ', 'tx-rate': '1200Mbps', 'rx-rate': '1000Mbps',
        uptime: '10m', 'last-activity': '1s',
      }]),
    }),
  });

  assert.deepEqual(report.device, { id: 'router-1', name: 'edge' });
  assert.equal(report.sampledAt, '2026-11-09T00:00:00.000Z');
  assert.deepEqual(Object.keys(report.coverage), ['legacyWireless', 'legacyCapsman', 'wifi']);
  assert.deepEqual(report.associations, [
    {
      source: 'legacyWireless', driver: 'legacy-wireless', id: '*1', interface: 'wlan1',
      mac: '00:11:22:33:44:55', ssid: 'legacy', signal: -61, txRate: '54Mbps',
      rxRate: '48Mbps', uptime: '1h2m', lastActivity: '3s',
    },
    {
      source: 'legacyCapsman', driver: 'legacy-capsman', id: '*2', interface: 'cap-wlan2',
      mac: '00:11:22:33:44:66', ssid: 'managed', signal: -72, txRate: '150Mbps',
      rxRate: '130Mbps', uptime: '2h', lastActivity: '5s',
    },
    {
      source: 'wifi', driver: 'wifi', id: '*3', interface: 'wifi1',
      mac: '00:11:22:33:44:77', ssid: 'new-wifi', signal: -48.5, txRate: '1200Mbps',
      rxRate: '1000Mbps', uptime: '10m', lastActivity: '1s',
    },
  ]);
  assert.ok(report.notes.some((note) => /local WiFi and WiFi CAPsMAN clients/.test(note)));
  assert.match(report.notes[0], /current, possibly incomplete observation/i);
  assert.equal(report.observation.scanPerformed, false);
  assert.equal(report.observation.writePerformed, false);
});

test('keeps repeated client observations separate across source tables', () => {
  const sameClient = { interface: 'wlan1', 'mac-address': 'AA:BB:CC:DD:EE:FF', ssid: 'same', 'signal-strength': '-60' };
  const report = buildWirelessInventory({ sections: baseSections({
    legacyWireless: available([sameClient]),
    legacyCapsman: available([{ ...sameClient, interface: 'cap1' }]),
    wifi: available([{ interface: 'wifi1', 'mac-address': 'AA:BB:CC:DD:EE:FF', ssid: 'same', signal: '-59' }]),
  }) });

  assert.equal(report.associations.length, 3);
  assert.deepEqual(report.associations.map(({ source }) => source), ['legacyWireless', 'legacyCapsman', 'wifi']);
  assert.deepEqual(report.associations.map(({ mac }) => mac), Array(3).fill('AA:BB:CC:DD:EE:FF'));
});

test('reports unavailable and error sections as unknown coverage, not empty tables', () => {
  const report = buildWirelessInventory({ sections: {
    legacyWireless: { status: 'unavailable-or-not-permitted' },
    legacyCapsman: { status: 'error' },
    wifi: { status: 'available', records: {} },
  } });

  assert.deepEqual(report.coverage, {
    legacyWireless: { status: 'unavailable-or-not-permitted', recordCount: null, associationCount: null },
    legacyCapsman: { status: 'error', recordCount: null, associationCount: null },
    wifi: { status: 'error', recordCount: null, associationCount: null },
  });
  assert.deepEqual(report.associations, []);
});

test('preserves unknown signals as null and rejects malformed or non-finite signal formats', () => {
  const report = buildWirelessInventory({ sections: baseSections({
    legacyWireless: available([
      { 'signal-strength': '-55' },
      { 'signal-strength': '+12.75 dBm' },
      { 'signal-strength': '.5' },
      { 'signal-strength': '' },
      { 'signal-strength': 'about -60 dBm' },
      { 'signal-strength': 'Infinity' },
      { 'signal-strength': Number.NaN },
      { 'signal-strength': null },
    ]),
    legacyCapsman: available([{ 'signal-strength': 'not-a-number' }]),
    wifi: available([
      { signal: 0 },
      { signal: '1e3' },
      { signal: '-44 dBm @ 6Mbps' },
      { signal: {} },
    ]),
  }) });

  assert.deepEqual(report.associations.map(({ signal }) => signal), [
    -55, 12.75, 0.5, null, null, null, null, null, null, 0, null, null, null,
  ]);
  assert.ok(report.notes.some((note) => /no measurement unit is inferred/i.test(note)));
});

test('malformed rows are excluded, while valid rows keep explicit nulls for missing fields', () => {
  const report = buildWirelessInventory({ sections: baseSections({
    wifi: available([null, [], 'bad-row', { signal: '-63' }, { interface: ['not', 'scalar'] }]),
  }) });

  assert.deepEqual(report.coverage.wifi, { status: 'available', recordCount: 5, associationCount: 2 });
  assert.deepEqual(report.associations, [
    {
      source: 'wifi', driver: 'wifi', id: null, interface: null, mac: null, ssid: null,
      signal: -63, txRate: null, rxRate: null, uptime: null, lastActivity: null,
    },
    {
      source: 'wifi', driver: 'wifi', id: null, interface: null, mac: null, ssid: null,
      signal: null, txRate: null, rxRate: null, uptime: null, lastActivity: null,
    },
  ]);
});

test('only explicit allowlisted data is emitted; secret and unexpected fields never leak', () => {
  const report = buildWirelessInventory({
    device: { id: 'router-2', privateKey: 'device-private-key' },
    sections: baseSections({
      legacyWireless: available([{
        '.id': '*1', interface: 'wlan1', 'mac-address': '00:00:00:00:00:01', ssid: 'safe',
        'signal-strength': -50, password: 'row-password', 'private-key': 'row-private-key',
        secret: 'row-secret', token: 'row-token', arbitrary: 'not-approved',
      }]),
    }),
  });
  const serialized = JSON.stringify(report).toLowerCase();

  for (const forbidden of ['device-private-key', 'row-password', 'row-private-key', 'row-secret', 'row-token', 'not-approved']) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} leaked`);
  }
  assert.deepEqual(Object.keys(report.associations[0]).sort(), [
    'driver', 'id', 'interface', 'lastActivity', 'mac', 'rxRate', 'signal', 'source', 'ssid', 'txRate', 'uptime',
  ].sort());
  assert.equal(report.associations[0].signal, -50);
});

test('missing sections and invalid statuses are treated as errors', () => {
  const report = buildWirelessInventory({ sections: {
    legacyWireless: { status: 'available' },
    legacyCapsman: { status: 'healthy', records: [] },
  } });

  assert.deepEqual(report.coverage.legacyWireless, { status: 'available', recordCount: 0, associationCount: 0 });
  assert.deepEqual(report.coverage.legacyCapsman, { status: 'error', recordCount: null, associationCount: null });
  assert.deepEqual(report.coverage.wifi, { status: 'error', recordCount: null, associationCount: null });
});
