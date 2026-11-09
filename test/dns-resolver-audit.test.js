import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDnsResolverAudit } from '../src/dns-resolver-audit.js';

function dnsSections({ settings = {}, staticRecords = [], upstream = undefined } = {}) {
  return {
    ip_dns_settings: {
      status: 'available',
      records: [{ 'allow-remote-requests': 'no', servers: '192.0.2.53', 'use-doh-server': '' , ...settings }],
    },
    dns_static: { status: 'available', records: staticRecords },
    ...(upstream === undefined ? {} : { dns_upstream_servers: upstream }),
  };
}

function find(report, code) {
  return report.findings.filter((item) => item.code === code);
}

test('safe resolver settings report upstream presence without warnings or raw values', () => {
  const report = buildDnsResolverAudit({ sections: dnsSections({
    settings: {
      servers: '203.0.113.53',
      'use-doh-server': 'https://private-doh.example/dns-query',
      comment: 'secret-comment',
      'tls-key': 'secret-key',
    },
    staticRecords: [{ name: 'private.internal', address: '10.2.3.4', comment: 'hidden' }],
  }) });

  assert.deepEqual(find(report, 'remote-requests-enabled-review'), []);
  assert.deepEqual(find(report, 'upstream-configured'), [{ code: 'upstream-configured', severity: 'info', recordIndices: [0] }]);
  assert.deepEqual(find(report, 'doh-configured'), [{ code: 'doh-configured', severity: 'info', recordIndices: [0] }]);
  assert.equal(report.counts.duplicateStaticNames, 0);
  assert.equal(JSON.stringify(report).includes('203.0.113.53'), false);
  assert.equal(JSON.stringify(report).includes('private.internal'), false);
  assert.equal(JSON.stringify(report).includes('private-doh.example'), false);
  assert.equal(JSON.stringify(report).includes('secret-comment'), false);
  assert.equal(JSON.stringify(report).includes('secret-key'), false);
});

test('allow-remote-requests alone is a review finding and does not claim exposure', () => {
  const report = buildDnsResolverAudit({ sections: dnsSections({ settings: { 'allow-remote-requests': 'yes' } }) });
  assert.deepEqual(find(report, 'remote-requests-enabled-review'), [
    { code: 'remote-requests-enabled-review', severity: 'review', recordIndices: [0] },
  ]);
  assert.equal(report.findings.some(({ code }) => code.includes('exposed') || code.includes('reachable')), false);
});

test('detects duplicate enabled static names without returning the names or records', () => {
  const secretName = 'hidden.example.net';
  const report = buildDnsResolverAudit({ sections: dnsSections({
    staticRecords: [
      { name: secretName, address: '10.0.0.1', comment: 'private' },
      { name: 'HIDDEN.EXAMPLE.NET.', address: '10.0.0.2' },
      { name: secretName, disabled: 'yes', address: '10.0.0.3' },
    ],
  }) });
  assert.deepEqual(find(report, 'duplicate-static-name'), [
    { code: 'duplicate-static-name', severity: 'warning', recordIndices: [0, 1] },
  ]);
  assert.equal(report.counts.duplicateStaticNames, 1);
  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes(secretName), false);
  assert.equal(serialized.includes('10.0.0.1'), false);
  assert.equal(serialized.includes('private'), false);
});

test('unknown and unavailable upstream data are reported as unknown, not absent or healthy', () => {
  const noField = buildDnsResolverAudit({ sections: {
    ip_dns_settings: { status: 'available', records: [{ 'allow-remote-requests': 'no' }] },
    dns_static: { status: 'available', records: [] },
  } });
  assert.equal(find(noField, 'upstream-coverage-unknown').length, 1);
  assert.deepEqual(find(noField, 'upstream-not-configured'), []);

  const unavailable = buildDnsResolverAudit({ sections: dnsSections({
    upstream: { status: 'unavailable-or-not-permitted' },
  }) });
  assert.equal(find(unavailable, 'upstream-coverage-unknown').length, 1);
  assert.deepEqual(find(unavailable, 'upstream-not-configured'), []);
  assert.equal(unavailable.counts.upstreamRecords, null);
});

test('malformed and truncated sections produce incomplete-coverage findings with bounded indices', () => {
  const report = buildDnsResolverAudit({ sections: {
    ip_dns_settings: { status: 'available', records: [{ servers: '192.0.2.1' }, { servers: '192.0.2.2' }] },
    dns_static: { status: 'available', truncated: true, total: 9, records: [{ name: 'secret.example' }] },
    dns_upstream_servers: { status: 'available', records: 'not-an-array' },
  } });

  assert.equal(find(report, 'dns-settings-coverage-incomplete').length, 1);
  assert.equal(find(report, 'static-records-coverage-incomplete').length, 1);
  assert.equal(find(report, 'upstream-coverage-unknown').length, 1);
  assert.equal(find(report, 'duplicate-static-name').length, 0);
  assert.equal(JSON.stringify(report).includes('secret.example'), false);
  assert.ok(report.findings.every(({ recordIndices }) => Array.isArray(recordIndices)
    && recordIndices.every((index) => Number.isSafeInteger(index) && index >= 0)));
});
