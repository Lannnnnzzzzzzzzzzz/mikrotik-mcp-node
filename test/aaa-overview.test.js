import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAaaOverview } from '../src/aaa-overview.js';

function sections(overrides = {}) {
  return {
    radiusClients: { status: 'available', records: [] },
    userManagerUsers: { status: 'available', records: [] },
    profiles: { status: 'available', records: [] },
    routers: { status: 'available', records: [] },
    sessions: { status: 'available', records: [] },
    limitations: { status: 'available', records: [] },
    ...overrides,
  };
}

test('available empty sections are distinct from unavailable and error sections', () => {
  const report = buildAaaOverview({ sections: sections({
    radiusClients: { status: 'available' },
    userManagerUsers: { status: 'unavailable-or-not-permitted', records: [] },
    profiles: { status: 'error' },
  }) });

  assert.deepEqual(report.sections.radiusClients, {
    status: 'available', recordCount: 0, records: [], truncated: false,
  });
  assert.equal(report.sections.userManagerUsers.status, 'unavailable-or-not-permitted');
  assert.equal(report.sections.userManagerUsers.recordCount, null);
  assert.equal(report.sections.userManagerUsers.records, null);
  assert.equal(report.sections.profiles.status, 'error');
  assert.equal(report.sections.profiles.recordCount, null);
  assert.equal(report.sections.profiles.records, null);
  assert.deepEqual(report.sessionTotals, { sessionCount: 0, bytesInTotal: 0, bytesOutTotal: 0 });
  assert.ok(report.notes.some((note) => /on-demand accounting snapshot/i.test(note)));
  assert.ok(report.notes.some((note) => /package.*permissions.*incomplete.*stale.*NAS-dependent/i.test(note)));
});

test('session byte totals cover all valid snapshot rows while displayed records are capped', () => {
  const records = Array.from({ length: 105 }, (_, index) => ({
    user: `user-${index}`,
    address: `192.0.2.${index + 1}`,
    'bytes-in': String(index + 1),
    'bytes-out': index * 2,
    comment: 'must not be projected',
  }));
  const report = buildAaaOverview({ sections: sections({ sessions: { status: 'available', records } }) });

  assert.equal(report.sections.sessions.recordCount, 105);
  assert.equal(report.sections.sessions.records.length, 100);
  assert.equal(report.sections.sessions.truncated, true);
  assert.deepEqual(report.sessionTotals, { sessionCount: 105, bytesInTotal: 5565, bytesOutTotal: 10920 });
  assert.deepEqual(report.sections.sessions.records[0], {
    user: 'user-0', address: '192.0.2.1', bytesIn: '1', bytesOut: 0,
  });
});

test('missing and malformed fields are omitted and incomplete byte totals remain unknown', () => {
  const report = buildAaaOverview({ sections: sections({ sessions: { status: 'available', records: [
    {}, null, [], { username: 'alice' }, { user: 'bob', 'bytes-in': 'not-a-number', 'bytes-out': 12 },
  ] } }) });

  assert.equal(report.sections.sessions.recordCount, 2);
  assert.deepEqual(report.sections.sessions.records, [
    { user: 'alice' },
    { user: 'bob', bytesIn: 'not-a-number', bytesOut: 12 },
  ]);
  assert.deepEqual(report.sessionTotals, { sessionCount: 2, bytesInTotal: null, bytesOutTotal: null });
});

test('secret-like and unapproved properties never leak into serialized output', () => {
  const report = buildAaaOverview({
    device: { id: 'router-1', name: 'edge', password: 'device-password' },
    sampledAt: '2026-11-09T00:00:00Z',
    sections: sections({
      radiusClients: { status: 'available', records: [{
        service: 'login', address: '192.0.2.9', protocol: 'udp',
        password: 'pw-value', secret: 'secret-value', 'shared-secret': 'shared-value',
        key: 'key-value', 'api-key': 'api-value', token: 'token-value', otp: 'otp-value',
        attribute: 'attribute-value', attributes: 'attributes-value', credential: 'credential-value',
        'raw-value': 'raw-value-content', comment: 'comment-content', arbitrary: 'not-approved',
      }] },
      sessions: { status: 'available', records: [{
        user: 'alice', address: '192.0.2.10', password: 'pw-value', secret: 'secret-value',
        key: 'key-value', token: 'token-value', OTP: 'otp-value', attributes: 'attributes-value',
        credential: 'credential-value', 'raw-value': 'raw-value-content', comment: 'comment-content',
      }] },
    }),
  });
  const serialized = JSON.stringify(report);

  for (const forbidden of [
    'password', 'secret', 'shared-secret', 'api-key', 'token', 'otp', 'attribute',
    'attributes', 'credential', 'raw-value', 'comment', 'not-approved',
    'pw-value', 'secret-value', 'shared-value', 'api-value', 'token-value', 'otp-value',
    'attribute-value', 'attributes-value', 'credential-value', 'raw-value-content', 'comment-content',
  ]) assert.equal(serialized.toLowerCase().includes(forbidden.toLowerCase()), false, `${forbidden} leaked`);
  assert.equal(report.device.id, 'router-1');
  assert.equal(report.sections.radiusClients.records[0].address, '192.0.2.9');
});

test('malformed available records and invalid section status are not reported as healthy empty data', () => {
  const report = buildAaaOverview({ sections: sections({
    routers: { status: 'available', records: {} },
    limitations: { status: 'healthy', records: [] },
  }) });

  assert.equal(report.sections.routers.status, 'error');
  assert.equal(report.sections.routers.recordCount, null);
  assert.equal(report.sections.routers.records, null);
  assert.equal(report.sections.limitations.status, 'error');
  assert.equal(report.sections.limitations.recordCount, null);
});
