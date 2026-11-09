import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAlertRule, deleteAlertRule, listAlertHistory, listAlertRules, metricCatalog, recordAlertEvaluation, validateAlertRule } from '../src/alert-store.js';

test('manual alert rules validate, store privately, record transitions once and preserve history after deletion', async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-alert-test-'));
  await fs.chmod(dataDir, 0o700);
  const previous = process.env.MIKROTIK_DATA_DIR;
  process.env.MIKROTIK_DATA_DIR = dataDir;
  t.after(async () => {
    if (previous === undefined) delete process.env.MIKROTIK_DATA_DIR;
    else process.env.MIKROTIK_DATA_DIR = previous;
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  assert.ok(metricCatalog().cpuUsedPercent);
  assert.throws(() => validateAlertRule({ device: 'edge-a', metric: 'unknown', operator: 'gt', threshold: 10, label: 'Bad' }), /metric must be one of/);
  assert.throws(() => validateAlertRule({ device: 'edge-a', metric: 'activeDefaultRouteCount', operator: 'gte', threshold: 1.5, label: 'Bad' }), /integer threshold/);

  const rule = await createAlertRule({ device: 'edge-a', metric: 'cpuUsedPercent', operator: 'gte', threshold: 85, label: 'CPU high' });
  assert.equal((await listAlertRules('edge-a')).length, 1);
  const triggered = await recordAlertEvaluation('edge-a', { cpuUsedPercent: 90 });
  assert.equal(triggered.events[0].status, 'triggered');
  const stillTriggered = await recordAlertEvaluation('edge-a', { cpuUsedPercent: 95 });
  assert.equal(stillTriggered.events.length, 0);
  const recovered = await recordAlertEvaluation('edge-a', { cpuUsedPercent: 70 });
  assert.equal(recovered.events[0].status, 'recovered');
  const history = await listAlertHistory({ device: 'edge-a', limit: 20 });
  assert.deepEqual(history.events.map((event) => event.status), ['recovered', 'triggered']);
  assert.equal(history.total, 2);

  const directoryStat = await fs.stat(path.join(dataDir, 'alerts'));
  const rulesStat = await fs.stat(path.join(dataDir, 'alerts', 'rules.json'));
  assert.equal(directoryStat.mode & 0o077, 0);
  assert.equal(rulesStat.mode & 0o077, 0);
  assert.deepEqual(await deleteAlertRule(rule.id), { id: rule.id, deleted: true });
  assert.deepEqual(await listAlertRules('edge-a'), []);
  assert.equal((await listAlertHistory({ device: 'edge-a' })).total, 2);
});
