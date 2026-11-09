import test from 'node:test';
import assert from 'node:assert/strict';
import { isAlertWebhookEnabled, sendAlertWebhook, validateAlertWebhookUrl } from '../src/alert-webhook.js';

const event = {
  id: 'event-secret', at: '2026-11-09T01:00:00.000Z', device: 'branch-1', ruleId: 'rule-secret', label: 'private label',
  metric: 'cpuUsedPercent', value: 97, threshold: 90, operator: 'gt', status: 'triggered',
};

test('webhook delivery is disabled by default and does not call fetch', async () => {
  let calls = 0;
  assert.equal(isAlertWebhookEnabled({}), false);
  const result = await sendAlertWebhook([event], { env: {}, fetchFn: async () => { calls += 1; } });
  assert.deepEqual(result, { enabled: false, delivered: 0 });
  assert.equal(calls, 0);
});

test('accepts only HTTPS public DNS endpoints without embedded credentials or IP literals', () => {
  assert.equal(validateAlertWebhookUrl('https://alerts.example.com/hooks/abc'), 'https://alerts.example.com/hooks/abc');
  for (const value of [
    'http://alerts.example.com/hook', 'https://user:pass@alerts.example.com/hook',
    'https://127.0.0.1/hook', 'https://localhost/hook', 'https://router.local/hook',
  ]) assert.throws(() => validateAlertWebhookUrl(value), /HTTPS URL on a public DNS hostname/);
});

test('sends only approved transition fields and forbids redirects', async () => {
  let request;
  const result = await sendAlertWebhook([event], {
    env: { MIKROTIK_ALERT_WEBHOOK_ENABLED: 'true', MIKROTIK_ALERT_WEBHOOK_URL: 'https://alerts.example.com/hook' },
    fetchFn: async (url, options) => {
      request = { url, options };
      return { ok: true, status: 204 };
    },
  });
  assert.deepEqual(result, { enabled: true, delivered: 1, status: 204 });
  assert.equal(request.url, 'https://alerts.example.com/hook');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.redirect, 'error');
  const body = JSON.parse(request.options.body);
  assert.deepEqual(body, { source: 'mikrotik-mcp-js', events: [{ device: 'branch-1', at: event.at, status: 'triggered', metric: 'cpuUsedPercent', value: 97, operator: 'gt', threshold: 90 }] });
  assert.equal(request.options.body.includes('private label'), false);
  assert.equal(request.options.body.includes('rule-secret'), false);
});

test('rejects missing URL and hides endpoint and response body from delivery errors', async () => {
  await assert.rejects(sendAlertWebhook([event], { env: { MIKROTIK_ALERT_WEBHOOK_ENABLED: 'true' } }), /webhook URL/);
  await assert.rejects(sendAlertWebhook([event], {
    env: { MIKROTIK_ALERT_WEBHOOK_ENABLED: 'true', MIKROTIK_ALERT_WEBHOOK_URL: 'https://alerts.example.com/secret-token' },
    fetchFn: async () => { throw new Error('secret-token network error'); },
  }), (error) => !error.message.includes('secret-token') && /failed or timed out/.test(error.message));
  let bodyRead = false;
  await assert.rejects(sendAlertWebhook([event], {
    env: { MIKROTIK_ALERT_WEBHOOK_ENABLED: 'true', MIKROTIK_ALERT_WEBHOOK_URL: 'https://alerts.example.com/hook' },
    fetchFn: async () => ({ ok: false, status: 500, text: async () => { bodyRead = true; return 'secret'; } }),
  }), /HTTP 500/);
  assert.equal(bodyRead, false);
});
