const ENABLED = new Set(['1', 'true', 'yes', 'on']);
const MAX_BODY_BYTES = 16 * 1024;
const REQUEST_TIMEOUT_MS = 5000;

export function isAlertWebhookEnabled(env = process.env) {
  return ENABLED.has(String(env.MIKROTIK_ALERT_WEBHOOK_ENABLED ?? '').toLowerCase());
}

export function validateAlertWebhookUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048) throw new Error('A webhook URL of at most 2048 characters is required.');
  let url;
  try { url = new URL(value); } catch { throw new Error('The alert webhook URL is invalid.'); }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || !hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.split('.').length < 2 || hostname.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
    throw new Error('Alert webhooks require an HTTPS URL on a public DNS hostname, without embedded credentials or an IP literal.');
  }
  return url.toString();
}

function projectEvent(event) {
  const allowedStatuses = new Set(['triggered', 'recovered']);
  const allowedMetrics = new Set(['cpuUsedPercent', 'memoryUsedPercent', 'activeDefaultRouteCount']);
  if (!event || !allowedStatuses.has(event.status) || !allowedMetrics.has(event.metric)) return null;
  if (typeof event.device !== 'string' || !/^[A-Za-z0-9_-]{1,48}$/.test(event.device)) return null;
  if (typeof event.value !== 'number' || !Number.isFinite(event.value) || typeof event.threshold !== 'number' || !Number.isFinite(event.threshold)) return null;
  if (!['gt', 'gte', 'lt', 'lte'].includes(event.operator)) return null;
  if (typeof event.at !== 'string' || !Number.isFinite(Date.parse(event.at))) return null;
  return {
    device: event.device,
    at: event.at,
    status: event.status,
    metric: event.metric,
    value: event.value,
    operator: event.operator,
    threshold: event.threshold,
  };
}

/** Send only validated state-transition fields; never include labels, credentials, or router records. */
export async function sendAlertWebhook(events, {
  env = process.env,
  fetchFn = globalThis.fetch,
  timeoutMs = REQUEST_TIMEOUT_MS,
} = {}) {
  if (!isAlertWebhookEnabled(env)) return { enabled: false, delivered: 0 };
  const url = validateAlertWebhookUrl(env.MIKROTIK_ALERT_WEBHOOK_URL);
  if (typeof fetchFn !== 'function') throw new Error('This Node.js runtime does not provide fetch for alert webhooks.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new RangeError('Webhook timeout must be from 1 to 30000 ms.');
  if (!Array.isArray(events)) throw new TypeError('events must be an array.');
  const projected = events.map(projectEvent).filter(Boolean).slice(0, 50);
  if (projected.length === 0) return { enabled: true, delivered: 0 };
  const body = JSON.stringify({ source: 'mikrotik-mcp-js', events: projected });
  if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) throw new RangeError('Alert webhook payload exceeds its size limit.');
  let response;
  try {
    response = await fetchFn(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'mikrotik-mcp-js-alerts/1' },
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new Error('Alert webhook delivery failed or timed out; the endpoint URL and response body were not logged.');
  }
  if (!response || response.ok !== true) {
    const status = Number.isInteger(response?.status) ? response.status : 'unknown';
    throw new Error(`Alert webhook returned HTTP ${status}; the response body was not read.`);
  }
  return { enabled: true, delivered: projected.length, status: response.status };
}
