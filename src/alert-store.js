import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const METRICS = {
  cpuUsedPercent: { label: 'CPU use', unit: '%', min: 0, max: 100 },
  memoryUsedPercent: { label: 'Memory use', unit: '%', min: 0, max: 100 },
  activeDefaultRouteCount: { label: 'Active IPv4 default routes', unit: 'routes', min: 0, max: 1000, integer: true },
};
let mutationQueue = Promise.resolve();

function storageDirectory() {
  const root = process.env.MIKROTIK_DATA_DIR
    ? path.resolve(process.env.MIKROTIK_DATA_DIR)
    : path.resolve(__dirname, '..', '.data');
  return path.join(root, 'alerts');
}

async function assertPrivateDirectory(directory) {
  try {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  } catch (error) {
    throw new Error(`Unable to create private alert storage: ${error.message}`);
  }
  const info = await fs.lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('Alert storage path must be a regular directory, not a symlink.');
  if ((info.mode & 0o077) !== 0) throw new Error('Alert storage directories must be private (mode 0700 or stricter).');
}

async function ensureStorage() {
  const directory = storageDirectory();
  await assertPrivateDirectory(path.dirname(directory));
  await assertPrivateDirectory(directory);
  return directory;
}

function validateId(id) {
  if (typeof id !== 'string' || !UUID.test(id)) throw new Error('Alert rule ID must be a valid UUID.');
  return id.toLowerCase();
}

async function readJson(name, fallback) {
  const directory = await ensureStorage();
  const target = path.join(directory, name);
  try {
    const info = await fs.lstat(target);
    if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o077) !== 0) throw new Error('Alert store file must be a private regular file.');
    const value = JSON.parse(await fs.readFile(target, 'utf8'));
    if (!Array.isArray(value)) throw new Error('Alert store file must contain a JSON array.');
    return value;
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw new Error(`Unable to read alert store: ${error.message}`);
  }
}

async function writeJson(name, value) {
  const directory = await ensureStorage();
  const target = path.join(directory, name);
  const temporary = path.join(directory, `.${name}.${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(value), 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw new Error(`Unable to persist alert store: ${error.message}`);
  }
}

function serializeMutation(operation) {
  const pending = mutationQueue.then(operation, operation);
  mutationQueue = pending.catch(() => {});
  return pending;
}

export function validateAlertRule({ device, metric, operator, threshold, label }) {
  if (typeof device !== 'string' || !/^[a-zA-Z0-9_-]{1,48}$/.test(device)) throw new TypeError('device must be a configured router ID.');
  const definition = METRICS[metric];
  if (!definition) throw new TypeError(`metric must be one of: ${Object.keys(METRICS).join(', ')}.`);
  if (!['gt', 'gte', 'lt', 'lte'].includes(operator)) throw new TypeError('operator must be gt, gte, lt, or lte.');
  if (typeof threshold !== 'number' || !Number.isFinite(threshold) || threshold < definition.min || threshold > definition.max) throw new RangeError(`threshold must be between ${definition.min} and ${definition.max} ${definition.unit}.`);
  if (definition.integer && !Number.isInteger(threshold)) throw new TypeError('This metric requires an integer threshold.');
  if (typeof label !== 'string' || label.length < 1 || label.length > 80 || /[\u0000-\u001f\u007f]/.test(label)) throw new TypeError('label must be 1–80 printable characters.');
  return { device, metric, operator, threshold, label };
}

export function metricCatalog() {
  return Object.fromEntries(Object.entries(METRICS).map(([key, value]) => [key, { ...value, operators: ['gt', 'gte', 'lt', 'lte'] }]));
}

export async function createAlertRule(input) {
  const data = validateAlertRule(input);
  return serializeMutation(async () => {
    const rules = await readJson('rules.json', []);
    const rule = { id: crypto.randomUUID(), ...data, enabled: true, createdAt: new Date().toISOString(), lastTriggered: false, lastValue: null, lastCheckedAt: null };
    rules.push(rule);
    await writeJson('rules.json', rules);
    return rule;
  });
}

export async function listAlertRules(device) {
  const rules = await readJson('rules.json', []);
  return device ? rules.filter((rule) => rule.device === device) : rules;
}

export async function deleteAlertRule(id) {
  const normalized = validateId(id);
  return serializeMutation(async () => {
    const rules = await readJson('rules.json', []);
    const remaining = rules.filter((rule) => rule.id !== normalized);
    if (remaining.length === rules.length) throw new Error(`Alert rule not found: ${normalized}`);
    await writeJson('rules.json', remaining);
    return { id: normalized, deleted: true };
  });
}

function isTriggered(rule, value) {
  if (rule.operator === 'gt') return value > rule.threshold;
  if (rule.operator === 'gte') return value >= rule.threshold;
  if (rule.operator === 'lt') return value < rule.threshold;
  return value <= rule.threshold;
}

export async function recordAlertEvaluation(device, values) {
  return serializeMutation(async () => {
    const rules = await readJson('rules.json', []);
    const history = await readJson('history.json', []);
    const now = new Date().toISOString();
    const events = [];
    const evaluations = [];
    for (const rule of rules.filter((item) => item.device === device && item.enabled)) {
      const value = values[rule.metric];
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        evaluations.push({ ruleId: rule.id, label: rule.label, metric: rule.metric, available: false, triggered: rule.lastTriggered });
        continue;
      }
      const triggered = isTriggered(rule, value);
      const previous = rule.lastTriggered === true;
      const status = triggered === previous ? null : triggered ? 'triggered' : 'recovered';
      if (status) {
        const event = { id: crypto.randomUUID(), at: now, device, ruleId: rule.id, label: rule.label, metric: rule.metric, value, threshold: rule.threshold, operator: rule.operator, status };
        events.push(event);
      }
      rule.lastTriggered = triggered;
      rule.lastValue = value;
      rule.lastCheckedAt = now;
      evaluations.push({ ruleId: rule.id, label: rule.label, metric: rule.metric, unit: METRICS[rule.metric]?.unit, value, threshold: rule.threshold, operator: rule.operator, available: true, triggered });
    }
    if (rules.some((item) => item.device === device && item.enabled)) {
      await writeJson('rules.json', rules);
      if (events.length) await writeJson('history.json', [...history, ...events].slice(-500));
    }
    return { evaluations, events, evaluatedAt: now };
  });
}

export async function listAlertHistory({ device, limit = 100 } = {}) {
  const history = await readJson('history.json', []);
  const selected = device ? history.filter((event) => event.device === device) : history;
  return { events: selected.slice(-Math.min(200, limit)).reverse(), total: selected.length };
}
