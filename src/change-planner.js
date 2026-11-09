import { randomUUID } from 'node:crypto';

const PLAN_TTL_MS = 10 * 60 * 1000;
const plans = new Map();
const SECRET_FIELD_PATTERN = /(password|secret|private.?key|pre.?shared.?key|token|credential)/i;

export function validateChangeInput(resource, action, fields = {}, targetId) {
  if (!['add', 'set', 'remove'].includes(action)) throw new TypeError('Action must be add, set, or remove.');
  if (!resource || resource.risk === 'read-only') throw new Error('This resource is read-only.');
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new TypeError('Fields must be an object of string values.');
  if (action === 'remove' && Object.keys(fields).length !== 0) throw new Error('Remove plans cannot include fields.');
  if (action !== 'remove' && Object.keys(fields).length === 0) throw new Error('Add and set plans require at least one field.');
  if ((action === 'set' || action === 'remove') && !/^\*\d+$/.test(targetId ?? '')) {
    throw new TypeError('Set/remove requires a RouterOS internal item ID such as *1.');
  }
  if (action === 'add' && targetId !== undefined) throw new Error('Add plans do not accept a target ID.');
  const accepted = new Set(resource.writeFields);
  for (const [key, value] of Object.entries(fields)) {
    if (!accepted.has(key)) throw new Error(`Field "${key}" is not writable for ${resource.key}.`);
    if (typeof value !== 'string') throw new TypeError(`Field "${key}" must be a string.`);
    if (value.length > 1024) throw new RangeError(`Field "${key}" exceeds the 1024-character limit.`);
    if (value.includes('\u0000')) throw new Error(`Field "${key}" contains an unsupported NUL character.`);
  }
}

export function redactFields(fields) {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => [
    key,
    SECRET_FIELD_PATTERN.test(key) ? '[redacted]' : value,
  ]));
}

export function stagePlan({ resourceKey, action, device, fields, targetId, baseline }) {
  const id = randomUUID();
  const entry = {
    id,
    type: 'single',
    resourceKey,
    action,
    device,
    fields: { ...fields },
    targetId,
    baseline: baseline ? { ...baseline } : undefined,
    expiresAt: Date.now() + PLAN_TTL_MS,
  };
  plans.set(id, entry);
  prunePlans();
  return {
    id,
    expiresInSeconds: Math.floor(PLAN_TTL_MS / 1000),
    confirmation: `APPLY ${id}`,
    resource: resourceKey,
    action,
    device,
    targetId: targetId ?? null,
    fields: redactFields(fields),
    current: baseline ? redactFields(baseline) : null,
    risk: 'high',
    note: 'Plan only; no router configuration has been changed. Applying requires writes enabled and exact confirmation.',
  };
}

export function stageTransaction(steps, preconditions = []) {
  const id = randomUUID();
  const entry = {
    id,
    type: 'transaction',
    steps: steps.map((step) => ({ ...step, fields: { ...step.fields }, baseline: step.baseline ? { ...step.baseline } : undefined })),
    preconditions: preconditions.map((guard) => ({ ...guard, baseline: guard.baseline ? { ...guard.baseline } : undefined })),
    expiresAt: Date.now() + PLAN_TTL_MS,
  };
  plans.set(id, entry);
  prunePlans();
  return {
    id,
    expiresInSeconds: Math.floor(PLAN_TTL_MS / 1000),
    confirmation: `APPLY ${id}`,
    stepCount: steps.length,
    devices: [...new Set(steps.map((step) => step.device))],
    steps: steps.map((step, index) => ({
      index: index + 1,
      device: step.device,
      resource: step.resourceKey,
      action: step.action,
      targetId: step.targetId ?? null,
      fields: redactFields(step.fields),
      current: step.baseline ? redactFields(step.baseline) : null,
    })),
    preconditionCount: preconditions.length,
    preconditions: preconditions.map((guard) => ({ device: guard.device, resource: guard.resourceKey, targetId: guard.targetId, current: guard.baseline ? redactFields(guard.baseline) : null })),
    risk: 'high',
    note: 'Plan only; no router has been changed. Apply executes in order and can stop in a partial state; it is not an atomic or automatically reversible transaction.',
  };
}

export function takePlan(id, confirmation, expectedType = 'single') {
  prunePlans();
  const entry = plans.get(id);
  if (!entry) throw new Error('Change plan not found, expired, or already used. Create a new plan.');
  if (confirmation !== `APPLY ${id}`) throw new Error(`Exact confirmation required: APPLY ${id}`);
  if (entry.type !== expectedType) throw new Error(`This plan is a ${entry.type} plan; use the matching apply tool.`);
  plans.delete(id);
  return entry;
}

export function cancelPlan(id) {
  return plans.delete(id);
}

export function clearPlans() {
  plans.clear();
}

function prunePlans() {
  const now = Date.now();
  for (const [id, plan] of plans) {
    if (plan.expiresAt <= now) plans.delete(id);
  }
}
