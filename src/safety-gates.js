const ENABLED = new Set(['1', 'true', 'yes', 'on']);

export function isEnabled(value) {
  return value === true || ENABLED.has(String(value ?? '').toLowerCase());
}

export function assertWriteSafety(env = process.env, { destructive = false, activeDiagnostics = false } = {}) {
  if (!isEnabled(env.MIKROTIK_ALLOW_WRITES)) {
    throw new Error('Writes and active operations are disabled. Set MIKROTIK_ALLOW_WRITES=true only after reviewing the risk.');
  }
  if (!isEnabled(env.MIKROTIK_ALLOW_HIGH_RISK_WRITES)) {
    throw new Error('High-risk writes are disabled. Set MIKROTIK_ALLOW_HIGH_RISK_WRITES=true only after establishing a recovery path.');
  }
  if (destructive && !isEnabled(env.MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS)) {
    throw new Error('Destructive operations are disabled. Set MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true only for a planned maintenance window.');
  }
  if (activeDiagnostics && !isEnabled(env.MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS)) {
    throw new Error('Active traffic diagnostics are disabled. Set MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true after assessing network impact.');
  }
}

export function assertExactConfirmation(actual, expected) {
  if (actual !== expected) throw new Error(`Exact operation confirmation required: ${expected}`);
}
