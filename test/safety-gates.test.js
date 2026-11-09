import test from 'node:test';
import assert from 'node:assert/strict';
import { assertExactConfirmation, assertWriteSafety, isEnabled } from '../src/safety-gates.js';

test('write operations are closed unless both write switches are enabled', () => {
  assert.throws(() => assertWriteSafety({}), /MIKROTIK_ALLOW_WRITES/);
  assert.throws(() => assertWriteSafety({ MIKROTIK_ALLOW_WRITES: 'true' }), /MIKROTIK_ALLOW_HIGH_RISK_WRITES/);
  assert.doesNotThrow(() => assertWriteSafety({ MIKROTIK_ALLOW_WRITES: 'true', MIKROTIK_ALLOW_HIGH_RISK_WRITES: '1' }));
});

test('destructive actions and active diagnostics have independent extra gates', () => {
  const base = { MIKROTIK_ALLOW_WRITES: 'true', MIKROTIK_ALLOW_HIGH_RISK_WRITES: 'true' };
  assert.throws(() => assertWriteSafety(base, { destructive: true }), /MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS/);
  assert.throws(() => assertWriteSafety(base, { activeDiagnostics: true }), /MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS/);
  assert.doesNotThrow(() => assertWriteSafety({ ...base, MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS: 'yes', MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS: 'on' }, { destructive: true, activeDiagnostics: true }));
});

test('operation confirmations are exact and boolean-like strings do not enable gates', () => {
  assert.throws(() => assertExactConfirmation('REBOOT router-a', 'REBOOT router-b'), /REBOOT router-b/);
  assert.doesNotThrow(() => assertExactConfirmation('REBOOT router-a', 'REBOOT router-a'));
  assert.equal(isEnabled('false'), false);
  assert.equal(isEnabled('TRUE'), true);
});
