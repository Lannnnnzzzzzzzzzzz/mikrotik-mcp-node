import test from 'node:test';
import assert from 'node:assert/strict';
import { stageTransaction, takePlan } from '../src/change-planner.js';

test('staged transaction exposes and retains read-only baseline preconditions', () => {
  const baseline = { '.id': '*1', name: 'wg-mesh', 'public-key': Buffer.alloc(32, 4).toString('base64'), 'listen-port': '13231' };
  const preview = stageTransaction([
    { resourceKey: 'wireguard_peers', action: 'add', device: 'edge-a', fields: { interface: 'wg-mesh', 'public-key': Buffer.alloc(32, 5).toString('base64') } },
  ], [{ resourceKey: 'interface_wireguard', device: 'edge-a', targetId: '*1', baseline }]);
  assert.equal(preview.preconditionCount, 1);
  assert.equal(preview.preconditions[0].current['public-key'], baseline['public-key']);
  const stored = takePlan(preview.id, preview.confirmation, 'transaction');
  assert.equal(stored.preconditions[0].baseline.name, 'wg-mesh');
  assert.equal(stored.preconditions[0].targetId, '*1');
});

test('transaction precondition output redacts private keys but preserves public keys', () => {
  const publicKey = Buffer.alloc(32, 6).toString('base64');
  const preview = stageTransaction([], [{ resourceKey: 'interface_wireguard', device: 'edge-a', targetId: '*1', baseline: { 'public-key': publicKey, 'private-key': 'never-return-this' } }]);
  assert.equal(preview.preconditions[0].current['public-key'], publicKey);
  assert.equal(preview.preconditions[0].current['private-key'], '[redacted]');
  takePlan(preview.id, preview.confirmation, 'transaction');
});
