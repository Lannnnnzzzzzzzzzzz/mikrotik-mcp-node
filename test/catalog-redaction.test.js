import test from 'node:test';
import assert from 'node:assert/strict';
import { RESOURCE_BY_KEY, isSensitiveProperty, redactSensitiveRecords, sanitizeResourceProperties } from '../src/catalog.js';

test('default catalog property lists omit passwords, secrets and other sensitive fields', () => {
  const routerRadius = RESOURCE_BY_KEY.get('radius_user_manager_routers');
  const radiusProperties = sanitizeResourceProperties(routerRadius);
  assert.ok(radiusProperties.includes('address'));
  assert.ok(!radiusProperties.includes('shared-secret'));

  const wifiSecurity = RESOURCE_BY_KEY.get('wifi_security');
  assert.ok(!sanitizeResourceProperties(wifiSecurity).includes('passphrase'));
  assert.equal(isSensitiveProperty('public-key'), false);
  assert.equal(isSensitiveProperty('private-key'), true);
  assert.equal(isSensitiveProperty('preshared-key'), true);
});

test('explicit requests for sensitive properties are rejected before router access', () => {
  const resource = RESOURCE_BY_KEY.get('radius_user_manager_routers');
  assert.throws(() => sanitizeResourceProperties(resource, ['name', 'shared-secret']), /Sensitive properties cannot be read/);
  assert.throws(() => sanitizeResourceProperties(RESOURCE_BY_KEY.get('wifi_security'), ['passphrase']), /Sensitive properties cannot be read/);
  assert.throws(() => sanitizeResourceProperties(RESOURCE_BY_KEY.get('wireguard_peers'), ['preshared-key']), /Sensitive properties cannot be read/);
  assert.throws(() => sanitizeResourceProperties(resource, 'shared-secret'), /must be an array/);
});

test('defensive nested output redaction preserves public keys and masks secret assignments in comments', () => {
  const source = [{
    name: 'peer-a',
    'public-key': 'public-key-content',
    'private-key': 'private-key-content',
    'preshared-key': 'wireguard-psk-content',
    password: 'password-content',
    'shared-secret': 'radius-secret-content',
    attributes: 'attribute-content',
    comment: 'owner=net password=hunter2; note="shared-secret=abc123"',
    nested: { token: 'token-content', safe: 'visible' },
  }];
  const result = redactSensitiveRecords(source);
  const serialized = JSON.stringify(result);

  assert.equal(result[0]['public-key'], 'public-key-content');
  assert.equal(result[0].nested.safe, 'visible');
  for (const secret of ['private-key-content', 'wireguard-psk-content', 'password-content', 'radius-secret-content', 'attribute-content', 'hunter2', 'abc123', 'token-content']) {
    assert.equal(serialized.includes(secret), false, `${secret} leaked`);
  }
  assert.match(result[0].comment, /password=\[redacted\]/);
});
