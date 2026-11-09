import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWirelessSecurityAudit } from '../src/wireless-security-audit.js';

const available = (records = []) => ({ status: 'available', records });

function baseSections(overrides = {}) {
  return {
    wireless_security_profiles: available(),
    legacy_capsman_security: available(),
    wifi_security: available(),
    ...overrides,
  };
}

test('reports an explicit open/no-authentication legacy profile without returning profile data', () => {
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wireless_security_profiles: available([{
      name: 'open-secret-profile-name',
      mode: 'none',
      'authentication-types': 'none',
      'unicast-ciphers': 'aes-ccm',
      'group-ciphers': 'aes-ccm',
      'management-protection': 'required',
      'wpa-pre-shared-key': '',
      comment: 'private-comment',
    }]),
  }) });

  assert.deepEqual(report.findings, [
    { section: 'wireless_security_profiles', index: 0, code: 'open-no-authentication' },
  ]);
  assert.equal(report.profiles[0].secretPresent, false);
  assert.equal(report.findingCount, 1);
  assert.equal(JSON.stringify(report).includes('open-secret-profile-name'), false);
  assert.equal(JSON.stringify(report).includes('private-comment'), false);
});

test('detects explicitly configured WPA1 and WEP/TKIP ciphers', () => {
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wireless_security_profiles: available([{
      mode: 'dynamic-keys',
      'authentication-types': 'wpa-psk,wpa2-psk',
      'unicast-ciphers': 'wep40,aes-ccm',
      'group-ciphers': 'tkip',
      'management-protection': 'disabled',
      'wpa2-pre-shared-key': 'secret-value-must-not-leak',
    }]),
  }) });

  assert.deepEqual(report.findings.map(({ code }) => code), [
    'wpa1-authentication',
    'legacy-cipher',
    'management-frame-protection-disabled',
  ]);
  assert.deepEqual(report.findings.map(({ index }) => index), [0, 0, 0]);
  assert.equal(report.profiles[0].secretPresent, true);
  assert.equal(JSON.stringify(report).includes('secret-value-must-not-leak'), false);
});

test('recognizes an explicitly modern WiFi profile without inferring safety from unrelated fields', () => {
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wifi_security: available([{
      'authentication-types': ['wpa2-psk', 'wpa3-psk'],
      encryption: 'ccmp,gcmp',
      'management-protection': 'required',
      passphrase: 'wifi-secret-should-be-redacted',
      name: 'private-wifi-profile',
    }]),
  }) });

  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.indeterminate, []);
  assert.deepEqual(report.profiles, [{ section: 'wifi_security', index: 0, secretPresent: true }]);
  assert.equal(JSON.stringify(report).includes('wifi-secret-should-be-redacted'), false);
  assert.equal(JSON.stringify(report).includes('private-wifi-profile'), false);
});

test('keeps absent fields and unavailable or malformed sections indeterminate', () => {
  const report = buildWirelessSecurityAudit({ sections: {
    wireless_security_profiles: { status: 'unavailable-or-not-permitted' },
    legacy_capsman_security: { status: 'available', records: {} },
    wifi_security: available([{}]),
  } });

  assert.deepEqual(report.coverage.sections, {
    wireless_security_profiles: { status: 'unavailable-or-not-permitted', recordCount: null },
    legacy_capsman_security: { status: 'error', recordCount: null },
    wifi_security: { status: 'available', recordCount: 1, complete: true },
  });
  assert.ok(report.indeterminate.some(({ section, code }) => section === 'wireless_security_profiles' && code === 'section-unavailable'));
  assert.ok(report.indeterminate.some(({ section, code }) => section === 'legacy_capsman_security' && code === 'records-unavailable'));
  for (const code of [
    'authentication-unknown', 'encryption-unknown',
    'management-frame-protection-unknown', 'secret-presence-unknown',
  ]) {
    assert.ok(report.indeterminate.some(({ section, index, code: foundCode }) =>
      section === 'wifi_security' && index === 0 && foundCode === code), `${code} should be indeterminate`);
  }
  assert.equal(report.profiles.find(({ section }) => section === 'wifi_security').secretPresent, null);
  assert.deepEqual(report.findings, []);
});

test('marks unrecognized field values indeterminate rather than treating them as secure', () => {
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wifi_security: available([{
      'authentication-types': 'vendor-auth-mode',
      encryption: 'vendor-cipher',
      'management-protection': 'vendor-protection-mode',
      passphrase: '',
    }]),
  }) });

  for (const code of [
    'authentication-unknown', 'encryption-unknown', 'management-frame-protection-unknown',
  ]) {
    assert.ok(report.indeterminate.some(({ code: foundCode }) => foundCode === code));
  }
  assert.deepEqual(report.findings, []);
  assert.equal(report.profiles.find(({ section }) => section === 'wifi_security').secretPresent, false);
});

test('redacts names, keys, comments, SSIDs, MACs, and arbitrary raw-row values', () => {
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wifi_security: available([{
      name: 'profile-name-marker',
      'authentication-types': 'wpa3-psk',
      encryption: 'gcmp',
      'management-protection': 'required',
      passphrase: 'passphrase-marker',
      comment: 'comment-marker',
      ssid: 'ssid-marker',
      'mac-address': 'mac-marker',
      arbitrary: 'raw-row-marker',
    }]),
  }) });
  const serialized = JSON.stringify(report);

  for (const forbidden of [
    'profile-name-marker', 'passphrase-marker', 'comment-marker', 'ssid-marker', 'mac-marker', 'raw-row-marker',
  ]) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} leaked`);
  }
  assert.deepEqual(report.profiles, [{ section: 'wifi_security', index: 0, secretPresent: true }]);
});

test('bounds profile summaries and marks truncated snapshots incomplete', () => {
  const modernProfile = {
    'authentication-types': 'wpa3-psk',
    encryption: 'gcmp',
    'management-protection': 'required',
    passphrase: 'not-returned',
  };
  const report = buildWirelessSecurityAudit({ sections: baseSections({
    wifi_security: available(Array.from({ length: 1001 }, () => modernProfile)),
    wireless_security_profiles: { status: 'available', records: [], total: 1 },
  }) });
  assert.equal(report.profiles.length, 1000);
  assert.equal(report.profilesOmittedCount, 1);
  assert.equal(report.profilesTruncated, true);
  assert.equal(report.coverage.sections.wifi_security.complete, true);
  assert.equal(report.coverage.sections.wireless_security_profiles.complete, false);
  assert.ok(report.indeterminate.some(({ section, code }) => section === 'wireless_security_profiles' && code === 'partial-section'));
  assert.equal(JSON.stringify(report).includes('not-returned'), false);
});
