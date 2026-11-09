const SECTION_SCHEMAS = {
  wireless_security_profiles: {
    mode: 'mode',
    authentication: 'authentication-types',
    ciphers: ['unicast-ciphers', 'group-ciphers'],
    managementProtection: 'management-protection',
    secrets: ['wpa-pre-shared-key', 'wpa2-pre-shared-key', 'passphrase'],
  },
  legacy_capsman_security: {
    authentication: 'authentication-types',
    ciphers: ['encryption'],
    managementProtection: 'management-protection',
    secrets: ['passphrase', 'wpa-pre-shared-key', 'wpa2-pre-shared-key'],
  },
  wifi_security: {
    authentication: 'authentication-types',
    ciphers: ['encryption'],
    managementProtection: 'management-protection',
    secrets: ['passphrase'],
  },
};
const SECTION_KEYS = Object.keys(SECTION_SCHEMAS);
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const MAX_RECORDS = 5000;
const MAX_OUTPUT_ITEMS = 1000;
const AUTHENTICATIONS = new Set([
  'wpa-psk', 'wpa-eap', 'wpa2-psk', 'wpa2-eap', 'wpa3-psk', 'wpa3-eap',
  'owe', 'dot1x', 'wep', 'none', 'open', 'no-authentication', 'no-auth',
]);
const MODERN_CIPHERS = new Set([
  'aes-ccm', 'ccmp', 'ccmp-128', 'ccmp-256', 'gcmp', 'gcmp-128', 'gcmp-256',
]);
const LEGACY_CIPHERS = new Set(['wep', 'wep40', 'wep104', 'tkip']);
const KNOWN_CIPHER_LABELS = new Set([...MODERN_CIPHERS, ...LEGACY_CIPHERS]);

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function safeRead(object, key) {
  try {
    return object?.[key];
  } catch {
    return undefined;
  }
}

function own(object, key) {
  try {
    return Object.hasOwn(object, key);
  } catch {
    return false;
  }
}

function tokens(value) {
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase();
    return trimmed ? trimmed.split(/[\s,]+/).filter(Boolean) : [];
  }
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value.flatMap((item) => item.trim().toLowerCase().split(/[\s,]+/).filter(Boolean));
  }
  return null;
}

function addIndeterminate(items, code) {
  if (!items.includes(code)) items.push(code);
}

function analyzeAuthentication(row, schema, findingCodes, indeterminateCodes) {
  const field = schema.authentication;
  if (!field || !own(row, field)) {
    addIndeterminate(indeterminateCodes, 'authentication-unknown');
    return;
  }
  const values = tokens(safeRead(row, field));
  if (!values || values.length === 0) {
    addIndeterminate(indeterminateCodes, 'authentication-unknown');
    return;
  }

  let recognized = false;
  for (const value of values) {
    if (!AUTHENTICATIONS.has(value)) {
      addIndeterminate(indeterminateCodes, 'authentication-unknown');
      continue;
    }
    recognized = true;
    if (['none', 'open', 'no-authentication', 'no-auth'].includes(value)) {
      if (!findingCodes.includes('open-no-authentication')) findingCodes.push('open-no-authentication');
    }
    if (value === 'wpa-psk' || value === 'wpa-eap') {
      if (!findingCodes.includes('wpa1-authentication')) findingCodes.push('wpa1-authentication');
    }
  }
  if (!recognized) addIndeterminate(indeterminateCodes, 'authentication-unknown');
}

function analyzeMode(row, schema, findingCodes, indeterminateCodes) {
  if (!schema.mode) return;
  const field = schema.mode;
  if (!own(row, field)) {
    addIndeterminate(indeterminateCodes, 'open-mode-unknown');
    return;
  }
  const value = safeRead(row, field);
  if (typeof value !== 'string') {
    addIndeterminate(indeterminateCodes, 'open-mode-unknown');
    return;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === 'none' || normalized === 'open') {
    if (!findingCodes.includes('open-no-authentication')) findingCodes.push('open-no-authentication');
  } else if (!['static-keys-required', 'static-keys-optional', 'dynamic-keys'].includes(normalized)) {
    addIndeterminate(indeterminateCodes, 'open-mode-unknown');
  }
}

function analyzeCiphers(row, schema, findingCodes, indeterminateCodes) {
  for (const field of schema.ciphers) {
    if (!own(row, field)) {
      addIndeterminate(indeterminateCodes, field === 'encryption' ? 'encryption-unknown' : 'cipher-unknown');
      continue;
    }
    const values = tokens(safeRead(row, field));
    if (!values || values.length === 0) {
      addIndeterminate(indeterminateCodes, field === 'encryption' ? 'encryption-unknown' : 'cipher-unknown');
      continue;
    }
    let recognized = false;
    for (const value of values) {
      if (!KNOWN_CIPHER_LABELS.has(value)) {
        addIndeterminate(indeterminateCodes, field === 'encryption' ? 'encryption-unknown' : 'cipher-unknown');
        continue;
      }
      recognized = true;
      if (LEGACY_CIPHERS.has(value) && !findingCodes.includes('legacy-cipher')) {
        findingCodes.push('legacy-cipher');
      }
    }
    if (!recognized) addIndeterminate(indeterminateCodes, field === 'encryption' ? 'encryption-unknown' : 'cipher-unknown');
  }
}

function analyzeManagementProtection(row, schema, findingCodes, indeterminateCodes) {
  const field = schema.managementProtection;
  if (!field || !own(row, field)) {
    addIndeterminate(indeterminateCodes, 'management-frame-protection-unknown');
    return;
  }
  const value = safeRead(row, field);
  if (typeof value !== 'string') {
    addIndeterminate(indeterminateCodes, 'management-frame-protection-unknown');
    return;
  }
  const normalized = value.trim().toLowerCase();
  if (['disabled', 'no', 'off', 'false'].includes(normalized)) {
    if (!findingCodes.includes('management-frame-protection-disabled')) {
      findingCodes.push('management-frame-protection-disabled');
    }
  } else if (['allowed', 'optional'].includes(normalized)) {
    if (!findingCodes.includes('management-frame-protection-not-required')) {
      findingCodes.push('management-frame-protection-not-required');
    }
  } else if (!['required', 'yes', 'on', 'true'].includes(normalized)) {
    addIndeterminate(indeterminateCodes, 'management-frame-protection-unknown');
  }
}

function secretPresence(row, fields, indeterminateCodes) {
  let knownEmpty = false;
  let unknown = false;
  for (const field of fields) {
    if (!own(row, field)) continue;
    const value = safeRead(row, field);
    if (typeof value !== 'string') {
      unknown = true;
    } else if (value.length > 0) {
      return true;
    } else {
      knownEmpty = true;
    }
  }
  if (unknown) {
    addIndeterminate(indeterminateCodes, 'secret-presence-unknown');
    return null;
  }
  if (knownEmpty) return false;
  addIndeterminate(indeterminateCodes, 'secret-presence-unknown');
  return null;
}

function normalizeStatus(section) {
  const status = isRecord(section) ? safeRead(section, 'status') : undefined;
  return VALID_STATUSES.has(status) ? status : 'error';
}

/** Analyze explicit security facts in RouterOS wireless security profile snapshots. */
export function buildWirelessSecurityAudit(input = {}) {
  const inputSections = isRecord(input) && isRecord(safeRead(input, 'sections'))
    ? safeRead(input, 'sections')
    : {};
  const coverage = {};
  const findings = [];
  const indeterminate = [];
  const profiles = [];
  let findingCount = 0;
  let indeterminateCount = 0;
  let profilesOmittedCount = 0;

  const addItems = (target, entries, countKey) => {
    for (const entry of entries) {
      if (countKey === 'finding') findingCount += 1;
      else indeterminateCount += 1;
      if (target.length < MAX_OUTPUT_ITEMS) target.push(entry);
    }
  };

  for (const sectionKey of SECTION_KEYS) {
    const section = safeRead(inputSections, sectionKey);
    let status = normalizeStatus(section);
    if (status !== 'available') {
      coverage[sectionKey] = { status, recordCount: null };
      indeterminateCount += 1;
      if (indeterminate.length < MAX_OUTPUT_ITEMS) indeterminate.push({ section: sectionKey, index: null, code: 'section-unavailable' });
      continue;
    }

    const records = safeRead(section, 'records');
    if (!Array.isArray(records)) {
      status = 'error';
      coverage[sectionKey] = { status, recordCount: null };
      indeterminateCount += 1;
      if (indeterminate.length < MAX_OUTPUT_ITEMS) indeterminate.push({ section: sectionKey, index: null, code: 'records-unavailable' });
      continue;
    }

    const totalValue = safeRead(section, 'total');
    const total = totalValue === undefined ? records.length
      : typeof totalValue === 'number' ? totalValue
        : typeof totalValue === 'string' && /^\d+$/.test(totalValue) ? Number(totalValue) : NaN;
    const complete = safeRead(section, 'truncated') !== true
      && safeRead(section, 'partial') !== true
      && Number.isSafeInteger(total)
      && total === records.length
      && records.length <= MAX_RECORDS;
    coverage[sectionKey] = { status: 'available', recordCount: records.length, complete };
    if (!complete) {
      indeterminateCount += 1;
      if (indeterminate.length < MAX_OUTPUT_ITEMS) {
        indeterminate.push({ section: sectionKey, index: null, code: records.length > MAX_RECORDS ? 'record-limit-exceeded' : 'partial-section' });
      }
    }
    const limit = Math.min(records.length, MAX_RECORDS);
    for (let index = 0; index < limit; index += 1) {
      const row = records[index];
      const findingCodes = [];
      const indeterminateCodes = [];
      let hasSecret = null;
      if (!isRecord(row)) {
        indeterminateCodes.push('malformed-profile-record');
      } else {
        const schema = SECTION_SCHEMAS[sectionKey];
        analyzeMode(row, schema, findingCodes, indeterminateCodes);
        analyzeAuthentication(row, schema, findingCodes, indeterminateCodes);
        analyzeCiphers(row, schema, findingCodes, indeterminateCodes);
        analyzeManagementProtection(row, schema, findingCodes, indeterminateCodes);
        hasSecret = secretPresence(row, schema.secrets, indeterminateCodes);
      }
      if (profiles.length < MAX_OUTPUT_ITEMS) profiles.push({ section: sectionKey, index, secretPresent: hasSecret });
      else profilesOmittedCount += 1;
      for (const code of findingCodes) addItems(findings, [{ section: sectionKey, index, code }], 'finding');
      for (const code of indeterminateCodes) addItems(indeterminate, [{ section: sectionKey, index, code }], 'indeterminate');
    }

    if (records.length > MAX_RECORDS) {
      indeterminateCount += 1;
      if (indeterminate.length < MAX_OUTPUT_ITEMS) {
        indeterminate.push({ section: sectionKey, index: null, code: 'record-limit-exceeded' });
      }
    }
  }

  return {
    coverage: { sections: coverage },
    profiles,
    profilesOmittedCount,
    profilesTruncated: profilesOmittedCount > 0,
    findings,
    findingCount,
    findingsTruncated: findingCount > findings.length,
    indeterminate,
    indeterminateCount,
    indeterminateTruncated: indeterminateCount > indeterminate.length,
    notes: [
      'Only explicit authentication, encryption, management-frame-protection, and secret-presence fields are evaluated; missing or unsupported values remain indeterminate.',
      'Secret fields are reduced to a presence boolean and are never returned. Profile names, comments, key values, SSIDs, MAC addresses, and raw rows are not included.',
      'No finding is not proof that a profile is safe; this is a read-only snapshot analysis.',
    ],
  };
}
