const MAX_RECORDS = 5000;
const MAX_FINDINGS = 100;
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const SECTION_KEYS = {
  settings: ['ip_dns_settings', 'dns_resolver_settings', 'dns'],
  staticRecords: ['dns_static', 'dns_static_records_extended'],
  upstream: ['dns_upstream_servers', 'dns_servers'],
};

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

function hasOwn(object, key) {
  try {
    return Object.prototype.hasOwnProperty.call(object, key);
  } catch {
    return false;
  }
}

function booleanValue(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['true', 'yes', '1'].includes(normalized)) return true;
  if (['false', 'no', '0'].includes(normalized)) return false;
  return undefined;
}

function nonEmpty(value) {
  if (typeof value !== 'string') return value !== undefined && value !== null && value !== false;
  return value.trim().length > 0;
}

function sectionFor(sections, aliases) {
  for (const key of aliases) {
    if (hasOwn(sections, key)) return safeRead(sections, key);
  }
  return undefined;
}

function normalizeSection(section) {
  const statusValue = isRecord(section) ? safeRead(section, 'status') : undefined;
  const status = VALID_STATUSES.has(statusValue) ? statusValue : 'error';
  if (status !== 'available') return { status, records: [], complete: false };

  const recordsValue = safeRead(section, 'records');
  if (!Array.isArray(recordsValue)) return { status: 'error', records: [], complete: false };
  const totalValue = safeRead(section, 'total');
  const total = totalValue === undefined ? recordsValue.length
    : typeof totalValue === 'number' ? totalValue
      : typeof totalValue === 'string' && /^\d+$/.test(totalValue) ? Number(totalValue) : NaN;
  const complete = safeRead(section, 'truncated') !== true
    && Number.isSafeInteger(total)
    && total === recordsValue.length
    && recordsValue.length <= MAX_RECORDS;
  return { status, records: recordsValue, complete };
}

function normalizeName(value) {
  if (typeof value !== 'string' || value.length > 253) return null;
  const name = value.trim().toLowerCase().replace(/\.+$/, '');
  return name || null;
}

function addFinding(findings, code, severity, recordIndices = []) {
  if (findings.length < MAX_FINDINGS) findings.push({ code, severity, recordIndices });
}

/** Analyze a supplied RouterOS DNS snapshot without exposing names, addresses, or record contents. */
export function buildDnsResolverAudit(input = {}) {
  const inputSections = isRecord(input) ? safeRead(input, 'sections') : undefined;
  const sections = isRecord(inputSections) ? inputSections : {};
  const settings = normalizeSection(sectionFor(sections, SECTION_KEYS.settings));
  const staticRecords = normalizeSection(sectionFor(sections, SECTION_KEYS.staticRecords));
  const upstreamSectionValue = sectionFor(sections, SECTION_KEYS.upstream);
  const upstreamSectionProvided = upstreamSectionValue !== undefined;
  const upstreamSection = upstreamSectionProvided ? normalizeSection(upstreamSectionValue) : null;
  const findings = [];

  const settingsRow = settings.status === 'available' && settings.records.length === 1
    && isRecord(settings.records[0]) ? settings.records[0] : null;
  const settingsComplete = settings.status === 'available' && settings.complete && settings.records.length === 1 && settingsRow !== null;
  const staticComplete = staticRecords.status === 'available' && staticRecords.complete
    && staticRecords.records.every(isRecord);

  if (!settingsComplete) addFinding(findings, 'dns-settings-coverage-incomplete', 'review', []);
  if (!staticComplete) addFinding(findings, 'static-records-coverage-incomplete', 'review', []);

  let allowRemote = null;
  let dohPresent = null;
  let settingsUpstreamKnown = false;
  let settingsUpstreamPresent = false;
  if (settingsRow) {
    const remoteRequestsValue = safeRead(settingsRow, 'allow-remote-requests');
    allowRemote = booleanValue(remoteRequestsValue);
    if (allowRemote === true) {
      // This flag alone cannot establish reachability; no firewall or interface evidence is assumed.
      addFinding(findings, 'remote-requests-enabled-review', 'review', [0]);
    } else if (allowRemote === undefined) {
      addFinding(findings, 'remote-requests-state-unknown', 'review', [0]);
    }
    const dohValue = safeRead(settingsRow, 'use-doh-server');
    dohPresent = nonEmpty(dohValue);
    if (dohPresent) addFinding(findings, 'doh-configured', 'info', [0]);
    else if (hasOwn(settingsRow, 'use-doh-server')) addFinding(findings, 'doh-not-configured', 'info', [0]);
    else addFinding(findings, 'doh-coverage-unknown', 'review', [0]);
    const serverFields = ['servers', 'dynamic-servers'];
    settingsUpstreamKnown = serverFields.some((key) => hasOwn(settingsRow, key));
    settingsUpstreamPresent = serverFields.some((key) => nonEmpty(safeRead(settingsRow, key)));
  }

  let upstreamKnown = settingsUpstreamKnown;
  let upstreamPresent = settingsUpstreamPresent;
  let upstreamRecordCount = null;
  if (upstreamSectionProvided) {
    upstreamKnown = upstreamSection.status === 'available' && upstreamSection.complete;
    upstreamRecordCount = upstreamSection.status === 'available' ? upstreamSection.records.length : null;
    if (upstreamKnown) {
      upstreamPresent = upstreamSection.records.length > 0;
      if (upstreamPresent) addFinding(findings, 'upstream-configured', 'info', upstreamSection.records.map((_, index) => index));
    }
  } else if (settingsUpstreamPresent) {
    addFinding(findings, 'upstream-configured', 'info', [0]);
  }

  if (!upstreamKnown) addFinding(findings, 'upstream-coverage-unknown', 'review', []);
  else if (!upstreamPresent) addFinding(findings, 'upstream-not-configured', 'review', []);

  const seenNames = new Map();
  if (staticRecords.status === 'available') {
    for (let index = 0; index < staticRecords.records.length; index += 1) {
      const row = staticRecords.records[index];
      if (!isRecord(row) || booleanValue(safeRead(row, 'disabled')) === true) continue;
      const name = normalizeName(safeRead(row, 'name'));
      if (!name) continue;
      const priorIndices = seenNames.get(name) ?? [];
      if (priorIndices.length) {
        addFinding(findings, 'duplicate-static-name', 'warning', [...priorIndices, index]);
      }
      priorIndices.push(index);
      seenNames.set(name, priorIndices);
    }
  }

  const recordCount = (section) => section.status === 'available' ? section.records.length : null;
  return {
    findings,
    counts: {
      settingsRecords: recordCount(settings),
      staticRecords: recordCount(staticRecords),
      upstreamRecords: upstreamRecordCount,
      duplicateStaticNames: findings.filter(({ code }) => code === 'duplicate-static-name').length,
      findings: findings.length,
    },
  };
}
