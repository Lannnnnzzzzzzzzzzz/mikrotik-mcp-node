const SECTION_KEYS = [
  'radiusClients',
  'userManagerUsers',
  'profiles',
  'routers',
  'sessions',
  'limitations',
];

const MAX_RECORDS_PER_SECTION = 100;
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const FORBIDDEN_KEY_PARTS = /password|secret|key|token|otp|attribute|credential|raw[-_]?value|comment/i;

const PROJECTED_FIELDS = {
  radiusClients: {
    service: ['service'],
    address: ['address'],
    protocol: ['protocol'],
    authenticationPort: ['authentication-port', 'authenticationPort'],
    accountingPort: ['accounting-port', 'accountingPort'],
    disabled: ['disabled'],
  },
  userManagerUsers: {
    name: ['name'],
    disabled: ['disabled'],
  },
  profiles: {
    name: ['name'],
    validity: ['validity'],
    startsWhen: ['starts-when', 'startsWhen'],
  },
  routers: {
    name: ['name'],
    address: ['address'],
    disabled: ['disabled'],
  },
  sessions: {
    user: ['user', 'username'],
    address: ['address'],
    nasAddress: ['nas-address', 'nasAddress'],
    nasPortId: ['nas-port-id', 'nasPortId'],
    startedAt: ['started-at', 'startedAt', 'started'],
    uptime: ['uptime'],
    status: ['status'],
    bytesIn: ['bytes-in', 'bytesIn'],
    bytesOut: ['bytes-out', 'bytesOut'],
  },
  limitations: {
    name: ['name'],
    uptimeLimit: ['uptime-limit', 'uptimeLimit'],
    transferLimit: ['transfer-limit', 'transferLimit'],
    downloadLimit: ['download-limit', 'downloadLimit'],
    uploadLimit: ['upload-limit', 'uploadLimit'],
  },
};

const OVERVIEW_NOTES = [
  'This is an on-demand accounting snapshot, not a billing-grade record.',
  'RouterOS User Manager availability depends on installed packages and permissions; accounting may be incomplete, stale, or NAS-dependent.',
];

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function safeRead(object, key) {
  try {
    return object[key];
  } catch {
    return undefined;
  }
}

function safeScalar(value) {
  return typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value));
}

function safeNote(value) {
  if (typeof value !== 'string') return undefined;
  const note = value.trim().slice(0, 500);
  if (!note) return undefined;
  // Avoid forwarding common inline secret assignments in free-form collector notes.
  return note.replace(/\b(password|secret|token|otp|credential|api[-_ ]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]');
}

function normalizeDevice(device) {
  if (typeof device === 'string' && device.length <= 128) return device;
  if (!isRecord(device)) return undefined;
  const result = {};
  for (const key of ['id', 'name', 'address']) {
    const value = safeRead(device, key);
    if (safeScalar(value) && (typeof value !== 'string' || value.length <= 253)) result[key] = value;
  }
  return Object.keys(result).length ? result : undefined;
}

function normalizeSampledAt(sampledAt) {
  if (sampledAt instanceof Date && Number.isFinite(sampledAt.getTime())) return sampledAt.toISOString();
  return typeof sampledAt === 'string' && sampledAt.length <= 128 ? sampledAt : undefined;
}

function normalizeStatus(section) {
  if (!isRecord(section)) return 'error';
  const status = safeRead(section, 'status');
  return VALID_STATUSES.has(status) ? status : 'error';
}

function projectRecord(sectionKey, row) {
  if (!isRecord(row)) return null;
  const fields = PROJECTED_FIELDS[sectionKey];
  const projected = {};
  for (const [outputKey, inputKeys] of Object.entries(fields)) {
    if (FORBIDDEN_KEY_PARTS.test(outputKey)) continue;
    for (const inputKey of inputKeys) {
      if (FORBIDDEN_KEY_PARTS.test(inputKey)) continue;
      const value = safeRead(row, inputKey);
      if (safeScalar(value)) {
        projected[outputKey] = value;
        break;
      }
    }
  }
  return Object.keys(projected).length ? projected : null;
}

function sectionNote(section, status) {
  const supplied = isRecord(section) ? safeNote(safeRead(section, 'note')) : undefined;
  if (supplied) return supplied;
  if (status === 'unavailable-or-not-permitted') return 'Data was unavailable or permission was not granted.';
  if (status === 'error') return 'Data could not be read or the section input was malformed.';
  return undefined;
}

function numericBytes(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? value : null;
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) {
    const number = Number(value);
    return Number.isSafeInteger(number) ? number : null;
  }
  return null;
}

/** Build a minimized, on-demand accounting overview without performing I/O. */
export function buildAaaOverview({ device, sampledAt, sections } = {}) {
  const normalizedSections = {};
  const topLevelNotes = [...OVERVIEW_NOTES];
  let allProjectedSessions = null;
  const inputSections = isRecord(sections) ? sections : {};

  for (const sectionKey of SECTION_KEYS) {
    const section = safeRead(inputSections, sectionKey);
    const status = normalizeStatus(section);
    const note = sectionNote(section, status);
    const normalized = { status };

    if (status === 'available') {
      const recordsInput = safeRead(section, 'records');
      const sourceRecords = recordsInput === undefined ? [] : Array.isArray(recordsInput) ? recordsInput : null;
      if (sourceRecords === null) {
        normalized.status = 'error';
        normalized.recordCount = null;
        normalized.records = null;
        normalized.truncated = false;
        normalized.note = 'The available section had a malformed records value; it was not treated as empty.';
      } else {
        const projectedRecords = [];
        for (const row of sourceRecords) {
          const projected = projectRecord(sectionKey, row);
          if (projected) projectedRecords.push(projected);
        }
        if (sectionKey === 'sessions') allProjectedSessions = projectedRecords;
        normalized.recordCount = projectedRecords.length;
        normalized.records = projectedRecords.slice(0, MAX_RECORDS_PER_SECTION);
        normalized.truncated = projectedRecords.length > MAX_RECORDS_PER_SECTION;
        if (note) normalized.note = note;
      }
    } else {
      normalized.recordCount = null;
      normalized.records = null;
      normalized.truncated = false;
      if (note) normalized.note = note;
    }

    if (normalized.note) topLevelNotes.push(`${sectionKey}: ${normalized.note}`);
    normalizedSections[sectionKey] = normalized;
  }

  const output = {
    ...(normalizeDevice(device) !== undefined ? { device: normalizeDevice(device) } : {}),
    ...(normalizeSampledAt(sampledAt) !== undefined ? { sampledAt: normalizeSampledAt(sampledAt) } : {}),
    sections: normalizedSections,
    notes: [...new Set(topLevelNotes)],
  };

  if (normalizedSections.sessions.status === 'available') {
    const sessionRows = allProjectedSessions ?? [];
    let bytesIn = 0;
    let bytesOut = 0;
    let bytesInComplete = true;
    let bytesOutComplete = true;
    for (const row of sessionRows) {
      if (Object.hasOwn(row, 'bytesIn')) {
        const value = numericBytes(row.bytesIn);
        if (value === null) bytesInComplete = false;
        else bytesIn += value;
      } else bytesInComplete = false;
      if (Object.hasOwn(row, 'bytesOut')) {
        const value = numericBytes(row.bytesOut);
        if (value === null) bytesOutComplete = false;
        else bytesOut += value;
      } else bytesOutComplete = false;
    }
    output.sessionTotals = {
      sessionCount: normalizedSections.sessions.recordCount,
      bytesInTotal: bytesInComplete && Number.isSafeInteger(bytesIn) ? bytesIn : null,
      bytesOutTotal: bytesOutComplete && Number.isSafeInteger(bytesOut) ? bytesOut : null,
    };
    if (!bytesInComplete || !bytesOutComplete || !Number.isSafeInteger(bytesIn) || !Number.isSafeInteger(bytesOut)) {
      output.notes.push('Session byte totals are null when any included session lacks a valid byte counter or the sum exceeds the safe integer range.');
    }
  }

  return output;
}
