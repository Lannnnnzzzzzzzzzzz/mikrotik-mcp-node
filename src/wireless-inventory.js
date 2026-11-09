const SECTION_KEYS = ['legacyWireless', 'legacyCapsman', 'wifi'];
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const SECTION_DRIVERS = {
  legacyWireless: 'legacy-wireless',
  legacyCapsman: 'legacy-capsman',
  wifi: 'wifi',
};

const SOURCE_FIELDS = {
  legacyWireless: { signal: 'signal-strength' },
  legacyCapsman: { signal: 'signal-strength' },
  wifi: { signal: 'signal' },
};

const OBSERVATION_NOTE = 'This is a current, possibly incomplete observation; it does not infer history or reachability. No scan or write occurred.';
const WIFI_SOURCE_NOTE = 'The wifi source is the shared new-WiFi registration table for local WiFi and WiFi CAPsMAN clients.';
const PROPERTY_KEYS = {
  id: ['.id', 'id'],
  interface: ['interface'],
  mac: ['mac-address'],
  ssid: ['ssid'],
  txRate: ['tx-rate'],
  rxRate: ['rx-rate'],
  uptime: ['uptime'],
  lastActivity: ['last-activity'],
};

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

function safeField(row, keys) {
  for (const key of keys) {
    const value = safeRead(row, key);
    if (safeScalar(value)) return value;
  }
  return null;
}

// Accept only a standalone numeric value, optionally followed by an explicit dBm label.
// No unit is added or inferred in the output.
function parseSignal(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  const match = value.trim().match(/^([+-]?(?:\d+(?:\.\d*)?|\.\d+))(?:\s*dBm)?$/i);
  if (!match) return null;
  const numeric = Number(match[1]);
  return Number.isFinite(numeric) ? numeric : null;
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

function normalizeSection(section) {
  if (!isRecord(section)) return { status: 'error' };
  const status = safeRead(section, 'status');
  return { status: VALID_STATUSES.has(status) ? status : 'error', section };
}

function normalizeAssociation(sectionKey, row) {
  if (!isRecord(row)) return null;
  const signalField = SOURCE_FIELDS[sectionKey].signal;
  return {
    source: sectionKey,
    driver: SECTION_DRIVERS[sectionKey],
    id: safeField(row, PROPERTY_KEYS.id),
    interface: safeField(row, PROPERTY_KEYS.interface),
    mac: safeField(row, PROPERTY_KEYS.mac),
    ssid: safeField(row, PROPERTY_KEYS.ssid),
    signal: parseSignal(safeRead(row, signalField)),
    txRate: safeField(row, PROPERTY_KEYS.txRate),
    rxRate: safeField(row, PROPERTY_KEYS.rxRate),
    uptime: safeField(row, PROPERTY_KEYS.uptime),
    lastActivity: safeField(row, PROPERTY_KEYS.lastActivity),
  };
}

/** Build a pure, minimized inventory of current wireless association observations. */
export function buildWirelessInventory({ device, sampledAt, sections } = {}) {
  const inputSections = isRecord(sections) ? sections : {};
  const coverage = {};
  const associations = [];

  for (const sectionKey of SECTION_KEYS) {
    const { status, section } = normalizeSection(safeRead(inputSections, sectionKey));
    if (status !== 'available') {
      coverage[sectionKey] = { status, recordCount: null, associationCount: null };
      continue;
    }

    const records = safeRead(section, 'records');
    if (records !== undefined && !Array.isArray(records)) {
      coverage[sectionKey] = { status: 'error', recordCount: null, associationCount: null };
      continue;
    }

    const sourceRows = records ?? [];
    const normalizedRows = [];
    for (const row of sourceRows) {
      const normalized = normalizeAssociation(sectionKey, row);
      if (normalized) normalizedRows.push(normalized);
    }
    associations.push(...normalizedRows);
    coverage[sectionKey] = {
      status: 'available',
      recordCount: sourceRows.length,
      associationCount: normalizedRows.length,
    };
  }

  const normalizedDevice = normalizeDevice(device);
  const normalizedTime = normalizeSampledAt(sampledAt);
  return {
    ...(normalizedDevice !== undefined ? { device: normalizedDevice } : {}),
    ...(normalizedTime !== undefined ? { sampledAt: normalizedTime } : {}),
    observation: {
      scope: 'current wireless association observation',
      completeness: 'possibly incomplete',
      scanPerformed: false,
      writePerformed: false,
    },
    coverage,
    associations,
    notes: [OBSERVATION_NOTE, WIFI_SOURCE_NOTE, 'Signal values are numeric observations only; no measurement unit is inferred.'],
  };
}
