const SECTION_KEYS = [
  'interfaces',
  'ip_addresses',
  'routes',
  'firewall_filter',
  'firewall_nat',
  'dhcp_leases',
  'wireguard_peers',
  'wireless_registrations',
  'legacy_capsman_registrations',
  'wifi_registrations',
];

const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const SYSTEM_FIELDS = [
  'version', 'uptime', 'cpu', 'cpu-count', 'board-name', 'architecture-name', 'free-memory', 'total-memory',
];
const DHCP_STATUSES = ['bound', 'waiting', 'offered', 'declined', 'expired', 'busy', 'unknown', 'other'];
const LIMITATIONS = [
  'This is a minimized read-only summary, not a full configuration export or support bundle.',
  'It is a current snapshot and contains no history; missing, unavailable, malformed, or truncated data is not evidence of health.',
];

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

function safeScalar(value, maxLength = 256) {
  if (typeof value === 'string') return value.length <= maxLength ? value : undefined;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return undefined;
}

function booleanValue(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['true', 'yes', '1'].includes(normalized)) return true;
  if (['false', 'no', '0'].includes(normalized)) return false;
  return undefined;
}

function normalizeSection(section) {
  if (!isRecord(section)) return { status: 'error' };
  const status = safeRead(section, 'status');
  if (!VALID_STATUSES.has(status)) return { status: 'error' };
  if (status !== 'available') return { status };
  const records = safeRead(section, 'records');
  if (!Array.isArray(records)) return { status: 'error' };
  const rawTotal = safeRead(section, 'total');
  const total = typeof rawTotal === 'number' && Number.isSafeInteger(rawTotal) && rawTotal >= 0 ? rawTotal : null;
  return {
    status,
    records,
    truncated: safeRead(section, 'truncated') === true,
    total,
  };
}

function coverageFor(section) {
  if (section.status !== 'available') {
    return { status: section.status, recordCount: null, validRecordCount: null, truncated: null, total: null };
  }
  const validRecordCount = section.records.filter(isRecord).length;
  return {
    status: 'available',
    recordCount: section.records.length,
    validRecordCount,
    truncated: section.truncated,
    total: section.total,
  };
}

function unavailableCounts(fields) {
  return Object.fromEntries(fields.map((field) => [field, null]).concat([['partial', true]]));
}

function summarizeRows(section, classifier) {
  if (section.status !== 'available') return null;
  const counts = classifier.initial();
  let partial = section.truncated;
  for (const row of section.records) {
    if (!isRecord(row)) {
      partial = true;
      continue;
    }
    if (classifier.count(row, counts) === false) partial = true;
  }
  return { ...counts, partial };
}

function classifyBooleanCounts(field, category) {
  return {
    initial: () => ({ total: 0, [category]: 0 }),
    count(row, counts) {
      counts.total += 1;
      const value = booleanValue(safeRead(row, field));
      if (value === undefined) return false;
      if (value) counts[category] += 1;
      return true;
    },
  };
}

function isIpv4Cidr(value) {
  if (typeof value !== 'string') return false;
  const address = value.trim().split('/')[0];
  const parts = address.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function summarizeAddresses(section) {
  return summarizeRows(section, {
    initial: () => ({ total: 0, disabled: 0 }),
    count(row, counts) {
      const address = safeRead(row, 'address');
      if (typeof address === 'string' && address.includes(':')) return true;
      if (!isIpv4Cidr(address)) return false;
      counts.total += 1;
      const disabled = booleanValue(safeRead(row, 'disabled'));
      if (disabled === undefined) return false;
      if (disabled) counts.disabled += 1;
      return true;
    },
  });
}

function summarizeDefaultRoutes(section) {
  return summarizeRows(section, {
    initial: () => ({ total: 0, active: 0, disabled: 0 }),
    count(row, counts) {
      const destination = safeRead(row, 'dst-address');
      if (typeof destination !== 'string') return false;
      if (destination.trim() !== '0.0.0.0/0') return true;
      counts.total += 1;
      const active = booleanValue(safeRead(row, 'active'));
      const disabled = booleanValue(safeRead(row, 'disabled'));
      let known = true;
      if (active === true) counts.active += 1;
      else if (active !== false) known = false;
      if (disabled === true) counts.disabled += 1;
      else if (disabled !== false) known = false;
      return known;
    },
  });
}

function summarizeDhcpLeases(section) {
  return summarizeRows(section, {
    initial: () => ({ total: 0, byStatus: Object.fromEntries(DHCP_STATUSES.map((status) => [status, 0])) }),
    count(row, counts) {
      counts.total += 1;
      const rawStatus = safeRead(row, 'status');
      if (typeof rawStatus !== 'string' || !rawStatus.trim()) {
        counts.byStatus.unknown += 1;
        return false;
      }
      const status = rawStatus.trim().toLowerCase();
      const bucket = DHCP_STATUSES.includes(status) && status !== 'unknown' && status !== 'other' ? status : 'other';
      counts.byStatus[bucket] += 1;
      return bucket !== 'other';
    },
  });
}

function summarizeRegistrations(sections, coverage) {
  const bySource = {};
  let total = 0;
  let partial = false;
  for (const [source, key] of [
    ['wireless', 'wireless_registrations'],
    ['legacy_capsman', 'legacy_capsman_registrations'],
    ['wifi', 'wifi_registrations'],
  ]) {
    const status = coverage[key].status;
    if (status !== 'available') {
      bySource[source] = null;
      partial = true;
      continue;
    }
    const result = summarizeRows(sections[key], {
      initial: () => ({ total: 0 }),
      count(_row, counts) { counts.total += 1; return true; },
    });
    bySource[source] = result.total;
    total += result.total;
    partial ||= result.partial;
  }
  return { bySource, total, partial };
}

function projectDeviceId(device) {
  if (typeof device === 'string') return device.length <= 128 ? device : null;
  if (!isRecord(device)) return null;
  const id = safeScalar(safeRead(device, 'id'), 128);
  return id === undefined ? null : id;
}

function projectNamedScalar(input, key, maxLength = 256) {
  if (!isRecord(input)) return null;
  const value = safeScalar(safeRead(input, key), maxLength);
  return value === undefined ? null : value;
}

/** Build a minimized, read-only RouterOS support summary from supplied observations. */
export function buildRouterSupportSummary(input = {}) {
  const device = safeRead(input, 'device');
  const identity = safeRead(input, 'identity');
  const resources = safeRead(input, 'resources');
  const sections = safeRead(input, 'sections');
  const inputSections = isRecord(sections) ? sections : {};
  const normalizedSections = {};
  const coverageSections = {};
  for (const key of SECTION_KEYS) {
    normalizedSections[key] = normalizeSection(safeRead(inputSections, key));
    coverageSections[key] = coverageFor(normalizedSections[key]);
  }

  const coverage = { sections: coverageSections };
  const summary = {};
  summary.deviceId = projectDeviceId(device);
  summary.identityName = projectNamedScalar(identity, 'name');
  summary.system = {};
  for (const field of SYSTEM_FIELDS) {
    const value = projectNamedScalar(resources, field);
    if (value !== null) summary.system[field] = value;
  }
  summary.coverage = coverage;

  const interfaces = summarizeRows(normalizedSections.interfaces, {
    initial: () => ({ total: 0, running: 0, disabled: 0 }),
    count(row, counts) {
      counts.total += 1;
      const running = booleanValue(safeRead(row, 'running'));
      const disabled = booleanValue(safeRead(row, 'disabled'));
      let known = true;
      if (running === true) counts.running += 1;
      else if (running !== false) known = false;
      if (disabled === true) counts.disabled += 1;
      else if (disabled !== false) known = false;
      return known;
    },
  });
  const filterRules = summarizeRows(normalizedSections.firewall_filter, classifyBooleanCounts('disabled', 'disabled'));
  const natRules = summarizeRows(normalizedSections.firewall_nat, classifyBooleanCounts('disabled', 'disabled'));
  const wireguardPeers = summarizeRows(normalizedSections.wireguard_peers, classifyBooleanCounts('disabled', 'disabled'));

  const registrations = summarizeRegistrations(normalizedSections, coverageSections);
  summary.counts = {
    interfaces: interfaces ?? unavailableCounts(['total', 'running', 'disabled']),
    ipv4Addresses: summarizeAddresses(normalizedSections.ip_addresses) ?? unavailableCounts(['total', 'disabled']),
    defaultIpv4Routes: summarizeDefaultRoutes(normalizedSections.routes) ?? unavailableCounts(['total', 'active', 'disabled']),
    firewallFilterRules: filterRules ?? unavailableCounts(['total', 'disabled']),
    firewallNatRules: natRules ?? unavailableCounts(['total', 'disabled']),
    dhcpLeases: summarizeDhcpLeases(normalizedSections.dhcp_leases) ?? unavailableCounts(['total', 'byStatus']),
    wireguardPeers: wireguardPeers ?? unavailableCounts(['total', 'disabled']),
    wirelessRegistrations: registrations,
  };
  summary.notes = LIMITATIONS.slice();
  return summary;
}
