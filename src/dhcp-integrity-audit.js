import { isIP } from 'node:net';

const SECTION_KEYS = ['dhcp_servers', 'dhcp_networks', 'ip_pools_dhcp', 'dhcp_leases'];
const MAX_RECORDS = 2000;
const MAX_FINDINGS = 500;
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const UNAVAILABLE = 'unavailable-or-not-permitted';

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

function booleanValue(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['true', 'yes', '1'].includes(normalized)) return true;
  if (['false', 'no', '0'].includes(normalized)) return false;
  return undefined;
}

function ipv4Number(value) {
  if (typeof value !== 'string' || value.length > 64 || isIP(value) !== 4) return null;
  return value.split('.').reduce((address, octet) => address * 256 + Number(octet), 0);
}

function parseNetwork(value) {
  if (typeof value !== 'string' || value.length > 80 || value.includes(',') || value.includes('!')) return null;
  const parts = value.trim().split('/');
  if (parts.length > 2) return null;
  const address = ipv4Number(parts[0]);
  if (address === null || parts.length !== 2 || !/^\d{1,2}$/.test(parts[1])) return null;
  const prefix = Number(parts[1]);
  if (prefix < 0 || prefix > 32) return null;
  const size = 2 ** (32 - prefix);
  const start = Math.floor(address / size) * size;
  return { start, end: start + size - 1 };
}

function parsePoolRanges(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return null;
  const pieces = value.split(',');
  if (pieces.length > 128) return null;
  const ranges = [];
  for (const piece of pieces) {
    const bounds = piece.trim().split('-');
    if (bounds.length > 2) return null;
    const start = ipv4Number(bounds[0].trim());
    const end = bounds.length === 1 ? start : ipv4Number(bounds[1].trim());
    if (start === null || end === null || start > end) return null;
    ranges.push({ start, end });
  }
  return ranges.length ? ranges : null;
}

function overlaps(left, right) {
  return left.start <= right.end && right.start <= left.end;
}

function normalizeSection(section) {
  const requestedStatus = isRecord(section) ? safeRead(section, 'status') : undefined;
  const status = VALID_STATUSES.has(requestedStatus) ? requestedStatus : 'error';
  if (status !== 'available') return { status, records: [], complete: false, recordCount: null };
  const source = safeRead(section, 'records');
  if (!Array.isArray(source)) return { status: 'error', records: [], complete: false, recordCount: null };
  const observedCount = source.length;
  const records = [];
  const limit = Math.min(observedCount, MAX_RECORDS);
  for (let index = 0; index < limit; index += 1) records.push(source[index]);
  const totalValue = safeRead(section, 'total');
  const total = totalValue === undefined ? observedCount
    : (typeof totalValue === 'number' ? totalValue
      : (typeof totalValue === 'string' && /^\d+$/.test(totalValue) ? Number(totalValue) : NaN));
  const complete = safeRead(section, 'truncated') !== true
    && Number.isSafeInteger(total)
    && total === observedCount
    && observedCount <= MAX_RECORDS;
  return { status, records, complete, recordCount: observedCount };
}

function nameValue(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 ? value : null;
}

function addFinding(findings, counts, severity, code, section, index) {
  const key = `${severity}:${code}`;
  counts[key] = (counts[key] ?? 0) + 1;
  if (findings.length < MAX_FINDINGS) findings.push({ severity, code, section, index, count: 1 });
}

/** Inspect supplied DHCP snapshots for conservative, provable IPv4 integrity issues. */
export function buildDhcpIntegrityAudit(input = {}) {
  const sectionsInput = isRecord(input) ? safeRead(input, 'sections') : undefined;
  const sourceSections = isRecord(sectionsInput) ? sectionsInput : {};
  const sections = Object.fromEntries(SECTION_KEYS.map((key) => [key, normalizeSection(safeRead(sourceSections, key))]));
  const findings = [];
  const counts = {};
  const indeterminateCounts = {};
  const markIndeterminate = (section, code, index = null) => {
    indeterminateCounts[code] = (indeterminateCounts[code] ?? 0) + 1;
    addFinding(findings, counts, 'indeterminate', code, section, index);
  };
  const markIssue = (code, section, index) => addFinding(findings, counts, 'warning', code, section, index);

  for (const key of SECTION_KEYS) {
    const section = sections[key];
    if (section.status === 'available' && !section.complete) {
      markIndeterminate(key, section.recordCount > MAX_RECORDS ? 'record-limit-exceeded' : 'partial-section');
    } else if (section.status !== 'available') {
      markIndeterminate(key, section.status === UNAVAILABLE ? 'section-unavailable' : 'section-error');
    }
  }

  const validRows = Object.fromEntries(SECTION_KEYS.map((key) => [key, []]));
  for (const key of SECTION_KEYS) {
    const section = sections[key];
    if (section.status !== 'available') continue;
    section.records.forEach((row, index) => {
      if (!isRecord(row)) {
        markIndeterminate(key, 'malformed-record', index);
        return;
      }
      validRows[key].push({ row, index });
    });
  }
  const contentComplete = Object.fromEntries(SECTION_KEYS.map((key) => [
    key,
    sections[key].status === 'available'
      && sections[key].complete
      && validRows[key].length === sections[key].records.length,
  ]));

  const poolsByName = new Map();
  const pools = [];
  for (const { row, index } of validRows.ip_pools_dhcp) {
    const name = nameValue(safeRead(row, 'name'));
    const ranges = parsePoolRanges(safeRead(row, 'ranges'));
    const dynamic = booleanValue(safeRead(row, 'dynamic'));
    const nextPool = safeRead(row, 'next-pool');
    const usable = name !== null && ranges !== null && dynamic !== true && (nextPool === undefined || nextPool === '' || nextPool === 'none');
    const pool = { name, ranges, index, usable };
    pools.push(pool);
    if (name !== null) poolsByName.set(name, [...(poolsByName.get(name) ?? []), pool]);
    if (!usable) markIndeterminate('ip_pools_dhcp', 'unsupported-or-malformed-pool', index);
  }

  const networks = [];
  for (const { row, index } of validRows.dhcp_networks) {
    const network = parseNetwork(safeRead(row, 'address'));
    if (network === null) markIndeterminate('dhcp_networks', 'unsupported-or-malformed-network', index);
    else networks.push({ network, index });
  }

  for (const pool of pools) {
    if (!pool.usable) continue;
    for (const range of pool.ranges) {
      if (!contentComplete.dhcp_networks) {
        markIndeterminate('ip_pools_dhcp', 'pool-network-coverage-incomplete', pool.index);
        continue;
      }
      const containingNetworks = networks.filter(({ network }) => range.start >= network.start && range.end <= network.end);
      if (containingNetworks.length === 0) markIssue('pool-outside-dhcp-network', 'ip_pools_dhcp', pool.index);
      else if (containingNetworks.length > 1) markIssue('pool-in-multiple-dhcp-networks', 'ip_pools_dhcp', pool.index);
    }
  }

  const overlappingPools = new Set();
  for (let leftIndex = 0; leftIndex < pools.length; leftIndex += 1) {
    const left = pools[leftIndex];
    if (!left.usable) continue;
    for (let rightIndex = leftIndex + 1; rightIndex < pools.length; rightIndex += 1) {
      const right = pools[rightIndex];
      if (!right.usable) continue;
      if (left.ranges.some((leftRange) => right.ranges.some((rightRange) => overlaps(leftRange, rightRange)))) {
        overlappingPools.add(right.index);
      }
    }
  }
  for (const index of overlappingPools) markIssue('overlapping-pool-ranges', 'ip_pools_dhcp', index);

  const serversByName = new Map();
  for (const { row, index } of validRows.dhcp_servers) {
    const name = nameValue(safeRead(row, 'name'));
    const disabled = booleanValue(safeRead(row, 'disabled'));
    const poolName = safeRead(row, 'address-pool');
    if (name !== null) serversByName.set(name, [...(serversByName.get(name) ?? []), { row, index, disabled, poolName }]);
    if (disabled === undefined) markIndeterminate('dhcp_servers', 'unknown-server-state', index);
    if (disabled !== false) continue;
    if (typeof poolName !== 'string' || poolName.trim() === '') {
      markIndeterminate('dhcp_servers', 'unknown-server-pool', index);
      continue;
    }
    if (['static-only', 'none'].includes(poolName.trim().toLowerCase())) continue;
    const matches = poolsByName.get(poolName) ?? [];
    if (matches.length === 0) {
      if (contentComplete.ip_pools_dhcp) markIssue('referenced-pool-missing', 'dhcp_servers', index);
      else markIndeterminate('dhcp_servers', 'pool-reference-unverifiable', index);
    } else if (matches.length > 1) markIndeterminate('dhcp_servers', 'ambiguous-pool-reference', index);
    else if (!matches[0].usable) markIndeterminate('dhcp_servers', 'unsupported-referenced-pool', index);
  }

  for (const { row, index } of validRows.dhcp_leases) {
    const dynamic = booleanValue(safeRead(row, 'dynamic'));
    if (dynamic === true) continue;
    if (dynamic !== false) {
      markIndeterminate('dhcp_leases', 'unknown-lease-type', index);
      continue;
    }
    const address = ipv4Number(safeRead(row, 'address'));
    const serverName = nameValue(safeRead(row, 'server'));
    if (address === null || serverName === null) {
      markIndeterminate('dhcp_leases', 'unsupported-or-malformed-static-lease', index);
      continue;
    }
    const serverMatches = serversByName.get(serverName) ?? [];
    if (serverMatches.length !== 1 || !contentComplete.dhcp_servers) {
      markIndeterminate('dhcp_leases', 'lease-server-unresolved', index);
      continue;
    }
    const server = serverMatches[0];
    if (server.disabled === true || server.disabled === undefined) continue;
    if (!contentComplete.dhcp_networks) markIndeterminate('dhcp_leases', 'lease-network-coverage-incomplete', index);
    else if (!networks.some(({ network }) => address >= network.start && address <= network.end)) {
      markIssue('static-lease-outside-dhcp-network', 'dhcp_leases', index);
    }
  }

  const coverageSections = Object.fromEntries(SECTION_KEYS.map((key) => [key, {
    status: sections[key].status,
    recordCount: sections[key].recordCount,
    complete: sections[key].status === 'available' ? contentComplete[key] : null,
  }]));
  const totalFindingCount = Object.values(counts).reduce((sum, count) => sum + count, 0);
  return {
    coverage: {
      sections: coverageSections,
      partial: SECTION_KEYS.some((key) => sections[key].status !== 'available' || !sections[key].complete),
    },
    counts,
    indeterminateCounts,
    findings,
    findingsTruncated: totalFindingCount > findings.length,
    limits: { maxRecordsPerSection: MAX_RECORDS, maxFindings: MAX_FINDINGS },
  };
}
