const SECTION_KEYS = [
  'routes',
  'bgp_sessions',
  'ospf_neighbors',
  'rip_neighbors',
  'rip_routes',
  'routing_bfd_peers',
];
const MAX_FINDINGS = 100;
const MAX_VALUE_LENGTH = 256;
const VALID_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const LIMITATION = 'This snapshot does not test end-to-end reachability, forwarding, or service availability.';

const EVIDENCE_FIELDS = {
  routes: ['.id', 'dst-address', 'gateway', 'immediate-gw', 'routing-table', 'distance', 'active', 'disabled'],
  bgp_sessions: ['.id', 'name', 'remote.address', 'remote.as', 'local.as', 'state', 'uptime', 'prefix-count', 'established'],
  ospf_neighbors: ['.id', 'instance', 'area', 'router-id', 'address', 'state', 'uptime'],
  rip_neighbors: ['.id', 'instance', 'address', 'interface', 'uptime', 'last-update'],
  rip_routes: ['.id', 'dst-address', 'gateway', 'metric', 'active', 'distance'],
  routing_bfd_peers: ['.id', 'local-address', 'remote-address', 'state', 'uptime', 'rx-interval', 'tx-interval'],
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

function safeValue(value) {
  if (typeof value === 'string') return value.slice(0, MAX_VALUE_LENGTH);
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return undefined;
}

function normalizeStatus(section) {
  const value = isRecord(section) ? safeRead(section, 'status') : undefined;
  return VALID_STATUSES.has(value) ? value : 'error';
}

function projectEvidence(sectionKey, row) {
  if (!isRecord(row)) return null;
  const evidence = {};
  for (const field of EVIDENCE_FIELDS[sectionKey]) {
    const value = safeValue(safeRead(row, field));
    if (value !== undefined) evidence[field] = value;
  }
  return evidence;
}

function booleanValue(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['true', 'yes', '1'].includes(normalized)) return true;
  if (['false', 'no', '0'].includes(normalized)) return false;
  return undefined;
}

function normalizedState(value) {
  return typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : undefined;
}

function addFinding(findings, type, section, evidence, counter) {
  counter.count += 1;
  if (findings.length >= MAX_FINDINGS) return;
  findings.push({ type, section, evidence, limitation: LIMITATION });
}

/** Build a bounded, read-only routing protocol health summary from supplied RouterOS sections. */
export function buildRoutingProtocolAudit(input = {}) {
  const deviceInput = isRecord(input) ? safeRead(input, 'device') : undefined;
  const sectionsInput = isRecord(input) ? safeRead(input, 'sections') : undefined;
  const sections = isRecord(sectionsInput) ? sectionsInput : {};
  const sectionSummaries = {};
  const findings = [];
  const findingCounter = { count: 0 };
  const coverageCounts = { available: 0, 'unavailable-or-not-permitted': 0, error: 0 };
  const projectedRows = {};

  for (const sectionKey of SECTION_KEYS) {
    const section = safeRead(sections, sectionKey);
    let status = normalizeStatus(section);
    let recordCount = null;
    let validRecordCount = null;
    let rows = [];

    if (status === 'available') {
      const records = safeRead(section, 'records');
      if (records === undefined) {
        rows = [];
      } else if (Array.isArray(records)) {
        rows = records;
      } else {
        status = 'error';
      }
      if (status === 'available') {
        recordCount = rows.length;
        projectedRows[sectionKey] = rows.map((row) => projectEvidence(sectionKey, row));
        validRecordCount = projectedRows[sectionKey].filter(Boolean).length;
      }
    }

    coverageCounts[status] += 1;
    sectionSummaries[sectionKey] = {
      status,
      recordCount,
      validRecordCount,
    };
  }

  let activeRouteCount = null;
  let inactiveRouteCount = null;
  let unknownRouteCount = null;
  const routeSection = sectionSummaries.routes;
  if (routeSection.status === 'available') {
    activeRouteCount = 0;
    inactiveRouteCount = 0;
    unknownRouteCount = 0;
    for (let index = 0; index < projectedRows.routes.length; index += 1) {
      const evidence = projectedRows.routes[index];
      if (!evidence) {
        unknownRouteCount += 1;
        continue;
      }
      const active = booleanValue(evidence.active);
      const disabled = booleanValue(evidence.disabled);
      if (disabled === true || active === false) inactiveRouteCount += 1;
      else if (active === true) activeRouteCount += 1;
      else unknownRouteCount += 1;
    }
  }

  const protocolCounts = {};
  for (const sectionKey of ['bgp_sessions', 'ospf_neighbors', 'rip_neighbors', 'rip_routes', 'routing_bfd_peers']) {
    const summary = sectionSummaries[sectionKey];
    protocolCounts[sectionKey] = summary.status === 'available' ? summary.validRecordCount : null;
  }

  if (sectionSummaries.bgp_sessions.status === 'available') {
    for (const evidence of projectedRows.bgp_sessions) {
      if (!evidence) continue;
      const established = booleanValue(evidence.established);
      const state = normalizedState(evidence.state);
      if (established === false || (state !== undefined && state !== 'established')) {
        addFinding(findings, 'bgp-not-established', 'bgp_sessions', evidence, findingCounter);
      }
    }
  }
  if (sectionSummaries.ospf_neighbors.status === 'available') {
    for (const evidence of projectedRows.ospf_neighbors) {
      const state = evidence && normalizedState(evidence.state);
      if (state !== undefined && state !== 'full') {
        addFinding(findings, 'ospf-not-full', 'ospf_neighbors', evidence, findingCounter);
      }
    }
  }
  if (sectionSummaries.routing_bfd_peers.status === 'available') {
    for (const evidence of projectedRows.routing_bfd_peers) {
      const state = evidence && normalizedState(evidence.state);
      if (state !== undefined && state !== 'up') {
        addFinding(findings, 'bfd-not-up', 'routing_bfd_peers', evidence, findingCounter);
      }
    }
  }

  const device = {};
  if (typeof deviceInput === 'string' && deviceInput.length <= 128) device.name = deviceInput;
  else if (isRecord(deviceInput)) {
    for (const field of ['id', 'name', 'address']) {
      const value = safeValue(safeRead(deviceInput, field));
      if (value !== undefined && (typeof value !== 'string' || value.length <= 253)) device[field] = value;
    }
  }

  return {
    ...(Object.keys(device).length ? { device } : {}),
    coverage: {
      counts: coverageCounts,
      sections: sectionSummaries,
    },
    routeTotals: {
      active: activeRouteCount,
      inactive: inactiveRouteCount,
      unknown: unknownRouteCount,
    },
    protocolCounts,
    findings,
    findingsTruncated: findingCounter.count > findings.length,
    notes: [
      'Counts describe rows observed in this snapshot; absent, unavailable, or malformed data is unknown rather than healthy.',
      'RIP is reported as observed neighbor and route rows; no RIP health is inferred.',
      'Route totals classify explicit active/disabled flags only; this summary does not simulate route lookup.',
      LIMITATION,
    ],
  };
}
