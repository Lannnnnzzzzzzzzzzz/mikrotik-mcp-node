import { isIP } from 'node:net';

const MAX_ROUTES = 500;
const REDACTED_DESTINATION = '[redacted IPv6 address]';
const LIMITATIONS = [
  'This is a snapshot-based IPv6 route-candidate simulation, not RouterOS-equivalent forwarding or an end-to-end reachability test.',
  'Recursive next-hop resolution, gateway reachability, scope/target-scope, ECMP forwarding behavior, and route-type semantics are not evaluated.',
  'Routing rules and VRF/table selection are not evaluated; the caller must supply a routingTable and the result applies only within that table.',
  'IPv6 address and gateway values are not included in the result.',
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

function read(object, key) {
  try {
    return object[key];
  } catch {
    return undefined;
  }
}

function parseIpv6(value) {
  if (typeof value !== 'string' || isIP(value) !== 6) return null;
  let address = value.toLowerCase();
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const ipv4 = address.slice(lastColon + 1).split('.').map(Number);
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    address = `${address.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = address.split('::');
  let groups;
  if (halves.length === 1) {
    groups = halves[0].split(':');
    if (groups.length !== 8) return null;
  } else {
    if (halves.length !== 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  }
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n);
}

function parseCidr(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split('/');
  if (parts.length !== 2 || !/^(0|[1-9][0-9]{0,2})$/.test(parts[1])) return null;
  const address = parseIpv6(parts[0]);
  const prefix = Number(parts[1]);
  if (address === null || prefix > 128) return null;
  const shift = BigInt(128 - prefix);
  return { prefix, network: (address >> shift) << shift };
}

function parseBoolean(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  switch (value.trim().toLowerCase()) {
    case 'true':
    case 'yes':
    case '1':
      return true;
    case 'false':
    case 'no':
    case '0':
      return false;
    default:
      return undefined;
  }
}

function parseDistance(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 0 && value <= 255 ? value : null;
  }
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,2})$/.test(value.trim())) return null;
  const distance = Number(value.trim());
  return distance <= 255 ? distance : null;
}

function hasCompleteCoverage(coverage, routeCount) {
  if (coverage === 'complete') return true;
  if (!isRecord(coverage)) return false;
  const status = read(coverage, 'status');
  const complete = status === 'complete' || (status === 'available' && read(coverage, 'complete') === true);
  if (!complete || read(coverage, 'truncated') === true) return false;
  const recordCount = read(coverage, 'recordCount');
  return recordCount === undefined || (Number.isInteger(recordCount) && recordCount === routeCount);
}

function unknownResult(routingTable, reason) {
  return {
    status: 'unknown',
    destination: REDACTED_DESTINATION,
    routingTable: typeof routingTable === 'string' ? routingTable : null,
    winners: null,
    rank: null,
    uncertainty: [reason],
    limitations: LIMITATIONS,
  };
}

/**
 * Rank IPv6 route candidates in one explicitly selected table by longest prefix,
 * then lowest distance. Complete route coverage is required; this never models
 * forwarding or reachability, and returned route metadata contains no IP values.
 */
export function simulateIpv6RouteCandidates(input = {}) {
  const destination = isRecord(input) ? read(input, 'destination') : undefined;
  const routingTable = isRecord(input) ? read(input, 'routingTable') : undefined;
  const routes = isRecord(input) ? read(input, 'routes') : undefined;
  const coverage = isRecord(input) ? read(input, 'coverage') : undefined;
  const destinationNumber = parseIpv6(destination);
  if (destinationNumber === null) return unknownResult(routingTable, 'destination must be a valid IPv6 address.');
  if (typeof routingTable !== 'string' || !routingTable.trim()) {
    return unknownResult(routingTable, 'routingTable must be supplied explicitly as a non-empty table name.');
  }
  if (!Array.isArray(routes)) return unknownResult(routingTable, 'routes must be an array of route records.');
  if (routes.length > MAX_ROUTES) return unknownResult(routingTable, `routes exceeds the ${MAX_ROUTES}-record safety limit.`);
  if (!hasCompleteCoverage(coverage, routes.length)) {
    return unknownResult(routingTable, 'coverage must explicitly confirm a complete, non-truncated route snapshot matching the supplied routes.');
  }

  const eligible = [];
  for (let index = 0; index < routes.length; index += 1) {
    const route = routes[index];
    if (!isRecord(route)) return unknownResult(routingTable, `route at index ${index} is not a valid record.`);
    const disabled = parseBoolean(read(route, 'disabled'));
    const active = parseBoolean(read(route, 'active'));
    if (disabled === true || active === false) continue;
    if (disabled !== false || active !== true) {
      return unknownResult(routingTable, `route at index ${index} has missing or malformed active/disabled state.`);
    }
    const table = read(route, 'routing-table');
    if (typeof table !== 'string' || !table.trim()) {
      return unknownResult(routingTable, `active route at index ${index} has no valid routing-table.`);
    }
    if (table !== routingTable) continue;
    const cidr = parseCidr(read(route, 'dst-address'));
    if (!cidr) return unknownResult(routingTable, `active route at index ${index} has a missing or malformed IPv6 dst-address CIDR.`);
    const distance = parseDistance(read(route, 'distance'));
    if (distance === null) return unknownResult(routingTable, `active route at index ${index} has a missing or malformed distance.`);
    const shift = BigInt(128 - cidr.prefix);
    if ((destinationNumber >> shift) << shift !== cidr.network) continue;
    const id = read(route, '.id');
    eligible.push({
      ...(typeof id === 'string' || typeof id === 'number' ? { id } : {}),
      routingTable: table,
      distance,
      prefixLength: cidr.prefix,
    });
  }

  if (eligible.length === 0) {
    return { status: 'unmatched', destination: REDACTED_DESTINATION, routingTable, winners: [], rank: null, uncertainty: [], limitations: LIMITATIONS };
  }
  const longestPrefix = Math.max(...eligible.map((route) => route.prefixLength));
  const longest = eligible.filter((route) => route.prefixLength === longestPrefix);
  const lowestDistance = Math.min(...longest.map((route) => route.distance));
  const winners = longest.filter((route) => route.distance === lowestDistance);
  return {
    status: 'matched',
    destination: REDACTED_DESTINATION,
    routingTable,
    winners,
    rank: { prefixLength: longestPrefix, distance: lowestDistance },
    uncertainty: [],
    limitations: LIMITATIONS,
  };
}
