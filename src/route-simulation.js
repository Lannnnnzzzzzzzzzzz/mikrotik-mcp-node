const LIMITATIONS = [
  'This is a snapshot-based IPv4 route-candidate simulation, not RouterOS-equivalent forwarding or an end-to-end reachability test.',
  'Recursive next-hop resolution, gateway reachability, scope/target-scope, ECMP forwarding behavior, and route-type semantics are not evaluated.',
  'Routing rules and VRF/table selection are not evaluated; the caller must supply a routingTable and the result applies only within that table.',
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

function parseIpv4(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let number = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    number = number * 256 + octet;
  }
  return number;
}

function parseCidr(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split('/');
  if (parts.length !== 2) return null;
  const address = parseIpv4(parts[0]);
  if (address === null || !/^(0|[1-9]|[12][0-9]|3[0-2])$/.test(parts[1])) return null;
  const prefix = Number(parts[1]);
  const size = 2 ** (32 - prefix);
  return { prefix, network: Math.floor(address / size) * size };
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

function unknownResult(destination, routingTable, reason) {
  return {
    status: 'unknown',
    destination: typeof destination === 'string' ? destination : null,
    routingTable: typeof routingTable === 'string' ? routingTable : null,
    winners: null,
    rank: null,
    uncertainty: [reason],
    limitations: LIMITATIONS,
  };
}

/**
 * Rank IPv4 route candidates in one explicitly selected table by longest prefix,
 * then lowest distance. This does not resolve gateways or emulate RouterOS forwarding.
 */
export function simulateIpv4RouteCandidates(input = {}) {
  const destination = isRecord(input) ? read(input, 'destination') : undefined;
  const routingTable = isRecord(input) ? read(input, 'routingTable') : undefined;
  const routes = isRecord(input) ? read(input, 'routes') : undefined;
  const destinationNumber = parseIpv4(destination);
  if (destinationNumber === null) return unknownResult(destination, routingTable, 'destination must be a valid dotted-decimal IPv4 address.');
  if (typeof routingTable !== 'string' || !routingTable.trim()) {
    return unknownResult(destination, routingTable, 'routingTable must be supplied explicitly as a non-empty table name.');
  }
  if (!Array.isArray(routes)) return unknownResult(destination, routingTable, 'routes must be an array of route records.');

  const eligible = [];
  for (let index = 0; index < routes.length; index += 1) {
    const route = routes[index];
    if (!isRecord(route)) return unknownResult(destination, routingTable, `route at index ${index} is not a valid record.`);

    const disabled = parseBoolean(read(route, 'disabled'));
    const active = parseBoolean(read(route, 'active'));
    if (disabled === true || active === false) continue;
    if (disabled !== false || active !== true) {
      return unknownResult(destination, routingTable, `route at index ${index} has missing or malformed active/disabled state.`);
    }

    const table = read(route, 'routing-table');
    if (typeof table !== 'string' || !table.trim()) {
      return unknownResult(destination, routingTable, `active route at index ${index} has no valid routing-table.`);
    }
    if (table !== routingTable) continue;

    const cidr = parseCidr(read(route, 'dst-address'));
    if (!cidr) return unknownResult(destination, routingTable, `active route at index ${index} has a missing or malformed IPv4 dst-address CIDR.`);
    const distance = parseDistance(read(route, 'distance'));
    if (distance === null) return unknownResult(destination, routingTable, `active route at index ${index} has a missing or malformed distance.`);

    const size = 2 ** (32 - cidr.prefix);
    if (Math.floor(destinationNumber / size) * size !== cidr.network) continue;
    const id = read(route, '.id');
    eligible.push({
      ...(typeof id === 'string' || typeof id === 'number' ? { id } : {}),
      destination: read(route, 'dst-address'),
      routingTable: table,
      distance,
      prefixLength: cidr.prefix,
    });
  }

  if (eligible.length === 0) {
    return {
      status: 'unmatched', destination, routingTable, winners: [], rank: null, uncertainty: [], limitations: LIMITATIONS,
    };
  }

  const longestPrefix = Math.max(...eligible.map((route) => route.prefixLength));
  const longest = eligible.filter((route) => route.prefixLength === longestPrefix);
  const lowestDistance = Math.min(...longest.map((route) => route.distance));
  const winners = longest.filter((route) => route.distance === lowestDistance);
  return {
    status: 'matched',
    destination,
    routingTable,
    winners,
    rank: { prefixLength: longestPrefix, distance: lowestDistance },
    uncertainty: [],
    limitations: LIMITATIONS,
  };
}
