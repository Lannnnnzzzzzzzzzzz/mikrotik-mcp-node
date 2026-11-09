import net from 'node:net';
import { RESOURCE_BY_KEY } from './catalog.js';
import { validateChangeInput } from './change-planner.js';

const NAME = /^[a-zA-Z0-9_.:@-]{1,64}$/;
const MAX_INTERFACES = 64;
const MAX_EXISTING = 128;
const IPV6_LIMIT = (1n << 128n) - 1n;

function safeName(value, field) {
  if (typeof value !== 'string' || !NAME.test(value)) {
    throw new TypeError(`${field} must be a 1–64 character RouterOS interface/name identifier without spaces or command syntax.`);
  }
  return value;
}

function ipv6Number(value, field) {
  if (typeof value !== 'string' || net.isIP(value) !== 6) {
    throw new TypeError(`${field} must be a valid IPv6 address without a zone identifier.`);
  }
  let groups = value.toLowerCase().split('::');
  if (groups.length > 2) throw new TypeError(`${field} must be a valid IPv6 address.`);
  const parseGroups = (part) => {
    if (part === '') return [];
    return part.split(':').flatMap((group) => {
      if (group.includes('.')) {
        const octets = group.split('.').map(Number);
        if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
          throw new TypeError(`${field} must be a valid IPv6 address.`);
        }
        return [((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16)];
      }
      return [group];
    });
  };
  const left = parseGroups(groups[0]);
  const right = groups.length === 2 ? parseGroups(groups[1]) : [];
  let expanded;
  if (groups.length === 1) {
    if (left.length !== 8) throw new TypeError(`${field} must be a valid IPv6 address.`);
    expanded = left;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 1) throw new TypeError(`${field} must be a valid IPv6 address.`);
    expanded = [...left, ...Array(missing).fill('0'), ...right];
  }
  return expanded.reduce((valueSoFar, group) => (valueSoFar << 16n) | BigInt(`0x${group || '0'}`), 0n);
}

function parseIpv6Prefix(value, field, { allowHostAddress = false } = {}) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be an IPv6 CIDR string.`);
  const [address, prefixText, extra] = value.split('/');
  if (prefixText === undefined || extra !== undefined || !/^(0|[1-9]\d{0,2})$/.test(prefixText)) {
    throw new TypeError(`${field} must use IPv6 address/prefix notation.`);
  }
  const prefix = Number(prefixText);
  if (prefix < 0 || prefix > 128) throw new RangeError(`${field} prefix must be from 0 to 128.`);
  const addressNumber = ipv6Number(address, field);
  const mask = prefix === 0 ? 0n : (IPV6_LIMIT << BigInt(128 - prefix)) & IPV6_LIMIT;
  const network = addressNumber & mask;
  if (!allowHostAddress && network !== addressNumber) throw new Error(`${field} must use the network address, not a host address.`);
  return { address, prefix, network, last: network | (IPV6_LIMIT ^ mask) };
}

function ipv6AddressInPrefix(value, field, prefix) {
  const address = ipv6Number(value, field);
  if (address < prefix.network || address > prefix.last || (prefix.prefix < 128 && address === prefix.network)) {
    throw new Error(`${field} must be a host address inside the IPv6 subnet.`);
  }
  return address;
}

function boundedArray(value, field, maximum = MAX_INTERFACES) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new TypeError(`${field} must be an array of at most ${maximum} values.`);
  }
  return value;
}

function uniqueNames(values, field) {
  const names = values.map((value) => safeName(value, field));
  if (new Set(names).size !== names.length) throw new Error(`${field} contains duplicate interface identifiers.`);
  return names;
}

function rejectUnsupported(options) {
  const unsupported = [
    ['dhcpv6', 'DHCPv6'], ['dhcp', 'DHCP'], ['ra', 'router advertisements'],
    ['routerAdvertisements', 'router advertisements'], ['firewallIsolation', 'IPv6 firewall isolation'],
    ['apply', 'applying changes'], ['rollback', 'rollback'],
  ];
  for (const [key, label] of unsupported) {
    if (options[key] === true) throw new Error(`${label} is unsupported by this dry-run IPv6 VLAN builder.`);
  }
}

function validateExistingConflicts({ vlanId, name, existingVlanIds, existingNames, prefix }) {
  if (existingVlanIds !== undefined) {
    const ids = boundedArray(existingVlanIds, 'existingVlanIds', MAX_EXISTING);
    if (ids.some((id) => !Number.isInteger(id) || id < 1 || id > 4094)) {
      throw new RangeError('existingVlanIds must contain VLAN IDs from 1 to 4094.');
    }
    if (new Set(ids).size !== ids.length) throw new Error('existingVlanIds contains duplicate VLAN IDs.');
    if (ids.includes(vlanId)) throw new Error(`VLAN ID ${vlanId} already exists.`);
  }
  if (existingNames !== undefined) {
    const names = boundedArray(existingNames, 'existingNames', MAX_EXISTING).map((item) => safeName(item, 'existing name'));
    if (new Set(names).size !== names.length) throw new Error('existingNames contains duplicate interface/name identifiers.');
    if (names.includes(name)) throw new Error(`VLAN name ${name} already exists.`);
  }
  if (prefix.existingSubnets !== undefined) {
    const subnets = boundedArray(prefix.existingSubnets, 'existingSubnets', MAX_EXISTING);
    const seen = new Set();
    for (const subnet of subnets) {
      const parsed = parseIpv6Prefix(subnet, 'existingSubnets entry', { allowHostAddress: true });
      if (seen.has(subnet)) throw new Error('existingSubnets contains duplicate IPv6 prefixes.');
      seen.add(subnet);
      if (parsed.network <= prefix.last && prefix.network <= parsed.last) {
        throw new Error('IPv6 subnet overlaps an existing IPv6 prefix.');
      }
    }
  }
}

/** Build a validated, dry-run-only IPv6 VLAN plan using only catalog-allowlisted fields. */
export function buildIpv6VlanSegmentPlan(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Options must be an object.');
  rejectUnsupported(options);
  const {
    vlanId, name, subnet, gateway, bridge, taggedPorts = [], untaggedPorts = [],
    existingVlanIds, existingNames, existingSubnets, comment,
  } = options;
  if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
    throw new RangeError('vlanId must be an integer from 1 to 4094.');
  }
  const vlanName = safeName(name, 'name');
  const bridgeName = safeName(bridge, 'bridge');
  if (vlanName === bridgeName) throw new Error('VLAN name must be distinct from the bridge identifier.');
  const network = parseIpv6Prefix(subnet, 'subnet');
  ipv6AddressInPrefix(gateway, 'gateway', network);
  const taggedInput = uniqueNames(boundedArray(taggedPorts, 'taggedPorts'), 'tagged port');
  const untagged = uniqueNames(boundedArray(untaggedPorts, 'untaggedPorts'), 'untagged port');
  if (taggedInput.includes(bridgeName)) throw new Error('taggedPorts must not repeat bridge; the bridge is tagged automatically.');
  const tagged = [bridgeName, ...taggedInput];
  if (tagged.some((item) => untagged.includes(item))) {
    throw new Error('An interface cannot be both tagged and untagged in this VLAN plan.');
  }
  if ([...tagged, ...untagged].includes(vlanName)) {
    throw new Error('VLAN name must not duplicate a bridge-port interface identifier.');
  }
  validateExistingConflicts({
    vlanId, name: vlanName, existingVlanIds, existingNames,
    prefix: { ...network, existingSubnets },
  });
  if (comment !== undefined && comment !== ''
    && (typeof comment !== 'string' || comment.length > 80 || /[\u0000\r\n]/.test(comment))) {
    throw new TypeError('comment must be at most 80 characters and cannot contain control line breaks.');
  }
  const tag = comment ? `managed-by:mikrotik-mcp-js ${comment}` : 'managed-by:mikrotik-mcp-js';
  const steps = [
    { resource: 'vlans', action: 'add', fields: { name: vlanName, interface: bridgeName, 'vlan-id': String(vlanId), comment: `${tag} vlan:interface` } },
    { resource: 'bridge_vlans', action: 'add', fields: { bridge: bridgeName, 'vlan-ids': String(vlanId), tagged: tagged.join(','), untagged: untagged.join(','), comment: `${tag} vlan:membership` } },
    { resource: 'ipv6_addresses', action: 'add', fields: { address: `${gateway}/${network.prefix}`, interface: vlanName, advertise: 'no', comment: `${tag} vlan:gateway` } },
  ];
  for (const step of steps) validateChangeInput(RESOURCE_BY_KEY.get(step.resource), step.action, step.fields);
  return {
    steps,
    notes: [
      'Preview only: no router was contacted or changed; this builder has no apply or rollback capability.',
      'The plan stages only a VLAN interface, bridge VLAN membership and a non-advertised IPv6 address using catalog-allowlisted fields.',
      'DHCPv6, router advertisements, IPv6 firewall isolation, apply and rollback are unsupported and are not staged.',
      'This is not a complete isolated segment. Review bridge hardware capabilities, client-port PVID/frame admission, IPv6 policy and end-to-end behavior separately.',
    ],
  };
}
