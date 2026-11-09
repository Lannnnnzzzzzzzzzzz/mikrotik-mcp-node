import net from 'node:net';

const NAME = /^[a-zA-Z0-9_.:@-]{1,64}$/;

function ipv4Number(value, field) {
  if (net.isIP(value) !== 4) throw new TypeError(`${field} must be a valid IPv4 address.`);
  return value.split('.').reduce((result, part) => (result << 8n) | BigInt(part), 0n);
}

function parseCidr(value, field = 'subnet') {
  if (typeof value !== 'string') throw new TypeError(`${field} must be an IPv4 CIDR string.`);
  const [address, prefixText, extra] = value.split('/');
  if (prefixText === undefined || extra !== undefined) throw new TypeError(`${field} must use canonical IPv4 CIDR notation.`);
  const ip = ipv4Number(address, field);
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new RangeError(`${field} prefix must be from 0 to 32.`);
  const mask = prefix === 0 ? 0n : (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn;
  const network = ip & mask;
  if (network !== ip) throw new Error(`${field} must use the network address, not a host address.`);
  const broadcast = network | (0xffffffffn ^ mask);
  return { address, prefix, network, broadcast };
}

function port(value, field) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new RangeError(`${field} must be an integer from 1 to 65535.`);
  return String(value);
}

function safeName(value, field) {
  if (typeof value !== 'string' || !NAME.test(value)) throw new TypeError(`${field} must be a 1–64 character RouterOS name without spaces or command syntax.`);
  return value;
}

function safeComment(value) {
  if (value === undefined || value === '') return 'managed-by:mikrotik-mcp-js';
  if (typeof value !== 'string' || value.length > 80 || /[\u0000\r\n]/.test(value)) throw new TypeError('comment must be at most 80 characters and cannot contain control line breaks.');
  return `managed-by:mikrotik-mcp-js ${value}`;
}

export function buildPortForwardPlan({ protocol, externalPort, internalHost, internalPort, wanInterface, lanSubnet, lanInterface, comment }) {
  if (!['tcp', 'udp'].includes(protocol)) throw new TypeError('protocol must be tcp or udp.');
  const publicPort = port(externalPort, 'externalPort');
  const privatePort = port(internalPort ?? externalPort, 'internalPort');
  ipv4Number(internalHost, 'internalHost');
  if (wanInterface) safeName(wanInterface, 'wanInterface');
  if (lanSubnet && !lanInterface) throw new Error('lanInterface is required with lanSubnet so hairpin NAT can be scoped to the intended LAN.');
  if (lanSubnet) parseCidr(lanSubnet, 'lanSubnet');
  if (lanInterface) safeName(lanInterface, 'lanInterface');
  const tag = safeComment(comment);
  const steps = [
    {
      resource: 'firewall_nat', action: 'add', fields: {
        chain: 'dstnat', action: 'dst-nat', protocol, 'dst-port': publicPort,
        'to-addresses': internalHost, 'to-ports': privatePort,
        ...(wanInterface ? { 'in-interface': wanInterface } : {}), comment: `${tag} port-forward:dstnat`,
      },
    },
    {
      resource: 'firewall_filter', action: 'add', fields: {
        chain: 'forward', action: 'accept', protocol, 'dst-address': internalHost, 'dst-port': privatePort,
        'connection-state': 'new', 'connection-nat-state': 'dstnat',
        ...(wanInterface ? { 'in-interface': wanInterface } : {}), comment: `${tag} port-forward:accept`,
      },
    },
  ];
  if (lanSubnet) {
    steps.push({
      resource: 'firewall_nat', action: 'add', fields: {
        chain: 'srcnat', action: 'masquerade', 'src-address': lanSubnet,
        'dst-address': internalHost, 'out-interface': lanInterface, comment: `${tag} port-forward:hairpin`,
      },
    });
  }
  return {
    steps,
    notes: [
      'Preview only: no router was contacted or changed.',
      'The forward-chain accept rule may interact with rule order and existing policies; review the full firewall before applying.',
      'This plan does not prove that the service is reachable from the Internet.',
      ...(lanSubnet ? [] : ['Hairpin NAT was not included because lanSubnet/lanInterface were not supplied.']),
    ],
  };
}

export function buildVlanSegmentPlan({ vlanId, name, subnet, gateway, bridge, taggedPorts = [], untaggedPorts = [], dhcp = false, dhcpRange, internet = false, wanInterface, comment }) {
  if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) throw new RangeError('vlanId must be an integer from 1 to 4094.');
  const vlanName = safeName(name, 'name');
  const bridgeName = safeName(bridge, 'bridge');
  const network = parseCidr(subnet, 'subnet');
  const gatewayNumber = ipv4Number(gateway, 'gateway');
  if (network.prefix > 30 || gatewayNumber <= network.network || gatewayNumber >= network.broadcast) throw new Error('gateway must be a usable IPv4 host address inside subnet; /31 and /32 segments are not supported.');
  if (!Array.isArray(taggedPorts) || !Array.isArray(untaggedPorts) || taggedPorts.length > 64 || untaggedPorts.length > 64) throw new TypeError('taggedPorts and untaggedPorts must be arrays of at most 64 interface names.');
  const tagged = [...new Set([bridgeName, ...taggedPorts.map((item) => safeName(item, 'tagged port'))])];
  const untagged = [...new Set(untaggedPorts.map((item) => safeName(item, 'untagged port')))];
  if (tagged.some((item) => untagged.includes(item))) throw new Error('An interface cannot be both tagged and untagged in this VLAN plan.');
  if (dhcp !== true && dhcp !== false) throw new TypeError('dhcp must be a boolean.');
  if (internet !== true && internet !== false) throw new TypeError('internet must be a boolean.');
  if (internet && !wanInterface) throw new Error('wanInterface is required when internet=true; egress is never inferred.');
  if (wanInterface) safeName(wanInterface, 'wanInterface');
  const tag = safeComment(comment);
  const steps = [
    { resource: 'vlans', action: 'add', fields: { name: vlanName, interface: bridgeName, 'vlan-id': String(vlanId), comment: `${tag} vlan:interface` } },
    { resource: 'bridge_vlans', action: 'add', fields: { bridge: bridgeName, 'vlan-ids': String(vlanId), tagged: tagged.join(','), untagged: untagged.join(','), comment: `${tag} vlan:membership` } },
    { resource: 'ip_addresses', action: 'add', fields: { address: `${gateway}/${network.prefix}`, interface: vlanName, comment: `${tag} vlan:gateway` } },
  ];
  if (dhcp) {
    if (typeof dhcpRange !== 'string') throw new Error('dhcpRange is required when dhcp=true; provide one start-end IPv4 range.');
    const range = dhcpRange.split('-');
    if (range.length !== 2) throw new TypeError('dhcpRange must be an IPv4 start-end pair.');
    const start = ipv4Number(range[0], 'dhcpRange start');
    const end = ipv4Number(range[1], 'dhcpRange end');
    if (start > end || start <= network.network || end >= network.broadcast || (gatewayNumber >= start && gatewayNumber <= end)) throw new Error('dhcpRange must be an increasing range inside subnet and must exclude network, broadcast and gateway addresses.');
    const poolName = `${vlanName}-pool`;
    const dhcpName = `${vlanName}-dhcp`;
    steps.push(
      { resource: 'ip_pools', action: 'add', fields: { name: poolName, ranges: `${range[0]}-${range[1]}`, comment: `${tag} vlan:pool` } },
      { resource: 'dhcp_networks', action: 'add', fields: { address: subnet, gateway, 'dns-server': gateway, comment: `${tag} vlan:dhcp-network` } },
      { resource: 'dhcp_servers', action: 'add', fields: { name: dhcpName, interface: vlanName, 'address-pool': poolName, 'lease-time': '1d', disabled: 'yes', comment: `${tag} vlan:dhcp-server-disabled-until-reviewed` } },
    );
  } else if (dhcpRange !== undefined) {
    throw new Error('dhcpRange was supplied while dhcp=false.');
  }
  if (internet) {
    steps.push({ resource: 'firewall_nat', action: 'add', fields: { chain: 'srcnat', action: 'masquerade', 'src-address': subnet, 'out-interface': wanInterface, comment: `${tag} vlan:egress` } });
  }
  return {
    steps,
    notes: [
      'Preview only: no router was contacted or changed.',
      'This is partial IPv4 scaffolding, not a complete isolated segment. Review bridge hardware capabilities, rule order and IPv6 separately.',
      'The DHCP server is staged disabled until an operator explicitly reviews and enables it.',
      ...(internet ? ['The new masquerade rule does not create an input/forward firewall allow policy.'] : []),
      'The plan does not add client-port PVID, frame admission, IPv6 policy, Wi-Fi/CAPsMAN or client verification.',
    ],
  };
}


function ipv4String(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join('.');
}

function validEndpoint(value) {
  if (typeof value !== 'string' || value.length > 253 || /[\s/:\\]/.test(value)) return false;
  if (net.isIP(value) === 4) return true;
  return value.split('.').every((label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

function validWireguardPublicKey(value) {
  if (typeof value !== 'string') return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === 32 && decoded.toString('base64') === value;
}

export function buildWireguardMeshPlan({ devices, addressPrefix, interfaceName = 'wg-mesh', topology = 'full-mesh', hub, persistentKeepalive = '25s', comment }) {
  if (!Array.isArray(devices) || devices.length < 2 || devices.length > 6) throw new RangeError('devices must contain 2 to 6 routers.');
  const ids = devices.map((item) => item.id);
  if (ids.some((id) => typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,48}$/.test(id)) || new Set(ids).size !== ids.length) throw new TypeError('Each configured router ID must be valid and unique.');
  if (!['full-mesh', 'hub-spoke'].includes(topology)) throw new TypeError('topology must be full-mesh or hub-spoke.');
  if (topology === 'hub-spoke' && !ids.includes(hub)) throw new Error('hub must name one of the selected devices for hub-spoke topology.');
  if (topology === 'full-mesh' && hub !== undefined) throw new Error('hub is only valid when topology=hub-spoke.');
  const wgInterface = safeName(interfaceName, 'interfaceName');
  const network = parseCidr(addressPrefix, 'addressPrefix');
  if (network.prefix < 8 || network.prefix > 29) throw new RangeError('addressPrefix must be between /8 and /29 to provide usable host addresses.');
  if (BigInt(devices.length) > network.broadcast - network.network - 1n) throw new Error('addressPrefix does not have enough usable host addresses for every router.');
  if (!/^(?:0s|[1-9]\d{0,3}[smh])$/.test(persistentKeepalive)) throw new TypeError('persistentKeepalive must be 0s or a bounded seconds/minutes/hours duration such as 25s.');
  const tag = safeComment(comment);
  const meshDevices = devices.map((item, index) => {
    if (!validWireguardPublicKey(item.publicKey)) throw new TypeError(`Device ${item.id} must have a valid 32-byte base64 WireGuard public key.`);
    if (!validEndpoint(item.endpointAddress)) throw new TypeError(`Device ${item.id} requires a public endpoint address or DNS hostname without a scheme or port.`);
    if (!Number.isInteger(item.endpointPort) || item.endpointPort < 1 || item.endpointPort > 65535) throw new RangeError(`Device ${item.id} endpointPort must be an integer from 1 to 65535.`);
    if (item.allowedLan !== undefined && item.allowedLan !== '') {
      const lan = parseCidr(item.allowedLan, `allowedLan for ${item.id}`);
      if (lan.network <= network.broadcast && network.network <= lan.broadcast) throw new Error(`allowedLan for ${item.id} overlaps the WireGuard addressPrefix.`);
    }
    return { ...item, meshIp: ipv4String(network.network + BigInt(index + 1)) };
  });
  const byId = new Map(meshDevices.map((item) => [item.id, item]));
  const steps = [];
  for (const local of meshDevices) {
    steps.push({ resource: 'ip_addresses', action: 'add', fields: {
      address: `${local.meshIp}/${network.prefix}`, interface: wgInterface,
      comment: `${tag} wireguard:mesh-address:${local.id}`,
    }, device: local.id });
    const peers = topology === 'full-mesh'
      ? meshDevices.filter((peer) => peer.id !== local.id)
      : local.id === hub ? meshDevices.filter((peer) => peer.id !== hub) : [byId.get(hub)];
    for (const peer of peers) {
      const allowedAddress = [`${peer.meshIp}/32`, ...(peer.allowedLan ? [peer.allowedLan] : [])].join(',');
      steps.push({ resource: 'wireguard_peers', action: 'add', fields: {
        interface: wgInterface, 'public-key': peer.publicKey, 'endpoint-address': peer.endpointAddress,
        'endpoint-port': String(peer.endpointPort), 'allowed-address': allowedAddress,
        'persistent-keepalive': persistentKeepalive,
        comment: `${tag} wireguard:peer:${peer.id}`,
      }, device: local.id });
    }
  }
  if (steps.length > 10) throw new Error(`This topology needs ${steps.length} operations, above the 10-step review limit; use a smaller mesh or stage it in separately reviewed phases.`);
  return {
    steps,
    assignments: meshDevices.map(({ id, meshIp }) => ({ device: id, interface: wgInterface, address: `${meshIp}/${network.prefix}` })),
    topology,
    notes: [
      'Preview only: it does not create WireGuard interfaces, generate keys, or change router state.',
      'Every selected router must already have the named WireGuard interface and a valid key pair; only public keys are used.',
      'The peer plan does not add explicit routes for allowed LANs or firewall rules for UDP endpoints; review those separately.',
      'Application is a sequential non-atomic transaction. A failure may leave addresses or peers on some routers.',
    ],
  };
}
