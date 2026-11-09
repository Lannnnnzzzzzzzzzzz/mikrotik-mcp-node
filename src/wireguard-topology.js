const MAX_LINKS = 32;
const MAX_TEXT_LENGTH = 128;
const SEVERITY = { verified: 0, review: 1, unknown: 2 };
const AVAILABLE = 'available';

function safeText(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TEXT_LENGTH
    ? value
    : undefined;
}

function isDisabled(value) {
  return value === true || value === 1 || value === '1' || value === 'yes' || value === 'true';
}

function finding(code, status) {
  return { code, status };
}

function mergeStatus(current, next) {
  return SEVERITY[next] > SEVERITY[current] ? next : current;
}

function normalizeEndpoint(deviceId, interfaceName) {
  return {
    routerId: safeText(deviceId),
    interface: safeText(interfaceName),
    publicKey: null,
    status: 'unknown',
  };
}

function sectionAvailable(router, arrayField, statusField) {
  if (router[statusField] !== undefined) return router[statusField] === AVAILABLE && Array.isArray(router[arrayField]);
  return Array.isArray(router[arrayField]);
}

function endpointLookup(routerIndex, endpoint, findings) {
  const { routerId, interface: interfaceName } = endpoint;
  if (!routerId || !interfaceName) {
    findings.push(finding('malformed-endpoint', 'unknown'));
    return { status: 'unknown' };
  }

  const routerRows = routerIndex.get(routerId);
  if (!routerRows || routerRows.length === 0) {
    findings.push(finding('missing-router', 'unknown'));
    return { status: 'unknown' };
  }
  if (routerRows.length !== 1) {
    findings.push(finding('duplicate-router-id', 'unknown'));
    return { status: 'unknown' };
  }

  const router = routerRows[0];
  if (!sectionAvailable(router, 'interfaces', 'interfacesStatus')) {
    findings.push(finding('interface-data-unavailable', 'unknown'));
    return { status: 'unknown', router };
  }
  if (router.interfaces.some((row) => !row || typeof row !== 'object')) {
    findings.push(finding('incomplete-interface-data', 'unknown'));
    return { status: 'unknown', router };
  }

  const interfaces = router.interfaces.filter((row) => row.name === interfaceName);
  if (interfaces.length === 0) {
    findings.push(finding('missing-interface', 'unknown'));
    return { status: 'unknown', router };
  }
  if (interfaces.length > 1) {
    findings.push(finding('duplicate-interface', 'unknown'));
    return { status: 'unknown', router };
  }

  const iface = interfaces[0];
  const publicKey = safeText(iface['public-key']);
  endpoint.publicKey = publicKey ?? null;
  if (!publicKey) {
    findings.push(finding('missing-endpoint-public-key', 'unknown'));
    return { status: 'unknown', router, iface };
  }

  if (isDisabled(iface.disabled)) {
    findings.push(finding('disabled-endpoint', 'review'));
    endpoint.status = 'review';
  } else {
    endpoint.status = 'verified';
  }
  return { status: endpoint.status, router, iface };
}

function verifyDirection(local, remote) {
  if (!local.router || !local.iface || !remote.endpoint.publicKey) {
    return { status: 'unknown', peer: null };
  }
  if (!sectionAvailable(local.router, 'peers', 'peersStatus')) {
    return { status: 'unknown', peer: null, finding: 'peer-data-unavailable' };
  }
  if (local.router.peers.some((peer) => !peer || typeof peer !== 'object')) {
    return { status: 'unknown', peer: null, finding: 'incomplete-peer-data' };
  }

  const peers = local.router.peers.filter((peer) =>
    (peer.interface === local.iface.name || peer.interface === local.iface['.id'])
      && peer['public-key'] === remote.endpoint.publicKey);
  const enabled = peers.find((peer) => !isDisabled(peer.disabled));
  if (!enabled) {
    if (peers.length > 0) return { status: 'review', peer: peers[0], disabled: true };
    if (local.router.peersTruncated === true) {
      return { status: 'unknown', peer: null, finding: 'peer-list-truncated' };
    }
    return { status: 'review', peer: null };
  }
  return { status: 'verified', peer: enabled };
}

function verifyLink(link, index, routerIndex) {
  const findings = [];
  const a = normalizeEndpoint(link?.deviceA, link?.interfaceA);
  const b = normalizeEndpoint(link?.deviceB, link?.interfaceB);
  const record = { index, endpoints: { a, b }, status: 'unknown', findings };
  if (!link || typeof link !== 'object' || Array.isArray(link)) {
    findings.push(finding('malformed-link', 'unknown'));
    return record;
  }

  const checkedA = endpointLookup(routerIndex, a, findings);
  const checkedB = endpointLookup(routerIndex, b, findings);
  let status = mergeStatus(checkedA.status, checkedB.status);

  if (a.routerId && a.interface && a.routerId === b.routerId && a.interface === b.interface) {
    findings.push(finding('self-link', 'review'));
    status = mergeStatus(status, 'review');
  }

  const directionA = verifyDirection({ ...checkedA, endpoint: a }, { endpoint: b });
  const directionB = verifyDirection({ ...checkedB, endpoint: b }, { endpoint: a });
  for (const [direction, result] of [
    ['a-to-b', directionA],
    ['b-to-a', directionB],
  ]) {
    if (result.status === 'unknown') {
      if (result.finding) findings.push(finding(result.finding, 'unknown'));
      status = mergeStatus(status, 'unknown');
      continue;
    }
    if (!result.peer) {
      findings.push(finding(`missing-peer-${direction}`, 'review'));
      status = mergeStatus(status, 'review');
      continue;
    }
    if (result.disabled) {
      findings.push(finding(`disabled-peer-${direction}`, 'review'));
      status = mergeStatus(status, 'review');
    }
    if (!safeText(result.peer['allowed-address'])) {
      findings.push(finding(`missing-allowed-address-${direction}`, 'review'));
      status = mergeStatus(status, 'review');
    }
  }

  record.status = status;
  return record;
}

/**
 * Check caller-supplied WireGuard links against router/interface/public-key/peer configuration.
 * A verified result is configuration evidence only; this function does not infer forwarding,
 * firewall reachability, or operational health from handshakes or traffic counters.
 */
export function verifyWireGuardTopology({ routers, links } = {}) {
  const findings = [];
  const globalFindingCodes = new Set();
  const addGlobalFinding = (code) => {
    if (!globalFindingCodes.has(code)) {
      globalFindingCodes.add(code);
      findings.push(finding(code, 'unknown'));
    }
  };
  let status = 'verified';
  if (!Array.isArray(routers)) {
    addGlobalFinding('incomplete-routers-input');
    status = 'unknown';
  }
  if (!Array.isArray(links)) {
    addGlobalFinding('incomplete-links-input');
    status = 'unknown';
  }

  const routerIndex = new Map();
  if (Array.isArray(routers)) {
    for (const router of routers) {
      const id = safeText(router?.id);
      if (!id) {
        addGlobalFinding('malformed-router');
        status = 'unknown';
        continue;
      }
      const existing = routerIndex.get(id) ?? [];
      existing.push(router);
      routerIndex.set(id, existing);
      if (!Array.isArray(router.interfaces) || !Array.isArray(router.peers)
        || (router.interfacesStatus !== undefined && router.interfacesStatus !== AVAILABLE)
        || (router.peersStatus !== undefined && router.peersStatus !== AVAILABLE)
        || router.peersTruncated === true) {
        addGlobalFinding('incomplete-router-data');
        status = 'unknown';
      }
    }
  }
  for (const rows of routerIndex.values()) {
    if (rows.length > 1) {
      addGlobalFinding('duplicate-router-id');
      status = 'unknown';
    }
  }

  const linkRows = Array.isArray(links) ? links : [];
  const outputLinks = linkRows.slice(0, MAX_LINKS).map((link, index) => verifyLink(link, index, routerIndex));
  if (linkRows.length > MAX_LINKS) {
    addGlobalFinding('links-truncated-at-32');
    status = 'unknown';
  }

  const seen = new Set();
  for (const result of outputLinks) {
    const [a, b] = [result.endpoints.a, result.endpoints.b];
    if (!a.routerId || !a.interface || !b.routerId || !b.interface) continue;
    const left = `${a.routerId}\u0000${a.interface}`;
    const right = `${b.routerId}\u0000${b.interface}`;
    const key = left < right ? `${left}\u0001${right}` : `${right}\u0001${left}`;
    if (seen.has(key)) {
      result.findings.push(finding('duplicate-link', 'review'));
      result.status = mergeStatus(result.status, 'review');
    } else {
      seen.add(key);
    }
  }

  for (const result of outputLinks) status = mergeStatus(status, result.status);
  return { status, findings, links: outputLinks };
}
