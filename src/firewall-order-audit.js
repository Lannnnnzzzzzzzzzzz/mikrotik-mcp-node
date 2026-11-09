import { isIP } from 'node:net';

const SECTION_KEYS = ['firewall_filter', 'ipv6_firewall_filter'];
const MAX_FINDINGS = 100;
const MAX_INDETERMINATE = 100;
const MAX_RECORDS = 5000;
const MAX_VALUE_LENGTH = 128;
const LIMITATION = 'This is a read-only snapshot analyzer, not a RouterOS packet-path simulation; verify policy and behavior independently. It never recommends changing live rules.';
const SAFE_MATCH_FIELDS = new Set([
  'protocol',
  'src-address',
  'dst-address',
  'src-port',
  'dst-port',
  'in-interface',
  'out-interface',
]);
const METADATA_FIELDS = new Set([
  '.id',
  'chain',
  'action',
  'disabled',
  'dynamic',
  'invalid',
  'comment',
  'bytes',
  'packets',
  'log',
  'log-prefix',
]);
const TERMINAL_ACTIONS = new Set(['accept', 'drop', 'reject']);
const KNOWN_ACTIONS = new Set([
  ...TERMINAL_ACTIONS,
  'jump',
  'return',
  'log',
  'passthrough',
  'fasttrack-connection',
  'tarpit',
  'add-src-to-address-list',
  'add-dst-to-address-list',
  'notrack',
]);

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

function boundedId(value) {
  return typeof value === 'string' && value.length <= MAX_VALUE_LENGTH ? value : undefined;
}

function parseIpv4Network(value) {
  if (typeof value !== 'string' || value.includes('!') || value.includes(',') || value.includes('-')) return null;
  const parts = value.split('/');
  if (parts.length > 2 || isIP(parts[0]) !== 4) return null;
  const prefix = parts.length === 1 ? 32 : Number(parts[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32 || !/^\d{1,2}$/.test(parts[1] ?? '32')) return null;
  const octets = parts[0].split('.').map(Number);
  let address = 0n;
  for (const octet of octets) address = (address << 8n) | BigInt(octet);
  const hostBits = BigInt(32 - prefix);
  const mask = prefix === 0 ? 0n : ((0xffffffffn << hostBits) & 0xffffffffn);
  return { network: address & mask, prefix };
}

function parseMatch(field, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_VALUE_LENGTH) {
    return { error: 'unsupported-match-value' };
  }
  if (field === 'src-address' || field === 'dst-address') {
    const network = parseIpv4Network(value);
    return network ? { value: network } : { error: 'unsupported-address-match' };
  }
  if (field === 'src-port' || field === 'dst-port') {
    if (!/^\d{1,5}$/.test(value)) return { error: 'unsupported-port-match' };
    const port = Number(value);
    return port <= 65535 ? { value: String(port) } : { error: 'unsupported-port-match' };
  }
  if (field === 'protocol') {
    if (!/^(?:[a-z][a-z0-9-]{0,31}|\d{1,3})$/i.test(value)) return { error: 'unsupported-protocol-match' };
    return { value: value.toLowerCase() };
  }
  // Interface names are compared only as exact literals; list expressions and negation are unsupported.
  if (value.includes('!') || value.includes(',') || value.includes('*') || /\s/.test(value)) {
    return { error: 'unsupported-interface-match' };
  }
  return { value };
}

function normalizeRule(row, index) {
  if (!isRecord(row)) return { index, chain: null, eligibility: 'indeterminate', reason: 'malformed-rule-record' };
  let keys;
  try {
    keys = Object.keys(row);
  } catch {
    return { index, chain: null, eligibility: 'indeterminate', reason: 'malformed-rule-record' };
  }
  const chainValue = safeRead(row, 'chain');
  const chain = typeof chainValue === 'string' && chainValue.length > 0 && chainValue.length <= MAX_VALUE_LENGTH
    ? chainValue
    : null;
  const actionValue = safeRead(row, 'action');
  const action = typeof actionValue === 'string' ? actionValue.trim().toLowerCase() : null;
  const disabled = booleanValue(safeRead(row, 'disabled'));
  const dynamic = booleanValue(safeRead(row, 'dynamic'));
  const invalid = booleanValue(safeRead(row, 'invalid'));
  const matches = {};
  let reason = null;

  if (!chain) reason = 'malformed-chain';
  else if (!action || !KNOWN_ACTIONS.has(action)) reason = 'unsupported-action';
  else if (disabled === undefined) reason = 'unknown-disabled-state';
  else if (dynamic !== undefined && dynamic !== false) reason = 'dynamic-rule';
  else if (invalid === true) reason = 'invalid-rule';
  else if (invalid === undefined && keys.includes('invalid')) reason = 'unknown-invalid-state';
  else if (action === 'jump' || action === 'return') reason = 'jump-or-return-semantics';
  else if (['fasttrack-connection', 'tarpit', 'add-src-to-address-list', 'add-dst-to-address-list', 'notrack'].includes(action)) {
    reason = 'unsupported-action-semantics';
  }

  for (const key of keys) {
    if (METADATA_FIELDS.has(key)) continue;
    if (!SAFE_MATCH_FIELDS.has(key)) {
      reason ??= key === 'src-address-list' || key === 'dst-address-list'
        || key === 'in-interface-list' || key === 'out-interface-list'
        || key === 'connection-state' || key === 'connection-nat-state'
        ? 'unsupported-list-or-state-match'
        : 'unknown-match-property';
      continue;
    }
    const raw = safeRead(row, key);
    if (raw === undefined || raw === null || raw === '') continue;
    const parsed = parseMatch(key, raw);
    if (parsed.error) reason ??= parsed.error;
    else matches[key] = parsed.value;
  }

  const id = boundedId(safeRead(row, '.id'));
  if (disabled === true) return { index, id, chain, action, disabled, eligibility: 'disabled' };
  if (reason) return { index, id, chain, action, disabled, matches, eligibility: 'indeterminate', reason };
  if (action === 'jump' || action === 'return') {
    return { index, id, chain, action, disabled, matches, eligibility: 'indeterminate', reason: 'jump-or-return-semantics' };
  }
  return { index, id, chain, action, disabled, matches, eligibility: 'comparable' };
}

function containsNetwork(earlier, later) {
  if (earlier.prefix > later.prefix) return false;
  const hostBits = BigInt(32 - earlier.prefix);
  const mask = earlier.prefix === 0 ? 0n : ((0xffffffffn << hostBits) & 0xffffffffn);
  return (later.network & mask) === earlier.network;
}

function compareCoverage(earlier, later) {
  if (earlier.eligibility !== 'comparable') return { result: 'indeterminate', reason: earlier.reason ?? 'unsupported-earlier-rule' };
  if (later.eligibility !== 'comparable') return { result: 'indeterminate', reason: later.reason ?? 'unsupported-later-rule' };
  if (!TERMINAL_ACTIONS.has(earlier.action)) return { result: 'not-terminal' };
  for (const [field, earlierValue] of Object.entries(earlier.matches)) {
    const laterValue = later.matches[field];
    if (laterValue === undefined) return { result: 'not-covered' };
    if (field === 'src-address' || field === 'dst-address') {
      if (!containsNetwork(earlierValue, laterValue)) return { result: 'not-covered' };
    } else if (earlierValue !== laterValue) return { result: 'not-covered' };
  }
  return { result: 'covered' };
}

function normalizeStatus(section) {
  const status = isRecord(section) ? safeRead(section, 'status') : undefined;
  return ['available', 'unavailable-or-not-permitted', 'error'].includes(status) ? status : 'error';
}

/** Analyze supplied RouterOS firewall-filter snapshots without making changes or simulating packets. */
export function buildFirewallOrderAudit(input = {}) {
  const sectionsInput = isRecord(input) ? safeRead(input, 'sections') : undefined;
  const sections = isRecord(sectionsInput) ? sectionsInput : {};
  const findings = [];
  const indeterminate = [];
  const sectionSummaries = {};
  let findingCount = 0;
  let indeterminateCount = 0;

  const addIndeterminate = (section, reason, earlierIndex = null, laterIndex = null) => {
    indeterminateCount += 1;
    if (indeterminate.length >= MAX_INDETERMINATE) return;
    indeterminate.push({
      section,
      ...(earlierIndex === null ? {} : { earlierIndex }),
      ...(laterIndex === null ? {} : { laterIndex }),
      reason,
      limitation: LIMITATION,
    });
  };

  for (const sectionKey of SECTION_KEYS) {
    const section = safeRead(sections, sectionKey);
    let status = normalizeStatus(section);
    const recordsValue = status === 'available' ? safeRead(section, 'records') : undefined;
    const records = Array.isArray(recordsValue) ? recordsValue : [];
    let completeOrder = false;
    if (status === 'available') {
      if (!Array.isArray(recordsValue)) status = 'error';
      else {
        const total = safeRead(section, 'total');
        const normalizedTotal = total === undefined ? records.length
          : (typeof total === 'number' ? total : (typeof total === 'string' && /^\d+$/.test(total) ? Number(total) : NaN));
        completeOrder = safeRead(section, 'truncated') !== true
          && Number.isSafeInteger(normalizedTotal)
          && normalizedTotal === records.length
          && records.length <= MAX_RECORDS;
        const ids = records.filter(isRecord).map((row) => safeRead(row, '.id')).filter((id) => typeof id === 'string');
        if (new Set(ids).size !== ids.length) completeOrder = false;
      }
    }
    sectionSummaries[sectionKey] = {
      status,
      recordCount: status === 'available' ? records.length : null,
      completeOrder: status === 'available' ? completeOrder : null,
    };
    if (status !== 'available') continue;
    if (!completeOrder) {
      addIndeterminate(sectionKey, records.length > MAX_RECORDS ? 'record-limit-exceeded' : 'incomplete-or-malformed-order');
      continue;
    }

    const rules = records.map((row, index) => normalizeRule(row, index));
    for (let laterIndex = 0; laterIndex < rules.length; laterIndex += 1) {
      const later = rules[laterIndex];
      for (let earlierIndex = 0; earlierIndex < laterIndex; earlierIndex += 1) {
        const earlier = rules[earlierIndex];
        if (!earlier.chain || !later.chain || earlier.chain !== later.chain) continue;
        if (earlier.eligibility === 'disabled' || later.eligibility === 'disabled') continue;
        // Nonterminal earlier actions cannot shadow a later rule; jumps/returns remain indeterminate.
        if (earlier.eligibility === 'comparable' && !TERMINAL_ACTIONS.has(earlier.action)) continue;
        const comparison = compareCoverage(earlier, later);
        if (comparison.result === 'covered') {
          findingCount += 1;
          if (findings.length < MAX_FINDINGS) {
            findings.push({
              type: 'possible-shadowing',
              section: sectionKey,
              chain: later.chain,
              earlierRule: { index: earlier.index, ...(earlier.id ? { id: earlier.id } : {}), action: earlier.action },
              laterRule: { index: later.index, ...(later.id ? { id: later.id } : {}), action: later.action },
              limitation: LIMITATION,
            });
          }
        } else if (comparison.result === 'indeterminate') {
          addIndeterminate(sectionKey, comparison.reason, earlierIndex, laterIndex);
        }
      }
    }
  }

  return {
    coverage: { sections: sectionSummaries },
    findings,
    findingsTruncated: findingCount > findings.length,
    indeterminate,
    indeterminateTruncated: indeterminateCount > indeterminate.length,
    notes: [
      'Only the supplied ordered record arrays are examined; order is not inferred from RouterOS .id values.',
      'Possible shadowing is reported only for explicitly enabled, valid terminal rules not flagged dynamic, with recognized, safely comparable match fields in the same chain.',
      'Address-list and interface-list matches, connection state, jumps/returns, unknown properties, IPv6 address expressions, and unsupported match syntax are indeterminate.',
      'Absence of a finding is not evidence that the firewall order is correct or safe.',
      LIMITATION,
    ],
  };
}
