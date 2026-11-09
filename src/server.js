import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { RouterOsApiClient, RouterOsApiError } from './routeros-api.js';
import { RESOURCE_CATALOG, RESOURCE_BY_KEY, RESOURCE_GROUPS, redactSensitiveRecords, sanitizeResourceProperties } from './catalog.js';
import { cancelPlan, redactFields, stagePlan, stageTransaction, takePlan, validateChangeInput } from './change-planner.js';
import { createSnapshot, deleteSnapshot, diffSnapshots, listSnapshots } from './snapshot-store.js';
import { assertExactConfirmation, assertWriteSafety } from './safety-gates.js';
import { createAlertRule, deleteAlertRule, listAlertHistory, listAlertRules, metricCatalog, recordAlertEvaluation } from './alert-store.js';
import { createAlertWorker } from './alert-worker.js';
import { isAlertWebhookEnabled, sendAlertWebhook } from './alert-webhook.js';
import { buildAaaOverview } from './aaa-overview.js';
import { buildRouterSupportSummary } from './support-summary.js';
import { createRouterSupportBundle } from './support-bundle.js';
import { backupFilePath, createPendingBackup, deleteLocalBackup, getBackupRecord, listBackupRecords, markBackupDownloaded } from './backup-store.js';
import { assertSftpConfiguration, downloadRouterBackup } from './ssh-sftp.js';
import { deleteEncryptedRouterBackupFromS3, deleteEncryptedRouterBackupVersionFromS3, getS3BackupConfiguration, getS3BackupTarget, listEncryptedRouterBackupVersionsInS3, listEncryptedRouterBackupsInS3, uploadEncryptedBackupToS3 } from './s3-backup.js';
import { buildPortForwardPlan, buildVlanSegmentPlan, buildWireguardMeshPlan } from './builders.js';
import { buildRoutingProtocolAudit } from './routing-audit.js';
import { buildWirelessInventory } from './wireless-inventory.js';
import { verifyWireGuardTopology } from './wireguard-topology.js';
import { createTzspCaptureManager } from './tzsp-capture.js';
import { runRouterSnifferCapture } from './sniffer-workflow.js';
import { buildFirewallOrderAudit } from './firewall-order-audit.js';
import { simulateIpv4RouteCandidates } from './route-simulation.js';
import { buildIpv6VlanSegmentPlan } from './ipv6-vlan-builder.js';
import { summarizeLocalCapture } from './capture-summary.js';
import { simulateIpv6RouteCandidates } from './ipv6-route-simulation.js';
import { buildDhcpIntegrityAudit } from './dhcp-integrity-audit.js';
import { buildDnsResolverAudit } from './dns-resolver-audit.js';
import { buildWirelessSecurityAudit } from './wireless-security-audit.js';
import { buildSchedulerSafetyAudit } from './scheduler-safety-audit.js';

const MAX_ROWS = 500;
let tzspCaptureManager;
const server = new McpServer({ name: 'mikrotik-mcp-js', version: '0.2.0' });

function readBoolean(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}
function parseBoolean(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return typeof value === 'boolean' ? value : ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}
function integer(value, name, fallback, max = 65535) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) throw new Error(`${name} must be an integer from 1 to ${max}.`);
  return parsed;
}
function tzspSourceAllowlist() {
  const value = process.env.MIKROTIK_TZSP_ALLOWED_SOURCES ?? '';
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}
function getTzspCaptureManager({ requireEnabled = false } = {}) {
  const enabled = readBoolean('MIKROTIK_TZSP_RECEIVER_ENABLED', false);
  if (requireEnabled && !enabled) throw new Error('The TZSP receiver is disabled. Set MIKROTIK_TZSP_RECEIVER_ENABLED=true only after reviewing the unencrypted capture risk.');
  const configuredBindAddress = process.env.MIKROTIK_TZSP_BIND_ADDRESS;
  const configuredSources = tzspSourceAllowlist();
  if (requireEnabled && (!configuredBindAddress || configuredSources.length === 0)) {
    throw new Error('TZSP capture requires MIKROTIK_TZSP_BIND_ADDRESS and an exact comma-separated MIKROTIK_TZSP_ALLOWED_SOURCES IP allowlist.');
  }
  const dataDir = process.env.MIKROTIK_DATA_DIR
    ? path.resolve(process.env.MIKROTIK_DATA_DIR)
    : path.resolve(process.cwd(), '.data');
  if (!tzspCaptureManager) {
    tzspCaptureManager = createTzspCaptureManager({
      dataDir,
      bindAddress: configuredBindAddress || '127.0.0.1',
      port: integer(process.env.MIKROTIK_TZSP_PORT, 'MIKROTIK_TZSP_PORT', 37008),
      allowedSources: configuredSources.length ? configuredSources : ['127.0.0.1'],
      maxDurationSeconds: integer(process.env.MIKROTIK_TZSP_MAX_DURATION_SECONDS, 'MIKROTIK_TZSP_MAX_DURATION_SECONDS', 60, 600),
      maxCaptureBytes: 64 * 1024 * 1024,
      maxPackets: 100000,
      maxPendingBytes: 1024 * 1024,
    });
  }
  return tzspCaptureManager;
}
function loadCa(value) {
  if (!value) return undefined;
  try { return fs.readFileSync(value, 'utf8'); } catch { throw new Error('Unable to read the configured RouterOS TLS CA file.'); }
}
function normalizeRouter(entry, index) {
  const id = String(entry.id ?? (index === 0 ? 'default' : `router-${index + 1}`));
  if (!/^[a-zA-Z0-9_-]{1,48}$/.test(id)) throw new Error(`Invalid router ID "${id}"; use letters, numbers, _ or - only.`);
  const candidates = [...(Array.isArray(entry.hosts) ? entry.hosts : []), entry.host].filter(Boolean);
  if (candidates.length === 0 || candidates.length > 8 || candidates.some((host) => typeof host !== 'string') || !entry.username || typeof entry.password !== 'string') throw new Error(`Router "${id}" must define host (or up to 8 hosts), username and password.`);
  const hosts = [...new Set(candidates)];
  const tls = parseBoolean(entry.tls, true);
  return {
    id, host: hosts[0], hosts, username: entry.username, password: entry.password,
    port: integer(entry.port, `Router "${id}" port`, tls ? 8729 : 8728),
    tls,
    tlsCa: entry.tlsCa ? loadCa(entry.tlsCa) : loadCa(process.env.MIKROTIK_TLS_CA),
    tlsRejectUnauthorized: parseBoolean(entry.tlsRejectUnauthorized, readBoolean('MIKROTIK_TLS_REJECT_UNAUTHORIZED', true)),
    timeoutMs: integer(entry.timeoutMs ?? process.env.MIKROTIK_TIMEOUT_MS, `Router "${id}" timeout`, 8000, 120000),
    sshPort: integer(entry.sshPort ?? process.env.MIKROTIK_SSH_PORT, `Router "${id}" SSH port`, 22),
    sshUsername: entry.sshUsername ?? process.env.MIKROTIK_SSH_USERNAME,
    sshPassword: entry.sshPassword ?? process.env.MIKROTIK_SSH_PASSWORD,
    sshHostKeyFingerprint: entry.sshHostKeyFingerprint ?? process.env.MIKROTIK_SSH_HOST_KEY_SHA256,
  };
}
function getRouterSet() {
  if (process.env.MIKROTIK_ROUTERS_JSON) {
    let document;
    try { document = JSON.parse(process.env.MIKROTIK_ROUTERS_JSON); } catch { throw new Error('MIKROTIK_ROUTERS_JSON must contain valid JSON.'); }
    const entries = Array.isArray(document) ? document : document.routers;
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > 64) throw new Error('MIKROTIK_ROUTERS_JSON must contain a routers array with 1–64 entries.');
    const routers = entries.map(normalizeRouter);
    if (new Set(routers.map((r) => r.id)).size !== routers.length) throw new Error('Router IDs in MIKROTIK_ROUTERS_JSON must be unique.');
    const defaultId = process.env.MIKROTIK_DEFAULT_DEVICE ?? (Array.isArray(document) ? undefined : document.defaultDevice) ?? routers[0].id;
    if (!routers.some((r) => r.id === defaultId)) throw new Error('The configured default router ID does not exist.');
    return { routers, defaultId };
  }
  const router = normalizeRouter({
    id: process.env.MIKROTIK_DEVICE_ID ?? 'default', host: process.env.MIKROTIK_HOST,
    port: process.env.MIKROTIK_PORT, username: process.env.MIKROTIK_USERNAME,
    password: process.env.MIKROTIK_PASSWORD, tls: process.env.MIKROTIK_TLS,
    tlsCa: process.env.MIKROTIK_TLS_CA, tlsRejectUnauthorized: process.env.MIKROTIK_TLS_REJECT_UNAUTHORIZED,
    timeoutMs: process.env.MIKROTIK_TIMEOUT_MS, sshPort: process.env.MIKROTIK_SSH_PORT,
    sshUsername: process.env.MIKROTIK_SSH_USERNAME, sshPassword: process.env.MIKROTIK_SSH_PASSWORD,
    sshHostKeyFingerprint: process.env.MIKROTIK_SSH_HOST_KEY_SHA256,
  }, 0);
  return { routers: [router], defaultId: router.id };
}
function resolveRouter(deviceId) {
  const set = getRouterSet();
  const id = deviceId ?? set.defaultId;
  const router = set.routers.find((item) => item.id === id);
  if (!router) throw new Error(`Unknown router device "${id}". Use router_devices to list configured devices.`);
  return router;
}
function publicRouter(router, defaultId) {
  return { id: router.id, host: router.host, endpointCount: router.hosts.length, port: router.port, tls: router.tls, sshSftpConfigured: Boolean(router.sshUsername && router.sshPassword && router.sshHostKeyFingerprint), default: router.id === defaultId };
}
async function withRouter(device, operation, { onlyHost } = {}) {
  const config = resolveRouter(device);
  if (onlyHost !== undefined && !config.hosts.includes(onlyHost)) throw new Error(`Requested router endpoint is not configured for device ${config.id}.`);
  let lastError;
  for (const host of onlyHost === undefined ? config.hosts : [onlyHost]) {
    const client = new RouterOsApiClient({ ...config, host });
    try {
      await client.connect();
    } catch (error) {
      lastError = error;
      await client.close().catch(() => {});
      continue;
    }
    if (host !== config.host) console.error(JSON.stringify({ event: 'router_endpoint_failover', device: config.id, connectedHost: host }));
    try { return await operation(client, { ...config, host, connectedHost: host }); }
    finally { await client.close(); }
  }
  throw lastError ?? new Error(`Unable to connect to router "${config.id}".`);
}
async function collectAlertValues(deviceId, rules) {
  const required = new Set(rules.map((rule) => rule.metric));
  return withRouter(deviceId, async (client) => {
    const result = {};
    if (required.has('cpuUsedPercent') || required.has('memoryUsedPercent')) {
      const resources = (await client.print('/system/resource', ['cpu', 'free-memory', 'total-memory']))[0] ?? {};
      const cpu = Number.parseFloat(String(resources.cpu ?? '').replace('%', ''));
      if (required.has('cpuUsedPercent')) result.cpuUsedPercent = Number.isFinite(cpu) ? cpu : null;
      if (required.has('memoryUsedPercent')) {
        const free = Number(resources['free-memory']);
        const total = Number(resources['total-memory']);
        result.memoryUsedPercent = Number.isFinite(free) && Number.isFinite(total) && total > 0 ? Math.round((total - free) / total * 1000) / 10 : null;
      }
    }
    if (required.has('activeDefaultRouteCount')) {
      const routes = await client.print('/ip/route', ['dst-address', 'active', 'disabled']);
      result.activeDefaultRouteCount = routes.filter((row) => row['dst-address'] === '0.0.0.0/0' && ['true', 'yes'].includes(row.active) && !['true', 'yes'].includes(row.disabled)).length;
    }
    return result;
  });
}
async function recordAlertAndNotify(device, values) {
  const result = await recordAlertEvaluation(device.id, values);
  if (result.events.length && isAlertWebhookEnabled()) {
    result.notification = await sendAlertWebhook(result.events);
  }
  return result;
}
const alertWorker = createAlertWorker({
  listDevices: async () => getRouterSet().routers.map((router) => ({ id: router.id })),
  listRules: (device) => listAlertRules(device.id),
  collect: (device, rules) => collectAlertValues(device.id, rules),
  record: recordAlertAndNotify,
});
let alertAutostartError = null;
function jsonResult(value) { return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] }; }
async function printSafeResource(client, resource, queryWords) {
  const properties = sanitizeResourceProperties(resource);
  const rows = await client.print(resource.path, properties, queryWords);
  return redactSensitiveRecords(rows);
}
async function optionalResourceSection(client, resourceKey) {
  const resource = RESOURCE_BY_KEY.get(resourceKey);
  if (!resource) throw new Error(`Missing fixed resource ${resourceKey}.`);
  try {
    return { status: 'available', records: await printSafeResource(client, resource) };
  } catch (error) {
    if (error instanceof RouterOsApiError && error.message.startsWith('RouterOS rejected the command:')) {
      return { status: 'unavailable-or-not-permitted' };
    }
    throw error;
  }
}
function boundedAuditSection(section, maxRows) {
  if (section?.status !== 'available' || !Array.isArray(section.records)) return section;
  const total = section.records.length;
  return { status: 'available', records: section.records.slice(0, maxRows), total, truncated: total > maxRows };
}
async function readFixedAuditSection(client, apiPath, properties, maxRows = 5000) {
  try {
    const rows = await client.print(apiPath, properties);
    if (!Array.isArray(rows)) return { status: 'error' };
    return { status: 'available', records: rows.slice(0, maxRows), total: rows.length, truncated: rows.length > maxRows };
  } catch (error) {
    if (error instanceof RouterOsApiError && error.message.startsWith('RouterOS rejected the command:')) {
      return { status: 'unavailable-or-not-permitted' };
    }
    return { status: 'error' };
  }
}
async function readDnsSettingsAuditSection(client) {
  const resource = RESOURCE_BY_KEY.get('ip_dns_settings');
  const extended = await readFixedAuditSection(client, resource.path, [...resource.properties, 'use-doh-server']);
  if (extended.status !== 'unavailable-or-not-permitted') return extended;
  return readFixedAuditSection(client, resource.path, resource.properties);
}
async function readWirelessSecurityAuditSection(client, apiPath, properties, secretProperties) {
  const extended = await readFixedAuditSection(client, apiPath, properties);
  if (extended.status !== 'unavailable-or-not-permitted') return extended;
  return readFixedAuditSection(client, apiPath, properties.filter((property) => !secretProperties.includes(property)));
}
function errorWithoutSecrets(error, secrets = []) {
  let message = error instanceof Error ? error.message : 'Unknown remote operation error';
  for (const secret of secrets) if (typeof secret === 'string' && secret.length > 0) message = message.split(secret).join('[redacted]');
  return new Error(message);
}
function errorResult(error) {
  const message = error instanceof RouterOsApiError || error instanceof Error ? error.message : 'Unknown RouterOS operation error';
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}
async function safely(operation) {
  try { return jsonResult(await operation()); } catch (error) { return errorResult(error); }
}
const deviceArg = () => z.string().min(1).max(48).optional().describe('Configured router ID; defaults to the configured default router.');
const stringMapSchema = z.record(z.string().min(1).max(64), z.string().max(1024));

function validateFilter(resource, filters) {
  if (!filters) return [];
  const allowed = new Set(resource.properties);
  const entries = Object.entries(filters);
  if (entries.length > 12) throw new Error('At most 12 filters may be supplied.');
  return entries.map(([key, value]) => {
    if (!allowed.has(key)) throw new Error(`Filter "${key}" is not available for ${resource.key}.`);
    if (typeof value !== 'string' || value.length > 256 || /[\u0000\r\n]/.test(value)) throw new Error(`Filter value for "${key}" is invalid.`);
    return `?=${key}=${value}`;
  });
}
function registerResourceList(resource, toolName) {
  server.registerTool(toolName, {
    title: resource.title,
    description: `Read ${resource.title.toLowerCase()} from fixed RouterOS API path ${resource.path}. This tool never changes router configuration. Sensitive fields are omitted and explicit sensitive-property requests are rejected. Results are capped at ${MAX_ROWS} records.`,
    inputSchema: {
      device: deviceArg(),
      limit: z.number().int().min(1).max(MAX_ROWS).optional().describe(`Maximum records to return (1–${MAX_ROWS}; default 100).`),
      properties: z.array(z.string().min(1).max(64)).max(25).optional().describe('Optional subset of supported fields.'),
      filters: z.record(z.string().min(1).max(64), z.string().max(256)).optional().describe('Exact-match filters; only fields in this resource are accepted.'),
    },
  }, async ({ device, limit = 100, properties, filters }) => safely(async () => {
    const selected = sanitizeResourceProperties(resource, properties);
    const queryWords = validateFilter(resource, filters);
    const rawRows = await withRouter(device, (client) => client.print(resource.path, selected, queryWords));
    const allRows = redactSensitiveRecords(rawRows);
    const records = allRows.slice(0, limit);
    return { device: resolveRouter(device).id, resource: resource.key, path: resource.path, records, returned: records.length, total: allRows.length, truncated: allRows.length > records.length };
  }));
}
const listAliases = { ip_addresses: 'list_ip_addresses', routes: 'list_routes', dhcp_leases: 'list_dhcp_leases', firewall_filter: 'list_firewall_filter_rules' };
const listToolNames = new Set();
for (const resource of RESOURCE_CATALOG) {
  const name = listAliases[resource.key] ?? `list_${resource.key}`;
  if (listToolNames.has(name)) continue;
  listToolNames.add(name);
  registerResourceList(resource, name);
}

server.registerTool('router_devices', {
  title: 'Configured routers',
  description: 'List configured routers without exposing usernames, passwords, or private keys.',
  inputSchema: {},
}, async () => safely(async () => {
  const set = getRouterSet();
  return { defaultDevice: set.defaultId, devices: set.routers.map((r) => publicRouter(r, set.defaultId)) };
}));

server.registerTool('router_feature_catalog', {
  title: 'Router feature catalog',
  description: 'Describe the feature groups, generated read tools, fixed RouterOS paths and guarded change support exposed by this server.',
  inputSchema: {},
}, async () => safely(async () => ({
  implementation: 'Original JavaScript MCP server using the RouterOS native API',
  resourceCount: RESOURCE_CATALOG.length,
  uniqueApiPathCount: new Set(RESOURCE_CATALOG.map((item) => item.path)).size,
  writableResourceCount: RESOURCE_CATALOG.filter((item) => item.writeFields.length > 0).length,
  readOnlyResourceCount: RESOURCE_CATALOG.filter((item) => item.writeFields.length === 0).length,
  groups: RESOURCE_GROUPS.map((group) => ({
    name: group,
    resources: RESOURCE_CATALOG.filter((item) => item.group === group).map((item) => ({
      key: item.key, title: item.title, path: item.path,
      readTool: listAliases[item.key] ?? `list_${item.key}`,
      writable: item.writeFields.length > 0, risk: item.risk, writableFields: item.writeFields,
    })),
  })),
  generatedReadTools: listToolNames.size,
  purposeBuiltTools: ['probe_router_capabilities', 'router_health_report', 'router_support_summary', 'create_router_support_bundle', 'audit_router_security_posture', 'list_connected_devices', 'audit_multiwan_paths', 'audit_routing_protocol_health', 'simulate_ipv4_route_candidates', 'simulate_ipv6_route_candidates', 'audit_dhcp_integrity', 'audit_dns_resolver', 'audit_firewall_rule_order', 'audit_wireless_clients', 'audit_wireless_security_profiles', 'wireless_client_inventory', 'audit_vlan_consistency', 'audit_wireguard_peers', 'verify_wireguard_topology', 'audit_scheduler_safety', 'router_aaa_overview', 'create_encrypted_router_backup', 'download_encrypted_router_backup', 'upload_encrypted_router_backup_to_s3', 'list_encrypted_router_backups_in_s3', 'list_encrypted_router_backup_versions_in_s3', 'delete_encrypted_router_backup_from_s3', 'delete_encrypted_router_backup_version_from_s3', 'list_local_encrypted_backups', 'delete_local_encrypted_backup', 'preview_port_forward', 'preview_vlan_segment', 'preview_ipv6_vlan_segment', 'preview_wireguard_mesh', 'router_alert_metric_catalog', 'create_router_alert_rule', 'list_router_alert_rules', 'delete_router_alert_rule', 'evaluate_router_alert_rules', 'list_router_alert_history', 'start_router_alert_service', 'stop_router_alert_service', 'router_alert_service_status', 'run_bandwidth_test', 'run_speed_test', 'run_ip_scan', 'run_flood_ping', 'wake_on_lan', 'make_dhcp_lease_static', 'operate_dhcp_client', 'flush_dns_cache', 'start_tzsp_capture_receiver', 'capture_router_sniffer', 'tzsp_capture_status', 'stop_tzsp_capture_receiver', 'list_tzsp_captures', 'summarize_tzsp_capture', 'delete_tzsp_capture'],
  changeTools: ['plan_router_change', 'apply_router_change_plan', 'cancel_router_change_plan', 'plan_router_transaction', 'apply_router_transaction'],
  knownGaps: ['interactive Safe Mode and automatic rollback', 'interactive binary backup restore (RouterOS requires a terminal confirmation before reboot), User Manager database export, and S3 lifecycle/retention management', 'external scheduling while the MCP process is unavailable', 'automated bounded sniffer capture is opt-in and best-effort; per-flow mirror lifecycle, live packet decoding/dashboard remain unavailable', 'full RouterOS configuration export/CLI export and supout retrieval; the private support bundle is limited to the allowlisted resource catalog', 'safe wireless RF surveys and client lifecycle workflows', 'reference application views/access/memory/traces'],
  note: 'Broad original JavaScript implementation, not a one-for-one recreation of the reference documentation’s 983 tools across 155 modules.',
})));

server.registerTool('probe_router_capabilities', {
  title: 'Probe RouterOS menu capabilities',
  description: 'Read a bounded page of fixed catalog paths on a router to distinguish available menus from menus that are unavailable or not permitted to this account. A failed probe is not proof that a RouterOS package is absent.',
  inputSchema: { device: deviceArg(), groups: z.array(z.enum(RESOURCE_GROUPS)).max(RESOURCE_GROUPS.length).optional(), cursor: z.number().int().min(0).max(1000).optional(), limit: z.number().int().min(1).max(40).optional() },
}, async ({ device, groups, cursor = 0, limit = 20 }) => safely(async () => {
  const selectedGroups = groups ? new Set(groups) : null;
  const menus = [...new Map(RESOURCE_CATALOG.filter((item) => !selectedGroups || selectedGroups.has(item.group)).map((item) => [item.path, item])).values()];
  const page = menus.slice(cursor, cursor + limit);
  const checked = await withRouter(device, async (client, router) => {
    const results = [];
    for (const resource of page) {
      try {
        const records = await client.print(resource.path, ['.id']);
        results.push({ key: resource.key, group: resource.group, path: resource.path, status: 'available', recordsObserved: records.length });
      } catch (error) {
        if (!(error instanceof RouterOsApiError) || !error.message.startsWith('RouterOS rejected the command:')) throw error;
        results.push({ key: resource.key, group: resource.group, path: resource.path, status: 'unavailable-or-not-permitted' });
      }
    }
    return { device: router.id, results };
  });
  const nextCursor = cursor + page.length < menus.length ? cursor + page.length : null;
  return { ...checked, totalMenus: menus.length, cursor, nextCursor, note: 'Results are a best-effort probe using the configured account; permission denial and RouterOS version/package absence may look the same.' };
}));

server.registerTool('router_identity', {
  title: 'Router identity', description: 'Read the identity of one configured MikroTik router.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(() => withRouter(device, async (client, config) => ({ device: config.id, records: await client.print('/system/identity', ['name']) }))));

server.registerTool('router_system_resources', {
  title: 'System resources', description: 'Read RouterOS version, uptime, CPU, memory, storage, board and architecture details.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(() => withRouter(device, async (client, config) => ({
  device: config.id,
  records: await client.print('/system/resource', ['version', 'uptime', 'cpu', 'cpu-count', 'cpu-frequency', 'free-memory', 'total-memory', 'free-hdd-space', 'total-hdd-space', 'board-name', 'architecture-name', 'platform']),
}))));

export async function readRouterSummary(device) {
  return withRouter(device, async (client, config) => {
    const identity = await client.print('/system/identity', ['name']);
    const resources = await client.print('/system/resource', ['version', 'uptime', 'cpu', 'cpu-count', 'free-memory', 'total-memory', 'board-name', 'architecture-name']);
    return { device: config.id, identity: identity[0] ?? null, resources: resources[0] ?? null };
  });
}
server.registerTool('router_summary', {
  title: 'Router status summary', description: 'Read a compact identity, version, uptime and resource summary for one configured router.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(() => readRouterSummary(device)));

server.registerTool('router_support_summary', {
  title: 'Privacy-minimized router support summary',
  description: 'Build a current count-only support summary from fixed, safe RouterOS reads. Returns identity and selected system fields plus counts/coverage; omits addresses, MACs, client names, comments, keys, gateways and raw records. This is not a full config export, support bundle or historical report.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(() => withRouter(device, async (client, config) => {
  const identity = await client.print('/system/identity', ['name']);
  const resources = await client.print('/system/resource', ['version', 'uptime', 'cpu', 'cpu-count', 'board-name', 'architecture-name', 'free-memory', 'total-memory']);
  const sections = {};
  for (const key of ['interfaces', 'ip_addresses', 'routes', 'firewall_filter', 'firewall_nat', 'dhcp_leases', 'wireguard_peers', 'wireless_registrations', 'legacy_capsman_registrations', 'wifi_registrations']) {
    const section = await optionalResourceSection(client, key);
    if (section.status === 'available') {
      const total = section.records.length;
      sections[key] = { ...section, records: section.records.slice(0, MAX_ROWS), total, truncated: total > MAX_ROWS };
    } else {
      sections[key] = section;
    }
  }
  return buildRouterSupportSummary({ device: config.id, identity: identity[0] ?? null, resources: resources[0] ?? null, sections });
})));

server.registerTool('create_router_support_bundle', {
  title: 'Create a private allowlisted router support bundle',
  description: 'Read the fixed RouterOS resource catalog, redact sensitive fields, and save a bounded gzip JSON artifact in private local storage. This is not a full CLI export or restorable backup. Requires MIKROTIK_SUPPORT_BUNDLE_ENABLED=true and exact confirmation CREATE SUPPORT BUNDLE <device> because the file can contain private addresses and configuration details.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(100) },
}, async ({ device, confirmation }) => safely(async () => {
  if (!readBoolean('MIKROTIK_SUPPORT_BUNDLE_ENABLED', false)) throw new Error('Support bundle creation is disabled. Set MIKROTIK_SUPPORT_BUNDLE_ENABLED=true only after reviewing the local-data risk.');
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `CREATE SUPPORT BUNDLE ${router.id}`);
  return withRouter(router.id, async (client, connection) => {
    const identity = await client.print('/system/identity', ['name']);
    const systemRows = await client.print('/system/resource', ['version', 'uptime', 'cpu', 'cpu-count', 'board-name', 'architecture-name', 'free-memory', 'total-memory']);
    const resources = [];
    for (const resource of RESOURCE_CATALOG) {
      try {
        const rawRows = await client.print(resource.path, sanitizeResourceProperties(resource));
        const redacted = redactSensitiveRecords(rawRows);
        resources.push({
          key: resource.key,
          title: resource.title,
          group: resource.group,
          path: resource.path,
          status: 'available',
          records: redacted.slice(0, MAX_ROWS),
          total: redacted.length,
          truncated: redacted.length > MAX_ROWS,
        });
      } catch (error) {
        const rejected = error instanceof RouterOsApiError && error.message.startsWith('RouterOS rejected the command:');
        resources.push({
          key: resource.key,
          title: resource.title,
          group: resource.group,
          path: resource.path,
          status: rejected ? 'unavailable-or-not-permitted' : 'error',
          records: [],
          total: null,
          truncated: null,
        });
      }
    }
    const summaryKeys = ['interfaces', 'ip_addresses', 'routes', 'firewall_filter', 'firewall_nat', 'dhcp_leases', 'wireguard_peers', 'wireless_registrations', 'legacy_capsman_registrations', 'wifi_registrations'];
    const summarySections = Object.fromEntries(resources.filter((item) => summaryKeys.includes(item.key)).map((item) => [item.key, item]));
    const summary = buildRouterSupportSummary({ device: router.id, identity: identity[0] ?? null, resources: systemRows[0] ?? null, sections: summarySections });
    const bundle = await createRouterSupportBundle({
      device: router.id,
      router: { endpoint: connection.connectedHost ?? connection.host, identity: identity[0] ?? null, resources: systemRows[0] ?? null },
      resources,
      dataDir: process.env.MIKROTIK_DATA_DIR ? path.resolve(process.env.MIKROTIK_DATA_DIR) : path.resolve(process.cwd(), '.data'),
    });
    return { ...bundle, supportSummary: summary, note: 'The file contains allowlisted and redacted resource records, which can still include private IPs, account names, topology, and other configuration details. It is stored locally with mode 0600 and is neither a complete RouterOS export nor a restorable backup.' };
  });
}));

server.registerTool('router_safety_capabilities', {
  title: 'Router change-safety capabilities',
  description: 'Explain which change-safety mechanisms this native-API implementation actually provides and which are not available through its transport.',
  inputSchema: {},
}, async () => jsonResult({
  writeDisabledByDefault: !readBoolean('MIKROTIK_ALLOW_WRITES', false),
  highRiskWritesDisabledByDefault: !readBoolean('MIKROTIK_ALLOW_HIGH_RISK_WRITES', false),
  previewPlans: true,
  configurationInventorySnapshots: true,
  sequentialMultiStepPlans: true,
  automaticRollback: false,
  nativeApiSafeMode: false,
  nativeApiSafeModeNote: 'RouterOS Safe Mode is a session-based console feature. This project uses the native RouterOS API and does not claim Safe Mode protection or ACID transactions.',
  routerEndpointFailover: 'Connect-time only; no command is replayed after a session is established.',
}));

server.registerTool('start_tzsp_capture_receiver', {
  title: 'Start a bounded local TZSP receiver',
  description: 'Start a host-only UDP receiver that accepts TZSP v1 Ethernet frames from the exact configured source-IP allowlist and writes a private classic PCAP. It never starts or changes RouterOS sniffer/mangle rules. TZSP is unencrypted; requires explicit receiver opt-in, both write gates, active-diagnostics gate, and exact confirmation: START TZSP CAPTURE <device> <name> <seconds>s <bind-address> UDP <port>.',
  inputSchema: {
    device: deviceArg(),
    name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/),
    durationSeconds: z.number().int().min(1).max(600).optional(),
    confirmation: z.string().min(1).max(200),
  },
}, async ({ device, name, durationSeconds: requestedDuration, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  const enabled = readBoolean('MIKROTIK_TZSP_RECEIVER_ENABLED', false);
  if (!enabled) throw new Error('The TZSP receiver is disabled. Set MIKROTIK_TZSP_RECEIVER_ENABLED=true only after reviewing the unencrypted capture risk.');
  const bindAddress = process.env.MIKROTIK_TZSP_BIND_ADDRESS;
  const sourceIps = tzspSourceAllowlist();
  if (!bindAddress || net.isIP(bindAddress) === 0 || bindAddress === '0.0.0.0' || bindAddress === '::') {
    throw new Error('MIKROTIK_TZSP_BIND_ADDRESS must be an explicit, non-wildcard local IP reachable from the router.');
  }
  if (sourceIps.length === 0) throw new Error('MIKROTIK_TZSP_ALLOWED_SOURCES must list exact sender IP addresses separated by commas.');
  const port = integer(process.env.MIKROTIK_TZSP_PORT, 'MIKROTIK_TZSP_PORT', 37008);
  const maxDurationSeconds = integer(process.env.MIKROTIK_TZSP_MAX_DURATION_SECONDS, 'MIKROTIK_TZSP_MAX_DURATION_SECONDS', 60, 600);
  const durationSeconds = integer(requestedDuration, 'durationSeconds', maxDurationSeconds, maxDurationSeconds);
  const expected = `START TZSP CAPTURE ${router.id} ${name} ${durationSeconds}s ${bindAddress} UDP ${port}`;
  assertExactConfirmation(confirmation, expected);
  const capture = await getTzspCaptureManager({ requireEnabled: true }).start({ device: router.id, name, durationSeconds });
  return {
    ...capture,
    routerConfigurationNotChanged: true,
    suggestedRouterCommands: [
      `/tool/sniffer/set streaming-enabled=yes streaming-server=${bindAddress} streaming-port=${port} filter-stream=yes`,
      '/tool/sniffer/start',
    ],
    stopRouterStreamingManuallyWith: ['/tool/sniffer/stop', '/tool/sniffer/set streaming-enabled=no'],
    note: 'These are suggestions only and were not sent to RouterOS. Stop RouterOS streaming manually before stopping this host receiver. Captures can contain private traffic and remain in the local private data directory until explicitly deleted.',
  };
}));

server.registerTool('capture_router_sniffer', {
  title: 'Run a bounded RouterOS TZSP sniffer capture',
  description: 'Open the allowlisted local receiver, check RouterOS sniffer is idle, enable TZSP streaming, capture for at most 60 seconds, then stop the sniffer and restore its prior streaming settings. Requires MIKROTIK_TZSP_AUTOMATION_ENABLED=true, receiver opt-in, both write gates, active-diagnostics gate, exact source-IP allowlisting, and confirmation CAPTURE ROUTER SNIFFER <device> <name> <seconds>s TO <bind-address>:<port>. A process/network/router failure can prevent cleanup; verify /tool/sniffer after any interruption. TZSP is unencrypted and captures may contain private traffic.',
  inputSchema: {
    device: deviceArg(),
    name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/),
    durationSeconds: z.number().int().min(1).max(60),
    confirmation: z.string().min(1).max(200),
  },
}, async ({ device, name, durationSeconds, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { activeDiagnostics: true });
  if (!readBoolean('MIKROTIK_TZSP_AUTOMATION_ENABLED', false)) throw new Error('RouterOS sniffer automation is disabled. Set MIKROTIK_TZSP_AUTOMATION_ENABLED=true only after reviewing the remote capture and cleanup risks.');
  const router = resolveRouter(device);
  if (!readBoolean('MIKROTIK_TZSP_RECEIVER_ENABLED', false)) throw new Error('The local TZSP receiver is disabled.');
  const bindAddress = process.env.MIKROTIK_TZSP_BIND_ADDRESS;
  const sourceIps = tzspSourceAllowlist();
  if (!bindAddress || net.isIP(bindAddress) === 0 || bindAddress === '0.0.0.0' || bindAddress === '::') throw new Error('An explicit non-wildcard MIKROTIK_TZSP_BIND_ADDRESS is required.');
  if (!sourceIps.length) throw new Error('MIKROTIK_TZSP_ALLOWED_SOURCES must list exact source IP addresses.');
  if (!router.hosts.some((host) => net.isIP(host) !== 0 && sourceIps.includes(host))) throw new Error('The exact router management IP must appear in MIKROTIK_TZSP_ALLOWED_SOURCES; hostnames cannot be matched safely.');
  const port = integer(process.env.MIKROTIK_TZSP_PORT, 'MIKROTIK_TZSP_PORT', 37008);
  const configuredMax = integer(process.env.MIKROTIK_TZSP_MAX_DURATION_SECONDS, 'MIKROTIK_TZSP_MAX_DURATION_SECONDS', 60, 600);
  if (durationSeconds > Math.min(60, configuredMax)) throw new Error(`durationSeconds cannot exceed the managed workflow limit of ${Math.min(60, configuredMax)} seconds.`);
  assertExactConfirmation(confirmation, `CAPTURE ROUTER SNIFFER ${router.id} ${name} ${durationSeconds}s TO ${bindAddress}:${port}`);
  return runRouterSnifferCapture({
    device: router.id,
    name,
    durationSeconds,
    bindAddress,
    port,
    withRouter,
    captureManager: getTzspCaptureManager({ requireEnabled: true }),
  });
}));

server.registerTool('tzsp_capture_status', {
  title: 'Read local TZSP capture status',
  description: 'Read current host-side capture metadata only. Does not query or change RouterOS and never returns packet payloads.',
  inputSchema: {},
}, async () => safely(async () => {
  const bindAddress = process.env.MIKROTIK_TZSP_BIND_ADDRESS ?? null;
  const sources = tzspSourceAllowlist();
  const configured = Boolean(bindAddress && net.isIP(bindAddress) !== 0 && bindAddress !== '0.0.0.0' && bindAddress !== '::' && sources.length > 0);
  return {
    enabled: readBoolean('MIKROTIK_TZSP_RECEIVER_ENABLED', false),
    configured,
    activeCapture: tzspCaptureManager ? await tzspCaptureManager.status() : null,
    note: 'Only receiver metadata is returned; packet bytes are written to private PCAP files and are never included in MCP responses.',
  };
}));

server.registerTool('stop_tzsp_capture_receiver', {
  title: 'Stop a local TZSP receiver',
  description: 'Stop/finalize one host-side PCAP capture. This does not stop or disable the RouterOS sniffer; do so manually. Requires both write gates, the active-diagnostics gate, and exact confirmation STOP TZSP CAPTURE <captureId>.',
  inputSchema: { captureId: z.string().uuid(), confirmation: z.string().min(1).max(100) },
}, async ({ captureId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { activeDiagnostics: true });
  assertExactConfirmation(confirmation, `STOP TZSP CAPTURE ${captureId}`);
  const capture = await getTzspCaptureManager({ requireEnabled: true }).stop(captureId);
  return { ...capture, routerSnifferStopped: false, note: 'The host receiver is stopped. Stop RouterOS sniffer streaming manually if it is still enabled.' };
}));

server.registerTool('list_tzsp_captures', {
  title: 'List local TZSP PCAP files',
  description: 'List metadata and local paths for completed private TZSP PCAP files. Packet contents are not read or returned.',
  inputSchema: {},
}, async () => safely(async () => ({ captures: await getTzspCaptureManager().list() })));

server.registerTool('summarize_tzsp_capture', {
  title: 'Summarize a completed local TZSP capture',
  description: 'Read one completed private PCAP file using no-follow, owner-only checks and return packet/protocol counts only. IP/MAC addresses, packet payloads and filesystem paths are never returned; the 64 MiB and 100,000-packet limits apply.',
  inputSchema: { captureId: z.string().uuid() },
}, async ({ captureId }) => safely(async () => {
  const dataDir = process.env.MIKROTIK_DATA_DIR
    ? path.resolve(process.env.MIKROTIK_DATA_DIR)
    : path.resolve(process.cwd(), '.data');
  return summarizeLocalCapture({ captureManager: getTzspCaptureManager(), captureId, dataDir });
}));

server.registerTool('delete_tzsp_capture', {
  title: 'Delete a local TZSP capture file',
  description: 'Permanently delete one completed local PCAP file only. Requires both write gates, destructive-operation gate, and exact confirmation DELETE TZSP CAPTURE <captureId>. RouterOS settings/files are not changed.',
  inputSchema: { captureId: z.string().uuid(), confirmation: z.string().min(1).max(100) },
}, async ({ captureId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  assertExactConfirmation(confirmation, `DELETE TZSP CAPTURE ${captureId}`);
  return getTzspCaptureManager().delete(captureId);
}));

const snapshotResources = [...new Map(RESOURCE_CATALOG
  .filter((resource) => resource.writeFields.length > 0)
  .map((resource) => [resource.path, resource])).values()];
server.registerTool('create_router_snapshot', {
  title: 'Create a router configuration inventory snapshot',
  description: 'Save a private local snapshot of allowlisted configuration records for one router. This is not a restorable RouterOS backup and does not change the router.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const router = resolveRouter(device);
  const captured = await withRouter(router.id, async (client, config) => {
    const resourceRows = [];
    for (const resource of snapshotResources) {
      try {
        const rows = await printSafeResource(client, resource);
        resourceRows.push({ name: resource.key, path: resource.path, records: rows.slice(0, 2000), truncated: rows.length > 2000, total: rows.length });
      } catch (error) {
        if (!(error instanceof RouterOsApiError) || !error.message.startsWith('RouterOS rejected the command:')) throw error;
        resourceRows.push({ name: resource.key, path: resource.path, records: [], unavailable: true, reason: error.message.slice(0, 256) });
      }
    }
    const identity = await client.print('/system/identity', ['name']);
    const system = await client.print('/system/resource', ['version']);
    return { host: config.connectedHost ?? config.host, device: config.id, identity: identity[0] ?? null, version: system[0]?.version ?? 'unknown', resources: resourceRows };
  });
  return createSnapshot(captured);
}));
server.registerTool('list_router_snapshots', {
  title: 'List saved router snapshots', description: 'List local configuration-inventory snapshots without reading or changing a router.',
  inputSchema: {},
}, async () => safely(() => listSnapshots()));
server.registerTool('diff_router_snapshots', {
  title: 'Compare two router snapshots', description: 'Compare saved configuration-inventory snapshots; changing counters and other volatile status values are ignored.',
  inputSchema: { baseId: z.string().uuid(), currentId: z.string().uuid() },
}, async ({ baseId, currentId }) => safely(async () => {
  const result = await diffSnapshots(baseId, currentId);
  const perResourceLimit = 100;
  let truncated = false;
  for (const entry of result.resources) {
    for (const key of ['added', 'removed', 'changed']) {
      if (entry[key].length > perResourceLimit) { entry[key] = entry[key].slice(0, perResourceLimit); truncated = true; }
    }
  }
  return redactSensitiveRecords({ ...result, truncated, perResourceRecordLimit: perResourceLimit });
}));
server.registerTool('delete_router_snapshot', {
  title: 'Delete a saved router snapshot', description: 'Delete one local snapshot by UUID after exact confirmation. This only deletes the local inventory file; it does not affect the router.',
  inputSchema: { snapshotId: z.string().uuid(), confirmation: z.string().min(1).max(80) },
}, async ({ snapshotId, confirmation }) => safely(async () => {
  if (confirmation !== `DELETE ${snapshotId}`) throw new Error(`Exact confirmation required: DELETE ${snapshotId}`);
  return deleteSnapshot(snapshotId);
}));

server.registerTool('create_encrypted_router_backup', {
  title: 'Create a password-encrypted RouterOS backup',
  description: 'Save a RouterOS binary .backup using a unique name and user-supplied encryption passphrase, then verify its router-side file entry. Requires both write gates, a pinned SSH/SFTP host key, separate SSH credentials and exact confirmation. The passphrase is neither returned nor stored. This backup is device/version sensitive and does not include User Manager or The Dude databases.',
  inputSchema: {
    device: deviceArg(), name: z.string().regex(/^[A-Za-z0-9_-]{1,48}$/).describe('Safe backup name prefix; the tool appends a random suffix to avoid overwriting files.'),
    encryptionPassword: z.string().min(16).max(128), confirmation: z.string().min(1).max(160),
  },
}, async ({ device, name, encryptionPassword, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `CREATE ENCRYPTED BACKUP ${router.id} ${name}`);
  if (!router.tls || !router.tlsRejectUnauthorized) throw new Error('Encrypted backup creation requires RouterOS API TLS with certificate verification enabled before transmitting the encryption passphrase.');
  assertSftpConfiguration(router);
  if (encryptionPassword === router.password || encryptionPassword === router.sshPassword) throw new Error('Choose an encryption passphrase that is different from the RouterOS API and SSH login passwords.');
  if (/[\u0000\r\n]/.test(encryptionPassword)) throw new Error('Encryption passphrase cannot contain control characters.');
  const routerBaseName = `${name}-${randomUUID()}`;
  const routerFile = `${routerBaseName}.backup`;
  let saveAttempted = false;
  let remote;
  try {
    remote = await withRouter(router.id, async (client, connection) => {
      const existing = await client.print('/file', ['name', 'type', 'size'], [`?=name=${routerFile}`]);
      if (existing.length !== 0) throw new Error(`Router file ${routerFile} already exists; choose a new name and inspect the existing file.`);
      saveAttempted = true;
      await client.command('/system/backup/save', { name: routerBaseName, password: encryptionPassword, 'dont-encrypt': 'no' });
      const saved = await client.print('/file', ['name', 'type', 'size'], [`?=name=${routerFile}`]);
      if (saved.length !== 1 || saved[0].type !== 'backup') throw new Error('RouterOS did not verify exactly one binary backup file after the save command.');
      return { host: connection.connectedHost ?? connection.host, size: saved[0].size ?? null };
    });
  } catch (error) {
    let message = error instanceof Error ? error.message : 'Unknown RouterOS backup error';
    if (encryptionPassword) message = message.split(encryptionPassword).join('[redacted]');
    if (saveAttempted) throw new Error(`Backup save or verification may have an ambiguous router-side outcome. Inspect /file for ${routerFile} before retrying. ${message}`);
    throw new Error(message);
  }
  let record;
  try {
    record = await createPendingBackup({ device: router.id, host: remote.host, routerFile });
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'unknown local storage error';
    throw new Error(`The encrypted backup was saved and verified on ${remote.host} as ${routerFile}, but local metadata could not be stored. Inspect /file before retrying. ${detail}`);
  }
  return { ...record, size: remote.size, note: 'Encrypted backup remains on the router until downloaded; keep the passphrase separately. RouterOS binary backups are device/version sensitive and do not include User Manager or The Dude databases.' };
}));

server.registerTool('list_local_encrypted_backups', {
  title: 'List encrypted router backup records',
  description: 'List local metadata for encrypted router backups and their download state; this does not connect to routers or reveal passphrases.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const router = device ? resolveRouter(device) : null;
  const records = await listBackupRecords({ device: router?.id });
  return { backups: records.map((record) => record.status === 'downloaded' ? { ...record, localPath: backupFilePath(record.id) } : record), localVaultPermissions: 'owner-only (directories 0700, files 0600)', note: 'File permissions do not guarantee full-disk encryption; keep backups on encrypted storage.' };
}));

server.registerTool('download_encrypted_router_backup', {
  title: 'Download an encrypted router backup over pinned SFTP',
  description: 'Stream a previously recorded .backup file from the router into a private local vault, verifying host key, size and SHA-256. Requires both write gates, separate SSH credentials, pinned host key and exact confirmation. The router-side copy is not removed.',
  inputSchema: { backupId: z.string().uuid(), confirmation: z.string().min(1).max(160) },
}, async ({ backupId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const record = await getBackupRecord(backupId);
  if (record.status !== 'on-router') throw new Error('This backup is not awaiting a local download.');
  const router = resolveRouter(record.device);
  if (!router.hosts.includes(record.host)) throw new Error('The stored backup host is no longer one of this router’s configured endpoints; verify router configuration before transfer.');
  assertExactConfirmation(confirmation, `DOWNLOAD ENCRYPTED BACKUP ${router.id} ${backupId}`);
  assertSftpConfiguration(router);
  const remoteRows = await withRouter(router.id, (client) => client.print('/file', ['name', 'type', 'size'], [`?=name=${record.routerFile}`]), { onlyHost: record.host });
  if (remoteRows.length !== 1 || remoteRows[0].name !== record.routerFile || remoteRows[0].type !== 'backup') {
    throw new Error('The recorded router file is missing, ambiguous, or no longer a RouterOS binary backup; no SFTP transfer was started.');
  }
  const destination = backupFilePath(backupId);
  let downloaded;
  try { downloaded = await downloadRouterBackup({ ...router, host: record.host }, record.routerFile, destination); }
  catch (error) { throw errorWithoutSecrets(error, [router.sshUsername, router.sshPassword]); }
  let updated;
  try {
    updated = await markBackupDownloaded(backupId, { size: downloaded.size, sha256: downloaded.sha256 });
  } catch (error) {
    await fsp.unlink(destination).catch(() => {});
    throw error;
  }
  return { ...updated, localPath: destination, note: 'The encrypted backup bytes are stored in the private local vault. The router-side file remains in place; this tool does not restore the backup.' };
}));

server.registerTool('upload_encrypted_router_backup_to_s3', {
  title: 'Upload one encrypted router backup to S3',
  description: 'Stream one already-downloaded, RouterOS-encrypted backup to a configured Amazon S3 bucket using the AWS default credential chain, expected bucket-owner check, SHA-256 checksum, server-side encryption and conditional no-overwrite. No credentials, object key, endpoint, or packet bytes are returned. Requires MIKROTIK_S3_ENABLED=true, both write gates, and exact confirmation: UPLOAD ENCRYPTED BACKUP <device> <backupId> TO S3 s3://<bucket>/<derived-key>. Does not delete local/router copies or configure retention.',
  inputSchema: { backupId: z.string().uuid(), confirmation: z.string().min(1).max(320) },
}, async ({ backupId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const record = await getBackupRecord(backupId);
  if (record.status !== 'downloaded') throw new Error('Only an already-downloaded encrypted backup can be sent to S3.');
  const configuration = getS3BackupConfiguration(process.env);
  const target = getS3BackupTarget(record, configuration);
  assertExactConfirmation(confirmation, `UPLOAD ENCRYPTED BACKUP ${record.device} ${record.id} TO S3 s3://${configuration.bucket}/${target.key}`);
  return uploadEncryptedBackupToS3({ backupId: record.id, env: process.env });
}));

server.registerTool('list_encrypted_router_backups_in_s3', {
  title: 'List this router’s encrypted backups in S3',
  description: 'Read one page of backup objects under the configured prefix for one configured router. Requires MIKROTIK_S3_ENABLED=true and MIKROTIK_S3_ALLOW_LISTING=true, plus prefix-scoped s3:ListBucket permission. Uses an expected bucket-owner check and filters output to UUID .backup keys; no object bodies or other router prefixes are returned.',
  inputSchema: { device: z.string().regex(/^[A-Za-z0-9_-]{1,48}$/), continuationToken: z.string().max(2048).optional() },
}, async ({ device, continuationToken }) => safely(async () => {
  const router = resolveRouter(device);
  return listEncryptedRouterBackupsInS3({ device: router.id, continuationToken, env: process.env });
}));

server.registerTool('list_encrypted_router_backup_versions_in_s3', {
  title: 'List versions of this router’s encrypted backups in S3',
  description: 'Read one page (up to 100 entries) of object versions for exact UUID .backup keys under one configured router prefix. Requires MIKROTIK_S3_ENABLED=true, MIKROTIK_S3_ALLOW_LISTING=true and prefix-scoped s3:ListBucketVersions permission. Returns version IDs and metadata only; it never reads object bodies or delete markers.',
  inputSchema: { device: z.string().regex(/^[A-Za-z0-9_-]{1,48}$/), continuationToken: z.string().max(4096).optional() },
}, async ({ device, continuationToken }) => safely(async () => {
  const router = resolveRouter(device);
  return listEncryptedRouterBackupVersionsInS3({ device: router.id, continuationToken, env: process.env });
}));

server.registerTool('delete_encrypted_router_backup_from_s3', {
  title: 'Delete one encrypted router backup key from S3',
  description: 'Submit DeleteObject for one exact derived backup key only. Requires MIKROTIK_S3_ENABLED=true, MIKROTIK_S3_ALLOW_DELETE=true, both write gates, the destructive-operation gate and exact confirmation: DELETE S3 ENCRYPTED BACKUP <device> <backupId> FROM s3://<bucket>/<derived-key>. In a versioned bucket this normally creates a delete marker; it does not purge old versions or bypass Object Lock/retention.',
  inputSchema: { device: z.string().regex(/^[A-Za-z0-9_-]{1,48}$/), backupId: z.string().uuid(), confirmation: z.string().min(1).max(320) },
}, async ({ device, backupId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  const configuration = getS3BackupConfiguration(process.env);
  if (!configuration.enabled) throw new Error('S3 backup is disabled.');
  if (!configuration.allowDelete) throw new Error('S3 deletion is disabled; set MIKROTIK_S3_ALLOW_DELETE=true only after reviewing bucket versioning and retention.');
  const target = getS3BackupTarget({ device: router.id, id: backupId, status: 'downloaded' }, configuration);
  assertExactConfirmation(confirmation, `DELETE S3 ENCRYPTED BACKUP ${router.id} ${backupId} FROM s3://${target.bucket}/${target.key}`);
  return deleteEncryptedRouterBackupFromS3({ device: router.id, backupId, env: process.env });
}));

server.registerTool('delete_encrypted_router_backup_version_from_s3', {
  title: 'Request deletion of one selected S3 backup version',
  description: 'Submit DeleteObject for exactly one caller-selected version of the derived UUID .backup key. Requires MIKROTIK_S3_ENABLED=true, MIKROTIK_S3_ALLOW_DELETE=true, MIKROTIK_S3_ALLOW_VERSION_PURGE=true, both app write gates, the destructive-operation gate, and exact confirmation: DELETE S3 BACKUP VERSION <device> <backupId> <versionId> FROM s3://<bucket>/<derived-key>. The result confirms request acceptance only; Object Lock/retention may prevent permanent removal.',
  inputSchema: {
    device: z.string().regex(/^[A-Za-z0-9_-]{1,48}$/),
    backupId: z.string().uuid(),
    versionId: z.string().min(1).max(1024),
    confirmation: z.string().min(1).max(2048),
  },
}, async ({ device, backupId, versionId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  const configuration = getS3BackupConfiguration(process.env);
  if (!configuration.enabled) throw new Error('S3 backup is disabled.');
  if (!configuration.allowDelete) throw new Error('S3 deletion is disabled; set MIKROTIK_S3_ALLOW_DELETE=true only after reviewing bucket versioning and retention.');
  if (!configuration.allowVersionPurge) throw new Error('S3 object-version deletion is disabled; set MIKROTIK_S3_ALLOW_VERSION_PURGE=true only after review and explicit authorization.');
  const target = getS3BackupTarget({ device: router.id, id: backupId, status: 'downloaded' }, configuration);
  assertExactConfirmation(confirmation, `DELETE S3 BACKUP VERSION ${router.id} ${backupId} ${versionId} FROM s3://${target.bucket}/${target.key}`);
  return deleteEncryptedRouterBackupVersionFromS3({ device: router.id, backupId, versionId, env: process.env });
}));

server.registerTool('delete_local_encrypted_backup', {
  title: 'Delete a local encrypted backup copy',
  description: 'Delete only the downloaded local vault file and metadata after exact confirmation. Requires both write gates and never deletes the router-side file.',
  inputSchema: { backupId: z.string().uuid(), confirmation: z.string().min(1).max(120) },
}, async ({ backupId, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  assertExactConfirmation(confirmation, `DELETE LOCAL ENCRYPTED BACKUP ${backupId}`);
  return { ...await deleteLocalBackup(backupId), note: 'Only the local copy and metadata were deleted; the router-side backup file was not touched.' };
}));

function validTarget(target) {
  if (net.isIP(target)) return true;
  if (typeof target !== 'string' || target.length === 0 || target.length > 253 || /[\u0000\r\n\s]/.test(target)) return false;
  const host = target.endsWith('.') ? target.slice(0, -1) : target;
  return host.split('.').every((label) => label.length > 0 && label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
}
server.registerTool('ping_host', {
  title: 'Ping a host from the router', description: 'Run a bounded RouterOS ping to an IP address or DNS hostname; no configuration is changed.',
  inputSchema: { device: deviceArg(), target: z.string().min(1).max(253), count: z.number().int().min(1).max(10).optional() },
}, async ({ device, target, count = 4 }) => safely(async () => {
  if (!validTarget(target)) throw new Error('Target must be an IP address or DNS hostname; command syntax is not accepted.');
  const rows = await withRouter(device, (client) => client.command('/ping', { address: target, count: String(count) }));
  return { device: resolveRouter(device).id, target, count, results: rows.slice(0, 20) };
}));
server.registerTool('traceroute_host', {
  title: 'Trace a route from the router', description: 'Run a bounded RouterOS traceroute to an IP address or DNS hostname, up to 20 hops.',
  inputSchema: { device: deviceArg(), target: z.string().min(1).max(253), maxHops: z.number().int().min(1).max(20).optional(), useDns: z.boolean().optional() },
}, async ({ device, target, maxHops = 12, useDns = false }) => safely(async () => {
  if (!validTarget(target)) throw new Error('Target must be an IP address or DNS hostname; command syntax is not accepted.');
  const rows = await withRouter(device, (client) => client.command('/tool/traceroute', { address: target, 'max-hops': String(maxHops), 'use-dns': useDns ? 'yes' : 'no' }));
  return { device: resolveRouter(device).id, target, maxHops, results: rows.slice(0, 40) };
}));
server.registerTool('monitor_interface_traffic', {
  title: 'Monitor interface traffic', description: 'Read one traffic sample for a named interface without changing configuration.',
  inputSchema: { device: deviceArg(), interface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/) },
}, async ({ device, interface: name }) => safely(async () => {
  const rows = await withRouter(device, (client) => client.command('/interface/monitor-traffic', { interface: name, once: 'true' }));
  return { device: resolveRouter(device).id, interface: name, sample: rows[0] ?? null };
}));

function validIPv4Range(value) {
  if (typeof value !== 'string' || value.length > 80 || /[\u0000\r\n\s]/.test(value)) return false;
  if (net.isIP(value) === 4) return true;
  const [address, mask, extra] = value.split('/');
  if (extra === undefined && mask !== undefined && net.isIP(address) === 4) {
    const prefix = Number(mask);
    return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
  }
  const parts = value.split('-');
  return parts.length === 2 && parts.every((item) => net.isIP(item) === 4);
}

server.registerTool('run_bandwidth_test', {
  title: 'Run a bounded RouterOS bandwidth test',
  description: 'Run a remote throughput test for at most 5 seconds. It can saturate links; requires both write gates, MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true and exact target-specific confirmation.',
  inputSchema: {
    device: deviceArg(), target: z.string().min(1).max(253), durationSeconds: z.number().int().min(1).max(5).optional(),
    direction: z.enum(['receive', 'transmit', 'both']).optional(), protocol: z.enum(['tcp', 'udp']).optional(),
    username: z.string().max(128).optional(), password: z.string().max(256).optional(), confirmation: z.string().min(1).max(160),
  },
}, async ({ device, target, durationSeconds = 3, direction = 'receive', protocol = 'tcp', username, password, confirmation }) => safely(async () => {
  if (!validTarget(target)) throw new Error('Target must be an IP address or DNS hostname; command syntax is not accepted.');
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `RUN BANDWIDTH TEST ${router.id} ${target}`);
  const attributes = { address: target, duration: `${durationSeconds}s`, direction, protocol };
  if (username !== undefined) attributes.user = username;
  if (password !== undefined) attributes.password = password;
  let results;
  try { results = await withRouter(router.id, (client) => client.command('/tool/bandwidth-test', attributes)); }
  catch (error) { throw errorWithoutSecrets(error, [username, password]); }
  return { device: router.id, target, durationSeconds, direction, protocol, results: redactSensitiveRecords(results.slice(0, 20)), note: 'This test sends real traffic and may affect other users; no credentials are returned.' };
}));

server.registerTool('run_speed_test', {
  title: 'Run a bounded RouterOS link speed test',
  description: 'Measure ping, TCP and UDP throughput to a remote MikroTik bandwidth-test server using authenticated remote credentials. Each of five phases has RouterOS minimum duration 5 seconds (about 30 seconds total). The test can fill the link and load both router CPUs; it never creates firewall rules or remote test accounts. Requires both write gates, MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true and exact target confirmation.',
  inputSchema: {
    device: deviceArg(), target: z.string().min(1).max(253), durationSeconds: z.literal(5).optional(),
    connectionCount: z.number().int().min(1).max(20).optional(),
    username: z.string().min(1).max(128).optional(), password: z.string().min(1).max(256).optional(),
    confirmation: z.string().min(1).max(160),
  },
}, async ({ device, target, durationSeconds = 5, connectionCount = 4, username, password, confirmation }) => safely(async () => {
  if (!validTarget(target)) throw new Error('Target must be an IP address or DNS hostname; command syntax is not accepted.');
  if (username === undefined || password === undefined) throw new Error('Provide an authenticated remote bandwidth-test username and password.');
  if ([username, password].some((value) => value !== undefined && /[\u0000\r\n]/.test(value))) throw new Error('Credentials cannot contain control characters.');
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `RUN SPEED TEST ${router.id} ${target}`);
  const attributes = { address: target, 'test-duration': `${durationSeconds}s`, 'connection-count': String(connectionCount) };
  if (username !== undefined) attributes.user = username;
  if (password !== undefined) attributes.password = password;
  let results;
  try { results = await withRouter(router.id, (client) => client.command('/tool/speed-test', attributes)); }
  catch (error) { throw errorWithoutSecrets(error, [username, password]); }
  return { device: router.id, target, durationSeconds, connectionCount, results: redactSensitiveRecords(results.slice(0, 30)), note: 'Five phases can saturate the tested link for roughly 30 seconds; bandwidth-server, firewall and device-mode prerequisites must already be satisfied on both routers. Results may be CPU-limited, and credentials are not returned.' };
}));

server.registerTool('run_ip_scan', {
  title: 'Run a bounded IPv4 address scan',
  description: 'Probe IPv4 addresses on one interface for at most 5 seconds. Requires both write gates, MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true and exact interface/range confirmation.',
  inputSchema: { device: deviceArg(), interface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/), addressRange: z.string().min(1).max(80), durationSeconds: z.number().int().min(1).max(5).optional(), confirmation: z.string().min(1).max(180) },
}, async ({ device, interface: interfaceName, addressRange, durationSeconds = 3, confirmation }) => safely(async () => {
  if (!validIPv4Range(addressRange)) throw new Error('addressRange must be an IPv4 address, CIDR prefix, or IPv4 start-end range.');
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `RUN IP SCAN ${router.id} ${interfaceName} ${addressRange}`);
  const known = await withRouter(router.id, (client) => client.print('/interface', ['name'], [`?=name=${interfaceName}`]));
  if (known.length !== 1) throw new Error(`Interface ${interfaceName} was not found uniquely on ${router.id}.`);
  const results = await withRouter(router.id, (client) => client.command('/tool/ip-scan', { interface: interfaceName, 'address-range': addressRange, duration: `${durationSeconds}s` }));
  return { device: router.id, interface: interfaceName, addressRange, durationSeconds, results: results.slice(0, 100), truncated: results.length > 100 };
}));

server.registerTool('check_routeros_updates', {
  title: 'Check for RouterOS updates', description: 'Ask the configured RouterOS update channel for availability; does not install or reboot.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const result = await withRouter(device, (client) => client.command('/system/package/update/check-for-updates', { once: 'true' }));
  return { device: resolveRouter(device).id, results: result.slice(0, 10) };
}));

server.registerTool('make_dhcp_lease_static', {
  title: 'Make a DHCP lease static', description: 'Convert one currently dynamic DHCP lease to a persistent reservation. Requires both write gates and exact router/item confirmation.',
  inputSchema: { device: deviceArg(), id: z.string().regex(/^\*\d+$/), confirmation: z.string().min(1).max(140) },
}, async ({ device, id, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `MAKE DHCP LEASE STATIC ${router.id} ${id}`);
  const path = '/ip/dhcp-server/lease';
  const before = await withRouter(router.id, async (client) => {
    const rows = await client.print(path, ['.id', 'address', 'mac-address', 'host-name', 'status', 'dynamic'], [`?=.id=${id}`]);
    if (rows.length !== 1 || (rows[0].dynamic !== 'true' && rows[0].dynamic !== 'yes')) throw new Error(`DHCP lease ${id} is not a unique dynamic lease.`);
    return rows[0];
  });
  await withRouter(router.id, (client) => client.command(`${path}/make-static`, { '.id': id }));
  const after = await withRouter(router.id, (client) => client.print(path, ['.id', 'address', 'mac-address', 'host-name', 'dynamic'], [`?=.id=${id}`]));
  return { device: router.id, before, verified: after[0] ?? null, static: after.length === 1 && after[0].dynamic !== 'true' && after[0].dynamic !== 'yes' };
}));

server.registerTool('operate_dhcp_client', {
  title: 'Renew or release a DHCP client lease', description: 'Run one RouterOS DHCP client action. Requires both write gates and exact router/action/item confirmation.',
  inputSchema: { device: deviceArg(), id: z.string().regex(/^\*\d+$/), action: z.enum(['renew', 'release']), confirmation: z.string().min(1).max(140) },
}, async ({ device, id, action, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `${action.toUpperCase()} DHCP CLIENT ${router.id} ${id}`);
  const path = '/ip/dhcp-client';
  const before = await withRouter(router.id, async (client) => {
    const rows = await client.print(path, ['.id', 'interface', 'status', 'address', 'gateway', 'disabled'], [`?=.id=${id}`]);
    if (rows.length !== 1) throw new Error(`DHCP client ${id} is not unique on ${router.id}.`);
    return rows[0];
  });
  const result = await withRouter(router.id, (client) => client.command(`${path}/${action}`, { '.id': id }));
  return { device: router.id, action, before, result: result.slice(0, 5), note: 'Lease status may change asynchronously; inspect the DHCP client list before repeating.' };
}));

server.registerTool('flush_dns_cache', {
  title: 'Flush the RouterOS DNS cache', description: 'Clear cached DNS answers without changing static records or resolver configuration. Requires both write gates and exact router-ID confirmation.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(100) },
}, async ({ device, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `FLUSH DNS CACHE ${router.id}`);
  const result = await withRouter(router.id, (client) => client.command('/ip/dns/cache/flush'));
  return { device: router.id, flushed: true, result: result.slice(0, 5) };
}));

server.registerTool('reboot_router', {
  title: 'Reboot a router', description: 'Dangerous: disconnects all sessions and interrupts service. Requires both write gates, MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true and exact router-ID confirmation.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(96) },
}, async ({ device, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `REBOOT ${router.id}`);
  await withRouter(router.id, (client) => client.command('/system/reboot'));
  return { device: router.id, accepted: true, note: 'The router may drop this connection before a final response; inspect its status before retrying.' };
}));

server.registerTool('shutdown_router', {
  title: 'Shut down a router', description: 'Dangerous: powers the router off until it is physically restarted. Requires both write gates, MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true and exact router-ID confirmation.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(96) },
}, async ({ device, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `SHUTDOWN ${router.id}`);
  await withRouter(router.id, (client) => client.command('/system/shutdown'));
  return { device: router.id, accepted: true, note: 'Power is off; the router requires a physical power-on to return.' };
}));

server.registerTool('install_routeros_updates', {
  title: 'Install RouterOS updates', description: 'Dangerous maintenance operation; can replace packages and reboot. Check updates first. Requires both write gates, MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true and exact router-ID confirmation.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(120) },
}, async ({ device, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `INSTALL ROUTEROS UPDATES ${router.id}`);
  const result = await withRouter(router.id, (client) => client.command('/system/package/update/install'));
  return { device: router.id, accepted: true, results: result.slice(0, 10), note: 'The router may reboot or disconnect; do not retry until its package and uptime state are checked.' };
}));

server.registerTool('upgrade_routerboard_firmware', {
  title: 'Schedule RouterBOARD firmware upgrade', description: 'Dangerous maintenance operation; applies the firmware staged by RouterOS and requires a later reboot. Requires both write gates, MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true and exact router-ID confirmation.',
  inputSchema: { device: deviceArg(), confirmation: z.string().min(1).max(140) },
}, async ({ device, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { destructive: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `UPGRADE ROUTERBOARD FIRMWARE ${router.id}`);
  const result = await withRouter(router.id, (client) => client.command('/system/routerboard/upgrade'));
  return { device: router.id, accepted: true, results: result.slice(0, 10), note: 'Verify the firmware state, then plan a separate maintenance-window reboot if required.' };
}));

server.registerTool('audit_router_security_posture', {
  title: 'Run a read-only security posture check',
  description: 'Collect a small set of management-service, user and IPv4 input-filter facts, then report transparent heuristics. Not a penetration test or complete hardening audit.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const services = await client.print('/ip/service', ['name', 'port', 'address', 'disabled']);
  const users = await client.print('/user', ['name', 'group', 'address', 'disabled']);
  const inputRules = await client.print('/ip/firewall/filter', ['.id', 'chain', 'action', 'protocol', 'dst-port', 'in-interface', 'src-address', 'disabled']);
  const findings = [];
  const unrestricted = services.filter((row) => row.disabled !== 'true' && row.disabled !== 'yes' && (!row.address || row.address === '0.0.0.0/0'));
  if (unrestricted.length) findings.push({ severity: 'review', evidence: 'Enabled IP services have no explicit address allowlist.', services: unrestricted.map(({ name, port }) => ({ name, port })) });
  const adminUsers = users.filter((row) => row.group === 'full' && row.disabled !== 'true' && row.disabled !== 'yes');
  if (adminUsers.length) findings.push({ severity: 'review', evidence: 'Full-privilege accounts are enabled; verify they are named, individually managed and source-restricted.', users: adminUsers.map(({ name, address }) => ({ name, address })) });
  const enabledInputRules = inputRules.filter((row) => row.chain === 'input' && row.disabled !== 'true' && row.disabled !== 'yes');
  const hasInputDrop = enabledInputRules.some((row) => ['drop', 'reject'].includes(row.action));
  if (!hasInputDrop) findings.push({ severity: 'review', evidence: 'No enabled IPv4 input-chain drop/reject rule was found; verify policy and IPv6 separately.' });
  return { device: router.id, evidence: { enabledServiceCount: services.length - services.filter((r) => r.disabled === 'true' || r.disabled === 'yes').length, enabledFullUsers: adminUsers.length, enabledIPv4InputRules: enabledInputRules.length }, findings, limitations: ['Heuristic only; order, address lists, dynamic rules and IPv6 policy are not fully evaluated.', 'No configuration was changed.'] };
})));

server.registerTool('router_health_report', {
  title: 'Router health report', description: 'Read CPU, memory, storage, uptime and available hardware sensors, with transparent threshold-based review indicators; no configuration changes.',
  inputSchema: { device: deviceArg(), cpuReviewPercent: z.number().min(1).max(100).optional(), memoryReviewPercent: z.number().min(1).max(100).optional(), storageReviewPercent: z.number().min(1).max(100).optional() },
}, async ({ device, cpuReviewPercent = 85, memoryReviewPercent = 90, storageReviewPercent = 90 }) => safely(async () => withRouter(device, async (client, router) => {
  const resources = (await client.print('/system/resource', ['version', 'uptime', 'cpu', 'cpu-count', 'free-memory', 'total-memory', 'free-hdd-space', 'total-hdd-space', 'board-name', 'architecture-name']))[0] ?? {};
  const sensors = await client.print('/system/health', ['name', 'value', 'type']);
  const metricPercent = (freeKey, totalKey) => {
    const free = Number(resources[freeKey]);
    const total = Number(resources[totalKey]);
    return Number.isFinite(free) && Number.isFinite(total) && total > 0 ? Math.round((total - free) / total * 1000) / 10 : null;
  };
  const cpu = Number.parseFloat(String(resources.cpu ?? '').replace('%', ''));
  const memoryUsedPercent = metricPercent('free-memory', 'total-memory');
  const storageUsedPercent = metricPercent('free-hdd-space', 'total-hdd-space');
  const reviews = [];
  if (Number.isFinite(cpu) && cpu >= cpuReviewPercent) reviews.push({ metric: 'cpu', valuePercent: cpu, thresholdPercent: cpuReviewPercent });
  if (memoryUsedPercent !== null && memoryUsedPercent >= memoryReviewPercent) reviews.push({ metric: 'memory', valuePercent: memoryUsedPercent, thresholdPercent: memoryReviewPercent });
  if (storageUsedPercent !== null && storageUsedPercent >= storageReviewPercent) reviews.push({ metric: 'storage', valuePercent: storageUsedPercent, thresholdPercent: storageReviewPercent });
  return { device: router.id, resources, derived: { memoryUsedPercent, storageUsedPercent }, sensors, reviewThresholds: { cpuReviewPercent, memoryReviewPercent, storageReviewPercent }, reviews, note: 'Hardware temperature and voltage limits vary by model; sensor readings are reported without universal pass/fail thresholds.' };
})));

server.registerTool('list_connected_devices', {
  title: 'Build a connected-device inventory', description: 'Join DHCP leases, ARP entries and bridge learning records by MAC address for a best-effort local inventory.',
  inputSchema: { device: deviceArg(), limit: z.number().int().min(1).max(MAX_ROWS).optional() },
}, async ({ device, limit = 200 }) => safely(async () => withRouter(device, async (client, router) => {
  const leases = await client.print('/ip/dhcp-server/lease', ['address', 'mac-address', 'host-name', 'status', 'last-seen', 'expires-after']);
  const arp = await client.print('/ip/arp', ['address', 'mac-address', 'interface', 'complete', 'dynamic']);
  const bridgeHosts = await client.print('/interface/bridge/host', ['mac-address', 'on-interface', 'bridge', 'vid', 'age', 'local']);
  const devices = new Map();
  const keyFor = (mac, address) => String(mac || address || 'unknown').toLowerCase();
  for (const row of leases) {
    const key = keyFor(row['mac-address'], row.address);
    devices.set(key, { ...(devices.get(key) ?? {}), ...row, sources: [...new Set([...(devices.get(key)?.sources ?? []), 'dhcp'])] });
  }
  for (const row of arp) {
    const key = keyFor(row['mac-address'], row.address);
    devices.set(key, { ...(devices.get(key) ?? {}), ...row, sources: [...new Set([...(devices.get(key)?.sources ?? []), 'arp'])] });
  }
  for (const row of bridgeHosts) {
    const key = keyFor(row['mac-address'], row.address);
    devices.set(key, { ...(devices.get(key) ?? {}), ...row, sources: [...new Set([...(devices.get(key)?.sources ?? []), 'bridge'])] });
  }
  const records = [...devices.values()].slice(0, limit);
  return { device: router.id, records, returned: records.length, total: devices.size, truncated: devices.size > records.length, note: 'This merges observed/router-known records; it does not prove a device is currently reachable.' };
})));

server.registerTool('audit_multiwan_paths', {
  title: 'Audit IPv4 default-route redundancy', description: 'Read default routes and current interface states to summarize possible WAN path diversity; this does not test failover behavior.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const routes = await client.print('/ip/route', ['.id', 'dst-address', 'gateway', 'immediate-gw', 'distance', 'routing-table', 'active', 'disabled', 'check-gateway']);
  const interfaces = await client.print('/interface', ['name', 'type', 'running', 'disabled']);
  const defaults = routes.filter((row) => row['dst-address'] === '0.0.0.0/0' && row.disabled !== 'true' && row.disabled !== 'yes');
  const ranked = defaults.sort((a, b) => Number(a.distance ?? 0) - Number(b.distance ?? 0));
  return { device: router.id, defaultRouteCount: defaults.length, activeDefaultRouteCount: defaults.filter((row) => row.active === 'true' || row.active === 'yes').length, routes: ranked, interfaces, note: 'Multiple default routes are only a configuration signal; link monitoring, policy routing, NAT and end-to-end failover were not simulated.' };
})));

server.registerTool('audit_routing_protocol_health', {
  title: 'Audit routing protocol state',
  description: 'Summarize observed routes and BGP, OSPF, RIP, and BFD status from fixed read-only RouterOS paths. Unsupported or permission-denied sections remain unknown; this does not simulate route selection or prove forwarding/reachability.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const [routes, bgpSessions, ospfNeighbors, ripNeighbors, ripRoutes, bfdPeers] = await Promise.all([
    optionalResourceSection(client, 'routes'),
    optionalResourceSection(client, 'bgp_sessions'),
    optionalResourceSection(client, 'ospf_neighbors'),
    optionalResourceSection(client, 'rip_neighbors'),
    optionalResourceSection(client, 'rip_routes'),
    optionalResourceSection(client, 'routing_bfd_peers'),
  ]);
  return buildRoutingProtocolAudit({ device: router.id, sections: {
    routes, bgp_sessions: bgpSessions, ospf_neighbors: ospfNeighbors,
    rip_neighbors: ripNeighbors, rip_routes: ripRoutes, routing_bfd_peers: bfdPeers,
  } });
})));

server.registerTool('simulate_ipv4_route_candidates', {
  title: 'Simulate IPv4 route candidates in one table',
  description: 'Read a minimal fixed field set from /ip/route and rank candidates for one IPv4 destination in the explicitly selected routing table. The result is a bounded snapshot heuristic, not RouterOS forwarding, gateway recursion, VRF/rule processing or reachability. More than 500 routes or unavailable evidence returns unknown rather than a partial ranking.',
  inputSchema: { device: deviceArg(), destination: z.string().min(7).max(15), routingTable: z.string().min(1).max(64) },
}, async ({ device, destination, routingTable }) => safely(async () => withRouter(device, async (client, router) => {
  let routes;
  try {
    routes = await client.print('/ip/route', ['.id', 'dst-address', 'routing-table', 'distance', 'active', 'disabled']);
  } catch (error) {
    if (!(error instanceof RouterOsApiError) || !error.message.startsWith('RouterOS rejected the command:')) throw error;
    const unknown = simulateIpv4RouteCandidates({ destination, routingTable, routes: null });
    return { device: router.id, ...unknown, uncertainty: ['The IPv4 route list is unavailable or not permitted; no simulation was performed.'] };
  }
  if (routes.length > MAX_ROWS) {
    const unknown = simulateIpv4RouteCandidates({ destination, routingTable, routes: null });
    return { device: router.id, ...unknown, uncertainty: [`The IPv4 route table exceeds the ${MAX_ROWS}-record analysis limit; no partial ranking was performed.`] };
  }
  return { device: router.id, ...simulateIpv4RouteCandidates({ destination, routingTable, routes }) };
}))); 

server.registerTool('simulate_ipv6_route_candidates', {
  title: 'Simulate IPv6 route candidates in one table',
  description: 'Read a minimal field set from the fixed /ipv6/route path and rank candidates for one IPv6 destination in the explicitly selected table. The 500-route cap, complete-snapshot requirement, no-gateway redaction and limitations on rules, VRFs, recursion, forwarding and reachability apply.',
  inputSchema: { device: deviceArg(), destination: z.string().min(2).max(45), routingTable: z.string().min(1).max(64) },
}, async ({ device, destination, routingTable }) => safely(async () => withRouter(device, async (client, router) => {
  const section = await readFixedAuditSection(client, '/ipv6/route', ['.id', 'dst-address', 'routing-table', 'distance', 'active', 'disabled'], MAX_ROWS);
  const routes = section.status === 'available' ? section.records : [];
  const coverage = {
    status: section.status,
    complete: section.status === 'available' && section.truncated !== true,
    recordCount: routes.length,
    truncated: section.truncated === true,
  };
  return {
    device: router.id,
    coverage: { ipv6Routes: { status: section.status, recordCount: section.total ?? null, truncated: section.truncated === true } },
    ...simulateIpv6RouteCandidates({ destination, routingTable, routes, coverage }),
  };
})));

const FIREWALL_AUDIT_LIMIT = 5000;
const FIREWALL_ANALYSIS_FIELDS = new Set([
  '.id', 'chain', 'action', 'disabled', 'dynamic', 'invalid', 'protocol', 'src-address',
  'dst-address', 'src-port', 'dst-port', 'in-interface', 'out-interface',
]);
const FIREWALL_METADATA_FIELDS = new Set(['comment', 'bytes', 'packets', 'log', 'log-prefix']);
function sanitizeFirewallAuditRecord(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return row;
  const safe = Object.create(null);
  for (const [key, value] of Object.entries(row)) {
    if (key === '.id') {
      if (typeof value === 'string' && value.length <= 128) safe[key] = value;
      continue;
    }
    if (FIREWALL_ANALYSIS_FIELDS.has(key)) {
      if (key === 'chain') safe[key] = typeof value === 'string' && value.length <= 256 ? value : '';
      else if (key === 'action') safe[key] = typeof value === 'string' && value.length <= 256 ? value : '__unsupported_action__';
      else if (key === 'dynamic') safe[key] = typeof value === 'string' && value.length <= 256 ? value : 'yes';
      else safe[key] = typeof value === 'string' && value.length <= 256 ? value : '[invalid]';
      continue;
    }
    if (FIREWALL_METADATA_FIELDS.has(key)) continue;
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(key)) safe.unrecognized_property = 'present';
    else safe[key] = 'present';
  }
  return safe;
}
async function readFirewallAuditSection(client, apiPath) {
  try {
    const allRows = await client.printAll(apiPath);
    return {
      status: 'available', total: allRows.length,
      records: allRows.slice(0, FIREWALL_AUDIT_LIMIT).map(sanitizeFirewallAuditRecord),
      truncated: allRows.length > FIREWALL_AUDIT_LIMIT,
    };
  } catch (error) {
    if (error instanceof RouterOsApiError && error.message.startsWith('RouterOS rejected the command:')) {
      return { status: 'unavailable-or-not-permitted' };
    }
    return { status: 'error' };
  }
}

server.registerTool('audit_firewall_rule_order', {
  title: 'Audit possible firewall rule shadowing',
  description: 'Read all properties from only the fixed IPv4/IPv6 filter-rule paths so hidden match conditions become indeterminate instead of false proof. The 8 MiB API response cap and 5,000-rule per-family analysis cap apply. Returned output contains only possible-shadowing findings and coverage counts; raw rules, comments and match values are discarded. This is not a packet-path simulation and never proposes or applies a rule change.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const [ipv4, ipv6] = await Promise.all([
    readFirewallAuditSection(client, '/ip/firewall/filter'),
    readFirewallAuditSection(client, '/ipv6/firewall/filter'),
  ]);
  return { device: router.id, ...buildFirewallOrderAudit({ sections: { firewall_filter: ipv4, ipv6_firewall_filter: ipv6 } }) };
})));

async function collectWirelessInventory(device) {
  const router = resolveRouter(device);
  return withRouter(device, async (client) => {
    const [legacyWireless, legacyCapsman, wifi] = await Promise.all([
      optionalResourceSection(client, 'wireless_registrations'),
      optionalResourceSection(client, 'legacy_capsman_registrations'),
      optionalResourceSection(client, 'wifi_registrations'),
    ]);
    return buildWirelessInventory({
      device: router.id,
      sampledAt: new Date().toISOString(),
      sections: { legacyWireless, legacyCapsman, wifi },
    });
  });
}

server.registerTool('wireless_client_inventory', {
  title: 'Current wireless client inventory',
  description: 'Read current registration tables from legacy wireless, legacy CAPsMAN, and the new WiFi menu (including WiFi CAPsMAN). Unsupported paths remain unknown; no scan or configuration change is performed.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => collectWirelessInventory(device)));

server.registerTool('audit_wireless_clients', {
  title: 'Audit wireless client signal', description: 'Read current registrations across legacy wireless/CAPsMAN and new WiFi/CAPsMAN paths, then flag clients below a configurable RSSI threshold; advisory only.',
  inputSchema: { device: deviceArg(), weakSignalDbm: z.number().int().min(-120).max(-1).optional() },
}, async ({ device, weakSignalDbm = -70 }) => safely(async () => {
  const inventory = await collectWirelessInventory(device);
  const clients = inventory.associations.map((row) => ({ ...row, weak: row.signal !== null && row.signal < weakSignalDbm }));
  return { ...inventory, weakSignalDbm, weakClientCount: clients.filter((row) => row.weak).length, clients };
}));

server.registerTool('audit_vlan_consistency', {
  title: 'Audit VLAN and bridge consistency', description: 'Compare bridge VLAN filtering, bridge ports/PVIDs, VLAN tables, VLAN interfaces and IP addresses; returns review findings, not a claim of complete isolation.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const [bridges, ports, vlanRows, vlanInterfaces, addresses] = await Promise.all([
    client.print('/interface/bridge', ['.id', 'name', 'vlan-filtering', 'disabled']),
    client.print('/interface/bridge/port', ['.id', 'bridge', 'interface', 'pvid', 'frame-types', 'ingress-filtering', 'disabled']),
    client.print('/interface/bridge/vlan', ['.id', 'bridge', 'vlan-ids', 'tagged', 'untagged', 'current-tagged', 'current-untagged', 'disabled']),
    client.print('/interface/vlan', ['.id', 'name', 'interface', 'vlan-id', 'disabled']),
    client.print('/ip/address', ['.id', 'address', 'interface', 'disabled', 'dynamic']),
  ]);
  const expandVlanIds = (value) => String(value ?? '').split(',').flatMap((part) => {
    const [first, last] = part.trim().split('-').map(Number);
    if (!Number.isInteger(first) || first < 1 || first > 4094) return [];
    const end = Number.isInteger(last) ? Math.min(last, 4094) : first;
    return end >= first ? Array.from({ length: end - first + 1 }, (_, index) => first + index) : [];
  });
  const list = (value) => String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
  const findings = [];
  for (const bridge of bridges) {
    const entries = vlanRows.filter((row) => row.bridge === bridge.name && row.disabled !== 'true' && row.disabled !== 'yes');
    if (entries.length && bridge['vlan-filtering'] !== 'true' && bridge['vlan-filtering'] !== 'yes') findings.push({ severity: 'review', bridge: bridge.name, evidence: 'Bridge VLAN entries exist while VLAN filtering is not enabled.' });
    for (const port of ports.filter((item) => item.bridge === bridge.name && item.disabled !== 'true' && item.disabled !== 'yes')) {
      const pvid = Number(port.pvid ?? 1);
      if (pvid > 1 && !entries.some((row) => expandVlanIds(row['vlan-ids']).includes(pvid) && list(row.untagged).includes(port.interface))) {
        findings.push({ severity: 'review', bridge: bridge.name, interface: port.interface, pvid, evidence: 'Port PVID has no matching untagged membership in the bridge VLAN table.' });
      }
      if (port['ingress-filtering'] !== 'true' && port['ingress-filtering'] !== 'yes') findings.push({ severity: 'review', bridge: bridge.name, interface: port.interface, evidence: 'Ingress filtering is not enabled on this bridge port.' });
    }
  }
  for (const vlan of vlanInterfaces.filter((row) => row.disabled !== 'true' && row.disabled !== 'yes')) {
    const matching = vlanRows.some((row) => row.bridge === vlan.interface && expandVlanIds(row['vlan-ids']).includes(Number(vlan['vlan-id'])));
    if (!matching) findings.push({ severity: 'review', vlanInterface: vlan.name, bridge: vlan.interface, vlanId: vlan['vlan-id'], evidence: 'No matching bridge VLAN table entry was found for this VLAN interface.' });
  }
  return { device: router.id, counts: { bridges: bridges.length, bridgePorts: ports.length, bridgeVlanEntries: vlanRows.length, vlanInterfaces: vlanInterfaces.length, ipAddresses: addresses.length }, findings, evidence: { bridges, ports, vlanRows, vlanInterfaces, addresses }, limitations: ['RouterOS output and hardware-switch behavior vary by model; rule order, Wi-Fi, IPv6, firewall policy, and client reachability are not verified.', 'A clean report does not prove network isolation.'] };
})));

server.registerTool('audit_wireguard_peers', {
  title: 'Audit WireGuard peer status', description: 'Read interface public-key/listen-port and peer endpoint, allowed-address and handshake fields; does not test routed LAN traffic or firewall reachability.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const interfaces = await printSafeResource(client, RESOURCE_BY_KEY.get('interface_wireguard'));
  const peers = await printSafeResource(client, RESOURCE_BY_KEY.get('wireguard_peers'));
  const findings = [];
  for (const peer of peers) {
    if (peer.disabled === 'true' || peer.disabled === 'yes') continue;
    if (!peer['endpoint-address']) findings.push({ severity: 'review', peerId: peer['.id'], interface: peer.interface, evidence: 'Peer has no endpoint address; this may be intentional for a responder-only peer.' });
    if (!peer['allowed-address']) findings.push({ severity: 'review', peerId: peer['.id'], interface: peer.interface, evidence: 'Peer has no allowed-address entry.' });
    const handshake = String(peer['last-handshake'] ?? '').toLowerCase();
    if (!handshake || handshake === 'never' || handshake === '0s') findings.push({ severity: 'review', peerId: peer['.id'], interface: peer.interface, evidence: 'No recent successful handshake is reported.' });
  }
  return { device: router.id, interfaces, peerCount: peers.length, enabledPeerCount: peers.filter((peer) => peer.disabled !== 'true' && peer.disabled !== 'yes').length, findings, peers, limitations: ['Handshake age is reported by RouterOS and may not prove traffic is routed correctly.', 'This audit does not inspect endpoint reachability, IP routes, peer allowed-address overlap, or firewall/NAT policy.'] };
})));

server.registerTool('verify_wireguard_topology', {
  title: 'Verify declared WireGuard peer topology',
  description: 'Read configured public keys and peers on the selected router devices and compare them with caller-declared undirected links. This checks configuration evidence only; it does not prove forwarding, firewall reachability, or end-to-end connectivity. Private and preshared keys are never returned.',
  inputSchema: {
    links: z.array(z.object({
      deviceA: z.string().min(1).max(48), interfaceA: z.string().min(1).max(64).refine((value) => !/[\u0000\r\n]/.test(value)),
      deviceB: z.string().min(1).max(48), interfaceB: z.string().min(1).max(64).refine((value) => !/[\u0000\r\n]/.test(value)),
    }).strict()).min(1).max(32),
  },
}, async ({ links }) => safely(async () => {
  const deviceIds = [...new Set(links.flatMap((link) => [link.deviceA, link.deviceB]))];
  const routers = [];
  for (const id of deviceIds) {
    const router = resolveRouter(id);
    const data = await withRouter(id, async (client) => {
      const [interfacesSection, peersSection] = await Promise.all([
        optionalResourceSection(client, 'interface_wireguard'),
        optionalResourceSection(client, 'wireguard_peers'),
      ]);
      return {
        id: router.id,
        interfaces: interfacesSection.records ?? [],
        peers: peersSection.records ?? [],
        interfacesStatus: interfacesSection.status,
        peersStatus: peersSection.status,
        peersTruncated: peersSection.truncated ?? false,
      };
    });
    routers.push(data);
  }
  return verifyWireGuardTopology({ routers, links });
}));

server.registerTool('router_aaa_overview', {
  title: 'Summarize RADIUS and User Manager state',
  description: 'Create an on-demand, read-only overview of configured RADIUS clients, User Manager users, profiles, NAS routers, active sessions and limitations. Unsupported or permission-denied sections remain unknown; secrets and account attributes are not returned. This is not billing-grade accounting.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const router = resolveRouter(device);
  const sections = await withRouter(router.id, async (client) => {
    const read = async (sectionName, resourceKey, properties) => {
      const resource = RESOURCE_BY_KEY.get(resourceKey);
      if (!resource) throw new Error(`Missing fixed AAA resource ${resourceKey}.`);
      const safeProperties = sanitizeResourceProperties(resource, properties);
      try {
        return { status: 'available', records: await client.print(resource.path, safeProperties) };
      } catch (error) {
        if (error instanceof RouterOsApiError && error.message.startsWith('RouterOS rejected the command:')) {
          return { status: 'unavailable-or-not-permitted', note: 'RouterOS rejected this menu read; the package may be absent or the account may lack permission.' };
        }
        throw error;
      }
    };
    return {
      radiusClients: await read('radiusClients', 'radius_servers', ['.id', 'service', 'address', 'authentication-port', 'accounting-port', 'disabled']),
      userManagerUsers: await read('userManagerUsers', 'radius_user_manager_users', ['.id', 'name', 'disabled']),
      profiles: await read('profiles', 'radius_user_manager_profiles', ['.id', 'name', 'validity', 'starts-when']),
      routers: await read('routers', 'radius_user_manager_routers', ['.id', 'name', 'address', 'disabled']),
      sessions: await read('sessions', 'user_manager_sessions', ['.id', 'user', 'nas-port-id', 'started', 'uptime', 'bytes-in', 'bytes-out', 'status']),
      limitations: await read('limitations', 'user_manager_limitations', ['.id', 'name', 'download-limit', 'upload-limit', 'transfer-limit', 'uptime-limit']),
    };
  });
  return buildAaaOverview({ device: router.id, sampledAt: new Date().toISOString(), sections });
}));

server.registerTool('router_alert_metric_catalog', {
  title: 'Router alert metric catalog', description: 'List metrics available for manual, on-demand threshold rules; this does not start a background monitor.',
  inputSchema: {},
}, async () => safely(async () => ({ metrics: metricCatalog(), note: 'Rules are evaluated only when evaluate_router_alert_rules is called; no notification channel or scheduler is configured.' })));

server.registerTool('create_router_alert_rule', {
  title: 'Create a local router alert rule', description: 'Store a private local threshold rule for CPU, memory or active IPv4 default-route count. It does not change RouterOS configuration or start background monitoring.',
  inputSchema: { device: deviceArg(), metric: z.enum(['cpuUsedPercent', 'memoryUsedPercent', 'activeDefaultRouteCount']), operator: z.enum(['gt', 'gte', 'lt', 'lte']), threshold: z.number().finite(), label: z.string().min(1).max(80) },
}, async ({ device, ...rule }) => safely(async () => {
  const router = resolveRouter(device);
  return { rule: await createAlertRule({ ...rule, device: router.id }), note: 'Local rule saved; use evaluate_router_alert_rules to check it manually.' };
}));

server.registerTool('list_router_alert_rules', {
  title: 'List local router alert rules', description: 'Read local threshold rules without contacting routers.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const router = device ? resolveRouter(device) : null;
  return { rules: await listAlertRules(router?.id), storage: 'private local alert store' };
}));

server.registerTool('delete_router_alert_rule', {
  title: 'Delete a local router alert rule', description: 'Delete one local rule after exact UUID confirmation; this does not contact or change the router.',
  inputSchema: { ruleId: z.string().uuid(), confirmation: z.string().min(1).max(120) },
}, async ({ ruleId, confirmation }) => safely(async () => {
  assertExactConfirmation(confirmation, `DELETE ALERT RULE ${ruleId}`);
  return deleteAlertRule(ruleId);
}));

server.registerTool('evaluate_router_alert_rules', {
  title: 'Evaluate local router alert rules', description: 'Read the selected router and manually evaluate its stored CPU, memory and active IPv4 default-route thresholds. Records only state transitions; state transitions may be sent to a configured HTTPS webhook only when MIKROTIK_ALERT_WEBHOOK_ENABLED=true.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => {
  const router = resolveRouter(device);
  const rules = (await listAlertRules(router.id)).filter((rule) => rule.enabled);
  if (!rules.length) return { device: router.id, evaluations: [], events: [], note: 'No enabled local alert rules exist for this router.' };
  const values = await collectAlertValues(router.id, rules);
  return { device: router.id, ...await recordAlertAndNotify({ id: router.id }, values), note: 'Events are written to local history on state changes. If enabled, only minimal state-transition fields are POSTed to the configured HTTPS webhook. Polling runs only while this MCP process is available.' };
}));

server.registerTool('list_router_alert_history', {
  title: 'List local router alert history', description: 'Read up to 200 local trigger/recovery events; history is private to this runtime and is not sent to a notification provider.',
  inputSchema: { device: deviceArg(), limit: z.number().int().min(1).max(200).optional() },
}, async ({ device, limit = 100 }) => safely(async () => {
  const router = device ? resolveRouter(device) : null;
  return listAlertHistory({ device: router?.id, limit });
}));

server.registerTool('start_router_alert_service', {
  title: 'Start router alert polling',
  description: 'Start a single-flight polling loop in this MCP process. Requires MIKROTIK_ALERT_SERVICE_ENABLED=true and an interval of 60–86400 seconds. Optional restart recovery requires MIKROTIK_ALERT_SERVICE_AUTOSTART=true. The loop stops while this MCP process is unavailable; optional HTTPS webhook notifications are controlled separately.',
  inputSchema: { intervalSeconds: z.number().int().min(60).max(86400).optional() },
}, async ({ intervalSeconds }) => safely(async () => {
  if (!readBoolean('MIKROTIK_ALERT_SERVICE_ENABLED', false)) throw new Error('Alert polling is disabled. Set MIKROTIK_ALERT_SERVICE_ENABLED=true in the host environment.');
  const seconds = intervalSeconds ?? integer(process.env.MIKROTIK_ALERT_POLL_INTERVAL_SECONDS, 'MIKROTIK_ALERT_POLL_INTERVAL_SECONDS', 300, 86400);
  if (seconds < 60 || seconds > 86400) throw new Error('Alert polling interval must be an integer from 60 to 86400 seconds.');
  return { service: await alertWorker.start(seconds * 1000), note: 'Polling runs only while this MCP process is available. Optional startup recovery is controlled by MIKROTIK_ALERT_SERVICE_AUTOSTART; external scheduling is not provided.' };
}));

server.registerTool('stop_router_alert_service', {
  title: 'Stop router alert polling',
  description: 'Stop the in-process polling timer and wait for any active poll to finish. This does not delete rules or history.',
  inputSchema: {},
}, async () => safely(async () => ({ service: await alertWorker.stop() })));

server.registerTool('router_alert_service_status', {
  title: 'Read router alert polling status',
  description: 'Report alert worker configuration, optional restart autostart and current in-process status; this does not contact routers.',
  inputSchema: {},
}, async () => safely(async () => ({ configured: readBoolean('MIKROTIK_ALERT_SERVICE_ENABLED', false), autostartConfigured: readBoolean('MIKROTIK_ALERT_SERVICE_AUTOSTART', false), autostartError: alertAutostartError, processBound: true, notifications: { enabled: isAlertWebhookEnabled(), endpointConfigured: Boolean(process.env.MIKROTIK_ALERT_WEBHOOK_URL), endpointExposed: false }, service: alertWorker.status() })));

function stageBuilderPlan(routerId, steps, preconditions = []) {
  const prepared = steps.map((step) => {
    const resource = RESOURCE_BY_KEY.get(step.resource);
    if (!resource) throw new Error(`Unknown planner resource ${step.resource}.`);
    validateChangeInput(resource, step.action, step.fields ?? {}, step.targetId);
    return { resourceKey: step.resource, action: step.action, device: step.device ?? routerId, fields: step.fields ?? {}, targetId: step.targetId };
  });
  return stageTransaction(prepared, preconditions);
}

server.registerTool('preview_port_forward', {
  title: 'Preview a port-forward plan',
  description: 'Build a dry-run-only DST-NAT plus forward-accept plan, optionally including LAN hairpin NAT. It does not apply configuration; use the returned exact transaction confirmation only after reviewing every rule.',
  inputSchema: {
    device: deviceArg(), protocol: z.enum(['tcp', 'udp']), externalPort: z.number().int().min(1).max(65535),
    internalHost: z.string().min(1).max(64), internalPort: z.number().int().min(1).max(65535).optional(),
    wanInterface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/).optional(),
    lanSubnet: z.string().min(1).max(32).optional(), lanInterface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/).optional(),
    comment: z.string().max(80).optional(),
  },
}, async ({ device, ...input }) => safely(async () => {
  const router = resolveRouter(device);
  const built = buildPortForwardPlan(input);
  return { ...stageBuilderPlan(router.id, built.steps), planner: 'port-forward', notes: built.notes };
}));

server.registerTool('preview_vlan_segment', {
  title: 'Preview partial VLAN segment scaffolding',
  description: 'Create an exact-confirmation transaction preview for VLAN interface/membership, IPv4 gateway and optional disabled DHCP/NAT scaffolding. This is not complete network isolation and performs no writes until a separate reviewed apply.',
  inputSchema: {
    device: deviceArg(), vlanId: z.number().int().min(1).max(4094), name: z.string().min(1).max(64), subnet: z.string().min(9).max(18),
    gateway: z.string().min(7).max(15), bridge: z.string().min(1).max(64),
    taggedPorts: z.array(z.string().min(1).max(64)).max(64).optional(), untaggedPorts: z.array(z.string().min(1).max(64)).max(64).optional(),
    dhcp: z.boolean().optional(), dhcpRange: z.string().min(15).max(35).optional(), internet: z.boolean().optional(),
    wanInterface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/).optional(), comment: z.string().max(80).optional(),
  },
}, async ({ device, ...input }) => safely(async () => {
  const router = resolveRouter(device);
  const built = buildVlanSegmentPlan(input);
  return { ...stageBuilderPlan(router.id, built.steps), planner: 'vlan-segment', notes: built.notes };
}));

server.registerTool('preview_ipv6_vlan_segment', {
  title: 'Preview a partial IPv6 VLAN segment',
  description: 'Read existing VLAN interfaces and IPv6 addresses, reject detected ID/name/prefix conflicts, then stage only a VLAN interface, bridge membership and non-advertised IPv6 address. This is a partial dry-run plan, not DHCPv6, router advertisement or IPv6 firewall isolation; no changes occur until a separate reviewed apply. State must be rechecked before applying.',
  inputSchema: {
    device: deviceArg(), vlanId: z.number().int().min(1).max(4094), name: z.string().min(1).max(64),
    subnet: z.string().min(3).max(64), gateway: z.string().min(2).max(64), bridge: z.string().min(1).max(64),
    taggedPorts: z.array(z.string().min(1).max(64)).max(64).optional(),
    untaggedPorts: z.array(z.string().min(1).max(64)).max(64).optional(), comment: z.string().max(80).optional(),
  },
}, async ({ device, ...input }) => safely(async () => {
  const router = resolveRouter(device);
  const state = await withRouter(router.id, async (client) => {
    const [vlans, ipv6Addresses] = await Promise.all([
      client.print('/interface/vlan', ['name', 'vlan-id']),
      client.print('/ipv6/address', ['address']),
    ]);
    return { vlans, ipv6Addresses };
  });
  if (state.vlans.length > 128 || state.ipv6Addresses.length > 128) {
    throw new Error('The existing VLAN or IPv6 address inventory exceeds the 128-record conflict-check limit; no plan was staged.');
  }
  const existingNames = [...new Set(state.vlans.map((row) => {
    if (typeof row.name !== 'string' || row.name.length === 0) throw new Error('An existing VLAN interface returned no valid name; no plan was staged.');
    return row.name;
  }))];
  const existingVlanIds = [...new Set(state.vlans.flatMap((row) => {
    if (row['vlan-id'] === undefined || row['vlan-id'] === '') return [];
    const id = Number(row['vlan-id']);
    if (!Number.isInteger(id) || id < 1 || id > 4094) throw new Error('An existing VLAN interface returned a malformed VLAN ID; no plan was staged.');
    return [id];
  }))];
  const existingSubnets = [...new Set(state.ipv6Addresses.flatMap((row) => {
    const value = row.address;
    if (typeof value !== 'string' || value.length === 0) throw new Error('An IPv6 address record returned no usable prefix; no plan was staged.');
    const address = value.split('/')[0];
    if (address.includes('%') && address.toLowerCase().startsWith('fe80:')) return [];
    return [value];
  }))];
  const built = buildIpv6VlanSegmentPlan({ ...input, existingNames, existingVlanIds, existingSubnets });
  return {
    ...stageBuilderPlan(router.id, built.steps),
    planner: 'ipv6-vlan-segment',
    checked: { existingVlanInterfaces: state.vlans.length, existingIpv6Addresses: state.ipv6Addresses.length },
    notes: [...built.notes, 'Existing interface-scoped fe80:: link-local addresses are not compared as global prefixes. Re-run this preview if router state changes before apply.'],
  };
}));

server.registerTool('preview_wireguard_mesh', {
  title: 'Preview a multi-router WireGuard mesh',
  description: 'Read public keys from existing WireGuard interfaces and stage tunnel-address plus full-mesh/hub-spoke peer entries. No router state changes occur until the separate exact-confirmation transaction apply; explicit routes and firewall policy are not included.',
  inputSchema: {
    devices: z.array(z.string().min(1).max(48)).min(2).max(6), addressPrefix: z.string().min(9).max(18),
    interfaceName: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/).optional(), topology: z.enum(['full-mesh', 'hub-spoke']).optional(), hub: z.string().min(1).max(48).optional(),
    endpoints: z.record(z.string().min(1).max(48), z.string().min(1).max(253)),
    endpointPorts: z.record(z.string().min(1).max(48), z.number().int().min(1).max(65535)).optional(),
    allowedLans: z.record(z.string().min(1).max(48), z.string().min(1).max(32)).optional(),
    persistentKeepalive: z.string().max(8).optional(), comment: z.string().max(80).optional(),
  },
}, async ({ devices, addressPrefix, interfaceName = 'wg-mesh', topology = 'full-mesh', hub, endpoints, endpointPorts = {}, allowedLans = {}, persistentKeepalive = '25s', comment }) => safely(async () => {
  const stateByDevice = new Map();
  const meshDevices = [];
  for (const id of devices) {
    resolveRouter(id);
    const endpointAddress = endpoints[id];
    if (!endpointAddress) throw new Error(`A public endpoint address is required for router ${id}; endpoints are not inferred from private management hosts.`);
    const state = await withRouter(id, async (client, router) => {
      const interfaces = await client.print('/interface/wireguard', ['.id', 'name', 'public-key', 'listen-port'], [`?=name=${interfaceName}`]);
      if (interfaces.length !== 1) throw new Error(`Router ${router.id} must have exactly one existing WireGuard interface named ${interfaceName}.`);
      const addresses = await client.print('/ip/address', ['.id', 'address', 'interface']);
      const peers = await client.print('/interface/wireguard/peers', ['.id', 'interface', 'public-key']);
      return { interface: interfaces[0], addresses, peers };
    });
    stateByDevice.set(id, state);
    meshDevices.push({
      id, publicKey: state.interface['public-key'], endpointAddress,
      endpointPort: endpointPorts[id] ?? (Number(state.interface['listen-port']) || 13231),
      allowedLan: allowedLans[id],
    });
  }
  const built = buildWireguardMeshPlan({ devices: meshDevices, addressPrefix, interfaceName, topology, hub, persistentKeepalive, comment });
  for (const step of built.steps) {
    const state = stateByDevice.get(step.device);
    if (step.resource === 'ip_addresses') {
      const host = step.fields.address.split('/')[0];
      if (state.addresses.some((row) => row.address?.split('/')[0] === host)) throw new Error(`Address ${host} is already configured on router ${step.device}; no mesh plan was staged.`);
    } else if (state.peers.some((row) => row.interface === interfaceName && row['public-key'] === step.fields['public-key'])) {
      throw new Error(`A peer with the public key for ${step.fields.comment} already exists on router ${step.device}; no mesh plan was staged.`);
    }
  }
  const preconditions = devices.map((id) => {
    const baseline = stateByDevice.get(id)?.interface;
    if (!baseline || !/^\*\d+$/.test(baseline['.id'] ?? '')) throw new Error(`WireGuard interface on router ${id} did not return a valid RouterOS item ID; no plan was staged.`);
    return { resourceKey: 'interface_wireguard', device: id, targetId: baseline['.id'], baseline };
  });
  return { ...stageBuilderPlan(devices[0], built.steps, preconditions), planner: 'wireguard-mesh', topology: built.topology, assignments: built.assignments, notes: built.notes };
}));

server.registerTool('wake_on_lan', {
  title: 'Send a Wake-on-LAN packet', description: 'Fire-and-forget WOL packet. Requires both write gates, MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true and exact device/MAC confirmation; the target wake-up is not verified.',
  inputSchema: { device: deviceArg(), mac: z.string().regex(/^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/), interface: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.:@-]+$/).optional(), confirmation: z.string().min(1).max(120) },
}, async ({ device, mac, interface: interfaceName, confirmation }) => safely(async () => {
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  const normalizedMac = mac.toUpperCase();
  assertExactConfirmation(confirmation, `WAKE ${router.id} ${normalizedMac}`);
  const attributes = { mac: normalizedMac, ...(interfaceName ? { interface: interfaceName } : {}) };
  const result = await withRouter(router.id, (client) => client.command('/tool/wol', attributes));
  return { device: router.id, mac: normalizedMac, interface: interfaceName ?? null, dispatched: true, results: result.slice(0, 5), note: 'Packet dispatched; the device waking up was not verified.' };
}));

server.registerTool('run_flood_ping', {
  title: 'Run a bounded flood ping', description: 'Send at most 100 ICMP echo probes. Requires both write gates, MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=true and exact target-specific confirmation.',
  inputSchema: { device: deviceArg(), target: z.string().min(1).max(253), count: z.number().int().min(1).max(100).optional(), size: z.number().int().min(16).max(512).optional(), confirmation: z.string().min(1).max(160) },
}, async ({ device, target, count = 10, size = 56, confirmation }) => safely(async () => {
  if (!validTarget(target)) throw new Error('Target must be an IP address or DNS hostname; command syntax is not accepted.');
  assertWriteSafety(process.env, { activeDiagnostics: true });
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `RUN FLOOD PING ${router.id} ${target}`);
  const results = await withRouter(router.id, (client) => client.command('/tool/flood-ping', { address: target, count: String(count), size: String(size) }));
  return { device: router.id, target, count, size, results: results.slice(0, 20), note: 'Flood ping sends traffic and may be rate-limited by the destination or network.' };
}));

const writableKeys = RESOURCE_CATALOG.filter((r) => r.writeFields.length > 0).map((r) => r.key);
const transactionStepSchema = z.object({
  device: z.string().min(1).max(48).optional(),
  resource: z.enum(writableKeys),
  action: z.enum(['add', 'set', 'remove']),
  targetId: z.string().regex(/^\*\d+$/).optional(),
  fields: stringMapSchema.optional(),
});

server.registerTool('plan_router_transaction', {
  title: 'Preview a multi-router transaction',
  description: 'Stage up to 10 allowlisted operations across configured routers. It pre-reads all item targets, but application is sequential and may leave a partial state; this is not an atomic transaction.',
  inputSchema: { steps: z.array(transactionStepSchema).min(1).max(10) },
}, async ({ steps }) => safely(async () => {
  const prepared = [];
  const targetSet = new Set();
  for (const step of steps) {
    const resource = RESOURCE_BY_KEY.get(step.resource);
    const fields = step.fields ?? {};
    validateChangeInput(resource, step.action, fields, step.targetId);
    const router = resolveRouter(step.device);
    const targetKey = step.targetId ? `${router.id}:${resource.key}:${step.targetId}` : null;
    if (targetKey && targetSet.has(targetKey)) throw new Error(`Transaction repeats target ${targetKey}; split it into a separate reviewed transaction.`);
    if (targetKey) targetSet.add(targetKey);
    let baseline;
    if (step.targetId) baseline = await withRouter(router.id, async (client) => {
      const rows = await printSafeResource(client, resource, [`?=.id=${step.targetId}`]);
      if (rows.length !== 1) throw new Error(`Could not uniquely read ${step.targetId} from ${resource.key}; transaction plan was not created.`);
      return rows[0];
    });
    prepared.push({ resourceKey: step.resource, action: step.action, device: router.id, fields, targetId: step.targetId, baseline });
  }
  return stageTransaction(prepared);
}));

server.registerTool('apply_router_transaction', {
  title: 'Apply a reviewed multi-router transaction',
  description: 'Apply staged operations in order after preflighting all targets. Requires MIKROTIK_ALLOW_WRITES=true and MIKROTIK_ALLOW_HIGH_RISK_WRITES=true. Stops on failure and reports partial or unknown state; no automatic rollback is promised.',
  inputSchema: { planId: z.string().uuid(), confirmation: z.string().min(1).max(80) },
}, async ({ planId, confirmation }) => safely(async () => {
  if (!readBoolean('MIKROTIK_ALLOW_WRITES', false)) throw new Error('Write operations are disabled. Set MIKROTIK_ALLOW_WRITES=true only after reviewing the risk.');
  if (!readBoolean('MIKROTIK_ALLOW_HIGH_RISK_WRITES', false)) throw new Error('High-risk writes are disabled. Set MIKROTIK_ALLOW_HIGH_RISK_WRITES=true only after establishing a recovery path.');
  const plan = takePlan(planId, confirmation, 'transaction');
  const preflight = [];
  for (const guard of plan.preconditions ?? []) {
    const resource = RESOURCE_BY_KEY.get(guard.resourceKey);
    if (!resource) throw new Error(`Preflight stopped before writes: unknown precondition resource ${guard.resourceKey}.`);
    const current = await withRouter(guard.device, async (client) => printSafeResource(client, resource, [`?=.id=${guard.targetId}`]));
    if (current.length !== 1 || !stableSnapshotMatches(guard.baseline, current[0])) throw new Error(`Preflight stopped before writes: ${guard.device}/${guard.resourceKey}/${guard.targetId} changed since preview.`);
    preflight.push({ device: guard.device, resource: guard.resourceKey, targetId: guard.targetId, verified: true, kind: 'precondition' });
  }
  for (const step of plan.steps) {
    const resource = RESOURCE_BY_KEY.get(step.resourceKey);
    if (!step.targetId) continue;
    const current = await withRouter(step.device, async (client) => printSafeResource(client, resource, [`?=.id=${step.targetId}`]));
    if (current.length !== 1) throw new Error(`Preflight stopped before writes: ${step.device}/${step.resourceKey}/${step.targetId} is no longer unique.`);
    if (step.baseline && !stableSnapshotMatches(step.baseline, current[0])) throw new Error(`Preflight stopped before writes: ${step.device}/${step.resourceKey}/${step.targetId} changed since preview.`);
    preflight.push({ device: step.device, resource: step.resourceKey, targetId: step.targetId, verified: true });
  }
  const results = [];
  for (const [index, step] of plan.steps.entries()) {
    const resource = RESOURCE_BY_KEY.get(step.resourceKey);
    try {
      const result = await withRouter(step.device, async (client) => {
        if (step.targetId) {
          const current = await printSafeResource(client, resource, [`?=.id=${step.targetId}`]);
          if (current.length !== 1 || (step.baseline && !stableSnapshotMatches(step.baseline, current[0]))) throw new Error('Target changed after preflight; stopped before this operation.');
        }
        const attrs = step.action === 'add' ? step.fields : step.action === 'set' ? { '.id': step.targetId, ...step.fields } : { '.id': step.targetId };
        const commandRows = await client.command(`${resource.path}/${step.action}`, attrs);
        let verification = null;
        if (step.targetId) {
          const after = await printSafeResource(client, resource, [`?=.id=${step.targetId}`]);
          verification = step.action === 'set' ? (after[0] ?? null) : { removed: after.length === 0 };
        }
        return { commandAccepted: true, commandRows: redactSensitiveRecords(commandRows.slice(0, 5)), verification };
      });
      results.push({ index: index + 1, device: step.device, resource: step.resourceKey, action: step.action, targetId: step.targetId ?? null, status: 'completed', ...result });
    } catch (error) {
      results.push({ index: index + 1, device: step.device, resource: step.resourceKey, action: step.action, targetId: step.targetId ?? null, status: 'failed-or-unknown', error: error instanceof Error ? error.message : 'Unknown RouterOS operation error' });
      break;
    }
  }
  const completed = results.filter((item) => item.status === 'completed').length;
  const status = completed === plan.steps.length ? 'completed' : completed === 0 ? 'stopped-before-any-confirmed-write' : 'partial';
  console.error(JSON.stringify({ event: 'router_transaction_finished', planId: plan.id, status, completed, total: plan.steps.length }));
  return { transactionId: plan.id, status, preflight, results, completed, total: plan.steps.length, note: 'Operations are sequential and non-atomic. A lost response can make the last step ambiguous; inspect live state before retrying or attempting recovery.' };
}));

server.registerTool('plan_router_change', {
  title: 'Preview a router change',
  description: 'Create a 10-minute, single-use plan for an allowlisted add/set/remove. This only previews; high-risk writes require both write-enable switches and exact plan confirmation.',
  inputSchema: {
    device: deviceArg(), resource: z.enum(writableKeys), action: z.enum(['add', 'set', 'remove']),
    targetId: z.string().regex(/^\*\d+$/).optional(), fields: stringMapSchema.optional(),
  },
}, async ({ device, resource: key, action, targetId, fields = {} }) => safely(async () => {
  const resource = RESOURCE_BY_KEY.get(key);
  validateChangeInput(resource, action, fields, targetId);
  const router = resolveRouter(device);
  let baseline;
  if (targetId) baseline = await withRouter(router.id, async (client) => {
    const rows = await printSafeResource(client, resource, [`?=.id=${targetId}`]);
    if (rows.length !== 1) throw new Error(`Could not uniquely read ${targetId} from ${resource.key}; no plan was created.`);
    return rows[0];
  });
  return stagePlan({ resourceKey: key, action, device: router.id, fields, targetId, baseline });
}));
function stableSnapshotMatches(before, now) {
  const volatile = /^(?:bytes|packets|tx|rx|uptime|last-activity|last-seen|expires-after|run-count|last-started|time|date|status|running|actual-mtu|current-|invalid|dynamic|active|immediate-gw)/i;
  return Object.entries(before).every(([key, value]) => volatile.test(key) || now[key] === value);
}
server.registerTool('apply_router_change_plan', {
  title: 'Apply a reviewed router change plan',
  description: 'Apply one previously previewed change. Requires MIKROTIK_ALLOW_WRITES=true; high-risk resources also require MIKROTIK_ALLOW_HIGH_RISK_WRITES=true. Exact confirmation must match the plan. Not an atomic transaction.',
  inputSchema: { planId: z.string().uuid(), confirmation: z.string().min(1).max(80) },
}, async ({ planId, confirmation }) => safely(async () => {
  if (!readBoolean('MIKROTIK_ALLOW_WRITES', false)) throw new Error('Write operations are disabled. Set MIKROTIK_ALLOW_WRITES=true only after reviewing the risk.');
  if (!readBoolean('MIKROTIK_ALLOW_HIGH_RISK_WRITES', false)) throw new Error('High-risk writes are disabled. Set MIKROTIK_ALLOW_HIGH_RISK_WRITES=true only after establishing a recovery path.');
  const plan = takePlan(planId, confirmation);
  const resource = RESOURCE_BY_KEY.get(plan.resourceKey);
  if (resource.risk === 'high' && !readBoolean('MIKROTIK_ALLOW_HIGH_RISK_WRITES', false)) throw new Error('High-risk writes are disabled.');
  const outcome = await withRouter(plan.device, async (client) => {
    if (plan.targetId) {
      const current = await printSafeResource(client, resource, [`?=.id=${plan.targetId}`]);
      if (current.length !== 1) throw new Error(`Target ${plan.targetId} no longer exists or is not unique.`);
      if (plan.baseline && !stableSnapshotMatches(plan.baseline, current[0])) throw new Error('The target changed since preview. Create and review a fresh plan.');
    }
    const attributes = plan.action === 'add' ? plan.fields : plan.action === 'set' ? { '.id': plan.targetId, ...plan.fields } : { '.id': plan.targetId };
    const commandRows = await client.command(`${resource.path}/${plan.action}`, attributes);
    let verification;
    if (plan.action === 'set' || plan.action === 'remove') {
      const after = await printSafeResource(client, resource, [`?=.id=${plan.targetId}`]);
      verification = plan.action === 'set' ? (after[0] ?? null) : { removed: after.length === 0 };
    }
    return { commandAccepted: true, commandRows: redactSensitiveRecords(commandRows.slice(0, 5)), verification };
  });
  console.error(JSON.stringify({ event: 'router_change_applied', planId: plan.id, device: plan.device, resource: plan.resourceKey, action: plan.action, targetId: plan.targetId ?? null, fields: redactFields(plan.fields) }));
  return { ...outcome, device: plan.device, resource: plan.resourceKey, action: plan.action, targetId: plan.targetId ?? null, completed: true, note: 'One RouterOS API operation; no atomic or rollback-guaranteed transaction was used.' };
}));
server.registerTool('cancel_router_change_plan', {
  title: 'Cancel a router change plan', description: 'Discard an unused staged change without contacting the router.',
  inputSchema: { planId: z.string().uuid() },
}, async ({ planId }) => jsonResult({ cancelled: cancelPlan(planId) }));

server.registerTool('audit_dhcp_integrity', {
  title: 'Audit DHCP pool and lease integrity',
  description: 'Read fixed DHCP server, network, pool and lease resources; report only issue codes, counts, section/index metadata and coverage. IPv4 analysis is conservative, dynamic pool formats remain unknown, and normal pool containment within a network is not treated as an error.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const keys = ['dhcp_servers', 'dhcp_networks', 'ip_pools_dhcp', 'dhcp_leases'];
  const values = await Promise.all(keys.map(async (key) => [key, boundedAuditSection(await optionalResourceSection(client, key), 2000)]));
  return { device: router.id, ...buildDhcpIntegrityAudit({ sections: Object.fromEntries(values) }) };
})));

server.registerTool('audit_dns_resolver', {
  title: 'Audit DNS resolver configuration',
  description: 'Read DNS resolver settings and static records from fixed paths. Findings contain only codes, counts and record indices; allow-remote-requests is a review signal and does not prove external exposure, while absent firewall/interface evidence remains unknown.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const [settings, staticRecords] = await Promise.all([
    readDnsSettingsAuditSection(client),
    optionalResourceSection(client, 'dns_static').then((section) => boundedAuditSection(section, 5000)),
  ]);
  const analysis = buildDnsResolverAudit({ sections: { ip_dns_settings: settings, dns_static: staticRecords } });
  return { device: router.id, coverage: { dnsSettings: settings.status, staticRecords: staticRecords.status }, ...analysis };
})));

server.registerTool('audit_wireless_security_profiles', {
  title: 'Audit wireless security profiles',
  description: 'Read legacy wireless, legacy CAPsMAN and new WiFi security profiles from fixed paths. Output contains coded findings, indexes, counts and a secret-presence boolean only; profile names, SSIDs, keys and raw profile fields are never returned. Missing or unknown settings remain indeterminate.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const secretProperties = ['wpa-pre-shared-key', 'wpa2-pre-shared-key', 'passphrase'];
  const sections = Object.fromEntries(await Promise.all([
    ['wireless_security_profiles', '/interface/wireless/security-profiles', ['mode', 'authentication-types', 'unicast-ciphers', 'group-ciphers', 'management-protection', ...secretProperties]],
    ['legacy_capsman_security', '/caps-man/security', ['authentication-types', 'encryption', 'management-protection', ...secretProperties]],
    ['wifi_security', '/interface/wifi/security', ['authentication-types', 'encryption', 'management-protection', 'passphrase']],
  ].map(async ([key, apiPath, properties]) => [key, await readWirelessSecurityAuditSection(client, apiPath, properties, secretProperties)])));
  return { device: router.id, ...buildWirelessSecurityAudit({ sections }) };
})));

server.registerTool('audit_scheduler_safety', {
  title: 'Audit RouterOS scheduler and script risks',
  description: 'Statically inspect fixed scheduler event and script source fields for a short advisory list of risky command indicators. Nothing is executed; command bodies, names, addresses and secrets are not returned. Patterns can miss indirect behavior or produce false positives.',
  inputSchema: { device: deviceArg() },
}, async ({ device }) => safely(async () => withRouter(device, async (client, router) => {
  const [scheduler, scripts] = await Promise.all([
    readFixedAuditSection(client, '/system/scheduler', ['interval', 'start-time', 'on-event', 'disabled']),
    readFixedAuditSection(client, '/system/script', ['source']),
  ]);
  return { device: router.id, ...buildSchedulerSafetyAudit({ sections: { scheduler, scripts } }) };
})));

server.registerTool('set_interface_state', {
  title: 'Enable or disable an interface (legacy direct action)',
  description: 'Compatibility tool for one interface state change. Requires both write gates and exact confirmation SET INTERFACE <routerId> <itemId> ENABLE|DISABLE. Prefer plan_router_change for preview.',
  inputSchema: { device: deviceArg(), id: z.string().regex(/^\*\d+$/), enabled: z.boolean(), confirmation: z.string().min(1).max(120) },
}, async ({ device, id, enabled, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `SET INTERFACE ${router.id} ${id} ${enabled ? 'ENABLE' : 'DISABLE'}`);
  await withRouter(router.id, (client) => client.command(enabled ? '/interface/enable' : '/interface/disable', { '.id': id }));
  const rows = await withRouter(router.id, (client) => client.print('/interface', ['.id', 'name', 'running', 'disabled'], [`?=.id=${id}`]));
  console.error(JSON.stringify({ event: 'interface_state_changed', device: router.id, id, enabled }));
  return { device: router.id, requestedId: id, enabled, verified: rows.length === 1 ? rows[0] : null };
}));
server.registerTool('disconnect_client_session', {
  title: 'Disconnect a hotspot or PPP session',
  description: 'Terminate one active Hotspot or PPP session by RouterOS ID. Requires both write gates and exact confirmation DISCONNECT <routerId> <kind> <itemId>.',
  inputSchema: { device: deviceArg(), kind: z.enum(['hotspot', 'ppp']), id: z.string().regex(/^\*\d+$/), confirmation: z.string().min(1).max(160) },
}, async ({ device, kind, id, confirmation }) => safely(async () => {
  assertWriteSafety(process.env);
  const router = resolveRouter(device);
  assertExactConfirmation(confirmation, `DISCONNECT ${router.id} ${kind} ${id}`);
  const path = kind === 'hotspot' ? '/ip/hotspot/active' : '/ppp/active';
  const props = kind === 'hotspot' ? ['.id', 'user', 'address', 'mac-address', 'uptime'] : ['.id', 'name', 'service', 'caller-id', 'address', 'uptime'];
  const before = await withRouter(router.id, async (client) => {
    const rows = await client.print(path, props, [`?=.id=${id}`]);
    if (rows.length !== 1) throw new Error(`Active ${kind} session ${id} was not found.`);
    return rows[0];
  });
  await withRouter(router.id, (client) => client.command(`${path}/remove`, { '.id': id }));
  const remaining = await withRouter(router.id, (client) => client.print(path, ['.id'], [`?=.id=${id}`]));
  console.error(JSON.stringify({ event: 'client_session_disconnected', device: router.id, kind, id }));
  return { device: router.id, kind, session: before, disconnected: remaining.length === 0 };
}));

async function startOptionalDashboard() {
  if (!readBoolean('MIKROTIK_DASHBOARD_ENABLED', false)) return null;
  const { startDashboard } = await import('./dashboard.js');
  const host = process.env.MIKROTIK_DASHBOARD_HOST ?? '127.0.0.1';
  const port = integer(process.env.MIKROTIK_DASHBOARD_PORT, 'MIKROTIK_DASHBOARD_PORT', 9090);
  const set = getRouterSet();
  const dashboard = await startDashboard({
    host, port,
    listDevices: async () => { const current = getRouterSet(); return current.routers.map((r) => publicRouter(r, current.defaultId)); },
    readSummary: readRouterSummary,
  });
  console.error(`Read-only local dashboard listening at ${dashboard.url}; configured devices: ${set.routers.length}`);
  return dashboard;
}

async function startOptionalAlertService() {
  if (!readBoolean('MIKROTIK_ALERT_SERVICE_AUTOSTART', false)) return false;
  if (!readBoolean('MIKROTIK_ALERT_SERVICE_ENABLED', false)) {
    alertAutostartError = 'Autostart requested but alert polling is not enabled.';
    console.error(JSON.stringify({ event: 'alert_worker_autostart_skipped', reason: 'service_disabled' }));
    return false;
  }
  try {
    const seconds = integer(process.env.MIKROTIK_ALERT_POLL_INTERVAL_SECONDS, 'MIKROTIK_ALERT_POLL_INTERVAL_SECONDS', 300, 86400);
    if (seconds < 60) throw new Error('MIKROTIK_ALERT_POLL_INTERVAL_SECONDS must be at least 60 when autostart is enabled.');
    const status = await alertWorker.start(seconds * 1000);
    console.error(JSON.stringify({ event: 'alert_worker_autostart_started', intervalSeconds: seconds, pollCount: status.pollCount }));
    return true;
  } catch (error) {
    alertAutostartError = error instanceof Error ? error.message : 'Alert autostart failed.';
    console.error(JSON.stringify({ event: 'alert_worker_autostart_failed', reason: alertAutostartError }));
    return false;
  }
}

const transport = new StdioServerTransport();
await server.connect(transport);
await startOptionalAlertService();
const dashboard = await startOptionalDashboard();
async function shutdown() {
  await alertWorker.stop().catch(() => {});
  if (tzspCaptureManager) await tzspCaptureManager.shutdown().catch(() => {});
  if (dashboard) await dashboard.close().catch(() => {});
  await server.close?.().catch(() => {});
}
process.once('SIGINT', () => { void shutdown(); });
process.once('SIGTERM', () => { void shutdown(); });
