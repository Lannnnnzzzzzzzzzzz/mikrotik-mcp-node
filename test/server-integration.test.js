import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { decodeSentence, encodeSentence } from '../src/routeros-api.js';

function createMockRouter() {
  const peer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const decoded = decodeSentence(buffer);
        if (!decoded) break;
        buffer = buffer.subarray(decoded.bytesRead);
        const path = decoded.words[0];
        if (path === '/login') {
          socket.write(encodeSentence(['!done']));
        } else if (path === '/system/identity/print') {
          socket.write(encodeSentence(['!re', '=name=Lab-Router']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/system/resource/print') {
          socket.write(encodeSentence(['!re', '=version=7.16', '=uptime=1d', '=cpu=0%']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/route/print') {
          socket.write(encodeSentence(['!re', '=.id=*r1', '=dst-address=0.0.0.0/0', '=gateway=192.0.2.1', '=routing-table=main', '=distance=1', '=active=yes', '=disabled=no']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ipv6/route/print') {
          socket.write(encodeSentence(['!re', '=.id=*v61', '=dst-address=2001:db8:100::/48', '=routing-table=main', '=distance=1', '=active=yes', '=disabled=no', '=gateway=fe80::1%ether1']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/firewall/filter/print') {
          socket.write(encodeSentence(['!re', '=.id=*fw1', '=chain=input', '=action=drop', '=disabled=no', '=dynamic=no', '=invalid=no', '=src-address=192.0.2.0/24', '=comment=firewall-comment-must-not-leak']));
          socket.write(encodeSentence(['!re', '=.id=*fw2', '=chain=input', '=action=accept', '=disabled=no', '=dynamic=no', '=invalid=no', '=src-address=192.0.2.4', '=comment=second-comment-must-not-leak']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ipv6/firewall/filter/print') {
          socket.write(encodeSentence(['!re', '=.id=*v6fw1', '=chain=input', '=action=accept', '=disabled=no', '=dynamic=no', '=invalid=no', '=src-address=2001:db8::/64']));
          socket.write(encodeSentence(['!re', '=.id=*v6fw2', '=chain=input', '=action=drop', '=disabled=no', '=dynamic=no', '=invalid=no', '=src-address=2001:db8::1']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/vlan/print' || path === '/ipv6/address/print') {
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/dhcp-server/print') {
          socket.write(encodeSentence(['!re', '=name=dhcp-private', '=address-pool=test-pool', '=disabled=no']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/dhcp-server/network/print') {
          socket.write(encodeSentence(['!re', '=address=192.0.2.0/24']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/pool/print') {
          socket.write(encodeSentence(['!re', '=name=test-pool', '=ranges=192.0.2.10-192.0.2.20']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/dhcp-server/lease/print') {
          socket.write(encodeSentence(['!re', '=address=192.0.2.51', '=server=dhcp-private', '=dynamic=no', '=host-name=private-dhcp-host', '=mac-address=02:00:00:00:aa:bb']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/dns/print') {
          socket.write(encodeSentence(['!re', '=servers=192.0.2.53', '=allow-remote-requests=yes', '=use-doh-server=https://secret-doh.invalid/query']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/ip/dns/static/print') {
          socket.write(encodeSentence(['!re', '=name=private.example.test', '=address=192.0.2.12', '=disabled=no', '=comment=dns-private-comment']));
          socket.write(encodeSentence(['!re', '=name=PRIVATE.EXAMPLE.TEST.', '=address=192.0.2.13', '=disabled=no']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wireless/security-profiles/print') {
          socket.write(encodeSentence(['!re', '=mode=none', '=authentication-types=none', '=unicast-ciphers=aes-ccm', '=group-ciphers=aes-ccm', '=management-protection=disabled', '=wpa-pre-shared-key=wireless-profile-secret']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/caps-man/security/print') {
          socket.write(encodeSentence(['!re', '=authentication-types=wpa2-psk', '=encryption=aes-ccm', '=management-protection=required', '=passphrase=capsman-profile-secret']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wifi/security/print') {
          socket.write(encodeSentence(['!re', '=authentication-types=wpa3-psk', '=encryption=gcmp', '=management-protection=required', '=passphrase=wifi-profile-secret']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/system/scheduler/print') {
          socket.write(encodeSentence(['!re', '=interval=1d', '=start-time=03:00:00', '=on-event=/system reboot', '=disabled=no']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/system/script/print') {
          socket.write(encodeSentence(['!re', '=source=:log info "scheduler-private-marker"; /tool fetch url=https://private.invalid/token']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/routing/bgp/session/print') {
          socket.write(encodeSentence(['!re', '=.id=*b1', '=name=upstream', '=state=established', '=established=true', '=prefix-count=12']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/routing/ospf/neighbor/print') {
          socket.write(encodeSentence(['!re', '=.id=*o1', '=router-id=192.0.2.2', '=state=Full', '=uptime=1h']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/routing/rip/neighbor/print') {
          socket.write(encodeSentence(['!re', '=.id=*rip1', '=address=192.0.2.3', '=interface=ether1', '=uptime=1h']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/routing/rip/route/print') {
          socket.write(encodeSentence(['!re', '=.id=*rip2', '=dst-address=198.51.100.0/24', '=gateway=192.0.2.3', '=metric=2', '=active=yes']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/routing/bfd/peer/print') {
          socket.write(encodeSentence(['!re', '=.id=*bfd1', '=remote-address=192.0.2.3', '=state=Up', '=uptime=1h']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wireless/registration-table/print') {
          socket.write(encodeSentence(['!re', '=.id=*wl1', '=interface=wlan1', '=mac-address=02:00:00:00:00:01', '=ssid=legacy', '=signal-strength=-80dBm', '=tx-rate=54Mbps', '=rx-rate=48Mbps', '=uptime=1h', '=password=wireless-secret']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/caps-man/registration-table/print') {
          socket.write(encodeSentence(['!re', '=.id=*cm1', '=interface=cap-wlan2', '=mac-address=02:00:00:00:00:02', '=ssid=managed', '=signal-strength=-65dBm', '=tx-rate=150Mbps', '=rx-rate=130Mbps', '=uptime=2h']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wifi/registration-table/print') {
          socket.write(encodeSentence(['!re', '=.id=*wf1', '=interface=wifi1', '=mac-address=02:00:00:00:00:03', '=ssid=new-wifi', '=signal=-60', '=tx-rate=1200Mbps', '=rx-rate=1000Mbps', '=uptime=10m']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wireguard/print') {
          socket.write(encodeSentence(['!re', '=.id=*wg0', '=name=wg0', '=public-key=public-key-a', '=running=true', '=disabled=false', '=private-key=wg-private-must-not-leak']));
          socket.write(encodeSentence(['!re', '=.id=*wg1', '=name=wg1', '=public-key=public-key-b', '=running=true', '=disabled=false']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/wireguard/peers/print') {
          socket.write(encodeSentence(['!re', '=.id=*wgp0', '=interface=wg0', '=public-key=public-key-b', '=allowed-address=10.0.0.2/32', '=disabled=false', '=preshared-key=wg-psk-must-not-leak']));
          socket.write(encodeSentence(['!re', '=.id=*wgp1', '=interface=wg1', '=public-key=public-key-a', '=allowed-address=10.0.0.1/32', '=disabled=false']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/interface/print') {
          socket.write(encodeSentence(['!re', '=.id=*1', '=name=ether1', '=type=ether', '=running=true', '=disabled=false']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/user-manager/router/print') {
          socket.write(encodeSentence(['!re', '=.id=*7', '=name=nas-a', '=address=192.0.2.5', '=shared-secret=mock-secret-must-not-leak']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/radius/print') {
          socket.write(encodeSentence(['!re', '=service=hotspot', '=address=192.0.2.6', '=authentication-port=1812', '=accounting-port=1813', '=disabled=false']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/user-manager/user/print') {
          socket.write(encodeSentence(['!re', '=.id=*8', '=name=alice', '=disabled=false']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/user-manager/profile/print') {
          socket.write(encodeSentence(['!re', '=.id=*9', '=name=basic', '=validity=1d', '=starts-when=first-auth']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/user-manager/session/print') {
          socket.write(encodeSentence(['!re', '=.id=*10', '=user=alice', '=nas-port-id=ether1', '=started=2026-11-09T00:00:00Z', '=uptime=1h', '=bytes-in=100', '=bytes-out=200', '=status=started']));
          socket.write(encodeSentence(['!done']));
        } else if (path === '/user-manager/limitation/print') {
          socket.write(encodeSentence(['!re', '=.id=*11', '=name=basic-limit', '=download-limit=10000', '=upload-limit=5000', '=transfer-limit=15000', '=uptime-limit=1d']));
          socket.write(encodeSentence(['!done']));
        } else {
          socket.write(encodeSentence(['!trap', '=message=unexpected mock command']));
          socket.write(encodeSentence(['!done']));
        }
      }
    });
  });
  return peer;
}

test('MCP stdio registers the broad catalog and dispatches read tools against a local mock router', async (t) => {
  const peer = createMockRouter();
  await new Promise((resolve, reject) => peer.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  t.after(() => new Promise((resolve) => peer.close(resolve)));
  const alertDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-mcp-alert-integration-'));
  await fs.chmod(alertDataDir, 0o700);
  t.after(() => fs.rm(alertDataDir, { recursive: true, force: true }));
  const { port } = peer.address();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['src/server.js'],
    cwd: process.cwd(),
    env: {
      ...process.env,
      MIKROTIK_HOST: '127.0.0.1',
      MIKROTIK_PORT: String(port),
      MIKROTIK_TLS: 'false',
      MIKROTIK_USERNAME: 'test-user',
      MIKROTIK_PASSWORD: 'test-password',
      MIKROTIK_DATA_DIR: alertDataDir,
      MIKROTIK_ALERT_SERVICE_ENABLED: 'false',
      MIKROTIK_ALERT_SERVICE_AUTOSTART: 'true',
      MIKROTIK_ALERT_WEBHOOK_ENABLED: 'false',
      MIKROTIK_ALERT_WEBHOOK_URL: '',
      MIKROTIK_SSH_USERNAME: '',
      MIKROTIK_SSH_PASSWORD: '',
      MIKROTIK_SSH_HOST_KEY_SHA256: '',
      MIKROTIK_DASHBOARD_ENABLED: 'false',
      MIKROTIK_TZSP_RECEIVER_ENABLED: 'false',
      MIKROTIK_TZSP_AUTOMATION_ENABLED: 'false',
      MIKROTIK_TZSP_BIND_ADDRESS: '',
      MIKROTIK_TZSP_PORT: '37008',
      MIKROTIK_TZSP_ALLOWED_SOURCES: '',
      MIKROTIK_TZSP_MAX_DURATION_SECONDS: '60',
      MIKROTIK_S3_ENABLED: 'false',
      MIKROTIK_S3_ALLOW_LISTING: 'false',
      MIKROTIK_S3_ALLOW_DELETE: 'false',
      MIKROTIK_S3_ALLOW_VERSION_PURGE: 'false',
      MIKROTIK_S3_BUCKET: '',
      MIKROTIK_S3_REGION: '',
      MIKROTIK_S3_EXPECTED_BUCKET_OWNER: '',
      MIKROTIK_SUPPORT_BUNDLE_ENABLED: 'false',
      MIKROTIK_ALLOW_WRITES: 'false',
      MIKROTIK_ALLOW_HIGH_RISK_WRITES: 'false',
      MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS: 'false',
      MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS: 'false',
    },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'mikrotik-test-client', version: '1.0.0' });
  try {
    await client.connect(transport);
    const catalog = await client.listTools();
    const names = catalog.tools.map((tool) => tool.name);
    assert.equal(names.length, 312, `expected the verified 312-tool catalog, got ${names.length}`);
    assert.ok(names.includes('list_ipv6_firewall_filter'));
    assert.ok(names.includes('list_bgp_sessions'));
    assert.ok(names.includes('list_legacy_capsman_remote_caps'));
    assert.ok(names.includes('list_vxlan_interfaces'));
    assert.ok(names.includes('probe_router_capabilities'));
    assert.ok(names.includes('router_support_summary'));
    assert.ok(names.includes('create_router_support_bundle'));
    assert.ok(names.includes('run_bandwidth_test'));
    assert.ok(names.includes('preview_port_forward'));
    assert.ok(names.includes('preview_vlan_segment'));
    assert.ok(names.includes('preview_ipv6_vlan_segment'));
    assert.ok(names.includes('preview_wireguard_mesh'));
    assert.ok(names.includes('simulate_ipv4_route_candidates'));
    assert.ok(names.includes('simulate_ipv6_route_candidates'));
    assert.ok(names.includes('audit_dhcp_integrity'));
    assert.ok(names.includes('audit_dns_resolver'));
    assert.ok(names.includes('audit_wireless_security_profiles'));
    assert.ok(names.includes('audit_scheduler_safety'));
    assert.ok(names.includes('audit_firewall_rule_order'));
    assert.ok(names.includes('audit_vlan_consistency'));
    assert.ok(names.includes('audit_wireguard_peers'));
    assert.ok(names.includes('audit_routing_protocol_health'));
    assert.ok(names.includes('wireless_client_inventory'));
    assert.ok(names.includes('verify_wireguard_topology'));
    assert.ok(names.includes('router_aaa_overview'));
    assert.ok(names.includes('router_alert_metric_catalog'));
    assert.ok(names.includes('create_router_alert_rule'));
    assert.ok(names.includes('evaluate_router_alert_rules'));
    assert.ok(names.includes('list_router_alert_history'));
    assert.ok(names.includes('start_router_alert_service'));
    assert.ok(names.includes('stop_router_alert_service'));
    assert.ok(names.includes('router_alert_service_status'));
    assert.ok(names.includes('run_speed_test'));
    assert.ok(names.includes('create_encrypted_router_backup'));
    assert.ok(names.includes('download_encrypted_router_backup'));
    assert.ok(names.includes('upload_encrypted_router_backup_to_s3'));
    assert.ok(names.includes('list_encrypted_router_backups_in_s3'));
    assert.ok(names.includes('list_encrypted_router_backup_versions_in_s3'));
    assert.ok(names.includes('delete_encrypted_router_backup_from_s3'));
    assert.ok(names.includes('delete_encrypted_router_backup_version_from_s3'));
    assert.ok(names.includes('list_local_encrypted_backups'));
    assert.ok(names.includes('delete_local_encrypted_backup'));
    assert.ok(names.includes('wake_on_lan'));
    assert.ok(names.includes('make_dhcp_lease_static'));
    assert.ok(names.includes('operate_dhcp_client'));
    assert.ok(names.includes('flush_dns_cache'));
    assert.ok(names.includes('start_tzsp_capture_receiver'));
    assert.ok(names.includes('capture_router_sniffer'));
    assert.ok(names.includes('tzsp_capture_status'));
    assert.ok(names.includes('stop_tzsp_capture_receiver'));
    assert.ok(names.includes('list_tzsp_captures'));
    assert.ok(names.includes('summarize_tzsp_capture'));
    assert.ok(names.includes('delete_tzsp_capture'));
    assert.ok(names.includes('audit_router_security_posture'));
    assert.ok(names.includes('install_routeros_updates'));
    assert.ok(names.includes('plan_router_transaction'));
    assert.ok(names.includes('create_router_snapshot'));

    const featureCatalog = await client.callTool({ name: 'router_feature_catalog', arguments: {} });
    const featureSummary = JSON.parse(featureCatalog.content[0].text);
    assert.equal(featureSummary.resourceCount, 229);
    assert.equal(featureSummary.uniqueApiPathCount, 218);
    assert.ok(featureSummary.knownGaps.some((gap) => gap.includes('Safe Mode')));
    for (const tool of ['router_support_summary', 'create_router_support_bundle', 'audit_routing_protocol_health', 'simulate_ipv4_route_candidates', 'simulate_ipv6_route_candidates', 'audit_dhcp_integrity', 'audit_dns_resolver', 'audit_wireless_security_profiles', 'audit_scheduler_safety', 'audit_firewall_rule_order', 'wireless_client_inventory', 'verify_wireguard_topology', 'start_tzsp_capture_receiver', 'capture_router_sniffer', 'tzsp_capture_status', 'summarize_tzsp_capture', 'upload_encrypted_router_backup_to_s3', 'list_encrypted_router_backups_in_s3', 'list_encrypted_router_backup_versions_in_s3', 'delete_encrypted_router_backup_from_s3', 'delete_encrypted_router_backup_version_from_s3', 'preview_ipv6_vlan_segment']) {
      assert.ok(featureSummary.purposeBuiltTools.includes(tool));
    }
    assert.ok(featureSummary.knownGaps.some((gap) => gap.includes('live packet decoding')));
    assert.ok(featureSummary.knownGaps.some((gap) => gap.includes('S3 lifecycle/retention management')));
    assert.ok(featureSummary.knownGaps.some((gap) => gap.includes('full RouterOS configuration export')));
    const captureStatusResult = await client.callTool({ name: 'tzsp_capture_status', arguments: {} });
    assert.equal(captureStatusResult.isError, undefined);
    assert.equal(JSON.parse(captureStatusResult.content[0].text).enabled, false);
    const captureListResult = await client.callTool({ name: 'list_tzsp_captures', arguments: {} });
    assert.equal(captureListResult.isError, undefined);
    assert.deepEqual(JSON.parse(captureListResult.content[0].text).captures, []);
    const syntheticCaptureId = '123e4567-e89b-42d3-a456-426614174000';
    const captureDirectory = path.join(alertDataDir, 'captures');
    const syntheticCapturePath = path.join(captureDirectory, `${syntheticCaptureId}-integration.pcap`);
    const syntheticPcap = Buffer.alloc(24);
    Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]).copy(syntheticPcap);
    syntheticPcap.writeUInt16LE(2, 4);
    syntheticPcap.writeUInt16LE(4, 6);
    syntheticPcap.writeUInt32LE(65_535, 16);
    syntheticPcap.writeUInt32LE(1, 20);
    await fs.writeFile(syntheticCapturePath, syntheticPcap, { mode: 0o600 });
    const captureSummaryResult = await client.callTool({ name: 'summarize_tzsp_capture', arguments: { captureId: syntheticCaptureId } });
    assert.equal(captureSummaryResult.isError, undefined, captureSummaryResult.content?.[0]?.text);
    const captureSummary = JSON.parse(captureSummaryResult.content[0].text);
    assert.equal(captureSummary.packetCount, 0);
    assert.equal(captureSummary.linkType, 1);
    assert.equal(JSON.stringify(captureSummary).includes(syntheticCapturePath), false);
    const blockedCaptureStart = await client.callTool({ name: 'start_tzsp_capture_receiver', arguments: {
      device: 'default', name: 'integration', durationSeconds: 1,
      confirmation: 'START TZSP CAPTURE default integration 1s 127.0.0.1 UDP 37008',
    } });
    assert.equal(blockedCaptureStart.isError, true);
    assert.match(blockedCaptureStart.content[0].text, /disabled/);
    const blockedManagedCapture = await client.callTool({ name: 'capture_router_sniffer', arguments: {
      device: 'default', name: 'integration', durationSeconds: 1,
      confirmation: 'CAPTURE ROUTER SNIFFER default integration 1s TO 127.0.0.1:37008',
    } });
    assert.equal(blockedManagedCapture.isError, true);
    assert.match(blockedManagedCapture.content[0].text, /Writes and active operations are disabled/);
    const blockedBundle = await client.callTool({ name: 'create_router_support_bundle', arguments: {
      device: 'default', confirmation: 'CREATE SUPPORT BUNDLE default',
    } });
    assert.equal(blockedBundle.isError, true);
    assert.match(blockedBundle.content[0].text, /Support bundle creation is disabled/);
    const alertStatusResult = await client.callTool({ name: 'router_alert_service_status', arguments: {} });
    assert.equal(JSON.parse(alertStatusResult.content[0].text).notifications.enabled, false);
    const blockedS3Upload = await client.callTool({ name: 'upload_encrypted_router_backup_to_s3', arguments: {
      backupId: '123e4567-e89b-42d3-a456-426614174000', confirmation: 'UPLOAD ENCRYPTED BACKUP default 123e4567-e89b-42d3-a456-426614174000 TO S3',
    } });
    assert.equal(blockedS3Upload.isError, true);
    const disabledS3List = await client.callTool({ name: 'list_encrypted_router_backups_in_s3', arguments: { device: 'default' } });
    assert.equal(disabledS3List.isError, true);
    const disabledS3Versions = await client.callTool({ name: 'list_encrypted_router_backup_versions_in_s3', arguments: { device: 'default' } });
    assert.equal(disabledS3Versions.isError, true);
    const blockedS3Delete = await client.callTool({ name: 'delete_encrypted_router_backup_from_s3', arguments: {
      device: 'default', backupId: '123e4567-e89b-42d3-a456-426614174000', confirmation: 'DELETE S3 ENCRYPTED BACKUP default 123e4567-e89b-42d3-a456-426614174000 FROM S3',
    } });
    assert.equal(blockedS3Delete.isError, true);
    const blockedS3VersionDelete = await client.callTool({ name: 'delete_encrypted_router_backup_version_from_s3', arguments: {
      device: 'default', backupId: '123e4567-e89b-42d3-a456-426614174000', versionId: 'version-1',
      confirmation: 'DELETE S3 BACKUP VERSION default 123e4567-e89b-42d3-a456-426614174000 version-1',
    } });
    assert.equal(blockedS3VersionDelete.isError, true);

    const supportResult = await client.callTool({ name: 'router_support_summary', arguments: { device: 'default' } });
    assert.equal(supportResult.isError, undefined, supportResult.content?.[0]?.text);
    const support = JSON.parse(supportResult.content[0].text);
    assert.equal(support.deviceId, 'default');
    assert.equal(support.identityName, 'Lab-Router');
    assert.equal(support.system.version, '7.16');
    assert.deepEqual(support.counts.interfaces, { total: 1, running: 1, disabled: 0, partial: false });
    assert.equal(support.counts.defaultIpv4Routes.total, 1);
    assert.equal(support.counts.wirelessRegistrations.total, 3);
    assert.equal(support.coverage.sections.ip_addresses.status, 'unavailable-or-not-permitted');
    assert.match(support.notes.join(' '), /not a full configuration export or support bundle/);
    const supportText = JSON.stringify(support);
    for (const privateValue of ['192.0.2.1', '02:00:00:00:00:01', 'wg-private-must-not-leak', 'wg-psk-must-not-leak', 'wireless-secret']) {
      assert.equal(supportText.includes(privateValue), false, `${privateValue} leaked in support summary`);
    }

    const routingAuditResult = await client.callTool({ name: 'audit_routing_protocol_health', arguments: { device: 'default' } });
    assert.equal(routingAuditResult.isError, undefined);
    const routingAudit = JSON.parse(routingAuditResult.content[0].text);
    assert.equal(routingAudit.routeTotals.active, 1);
    assert.equal(routingAudit.protocolCounts.bgp_sessions, 1, JSON.stringify(routingAudit, null, 2));
    assert.equal(routingAudit.protocolCounts.ospf_neighbors, 1);
    assert.equal(routingAudit.protocolCounts.rip_routes, 1);
    assert.equal(routingAudit.protocolCounts.routing_bfd_peers, 1);

    const routeSimulationResult = await client.callTool({ name: 'simulate_ipv4_route_candidates', arguments: {
      device: 'default', destination: '198.51.100.22', routingTable: 'main',
    } });
    assert.equal(routeSimulationResult.isError, undefined);
    const routeSimulation = JSON.parse(routeSimulationResult.content[0].text);
    assert.equal(routeSimulation.status, 'matched');
    assert.deepEqual(routeSimulation.winners.map(({ id }) => id), ['*r1']);
    assert.equal(JSON.stringify(routeSimulation).includes('192.0.2.1'), false);

    const ipv6RouteResult = await client.callTool({ name: 'simulate_ipv6_route_candidates', arguments: {
      device: 'default', destination: '2001:db8:100::123', routingTable: 'main',
    } });
    assert.equal(ipv6RouteResult.isError, undefined, ipv6RouteResult.content?.[0]?.text);
    const ipv6Route = JSON.parse(ipv6RouteResult.content[0].text);
    assert.equal(ipv6Route.status, 'matched');
    assert.deepEqual(ipv6Route.winners.map(({ id }) => id), ['*v61']);
    assert.equal(JSON.stringify(ipv6Route).includes('2001:db8:'), false);
    assert.equal(JSON.stringify(ipv6Route).includes('fe80::1'), false);

    const dhcpAuditResult = await client.callTool({ name: 'audit_dhcp_integrity', arguments: { device: 'default' } });
    assert.equal(dhcpAuditResult.isError, undefined, dhcpAuditResult.content?.[0]?.text);
    const dhcpAudit = JSON.parse(dhcpAuditResult.content[0].text);
    assert.equal(dhcpAudit.findings.length, 0, 'static leases outside the dynamic pool but inside the subnet are valid');
    const dhcpAuditText = JSON.stringify(dhcpAudit);
    for (const privateValue of ['192.0.2.51', '02:00:00:00:aa:bb', 'private-dhcp-host', 'test-pool']) {
      assert.equal(dhcpAuditText.includes(privateValue), false, `${privateValue} leaked in DHCP audit`);
    }

    const dnsAuditResult = await client.callTool({ name: 'audit_dns_resolver', arguments: { device: 'default' } });
    assert.equal(dnsAuditResult.isError, undefined, dnsAuditResult.content?.[0]?.text);
    const dnsAudit = JSON.parse(dnsAuditResult.content[0].text);
    assert.ok(dnsAudit.findings.some(({ code }) => code === 'remote-requests-enabled-review'));
    assert.ok(dnsAudit.findings.some(({ code }) => code === 'duplicate-static-name'));
    const dnsAuditText = JSON.stringify(dnsAudit);
    for (const privateValue of ['192.0.2.53', '192.0.2.12', 'private.example.test', 'secret-doh.invalid', 'dns-private-comment']) {
      assert.equal(dnsAuditText.includes(privateValue), false, `${privateValue} leaked in DNS audit`);
    }

    const wirelessSecurityResult = await client.callTool({ name: 'audit_wireless_security_profiles', arguments: { device: 'default' } });
    assert.equal(wirelessSecurityResult.isError, undefined, wirelessSecurityResult.content?.[0]?.text);
    const wirelessSecurity = JSON.parse(wirelessSecurityResult.content[0].text);
    assert.ok(wirelessSecurity.findings.some(({ code }) => code === 'open-no-authentication'));
    assert.equal(wirelessSecurity.profiles.find(({ section }) => section === 'wireless_security_profiles').secretPresent, true);
    const wirelessSecurityText = JSON.stringify(wirelessSecurity);
    for (const privateValue of ['wireless-profile-secret', 'capsman-profile-secret', 'wifi-profile-secret']) {
      assert.equal(wirelessSecurityText.includes(privateValue), false, `${privateValue} leaked in wireless security audit`);
    }

    const schedulerAuditResult = await client.callTool({ name: 'audit_scheduler_safety', arguments: { device: 'default' } });
    assert.equal(schedulerAuditResult.isError, undefined, schedulerAuditResult.content?.[0]?.text);
    const schedulerAudit = JSON.parse(schedulerAuditResult.content[0].text);
    assert.ok(schedulerAudit.findings.some(({ riskCodes }) => riskCodes.includes('router-reboot')));
    assert.ok(schedulerAudit.findings.some(({ riskCodes }) => riskCodes.includes('remote-fetch')));
    const schedulerAuditText = JSON.stringify(schedulerAudit);
    for (const privateValue of ['scheduler-private-marker', 'private.invalid', '/system reboot']) {
      assert.equal(schedulerAuditText.includes(privateValue), false, `${privateValue} leaked in scheduler audit`);
    }

    const firewallAuditResult = await client.callTool({ name: 'audit_firewall_rule_order', arguments: { device: 'default' } });
    assert.equal(firewallAuditResult.isError, undefined);
    const firewallAudit = JSON.parse(firewallAuditResult.content[0].text);
    assert.equal(firewallAudit.findings.length, 1);
    assert.ok(firewallAudit.indeterminate.some(({ reason }) => reason === 'unsupported-address-match'));
    const firewallAuditText = JSON.stringify(firewallAudit);
    for (const privateValue of ['192.0.2.0/24', '192.0.2.4', '2001:db8::', 'firewall-comment-must-not-leak', 'second-comment-must-not-leak']) {
      assert.equal(firewallAuditText.includes(privateValue), false, `${privateValue} leaked in firewall audit`);
    }

    const wirelessInventoryResult = await client.callTool({ name: 'wireless_client_inventory', arguments: { device: 'default' } });
    assert.equal(wirelessInventoryResult.isError, undefined);
    const wirelessInventory = JSON.parse(wirelessInventoryResult.content[0].text);
    assert.equal(wirelessInventory.associations.length, 3);
    assert.deepEqual(wirelessInventory.associations.map((row) => row.source), ['legacyWireless', 'legacyCapsman', 'wifi']);
    assert.equal(JSON.stringify(wirelessInventory).includes('wireless-secret'), false);

    const wirelessAuditResult = await client.callTool({ name: 'audit_wireless_clients', arguments: { device: 'default' } });
    assert.equal(wirelessAuditResult.isError, undefined, wirelessAuditResult.content[0].text);
    assert.equal(JSON.parse(wirelessAuditResult.content[0].text).weakClientCount, 1);

    const topologyResult = await client.callTool({ name: 'verify_wireguard_topology', arguments: { links: [
      { deviceA: 'default', interfaceA: 'wg0', deviceB: 'default', interfaceB: 'wg1' },
    ] } });
    assert.equal(topologyResult.isError, undefined);
    const topology = JSON.parse(topologyResult.content[0].text);
    assert.equal(topology.status, 'verified');
    assert.equal(topology.links[0].status, 'verified');
    assert.equal(JSON.stringify(topology).includes('wg-private-must-not-leak'), false);
    assert.equal(JSON.stringify(topology).includes('wg-psk-must-not-leak'), false);
    const peerAuditResult = await client.callTool({ name: 'audit_wireguard_peers', arguments: { device: 'default' } });
    const peerAuditText = peerAuditResult.content[0].text;
    assert.equal(peerAuditResult.isError, undefined);
    assert.equal(peerAuditText.includes('wg-private-must-not-leak'), false);
    assert.equal(peerAuditText.includes('wg-psk-must-not-leak'), false);

    const createdRule = await client.callTool({ name: 'create_router_alert_rule', arguments: {
      device: 'default', metric: 'cpuUsedPercent', operator: 'gt', threshold: 0, label: 'CPU activity',
    } });
    assert.equal(createdRule.isError, undefined);
    const rule = JSON.parse(createdRule.content[0].text).rule;
    assert.equal(rule.device, 'default');
    const evaluation = await client.callTool({ name: 'evaluate_router_alert_rules', arguments: { device: 'default' } });
    assert.equal(evaluation.isError, undefined);
    assert.equal(JSON.parse(evaluation.content[0].text).evaluations[0].value, 0);
    const listedRules = await client.callTool({ name: 'list_router_alert_rules', arguments: { device: 'default' } });
    assert.equal(JSON.parse(listedRules.content[0].text).rules.length, 1);
    const deletedRule = await client.callTool({ name: 'delete_router_alert_rule', arguments: { ruleId: rule.id, confirmation: `DELETE ALERT RULE ${rule.id}` } });
    assert.equal(deletedRule.isError, undefined);

    const alertStatus = await client.callTool({ name: 'router_alert_service_status', arguments: {} });
    const alertStatusData = JSON.parse(alertStatus.content[0].text);
    assert.equal(alertStatusData.configured, false);
    assert.equal(alertStatusData.autostartConfigured, true);
    assert.match(alertStatusData.autostartError, /not enabled/);
    assert.equal(alertStatusData.service.running, false);
    const blockedAlertStart = await client.callTool({ name: 'start_router_alert_service', arguments: { intervalSeconds: 60 } });
    assert.equal(blockedAlertStart.isError, true);
    assert.match(blockedAlertStart.content[0].text, /MIKROTIK_ALERT_SERVICE_ENABLED/);
    const stoppedAlertWorker = await client.callTool({ name: 'stop_router_alert_service', arguments: {} });
    assert.equal(JSON.parse(stoppedAlertWorker.content[0].text).service.running, false);

    const backupList = await client.callTool({ name: 'list_local_encrypted_backups', arguments: {} });
    assert.equal(JSON.parse(backupList.content[0].text).backups.length, 0);
    const blockedBackupCreate = await client.callTool({ name: 'create_encrypted_router_backup', arguments: {
      name: 'mcp-test', encryptionPassword: 'dummy-backup-encryption-passphrase', confirmation: 'CREATE ENCRYPTED BACKUP default mcp-test',
    } });
    assert.equal(blockedBackupCreate.isError, true);
    assert.match(blockedBackupCreate.content[0].text, /MIKROTIK_ALLOW_WRITES/);
    const blockedBackupDownload = await client.callTool({ name: 'download_encrypted_router_backup', arguments: {
      backupId: '00000000-0000-4000-8000-000000000001', confirmation: 'DOWNLOAD ENCRYPTED BACKUP default 00000000-0000-4000-8000-000000000001',
    } });
    assert.equal(blockedBackupDownload.isError, true);
    assert.match(blockedBackupDownload.content[0].text, /MIKROTIK_ALLOW_WRITES/);
    const blockedBackupDelete = await client.callTool({ name: 'delete_local_encrypted_backup', arguments: {
      backupId: '00000000-0000-4000-8000-000000000001', confirmation: 'DELETE LOCAL ENCRYPTED BACKUP 00000000-0000-4000-8000-000000000001',
    } });
    assert.equal(blockedBackupDelete.isError, true);
    assert.match(blockedBackupDelete.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const forwardPreview = await client.callTool({ name: 'preview_port_forward', arguments: {
      protocol: 'tcp', externalPort: 443, internalHost: '192.0.2.10', wanInterface: 'ether1',
    } });
    assert.equal(forwardPreview.isError, undefined);
    const forwardPlan = JSON.parse(forwardPreview.content[0].text);
    assert.equal(forwardPlan.stepCount, 2);
    assert.match(forwardPlan.confirmation, /^APPLY /);
    await client.callTool({ name: 'cancel_router_change_plan', arguments: { planId: forwardPlan.id } });

    const vlanPreview = await client.callTool({ name: 'preview_vlan_segment', arguments: {
      vlanId: 30, name: 'guest', subnet: '192.168.30.0/24', gateway: '192.168.30.1', bridge: 'bridge', dhcp: false,
    } });
    assert.equal(vlanPreview.isError, undefined);
    const vlanPlan = JSON.parse(vlanPreview.content[0].text);
    assert.equal(vlanPlan.stepCount, 3);
    await client.callTool({ name: 'cancel_router_change_plan', arguments: { planId: vlanPlan.id } });

    const ipv6VlanPreview = await client.callTool({ name: 'preview_ipv6_vlan_segment', arguments: {
      device: 'default', vlanId: 60, name: 'guestv6', subnet: '2001:db8:60::/64', gateway: '2001:db8:60::1', bridge: 'bridge',
      taggedPorts: ['ether1'],
    } });
    assert.equal(ipv6VlanPreview.isError, undefined, ipv6VlanPreview.content?.[0]?.text);
    const ipv6VlanPlan = JSON.parse(ipv6VlanPreview.content[0].text);
    assert.equal(ipv6VlanPlan.stepCount, 3);
    assert.equal(ipv6VlanPlan.planner, 'ipv6-vlan-segment');
    assert.equal(ipv6VlanPlan.checked.existingVlanInterfaces, 0);
    assert.ok(ipv6VlanPlan.notes.some((note) => /DHCPv6/.test(note)));
    await client.callTool({ name: 'cancel_router_change_plan', arguments: { planId: ipv6VlanPlan.id } });

    const blockedBandwidthTest = await client.callTool({ name: 'run_bandwidth_test', arguments: {
      target: '192.0.2.10', confirmation: 'RUN BANDWIDTH TEST default 192.0.2.10',
    } });
    assert.equal(blockedBandwidthTest.isError, true);
    assert.match(blockedBandwidthTest.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const blockedSpeedTest = await client.callTool({ name: 'run_speed_test', arguments: {
      target: '192.0.2.20', durationSeconds: 5, username: 'speedtest', password: 'mock-password', confirmation: 'RUN SPEED TEST default 192.0.2.20',
    } });
    assert.equal(blockedSpeedTest.isError, true);
    assert.match(blockedSpeedTest.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const blockedReboot = await client.callTool({ name: 'reboot_router', arguments: {
      confirmation: 'REBOOT default',
    } });
    assert.equal(blockedReboot.isError, true);
    assert.match(blockedReboot.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const blockedLease = await client.callTool({ name: 'make_dhcp_lease_static', arguments: {
      id: '*1', confirmation: 'MAKE DHCP LEASE STATIC default *1',
    } });
    assert.equal(blockedLease.isError, true);
    assert.match(blockedLease.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const blockedDnsFlush = await client.callTool({ name: 'flush_dns_cache', arguments: {
      confirmation: 'FLUSH DNS CACHE default',
    } });
    assert.equal(blockedDnsFlush.isError, true);
    assert.match(blockedDnsFlush.content[0].text, /MIKROTIK_ALLOW_WRITES/);

    const identity = await client.callTool({ name: 'router_identity', arguments: {} });
    assert.equal(identity.isError, undefined);
    assert.deepEqual(JSON.parse(identity.content[0].text), { device: 'default', records: [{ name: 'Lab-Router' }] });

    const interfaces = await client.callTool({ name: 'list_interfaces', arguments: { limit: 10 } });
    const result = JSON.parse(interfaces.content[0].text);
    assert.equal(result.resource, 'interfaces');
    assert.equal(result.records[0].name, 'ether1');
    assert.equal(result.total, 1);

    const radiusRouters = await client.callTool({ name: 'list_radius_user_manager_routers', arguments: {} });
    assert.equal(radiusRouters.isError, undefined);
    assert.equal(radiusRouters.content[0].text.includes('mock-secret-must-not-leak'), false);
    const secretRequest = await client.callTool({ name: 'list_radius_user_manager_routers', arguments: { properties: ['shared-secret'] } });
    assert.equal(secretRequest.isError, true);
    assert.match(secretRequest.content[0].text, /Sensitive properties cannot be read/);

    const aaa = await client.callTool({ name: 'router_aaa_overview', arguments: {} });
    assert.equal(aaa.isError, undefined);
    const aaaReport = JSON.parse(aaa.content[0].text);
    assert.equal(aaaReport.sections.sessions.records[0].user, 'alice');
    assert.equal(aaaReport.sessionTotals.bytesInTotal, 100);
    assert.equal(aaaReport.sessionTotals.bytesOutTotal, 200);
    assert.equal(JSON.stringify(aaaReport).includes('mock-secret-must-not-leak'), false);
  } finally {
    await client.close();
  }
});

test('alert polling autostarts only when both service and restart-recovery flags are enabled', async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mikrotik-alert-autostart-'));
  await fs.chmod(dataDir, 0o700);
  t.after(() => fs.rm(dataDir, { recursive: true, force: true }));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['src/server.js'],
    cwd: process.cwd(),
    env: {
      ...process.env,
      MIKROTIK_HOST: '192.0.2.1',
      MIKROTIK_PORT: '8728',
      MIKROTIK_TLS: 'false',
      MIKROTIK_USERNAME: 'unused',
      MIKROTIK_PASSWORD: 'unused',
      MIKROTIK_DATA_DIR: dataDir,
      MIKROTIK_ALERT_SERVICE_ENABLED: 'true',
      MIKROTIK_ALERT_SERVICE_AUTOSTART: 'true',
      MIKROTIK_ALERT_POLL_INTERVAL_SECONDS: '60',
      MIKROTIK_DASHBOARD_ENABLED: 'false',
      MIKROTIK_TZSP_RECEIVER_ENABLED: 'false',
      MIKROTIK_S3_ENABLED: 'false',
      MIKROTIK_S3_ALLOW_LISTING: 'false',
      MIKROTIK_S3_ALLOW_DELETE: 'false',
      MIKROTIK_ALLOW_WRITES: 'false',
      MIKROTIK_ALLOW_HIGH_RISK_WRITES: 'false',
      MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS: 'false',
      MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS: 'false',
    },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'alert-autostart-test-client', version: '1.0.0' });
  try {
    await client.connect(transport);
    const statusResult = await client.callTool({ name: 'router_alert_service_status', arguments: {} });
    assert.equal(statusResult.isError, undefined, statusResult.content?.[0]?.text);
    const status = JSON.parse(statusResult.content[0].text);
    assert.equal(status.configured, true);
    assert.equal(status.autostartConfigured, true);
    assert.equal(status.autostartError, null);
    assert.equal(status.processBound, true);
    assert.equal(status.service.running, true);
    assert.equal(status.service.intervalMs, 60000);
    assert.equal(status.service.pollCount, 1);
  } finally {
    await client.close();
  }
});
