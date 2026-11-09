import test from 'node:test';
import assert from 'node:assert/strict';
import { buildPortForwardPlan, buildVlanSegmentPlan } from '../src/builders.js';
import { RESOURCE_BY_KEY } from '../src/catalog.js';
import { validateChangeInput } from '../src/change-planner.js';

test('port-forward planner returns staged NAT/filter rules and optional hairpin rule only', () => {
  const plan = buildPortForwardPlan({
    protocol: 'tcp', externalPort: 8443, internalHost: '192.168.20.10', internalPort: 443,
    wanInterface: 'ether1', lanSubnet: '192.168.20.0/24', lanInterface: 'bridge-lan',
  });
  assert.equal(plan.steps.length, 3);
  assert.equal(plan.steps[0].resource, 'firewall_nat');
  assert.equal(plan.steps[0].fields['to-addresses'], '192.168.20.10');
  assert.equal(plan.steps[1].resource, 'firewall_filter');
  assert.equal(plan.steps[1].fields['connection-nat-state'], 'dstnat');
  assert.equal(plan.steps[2].fields.action, 'masquerade');
  for (const step of plan.steps) validateChangeInput(RESOURCE_BY_KEY.get(step.resource), step.action, step.fields);
  assert.match(plan.notes[0], /Preview only/);
});

test('port-forward planner rejects unsafe or incomplete input', () => {
  assert.throws(() => buildPortForwardPlan({ protocol: 'tcp', externalPort: 443, internalHost: 'not-an-ip' }), /IPv4/);
  assert.throws(() => buildPortForwardPlan({ protocol: 'icmp', externalPort: 443, internalHost: '192.0.2.8' }), /tcp or udp/);
  assert.throws(() => buildPortForwardPlan({ protocol: 'tcp', externalPort: 443, internalHost: '192.0.2.8', lanSubnet: '192.0.2.0/24' }), /lanInterface/);
});

test('VLAN builder creates bounded partial IPv4/DHCP scaffolding and keeps DHCP disabled', () => {
  const plan = buildVlanSegmentPlan({
    vlanId: 30, name: 'guest-v30', subnet: '192.168.30.0/24', gateway: '192.168.30.1', bridge: 'bridge',
    taggedPorts: ['sfp1'], untaggedPorts: ['ether5'], dhcp: true, dhcpRange: '192.168.30.10-192.168.30.200',
    internet: true, wanInterface: 'ether1',
  });
  assert.equal(plan.steps.length, 7);
  assert.equal(plan.steps[1].fields.tagged, 'bridge,sfp1');
  assert.equal(plan.steps[2].fields.address, '192.168.30.1/24');
  assert.equal(plan.steps[5].fields.disabled, 'yes');
  assert.equal(plan.steps[6].fields['out-interface'], 'ether1');
  for (const step of plan.steps) validateChangeInput(RESOURCE_BY_KEY.get(step.resource), step.action, step.fields);
  assert.ok(plan.notes.some((note) => note.includes('not a complete isolated segment')));
});

test('VLAN builder rejects invalid subnet, overlaps, DHCP pool errors and inferred egress', () => {
  const base = { vlanId: 30, name: 'guest', subnet: '192.168.30.0/24', gateway: '192.168.30.1', bridge: 'bridge' };
  assert.throws(() => buildVlanSegmentPlan({ ...base, subnet: '192.168.30.1/24' }), /network address/);
  assert.throws(() => buildVlanSegmentPlan({ ...base, gateway: '192.168.30.0' }), /usable/);
  assert.throws(() => buildVlanSegmentPlan({ ...base, dhcp: true }), /dhcpRange is required/);
  assert.throws(() => buildVlanSegmentPlan({ ...base, dhcp: true, dhcpRange: '192.168.30.1-192.168.30.10' }), /exclude network, broadcast and gateway/);
  assert.throws(() => buildVlanSegmentPlan({ ...base, internet: true }), /wanInterface is required/);
});
