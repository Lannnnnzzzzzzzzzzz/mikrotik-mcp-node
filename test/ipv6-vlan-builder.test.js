import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIpv6VlanSegmentPlan } from '../src/ipv6-vlan-builder.js';
import { RESOURCE_BY_KEY } from '../src/catalog.js';
import { validateChangeInput } from '../src/change-planner.js';

const base = {
  vlanId: 60,
  name: 'guest-v6',
  subnet: '2001:db8:60::/64',
  gateway: '2001:db8:60::1',
  bridge: 'bridge-lan',
  taggedPorts: ['sfp1'],
  untaggedPorts: ['ether5'],
};

test('IPv6 VLAN builder creates a bounded dry-run plan from allowlisted resources only', () => {
  const plan = buildIpv6VlanSegmentPlan(base);
  assert.equal(plan.steps.length, 3);
  assert.deepEqual(plan.steps.map(({ resource }) => resource), ['vlans', 'bridge_vlans', 'ipv6_addresses']);
  assert.equal(plan.steps[0].fields['vlan-id'], '60');
  assert.equal(plan.steps[1].fields.tagged, 'bridge-lan,sfp1');
  assert.equal(plan.steps[1].fields.untagged, 'ether5');
  assert.equal(plan.steps[2].fields.address, '2001:db8:60::1/64');
  assert.equal(plan.steps[2].fields.advertise, 'no');
  for (const step of plan.steps) validateChangeInput(RESOURCE_BY_KEY.get(step.resource), step.action, step.fields);
  assert.match(plan.notes.join(' '), /Preview only/);
  for (const feature of ['DHCPv6', 'router advertisements', 'IPv6 firewall isolation', 'apply', 'rollback']) {
    assert.ok(plan.notes.some((note) => note.includes(feature)));
  }
});

test('IPv6 VLAN builder rejects malformed VLAN, identifier, address and gateway inputs', () => {
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, vlanId: 4095 }), /vlanId/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, name: 'invalid name' }), /name/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, bridge: 'bad/bridge' }), /bridge/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, subnet: '2001:db8:60::1/64' }), /network address/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, subnet: '2001:db8:60::/129' }), /prefix/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, subnet: '192.0.2.0/24' }), /valid IPv6/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, gateway: '2001:db8:61::1' }), /inside the IPv6 subnet/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, gateway: '2001:db8:60::' }), /host address/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, taggedPorts: ['bad port'] }), /identifier/);
});

test('IPv6 VLAN builder rejects membership duplicates, collisions, and overlapping existing prefixes', () => {
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, taggedPorts: ['sfp1', 'sfp1'] }), /duplicate/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, taggedPorts: ['ether5'] }), /both tagged and untagged/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, taggedPorts: ['bridge-lan'] }), /taggedPorts must not repeat bridge/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, name: 'bridge-lan' }), /distinct from the bridge/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, existingVlanIds: [60] }), /already exists/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, existingNames: ['guest-v6'] }), /already exists/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, existingSubnets: ['2001:db8:60:0:1::/80'] }), /overlaps/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, existingSubnets: ['2001:db8:60::/64'] }), /duplicate or overlap|overlaps/);
  assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, existingSubnets: ['2001:db8:60::1/64'] }), (error) => {
    assert.match(error.message, /overlaps an existing IPv6 prefix/);
    assert.equal(error.message.includes('2001:db8:60::1/64'), false);
    return true;
  });
  assert.doesNotThrow(() => buildIpv6VlanSegmentPlan({ ...base, existingSubnets: ['2001:db8:61::/64'] }));
});

test('IPv6 VLAN builder refuses requested unsupported features and does not leak private input', () => {
  for (const option of ['dhcpv6', 'ra', 'firewallIsolation', 'apply', 'rollback']) {
    assert.throws(() => buildIpv6VlanSegmentPlan({ ...base, [option]: true }), /unsupported/);
  }
  const plan = buildIpv6VlanSegmentPlan({ ...base, privateKey: 'do-not-return-this', secret: 'also-private' });
  const serialized = JSON.stringify(plan);
  assert.ok(!serialized.includes('do-not-return-this'));
  assert.ok(!serialized.includes('also-private'));
  assert.ok(!serialized.includes('privateKey'));
  assert.ok(plan.steps.every((step) => !Object.keys(step.fields).some((key) => /private|secret|token/i.test(key))));
});
