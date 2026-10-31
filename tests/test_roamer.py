import copy
import ipaddress
import json
from pathlib import Path
import tempfile
import time
import unittest

from probe.authorisation import scope_digest, verify
from probe.audit import Attestation, HEARTBEATS
from probe.egress import create_policy, denied_v4, validate_readback
from probe.analysis import network_facts, segments, topology
from probe.analysis.classify import HostClass, CONFIRMED_ONLINK
from probe.discovery.ingest import Evidence
from probe.planner import open_questions, Q_BACKEND
from probe.scope import ScopeGuard, ScopeViolation


class Roamer(unittest.TestCase):
    def test_legacy_hold_approval_cannot_expand_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'approvals.json'
            ScopeGuard.write_approval(p, '10.99.0.0/24')
            with self.assertRaises(ScopeViolation):
                ScopeGuard(['10.20.30.0/24'], approvals_path=p)

    def test_authorisation_rejects_neighbour_and_allows_exact_host_subset(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'grants.json'
            p.write_text(json.dumps({'grants': [{'cidr': '10.20.30.0/24', 'purposes': ['discovery','inventory'],
                'authority': 'test owner', 'reference': 'test grant', 'prefix_evidence': 'assigned boundary'}]}))
            self.assertEqual(['10.20.30.139/32'], verify(p, ['10.20.30.139/32'])['scope'])
            with self.assertRaises(ValueError):
                verify(p, ['10.20.31.0/24'])

    def test_equivalent_scope_encodings_have_one_digest(self):
        self.assertEqual(scope_digest(['10.20.30.0/24']), scope_digest(['10.20.30.128/25','10.20.30.0/25']))

    def test_firewall_complement_excludes_only_authorised_addresses(self):
        denied = [ipaddress.ip_network(n) for n in denied_v4(['10.20.30.0/24'])]
        for addr, expected in [('10.20.30.139',False),('10.20.31.1',True),('8.8.8.8',True),('224.0.0.1',True)]:
            self.assertEqual(expected, any(ipaddress.ip_address(addr) in n for n in denied))

    def test_firewall_readback_detects_a_hole_or_disabled_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = create_policy(Path(tmp)/'policy.json', 'nmap.exe', ['10.20.30.0/24'])
            rules = [{'name':f"ProbeScope.{policy['scope_digest']}.{family}", 'program':policy['program'],
                'enabled':True, 'direction':2, 'action':0, 'protocol':256, 'profiles':7,
                'remote':remote, 'service':'', 'interfaces':'All','local':'*','local_ports':'*','remote_ports':'*'}
                for family, remote in [('v4',','.join(policy['denied_v4'])),('v6','::/0')]]
            readback = {'scope_digest':policy['scope_digest'],'profiles_enabled':True,'rules':rules}
            validate_readback(policy, readback)
            broken = copy.deepcopy(readback)
            broken['rules'][0]['remote'] = ','.join(policy['denied_v4'][1:])
            with self.assertRaises(ValueError):
                validate_readback(policy, broken)
            readback['rules'][1]['enabled'] = False
            with self.assertRaises(ValueError):
                validate_readback(policy, readback)

    def test_native_windows_all_protocol_rule_has_no_port_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = create_policy(Path(tmp)/'policy.json', 'nmap.exe', ['10.20.30.0/24'])
            rules = [{'name':f"ProbeScope.{policy['scope_digest']}.{family}", 'program':policy['program'],
                'enabled':True, 'direction':2, 'action':0, 'protocol':256, 'profiles':7,
                'remote':remote, 'service':None, 'interfaces':'All','interface_ids':None,
                'local':'*','local_ports':None,'remote_ports':None}
                for family, remote in [('v4',','.join(str(ipaddress.ip_network(n).with_netmask) for n in policy['denied_v4'])),
                                       ('v6','::/1,8000::/1')]]
            result = {'scope_digest':policy['scope_digest'],'profiles_enabled':True,'rules':rules}
            validate_readback(policy, result)
            restricted = copy.deepcopy(result)
            restricted['rules'][0]['interface_ids'] = ['one-interface-only']
            with self.assertRaises(ValueError):
                validate_readback(policy, restricted)
            restricted = copy.deepcopy(result)
            restricted['rules'][0]['remote_ports'] = '443'
            with self.assertRaises(ValueError):
                validate_readback(policy, restricted)
            restricted = copy.deepcopy(result)
            restricted['rules'][1]['remote'] = '::/1'
            with self.assertRaises(ValueError):
                validate_readback(policy, restricted)

    def test_old_run_heartbeat_and_dead_capture_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            att = Attestation(Path(tmp), scope_digest='scope', run_id='new')
            hb = {'t':time.time(),'violations':0,'scope_digest':'scope','run_id':'old',
                  'capture_ready':True,'helper_egress_verified':True}
            p = Path(tmp) / HEARTBEATS[0]
            p.write_text(json.dumps(hb))
            self.assertFalse(att.check()[0])
            hb.update(run_id='new',capture_ready=False)
            p.write_text(json.dumps(hb))
            self.assertFalse(att.check()[0])
            hb['capture_ready'] = True
            p.write_text(json.dumps(hb))
            self.assertTrue(att.check()[0])

    def test_member_cover_does_not_establish_a_prefix(self):
        ev = Evidence()
        classes = {ip:HostClass(ip=ip, verdict=CONFIRMED_ONLINK) for ip in ('10.20.30.2','10.20.30.12')}
        found = segments.infer(classes, ev, [ipaddress.ip_network('10.20.30.0/24')])
        self.assertFalse(found[0].prefix_known)

    def test_unresolved_host_does_not_get_a_proven_l2_edge(self):
        edges = topology.build_edges('10.20.30.1', [{'ip':'10.20.30.2','verdict':'UNRESOLVED','discovery_methods':['tcp']}], [])
        self.assertEqual('attachment-unknown', edges[1][2])

    def test_forwarded_service_gets_unknown_backend_and_open_question(self):
        c = HostClass(ip='10.20.30.2', verdict=CONFIRMED_ONLINK)
        c.behind_ports[80] = 'controlled TTL expiry at published endpoint'
        c.behind_status[80] = 'confirmed'
        edges = topology.build_edges('10.20.30.1', [], [], classes={c.ip:c})
        self.assertTrue(any(e[2] == 'forwards' and e[1].startswith('unknown-backend:') for e in edges))
        qs = open_questions({c.ip:c}, Evidence(), blitzed=set(), silent=[])
        self.assertTrue(any(q.kind == Q_BACKEND for q in qs))

    def test_service_prefix_reference_is_not_a_confirmed_network(self):
        hosts = [{'ip':'10.20.30.2','open_ports':[{'port':80,'scripts':json.dumps({'http-inventory':'reported_prefixes: 172.20.0.0/20'})}]}]
        facts = network_facts.collect(hosts, Evidence(), {'scope':['10.20.30.0/24']})
        self.assertEqual('unverified', facts[0]['state'])
        self.assertEqual('172.20.0.0/20', facts[0]['prefix'])
        self.assertEqual('outside', facts[0]['scope_relation'])


    def test_later_identification_preserves_root_metadata(self):
        from probe.store import Store
        store = Store(":memory:")
        store.upsert_service('10.20.30.2', 80, scripts={'http-inventory':'reported prefix 172.20.0.0/20'})
        store.upsert_service('10.20.30.2', 80, service='http', product='nginx', scripts={'banner':'nginx'})
        scripts = json.loads(store.query('SELECT scripts FROM ports')[0]['scripts'])
        self.assertIn('http-inventory', scripts)
        self.assertIn('banner', scripts)

    def test_final_report_serializes_evidence_and_total_duration(self):
        from types import SimpleNamespace
        from probe.engine import Engine
        from probe.store import Store
        from probe.planner import Environment, Planner
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(":memory:")
            store.upsert_host('10.20.30.2', mac='02:00:00:00:00:02', method='arp')
            store.update_host('10.20.30.2', verdict='CONFIRMED_ONLINK')
            store.upsert_service('10.20.30.2',80,service='http',scripts={'http-inventory':'reported_prefixes: 172.20.0.0/20'})
            transport = SimpleNamespace(my_ip='10.20.30.1',my_network='10.20.30.0/24',sent=[],sent_out_of_scope=0)
            engine = Engine(ScopeGuard(['10.20.30.0/24']),store,transport,report_dir=Path(tmp))
            ev = Evidence()
            ev.visible['10.20.30.2'].add('arp')
            engine.ingest = SimpleNamespace(ev=ev)
            engine.env = Environment(['10.20.30.0/24'],254,'10.20.30.1','10.20.30.0/24',None,False)
            engine.planner = Planner(engine.env)
            engine.timings['total'] = 12.5
            engine._finish_report()
            result = json.loads((Path(tmp)/'report.json').read_text())
            self.assertEqual(12.5,result['timings']['total'])
            self.assertTrue(any(f['kind']=='reported-service-prefix' for f in result['network_observations']))
            self.assertTrue(result['devices'][0]['services'][0]['observations'])


if __name__ == '__main__':
    unittest.main()
