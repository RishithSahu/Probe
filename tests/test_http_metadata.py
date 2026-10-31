import json
import unittest
from unittest import mock
from types import SimpleNamespace
from probe.analysis import http_metadata
from probe.authorisation import header_test_grant
from probe.tools import nmap_tool
from probe.scope import ScopeGuard
from probe.store import Store
from probe.discovery.ingest import Ingest
from probe.engine import Engine

class HttpMetadata(unittest.TestCase):
    def record(self,address="0.0.0.0",port=8833):
        return {"ip":"10.20.30.2","port":80,"scripts":{http_metadata.KEY:json.dumps({"resources":[
            {"path":"/wiki/infra","status":"200","title":"Infrastructure","page_text":f"Console service listens on {address}:{port}."}]})}}

    def test_reported_wildcard_binding_is_source_host_not_new_device(self):
        lead = http_metadata.endpoint_leads([self.record()])[0]
        self.assertEqual(("10.20.30.2",8833),(lead["ip"],lead["port"]))
        self.assertEqual("reported-not-yet-probed",lead["state"])
        self.assertEqual("/wiki/infra",lead["source_path"])

    def test_invalid_addresses_and_ports_are_not_leads(self):
        self.assertEqual([],http_metadata.endpoint_leads([self.record("999.1.1.1")]))
        self.assertEqual([],http_metadata.endpoint_leads([self.record(port=65536)]))
        self.assertEqual([],http_metadata.endpoint_leads([self.record("127.0.0.1")]))

    def test_outside_endpoint_is_recorded_but_never_scheduled(self):
        leads = http_metadata.endpoint_leads([self.record("10.99.0.2")])
        with mock.patch.object(nmap_tool,"_extra_stage",return_value={}) as stage:
            nmap_tool.reported_endpoint_inventory(ScopeGuard(["10.20.30.0/24"]),leads)
            self.assertEqual([],stage.call_args.args[1])

    def test_header_grant_is_exact_endpoint_and_validated(self):
        grant = {"method_grants":[{"method":"read-only-proxy-header-test","target_ip":"10.20.30.2","target_port":80,
                 "authority":"operator","reference":"explicit test","header_name":"X-Forwarded-For","header_value":"10.20.30.1","max_requests":12}]}
        self.assertIsNone(header_test_grant(grant,"10.20.30.3",80))
        self.assertIsNone(header_test_grant(grant,"10.20.30.2",81))
        self.assertEqual("10.20.30.1",header_test_grant(grant,"10.20.30.2",80)["header_value"])
        grant["method_grants"][0]["header_value"] = "10.20.30.1\r\nInjected: true"
        with self.assertRaises(ValueError): header_test_grant(grant,"10.20.30.2",80)

    def test_structured_nse_resource_survives_xml_parser(self):
        xml = '<nmaprun><host><address addr="10.20.30.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><script id="http-inventory" output="metadata"><table key="resources"><table><elem key="status">200</elem><elem key="path">/infra</elem><elem key="page_text">Listener 0.0.0.0:8833</elem></table></table></script></port></ports></host></nmaprun>'
        records = nmap_tool.parse_xml(xml)
        self.assertEqual(8833,http_metadata.endpoint_leads(records)[0]["port"])

    def test_engine_promotes_only_successfully_observed_reported_endpoint(self):
        scope=ScopeGuard(["10.20.30.0/24"])
        store=Store(":memory:")
        engine=Engine(scope,store,SimpleNamespace(my_network=None))
        engine.ingest=Ingest(scope,store,"10.20.30.1","02:00:00:00:00:01")
        engine._service_records=[self.record()]
        row={"ip":"10.20.30.2","port":8833,"service":None,"banner":"console banner","scripts":{"banner":"console banner"}}
        result={"results":[("10.20.30.2",[row])],"ran":["10.20.30.2"],"completed":["10.20.30.2"]}
        with mock.patch.object(nmap_tool,"reported_endpoint_inventory",return_value=result):
            engine._reported_endpoint_inventory()
        self.assertEqual(8833,store.hosts()[0]["open_ports"][0]["port"])
        self.assertEqual("console banner",store.hosts()[0]["open_ports"][0]["banner"])
        self.assertTrue(store.leads())


    def test_empty_nse_table_with_whitespace_is_not_a_resource(self):
        xml = '<nmaprun><host><address addr="10.20.30.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><script id="http-inventory" output="no response"><table key="resources">\n</table></script></port></ports></host></nmaprun>'
        record=nmap_tool.parse_xml(xml)[0]
        self.assertEqual([],http_metadata.metadata(record)["resources"])
        self.assertEqual([],http_metadata.endpoint_leads([record]))

    def test_legacy_whitespace_resources_are_normalised(self):
        record={"scripts":{http_metadata.KEY:json.dumps({"resources":"\n"})}}
        self.assertEqual([],http_metadata.metadata(record)["resources"])

    def test_live_inventory_reset_restores_startup_method_grants(self):
        from probe.cli import reset_scan_inventory
        store=Store(":memory:")
        store.upsert_host("10.20.30.2",method="prior-scan")
        store.set_meta("authorisation",{"old_grant":True})
        verified={"scope":["10.20.30.0/24"],"method_grants":[{"id":"verified-method"}]}
        reset_scan_inventory(store,verified)
        self.assertEqual([],store.hosts())
        self.assertEqual(verified,store.meta()["authorisation"])

if __name__=='__main__': unittest.main()
