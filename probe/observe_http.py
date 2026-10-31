"""Bounded service-observation diagnostic using the engine's HTTP technique and full egress attestation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from . import authorisation, egress, fence
from .audit import Attestation
from .net.transport import GuardedTransport
from .scope import ScopeGuard
from .territory import Territory, require_in_territory
from .tools import nmap_tool


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--target', required=True)
    ap.add_argument('--header-test', action='store_true')
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--seed-report', required=True)
    ap.add_argument('--data-dir', required=True)
    ap.add_argument('--scope-file', default='probe-scope.txt')
    ap.add_argument('--authorisations', default='authorisations.json')
    a = ap.parse_args()
    data = Path(a.data_dir).resolve()
    data.mkdir(parents=True, exist_ok=True)
    started = time.time()
    cidrs = [part for line in Path(a.scope_file).read_text().splitlines()
             for part in line.split('#')[0].split()]
    grant = authorisation.verify(Path(a.authorisations), cidrs)
    scope = ScopeGuard(cidrs)
    test = authorisation.header_test_grant(grant,a.target,a.port) if a.header_test else None
    if a.header_test and test is None:
        raise ValueError('no explicit header-test grant for this exact endpoint')
    if not scope.in_scope(a.target):
        raise ValueError('target is outside the explicitly authorised scope')
    seed_path = Path(a.seed_report)
    seed_bytes = seed_path.read_bytes()
    seed = json.loads(seed_bytes)
    known = any(a.target in d['addresses'] and any(p['port'] == a.port and p.get('proto','tcp') == 'tcp'
                    for p in d['services']) for d in seed['devices'])
    if not known:
        raise ValueError('diagnostic requires an already-observed TCP endpoint in the seed report')
    nmap = nmap_tool.find_nmap()
    if not nmap:
        raise RuntimeError('nmap unavailable')
    policy_path = data/'egress-policy.json'
    egress.create_policy(policy_path, nmap, cidrs)
    ok, why = egress.check(policy_path)
    if not ok:
        raise RuntimeError('independent egress not verified: '+why)
    t = GuardedTransport(scope)
    t.prepare()
    require_in_territory(scope, t.my_ip)
    territory = Territory(scope,t.my_ip,if_index=t.if_index,iface_name=t.iface)
    ok,why = territory.check()
    if not ok:
        raise RuntimeError('territory not verified: '+why)
    token = uuid.uuid4().hex
    att = Attestation(data,scope_digest=grant['scope_digest'],run_id=token)
    aud = subprocess.Popen([sys.executable,'-m','probe.audit','--iface',str(t.iface),'--mac',t.my_mac,
        '--scope',*cidrs,'--state',str(data),'--pid',str(os.getpid()),'--ip',t.my_ip,
        '--ifindex',str(t.if_index or 0),'--iface-name',str(t.iface),'--run-id',token,
        '--egress-policy',str(policy_path)],creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        until = time.monotonic()+20
        while time.monotonic()<until and aud.poll() is None and not att.check()[0]:
            time.sleep(.25)
        ok,why = att.check()
        if not ok:
            raise RuntimeError('independent auditor unavailable: '+why)
        nmap_tool.configure_egress(att.check)
        fence.install()
        result = nmap_tool.http_inventory(scope,{a.target:[a.port]},budget_s=50,workdir=str(data/'nmap'),trace=True,header_tests={a.target:test} if test else None)
        from .analysis.http_metadata import endpoint_leads
        records = [r for _,rows in result["results"] for r in rows]
        leads = endpoint_leads(records)
        endpoints = nmap_tool.reported_endpoint_inventory(scope,leads,budget_s=25,workdir=str(data/'nmap'))
        ok,why = att.check()
        if not ok:
            raise RuntimeError('audit not healthy at completion: '+why)
        record = {'status':'observed' if any(rows for _,rows in result['results']) else 'no-service-response','scope':cidrs,'authorisation':grant,'target':a.target,'port':a.port,
            'source_report':str(seed_path.resolve()),'source_sha256':hashlib.sha256(seed_bytes).hexdigest(),
            'seconds':round(time.time()-started,3),'endpoint_leads':leads,'endpoint_results':endpoints,'result':result,'independent_audit':att.wire_summary(),
            'method_grant':test,'raw_probes_sent':len(t.sent),'new_ranges_scanned':[]}
        (data/'observation.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
        print(json.dumps(record,indent=2))
    finally:
        if aud.poll() is None:
            aud.terminate()
        aud.wait(timeout=8)


if __name__=='__main__':
    main()
