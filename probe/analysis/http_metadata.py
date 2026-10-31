"""Interpret structured service metadata as attributed leads, never as scope grants."""
from __future__ import annotations
import html
import ipaddress
import json
import re

KEY = "probe-http-metadata"
ENDPOINT = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")


def xml_value(node):
    children = list(node)
    if not children:
        return [] if node.tag == "table" else (node.text or "")
    if all(c.get("key") is not None for c in children):
        return {c.get("key"):xml_value(c) for c in children}
    if all(c.get("key") is None for c in children):
        return [xml_value(c) for c in children]
    return {**{c.get("key"):xml_value(c) for c in children if c.get("key")},
            "items":[xml_value(c) for c in children if c.get("key") is None]}


def metadata(record):
    scripts = record.get("scripts") or {}
    if isinstance(scripts,str):
        scripts = json.loads(scripts)
    data = scripts.get(KEY) or {}
    if isinstance(data,str):
        data = json.loads(data)
    if not isinstance(data,dict):
        return {}
    resources = data.get("resources") or []
    if isinstance(resources,dict) and "path" in resources:
        resources = [resources]
    data["resources"] = [r for r in resources if isinstance(r,dict)] if isinstance(resources,list) else []
    return data


def endpoint_leads(records):
    leads = {}
    for r in records:
        data = metadata(r)
        resources = data.get("resources") or []
        if not isinstance(resources,list):
            continue
        for resource in resources:
            if str(resource.get("status")) != "200":
                continue
            text = html.unescape(resource.get("page_text") or "")
            for address, raw_port in ENDPOINT.findall(text):
                try:
                    addr = ipaddress.IPv4Address(address)
                    port = int(raw_port)
                    if not 1 <= port <= 65535 or addr.is_multicast or addr.is_loopback:
                        continue
                except ValueError:
                    continue
                target = r["ip"] if addr.is_unspecified else str(addr)
                basis = "service-reported all-interface binding on the source host" if addr.is_unspecified else "service-referenced endpoint"
                key = (target,port)
                leads[key] = {"ip":target,"port":port,"proto":"tcp","state":"reported-not-yet-probed",
                    "source_ip":r["ip"],"source_port":r["port"],"source_path":resource.get("path"),
                    "source_title":resource.get("title"),"basis":basis,"evidence":text[:8192]}
    return list(leads.values())
