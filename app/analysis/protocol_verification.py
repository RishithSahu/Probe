"""Replay bounded, endpoint-bound protocol evidence without sending traffic.

These rules prove narrowly described observations. They do not establish
arbitrary data access, server configuration, privileges, or an attack transition.
"""
from __future__ import annotations

import ipaddress
import re

from app.agents.network_vulnerability.wire import verify_transcript
from app.core.schemas import AgentId, Evidence, Finding, Surface


def supports_protocol_observation(finding: Finding, evidence: Evidence) -> bool:
    data = evidence.raw_data or {}
    if (evidence.source_tool != "network_vulnerability_detective"
            or finding.agent_id != AgentId.NETWORK_VULNERABILITY_DETECTIVE
            or finding.surface != Surface.NETWORK or data.get("used_fixture")
            or data.get("asset_id") != finding.asset_id or data.get("service_id") != finding.service_id
            or not finding.asset_id or not finding.service_id):
        return False
    method = finding.detection_method or ""
    if evidence.evidence_type != method:
        return False
    wire = data.get("wire")
    if not isinstance(wire, dict):
        return False
    decoded = verify_transcript(wire)
    if decoded is None:
        return False
    try:
        ipaddress.ip_address(wire["ip"])
    except ValueError:
        return False
    request, response = decoded
    if method == "network_vulnerability:ssh_protocol_version":
        return (wire["protocol"] == "ssh" and not request and len(response) <= 255
                and re.fullmatch(rb"SSH-1\.(?:3|5)-[!-~]+(?: [ -~]*)?\r?\n", response) is not None)
    if method == "network_vulnerability:redis_auth_check":
        if wire["protocol"] != "redis" or request != b"PING\r\nINFO server\r\n" or not response.startswith(b"+PONG\r\n$"):
            return False
        header, separator, payload = response[8:].partition(b"\r\n")
        if not separator or not header.isdigit() or len(payload) != int(header) + 2 or not payload.endswith(b"\r\n"):
            return False
        return re.search(rb"(?m)^redis_version:[0-9]+\.[0-9]+[^\r\n]*\r?$", payload[:-2]) is not None
    if method == "network_vulnerability:postgresql_auth_check":
        if wire["protocol"] != "postgresql" or len(request) < 9 or int.from_bytes(request[:4], "big") != len(request):
            return False
        if request[4:8] != (196608).to_bytes(4, "big") or not request.endswith(b"\x00\x00"):
            return False
        pairs = request[8:-1].split(b"\x00")[:-1]
        if len(pairs) != 4 or set(pairs[::2]) != {b"user", b"database"} or any(not part for part in pairs):
            return False
        return response == b"R\x00\x00\x00\x08\x00\x00\x00\x00Z\x00\x00\x00\x05I"
    if method == "network_vulnerability:ftp_anonymous_login":
        if wire["protocol"] != "ftp":
            return False
        commands = request.splitlines(keepends=True)
        if commands not in ([b"USER anonymous\r\n"], [b"USER anonymous\r\n", b"PASS anonymous@example.invalid\r\n"]):
            return False
        lines = iter(response.splitlines(keepends=True))

        def reply():
            first = next(lines)
            if len(first) < 5 or not first[:3].isdigit() or first[3:4] not in (b" ", b"-"):
                return None
            if first[3:4] == b"-":
                for _ in range(63):
                    if next(lines).startswith(first[:3] + b" "):
                        return first[:3]
                return None
            return first[:3]

        try:
            if reply() != b"220":
                return False
            if len(commands) == 1:
                valid = reply() == b"230"
            else:
                valid = reply() == b"331" and reply() == b"230"
            return valid and next(lines, None) is None
        except StopIteration:
            return False
    return False
