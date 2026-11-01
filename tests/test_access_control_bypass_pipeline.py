"""End-to-end regression for the full chain that was missing before: a hidden directory only reachable
with a client-controllable header set to a trusted-looking value, containing a binary that a plain
content-discovery sweep (no such header) would never find at all.

Modelled directly on a real host confirmed on a live lab network this session: a "hidden wiki" only
appeared with X-Forwarded-For set to the network's own gateway address, and that wiki's /vault directory
(a 308 redirect to /vault/) listed a real binary the challenge required reversing. Every piece here is a
local test server, not the real target -- this proves the GENERIC mechanism works, not that one answer.
"""
from __future__ import annotations

import http.server
import threading

import pytest

from app.agents.web_security.content_discovery import discover_hidden_paths, discover_via_trusted_proxy_headers
from app.core.schemas import AssessmentPolicy
from app.core.scope_guard import ScopeGuard

_TRUSTED_VALUE = "10.20.30.1"  # the "likely gateway" heuristic's own derivation from the asset IP below
_ASSET_IP = "10.20.30.50"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        gated = self.headers.get("X-Forwarded-For") == _TRUSTED_VALUE
        if self.path == "/vault" and gated:
            self._send(308, headers={"Location": "/vault/"})
        elif self.path == "/vault/" and gated:
            self._send(200, b'<html><body><a href="keykeeper">keykeeper</a> (14 bytes)</body></html>',
                      headers={"Content-Type": "text/html"})
        elif self.path == "/vault/keykeeper" and gated:
            self._send(200, b"\x7fELF-fake-binary", headers={"Content-Type": "application/octet-stream"})
        elif self.path.startswith("/vault"):
            self._send(404)  # the whole /vault tree genuinely doesn't exist without the header
        elif gated:
            # The real target's own behaviour this reproduces: with the trusted header set, even the ROOT
            # page itself is a different, "internal" page -- that difference (not /vault specifically) is
            # what discover_via_trusted_proxy_headers actually detects.
            self._send(200, b"internal home page", headers={"Content-Type": "text/html"})
        else:
            self._send(200, b"plain home page", headers={"Content-Type": "text/html"})


@pytest.fixture
def gated_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url
    server.shutdown()


def _guard(base_url: str) -> ScopeGuard:
    policy = AssessmentPolicy(allow_content_discovery=True, approved_web_origins=[base_url],
                              approved_asset_ids=["HOST-GATED"], dry_run=False)
    return ScopeGuard(policy)


def test_bypass_probe_finds_the_gated_header_generically(gated_server):
    """discover_via_trusted_proxy_headers must find the winning header/value using only its own generic
    candidate list plus the asset's own IP-derived "likely gateway" heuristic -- no knowledge of this
    specific server's gating logic."""
    result = discover_via_trusted_proxy_headers(
        gated_server + "/", asset_id="HOST-GATED", asset_ip=_ASSET_IP, scope_guard=_guard(gated_server),
        rate_per_second=20,
    )
    assert len(result.hits) == 1
    assert result.hits[0].header == "X-Forwarded-For"
    assert result.hits[0].value == _TRUSTED_VALUE


def test_content_discovery_without_the_header_finds_nothing(gated_server):
    """The control: a plain sweep with no special header must NOT find the vault at all -- proving the
    gating is real and the fix below is actually necessary, not redundant with the existing sweep."""
    result = discover_hidden_paths(
        gated_server + "/", asset_id="HOST-GATED", scope_guard=_guard(gated_server),
        max_requests=60, rate_per_second=20, wordlist=("vault",),
    )
    assert result.binary_references == []


def test_content_discovery_under_the_gated_header_finds_the_binary_through_the_listing(gated_server):
    """The actual fix: once content discovery is re-run WITH the winning header, it must not just see the
    /vault redirect and stop -- it has to follow that one redirect, read the directory listing, and check
    the binary link inside it. This is the exact chain that found a real binary on a real lab host this
    session, reproduced here against a local server so it's verified every run, not just once by hand."""
    result = discover_hidden_paths(
        gated_server + "/", asset_id="HOST-GATED", scope_guard=_guard(gated_server),
        max_requests=60, rate_per_second=20, wordlist=("vault",),
        extra_headers={"X-Forwarded-For": _TRUSTED_VALUE},
    )
    assert len(result.binary_references) == 1
    ref = result.binary_references[0]
    assert ref.url == gated_server + "/vault/keykeeper"
    assert ref.content_type == "application/octet-stream"
