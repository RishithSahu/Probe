"""Shared pytest fixtures: a local synthetic HTTP server (no external network
access, no organisational targets) used by Web Agent tests, and a loaded
sample NetworkGraph."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.adapters.network_graph_adapter import JSONFileNetworkGraphSource, load_network_graph

FIXTURE_GRAPH = Path(__file__).parent / "fixtures" / "network_graphs" / "sample_graph.json"


class _SynthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence test output
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/redirect-out-of-scope":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/evil")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Deliberately missing security headers + an insecure cookie, so Web
        # Agent fingerprint-derived finding logic has something to detect.
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><body>synthetic lab app</body></html>")


@pytest.fixture(scope="session")
def synthetic_web_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SynthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url
    server.shutdown()


@pytest.fixture
def sample_graph():
    return load_network_graph(JSONFileNetworkGraphSource(FIXTURE_GRAPH))
