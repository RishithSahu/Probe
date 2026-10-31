"""Shared pytest fixtures: a local synthetic HTTP server (no external network
access, no organisational targets) used by Web Agent tests, a loaded sample
NetworkGraph, and a helper for standing up Probe's real FastAPI app for the
Probe-integration test files."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.adapters.network_graph_adapter import JSONFileNetworkGraphSource, load_network_graph

FIXTURE_GRAPH = Path(__file__).parent / "fixtures" / "network_graphs" / "sample_graph.json"


def start_probe_test_server(app) -> tuple:
    """Starts Probe's FastAPI `app` with uvicorn on a free port in a
    background thread, and returns (server, base_url) once it's actually
    answering requests — not merely once `server.started` is True.

    `server.started` becomes True as soon as uvicorn's own startup sequence
    finishes, which is a brief moment *before* the OS-level listen socket
    reliably accepts every connection attempt. Polling that flag alone was
    an observed source of flaky `ConnectionRefusedError`s / empty responses
    when the suite ran under load (e.g. right after another test-heavy
    file) — this function additionally retries a real HTTP request before
    declaring the server ready, which removed the flakiness in practice.
    Caller is responsible for `server.should_exit = True` + joining its
    thread on teardown.
    """
    import urllib.error
    import urllib.request

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        raise RuntimeError("probe test server did not report started in time")

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{base_url}/api/status", timeout=1)
            return server, thread, base_url
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"probe test server never answered a real request: {last_error}")


def stop_probe_test_server(server, thread: threading.Thread) -> None:
    server.should_exit = True
    thread.join(timeout=5)


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
