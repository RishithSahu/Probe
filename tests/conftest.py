"""Shared pytest fixtures: a local synthetic HTTP server (no external network
access, no organisational targets) used by Web Agent tests, a loaded sample
NetworkGraph, and a helper for standing up Probe's real FastAPI app for the
Probe-integration test files.

INCIDENT (2026-11-01): an earlier version of this file deleted `evidence/ape.db` -- the SAME path a real,
live assessment uses -- at the start of every pytest session, to work around stale-schema failures after a
migration landed. That autouse fixture ran AFTER `app.database.session` had already been imported (by the
`from app.adapters...` import a few lines below, among others), and that module builds its SQLAlchemy
engine from `settings.database_url` at MODULE IMPORT TIME -- so even monkeypatching `settings` inside a
fixture body is too late to redirect it. The result: every test run shared, and could destroy, the one
real production database. `ASSESSMENT-CREDENTIAL-ACCESS-397A` and its task/finding history were lost this
way.

The fix has two independent layers, so one of them failing cannot repeat the incident:
  1. Below, BEFORE any `app.*` import (the actual bug): every writable path pytest's own config/session
     code will ever touch is redirected into a fresh, unique temp root via environment variables, read by
     app.core.config.Settings exactly like a real deployment's own env-based config -- no test-only branch
     in application code, no "if running under pytest" special-casing there.
  2. app/database/session.py itself now refuses, at import time, to bind to the real evidence/ape.db path
     while pytest is the process running it (`"pytest" in sys.modules`) -- a second, independent guard in
     case anything ever imports that module before this file's env vars are set.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

# ---------------------------------------------------------------------------------------------------------
# MUST run before any `app.*` import anywhere in this file (or any test file pytest collects, since this
# conftest.py is imported first). A unique root per pytest session AND per xdist worker (pytest-xdist sets
# PYTEST_XDIST_WORKER before this file loads; its absence -- the normal, non-distributed case -- still
# gets a fresh uuid4-suffixed root every run, never a fixed path two sessions could collide on).
# ---------------------------------------------------------------------------------------------------------
import uuid  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if "app.core.config" in sys.modules and not os.environ.get("APE_TEST_ROOT"):
    raise RuntimeError("Application configuration was imported before pytest isolation; start a fresh test process")

_worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
_TEST_ROOT = Path(tempfile.gettempdir()) / "ape-pytest" / f"{_worker}-{uuid.uuid4().hex[:12]}"
_TEST_ROOT.mkdir(parents=True, exist_ok=True)
os.environ["APE_TEST_ROOT"] = str(_TEST_ROOT)
os.environ["APE_ENVIRONMENT"] = "test"
os.environ["APE_DATABASE_URL"] = f"sqlite:///{(_TEST_ROOT / 'ape-test.db').as_posix()}"
os.environ["APE_EVIDENCE_DIR"] = str(_TEST_ROOT / "evidence")
os.environ["APE_REPORTS_DIR"] = str(_TEST_ROOT / "evidence" / "reports")
os.environ["APE_GHIDRA_PROJECT_DIR"] = str(_TEST_ROOT / "ghidra_projects")
os.environ["APE_INPUTS_DIR"] = str(_TEST_ROOT / "inputs")
os.environ["APE_NETWORK_GRAPH_DIR"] = str(_TEST_ROOT / "inputs" / "network_graphs")
os.environ["APE_BINARIES_DIR"] = str(_TEST_ROOT / "inputs" / "binaries")

import pytest  # noqa: E402

from app.adapters.network_graph_adapter import JSONFileNetworkGraphSource, load_network_graph  # noqa: E402
from app.core.config import settings  # noqa: E402

FIXTURE_GRAPH = Path(__file__).parent / "fixtures" / "network_graphs" / "sample_graph.json"


def assert_database_url_is_safe() -> None:
    """A plain assertion helper imported and run by tests/test_db_isolation.py, kept here so it executes
    against the SAME `settings` object this conftest's own env vars configured, rather than re-deriving
    the check from scratch."""
    from app.database.safety import assert_test_database
    assert_test_database(settings.database_url)
    for path in (settings.evidence_dir, settings.reports_dir, settings.inputs_dir,
                 settings.binaries_dir, settings.network_graph_dir, settings.ghidra_project_dir):
        assert path.resolve().is_relative_to(_TEST_ROOT.resolve())


assert_database_url_is_safe()


def pytest_configure(config):
    # tmp_path outputs must share this invocation's private data boundary too.
    config.option.basetemp = str(_TEST_ROOT / "pytest")


def _production_fingerprint():
    import hashlib
    original = Path(__file__).resolve().parents[1] / "evidence"
    result = {}
    if original.exists():
        for path in original.rglob("*"):
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as stream:
                    result[str(path)] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def pytest_sessionstart(session):
    assert_database_url_is_safe()
    session._production_evidence_before = _production_fingerprint()


def pytest_sessionfinish(session, exitstatus):
    if _production_fingerprint() != session._production_evidence_before:
        session.exitstatus = 1
        print("INCIDENT: original evidence changed during tests; stop and preserve artifacts")
        return
    from app.database.safety import remove_test_workspace
    remove_test_workspace(_TEST_ROOT)


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
