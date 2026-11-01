"""Tests for the LLM-driven multi-step console session continuation agent.

Mirrors the local-TCP-server test pattern already used for console_auth / the network vulnerability
agent's socket checks. The LLM call itself is monkeypatched (`_next_line_from_llm`) rather than hitting a
real API, since what's under test here is the session-driving loop, bounds, and deliverable extraction --
not any particular model's behaviour.
"""
from __future__ import annotations

import socket
import threading

from app.agents.network_security import console_session_agent as mod
from app.agents.network_security.console_session_agent import (
    ConsoleTurn,
    run_llm_driven_console_session,
)
from app.core.schemas import AssessmentPolicy, NetworkGraph, NetworkGraphAssetRecord, NetworkGraphServiceRecord
from app.core.scope_guard import ScopeGuard


def _multi_step_server(script: dict[str, bytes], banner: bytes) -> tuple[str, int, threading.Thread]:
    """Starts a TCP server that sends `banner`, then for each received line looks it up (stripped) in
    `script` and sends back the mapped response; unmatched lines get a generic error line. Stops after the
    connection closes or 10 lines, whichever first."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        srv.settimeout(5)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(banner)
                conn.settimeout(5)
                buf = b""
                for _ in range(10):
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" not in buf:
                        continue
                    line, _, buf = buf.partition(b"\n")
                    key = line.decode().strip()
                    response = script.get(key, b"ERR unknown command\r\n")
                    conn.sendall(response)
        except OSError:
            pass
        finally:
            srv.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return "127.0.0.1", port, thread


def _guard() -> ScopeGuard:
    service = NetworkGraphServiceRecord(service_id="HOST-1:9000/tcp", asset_id="HOST-1", port=9000, service_name="console")
    asset = NetworkGraphAssetRecord(asset_id="HOST-1", ip="127.0.0.1", services=[service])
    policy = AssessmentPolicy(allow_single_credential_verification=True, dry_run=False)
    graph = NetworkGraph(scope_id="S", assets=[asset])
    return ScopeGuard(policy, graph)


def test_successful_multi_step_session_reaches_the_flag(monkeypatch):
    """AUTH succeeds, then the LLM-driven loop should send WHOAMI then PIDREQ (stubbed model) and the
    agent must extract the flag-shaped deliverable from the final response without any further steps."""
    script = {
        "AUTH secret123": b"OK authenticated\r\n",
        "WHOAMI": b"user=root session=42\r\n",
        "PIDREQ 42": b"flag{multi_step_console_ok}\r\n",
    }
    host, port, thread = _multi_step_server(script, banner=b"Welcome. Try HELP.\r\n")

    scripted_lines = iter(["WHOAMI", "PIDREQ 42"])

    def fake_llm(transcript: list[ConsoleTurn], *, model: str) -> str | None:
        return next(scripted_lines, None)

    monkeypatch.setattr(mod, "_next_line_from_llm", fake_llm)

    result = run_llm_driven_console_session(
        host, port, b"secret123", asset_id="HOST-1", service_id="HOST-1:9000/tcp", scope_guard=_guard(),
    )
    thread.join(timeout=2)

    assert result.outcome == "completed"
    assert result.extracted_deliverable == "flag{multi_step_console_ok}"
    assert result.steps_taken == 2
    assert result.transcript[0].sent is None  # banner
    assert result.transcript[1].sent == "AUTH secret123"


def test_session_stops_when_llm_says_done(monkeypatch):
    """If the model has nothing documented left to do, it must be able to end the loop early via DONE
    (modelled here as the stub returning None) rather than being forced to exhaust max_steps."""
    script = {"AUTH secret123": b"OK\r\n", "HELP": b"no further commands available\r\n"}
    host, port, thread = _multi_step_server(script, banner=b"Hi\r\n")

    scripted_lines = iter(["HELP"])

    def fake_llm(transcript: list[ConsoleTurn], *, model: str) -> str | None:
        return next(scripted_lines, None)

    monkeypatch.setattr(mod, "_next_line_from_llm", fake_llm)

    result = run_llm_driven_console_session(
        host, port, b"secret123", asset_id="HOST-1", service_id="HOST-1:9000/tcp", scope_guard=_guard(),
    )
    thread.join(timeout=2)

    assert result.outcome == "completed"
    assert result.extracted_deliverable is None
    assert result.steps_taken == 1


def test_session_is_bounded_by_max_steps_even_if_llm_never_stops(monkeypatch):
    """A misbehaving (or legitimately exploratory) model must never be able to run the loop forever --
    max_steps is an absolute ceiling regardless of what every response says."""
    host, port, thread = _multi_step_server({}, banner=b"Hi\r\n")

    def fake_llm(transcript: list[ConsoleTurn], *, model: str) -> str | None:
        return "PING"  # always wants to continue

    monkeypatch.setattr(mod, "_next_line_from_llm", fake_llm)

    result = run_llm_driven_console_session(
        host, port, b"x", asset_id="HOST-1", service_id="HOST-1:9000/tcp", scope_guard=_guard(), max_steps=3,
    )
    thread.join(timeout=2)

    assert result.steps_taken == 3


def test_scope_guard_denial_blocks_the_session_before_any_connection():
    """Exactly like console_auth's own gate: allow_single_credential_verification=False must stop this
    before any socket is even opened."""
    service = NetworkGraphServiceRecord(service_id="HOST-1:9000/tcp", asset_id="HOST-1", port=9000, service_name="console")
    asset = NetworkGraphAssetRecord(asset_id="HOST-1", ip="127.0.0.1", services=[service])
    policy = AssessmentPolicy(allow_single_credential_verification=False, dry_run=False)
    graph = NetworkGraph(scope_id="S", assets=[asset])
    guard = ScopeGuard(policy, graph)

    try:
        run_llm_driven_console_session(
            "127.0.0.1", 1, b"x", asset_id="HOST-1", service_id="HOST-1:9000/tcp", scope_guard=guard,
        )
        assert False, "expected a scope denial"
    except Exception as exc:
        assert "allow_single_credential_verification" in str(exc) or "disabled" in str(exc)


def test_connection_refused_is_reported_honestly():
    guard = _guard()
    result = run_llm_driven_console_session(
        "127.0.0.1", 1, b"x", asset_id="HOST-1", service_id="HOST-1:9000/tcp", scope_guard=guard,
    )
    assert result.outcome in ("connection_refused", "error")
