"""Single-credential verification against a line-oriented TCP console service.

This performs exactly one authentication attempt with an already-recovered credential (never a guess, never
a candidate list) against a service already present in the authorised `NetworkGraph`. It is gated by
`ScopeGuard.check_console_auth_allowed`, which is its own policy flag
(`allow_single_credential_verification`) distinct from ordinary read-only service assessment -- submitting a
credential is a materially different, higher-risk action.

The protocol here is generic (connect, read a banner, send one line, read the response) because this
service's own banner is itself the thing identifying the expected command -- not something to hardcode.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

from app.core.scope_guard import ScopeGuard

_CONNECT_TIMEOUT_SECONDS = 8.0
_READ_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 8192


@dataclass
class ConsoleAuthResult:
    service_id: str
    outcome: str  # "connected_response_received" | "connection_refused" | "timeout" | "error"
    banner: str = ""
    response: str = ""
    error: str | None = None
    duration_seconds: float = 0.0
    credential_bytes_sent: int = 0


def _recv_all(sock: socket.socket, *, timeout: float, max_bytes: int) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    try:
        while total < max_bytes and time.monotonic() < deadline:
            chunk = sock.recv(min(4096, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def attempt_single_credential_verification(
    host: str, port: int, credential: bytes, *, asset_id: str, service_id: str,
    scope_guard: ScopeGuard, auth_command: str = "AUTH",
) -> ConsoleAuthResult:
    """Connects once, reads the service's own banner, sends `auth_command` followed by the credential as a
    single line, and reads the response. The credential is held only in this function's local variables and
    on the wire to the evidenced target -- never logged, never returned in `ConsoleAuthResult` (only its
    byte length is), never written anywhere by this function."""
    scope_guard.check_console_auth_allowed(asset_id, service_id)

    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(_CONNECT_TIMEOUT_SECONDS)
        sock.connect((host, port))
        banner = _recv_all(sock, timeout=_READ_TIMEOUT_SECONDS, max_bytes=_MAX_RESPONSE_BYTES)
        line = f"{auth_command} {credential.decode('utf-8', errors='replace')}\n".encode()
        sock.sendall(line)
        response = _recv_all(sock, timeout=_READ_TIMEOUT_SECONDS, max_bytes=_MAX_RESPONSE_BYTES)
        return ConsoleAuthResult(
            service_id=service_id, outcome="connected_response_received",
            banner=banner, response=response, duration_seconds=time.monotonic() - start,
            credential_bytes_sent=len(credential),
        )
    except ConnectionRefusedError as exc:
        return ConsoleAuthResult(service_id=service_id, outcome="connection_refused", error=str(exc),
                                 duration_seconds=time.monotonic() - start)
    except socket.timeout as exc:
        return ConsoleAuthResult(service_id=service_id, outcome="timeout", error=str(exc),
                                 duration_seconds=time.monotonic() - start)
    except OSError as exc:
        return ConsoleAuthResult(service_id=service_id, outcome="error", error=str(exc),
                                 duration_seconds=time.monotonic() - start)
    finally:
        sock.close()
