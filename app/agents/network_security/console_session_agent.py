"""LLM-driven continuation of an authenticated line-oriented TCP console session.

`console_auth.attempt_single_credential_verification` deliberately stops after exactly one AUTH attempt --
"makes exactly one authentication attempt... never a loop," by design, because that function's whole job
is single-credential VERIFICATION, not session completion. Some real services, once authenticated, expect
a further, SERVICE-SPECIFIC sequence of commands before they hand over whatever they are gating (a
documented multi-step protocol with its own HELP text, its own session state, its own arithmetic) -- there
is no generic, hardcodable set of next commands for that, because every such service's protocol is its own.

This module is the generic answer to that: after AUTH succeeds, it hands the growing transcript to an LLM
and asks, each turn, for exactly one line to send next (or DONE), so the service's OWN documentation (its
banner, its HELP output, whatever it says) drives what happens next -- nothing here is written for one
target's specific protocol. Bounded by both a step count and a wall-clock budget regardless of what the
model decides, and the only external action it can take is "send this one line to the already-scoped,
already-authorised socket" -- never a tool call, never a file write, never a second connection.

Same safety posture and gating as console_auth.py: `ScopeGuard.check_console_auth_allowed` (the
`allow_single_credential_verification` policy flag), and this is never invoked automatically by the
scheduler -- only through `execute_console_session` in app/orchestrator/nodes.py, which requires an
explicit, recorded operator instruction, exactly like `execute_authorised_credential_access`.
"""
from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass, field

from app.core.scope_guard import ScopeGuard

logger = logging.getLogger("ape.console_session_agent")

_CONNECT_TIMEOUT_SECONDS = 8.0
_READ_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 8192
_DEFAULT_MAX_STEPS = 10
_DEFAULT_OVERALL_TIMEOUT_SECONDS = 90.0
_DEFAULT_MODEL = "gpt-4o-mini"

# A generic "this looks like the deliverable" pattern -- WORD{...}, the near-universal shape for a CTF-style
# flag, and the same kind of shape other "here is your token/secret" responses take. Matching this is a
# signal to stop early and report it, never a requirement for the session to be considered successful.
_DELIVERABLE_PATTERN = re.compile(r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]{2,300}\}")

_SYSTEM_PROMPT = (
    "You are continuing an ALREADY-AUTHENTICATED session with a line-oriented text console over a raw TCP "
    "socket, on a system the operator has explicit authorisation to test. You have just sent one "
    "authentication command and it was accepted. The transcript so far (everything sent and received) is "
    "given to you below.\n\n"
    "Your task: read the console's OWN documentation of itself (its banner, and its HELP output if you "
    "have not yet requested it) and follow exactly what it describes, one command at a time, to reach "
    "whatever it says is the result of doing so correctly (a confirmation, a resource, a value it names). "
    "If the protocol describes a piece of required arithmetic (e.g. a checksum derived from values the "
    "console already gave you), compute it yourself from the values already visible in the transcript and "
    "include the result in the command you send -- do not ask the service to compute it for you, and do "
    "not guess a value you have not been given a way to derive.\n\n"
    "Rules:\n"
    "- Reply with EXACTLY the single line to send next, nothing else -- no quotes, no explanation, no "
    "markdown.\n"
    "- Never guess a password, key, or credential; never attempt the same command repeatedly expecting a "
    "different result; never send more than the single documented command you intend to run.\n"
    "- If you don't yet know the console's own command reference, request it (e.g. a HELP-style command) "
    "before trying anything else.\n"
    "- If the transcript already shows the goal was reached, or you have no further documented step to "
    "take, reply with exactly: DONE"
)


@dataclass
class ConsoleTurn:
    sent: str | None  # None for the initial banner read
    received: str


@dataclass
class ConsoleSessionResult:
    service_id: str
    outcome: str  # "completed" | "auth_failed" | "connection_refused" | "timeout" | "error" | "llm_unavailable"
    transcript: list[ConsoleTurn] = field(default_factory=list)
    extracted_deliverable: str | None = None
    steps_taken: int = 0
    error: str | None = None
    duration_seconds: float = 0.0


_TRAILING_CHUNK_GRACE_SECONDS = 0.2


def _recv_all(sock: socket.socket, *, timeout: float, max_bytes: int) -> str:
    """Waits up to `timeout` for the FIRST chunk (the peer may be slow to answer at all), then only a short
    grace period for any further chunks already in flight behind it -- waiting the full `timeout` again
    after each chunk would mean every read takes as long as the slowest possible reply, even once the
    reply has fully arrived, which stalls a multi-step session by `timeout` seconds per step for nothing."""
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    sock.settimeout(timeout)
    try:
        while total < max_bytes and time.monotonic() < deadline:
            chunk = sock.recv(min(4096, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            sock.settimeout(_TRAILING_CHUNK_GRACE_SECONDS)
    except socket.timeout:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def _format_transcript(transcript: list[ConsoleTurn]) -> str:
    lines = []
    for turn in transcript:
        if turn.sent is not None:
            lines.append(f">>> {turn.sent}")
        lines.append(turn.received)
    return "\n".join(lines)


def _next_line_from_llm(transcript: list[ConsoleTurn], *, model: str) -> str | None:
    """Returns the next line to send, or None on DONE / any LLM-unavailable condition (never raises --
    the caller treats None as "stop here" either way, which is the safe default)."""
    try:
        import openai
    except ImportError:
        logger.warning("console_session_agent: openai package not installed; cannot continue the session")
        return None
    try:
        client = openai.OpenAI()
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _format_transcript(transcript)},
            ],
            max_tokens=200, temperature=0,
        )
        text = (resp.choices[0].message.content or "").strip()
    except Exception as exc:  # noqa: BLE001 - an LLM/API failure must stop the session cleanly, not crash it
        logger.warning("console_session_agent: LLM call failed: %s", exc)
        return None
    if not text or text.upper() == "DONE":
        return None
    return text.splitlines()[0].strip()  # exactly one line, even if the model added more


def run_llm_driven_console_session(
    host: str, port: int, credential: bytes, *, asset_id: str, service_id: str, scope_guard: ScopeGuard,
    auth_command: str = "AUTH", max_steps: int = _DEFAULT_MAX_STEPS,
    overall_timeout_seconds: float = _DEFAULT_OVERALL_TIMEOUT_SECONDS, model: str = _DEFAULT_MODEL,
) -> ConsoleSessionResult:
    """Connects once, authenticates once (exactly like console_auth.attempt_single_credential_verification),
    then -- only if that succeeds -- continues the SAME session turn by turn under an LLM's direction,
    bounded by `max_steps` and `overall_timeout_seconds` regardless of what the model decides. The
    credential is held only in this function's local variables and on the wire to the evidenced target --
    never logged, never placed in the returned result (the transcript records what was SENT as the AUTH
    line's own text, which is unavoidable since it includes the credential; callers persisting this result
    must treat the first turn's `sent` field with the same care as any other credential-bearing evidence)."""
    scope_guard.check_console_auth_allowed(asset_id, service_id)
    start = time.monotonic()
    deadline = start + overall_timeout_seconds
    transcript: list[ConsoleTurn] = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(_CONNECT_TIMEOUT_SECONDS)
        sock.connect((host, port))
        banner = _recv_all(sock, timeout=_READ_TIMEOUT_SECONDS, max_bytes=_MAX_RESPONSE_BYTES)
        transcript.append(ConsoleTurn(sent=None, received=banner))

        auth_line = f"{auth_command} {credential.decode('utf-8', errors='replace')}"
        sock.sendall((auth_line + "\n").encode())
        auth_response = _recv_all(sock, timeout=_READ_TIMEOUT_SECONDS, max_bytes=_MAX_RESPONSE_BYTES)
        transcript.append(ConsoleTurn(sent=auth_line, received=auth_response))

        steps_taken = 0
        extracted = None
        m = _DELIVERABLE_PATTERN.search(auth_response)
        if m:
            extracted = m.group(0)
        else:
            while steps_taken < max_steps and time.monotonic() < deadline:
                next_line = _next_line_from_llm(transcript, model=model)
                if next_line is None:
                    break
                sock.sendall((next_line + "\n").encode())
                response = _recv_all(sock, timeout=_READ_TIMEOUT_SECONDS, max_bytes=_MAX_RESPONSE_BYTES)
                transcript.append(ConsoleTurn(sent=next_line, received=response))
                steps_taken += 1
                m = _DELIVERABLE_PATTERN.search(response)
                if m:
                    extracted = m.group(0)
                    break

        return ConsoleSessionResult(
            service_id=service_id, outcome="completed", transcript=transcript,
            extracted_deliverable=extracted, steps_taken=steps_taken, duration_seconds=time.monotonic() - start,
        )
    except ConnectionRefusedError as exc:
        return ConsoleSessionResult(service_id=service_id, outcome="connection_refused", transcript=transcript,
                                    error=str(exc), duration_seconds=time.monotonic() - start)
    except socket.timeout as exc:
        return ConsoleSessionResult(service_id=service_id, outcome="timeout", transcript=transcript,
                                    error=str(exc), duration_seconds=time.monotonic() - start)
    except OSError as exc:
        return ConsoleSessionResult(service_id=service_id, outcome="error", transcript=transcript,
                                    error=str(exc), duration_seconds=time.monotonic() - start)
    finally:
        sock.close()
