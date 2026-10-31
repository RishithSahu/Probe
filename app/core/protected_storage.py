"""Protected storage for recovered sensitive values (credentials, keys).

A recovered value is written here and NEVER returned from `store_secret` or embedded anywhere else --
callers get back only an opaque `credential_ref`. Every other part of this application (Finding,
Evidence, AgentResult, orchestrator events, console output, JSON/PDF reports) must carry that reference,
never the value. `retrieve_secret` is the one deliberate exception, and it is not wired to anything that
runs automatically -- see app/orchestrator/nodes.py's authorised-access task, which stays BLOCKED until a
person calls it.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings

_DIR_NAME = "credentials"


@dataclass(frozen=True)
class CredentialProvenance:
    source_binary_sha256: str
    source_url: str | None
    function_name: str | None
    function_address: str | None
    extraction_method: str
    confidence: str
    limitations: str
    associated_service_id: str | None


def _store_dir() -> Path:
    d = Path(settings.evidence_dir) / _DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def store_secret(value: bytes | str, provenance: CredentialProvenance) -> str:
    """Writes `value` to a file named only by a fresh, unguessable id, with provenance kept in a SEPARATE
    metadata file (so even the metadata file never needs to carry the value). Returns the `credential_ref`
    -- the only thing safe to attach to an ordinary Finding/Evidence/event."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    credential_ref = f"CRED-{uuid.uuid4().hex[:16].upper()}"
    secret_path = _store_dir() / f"{credential_ref}.secret"
    meta_path = _store_dir() / f"{credential_ref}.meta.json"

    secret_path.write_bytes(value)
    try:  # best-effort on platforms that support POSIX permission bits
        os.chmod(secret_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    meta_path.write_text(json.dumps({
        "credential_ref": credential_ref, "stored_at": datetime.now(timezone.utc).isoformat(),
        "byte_length": len(value), "source_binary_sha256": provenance.source_binary_sha256,
        "source_url": provenance.source_url, "function_name": provenance.function_name,
        "function_address": provenance.function_address, "extraction_method": provenance.extraction_method,
        "confidence": provenance.confidence, "limitations": provenance.limitations,
        "associated_service_id": provenance.associated_service_id,
    }, indent=2), encoding="utf-8")
    return credential_ref


def retrieve_secret(credential_ref: str) -> bytes:
    """The one deliberate exception to 'never expose the value'. Nothing in this codebase calls this
    automatically -- it exists for a human-approved, separately authorised access workflow only."""
    path = _store_dir() / f"{credential_ref}.secret"
    if not path.exists():
        raise KeyError(f"no stored credential for ref {credential_ref!r}")
    return path.read_bytes()


def get_provenance(credential_ref: str) -> dict:
    path = _store_dir() / f"{credential_ref}.meta.json"
    if not path.exists():
        raise KeyError(f"no stored credential metadata for ref {credential_ref!r}")
    return json.loads(path.read_text(encoding="utf-8"))
