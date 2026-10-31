"""Retain the original discovery evidence without treating it as instructions.

The shared graph schema is deliberately left unchanged. Its raw_source_ref
points at this content-addressed envelope, preserving richer Probe records
through graph persistence without granting workers any new permission.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import GraphValidationError


def save_snapshot(raw: dict, *, source: str, scope_id: str) -> Path:
    envelope = {"schema_version": "1.0", "scope_id": scope_id, "source": source, "observation_only": True, "payload": raw}
    encoded = json.dumps(envelope, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 64 * 1024 * 1024:
        raise GraphValidationError("Discovery snapshot exceeds the retention limit")
    digest = hashlib.sha256(encoded).hexdigest()
    directory = Path(settings.evidence_dir) / "discovery_snapshots"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{digest}.json"
    if destination.exists():
        if destination.read_bytes() != encoded:
            raise GraphValidationError("Existing discovery snapshot failed its content hash check") from None
    else:
        # Publish without replacing an existing file. A hard link exposes the
        # complete bytes atomically and avoids Windows sharing violations from
        # concurrent file replacement. Both names are on the same filesystem.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
                temporary = Path(output.name)
                output.write(encoded)
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if destination.read_bytes() != encoded:
                    raise GraphValidationError("Existing discovery snapshot failed its content hash check") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return destination.resolve()


def read_snapshot(path: str | Path) -> dict:
    target = Path(path).resolve()
    root = (Path(settings.evidence_dir) / "discovery_snapshots").resolve()
    if target.parent != root or target.suffix != ".json" or len(target.stem) != 64:
        raise GraphValidationError("Not a retained discovery snapshot reference")
    if target.stat().st_size > 64 * 1024 * 1024:
        raise GraphValidationError("Discovery snapshot exceeds the read limit")
    encoded = target.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != target.stem:
        raise GraphValidationError("Discovery snapshot hash verification failed")
    return json.loads(encoded)
