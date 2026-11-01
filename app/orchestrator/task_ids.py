"""Bounded, deterministic task identifiers.

Every call site used to build a `task_id` by string-concatenating an assessment_id, a service_id, a
credential_ref, etc. directly (`f"TASK-{agent}-{assessment_id}-{service_id}"`). With real-length inputs
(e.g. `ASSESSMENT-CREDENTIAL-ACCESS-397A` + `192.168.60.139:8833/tcp`) that routinely exceeds the
`task_id` column's `String(64)` limit -- SQLite never enforces a VARCHAR length so this was silent there,
but it breaks outright on the documented Postgres swap-in. `make_task_id` fixes the ROOT CAUSE once: it
hashes the full, human-readable fingerprint into a fixed-width id and returns the fingerprint separately so
nothing loses the readability/filterability the old concatenated ids had -- callers store the fingerprint
in `AgentTask.task_fingerprint`.
"""
from __future__ import annotations

import hashlib

MAX_TASK_ID_LENGTH = 64


def make_task_id(*parts: str) -> tuple[str, str]:
    """Returns (task_id, fingerprint). `task_id` is stable for the same `parts` (so re-deriving it, e.g. to
    look up an existing task, never needs a second source of truth) and always fits `MAX_TASK_ID_LENGTH`.
    `fingerprint` is the full, readable "-".join(parts) for logs, dedup display, and debugging."""
    fingerprint = "-".join(str(p) for p in parts)
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:24]
    prefix = parts[0][:20] if parts else "TASK"
    task_id = f"T-{prefix}-{digest}"
    return task_id[:MAX_TASK_ID_LENGTH], fingerprint
