"""Append-only local audit trail for Vanguard-SIEM analyst actions.

The audit record stores action metadata only; raw telemetry, credentials and tokens
are intentionally excluded. The file is local to the offline deployment.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("VANGUARD_AUDIT_PATH", "vanguard_audit.jsonl"))
MAX_ACTION_LENGTH = 256


def audit_event(action: str, target: str = "", evidence_sha256: str = "") -> str:
    """Append one bounded, integrity-hashed audit record and return its hash."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": str(action)[:MAX_ACTION_LENGTH],
        "target": str(target)[:MAX_ACTION_LENGTH],
        "evidence_sha256": str(evidence_sha256)[:64],
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    line = json.dumps(record, separators=(",", ":")) + "\n"
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return record["record_sha256"]
