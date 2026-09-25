"""Append-only local audit trail with hash-chain verification."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("VANGUARD_AUDIT_PATH", "vanguard_audit.jsonl"))
MAX_ACTION_LENGTH = 256
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd)\s*=\s*[^\s,;]+"),
    re.compile(r"(?i)(token|api[_-]?key|secret)\s*=\s*[^\s,;]+"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[^\s,;]+"),
)


def _sanitize_metadata(value: object) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text[:MAX_ACTION_LENGTH]


def _last_hash(path: Path) -> str:
    if not path.exists():
        return ""
    last = ""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                try:
                    last = str(json.loads(line)["record_sha256"])
                except (ValueError, KeyError, TypeError):
                    continue
    return last


def audit_event(action: str, target: str = "", evidence_sha256: str = "") -> str:
    """Append one bounded, sanitized, hash-chained audit record."""
    previous_hash = _last_hash(AUDIT_PATH)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": _sanitize_metadata(action),
        "target": _sanitize_metadata(target),
        "evidence_sha256": str(evidence_sha256)[:64],
        "previous_hash": previous_hash,
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


def verify_audit_chain(path: str | Path | None = None) -> dict[str, object]:
    """Verify record hashes and previous-hash links without changing the trail."""
    target = Path(path) if path else AUDIT_PATH
    if not target.exists():
        return {"valid": True, "records": 0, "error": None}
    previous = ""
    records = 0
    with target.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                stored = record.pop("record_sha256")
                if record.get("previous_hash", "") != previous:
                    return {"valid": False, "records": records, "error": f"previous_hash mismatch at line {line_number}"}
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
                calculated = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if calculated != stored:
                    return {"valid": False, "records": records, "error": f"record hash mismatch at line {line_number}"}
                previous = stored
                records += 1
            except (ValueError, KeyError, TypeError):
                return {"valid": False, "records": records, "error": f"invalid record at line {line_number}"}
    return {"valid": True, "records": records, "error": None, "head": previous}
