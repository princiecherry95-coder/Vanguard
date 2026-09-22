"""Regression tests for the local append-only audit trail."""
import json
from pathlib import Path

import audit


def test_audit_record_is_bounded_and_integrity_hashed(tmp_path, monkeypatch):
    path = Path(tmp_path) / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_PATH", path)
    digest = audit.audit_event("TEST_ACTION", "10.0.0.1", "a" * 64)
    row = json.loads(path.read_text(encoding="utf-8").strip())
    assert row["record_sha256"] == digest
    assert row["action"] == "TEST_ACTION"
    assert len(row["target"]) <= audit.MAX_ACTION_LENGTH


def test_audit_never_stores_raw_secret(tmp_path, monkeypatch):
    path = Path(tmp_path) / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_PATH", path)
    audit.audit_event("TEST", "password=secret")
    content = path.read_text(encoding="utf-8")
    assert "secret" not in content


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test(Path("."))
    print("Vanguard-SIEM audit regression suite: PASS")
