"""Regression tests for the local append-only audit trail."""
import json
from pathlib import Path
import tempfile

import audit


def test_audit_record_is_bounded_and_integrity_hashed():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        original = audit.AUDIT_PATH
        audit.AUDIT_PATH = path
        try:
            digest = audit.audit_event("TEST_ACTION", "10.0.0.1", "a" * 64)
            row = json.loads(path.read_text(encoding="utf-8").strip())
            assert row["record_sha256"] == digest
            assert row["action"] == "TEST_ACTION"
            assert len(row["target"]) <= audit.MAX_ACTION_LENGTH
        finally:
            audit.AUDIT_PATH = original


def test_audit_never_stores_raw_secret():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        original = audit.AUDIT_PATH
        audit.AUDIT_PATH = path
        try:
            audit.audit_event("TEST", "password=secret")
            content = path.read_text(encoding="utf-8")
            assert "secret" not in content
        finally:
            audit.AUDIT_PATH = original


def main():
    test_audit_record_is_bounded_and_integrity_hashed()
    print("PASS test_audit_record_is_bounded_and_integrity_hashed")
    test_audit_never_stores_raw_secret()
    print("PASS test_audit_never_stores_raw_secret")
    print("Vanguard-SIEM audit regression suite: PASS")


if __name__ == "__main__":
    main()
