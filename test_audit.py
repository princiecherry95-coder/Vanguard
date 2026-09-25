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
            digest2 = audit.audit_event("SECOND_ACTION", "10.0.0.2")
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            assert rows[-1]["record_sha256"] == digest2
            assert rows[0]["record_sha256"] == digest
            assert rows[1]["previous_hash"] == digest
            assert rows[0]["action"] == "TEST_ACTION"
            assert len(rows[0]["target"]) <= audit.MAX_ACTION_LENGTH
            verification = audit.verify_audit_chain(path)
            assert verification["valid"] and verification["records"] == 2
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
