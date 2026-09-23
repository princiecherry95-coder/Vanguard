"""Regression tests for the evidence validation contract used by the upload gate."""
import hashlib

from ingestion import infer_upload_format, lines_from_upload, safe_uploaded_text


def validate_contract(data: bytes, filename: str) -> tuple[str, int]:
    text, digest = safe_uploaded_text(data, filename)
    fmt = infer_upload_format(text, filename)
    lines = lines_from_upload(text, "TEXT" if fmt in {"TEXT", "XML"} else fmt)
    if not lines:
        raise ValueError("No non-empty records were found.")
    if not all(hashlib.sha256(line[:16384].encode("utf-8")).hexdigest() for line in lines):
        raise ValueError("Evidence integrity check failed.")
    return digest, len(lines)


def test_valid_log():
    digest, count = validate_contract(
        b"2026-09-23T10:00:00Z sshd: Failed password from 10.0.0.7\n",
        "auth.log",
    )
    assert len(digest) == 64
    assert count == 1


def test_jsonl_is_validated_as_multiple_records():
    digest, count = validate_contract(
        b'{"timestamp":"2026-09-23T10:00:00Z","source_ip":"10.0.0.7"}\n'
        b'{"timestamp":"2026-09-23T10:00:01Z","source_ip":"10.0.0.8"}\n',
        "events.jsonl",
    )
    assert len(digest) == 64
    assert count == 2


def test_binary_nul_is_rejected():
    try:
        safe_uploaded_text(b"safe\x00binary", "auth.log")
    except ValueError:
        return
    raise AssertionError("Binary NUL content was accepted")


def test_unsupported_extension_is_rejected():
    try:
        safe_uploaded_text(b"event", "payload.exe")
    except ValueError:
        return
    raise AssertionError("Unsupported extension was accepted")


def test_tamper_changes_evidence_hash():
    original = b"event-a\n"
    changed = b"event-b\n"
    _, original_hash = safe_uploaded_text(original, "auth.log")
    _, changed_hash = safe_uploaded_text(changed, "auth.log")
    assert original_hash != changed_hash


if __name__ == "__main__":
    test_valid_log()
    test_jsonl_is_validated_as_multiple_records()
    test_binary_nul_is_rejected()
    test_unsupported_extension_is_rejected()
    test_tamper_changes_evidence_hash()
    print("Evidence validation regression tests: PASS")
