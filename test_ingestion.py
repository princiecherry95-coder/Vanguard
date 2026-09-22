"""Regression tests for secure dashboard log ingestion helpers."""
from ingestion import ALLOWED_UPLOAD_TYPES, MAX_RECORDS, MAX_UPLOAD_BYTES, lines_from_upload, safe_uploaded_text


def main():
    assert MAX_UPLOAD_BYTES == 10 * 1024 * 1024
    assert MAX_RECORDS == 50_000
    assert {"txt", "log", "csv", "json", "jsonl", "xml"} == ALLOWED_UPLOAD_TYPES

    text, digest = safe_uploaded_text(
        b"password=Secret123 token=ABC\n10.0.0.1 GET / HTTP/1.1\n",
        "events.log",
    )
    assert digest and len(digest) == 64
    assert text.startswith("password=Secret123")
    assert len(lines_from_upload(text, "TEXT")) == 2
    assert len(lines_from_upload('[{"message":"one"},{"message":"two"}]', "JSON")) == 2
    assert len(lines_from_upload('{"message":"one"}\n{"message":"two"}', "JSONL")) == 2
    assert len(lines_from_upload('source,message\n10.0.0.1,Failed login\n', "CSV")) == 1

    try:
        safe_uploaded_text(b"A" * (MAX_UPLOAD_BYTES + 1), "events.log")
    except ValueError:
        pass
    else:
        raise AssertionError("Oversized upload was not rejected")

    try:
        safe_uploaded_text(b"binary", "events.exe")
    except ValueError:
        pass
    else:
        raise AssertionError("Unsupported upload was not rejected")

    try:
        safe_uploaded_text(b"a\x00b", "events.log")
    except ValueError:
        pass
    else:
        raise AssertionError("Actual NUL/binary content was not rejected")

    print("Vanguard-SIEM ingestion security regression suite: PASS")


if __name__ == "__main__":
    main()
