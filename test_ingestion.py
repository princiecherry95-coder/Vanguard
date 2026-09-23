"""Regression tests for secure dashboard log ingestion helpers."""
from ingestion import ALLOWED_UPLOAD_TYPES, MAX_RECORDS, MAX_UPLOAD_BYTES, infer_upload_format, lines_from_upload, safe_uploaded_text, validate_upload_size


def main():
    assert MAX_UPLOAD_BYTES == 1024 * 1024 * 1024
    assert MAX_RECORDS == 1_000_000
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
    assert len(lines_from_upload('{"events":[{"src_ip":"10.0.0.1","message":"Failed password"},{"src_ip":"10.0.0.2","message":"ok"}]}', "JSON")) == 2
    assert len(lines_from_upload('{"data":[{"message":"one"},{"message":"two"}]}', "JSON")) == 2
    assert len(lines_from_upload('source,message\n10.0.0.1,Failed login\n', "CSV")) == 1
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event><TimeCreated>2026-09-23T10:00:00+00:00</TimeCreated><SourceIp>10.0.0.7</SourceIp><Message>Failed password for user=admin</Message></Event>"""
    assert len(lines_from_upload(xml, "XML")) == 1
    assert infer_upload_format(xml, "events.txt") == "TEXT"
    assert infer_upload_format("<Event><Message>x</Message></Event>", "events.xml") == "XML"

    # Evidence must not be silently truncated below the 1 GiB safety boundary.
    long_record = ("A" * 12000).encode("utf-8")
    long_text, long_digest = safe_uploaded_text(long_record, "large.log")
    assert len(long_text) == 12000
    assert long_digest and len(long_digest) == 64

    assert infer_upload_format('{"message":"one"}\n{"message":"two"}', "events.json") == "JSONL"
    assert infer_upload_format('[{"message":"one"}, {"message":"two"}]', "events.json") == "JSON"
    assert len(lines_from_upload('{"message":"one"}\n{"message":"two"}', "JSONL")) == 2

    try:
        validate_upload_size(MAX_UPLOAD_BYTES + 1)
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
