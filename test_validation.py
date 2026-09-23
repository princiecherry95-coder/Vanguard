"""Regression tests for the real evidence validation gate."""
from soc_pipeline import validate_bytes


def test_text_syslog():
    result = validate_bytes(
        b"2026-09-23T10:00:00Z sshd: Failed password from 10.0.0.7\n",
        "auth.log",
        "TEXT / SYSLOG",
    )
    assert result["format"] == "TEXT"
    assert result["records"] == 1
    assert result["validation_mode"] == "FAST_PREFLIGHT"
    assert len(result["sha256"]) == 64


def test_jsonl():
    result = validate_bytes(
        b'{"timestamp":"2026-09-23T10:00:00Z","source_ip":"10.0.0.7"}\n'
        b'{"timestamp":"2026-09-23T10:00:01Z","source_ip":"10.0.0.8"}\n',
        "events.jsonl",
        "AUTO",
    )
    assert result["format"] == "JSONL"
    assert result["records"] == 2


def test_csv():
    result = validate_bytes(
        b"timestamp,source_ip,message\n"
        b"2026-09-23T10:00:00Z,10.0.0.7,Failed login\n",
        "events.csv",
        "AUTO",
    )
    assert result["format"] == "CSV"
    assert result["records"] == 1


def test_xml():
    result = validate_bytes(
        b"<Event><Message>Failed login</Message></Event>",
        "events.xml",
        "AUTO",
    )
    assert result["format"] == "XML"
    assert result["records"] == 1


def test_empty_evidence_rejected():
    try:
        validate_bytes(b"\n\r\n", "empty.log", "AUTO")
    except ValueError:
        return
    raise AssertionError("Empty evidence was accepted")


def test_unsupported_extension_rejected():
    try:
        validate_bytes(b"event", "payload.exe", "AUTO")
    except ValueError:
        return
    raise AssertionError("Unsupported file was accepted")


def test_binary_nul_rejected():
    try:
        validate_bytes(b"safe\x00binary", "auth.log", "AUTO")
    except ValueError:
        return
    raise AssertionError("Binary NUL content was accepted")


if __name__ == "__main__":
    test_text_syslog()
    test_jsonl()
    test_csv()
    test_xml()
    test_empty_evidence_rejected()
    test_unsupported_extension_rejected()
    test_binary_nul_rejected()
    print("Evidence validation regression tests: PASS")
