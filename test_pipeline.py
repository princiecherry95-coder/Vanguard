"""Regression tests for the unified Vanguard SOC pipeline."""
from soc_pipeline import analyze_bytes, analyze_bytes_incremental, analysis_to_logs, stage_status, validate_bytes


def main():
    raw = (
        b"2026-09-23T10:00:00+00:00 sshd: Failed password for user=admin from 10.10.1.7\n"
        b"2026-09-23T10:00:10+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1\n"
    )
    validation = validate_bytes(raw, "events.log", "TEXT")
    assert validation["records"] == 2
    assert len(validation["sha256"]) == 64

    bundle = analyze_bytes(raw, "events.log", "TEXT")
    assert bundle["records"] == validation["records"]
    assert bundle["sha256"] == validation["sha256"]
    assert bundle["analysis"]["events"]
    assert bundle["analysis"]["alerts"]

    rows = analysis_to_logs(bundle)
    assert len(rows) == 2
    assert rows[0]["raw_sha256"]

    jsonl = (
        b'{"timestamp":"2026-09-23T10:01:00+00:00","src_ip":"10.10.1.7","event_type":"auth","message":"Failed password for user=admin"}\n'
        b'{"timestamp":"2026-09-23T10:01:10+00:00","src_ip":"10.10.1.7","message":"GET /search?q=\' OR \'1\'=\'1\' HTTP/1.1"}\n'
    )
    structured = analyze_bytes(jsonl, "events.jsonl", "JSONL")
    assert structured["records"] == 2
    assert structured["analysis"]["rule_counts"].get("SQL_INJECTION") == 1
    assert all(event.raw_sha256 for event in structured["events"])
    structured_rows = analysis_to_logs(structured)
    assert structured_rows[0]["source_ip"] == "10.10.1.7"
    assert structured_rows[1]["attack_type"] == "Web application injection indicator"

    csv_data = b"timestamp,source_ip,message\n2026-09-23T10:02:00+00:00,10.10.1.8,Failed password for user=admin\n"
    csv_bundle = analyze_bytes(csv_data, "events.csv", "CSV")
    assert csv_bundle["records"] == 1
    assert csv_bundle["events"][0].source_ip == "10.10.1.8"
    assert csv_bundle["analysis"]["rule_counts"].get("AUTH_FAILURE") == 1

    stages = stage_status()
    assert list(stages) == ["INGEST", "VALIDATE", "ANALYZE", "CORRELATE", "RISK", "INVESTIGATE", "RESPOND", "AUDIT"]
    assert stages["RESPOND"] == "APPROVAL_REQUIRED"

    progress = []
    incremental = analyze_bytes_incremental(
        raw, "events.log", "TEXT",
        on_chunk=lambda events, processed, total: progress.append((processed, total)),
        chunk_size=1,
    )
    assert incremental["records"] == 2
    assert progress == [(1, 2), (2, 2)]
    assert incremental["sha256"] == validation["sha256"]

    malformed = b"2026-09-23T10:03:00Z normal event\n"
    malformed_result = analyze_bytes_incremental(malformed, "malformed.log", "TEXT", chunk_size=1)
    assert malformed_result["records"] == 1
    assert malformed_result["events"][0].raw_sha256

    print("Vanguard-SIEM unified pipeline regression suite: PASS")


if __name__ == "__main__":
    main()
