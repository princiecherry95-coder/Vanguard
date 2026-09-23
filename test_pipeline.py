"""Regression tests for the unified Vanguard SOC pipeline."""
from soc_pipeline import analyze_bytes, analysis_to_logs, stage_status


def main():
    bundle = analyze_bytes(
        b"2026-09-23T10:00:00+00:00 sshd: Failed password for user=admin from 10.10.1.7\n"
        b"2026-09-23T10:00:10+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1\n",
        "events.log",
        "TEXT",
    )
    assert bundle["records"] == 2
    assert len(bundle["sha256"]) == 64
    assert bundle["analysis"]["events"]
    assert bundle["analysis"]["alerts"]
    rows = analysis_to_logs(bundle)
    assert len(rows) == 2
    assert rows[0]["raw_sha256"]
    stages = stage_status()
    assert list(stages) == ["INGEST", "VALIDATE", "ANALYZE", "CORRELATE", "RISK", "INVESTIGATE", "RESPOND", "AUDIT"]
    assert stages["RESPOND"] == "APPROVAL_REQUIRED"
    print("Vanguard-SIEM unified pipeline regression suite: PASS")


if __name__ == "__main__":
    main()
