from soc_context import (
    activity_baseline,
    build_soc_context,
    detection_coverage,
    duplicate_analysis,
    evidence_quality,
    observed_timeline,
)


ROWS = [
    {"event_id": "1", "timestamp": "2026-09-22T10:00:00+00:00", "source_ip": "10.0.0.1",
     "destination_ip": "10.0.0.2", "user": "alice", "severity": "HIGH",
     "attack_type": "AUTH_FAILURE", "raw_payload": "failed"},
    {"event_id": "2", "timestamp": "2026-09-22T10:00:10+00:00", "source_ip": "10.0.0.1",
     "destination_ip": "10.0.0.2", "user": "alice", "severity": "MEDIUM",
     "attack_type": "WEB", "raw_payload": "GET /"},
    {"event_id": "2", "timestamp": "2026-09-22T10:00:10+00:00", "source_ip": "10.0.0.1",
     "destination_ip": "10.0.0.2", "user": "alice", "severity": "MEDIUM",
     "attack_type": "WEB", "raw_payload": "GET /"},
    {"event_id": "3", "timestamp": "2026-09-22T11:00:00+00:00", "source_ip": "10.0.0.3",
     "destination_ip": "10.0.0.2", "user": "", "severity": "LOW",
     "attack_type": "NETWORK", "raw_payload": "probe"},
]


def test_quality_is_evidence_derived():
    result = evidence_quality(ROWS)
    assert result["records"] == 4
    assert result["field_coverage"]["timestamp"] == 100.0
    assert result["field_coverage"]["user"] == 75.0


def test_duplicates_are_not_counted_as_new_events():
    result = duplicate_analysis(ROWS)
    assert result["unique_events"] == 3
    assert result["duplicate_records"] == 1
    assert result["duplicate_rate"] == 25.0


def test_timeline_is_chronological_and_bounded():
    result = observed_timeline(ROWS, limit=2)
    assert [item["event_id"] for item in result] == ["2", "3"]


def test_baseline_refuses_insufficient_evidence():
    result = activity_baseline(ROWS)
    assert result["state"] == "INSUFFICIENT_EVIDENCE"


def test_coverage_does_not_invent_missing_identity():
    result = detection_coverage(ROWS)
    assert result["observed_category_rates"]["identity"] == 75.0


def test_full_context_is_consistent():
    result = build_soc_context(ROWS, {"alerts": [1, 2]})
    assert result["window"]["timestamped_records"] == 4
    assert result["duplicates"]["unique_events"] == 3
    assert result["coverage"]["analyzed_alerts"] == 2
