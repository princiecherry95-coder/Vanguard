"""Regression tests for evidence-preserving analyst finding grouping."""
from datetime import datetime, timezone, timedelta

from engine import Alert, NormalizedEvent
from triage import build_analyst_queue


def test_repeated_alerts_are_grouped_without_losing_occurrence_count():
    base = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    event1 = NormalizedEvent(base, "10.0.0.1", "10.0.0.2", message="SQL", raw_sha256="a" * 64)
    event2 = NormalizedEvent(base + timedelta(seconds=10), "10.0.0.1", "10.0.0.2", message="SQL", raw_sha256="b" * 64)
    alerts = [
        Alert("SQL_INJECTION", "CRITICAL", "SQL", "matched", event1),
        Alert("SQL_INJECTION", "CRITICAL", "SQL", "matched", event2),
    ]
    queue = build_analyst_queue(alerts)
    assert len(queue) == 1
    assert queue[0]["count"] == 2
    assert len(queue[0]["evidence_ids"]) == 2
    assert queue[0]["confidence"] == "HIGH"
    assert queue[0]["mitre_technique"] == "T1190"


def test_separate_time_windows_create_separate_findings():
    base = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    first = NormalizedEvent(base, "10.0.0.1", "10.0.0.2", message="SQL", raw_sha256="c" * 64)
    second = NormalizedEvent(base + timedelta(seconds=301), "10.0.0.1", "10.0.0.2", message="SQL", raw_sha256="d" * 64)
    alerts = [
        Alert("SQL_INJECTION", "CRITICAL", "SQL", "matched", first),
        Alert("SQL_INJECTION", "CRITICAL", "SQL", "matched", second),
    ]
    queue = build_analyst_queue(alerts, window_seconds=300)
    assert len(queue) == 2


if __name__ == "__main__":
    test_repeated_alerts_are_grouped_without_losing_occurrence_count()
    test_separate_time_windows_create_separate_findings()
    print("Vanguard-SIEM triage regression suite: PASS")
