from analytics import summary, trend, findings_dataframe


def test_summary_counts_only_loaded_evidence():
    rows = [
        {"timestamp": "2026-09-25T10:00:00+00:00", "event_id": "1", "severity": "CRITICAL", "source_ip": "192.0.2.1", "target_endpoint": "/login", "attack_type": "AUTH"},
        {"timestamp": "2026-09-25T10:15:00+00:00", "event_id": "2", "severity": "LOW", "source_ip": "192.0.2.2", "target_endpoint": "/health", "attack_type": "HEALTH"},
    ]
    result = summary(rows)
    assert result["records"] == 2
    assert result["severity_counts"]["CRITICAL"] == 1
    assert result["severity_counts"]["LOW"] == 1
    assert result["unique_sources"] == 2
    assert result["alert_rate_pct"] == 50.0
    assert result["critical_rate_pct"] == 50.0


def test_empty_evidence_has_no_synthetic_metrics():
    result = summary([])
    assert result["records"] == 0
    assert result["alert_rate_pct"] == 0.0
    assert result["first_seen"] is None
    assert result["last_seen"] is None
    assert result["top_sources"] == {}


def test_trend_is_derived_from_event_timestamps():
    rows = [
        {"timestamp": "2026-09-25T10:00:00+00:00", "event_id": "1", "severity": "HIGH", "source_ip": "192.0.2.1", "target_endpoint": "/", "attack_type": "A"},
        {"timestamp": "2026-09-25T10:30:00+00:00", "event_id": "2", "severity": "CRITICAL", "source_ip": "192.0.2.1", "target_endpoint": "/", "attack_type": "B"},
    ]
    result = trend(rows)
    assert len(result) == 1
    assert int(result.iloc[0]["records"]) == 2
    assert int(result.iloc[0]["alerts"]) == 2
    assert int(result.iloc[0]["critical"]) == 1


def test_findings_dataframe_preserves_observed_finding_counts():
    result = findings_dataframe({"analyst_alerts": [{
        "alert_id": "A1", "rule_id": "R1", "rule_version": "1.0", "title": "Observed",
        "severity": "HIGH", "confidence": "HIGH", "category": "TEST", "mitre_technique": "T1110",
        "count": 3, "sources": ["192.0.2.1"], "destinations": ["asset-1"],
        "first_seen": "2026-09-25T10:00:00+00:00", "last_seen": "2026-09-25T10:30:00+00:00",
        "guidance": "Investigate evidence.",
    }]})
    assert len(result) == 1
    assert result.iloc[0]["mitre_technique"] == "T1110"
    assert int(result.iloc[0]["count"]) == 3
