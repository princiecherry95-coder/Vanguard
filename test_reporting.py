"""Regression tests for offline analytics and report exports."""
from reporting import export_bundle


def test_report_bundle_contains_required_formats():
    rows = [{
        "event_id": "EVT-1",
        "timestamp": "2026-09-25T10:00:00+00:00",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.1",
        "target_endpoint": "/login",
        "attack_type": "SQL injection",
        "description": "test",
        "raw_sha256": "a" * 64,
    }]
    analysis = {
        "risk_score": 80,
        "alerts": [object()],
        "analyst_alerts": [{
            "alert_id": "FND-000001", "rule_id": "SQL_INJECTION", "rule_version": "1.0",
            "title": "SQL injection indicator", "severity": "CRITICAL", "confidence": "HIGH",
            "category": "WEB_ATTACK", "mitre_technique": "T1190", "count": 1,
            "sources": ["10.0.0.1"], "destinations": ["/login"],
            "first_seen": "2026-09-25T10:00:00+00:00", "last_seen": "2026-09-25T10:00:00+00:00",
            "guidance": "review",
        }],
        "incidents": [],
        "parse_coverage": 100.0,
    }
    bundle = export_bundle(rows, analysis, "test")
    assert {"pdf", "docx", "xlsx", "pptx", "html", "csv", "json"} <= set(bundle)
    for payload in bundle.values():
        assert isinstance(payload, bytes)
        assert payload
