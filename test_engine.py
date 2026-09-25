"""Security regression tests for the offline Vanguard detection engine."""
from datetime import datetime, timezone, timedelta

from engine import analyze_events, correlate, detect, detect_behavior, detection_policy, parse_line, sanitize


def event_line(ts, source="10.0.0.10", user="admin", extra=""):
    return f"{ts} sshd: Failed password for user={user} from {source} {extra}"


def test_sanitization_redacts_credentials_and_bounds_input():
    value = sanitize("password=Secret123 token=ABCDEF\x00 " + "A" * 20000)
    assert "Secret123" not in value
    assert "ABCDEF" not in value
    assert "[REDACTED]" in value
    assert len(value) <= 16384


def test_parser_extracts_core_fields():
    event = parse_line("2026-09-22T10:00:00+00:00 sshd pid=442 user=admin Failed password from 10.10.1.7 to 10.10.1.8")
    assert event.source_ip == "10.10.1.7"
    assert event.destination_ip == "10.10.1.8"
    assert event.user == "admin"
    assert event.process_id == 442
    assert event.action == "LOGIN_FAILURE"



def test_suricata_eve_json_is_parsed_and_detected():
    raw = """{"timestamp":"2026-09-22T10:00:00.000000+0000","flow_id":12345,"event_type":"alert","src_ip":"10.20.30.40","src_port":45678,"dest_ip":"10.20.30.50","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET WEB_SERVER SQL Injection Attempt","category":"Web Application Attack","severity":1},"http":{"hostname":"10.20.30.50","url":"/login","http_method":"POST"},"app_proto":"http"}"""
    event = parse_line(raw, "JSONL")
    assert event.source_ip == "10.20.30.40"
    assert event.destination_ip == "10.20.30.50"
    assert event.event_type == "ALERT"
    assert event.action == "SURICATA_ALERT"
    assert event.severity == "CRITICAL"
    assert event.fields["signature"] == "ET WEB_SERVER SQL Injection Attempt"
    rules = {a.rule_id for a in detect(event)}
    assert "SURICATA_ALERT" in rules

def test_web_attack_detection_is_deterministic():
    event = parse_line("2026-09-22T10:00:00+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1")
    rules = {a.rule_id for a in detect(event)}
    assert "SQL_INJECTION" in rules


def test_bruteforce_threshold_and_no_false_trigger_before_threshold():
    base = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
    events = []
    for i in range(4):
        ts = (base + timedelta(seconds=i * 10)).isoformat()
        events.append(parse_line(event_line(ts)))
    assert not any(a.rule_id == "BRUTE_FORCE_AUTH" for a in detect_behavior(events))

    events.append(parse_line(event_line((base + timedelta(seconds=45)).isoformat())))
    alerts = detect_behavior(events)
    assert any(a.rule_id == "BRUTE_FORCE_AUTH" for a in alerts)


def test_distributed_bruteforce_detects_multiple_sources():
    base = datetime(2026, 9, 22, 11, 0, tzinfo=timezone.utc)
    events = [
        parse_line(event_line((base + timedelta(seconds=i * 8)).isoformat(), source=f"10.0.0.{10 + (i % 2)}"))
        for i in range(5)
    ]
    alerts = detect_behavior(events)
    assert any(a.rule_id == "DISTRIBUTED_BRUTE_FORCE" for a in alerts)


def test_correlation_groups_same_source():
    base = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
    a = parse_line(f"{base.isoformat()} 10.0.0.10 GET /search?q=' OR '1'='1' HTTP/1.1")
    b = parse_line(f"{(base + timedelta(seconds=30)).isoformat()} 10.0.0.10 user=admin Failed password")
    alerts = detect(a) + detect(b)
    incidents = correlate(alerts)
    assert len(incidents) == 1
    assert len(incidents[0]["alerts"]) == 2



def test_generic_json_and_xml_fields_are_normalized():
    j = parse_line('{"timestamp":"2026-09-22T10:00:00+00:00","src_ip":"10.1.1.7","dest_ip":"10.1.1.8","user":"analyst","message":"Failed password"}', "JSON")
    assert j.source_ip == "10.1.1.7"
    assert j.destination_ip == "10.1.1.8"
    assert j.user == "analyst"
    x = parse_line("<Event><TimeCreated>2026-09-22T10:00:00+00:00</TimeCreated><SourceIP>10.2.2.7</SourceIP><Message>Failed password</Message></Event>", "XML")
    assert x.source_ip == "10.2.2.7"
    assert "Failed password" in x.message


def test_comprehensive_analysis_returns_explainable_metrics():
    events = [
        parse_line("2026-09-22T10:00:00+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1"),
        parse_line("2026-09-22T10:00:10+00:00 sshd: Failed password for user=admin from 10.10.1.7"),
    ]
    result = analyze_events(events)
    assert result["events"] == events
    assert result["alerts"]
    assert result["incidents"]
    assert result["parse_coverage"] == 100.0
    assert result["severity_counts"]["CRITICAL"] >= 1
    assert "SQL_INJECTION" in result["rule_counts"]
    assert 0 <= result["risk_score"] <= 100

def test_extended_web_detection_and_policy_are_explainable():
    payloads = [
        ("2026-09-22T12:00:00+00:00 10.10.1.7 GET /run?x=1; powershell -enc AAA HTTP/1.1", "COMMAND_INJECTION"),
        ("2026-09-22T12:00:01+00:00 10.10.1.7 GET /fetch?url=http://169.254.169.254/latest HTTP/1.1", "SSRF_INDICATOR"),
    ]
    for raw, rule in payloads:
        alerts = detect(parse_line(raw))
        assert any(a.rule_id == rule for a in alerts)
        match = next(a for a in alerts if a.rule_id == rule)
        assert match.evidence["pattern"] == rule
    policy = detection_policy()
    assert policy["brute_force_failures"] == 5
    assert policy["behavior_window_seconds"] == 120


def test_risk_breakdown_matches_reported_score():
    event = parse_line("2026-09-22T12:00:00+00:00 10.10.1.7 GET /?q=' OR '1'='1'")
    result = analyze_events([event])
    breakdown = result["risk_breakdown"]
    assert breakdown["raw_alerts"] >= breakdown["finding_groups"] >= 1
    assert result["risk_score"] <= 100


def main():
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("Vanguard-SIEM security regression suite: PASS")


if __name__ == "__main__":
    main()
