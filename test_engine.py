"""Security regression tests for the offline Vanguard detection engine."""
from datetime import datetime, timezone, timedelta

from engine import correlate, detect, detect_behavior, parse_line, sanitize


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


def main():
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("Vanguard-SIEM security regression suite: PASS")


if __name__ == "__main__":
    main()
