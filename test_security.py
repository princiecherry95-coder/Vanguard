"""Additional defensive security regression tests for Vanguard-SIEM."""
from datetime import datetime, timezone
from engine import Alert, NormalizedEvent, correlate, parse_line, sanitize

def test_sanitization_redacts_secrets_and_bounds_input():
    raw="password=topsecret token=abc123 Authorization: Bearer supersecret "+"X"*20000
    clean=sanitize(raw)
    assert "topsecret" not in clean and "abc123" not in clean and "supersecret" not in clean
    assert len(clean)<=16384

def test_parser_rejects_invalid_ips_without_crashing():
    event=parse_line("2026-09-22T10:00:00+00:00 user=admin from 999.999.999.999 to 10.0.0.5 pid=42")
    assert event.source_ip == "10.0.0.5"
    assert event.destination_ip is None
    assert event.process_id == 42

def test_parser_handles_malformed_untrusted_input():
    event=parse_line("\x00\x01\x02 "+"A"*50000)
    assert event.raw_sha256 and len(event.message)<=2048

def test_correlation_escalates_incident_to_highest_severity():
    timestamp=datetime(2026,9,22,10,0,tzinfo=timezone.utc)
    event=NormalizedEvent(timestamp=timestamp,source_ip="10.0.0.10",message="test",raw_sha256="a"*64)
    low=Alert("LOW_TEST","LOW","Low test","test",event)
    critical=Alert("CRITICAL_TEST","CRITICAL","Critical test","test",event)
    incidents=correlate([low,critical])
    assert len(incidents)==1 and incidents[0]["severity"]=="CRITICAL" and len(incidents[0]["alerts"])==2

def main():
    for test in [test_sanitization_redacts_secrets_and_bounds_input,test_parser_rejects_invalid_ips_without_crashing,test_parser_handles_malformed_untrusted_input,test_correlation_escalates_incident_to_highest_severity]:
        test(); print(f"PASS {test.__name__}")
    print("Vanguard-SIEM security regression suite: PASS")
if __name__=="__main__":
    main()
