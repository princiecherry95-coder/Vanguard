"""Regression tests for real local capabilities and report generation."""
from __future__ import annotations
import tempfile, socket, threading, time
from pathlib import Path
from analytics import summary
from collector import LocalLogCollector, SyslogUDPCollector
from firewall import block_ip
from reporting import export_bundle

def test_analytics():
    rows=[{"timestamp":"2026-09-25T10:00:00Z","event_id":"1","severity":"CRITICAL","source_ip":"10.0.0.1","target_endpoint":"/x","attack_type":"SQL Injection"},{"timestamp":"2026-09-25T10:01:00Z","event_id":"2","severity":"HIGH","source_ip":"10.0.0.2","target_endpoint":"/y","attack_type":"Brute Force"}]
    s=summary(rows)
    assert s["records"]==2 and s["unique_sources"]==2 and s["severity_counts"]["CRITICAL"]==1

def test_reports():
    rows=[{"timestamp":"2026-09-25T10:00:00Z","event_id":"1","severity":"HIGH","source_ip":"10.0.0.1","target_endpoint":"/x","attack_type":"Test","raw_payload":"x"}]
    out=export_bundle(rows,{"risk_score":10,"alerts":[],"analyst_alerts":[],"incidents":[]},"unit-test")
    assert all(out[k] for k in ("pdf","docx","xlsx","pptx","json"))
    assert out["pdf"][:4]==b"%PDF"

def test_firewall_dry_run():
    r=block_ip("10.0.0.5")
    assert r["status"]=="DRY_RUN"

def test_syslog_udp():
    got=[]
    c=SyslogUDPCollector(port=15514)
    t=threading.Thread(target=lambda:c.serve(got.append),daemon=True); t.start(); time.sleep(.1)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.sendto(b"test syslog",("127.0.0.1",15514)); sock.close(); time.sleep(.2); c.stop(); t.join(timeout=1)
    assert "test syslog" in got

def test_file_tail():
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/"x.log"; p.write_text("first\n")
        got=[]; c=LocalLogCollector(); c.tail_file(str(p),interval=.02,callback=got.append); time.sleep(.05)
        with p.open("a") as f: f.write("second\n")
        time.sleep(.1); c.stop()
        assert "second" in got
