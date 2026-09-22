"""Regression tests for the optional local deployment capabilities."""
from firewall import block_ip
from distributed import EventBuffer
from threat_intel import ThreatIntelCache
from remediation import propose, execute_approved
import tempfile
from pathlib import Path

def test_firewall_dry_run():
    assert block_ip("10.0.0.5")["status"] == "DRY_RUN"

def test_distributed_buffer_is_bounded():
    b=EventBuffer(2); b.add(1); b.add(2); b.add(3)
    assert b.snapshot()==[2,3]

def test_threat_intel_cache_is_local():
    with tempfile.TemporaryDirectory() as d:
        c=ThreatIntelCache(Path(d)/"ti.json")
        c.put_ip("10.0.0.5", {"source":"local"})
        assert c.lookup_ip("10.0.0.5")["source"]=="local"

def test_remediation_requires_approval():
    p=propose({"source_ip":"10.0.0.5","description":"test"})
    assert p["requires_approval"]
    assert execute_approved(p)["status"]=="APPROVAL_REQUIRED"

if __name__=="__main__":
    for f in [test_firewall_dry_run,test_distributed_buffer_is_bounded,test_threat_intel_cache_is_local,test_remediation_requires_approval]:
        f(); print("PASS",f.__name__)
    print("Vanguard-SIEM capability regression suite: PASS")
