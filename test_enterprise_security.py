from enterprise_security import EnterpriseSecurityStore
from platform_catalog import capability_summary, capabilities

def test_enterprise_security_store():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as d:
        s = EnterpriseSecurityStore(f"{d}/enterprise.db")
        s.upsert_case("CASE-1", "Test incident", "HIGH", evidence_sha256="a"*64)
        s.upsert_ioc("10.0.0.5", "IP", confidence="HIGH")
        s.upsert_vulnerability("VULN-1", "HOST-1", cve="CVE-2026-0001", cvss=8.1)
        s.upsert_playbook("PB-1", "Containment", steps=[{"action":"notify"}])
        s.request_playbook_run("RUN-1", "PB-1", requested_by="analyst")
        s.record_ueba("UEBA-1", "USER:alice", "USER", "UNUSUAL_LOGIN", 81.5, "b"*64)
        s.map_control("AC-1", "NIST-CSF", "Access control", evidence_refs=["CASE-1"])
        assert len(s.cases()) == 1
        assert len(s.iocs()) == 1
        assert len(s.vulnerabilities()) == 1
        assert s.playbook_runs()[0]["status"] == "APPROVAL_REQUIRED"
        assert s.ueba()[0]["score"] == 81.5
        assert s.compliance()[0]["framework"] == "NIST-CSF"
        assert s.summary() == {"cases":1,"iocs":1,"vulnerabilities":1,"playbooks":1,"playbook_runs":1,"ueba_observations":1,"compliance_controls":1}

def test_capability_catalog_is_explicit():
    summary = capability_summary()
    assert summary["AVAILABLE"] >= 10
    assert len(capabilities()) >= 15
    assert any(x.key == "stix_taxii" and x.status == "INTEGRATION" for x in capabilities())
    assert any(x.key == "graph_investigation" and x.status == "PLANNED" for x in capabilities())
