from hashlib import sha256

from audit import verify_audit_chain
from evidence_store import EvidenceStore
from export_service import record_export_download


def test_export_download_is_stored_and_audited(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    import audit
    original = audit.AUDIT_PATH
    audit.AUDIT_PATH = audit_path
    try:
        store = EvidenceStore(tmp_path / "evidence.db")
        evidence = b"evidence"
        digest = store.archive_evidence(evidence, "events.log", "LOG")
        run_id = store.start_analysis_run(digest, "2026-09-26T10:00:00+00:00")
        payload = b"%PDF-vanguard"
        export_id = record_export_download(
            store, digest, run_id, "pdf", "report.pdf", payload
        )
        assert export_id > 0
        rows = store.export_history(digest)
        assert len(rows) == 1
        assert rows[0]["analysis_run_id"] == run_id
        assert rows[0]["file_sha256"] == sha256(payload).hexdigest()
        assert rows[0]["source"] == "REPORT_CENTER_DOWNLOAD"
        verification = verify_audit_chain(audit_path)
        assert verification["valid"] and verification["records"] == 1
    finally:
        audit.AUDIT_PATH = original
