from hashlib import sha256

from evidence_store import EvidenceStore


def test_export_history_preserves_each_download_and_hash(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    evidence = b"immutable evidence"
    evidence_digest = store.archive_evidence(evidence, "events.log", "LOG", "2026-09-25T18:00:00+00:00")
    run_id = store.start_analysis_run(evidence_digest, "2026-09-25T18:01:00+00:00")
    store.finish_analysis_run(run_id, "COMPLETE", 3, 1, 80)

    pdf = b"%PDF-vanguard"
    docx = b"PK-vanguard-docx"
    store.record_export_event(evidence_digest, "pdf", "vanguard_soc_report.pdf", pdf, run_id, "2026-09-25T18:02:00+00:00")
    store.record_export_event(evidence_digest, "docx", "vanguard_soc_report.docx", docx, run_id, "2026-09-25T18:03:00+00:00")

    rows = store.export_history(evidence_digest)
    assert len(rows) == 2
    assert rows[0]["format"] == "DOCX"
    assert rows[0]["analysis_run_id"] == run_id
    assert rows[0]["exported_at"] == "2026-09-25T18:03:00+00:00"
    assert rows[0]["file_sha256"] == sha256(docx).hexdigest()
    assert rows[1]["format"] == "PDF"
    assert rows[1]["file_sha256"] == sha256(pdf).hexdigest()
    assert rows[1]["evidence_sha256"] == evidence_digest


def test_export_history_can_record_non_evidence_document(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")
    payload = b"offline operational text"
    store.record_export_event(None, "txt", "vanguard_notes.txt", payload, exported_at="2026-09-25T19:00:00+00:00")
    rows = store.export_history()
    assert len(rows) == 1
    assert rows[0]["evidence_sha256"] == ""
    assert rows[0]["format"] == "TXT"
    assert rows[0]["size_bytes"] == len(payload)
    assert rows[0]["file_sha256"] == sha256(payload).hexdigest()
