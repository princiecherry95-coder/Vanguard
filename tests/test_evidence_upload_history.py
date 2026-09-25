from evidence_store import EvidenceStore

def test_upload_event_history_preserves_repeat_uploads(tmp_path):
    s=EvidenceStore(tmp_path/"evidence.db")
    data=b"2026-09-25 login failed"
    d1=s.archive_evidence(data,"events.log","LOG","2026-09-25T10:00:00+00:00")
    d2=s.archive_evidence(data,"renamed.log","LOG","2026-09-25T11:00:00+00:00")
    assert d1==d2
    assert len(s.history())==1
    uploads=s.upload_history(d1)
    assert len(uploads)==2
    assert uploads[0]["uploaded_at"]=="2026-09-25T11:00:00+00:00"
    assert uploads[1]["filename"]=="events.log"

def test_replay_load_verifies_original_bytes(tmp_path):
    s=EvidenceStore(tmp_path/"evidence.db")
    data=b"immutable evidence"
    digest=s.archive_evidence(data,"evidence.log","LOG")
    loaded,meta=s.load_evidence(digest)
    assert loaded==data
    assert meta["filename"]=="evidence.log"
