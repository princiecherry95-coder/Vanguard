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


def test_analysis_variation_tracks_added_removed_and_changed(tmp_path):
    s=EvidenceStore(tmp_path/"evidence.db")
    data=b"same immutable evidence"
    digest=s.archive_evidence(data,"events.log","LOG")
    first=s.start_analysis_run(digest,"2026-09-25T10:00:00+00:00")
    s.record_analysis_snapshot(first,digest,[{
        "alert_id":"A","rule_id":"RULE-1","rule_version":"1","severity":"HIGH","confidence":"HIGH",
        "count":2,"sources":["a"],"destinations":["b"],"reason":"Initial reason"
    },{
        "alert_id":"B","rule_id":"RULE-2","rule_version":"1","severity":"LOW","confidence":"MEDIUM",
        "count":1,"sources":["c"],"destinations":[],"reason":"Removed later"
    }])
    s.finish_analysis_run(first,"COMPLETE",3,2,70)
    second=s.start_analysis_run(digest,"2026-09-25T11:00:00+00:00")
    s.record_analysis_snapshot(second,digest,[{
        "alert_id":"A","rule_id":"RULE-1","rule_version":"2","severity":"CRITICAL","confidence":"HIGH",
        "count":5,"sources":["a","x"],"destinations":["b"],"reason":"Severity changed"
    },{
        "alert_id":"C","rule_id":"RULE-3","rule_version":"1","severity":"MEDIUM","confidence":"MEDIUM",
        "count":1,"sources":["d"],"destinations":[],"reason":"New finding"
    }])
    s.finish_analysis_run(second,"COMPLETE",6,2,90)
    v=s.analysis_variation(digest,second)
    assert v["baseline_run_id"]==first
    assert v["added_count"]==1
    assert v["removed_count"]==1
    assert v["changed_count"]==1
    assert v["total_variations"]==3
    assert v["changed"][0]["differences"]["severity"]==("HIGH","CRITICAL")
