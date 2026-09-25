from security_operations import SecurityOperationsStore, telemetry_status

def test_asset_identity_incident_roundtrip(tmp_path):
    s=SecurityOperationsStore(tmp_path/"ops.db")
    s.upsert_asset("srv-1","Server 1","SERVER","HIGH",status="ACTIVE")
    s.upsert_identity("u-1","analyst","USER","PRIVILEGED","ACTIVE")
    s.create_incident("INC-1","Test incident","HIGH",summary="Observed evidence")
    s.update_incident_status("INC-1","INVESTIGATING")
    assert s.assets()[0]["asset_key"]=="srv-1"
    assert s.identities()[0]["privilege"]=="PRIVILEGED"
    assert s.incidents()[0]["status"]=="INVESTIGATING"

def test_telemetry_never_treats_missing_as_zero():
    status, reason=telemetry_status(None,0,10)
    assert status=="UNKNOWN"
    assert "not treated as zero" in reason

def test_telemetry_degrades_on_low_rate():
    status,_=telemetry_status("2026-09-25T10:00:00Z",4,10)
    assert status=="DEGRADED"
