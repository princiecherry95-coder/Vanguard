from unittest.mock import patch
import pytest
from supabase_store import SupabaseConfigurationError, SupabaseStore

def test_unconfigured_store_is_safe():
    store=SupabaseStore(url="",service_role_key="")
    assert store.configured is False
    assert store.safe_status=={"configured":False,"url_configured":False,"credential_configured":False}
    assert store.health() is False

def test_invalid_table_is_rejected():
    store=SupabaseStore("https://example.supabase.co","test-key")
    with pytest.raises(ValueError): store._request("not_a_vanguard_table")

def test_sync_mirrors_structured_metadata_only():
    store=SupabaseStore("https://example.supabase.co","test-key")
    fake=type("FakeStore",(),{
      "cases":lambda self,limit=500:[{"case_key":"C1","title":"Test"}],
      "iocs":lambda self,limit=500:[],
      "vulnerabilities":lambda self,limit=500:[],
      "playbooks":lambda self,limit=500:[],
      "playbook_runs":lambda self,limit=500:[],
      "ueba":lambda self,limit=500:[],
      "compliance":lambda self,limit=500:[]
    })()
    with patch.object(store,"upsert_rows",return_value=1) as upsert:
        result=store.sync_enterprise_store(fake)
    assert result["vanguard_cases"]==1
    assert upsert.call_count==7
    assert upsert.call_args_list[0].args[0]=="vanguard_cases"

def test_request_requires_configuration():
    with pytest.raises(SupabaseConfigurationError):
        SupabaseStore()._request("vanguard_cases")
