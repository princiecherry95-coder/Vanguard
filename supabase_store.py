"""Optional Supabase persistence for Vanguard.

Local SQLite remains authoritative for offline/air-gapped operation. This module
mirrors structured enterprise metadata to Supabase only when server-side
environment variables are configured.
"""
from __future__ import annotations
import json, os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TABLES=("vanguard_cases","vanguard_iocs","vanguard_vulnerabilities","vanguard_playbooks","vanguard_playbook_runs","vanguard_ueba_observations","vanguard_compliance_mappings")

class SupabaseConfigurationError(RuntimeError): pass

class SupabaseStore:
    """Dependency-free server-side Supabase REST adapter."""
    def __init__(self,url: str|None=None,service_role_key: str|None=None,timeout:float=10.0):
        self.url=(url or os.getenv("SUPABASE_URL") or "").rstrip("/")
        self.service_role_key=service_role_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY") or ""
        self.timeout=max(1.0,float(timeout))
    @property
    def configured(self): return bool(self.url and self.service_role_key)
    @property
    def safe_status(self): return {"configured":self.configured,"url_configured":bool(self.url),"credential_configured":bool(self.service_role_key)}
    def _require_configured(self):
        if not self.configured:
            raise SupabaseConfigurationError("Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as server-side environment variables.")
    def _request(self,table:str,method:str="GET",payload:Any=None,params:str=""):
        self._require_configured()
        if table not in TABLES: raise ValueError(f"Unsupported Vanguard Supabase table: {table}")
        body=None if payload is None else json.dumps(payload,separators=(",",":")).encode()
        request=Request(f"{self.url}/rest/v1/{table}{params}",data=body,headers={"apikey":self.service_role_key,"Authorization":f"Bearer {self.service_role_key}","Content-Type":"application/json","Accept":"application/json"},method=method)
        try:
            with urlopen(request,timeout=self.timeout) as response:
                raw=response.read()
                return json.loads(raw.decode("utf-8")) if raw else None
        except HTTPError as exc:
            detail=exc.read().decode("utf-8",errors="replace")[:500]
            raise RuntimeError(f"Supabase request failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Supabase connection failed: {exc.reason}") from exc
    def health(self)->bool:
        try:
            self._request("vanguard_cases",params="?select=case_key&limit=1")
            return True
        except (RuntimeError,SupabaseConfigurationError):
            return False
    def upsert_rows(self,table:str,rows:list[dict[str,Any]],conflict:str)->int:
        if not rows: return 0
        self._require_configured()
        if table not in TABLES: raise ValueError(f"Unsupported Vanguard Supabase table: {table}")
        request=Request(f"{self.url}/rest/v1/{table}?on_conflict={conflict}",data=json.dumps(rows,separators=(",",":")).encode(),headers={"apikey":self.service_role_key,"Authorization":f"Bearer {self.service_role_key}","Content-Type":"application/json","Accept":"application/json","Prefer":"resolution=merge-duplicates,return=minimal"},method="POST")
        try:
            with urlopen(request,timeout=self.timeout) as response: response.read()
            return len(rows)
        except HTTPError as exc:
            detail=exc.read().decode("utf-8",errors="replace")[:500]
            raise RuntimeError(f"Supabase upsert failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Supabase connection failed: {exc.reason}") from exc
    def sync_enterprise_store(self,store:Any)->dict[str,int]:
        mappings=(
            ("vanguard_cases",store.cases(limit=500),"case_key"),
            ("vanguard_iocs",store.iocs(limit=500),"indicator,indicator_type"),
            ("vanguard_vulnerabilities",store.vulnerabilities(limit=500),"vuln_key"),
            ("vanguard_playbooks",store.playbooks(limit=500),"playbook_key"),
            ("vanguard_playbook_runs",store.playbook_runs(limit=500),"run_key"),
            ("vanguard_ueba_observations",store.ueba(limit=500),"observation_key"),
            ("vanguard_compliance_mappings",store.compliance(limit=500),"control_key"),
        )
        return {table:self.upsert_rows(table,rows,conflict) for table,rows,conflict in mappings}
