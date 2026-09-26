"""Enterprise defensive-security capability registry for Vanguard.

Offline-first metadata stores for cases, IOCs, vulnerabilities, playbooks,
compliance mappings and UEBA observations. No network access is performed.
All response execution remains approval-gated by the existing remediation layer.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_TEXT = 1024

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _clip(value: Any, limit: int = MAX_TEXT) -> str:
    return str(value or "")[:limit]

def _db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
      case_key TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'OPEN', owner TEXT NOT NULL DEFAULT '',
      evidence_sha256 TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS iocs (
      indicator TEXT NOT NULL, indicator_type TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'LOCAL', confidence TEXT NOT NULL DEFAULT 'UNKNOWN',
      first_seen TEXT, last_seen TEXT, expires_at TEXT, tags_json TEXT NOT NULL DEFAULT '[]',
      PRIMARY KEY(indicator, indicator_type)
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      vuln_key TEXT PRIMARY KEY, cve TEXT, asset_key TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'UNKNOWN', cvss REAL, status TEXT NOT NULL DEFAULT 'OPEN',
      discovered_at TEXT NOT NULL, due_at TEXT, source TEXT NOT NULL DEFAULT 'LOCAL',
      details_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS playbooks (
      playbook_key TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, approval_required INTEGER NOT NULL DEFAULT 1,
      steps_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS playbook_runs (
      run_key TEXT PRIMARY KEY, playbook_key TEXT NOT NULL, status TEXT NOT NULL,
      approved INTEGER NOT NULL DEFAULT 0, requested_by TEXT NOT NULL DEFAULT '',
      started_at TEXT NOT NULL, completed_at TEXT, result_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS ueba_observations (
      observation_key TEXT PRIMARY KEY, entity_key TEXT NOT NULL,
      entity_type TEXT NOT NULL, anomaly_type TEXT NOT NULL,
      score REAL NOT NULL, observed_at TEXT NOT NULL, evidence_sha256 TEXT NOT NULL DEFAULT '',
      details_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS compliance_mappings (
      control_key TEXT PRIMARY KEY, framework TEXT NOT NULL, title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'NOT_ASSESSED', evidence_refs_json TEXT NOT NULL DEFAULT '[]',
      owner TEXT NOT NULL DEFAULT '', reviewed_at TEXT
    );
    """ )
    return conn

class EnterpriseSecurityStore:
    """Small, deterministic SQLite registry that can run in an air-gapped SOC."""

    def __init__(self, path: str | Path = "vanguard_enterprise.db"):
        self.path = Path(path)

    def _rows(self, sql: str, args: tuple[Any, ...] = (), limit: int = 500) -> list[dict[str, Any]]:
        with _db(self.path) as conn:
            return [dict(r) for r in conn.execute(sql, args).fetchmany(max(1, min(limit, 500)))]

    def upsert_case(self, case_key: str, title: str, severity: str, owner: str = "",
                    evidence_sha256: str = "", summary: str = "", status: str = "OPEN") -> None:
        now = _now()
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO cases
                (case_key,title,severity,status,owner,evidence_sha256,summary,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(case_key) DO UPDATE SET title=excluded.title,severity=excluded.severity,
                status=excluded.status,owner=excluded.owner,evidence_sha256=excluded.evidence_sha256,
                summary=excluded.summary,updated_at=excluded.updated_at""",
                (_clip(case_key),_clip(title),_clip(severity),_clip(status),_clip(owner),
                 _clip(evidence_sha256, 128),_clip(summary),now,now))

    def cases(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM cases ORDER BY updated_at DESC", limit=limit)

    def upsert_ioc(self, indicator: str, indicator_type: str, source: str = "LOCAL",
                   confidence: str = "UNKNOWN", first_seen: str | None = None,
                   last_seen: str | None = None, expires_at: str | None = None,
                   tags: list[str] | None = None) -> None:
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO iocs
                (indicator,indicator_type,source,confidence,first_seen,last_seen,expires_at,tags_json)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(indicator,indicator_type) DO UPDATE SET source=excluded.source,
                confidence=excluded.confidence,last_seen=excluded.last_seen,
                expires_at=excluded.expires_at,tags_json=excluded.tags_json""",
                (_clip(indicator),_clip(indicator_type),_clip(source),_clip(confidence),
                 first_seen,last_seen,expires_at,json.dumps(tags or [])[:4096]))

    def iocs(self, indicator_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if indicator_type:
            return self._rows("SELECT * FROM iocs WHERE indicator_type=? ORDER BY last_seen DESC", (_clip(indicator_type),), limit)
        return self._rows("SELECT * FROM iocs ORDER BY last_seen DESC", limit=limit)

    def upsert_vulnerability(self, vuln_key: str, asset_key: str, cve: str = "",
                             severity: str = "UNKNOWN", cvss: float | None = None,
                             status: str = "OPEN", due_at: str | None = None,
                             source: str = "LOCAL", details: dict[str, Any] | None = None) -> None:
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO vulnerabilities
                (vuln_key,cve,asset_key,severity,cvss,status,discovered_at,due_at,source,details_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(vuln_key) DO UPDATE SET cve=excluded.cve,asset_key=excluded.asset_key,
                severity=excluded.severity,cvss=excluded.cvss,status=excluded.status,
                due_at=excluded.due_at,source=excluded.source,details_json=excluded.details_json""",
                (_clip(vuln_key),_clip(cve),_clip(asset_key),_clip(severity),cvss,_clip(status),
                 _now(),due_at,_clip(source),json.dumps(details or {})[:8192]))

    def vulnerabilities(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM vulnerabilities ORDER BY discovered_at DESC", limit=limit)

    def upsert_playbook(self, playbook_key: str, name: str, version: str = "1.0",
                        steps: list[dict[str, Any]] | None = None,
                        enabled: bool = True, approval_required: bool = True) -> None:
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO playbooks
                (playbook_key,name,version,enabled,approval_required,steps_json,updated_at)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(playbook_key) DO UPDATE SET name=excluded.name,version=excluded.version,
                enabled=excluded.enabled,approval_required=excluded.approval_required,
                steps_json=excluded.steps_json,updated_at=excluded.updated_at""",
                (_clip(playbook_key),_clip(name),_clip(version),int(enabled),int(approval_required),
                 json.dumps(steps or [])[:16384],_now()))

    def playbooks(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM playbooks ORDER BY updated_at DESC", limit=limit)

    def request_playbook_run(self, run_key: str, playbook_key: str, requested_by: str = "") -> None:
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO playbook_runs
                (run_key,playbook_key,status,approved,requested_by,started_at)
                VALUES (?,?,?,?,?,?)""",
                (_clip(run_key),_clip(playbook_key),"APPROVAL_REQUIRED",0,_clip(requested_by),_now()))

    def playbook_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM playbook_runs ORDER BY started_at DESC", limit=limit)

    def record_ueba(self, observation_key: str, entity_key: str, entity_type: str,
                    anomaly_type: str, score: float, evidence_sha256: str = "",
                    details: dict[str, Any] | None = None) -> None:
        score = max(0.0, min(100.0, float(score)))
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO ueba_observations
                (observation_key,entity_key,entity_type,anomaly_type,score,observed_at,evidence_sha256,details_json)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(observation_key) DO UPDATE SET score=excluded.score,
                observed_at=excluded.observed_at,details_json=excluded.details_json""",
                (_clip(observation_key),_clip(entity_key),_clip(entity_type),_clip(anomaly_type),
                 score,_now(),_clip(evidence_sha256,128),json.dumps(details or {})[:8192]))

    def ueba(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM ueba_observations ORDER BY observed_at DESC", limit=limit)

    def map_control(self, control_key: str, framework: str, title: str,
                    status: str = "NOT_ASSESSED", evidence_refs: list[str] | None = None,
                    owner: str = "") -> None:
        with _db(self.path) as conn:
            conn.execute("""INSERT INTO compliance_mappings
                (control_key,framework,title,status,evidence_refs_json,owner,reviewed_at)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(control_key) DO UPDATE SET framework=excluded.framework,
                title=excluded.title,status=excluded.status,evidence_refs_json=excluded.evidence_refs_json,
                owner=excluded.owner,reviewed_at=excluded.reviewed_at""",
                (_clip(control_key),_clip(framework),_clip(title),_clip(status),
                 json.dumps(evidence_refs or [])[:8192],_clip(owner),_now()))

    def compliance(self, framework: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if framework:
            return self._rows("SELECT * FROM compliance_mappings WHERE framework=? ORDER BY control_key", (_clip(framework),), limit)
        return self._rows("SELECT * FROM compliance_mappings ORDER BY framework,control_key", limit=limit)

    def summary(self) -> dict[str, int]:
        with _db(self.path) as conn:
            return {
                "cases": conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
                "iocs": conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
                "vulnerabilities": conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
                "playbooks": conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0],
                "playbook_runs": conn.execute("SELECT COUNT(*) FROM playbook_runs").fetchone()[0],
                "ueba_observations": conn.execute("SELECT COUNT(*) FROM ueba_observations").fetchone()[0],
                "compliance_controls": conn.execute("SELECT COUNT(*) FROM compliance_mappings").fetchone()[0],
            }
