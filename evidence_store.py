"""Local SQLite evidence/findings/incident metadata store.

The store is intentionally offline and contains only normalized, bounded
metadata plus evidence digests. Raw evidence can remain in the operator's
controlled source location.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable
import hashlib
import os
from datetime import datetime, timezone


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS evidence_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    completed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence_history (id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_sha256 TEXT NOT NULL UNIQUE,filename TEXT NOT NULL,format TEXT NOT NULL,size_bytes INTEGER NOT NULL,stored_path TEXT NOT NULL,uploaded_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'STORED');
CREATE TABLE IF NOT EXISTS analysis_runs (id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_sha256 TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT,status TEXT NOT NULL,records INTEGER NOT NULL DEFAULT 0,finding_groups INTEGER NOT NULL DEFAULT 0,risk_score REAL,error TEXT);
CREATE INDEX IF NOT EXISTS idx_history_uploaded_at ON evidence_history(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_runs_evidence ON analysis_runs(evidence_sha256);
CREATE TABLE IF NOT EXISTS analysis_findings (id INTEGER PRIMARY KEY AUTOINCREMENT,run_id INTEGER NOT NULL,evidence_sha256 TEXT NOT NULL,finding_key TEXT NOT NULL,finding_id TEXT NOT NULL,rule_id TEXT NOT NULL,rule_version TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,occurrence_count INTEGER NOT NULL,source_count INTEGER NOT NULL,destination_count INTEGER NOT NULL,mitre_technique TEXT,reason TEXT NOT NULL,UNIQUE(run_id,finding_key));
CREATE INDEX IF NOT EXISTS idx_analysis_findings_run ON analysis_findings(run_id);
CREATE TABLE IF NOT EXISTS evidence_uploads (id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_sha256 TEXT NOT NULL,filename TEXT NOT NULL,format TEXT NOT NULL,size_bytes INTEGER NOT NULL,uploaded_at TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'LOCAL_UPLOAD');
CREATE INDEX IF NOT EXISTS idx_uploads_digest ON evidence_uploads(evidence_sha256);
CREATE INDEX IF NOT EXISTS idx_uploads_time ON evidence_uploads(uploaded_at);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_sha256 TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL,
    source_count INTEGER NOT NULL,
    destination_count INTEGER NOT NULL,
    mitre_technique TEXT,
    reason TEXT NOT NULL,
    UNIQUE(evidence_sha256, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_evidence ON findings(evidence_sha256);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class EvidenceStore:
    def __init__(self, path: str | Path = "vanguard_evidence.db") -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA)
        return conn

    def save_analysis(self, bundle: dict, analyst_alerts: Iterable[dict]) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO evidence_sets(sha256,filename,format,record_count,completed_at) VALUES(?,?,?,?,?)",
                (bundle["sha256"], bundle["filename"], bundle["format"], bundle["records"], bundle["completed_at"]),
            )
            for finding in analyst_alerts:
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                    (evidence_sha256,finding_id,rule_id,rule_version,severity,confidence,
                     first_seen,last_seen,occurrence_count,source_count,destination_count,mitre_technique,reason)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        bundle["sha256"], finding["alert_id"], finding["rule_id"], finding["rule_version"],
                        finding["severity"], finding["confidence"], str(finding["first_seen"]),
                        str(finding["last_seen"]), finding["count"], len(finding["sources"]),
                        len(finding["destinations"]), finding.get("mitre_technique"), finding["reason"],
                    ),
                )
            conn.commit()
        finally:
            conn.close()


    def archive_evidence(self, data: bytes, filename: str, format_name: str, uploaded_at: str | None = None) -> str:
        digest = hashlib.sha256(data).hexdigest()
        root = Path(os.environ.get('VANGUARD_EVIDENCE_ROOT', str(self.path.parent / 'evidence_archive'))).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        safe_name = ''.join(c if c.isalnum() or c in '._-' else '_' for c in Path(filename).name)[:120] or 'evidence.log'
        stored = root / f'{digest[:16]}_{safe_name}'
        if not stored.exists():
            stored.write_bytes(bytes(data))
        conn = self._connect()
        try:
            upload_time = uploaded_at or datetime.now(timezone.utc).isoformat()
            conn.execute('INSERT OR IGNORE INTO evidence_history(evidence_sha256,filename,format,size_bytes,stored_path,uploaded_at) VALUES(?,?,?,?,?,?)', (digest, Path(filename).name, format_name.upper(), len(data), str(stored), upload_time))
            conn.execute('INSERT INTO evidence_uploads(evidence_sha256,filename,format,size_bytes,uploaded_at) VALUES(?,?,?,?,?)', (digest, Path(filename).name, format_name.upper(), len(data), upload_time))
            conn.commit()
        finally:
            conn.close()
        return digest

    def upload_history(self, evidence_sha256: str | None = None, limit: int = 200) -> list[dict]:
        conn = self._connect()
        try:
            if evidence_sha256:
                rows = conn.execute("SELECT id,evidence_sha256,filename,format,size_bytes,uploaded_at,source FROM evidence_uploads WHERE evidence_sha256=? ORDER BY uploaded_at DESC LIMIT ?", (evidence_sha256, max(1,min(limit,1000)))).fetchall()
            else:
                rows = conn.execute("SELECT id,evidence_sha256,filename,format,size_bytes,uploaded_at,source FROM evidence_uploads ORDER BY uploaded_at DESC LIMIT ?", (max(1,min(limit,1000)),)).fetchall()
            cols=["id","evidence_sha256","filename","format","size_bytes","uploaded_at","source"]
            return [dict(zip(cols,row)) for row in rows]
        finally:
            conn.close()

    def history(self, limit: int = 100) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute('SELECT id,evidence_sha256,filename,format,size_bytes,stored_path,uploaded_at,status FROM evidence_history ORDER BY uploaded_at DESC LIMIT ?', (max(1, min(limit, 500)),)).fetchall()
            cols = ['id','evidence_sha256','filename','format','size_bytes','stored_path','uploaded_at','status']
            return [dict(zip(cols, row)) for row in rows]
        finally:
            conn.close()

    def load_evidence(self, evidence_sha256: str) -> tuple[bytes, dict]:
        conn = self._connect()
        try:
            row = conn.execute('SELECT filename,format,stored_path,uploaded_at,size_bytes FROM evidence_history WHERE evidence_sha256=?', (evidence_sha256,)).fetchone()
        finally:
            conn.close()
        if not row:
            raise FileNotFoundError('Evidence record was not found.')
        path = Path(row[2])
        if not path.exists():
            raise FileNotFoundError('Evidence archive file is missing.')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != evidence_sha256:
            raise ValueError('Evidence integrity check failed: SHA-256 mismatch.')
        return data, {'filename': row[0], 'format': row[1], 'uploaded_at': row[3], 'size_bytes': row[4]}

    def start_analysis_run(self, evidence_sha256: str, started_at: str | None = None) -> int:
        conn = self._connect()
        try:
            cur = conn.execute('INSERT INTO analysis_runs(evidence_sha256,started_at,status) VALUES(?,?,?)', (evidence_sha256, started_at or datetime.now(timezone.utc).isoformat(), 'RUNNING'))
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def finish_analysis_run(self, run_id: int, status: str, records: int = 0, finding_groups: int = 0, risk_score: float | None = None, error: str | None = None) -> None:
        conn = self._connect()
        try:
            conn.execute('UPDATE analysis_runs SET completed_at=?,status=?,records=?,finding_groups=?,risk_score=?,error=? WHERE id=?', (datetime.now(timezone.utc).isoformat(), status, records, finding_groups, risk_score, error, run_id))
            conn.commit()
        finally:
            conn.close()

    def analysis_history(self, evidence_sha256: str | None = None, limit: int = 100) -> list[dict]:
        conn = self._connect()
        try:
            if evidence_sha256:
                rows = conn.execute('SELECT id,evidence_sha256,started_at,completed_at,status,records,finding_groups,risk_score,error FROM analysis_runs WHERE evidence_sha256=? ORDER BY started_at DESC LIMIT ?', (evidence_sha256, max(1, min(limit, 500)))).fetchall()
            else:
                rows = conn.execute('SELECT id,evidence_sha256,started_at,completed_at,status,records,finding_groups,risk_score,error FROM analysis_runs ORDER BY started_at DESC LIMIT ?', (max(1, min(limit, 500)))).fetchall()
            cols = ['id','evidence_sha256','started_at','completed_at','status','records','finding_groups','risk_score','error']
            return [dict(zip(cols, row)) for row in rows]
        finally:
            conn.close()


    def record_analysis_snapshot(self, run_id: int, evidence_sha256: str, analyst_alerts: Iterable[dict]) -> None:
        conn = self._connect()
        try:
            for f in analyst_alerts:
                rule_id = str(f.get("rule_id", "UNKNOWN")).strip()
                reason = " ".join(str(f.get("reason", "")).split()).strip()
                mitre = str(f.get("mitre_technique") or "").strip()
                alert_id = str(f.get("alert_id") or "").strip()
                if alert_id:
                    key = alert_id
                else:
                    identity = f"{rule_id}|{reason}|{mitre}"
                    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT OR REPLACE INTO analysis_findings "
                    "(run_id,evidence_sha256,finding_key,finding_id,rule_id,rule_version,severity,confidence,"
                    "occurrence_count,source_count,destination_count,mitre_technique,reason) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id, evidence_sha256, key, str(f.get("alert_id", key)), rule_id,
                        str(f.get("rule_version", "")), str(f.get("severity", "UNKNOWN")),
                        str(f.get("confidence", "UNKNOWN")), int(f.get("count", 0)),
                        len(f.get("sources", [])), len(f.get("destinations", [])),
                        f.get("mitre_technique"), reason,
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def analysis_variation(self, evidence_sha256: str, run_id: int) -> dict:
        conn = self._connect()
        try:
            prev=conn.execute("SELECT id FROM analysis_runs WHERE evidence_sha256=? AND status='COMPLETE' AND id<? ORDER BY id DESC LIMIT 1",(evidence_sha256,run_id)).fetchone()
            cols=["finding_key","rule_id","rule_version","severity","confidence","occurrence_count","source_count","destination_count","mitre_technique","reason"]
            cur=[dict(zip(cols,r)) for r in conn.execute("SELECT finding_key,rule_id,rule_version,severity,confidence,occurrence_count,source_count,destination_count,mitre_technique,reason FROM analysis_findings WHERE run_id=?",(run_id,)).fetchall()]
            if not prev:
                return {
                    "baseline_run_id": None, "added": [], "removed": [], "changed": [],
                    "added_count": 0, "removed_count": 0, "changed_count": 0, "total_variations": 0,
                }
            old=[dict(zip(cols,r)) for r in conn.execute("SELECT finding_key,rule_id,rule_version,severity,confidence,occurrence_count,source_count,destination_count,mitre_technique,reason FROM analysis_findings WHERE run_id=?",(prev[0],)).fetchall()]
            c = {x["finding_key"]: x for x in cur}
            o = {x["finding_key"]: x for x in old}
            added = [c[k] for k in sorted(set(c) - set(o))]
            removed = [o[k] for k in sorted(set(o) - set(c))]
            changed = []
            for k in sorted(set(c)&set(o)):
                dif={f:(o[k][f],c[k][f]) for f in cols[1:] if o[k][f]!=c[k][f]}
                if dif:
                    changed.append({
                        "finding_key": k, "rule_id": c[k]["rule_id"], "reason": c[k]["reason"], "differences": dif,
                    })
            return {"baseline_run_id":prev[0],"added":added,"removed":removed,"changed":changed,"added_count":len(added),"removed_count":len(removed),"changed_count":len(changed),"total_variations":len(added)+len(removed)+len(changed)}
        finally:
            conn.close()

    def summary(self, evidence_sha256: str) -> dict:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT filename,format,record_count,completed_at FROM evidence_sets WHERE sha256=?",
                (evidence_sha256,),
            ).fetchone()
            findings = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(occurrence_count),0) FROM findings WHERE evidence_sha256=?",
                (evidence_sha256,),
            ).fetchone()
            return {
                "evidence": row,
                "finding_groups": int(findings[0] or 0),
                "finding_occurrences": int(findings[1] or 0),
            }
        finally:
            conn.close()
