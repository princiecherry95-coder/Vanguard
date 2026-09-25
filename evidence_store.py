"""Local SQLite evidence/findings/incident metadata store.

The store is intentionally offline and contains only normalized, bounded
metadata plus evidence digests. Raw evidence can remain in the operator's
controlled source location.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


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
