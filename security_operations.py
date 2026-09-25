"""Offline defensive security-operations registry for Vanguard.

Provides bounded metadata for assets, identities, incidents/cases and telemetry
health. It never performs discovery or external network calls.
"""
from __future__ import annotations
import hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path

MAX_TEXT = 512

def _now(): return datetime.now(timezone.utc).isoformat()
def _clip(v): return str(v or "")[:MAX_TEXT]
def _db(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS assets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, asset_key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL, asset_type TEXT NOT NULL, criticality TEXT NOT NULL DEFAULT 'MEDIUM',
      owner TEXT, status TEXT NOT NULL DEFAULT 'UNKNOWN', last_seen TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS identities(
      id INTEGER PRIMARY KEY AUTOINCREMENT, identity_key TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL, identity_type TEXT NOT NULL DEFAULT 'USER',
      privilege TEXT NOT NULL DEFAULT 'STANDARD', status TEXT NOT NULL DEFAULT 'UNKNOWN',
      last_seen TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_key TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NEW',
      owner TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      evidence_sha256 TEXT, summary TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS telemetry_health(
      id INTEGER PRIMARY KEY AUTOINCREMENT, source_key TEXT UNIQUE NOT NULL,
      last_event TEXT, observed_rate REAL, expected_rate REAL, parser_success REAL,
      parser_failure REAL, ingestion_delay_seconds REAL, status TEXT NOT NULL DEFAULT 'UNKNOWN',
      checked_at TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '');
    """)
    return conn

class SecurityOperationsStore:
    def __init__(self, path="vanguard_operations.db"):
        self.path = Path(path)
    def upsert_asset(self, asset_key, name, asset_type, criticality="MEDIUM", owner="", status="UNKNOWN", last_seen=None, metadata=None):
        with _db(self.path) as c:
            c.execute("""INSERT INTO assets(asset_key,name,asset_type,criticality,owner,status,last_seen,metadata_json)
              VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_key) DO UPDATE SET name=excluded.name,asset_type=excluded.asset_type,
              criticality=excluded.criticality,owner=excluded.owner,status=excluded.status,last_seen=excluded.last_seen,metadata_json=excluded.metadata_json""",
              (_clip(asset_key),_clip(name),_clip(asset_type),_clip(criticality),_clip(owner),_clip(status),last_seen,json.dumps(metadata or {})[:4096]))
    def assets(self, limit=500):
        with _db(self.path) as c: return [dict(x) for x in c.execute("SELECT * FROM assets ORDER BY id DESC LIMIT ?",(max(1,min(limit,500)),))]
    def upsert_identity(self, identity_key, username, identity_type="USER", privilege="STANDARD", status="UNKNOWN", last_seen=None, metadata=None):
        with _db(self.path) as c:
            c.execute("""INSERT INTO identities(identity_key,username,identity_type,privilege,status,last_seen,metadata_json)
              VALUES(?,?,?,?,?,?,?) ON CONFLICT(identity_key) DO UPDATE SET username=excluded.username,identity_type=excluded.identity_type,
              privilege=excluded.privilege,status=excluded.status,last_seen=excluded.last_seen,metadata_json=excluded.metadata_json""",
              (_clip(identity_key),_clip(username),_clip(identity_type),_clip(privilege),_clip(status),last_seen,json.dumps(metadata or {})[:4096]))
    def identities(self, limit=500):
        with _db(self.path) as c: return [dict(x) for x in c.execute("SELECT * FROM identities ORDER BY id DESC LIMIT ?",(max(1,min(limit,500)),))]
    def create_incident(self, incident_key, title, severity, owner="", evidence_sha256="", summary="", metadata=None):
        now=_now()
        with _db(self.path) as c:
            c.execute("""INSERT INTO incidents(incident_key,title,severity,owner,created_at,updated_at,evidence_sha256,summary,metadata_json)
              VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_key) DO UPDATE SET title=excluded.title,severity=excluded.severity,
              owner=excluded.owner,updated_at=excluded.updated_at,evidence_sha256=excluded.evidence_sha256,summary=excluded.summary,
              metadata_json=excluded.metadata_json""",
              (_clip(incident_key),_clip(title),_clip(severity),_clip(owner),now,now,_clip(evidence_sha256),_clip(summary),json.dumps(metadata or {})[:4096]))
    def update_incident_status(self, incident_key, status):
        with _db(self.path) as c: c.execute("UPDATE incidents SET status=?,updated_at=? WHERE incident_key=?",(_clip(status),_now(),_clip(incident_key)))
    def incidents(self, limit=500):
        with _db(self.path) as c: return [dict(x) for x in c.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",(max(1,min(limit,500)),))]
    def record_telemetry_health(self, source_key, last_event=None, observed_rate=None, expected_rate=None, parser_success=None, parser_failure=None, ingestion_delay_seconds=None, status="UNKNOWN", reason=""):
        with _db(self.path) as c:
            c.execute("""INSERT INTO telemetry_health(source_key,last_event,observed_rate,expected_rate,parser_success,parser_failure,
              ingestion_delay_seconds,status,checked_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(source_key) DO UPDATE SET last_event=excluded.last_event,observed_rate=excluded.observed_rate,
              expected_rate=excluded.expected_rate,parser_success=excluded.parser_success,parser_failure=excluded.parser_failure,
              ingestion_delay_seconds=excluded.ingestion_delay_seconds,status=excluded.status,checked_at=excluded.checked_at,reason=excluded.reason""",
              (_clip(source_key),last_event,observed_rate,expected_rate,parser_success,parser_failure,ingestion_delay_seconds,_clip(status),_now(),_clip(reason)))
    def telemetry(self, limit=500):
        with _db(self.path) as c: return [dict(x) for x in c.execute("SELECT * FROM telemetry_health ORDER BY checked_at DESC LIMIT ?",(max(1,min(limit,500)),))]

def telemetry_status(last_event, observed_rate, expected_rate, parser_failure=0.0, ingestion_delay_seconds=0.0):
    if not last_event:
        return "UNKNOWN", "NO TELEMETRY — absence of events is not treated as zero activity"
    if parser_failure is not None and parser_failure > 0.25:
        return "DEGRADED", "Parser failure rate exceeds 25%"
    if expected_rate and observed_rate is not None and observed_rate < expected_rate * 0.5:
        return "DEGRADED", "Observed event rate is below 50% of expected rate"
    if ingestion_delay_seconds is not None and ingestion_delay_seconds > 300:
        return "DEGRADED", "Ingestion delay exceeds 5 minutes"
    return "HEALTHY", "Telemetry is within configured health thresholds"
