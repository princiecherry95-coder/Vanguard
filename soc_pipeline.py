"""Unified local SOC pipeline shared by every Vanguard operating mode."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from audit import audit_event
from engine import analyze_events, parse_line
from ingestion import MAX_RECORDS, infer_upload_format, lines_from_upload, safe_uploaded_text


def validate_bytes(data: bytes, filename: str, format_hint: str = "AUTO") -> dict[str, Any]:
    """Validate evidence before analysis and return a stable content-bound validation record."""
    text, digest = safe_uploaded_text(data, filename)
    actual_fmt = format_hint if format_hint != "AUTO" else infer_upload_format(text, filename)
    parse_fmt = "TEXT" if actual_fmt in {"TEXT / SYSLOG", "XML"} else actual_fmt
    lines = lines_from_upload(text, parse_fmt)
    if not lines:
        raise ValueError("No non-empty records were found.")
    if len(lines) > MAX_RECORDS:
        raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per evidence set.")
    events = [parse_line(line, actual_fmt) for line in lines]
    parsed = sum(1 for event in events if event.message)
    coverage = (parsed / len(events) * 100) if events else 0.0
    if not all(bool(event.raw_sha256) for event in events):
        raise ValueError("Evidence integrity check failed: one or more records has no SHA-256 fingerprint.")
    return {
        "filename": filename,
        "format": actual_fmt,
        "records": len(lines),
        "parsed": parsed,
        "parse_coverage": coverage,
        "sha256": digest,
        "source_formats": sorted({event.source_format for event in events if event.source_format}),
    }


def analyze_bytes(data: bytes, filename: str, format_hint: str = "AUTO") -> dict[str, Any]:
    """Single canonical path for upload/paste/collector evidence."""
    text, digest = safe_uploaded_text(data, filename)
    actual_fmt = format_hint if format_hint != "AUTO" else infer_upload_format(text, filename)
    parse_fmt = "TEXT" if actual_fmt in {"TEXT / SYSLOG", "XML"} else actual_fmt
    lines = lines_from_upload(text, parse_fmt)
    if not lines:
        raise ValueError("No non-empty records were found.")
    if len(lines) > MAX_RECORDS:
        raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per evidence set.")
    events = [parse_line(line, actual_fmt) for line in lines]
    analysis = analyze_events(events)
    return {
        "filename": filename,
        "format": actual_fmt,
        "sha256": digest,
        "records": len(lines),
        "events": events,
        "analysis": analysis,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def analysis_to_logs(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Project canonical analysis into the dashboard's event representation."""
    events = bundle["events"]
    alerts = bundle["analysis"]["alerts"]
    by_event: dict[int, list[Any]] = {}
    for alert in alerts:
        by_event.setdefault(id(alert.event), []).append(alert)
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "WARNING": 3, "CRITICAL": 4}
    rows = []
    for index, event in enumerate(events, start=1):
        matches = by_event.get(id(event), [])
        primary = max(matches, key=lambda a: rank.get(a.severity, 0), default=None)
        rows.append({
            "timestamp": event.timestamp.isoformat(),
            "event_id": f"EVT-{event.raw_sha256[:10].upper()}" if event.raw_sha256 else f"EVT-LOCAL-{index:06d}",
            "source_ip": event.source_ip or "N/A",
            "severity": primary.severity if primary else (event.severity or "LOW"),
            "target_endpoint": event.fields.get("path") or event.fields.get("endpoint") or event.destination_ip or event.event_type,
            "attack_type": primary.title if primary else (event.action or event.event_type),
            "raw_payload": event.message,
            "description": primary.reason if primary else "No configured detection rule matched this event.",
            "raw_sha256": event.raw_sha256,
            "source_format": event.source_format,
        })
    return rows


def commit_dashboard_state(st, bundle: dict[str, Any], source_label: str) -> None:
    """Atomically connect evidence -> analysis -> dashboard -> audit."""
    analysis = bundle["analysis"]
    rows = analysis_to_logs(bundle)
    st.session_state.logs = rows
    st.session_state.selected_event = rows[0]["event_id"] if rows else None
    st.session_state.telemetry_source = source_label
    st.session_state.demo_mode = False
    st.session_state.analysis_result = analysis
    st.session_state.analysis_summary = {
        "risk_score": analysis["risk_score"],
        "parse_coverage": analysis["parse_coverage"],
        "unique_sources": len(analysis["unique_sources"]),
        "unique_destinations": len(analysis["unique_destinations"]),
        "rule_counts": analysis["rule_counts"],
        "severity_counts": analysis["severity_counts"],
    }
    st.session_state.analysis_completed_at = bundle["completed_at"]
    st.session_state.analysis_evidence_sha256 = bundle["sha256"]
    st.session_state.pipeline_source = source_label
    st.session_state.pipeline_stage = "COMPLETE"
    audit_event("EVIDENCE_ANALYSIS", source_label, bundle["sha256"])


def stage_status() -> dict[str, str]:
    return {
        "INGEST": "READY",
        "VALIDATE": "READY",
        "ANALYZE": "READY",
        "CORRELATE": "READY",
        "RISK": "READY",
        "INVESTIGATE": "READY",
        "RESPOND": "APPROVAL_REQUIRED",
        "AUDIT": "READY",
    }
