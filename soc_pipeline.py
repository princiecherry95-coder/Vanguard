"""Unified local SOC pipeline shared by every Vanguard operating mode."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from audit import audit_event
from engine import analyze_events, parse_line
from ingestion import MAX_RECORDS, infer_upload_format, infer_upload_format_bytes, iter_upload_records, lines_from_upload, safe_uploaded_text, validate_upload_size


def _normalize_format(format_hint: str, text: str, filename: str) -> str:
    """Return one canonical parser format for UI labels and analysis."""
    requested = (format_hint or "AUTO").upper()
    if requested == "AUTO":
        requested = infer_upload_format(text, filename)
    if requested == "TEXT / SYSLOG":
        return "TEXT"
    return requested


def validate_bytes(data: bytes, filename: str, format_hint: str = "AUTO") -> dict[str, Any]:
    """Fast evidence gate. It never performs full event parsing."""
    text, digest = safe_uploaded_text(data, filename)
    actual_fmt = _normalize_format(format_hint, text, filename)
    lines = lines_from_upload(text, actual_fmt)
    if not lines:
        raise ValueError("No non-empty records were found.")
    if len(lines) > MAX_RECORDS:
        raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per evidence set.")
    sample_count = min(6, len(lines))
    return {
        "filename": filename,
        "format": actual_fmt,
        "records": len(lines),
        "parsed": 0,
        "parse_coverage": 0.0,
        "sample_records": sample_count,
        "sha256": digest,
        "source_formats": [actual_fmt],
        "validation_mode": "FAST_PREFLIGHT",
    }

def analyze_bytes(data: bytes, filename: str, format_hint: str = "AUTO") -> dict[str, Any]:
    """Single canonical path for upload/paste/collector evidence."""
    text, digest = safe_uploaded_text(data, filename)
    actual_fmt = _normalize_format(format_hint, text, filename)
    parse_fmt = actual_fmt
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


def analyze_bytes_incremental(data: bytes, filename: str, format_hint: str = "AUTO", on_chunk=None, chunk_size: int = 5000):
    """Analyze every evidence record while keeping UI previews bounded.

    JSONL/text/CSV records are streamed from the uploaded byte buffer. The
    complete normalized event set is retained for deterministic correlation
    and final dashboard state; only the visible preview is bounded.
    """
    validate_upload_size(len(data))
    import hashlib
    digest = hashlib.sha256(data).hexdigest()
    requested = (format_hint or "AUTO").upper()
    actual_fmt = infer_upload_format_bytes(data, filename) if requested == "AUTO" else (
        "TEXT" if requested == "TEXT / SYSLOG" else requested
    )
    events = []
    parsed_total = 0
    chunk = []
    for line in iter_upload_records(data, actual_fmt):
        chunk.append(line)
        if len(chunk) < max(1, chunk_size):
            continue
        parsed = []
        for record in chunk:
            try:
                parsed.append(parse_line(record, actual_fmt))
            except Exception:
                from engine import NormalizedEvent
                clean = str(record).strip()
                parsed.append(NormalizedEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=None,
                    destination_ip=None,
                    user=None,
                    process_id=None,
                    event_type="UNPARSED",
                    action="PARSE_ERROR",
                    severity="LOW",
                    message=clean[:4096],
                    raw_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest(),
                    source_format=actual_fmt,
                    fields={"parse_error": "record could not be normalized"},
                ))
        events.extend(parsed)
        parsed_total += len(parsed)
        if parsed_total > MAX_RECORDS:
            raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per evidence set.")
        if on_chunk is not None:
            on_chunk(parsed, parsed_total, None)
        chunk = []
    if chunk:
        parsed = []
        for record in chunk:
            try:
                parsed.append(parse_line(record, actual_fmt))
            except Exception:
                from engine import NormalizedEvent
                clean = str(record).strip()
                parsed.append(NormalizedEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_ip=None,
                    destination_ip=None,
                    user=None,
                    process_id=None,
                    event_type="UNPARSED",
                    action="PARSE_ERROR",
                    severity="LOW",
                    message=clean[:4096],
                    raw_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest(),
                    source_format=actual_fmt,
                    fields={"parse_error": "record could not be normalized"},
                ))
        events.extend(parsed)
        parsed_total += len(parsed)
        if parsed_total > MAX_RECORDS:
            raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per evidence set.")
        if on_chunk is not None:
            on_chunk(parsed, parsed_total, None)
    if parsed_total == 0:
        raise ValueError("No non-empty records were found.")
    analysis = analyze_events(events)
    return {
        "filename": filename, "format": actual_fmt, "sha256": digest, "records": parsed_total,
        "events": events, "analysis": analysis,
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
