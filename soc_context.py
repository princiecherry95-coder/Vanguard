"""Evidence-derived SOC context and telemetry-quality analytics.

All metrics are computed from supplied records. The module never invents
operational values and never treats missing telemetry as zero.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import median
from typing import Iterable


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "WARNING": 2, "HIGH": 3, "CRITICAL": 4}


def _text(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _timestamp(row: dict) -> datetime | None:
    value = _text(row, "timestamp", "time", "datetime")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def evidence_quality(rows: Iterable[dict]) -> dict[str, object]:
    rows = list(rows)
    total = len(rows)
    fields = {
        "timestamp": lambda r: _timestamp(r) is not None,
        "source": lambda r: bool(_text(r, "source_ip", "source", "hostname", "host")),
        "destination": lambda r: bool(_text(r, "destination_ip", "destination", "target_endpoint")),
        "severity": lambda r: bool(_text(r, "severity")),
        "event_type": lambda r: bool(_text(r, "attack_type", "event_type", "action")),
        "user": lambda r: bool(_text(r, "user", "username", "account")),
        "raw_evidence": lambda r: bool(_text(r, "raw_payload", "message", "description")),
    }
    coverage = {
        name: round(sum(bool(check(r)) for r in rows) / total * 100, 1) if total else None
        for name, check in fields.items()
    }
    parseable_timestamps = [ts for r in rows if (ts := _timestamp(r)) is not None]
    future = sum(ts > datetime.now(timezone.utc) for ts in parseable_timestamps)
    return {
        "records": total,
        "field_coverage": coverage,
        "missing_timestamp": sum(not bool(_timestamp(r)) for r in rows),
        "future_timestamps": future,
        "timestamp_quality": coverage["timestamp"],
    }


def duplicate_analysis(rows: Iterable[dict]) -> dict[str, object]:
    rows = list(rows)
    fingerprints: list[str] = []
    for row in rows:
        value = _text(row, "raw_sha256", "event_id")
        if not value:
            value = "|".join(_text(row, key) for key in ("timestamp", "source_ip", "destination_ip", "attack_type", "raw_payload"))
        fingerprints.append(value)
    counts = Counter(fingerprints)
    duplicates = sum(count - 1 for count in counts.values() if count > 1)
    return {
        "records": len(rows),
        "unique_events": len(counts),
        "duplicate_records": duplicates,
        "duplicate_rate": round(duplicates / len(rows) * 100, 1) if rows else None,
    }


def source_inventory(rows: Iterable[dict]) -> list[dict[str, object]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        source = _text(row, "source_ip", "source", "hostname", "host") or "UNATTRIBUTED"
        groups[source].append(row)
    result = []
    for source, items in groups.items():
        times = sorted(ts for row in items if (ts := _timestamp(row)) is not None)
        severities = [SEVERITY_ORDER.get(_text(row, "severity").upper(), 1) for row in items]
        result.append({
            "source": source,
            "events": len(items),
            "first_seen": times[0].isoformat() if times else "UNAVAILABLE",
            "last_seen": times[-1].isoformat() if times else "UNAVAILABLE",
            "max_severity": max((k for k, v in SEVERITY_ORDER.items() if v == max(severities)), default="LOW"),
            "unique_users": len({_text(row, "user", "username", "account") for row in items if _text(row, "user", "username", "account")}),
            "unique_targets": len({_text(row, "destination_ip", "destination", "target_endpoint") for row in items if _text(row, "destination_ip", "destination", "target_endpoint")}),
        })
    return sorted(result, key=lambda item: (-int(item["events"]), str(item["source"])))


def observed_timeline(rows: Iterable[dict], limit: int = 100) -> list[dict[str, object]]:
    ordered = sorted(
        [row for row in rows if _timestamp(row) is not None],
        key=lambda row: _timestamp(row),
    )
    timeline = []
    for row in ordered[-limit:]:
        timeline.append({
            "timestamp": _timestamp(row).isoformat(),
            "event_id": _text(row, "event_id", "raw_sha256") or "UNIDENTIFIED",
            "source": _text(row, "source_ip", "source", "hostname", "host") or "UNATTRIBUTED",
            "user": _text(row, "user", "username", "account") or "UNATTRIBUTED",
            "severity": _text(row, "severity").upper() or "UNSPECIFIED",
            "activity": _text(row, "attack_type", "event_type", "action") or "UNSPECIFIED",
        })
    return timeline


def telemetry_window(rows: Iterable[dict]) -> dict[str, object]:
    timestamps = sorted(ts for row in rows if (ts := _timestamp(row)) is not None)
    return {
        "first_seen": timestamps[0].isoformat() if timestamps else None,
        "last_seen": timestamps[-1].isoformat() if timestamps else None,
        "duration_seconds": (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0,
        "timestamped_records": len(timestamps),
    }


def activity_baseline(rows: Iterable[dict]) -> dict[str, object]:
    """Return an explainable hourly baseline only when enough evidence exists."""
    buckets = Counter()
    for row in rows:
        ts = _timestamp(row)
        if ts is not None:
            buckets[ts.strftime("%Y-%m-%d %H:00")] += 1
    values = list(buckets.values())
    if len(values) < 3:
        return {"state": "INSUFFICIENT_EVIDENCE", "buckets": len(values), "median": None, "peak": None, "peak_period": None}
    baseline = median(values)
    peak_period, peak = max(buckets.items(), key=lambda item: item[1])
    deviation = round(((peak - baseline) / baseline) * 100, 1) if baseline else None
    return {
        "state": "OBSERVED_BASELINE",
        "buckets": len(values),
        "median": baseline,
        "peak": peak,
        "peak_period": peak_period,
        "peak_deviation_percent": deviation,
    }


def detection_coverage(rows: Iterable[dict], analysis_result: dict | None = None) -> dict[str, object]:
    rows = list(rows)
    total = len(rows)
    observed = {
        "authentication": sum("AUTH" in _text(r, "attack_type", "event_type", "action").upper() for r in rows),
        "network": sum(bool(_text(r, "source_ip")) or bool(_text(r, "destination_ip")) for r in rows),
        "web": sum(any(token in _text(r, "target_endpoint", "attack_type", "event_type").upper() for token in ("HTTP", "WEB", "XSS", "SQL", "UPLOAD")) for r in rows),
        "identity": sum(bool(_text(r, "user", "username", "account")) for r in rows),
        "process": sum(bool(_text(r, "process", "process_name", "process_id")) for r in rows),
    }
    # These are evidence-presence rates, not claims that a security control has
    # detected all threats in the category.
    rates = {key: round(value / total * 100, 1) if total else None for key, value in observed.items()}
    alerts = len((analysis_result or {}).get("alerts", []))
    return {"records": total, "observed_category_rates": rates, "analyzed_alerts": alerts}



def asset_context(rows: Iterable[dict]) -> list[dict[str, object]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        asset = _text(row, "hostname", "host", "asset_id", "source_ip", "source") or "UNATTRIBUTED"
        groups[asset].append(row)
    result = []
    for asset, items in groups.items():
        times = sorted(ts for row in items if (ts := _timestamp(row)) is not None)
        users = sorted({_text(row, "user", "username", "account") for row in items if _text(row, "user", "username", "account")})
        targets = sorted({_text(row, "destination_ip", "destination", "target_endpoint") for row in items if _text(row, "destination_ip", "destination", "target_endpoint")})
        severities = [SEVERITY_ORDER.get(_text(row, "severity").upper(), 1) for row in items]
        max_value = max(severities) if severities else 1
        max_severity = next((name for name, value in SEVERITY_ORDER.items() if value == max_value), "LOW")
        result.append({
            "asset": asset,
            "events": len(items),
            "max_severity": max_severity,
            "users": len(users),
            "targets": len(targets),
            "first_seen": times[0].isoformat() if times else "UNAVAILABLE",
            "last_seen": times[-1].isoformat() if times else "UNAVAILABLE",
        })
    return sorted(result, key=lambda item: (-int(item["events"]), str(item["asset"])))


def identity_activity(rows: Iterable[dict]) -> list[dict[str, object]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        identity = _text(row, "user", "username", "account")
        if identity:
            groups[identity].append(row)
    result = []
    for identity, items in groups.items():
        result.append({
            "identity": identity,
            "events": len(items),
            "unique_sources": len({_text(r, "source_ip", "source", "hostname", "host") for r in items if _text(r, "source_ip", "source", "hostname", "host")}),
            "unique_targets": len({_text(r, "destination_ip", "destination", "target_endpoint") for r in items if _text(r, "destination_ip", "destination", "target_endpoint")}),
            "max_severity": max((_text(r, "severity").upper() for r in items), key=lambda value: SEVERITY_ORDER.get(value, 1), default="LOW"),
        })
    return sorted(result, key=lambda item: (-int(item["events"]), str(item["identity"])))


def incident_context(analysis_result: dict | None) -> list[dict[str, object]]:
    incidents = (analysis_result or {}).get("incidents", [])
    result = []
    for incident in incidents:
        result.append({
            "incident_id": incident.get("incident_id", "UNIDENTIFIED"),
            "severity": incident.get("severity", "UNSPECIFIED"),
            "first_seen": str(incident.get("first_seen", "UNAVAILABLE")),
            "last_seen": str(incident.get("last_seen", "UNAVAILABLE")),
            "alerts": len(incident.get("alerts", [])),
            "sources": len(incident.get("sources", [])),
        })
    return result

def build_soc_context(rows: Iterable[dict], analysis_result: dict | None = None) -> dict[str, object]:
    rows = list(rows)
    return {
        "window": telemetry_window(rows),
        "quality": evidence_quality(rows),
        "duplicates": duplicate_analysis(rows),
        "sources": source_inventory(rows),
        "assets": asset_context(rows),
        "identities": identity_activity(rows),
        "incidents": incident_context(analysis_result),
        "timeline": observed_timeline(rows),
        "baseline": activity_baseline(rows),
        "coverage": detection_coverage(rows, analysis_result),
    }
