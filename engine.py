"""Offline-first SOC parsing, sanitization, detection and correlation engine.

All logic is deterministic and local. No network calls, cloud APIs or external
threat-intelligence feeds are used by this module.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


MAX_LINE_LENGTH = 16_384
MAX_FIELD_LENGTH = 2_048

SENSITIVE_PATTERNS = (
    (re.compile(r"(?i)(password\s*[=:]\s*)[^&\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(passwd\s*[=:]\s*)[^&\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[=:]\s*)[^&\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^&\s,;]+"), r"\1[REDACTED]"),
)

PATTERNS = (
    ("SQL_INJECTION", re.compile(r"(?i)(?:union\s+select|(?:'|%27)\s*(?:or|and)\s+(?:'|%27)?\d|sleep\s*\(|information_schema)")),
    ("XSS", re.compile(r"(?is)(?:<script\b|javascript:|on(?:error|load|click)\s*=)")),
    ("PATH_MANIPULATION", re.compile(r"(?i)(?:\.\./|%2e%2e%2f|%2e%2e%5c)")),
    ("SUSPICIOUS_UPLOAD", re.compile(r"(?i)(?:filename=.*\.(?:jsp|php|asp|aspx|exe|dll|sh|ps1)\b|content-type=.*(?:x-httpd-php|octet-stream))")),
    ("AUTH_FAILURE", re.compile(r"(?i)(?:failed password|authentication failure|login failed|invalid password|bad credentials)")),
    ("PRIVILEGE_ESCALATION", re.compile(r"(?i)(?:sudo|su:|added to (?:sudo|administrators|wheel)|privilege escalation|role=admin)")),
)

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    process_id: int | None = None
    event_type: str = "UNKNOWN"
    action: str = ""
    severity: str = "LOW"
    message: str = ""
    raw_sha256: str = ""
    source_format: str = "unknown"
    fields: dict[str, str] = field(default_factory=dict)

@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    reason: str
    event: NormalizedEvent
    evidence: dict[str, object] = field(default_factory=dict)

def _clip(value: str, limit: int = MAX_FIELD_LENGTH) -> str:
    return value[:limit]

def sanitize(raw: str) -> str:
    """Bound size, remove dangerous controls, and redact credential-like values."""
    if not isinstance(raw, str):
        raw = str(raw)
    raw = raw[:MAX_LINE_LENGTH]
    raw = "".join(ch for ch in raw if ch in "\t\n\r" or ord(ch) >= 32)
    for pattern, replacement in SENSITIVE_PATTERNS:
        raw = pattern.sub(replacement, raw)
    return raw[:MAX_LINE_LENGTH]

def _timestamp(value: str | None) -> datetime:
    if value:
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)

def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

def _parse_suricata_json(clean: str, source_format: str) -> NormalizedEvent | None:
    try:
        payload = json.loads(clean)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    # Suricata EVE JSON has common fields such as timestamp, event_type,
    # src_ip/dest_ip and an event-specific object such as alert/http/dns.
    event_type = str(payload.get("event_type") or "UNKNOWN")
    alert_data = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    http_data = payload.get("http") if isinstance(payload.get("http"), dict) else {}
    flow_data = payload.get("flow") if isinstance(payload.get("flow"), dict) else {}
    src = _valid_ip(str(payload.get("src_ip") or flow_data.get("src_ip") or "")) 
    dst = _valid_ip(str(payload.get("dest_ip") or flow_data.get("dest_ip") or ""))
    timestamp_value = payload.get("timestamp")
    timestamp = _timestamp(str(timestamp_value) if timestamp_value else None)
    signature = str(alert_data.get("signature") or "")
    category = str(alert_data.get("category") or "")
    alert_action = str(alert_data.get("action") or "")
    app_proto = str(payload.get("app_proto") or "")
    url = str(http_data.get("url") or "")
    method = str(http_data.get("http_method") or "")
    user = None
    for key in ("user", "username", "account"):
        if payload.get(key) is not None:
            user = _clip(str(payload[key]))
            break
    if user is None and isinstance(payload.get("metadata"), dict):
        candidate = payload["metadata"].get("user")
        if candidate is not None:
            user = _clip(str(candidate))
    fields = {}
    for key in ("flow_id", "proto", "src_port", "dest_port", "app_proto"):
        if key in payload:
            fields[key] = _clip(str(payload[key]))
    if signature:
        fields["signature"] = _clip(signature)
    if category:
        fields["category"] = _clip(category)
    if alert_action:
        fields["alert_action"] = _clip(alert_action)
    severity_value = alert_data.get("severity")
    try:
        numeric_severity = int(severity_value)
    except (TypeError, ValueError):
        numeric_severity = 0
    severity = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(numeric_severity, "LOW")
    action = "SURICATA_ALERT" if event_type.lower() == "alert" or signature else ""
    parts = [event_type, signature, category, alert_action, app_proto, method, url]
    message = _clip(" | ".join(part for part in parts if part))
    if not message:
        message = _clip(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return NormalizedEvent(
        timestamp=timestamp,
        source_ip=src,
        destination_ip=dst,
        user=user,
        process_id=None,
        event_type=event_type.upper(),
        action=action,
        severity=severity,
        message=sanitize(message),
        raw_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest(),
        source_format=source_format,
        fields=fields,
    )


def parse_line(raw: str, source_format: str = "auto") -> NormalizedEvent:
    """Parse common syslog/auth/web/firewall-like lines without executing payloads."""
    clean = sanitize(raw)
    structured = _parse_suricata_json(clean, source_format)
    if structured is not None:
        return structured
    timestamp = None
    source_ip = None
    destination_ip = None
    user = None
    pid = None
    event_type = "UNKNOWN"
    action = ""
    fields: dict[str, str] = {}

    # ISO timestamp, common access-log timestamp, or syslog month/day time.
    m = re.search(r"\b(\d{4}-\d{2}-\d{2}T[^\s]+|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", clean)
    if m:
        timestamp = m.group(1)
    else:
        m = re.search(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b", clean)
        if m:
            timestamp = m.group(1)

    ips = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", clean)
    valid_ips = [_valid_ip(x) for x in ips]
    valid_ips = [x for x in valid_ips if x]
    if valid_ips:
        source_ip = valid_ips[0]
    if len(valid_ips) > 1:
        destination_ip = valid_ips[1]

    m = re.search(r"(?i)\b(?:user|username|account)=?([A-Za-z0-9._@-]+)", clean)
    if m:
        user = _clip(m.group(1))
        fields["user"] = user

    m = re.search(r"(?i)\b(?:pid|process[_-]?id)=(\d+)\b", clean)
    if m:
        pid = int(m.group(1))

    if re.search(r"(?i)(?:failed password|authentication failure|login failed|invalid password|bad credentials)", clean):
        event_type, action = "AUTHENTICATION", "LOGIN_FAILURE"
    elif re.search(r"(?i)(?:accepted password|login success|authentication successful)", clean):
        event_type, action = "AUTHENTICATION", "LOGIN_SUCCESS"
    elif re.search(r"(?i)(?:sudo|privilege|added to (?:sudo|administrators|wheel))", clean):
        event_type, action = "PRIVILEGE", "PRIVILEGE_CHANGE"
    elif re.search(r"(?i)(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/", clean):
        event_type, action = "WEB", "HTTP_REQUEST"
    elif re.search(r"(?i)(?:deny|drop|blocked|allow|accept)\s+", clean):
        event_type, action = "FIREWALL", "NETWORK_DECISION"

    return NormalizedEvent(
        timestamp=_timestamp(timestamp),
        source_ip=source_ip,
        destination_ip=destination_ip,
        user=user,
        process_id=pid,
        event_type=event_type,
        action=action,
        severity="LOW",
        message=_clip(clean),
        raw_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest(),
        source_format=source_format,
        fields=fields,
    )

def detect(event: NormalizedEvent) -> list[Alert]:
    alerts: list[Alert] = []
    message = event.message
    if event.event_type == "ALERT" or event.action == "SURICATA_ALERT":
        signature = event.fields.get("signature", "Suricata alert")
        category = event.fields.get("category", "Suricata detection")
        alerts.append(Alert(
            "SURICATA_ALERT", event.severity if event.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "HIGH",
            signature[:MAX_FIELD_LENGTH],
            f"Suricata reported a signature match: {category[:MAX_FIELD_LENGTH]}.",
            event, {"category": category, "signature": signature, "alert_action": event.fields.get("alert_action", "")}))

    for rule_id, pattern in PATTERNS:
        if pattern.search(message):
            severity = "HIGH"
            if rule_id in {"SQL_INJECTION", "XSS", "PRIVILEGE_ESCALATION"}:
                severity = "CRITICAL"
            title = {
                "SQL_INJECTION": "Web application injection indicator",
                "XSS": "Cross-site scripting indicator",
                "PATH_MANIPULATION": "Path manipulation indicator",
                "SUSPICIOUS_UPLOAD": "Suspicious file upload",
                "AUTH_FAILURE": "Authentication failure",
                "PRIVILEGE_ESCALATION": "Privilege escalation indicator",
            }[rule_id]
            alerts.append(Alert(rule_id, severity, title,
                f"Local rule {rule_id} matched a sanitized event payload.",
                event, {"pattern": rule_id}))

    return alerts

def detect_behavior(events: Iterable[NormalizedEvent], window_seconds: int = 120,
                    failure_threshold: int = 5, scan_threshold: int = 12) -> list[Alert]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    failures: dict[str, deque[NormalizedEvent]] = defaultdict(deque)
    targets: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    distributed_failures: deque[NormalizedEvent] = deque()

    for event in ordered:
        if event.action == "LOGIN_FAILURE" and event.source_ip:
            distributed_failures.append(event)
            while distributed_failures and (event.timestamp - distributed_failures[0].timestamp).total_seconds() > window_seconds:
                distributed_failures.popleft()
            unique_sources = {x.source_ip for x in distributed_failures if x.source_ip}
            if len(distributed_failures) >= failure_threshold and len(unique_sources) >= 2 and not any(
                a.rule_id == "DISTRIBUTED_BRUTE_FORCE" for a in alerts
            ):
                alerts.append(Alert(
                    "DISTRIBUTED_BRUTE_FORCE", "HIGH", "Distributed brute-force authentication pattern",
                    f"{len(distributed_failures)} failed authentication events from {len(unique_sources)} sources within {window_seconds} seconds.",
                    event, {"failure_count": len(distributed_failures), "unique_sources": len(unique_sources),
                            "window_seconds": window_seconds}))
            q = failures[event.source_ip]
            q.append(event)
            while q and (event.timestamp - q[0].timestamp).total_seconds() > window_seconds:
                q.popleft()
            if len(q) == failure_threshold:
                alerts.append(Alert(
                    "BRUTE_FORCE_AUTH", "HIGH", "Brute-force authentication pattern",
                    f"{len(q)} failed authentication events from one source within {window_seconds} seconds.",
                    event, {"failure_count": len(q), "window_seconds": window_seconds,
                            "source_ip": event.source_ip}))

        if event.source_ip and event.destination_ip:
            q2 = targets[event.source_ip]
            q2.append((event.timestamp, event.destination_ip))
            while q2 and (event.timestamp - q2[0][0]).total_seconds() > window_seconds:
                q2.popleft()
            unique_targets = len({target for _, target in q2})
            if unique_targets == scan_threshold:
                alerts.append(Alert(
                    "LATERAL_SCAN", "HIGH", "Suspicious network scanning pattern",
                    f"{unique_targets} unique destinations observed from one source within {window_seconds} seconds.",
                    event, {"unique_destinations": unique_targets,
                            "window_seconds": window_seconds, "source_ip": event.source_ip}))

    return alerts

def correlate(alerts: Iterable[Alert], window_seconds: int = 300) -> list[dict[str, object]]:
    grouped: list[dict[str, object]] = []
    for alert in sorted(alerts, key=lambda a: a.event.timestamp):
        attached = None
        for incident in grouped:
            same_source = alert.event.source_ip and alert.event.source_ip in incident["sources"]
            within = (alert.event.timestamp - incident["last_seen"]).total_seconds() <= window_seconds
            if same_source and within:
                attached = incident
                break
        if attached is None:
            attached = {
                "incident_id": "INC-" + alert.event.raw_sha256[:10].upper(),
                "first_seen": alert.event.timestamp,
                "last_seen": alert.event.timestamp,
                "sources": set(),
                "severity": alert.severity,
                "alerts": [],
            }
            grouped.append(attached)
        attached["sources"].add(alert.event.source_ip)
        attached["alerts"].append(alert)
        attached["last_seen"] = max(attached["last_seen"], alert.event.timestamp)
        if {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[alert.severity] > {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[attached["severity"]]:
            attached["severity"] = alert.severity
    return grouped
