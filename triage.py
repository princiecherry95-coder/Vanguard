"""Alert-fatigue reduction: group repeated findings without deleting evidence."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Iterable

from detection_registry import get_rule
from engine import Alert


def _fingerprint(alert: Alert) -> str:
    signature = alert.event.fields.get("signature", "")
    return "|".join([
        alert.rule_id,
        alert.event.source_ip or "",
        alert.event.destination_ip or "",
        signature,
        alert.event.fields.get("app_proto", ""),
    ])


def build_analyst_queue(alerts: Iterable[Alert], window_seconds: int = 300) -> list[dict]:
    groups: dict[str, dict] = {}
    for alert in sorted(alerts, key=lambda item: item.event.timestamp):
        rule = get_rule(alert.rule_id)
        fp = _fingerprint(alert)
        current = groups.get(fp)
        if current is None or (alert.event.timestamp - current["last_seen"]).total_seconds() > window_seconds:
            current = {
                "alert_id": f"FND-{len(groups)+1:06d}",
                "fingerprint": fp,
                "rule_id": alert.rule_id,
                "rule_version": rule.version,
                "title": rule.title,
                "severity": alert.severity,
                "confidence": rule.confidence,
                "category": rule.category,
                "mitre_technique": rule.mitre_technique,
                "first_seen": alert.event.timestamp,
                "last_seen": alert.event.timestamp,
                "count": 0,
                "sources": set(),
                "destinations": set(),
                "events": [],
                "reason": alert.reason,
                "guidance": rule.analyst_guidance,
                "correlated": False,
            }
            groups[fp] = current
        current["count"] += 1
        current["last_seen"] = max(current["last_seen"], alert.event.timestamp)
        if alert.event.source_ip:
            current["sources"].add(alert.event.source_ip)
        if alert.event.destination_ip:
            current["destinations"].add(alert.event.destination_ip)
        current["events"].append(alert.event)
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if rank.get(alert.severity, 1) > rank.get(current["severity"], 1):
            current["severity"] = alert.severity

    queue = []
    for group in groups.values():
        group["sources"] = sorted(group["sources"])
        group["destinations"] = sorted(group["destinations"])
        group["event_count"] = len(group["events"])
        group["evidence_ids"] = [event.raw_sha256 for event in group["events"]]
        group.pop("events", None)
        queue.append(group)
    queue.sort(key=lambda item: ({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(item["severity"], 1), item["count"]), reverse=True)
    return queue
