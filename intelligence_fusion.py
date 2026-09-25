"""Defensive intelligence-fusion primitives for Vanguard.

Offline-first, dependency-free core. External feed adapters belong above this layer.
No network collection or response actions are performed here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Any

IOC_RE = re.compile(
    r"(?P<url>https?://[^\s<>'\"]+)"
    r"|(?P<email>\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)"
    r"|(?P<sha256>\b[a-fA-F0-9]{64}\b)"
    r"|(?P<sha1>\b[a-fA-F0-9]{40}\b)"
    r"|(?P<md5>\b[a-fA-F0-9]{32}\b)"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class IntelligenceItem:
    value: str
    kind: str
    observed_at: str
    source: str
    source_reliability: float = 0.5
    confidence: float = 0.5
    state: str = "OBSERVED"
    evidence_sha256: str = ""
    expires_at: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evidence_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def extract_iocs(text: str, *, source: str = "local-evidence",
                 observed_at: str | None = None) -> list[IntelligenceItem]:
    """Extract passive IOCs from text without contacting any external system."""
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    digest = evidence_digest(text)
    found: list[IntelligenceItem] = []
    seen: set[tuple[str, str]] = set()

    for match in IOC_RE.finditer(text):
        kind = match.lastgroup or "unknown"
        value = match.group(0).rstrip(".,;:)]}")
        if kind == "ipv4" and not _valid_ipv4(value):
            continue
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        found.append(
            IntelligenceItem(
                value=value,
                kind=kind,
                observed_at=timestamp,
                source=source,
                confidence=0.8,
                state="OBSERVED",
                evidence_sha256=digest,
            )
        )
    priority = {"url": 0, "email": 1, "sha256": 2, "sha1": 3, "md5": 4, "ipv4": 5}
    return sorted(found, key=lambda item: (priority.get(item.kind, 99), item.value.lower()))


def corroboration_score(items: list[IntelligenceItem]) -> float:
    """Combine source reliability and confidence, bounded to [0, 1]."""
    if not items:
        return 0.0
    independent_sources = {item.source for item in items}
    evidence = sum(
        max(0.0, min(1.0, item.source_reliability))
        * max(0.0, min(1.0, item.confidence))
        for item in items
    ) / len(items)
    diversity = min(1.0, max(0, len(independent_sources) - 1))
    return round(min(1.0, evidence * (0.7 + 0.3 * diversity)), 4)


def relate(source: str, target: str, relation: str,
           *, confidence: float = 0.5) -> dict[str, Any]:
    """Create a graph-like relationship without requiring a graph database."""
    return {
        "source": source,
        "target": target,
        "relation": relation,
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
    }


def to_stix_like_bundle(items: list[IntelligenceItem]) -> dict[str, Any]:
    """Serialize the internal model to a stable STIX-shaped interchange envelope.

    This deliberately avoids requiring the stix2 package in Vanguard's offline core.
    A future optional adapter can emit fully validated STIX 2.1 objects.
    """
    objects = []
    for item in items:
        object_id = f"indicator--{hashlib.sha256((item.kind + ':' + item.value).encode()).hexdigest()[:32]}"
        objects.append(
            {
                "type": "indicator",
                "id": object_id,
                "spec_version": "2.1",
                "created": item.observed_at,
                "modified": item.observed_at,
                "pattern_type": "stix",
                "pattern": f"[{item.kind}:value = '{item.value}']",
                "confidence": round(item.confidence * 100),
                "labels": list(item.tags),
                "x_vanguard_state": item.state,
                "x_vanguard_source": item.source,
                "x_vanguard_evidence_sha256": item.evidence_sha256,
            }
        )
    return {"type": "bundle", "spec_version": "2.1", "objects": objects}
