"""Deterministic analyst risk scoring for Vanguard-SIEM."""
from __future__ import annotations

SEVERITY_WEIGHT = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}
CONFIDENCE_WEIGHT = {"LOW": 0.60, "MEDIUM": 0.80, "HIGH": 1.00}


def alert_risk(severity: str, confidence: str = "MEDIUM", frequency: int = 1, correlated: bool = False) -> float:
    base = float(SEVERITY_WEIGHT.get(str(severity).upper(), 5))
    confidence_factor = CONFIDENCE_WEIGHT.get(str(confidence).upper(), 0.8)
    frequency_factor = min(1.35, 1.0 + max(0, int(frequency) - 1) * 0.03)
    correlation_factor = 1.15 if correlated else 1.0
    return min(100.0, base * confidence_factor * frequency_factor * correlation_factor)


def analysis_risk(analyst_alerts: list[dict]) -> int:
    if not analyst_alerts:
        return 0
    scores = [alert_risk(a.get("severity", "LOW"), a.get("confidence", "MEDIUM"), a.get("count", 1), a.get("correlated", False)) for a in analyst_alerts]
    # Keep the score stable and bounded; volume alone cannot force 100.
    top = sorted(scores, reverse=True)[:10]
    weighted = sum(top) / max(1, len(top)) + min(30.0, len(analyst_alerts) * 2.0)
    return int(round(min(100.0, weighted)))
