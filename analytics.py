"""Offline SOC data analytics and analyst-oriented metrics."""
from __future__ import annotations

from typing import Any
import pandas as pd

SEVERITY_ORDER = ["CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW"]


def build_dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(rows or [])
    if df.empty:
        return pd.DataFrame(columns=["timestamp", "event_id", "severity", "source_ip", "target_endpoint", "attack_type"])
    for col in ["severity", "source_ip", "target_endpoint", "attack_type", "event_id"]:
        if col not in df:
            df[col] = ""
    df["severity"] = df["severity"].fillna("").astype(str).str.upper()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    df = build_dataframe(rows)
    if df.empty:
        return {
            "records": 0, "unique_sources": 0, "unique_targets": 0, "unique_attack_types": 0,
            "severity_counts": {s: 0 for s in SEVERITY_ORDER},
            "top_sources": {}, "top_attack_types": {}, "hourly": {},
            "alert_rate_pct": 0.0, "critical_rate_pct": 0.0,
            "first_seen": None, "last_seen": None,
        }
    severity_counts = {s: int((df["severity"] == s).sum()) for s in SEVERITY_ORDER}
    alert_mask = df["severity"].isin(["CRITICAL", "HIGH", "WARNING", "MEDIUM"])
    valid_times = df["timestamp"].dropna()
    return {
        "records": int(len(df)),
        "unique_sources": int(df["source_ip"].replace({"N/A": pd.NA, "": pd.NA}).nunique()),
        "unique_targets": int(df["target_endpoint"].replace({"N/A": pd.NA, "": pd.NA}).nunique()),
        "unique_attack_types": int(df["attack_type"].replace({"N/A": pd.NA, "": pd.NA}).nunique()),
        "severity_counts": severity_counts,
        "top_sources": df["source_ip"].replace({"N/A": pd.NA, "": pd.NA}).value_counts().head(10).to_dict(),
        "top_attack_types": df["attack_type"].replace({"N/A": pd.NA, "": pd.NA}).value_counts().head(10).to_dict(),
        "hourly": hourly_counts(df),
        "alert_rate_pct": round(float(alert_mask.mean() * 100), 2),
        "critical_rate_pct": round(float((df["severity"] == "CRITICAL").mean() * 100), 2),
        "first_seen": valid_times.min().isoformat() if not valid_times.empty else None,
        "last_seen": valid_times.max().isoformat() if not valid_times.empty else None,
    }


def hourly_counts(df: pd.DataFrame) -> dict[str, int]:
    if df.empty or "timestamp" not in df:
        return {}
    valid = df["timestamp"].dropna()
    return {str(k): int(v) for k, v in valid.dt.strftime("%Y-%m-%d %H:00").value_counts().sort_index().items()}


def attack_matrix(rows: list[dict[str, Any]]) -> pd.DataFrame:
    df = build_dataframe(rows)
    if df.empty:
        return pd.DataFrame()
    return pd.crosstab(df["attack_type"], df["severity"]).reindex(columns=SEVERITY_ORDER, fill_value=0).sort_values(
        by=SEVERITY_ORDER, ascending=False
    )


def trend(rows: list[dict[str, Any]]) -> pd.DataFrame:
    df = build_dataframe(rows)
    if df.empty or df["timestamp"].isna().all():
        return pd.DataFrame(columns=["period", "records", "alerts", "critical"])
    x = df.dropna(subset=["timestamp"]).copy()
    x["period"] = x["timestamp"].dt.floor("h")
    x["is_alert"] = x["severity"].isin(["CRITICAL", "HIGH", "WARNING", "MEDIUM"])
    x["is_critical"] = x["severity"].eq("CRITICAL")
    return x.groupby("period").agg(records=("event_id", "count"), alerts=("is_alert", "sum"), critical=("is_critical", "sum")).reset_index()


def findings_dataframe(analysis: dict[str, Any] | None) -> pd.DataFrame:
    findings = (analysis or {}).get("analyst_alerts", [])
    if not findings:
        return pd.DataFrame()
    rows = []
    for item in findings:
        rows.append({
            "alert_id": item.get("alert_id"),
            "rule_id": item.get("rule_id"),
            "rule_version": item.get("rule_version"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "category": item.get("category"),
            "mitre_technique": item.get("mitre_technique"),
            "count": item.get("count", 0),
            "sources": len(item.get("sources", [])),
            "destinations": len(item.get("destinations", [])),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "guidance": item.get("guidance"),
        })
    return pd.DataFrame(rows).sort_values(["severity", "count"], ascending=[True, False])


def rule_counts_dataframe(analysis: dict[str, Any] | None) -> pd.DataFrame:
    return pd.DataFrame(
        list(((analysis or {}).get("rule_counts") or {}).items()),
        columns=["rule_id", "count"],
    ).sort_values("count", ascending=False) if (analysis or {}).get("rule_counts") else pd.DataFrame(columns=["rule_id", "count"])
