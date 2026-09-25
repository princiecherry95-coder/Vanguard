"""Offline SOC analytics over normalized dashboard records."""
from __future__ import annotations
from collections import Counter
from datetime import datetime
from typing import Any
import pandas as pd

SEVERITY_ORDER = ["CRITICAL","HIGH","WARNING","MEDIUM","LOW"]

def build_dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(rows or [])
    if df.empty:
        return pd.DataFrame(columns=["timestamp","event_id","severity","source_ip","target_endpoint","attack_type"])
    for col in ["severity","source_ip","target_endpoint","attack_type"]:
        if col not in df: df[col] = ""
    if "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df

def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    df = build_dataframe(rows)
    sev = {s:int((df["severity"].astype(str).str.upper()==s).sum()) for s in SEVERITY_ORDER} if not df.empty else {s:0 for s in SEVERITY_ORDER}
    return {
        "records": int(len(df)),
        "unique_sources": int(df["source_ip"].replace({"N/A":pd.NA,"":pd.NA}).nunique()) if not df.empty else 0,
        "unique_targets": int(df["target_endpoint"].replace({"N/A":pd.NA,"":pd.NA}).nunique()) if not df.empty else 0,
        "unique_attack_types": int(df["attack_type"].replace({"N/A":pd.NA,"":pd.NA}).nunique()) if not df.empty else 0,
        "severity_counts": sev,
        "top_sources": df["source_ip"].value_counts().head(10).to_dict() if not df.empty else {},
        "top_attack_types": df["attack_type"].value_counts().head(10).to_dict() if not df.empty else {},
        "hourly": hourly_counts(df),
    }

def hourly_counts(df: pd.DataFrame) -> dict[str,int]:
    if df.empty or "timestamp" not in df:
        return {}
    valid = df["timestamp"].dropna()
    return {str(k):int(v) for k,v in valid.dt.strftime("%Y-%m-%d %H:00").value_counts().sort_index().items()}

def attack_matrix(rows: list[dict[str,Any]]) -> pd.DataFrame:
    df=build_dataframe(rows)
    if df.empty: return pd.DataFrame()
    return pd.crosstab(df["attack_type"], df["severity"]).sort_values(by=list(df["severity"].unique()), ascending=False)

def trend(rows: list[dict[str,Any]]) -> pd.DataFrame:
    df=build_dataframe(rows)
    if df.empty or df["timestamp"].isna().all(): return pd.DataFrame(columns=["period","records","alerts"])
    x=df.dropna(subset=["timestamp"]).copy()
    x["period"]=x["timestamp"].dt.floor("h")
    x["is_alert"]=x["severity"].str.upper().isin(["CRITICAL","HIGH","WARNING","MEDIUM"])
    return x.groupby("period").agg(records=("event_id","count"),alerts=("is_alert","sum")).reset_index()
