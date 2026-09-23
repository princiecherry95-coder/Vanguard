from __future__ import annotations

import html
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from engine import analyze_events, correlate, detect, detect_behavior, detection_policy, parse_line
from ingestion import ALLOWED_UPLOAD_TYPES, MAX_RECORDS, MAX_UPLOAD_BYTES, infer_upload_format, lines_from_upload, safe_uploaded_text
from audit import audit_event
from distributed import EventBuffer
from firewall import block_ip
from remediation import propose, execute_approved
from threat_intel import ThreatIntelCache
from windows_events import available as windows_events_available
from local_ai import explain as local_ai_explain
from soc_pipeline import analyze_bytes, analyze_bytes_incremental, commit_dashboard_state, stage_status, validate_bytes

st.set_page_config(page_title="Vanguard-SIEM", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

MOCK_LOGS = [
    {"timestamp":"2026-09-17 19:52:14","event_id":"EVT-7F31A9","source_ip":"10.42.17.91","severity":"CRITICAL","target_endpoint":"/api/auth/login","attack_type":"SQL Injection / Tautology Bypass","raw_payload":"' OR '1'='1' --","description":"The request attempts to manipulate an authentication query so the condition evaluates as true, potentially bypassing normal credential validation."},
    {"timestamp":"2026-09-17 19:51:42","event_id":"EVT-0C82D4","source_ip":"10.42.22.14","severity":"CRITICAL","target_endpoint":"/search?q=users","attack_type":"Cross-Site Scripting (XSS)","raw_payload":"<script>alert(document.domain)</script>","description":"The request contains executable script markup. If reflected or stored without output encoding, it could execute in another user's browser security context."},
    {"timestamp":"2026-09-17 19:50:11","event_id":"EVT-91BC20","source_ip":"10.42.31.77","severity":"WARNING","target_endpoint":"/admin/export","attack_type":"Suspicious Parameter Manipulation","raw_payload":"format=csv&scope=../../admin/system","description":"An administrative export request contains an unexpected path-like parameter. Validate authorization and input handling."},
    {"timestamp":"2026-09-17 19:48:33","event_id":"EVT-4420DE","source_ip":"10.42.18.44","severity":"WARNING","target_endpoint":"/api/session","attack_type":"Authentication Anomaly","raw_payload":"session_id=8d1f...; retry_count=17","description":"Repeated session activity from a single source exceeds the normal behavioral threshold."},
    {"timestamp":"2026-09-17 19:47:05","event_id":"EVT-2A71F0","source_ip":"10.42.12.103","severity":"LOW","target_endpoint":"/health","attack_type":"Network Probe","raw_payload":"GET /health HTTP/1.1","description":"A routine-looking service discovery request was observed. No direct exploitation indicator was identified."},
    {"timestamp":"2026-09-17 19:45:29","event_id":"EVT-73A112","source_ip":"10.42.25.61","severity":"CRITICAL","target_endpoint":"/api/users","attack_type":"SQL Injection","raw_payload":"id=42 UNION SELECT username,password FROM users --","description":"The payload attempts to alter a database query and retrieve data from another database relation."},
    {"timestamp":"2026-09-17 19:43:52","event_id":"EVT-CC1021","source_ip":"10.42.16.19","severity":"WARNING","target_endpoint":"/upload","attack_type":"Unexpected File Upload","raw_payload":"filename=payload.jsp; content-type=application/octet-stream","description":"A file upload does not match the expected application profile. Investigate against the allowed upload policy."},
    {"timestamp":"2026-09-17 19:41:18","event_id":"EVT-19F0A4","source_ip":"10.42.29.88","severity":"LOW","target_endpoint":"/robots.txt","attack_type":"Reconnaissance","raw_payload":"GET /robots.txt HTTP/1.1","description":"A low-confidence reconnaissance event was observed."},
]

CSS = """
<style>
.stApp{background:#070b10;color:#e7edf5}.block-container{max-width:1560px;padding:1.25rem 2rem 2.5rem}
[data-testid="stAppViewContainer"]{background-image:linear-gradient(rgba(3,8,14,.78),rgba(3,8,14,.9)),url("data:image/svg+xml;charset=UTF-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%201920%201080%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22bg%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20stop-color%3D%22%23020812%22%2F%3E%3Cstop%20offset%3D%22.5%22%20stop-color%3D%22%23071522%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2302070d%22%2F%3E%3C%2FlinearGradient%3E%3CradialGradient%20id%3D%22glow%22%3E%3Cstop%20stop-color%3D%22%2300e5ff%22%20stop-opacity%3D%22.35%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2300e5ff%22%20stop-opacity%3D%220%22%2F%3E%3C%2FradialGradient%3E%3Cpattern%20id%3D%22grid%22%20width%3D%2248%22%20height%3D%2248%22%20patternUnits%3D%22userSpaceOnUse%22%3E%3Cpath%20d%3D%22M48%200H0V48%22%20fill%3D%22none%22%20stroke%3D%22%232c6680%22%20stroke-opacity%3D%22.18%22%2F%3E%3C%2Fpattern%3E%3C%2Fdefs%3E%3Crect%20width%3D%221920%22%20height%3D%221080%22%20fill%3D%22url(%23bg)%22%2F%3E%3Crect%20width%3D%221920%22%20height%3D%221080%22%20fill%3D%22url(%23grid)%22%2F%3E%3Ccircle%20cx%3D%221500%22%20cy%3D%22250%22%20r%3D%22480%22%20fill%3D%22url(%23glow)%22%2F%3E%3Ccircle%20cx%3D%22420%22%20cy%3D%22800%22%20r%3D%22360%22%20fill%3D%22url(%23glow)%22%20opacity%3D%22.35%22%2F%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%2339d9ff%22%20stroke-opacity%3D%22.35%22%20stroke-width%3D%222%22%3E%3Cpath%20d%3D%22M100%20820%20C360%20570%20570%20690%20790%20430%20S1210%20180%201800%20420%22%2F%3E%3Cpath%20d%3D%22M160%20900%20C450%20680%20660%20760%20900%20560%20S1350%20390%201810%20620%22%2F%3E%3Cpath%20d%3D%22M320%20160%20L680%20340%20L1040%20170%20L1390%20350%20L1710%20180%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%235ee38a%22%3E%3Ccircle%20cx%3D%22680%22%20cy%3D%22340%22%20r%3D%227%22%2F%3E%3Ccircle%20cx%3D%221040%22%20cy%3D%22170%22%20r%3D%227%22%2F%3E%3Ccircle%20cx%3D%221390%22%20cy%3D%22350%22%20r%3D%227%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%23ff4d5f%22%3E%3Ccircle%20cx%3D%22790%22%20cy%3D%22430%22%20r%3D%229%22%2F%3E%3Ccircle%20cx%3D%221210%22%20cy%3D%22180%22%20r%3D%229%22%2F%3E%3Ccircle%20cx%3D%221600%22%20cy%3D%22500%22%20r%3D%229%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%2307131e%22%20stroke%3D%22%2339d9ff%22%20stroke-opacity%3D%22.28%22%3E%3Crect%20x%3D%221160%22%20y%3D%22650%22%20width%3D%22620%22%20height%3D%22260%22%20rx%3D%2222%22%2F%3E%3Crect%20x%3D%221260%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3Crect%20x%3D%221420%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3Crect%20x%3D%221580%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3C%2Fg%3E%3Cg%20stroke%3D%22%235ee38a%22%20stroke-width%3D%224%22%20stroke-linecap%3D%22round%22%20opacity%3D%22.7%22%3E%3Cpath%20d%3D%22M1290%20780h70%22%2F%3E%3Cpath%20d%3D%22M1450%20760h70%22%2F%3E%3Cpath%20d%3D%22M1610%20790h70%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%238aa5ba%22%20font-family%3D%22Arial%2Csans-serif%22%20font-size%3D%2228%22%20letter-spacing%3D%226%22%20opacity%3D%22.35%22%3E%3Ctext%20x%3D%221160%22%20y%3D%22620%22%3ESOC%20INTELLIGENCE%20%2F%20AIR-GAPPED%3C%2Ftext%3E%3Ctext%20x%3D%22110%22%20y%3D%22120%22%3EDETECT%20%E2%80%A2%20INVESTIGATE%20%E2%80%A2%20RESPOND%3C%2Ftext%3E%3C%2Fg%3E%3Cg%20opacity%3D%22.22%22%20stroke%3D%22%2300e5ff%22%20fill%3D%22none%22%3E%3Ccircle%20cx%3D%22960%22%20cy%3D%22520%22%20r%3D%22210%22%2F%3E%3Ccircle%20cx%3D%22960%22%20cy%3D%22520%22%20r%3D%22290%22%2F%3E%3Cpath%20d%3D%22M670%20520h580M960%20230v580%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E");background-size:cover;background-position:center top;background-attachment:fixed}
[data-testid="stHeader"]{background:rgba(5,8,12,.75)}
[data-testid="stMetric"]{background:linear-gradient(145deg,#101a24,#0a1118);border:1px solid #26384a;border-radius:14px;padding:8px 12px;box-shadow:0 8px 24px rgba(0,0,0,.22)}
.vh{border:1px solid #2b4054;border-radius:18px;padding:22px 26px;background:linear-gradient(135deg,rgba(16,30,43,.96),rgba(7,12,18,.98));margin-bottom:16px;box-shadow:0 14px 40px rgba(0,0,0,.28);position:relative;overflow:hidden}.vh:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(94,227,138,.05),transparent);pointer-events:none}.vk{display:flex;gap:10px;align-items:center;color:#8fa5ba;font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;margin-bottom:8px}.vt{font-size:1.55rem;font-weight:850;letter-spacing:.055em}.vs{color:#5ee38a;font-weight:700;margin-top:4px}.metric{border:1px solid #253444;border-radius:14px;padding:15px 17px;background:linear-gradient(145deg,#0e171f,#0a1017);box-shadow:0 8px 22px rgba(0,0,0,.18)}.mv{font-size:1.6rem;font-weight:850}.ml{color:#91a1b4;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}
.panel{border:1px solid #253444;border-radius:16px;padding:18px;background:rgba(9,15,22,.94);min-height:520px;box-shadow:0 12px 32px rgba(0,0,0,.18);backdrop-filter:blur(8px)}.pt{font-weight:850;text-transform:uppercase;letter-spacing:.1em;color:#d5e1ed;margin-bottom:12px;display:flex;align-items:center;gap:8px}.log{border:1px solid #1e2b38;border-left:4px solid #5ee38a;border-radius:10px;padding:11px 13px;margin:8px 0;background:linear-gradient(100deg,#0d151e,#0a1118);transition:transform .15s ease,border-color .15s ease}.log:hover{transform:translateX(2px);border-color:#35516a}.log.Critical{border-left-color:#ff4d5f}.log.Warning{border-left-color:#f6c453}.lh{display:flex;justify-content:space-between;gap:8px;font-size:.82rem}.sev{font-weight:800}.Critical .sev{color:#ff6675}.Warning .sev{color:#f6c453}.Low .sev{color:#5ee38a}.lm{color:#9aaabd;font-size:.76rem;margin-top:3px}.pill{display:inline-block;padding:3px 7px;border-radius:999px;background:#15202b;font-size:.7rem}.box{border:1px solid #253444;border-radius:11px;padding:13px;background:#080d13;margin:10px 0;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.ai{border-left:3px solid #7aa7ff;background:#0d1520;border-radius:8px;padding:12px}.q{color:#ff6675;font-weight:800}
@media (max-width:800px){.block-container{padding:.65rem}.vh{padding:14px}.vt{font-size:1.05rem}.panel{min-height:auto;padding:12px}.log{font-size:.88rem}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def init_state() -> None:
    defaults = {
        "demo_mode": False,
        "logs": [],
        "quarantined_ips": set(),
        "selected_event": None,
        "telemetry_source": "No local evidence loaded",
        "analysis_summary": None,
        "analysis_result": None,
        "analysis_state": "IDLE",
        "analysis_completed_at": None,
        "analysis_evidence_sha256": None,
        "validation_summary": None,
        "validation_key": None,
        "incident_exports": 0,
        "last_action": "System initialized in air-gapped mode.",
        "pipeline_source": "No local evidence loaded",
        "pipeline_stage": "IDLE",
        "pipeline_history": [],
        "event_buffer": EventBuffer(),
        "dashboard_drilldown": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def dataframe() -> pd.DataFrame:
    return pd.DataFrame(st.session_state.logs)


def selected_log() -> dict | None:
    for log in st.session_state.logs:
        if log["event_id"] == st.session_state.selected_event:
            return log
    return st.session_state.logs[0] if st.session_state.logs else None


def reset_demo() -> None:
    st.session_state.logs = [dict(x) for x in MOCK_LOGS]
    st.session_state.quarantined_ips = set()
    st.session_state.selected_event = MOCK_LOGS[0]["event_id"]
    st.session_state.incident_exports = 0
    st.session_state.last_action = "Demo telemetry reset."


def incident_report(log: dict) -> bytes:
    report = {
        "system": "Vanguard-SIEM",
        "classification": "LOCAL EVIDENCE / DEFENSIVE ANALYSIS",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event": log,
        "response_state": "QUARANTINED" if log["source_ip"] in st.session_state.quarantined_ips else "OBSERVED",
        "console_state": {"network": "DISCONNECTED", "telemetry": "LOCAL", "external_apis": False},
    }
    return json.dumps(report, indent=2).encode("utf-8")


init_state()

st.markdown('<div class="vh"><div class="vk">🛡️ CISMIC 2026 • LOCAL SOC • DEFENSIVE ANALYTICS</div><div class="vt">VANGUARD-SIEM // SOC INTELLIGENCE CENTER</div><div class="vs">● Status: SECURED • AIR-GAPPED • OFFLINE • EVIDENCE PROCESSING ONLINE</div></div>', unsafe_allow_html=True)

c1, c2 = st.columns([5, 1])
with c1:
    st.caption(f"SOC intelligence telemetry • {html.escape(st.session_state.telemetry_source)} • No hard-coded operational events")
with c2:
    demo = st.toggle("⚡ Demo Mode", value=st.session_state.demo_mode)
    if demo != st.session_state.demo_mode:
        st.session_state.demo_mode = demo
        if demo:
            reset_demo()
        else:
            st.session_state.logs = []
            st.session_state.quarantined_ips = set()
            st.session_state.selected_event = None
            st.session_state.telemetry_source = "No local evidence loaded"
        st.rerun()

_df = dataframe()
live_dashboard = st.empty()
metrics = st.columns(4)
critical = int((_df["severity"] == "CRITICAL").sum()) if not _df.empty else 0
high = int((_df["severity"].isin(["HIGH", "WARNING"])).sum()) if not _df.empty else 0
metric_specs = [
    ("Total Log Entries", len(_df), "ALL"),
    ("Critical Anomalies", critical, "CRITICAL"),
    ("High / Warning Alerts", high, "HIGH_WARNING"),
    ("Quarantined Hosts", len(st.session_state.quarantined_ips), "QUARANTINED"),
]
for col, (label, value, target) in zip(metrics, metric_specs):
    with col:
        st.markdown(f'<div class="metric"><div class="mv">{value}</div><div class="ml">{label}</div></div>', unsafe_allow_html=True)
        if st.button("View", key=f"metric_view_{target}", use_container_width=True, disabled=(value == 0 and target != "ALL")):
            st.session_state.dashboard_drilldown = target
            st.session_state.last_action = f"Dashboard drill-down opened: {label}."
            st.rerun()

if st.session_state.get("dashboard_drilldown"):
    target = st.session_state.dashboard_drilldown
    if target == "ALL":
        drill = _df.copy()
        title = "All analyzed log entries"
    elif target == "CRITICAL":
        drill = _df[_df["severity"] == "CRITICAL"].copy()
        title = "Critical anomalies"
    elif target == "HIGH_WARNING":
        drill = _df[_df["severity"].isin(["HIGH", "WARNING"])].copy()
        title = "High / Warning alerts"
    else:
        drill = _df[_df["source_ip"].isin(st.session_state.quarantined_ips)].copy() if not _df.empty else _df.copy()
        title = "Quarantined hosts"
    st.markdown(f"### {title}")
    if drill.empty:
        st.info("No records currently match this dashboard view.")
    else:
        drill = drill.reset_index(drop=True)
        st.dataframe(
            drill[["event_id", "timestamp", "severity", "source_ip", "target_endpoint", "attack_type"]],
            use_container_width=True,
            hide_index=True,
        )
        drill_options = drill["event_id"].tolist()
        drill_current = drill_options.index(st.session_state.selected_event) if st.session_state.selected_event in drill_options else 0
        drill_event = st.selectbox("Open event from this dashboard view", drill_options, index=drill_current, key=f"drill_select_{target}")
        st.session_state.selected_event = drill_event
        if st.button("Close dashboard view", key=f"close_drill_{target}", use_container_width=True):
            st.session_state.dashboard_drilldown = None
            st.rerun()

# Persisted analysis status: the main dashboard is rebuilt from the uploaded evidence.
if st.session_state.analysis_summary:
    summary = st.session_state.analysis_summary
    status_label = "ANALYSIS COMPLETE" if st.session_state.analysis_state == "COMPLETE" else st.session_state.analysis_state
    st.success(f"✓ {status_label} • {st.session_state.telemetry_source}")
    a1, a2, a3, a4, a5 = st.columns(5)
    a1.metric("Analyzed Records", len(st.session_state.logs))
    a2.metric("Parsed", len(st.session_state.analysis_result["events"]) if st.session_state.analysis_result else 0)
    a3.metric("Alerts", len(st.session_state.analysis_result["alerts"]) if st.session_state.analysis_result else 0)
    a4.metric("Incidents", len(st.session_state.analysis_result["incidents"]) if st.session_state.analysis_result else 0)
    a5.metric("Risk Score", summary["risk_score"])
    risk_breakdown = st.session_state.analysis_result.get("risk_breakdown", {}) if st.session_state.analysis_result else {}
    if risk_breakdown:
        st.caption(f"Risk composition • alert points: {risk_breakdown.get('alert_points', 0)} • incident points: {risk_breakdown.get('incident_points', 0)}")
    policy = detection_policy()
    st.caption(f"Detection policy • {policy['brute_force_failures']} failures / {policy['behavior_window_seconds']}s • {policy['scan_unique_destinations']} unique destinations / {policy['behavior_window_seconds']}s • correlation {policy['correlation_window_seconds']}s")
    st.caption(f"Parse coverage {summary['parse_coverage']:.1f}% • {summary['unique_sources']} unique source(s) • {summary['unique_destinations']} unique destination(s) • Completed {st.session_state.analysis_completed_at or 'now'}")
    if st.session_state.analysis_evidence_sha256:
        st.code(f"Evidence SHA-256: {st.session_state.analysis_evidence_sha256}", language="text")
    if summary["rule_counts"]:
        st.dataframe(pd.DataFrame([{"Detection Rule": k, "Matches": v} for k, v in sorted(summary["rule_counts"].items(), key=lambda x: (-x[1], x[0]))]), use_container_width=True, hide_index=True)
    else:
        st.info("Analysis completed. No configured detection rule matched the uploaded evidence.")

left, right = st.columns([1.35, 1], gap="large")
with left:
    st.markdown('<div class="panel"><div class="pt">Live Security Log Stream</div>', unsafe_allow_html=True)
    fcol, rcol = st.columns([3, 1])
    with fcol:
        severity_filter = st.selectbox("Filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW"], label_visibility="collapsed")
    with rcol:
        if st.button("↻ Refresh", use_container_width=True):
            st.session_state.last_action = "Local telemetry stream refreshed."
            st.rerun()
    view = _df if severity_filter == "ALL" else _df[_df["severity"] == severity_filter]
    if view.empty:
        st.info("No live telemetry loaded. Upload a JSON/JSONL/log file below." if _df.empty else "No events match the current filter.")
    for row in view.to_dict("records"):
        sev = row["severity"].title()
        state = " • QUARANTINED" if row["source_ip"] in st.session_state.quarantined_ips else ""
        st.markdown(f'<div class="log {sev}"><div class="lh"><span>{html.escape(row["timestamp"])} · <b>{html.escape(row["event_id"])}</b></span><span class="sev">{html.escape(row["severity"])}{state}</span></div><div><b>{html.escape(row["attack_type"])}</b> <span class="pill">{html.escape(row["source_ip"])}</span></div><div class="lm">Target: {html.escape(row["target_endpoint"])}</div></div>', unsafe_allow_html=True)
        if st.button(f"Inspect {row['event_id']}", key=f"inspect_{row['event_id']}", use_container_width=True):
            st.session_state.selected_event = row["event_id"]
            st.session_state.last_action = f"Event inspector opened for {row['event_id']}."
            st.rerun()
    if not _df.empty:
        options = _df["event_id"].tolist()
        current_index = options.index(st.session_state.selected_event) if st.session_state.selected_event in options else 0
        selected = st.selectbox("Inspect Event", options, index=current_index)
        st.session_state.selected_event = selected
    st.markdown('</div>', unsafe_allow_html=True)

with right:
    log = selected_log()
    st.markdown('<div class="panel"><div class="pt">Tactical AI Inspector & Playbook</div>', unsafe_allow_html=True)
    if log is None:
        st.info("No telemetry available.")
    else:
        st.markdown(f'<div class="box"><b>Event ID</b><br>{html.escape(log["event_id"])}<br><br><b>Source IP</b><br>{html.escape(log["source_ip"])}<br><br><b>Target Endpoint</b><br>{html.escape(log["target_endpoint"])}</div>', unsafe_allow_html=True)
        st.caption("RAW PAYLOAD")
        st.code(log["raw_payload"], language="text")
        st.markdown(f'<div class="ai"><b>Plain-language AI threat translation</b><br><br>{html.escape(log["description"])}</div>', unsafe_allow_html=True)
        st.write("")
        q1, q2 = st.columns(2)
        with q1:
            if st.button("🔒 Quarantine IP", type="primary", use_container_width=True):
                st.session_state.quarantined_ips.add(log["source_ip"])
                for item in st.session_state.logs:
                    if item["source_ip"] == log["source_ip"]:
                        item["host_state"] = "QUARANTINED"
                audit_event("QUARANTINE_SESSION", log["source_ip"], log.get("raw_sha256", ""))
                st.session_state.last_action = f"Local quarantine state applied to {log['source_ip']}. No external firewall action performed."
                st.rerun()
        with q2:
            report = incident_report(log)
            if st.download_button("⬇ Export Incident Report", data=report, file_name=f"vanguard_{log['event_id']}.json", mime="application/json", use_container_width=True):
                st.session_state.incident_exports += 1
                audit_event("INCIDENT_REPORT_EXPORT", log["event_id"])
                st.session_state.last_action = f"Incident report exported for {log['event_id']}."
        if log["source_ip"] in st.session_state.quarantined_ips:
            st.markdown(f'<div class="q">● Host {html.escape(log["source_ip"])} is quarantined in session state.</div>', unsafe_allow_html=True)
        if st.button("↺ Reset Demo Data", use_container_width=True):
            reset_demo()
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


st.markdown('<div class="panel"><div class="pt">Log Ingestion Center</div>', unsafe_allow_html=True)
st.caption(f"Local evidence intake • up to {MAX_UPLOAD_BYTES / (1024**3):.0f} GiB per file • sanitized, hashed and analyzed offline. Uploaded content is never executed.")
with st.expander("Upload security logs", expanded=True):
    uploaded = st.file_uploader("Choose a local log file", type=sorted(ALLOWED_UPLOAD_TYPES), accept_multiple_files=False, max_upload_size=1024, help="Local files up to 1 GiB. Use .log/.txt/.jsonl for very large event streams.")
    fmt = st.selectbox("Format", ["AUTO", "TEXT / SYSLOG", "CSV", "JSON", "JSONL", "XML"])
    source_name = st.text_input("Source", value="Local evidence")
    if uploaded is not None:
        size_mb = uploaded.size / (1024 * 1024) if getattr(uploaded, "size", None) else len(uploaded.getvalue()) / (1024 * 1024)
        st.caption(f"Evidence: {uploaded.name} • {size_mb:,.1f} MB • limit 1,024 MB")
    current_upload_key = None
    current_upload_digest = None
    if uploaded is not None:
        current_upload_bytes = uploaded.getvalue()
        current_upload_digest = __import__("hashlib").sha256(current_upload_bytes).hexdigest()
        current_upload_key = f"{uploaded.name}:{len(current_upload_bytes)}:{current_upload_digest}"
    if uploaded is not None and st.session_state.validation_key != current_upload_key:
        st.session_state.validation_summary = None
        st.session_state.validation_key = None
        st.session_state.analysis_state = "IDLE"

    st.markdown("**Evidence workflow**")
    st.caption("UPLOAD → VALIDATE → ANALYZE → COMPLETE. Analysis is locked until validation passes.")

    vcol, acol = st.columns(2)
    with vcol:
        if st.button("1. Validate Evidence", use_container_width=True, disabled=uploaded is None):
            try:
                raw_bytes = uploaded.getvalue()
                validation = validate_bytes(raw_bytes, uploaded.name, fmt)
                st.session_state.validation_summary = validation
                st.session_state.validation_key = current_upload_key
                st.session_state.analysis_state = "VALIDATED"
                st.session_state.pipeline_stage = "VALIDATE"
                st.session_state.last_action = f"Evidence validation passed for {uploaded.name}. Analysis is now unlocked."
            except Exception as exc:
                st.session_state.validation_summary = None
                st.session_state.validation_key = None
                st.session_state.analysis_state = "VALIDATION FAILED"
                st.session_state.pipeline_stage = "FAILED"
                detail = f"{type(exc).__name__}: {exc}"
                st.session_state.last_action = f"Validation failed safely for {uploaded.name}: {detail}"
                st.error(f"Evidence validation failed safely: {detail}")

    validation = st.session_state.validation_summary
    if validation:
        st.success(f"✓ VALIDATED • {validation['records']:,} records • fast preflight PASS • SHA-256 {validation['sha256'][:16]}…")
        st.caption(f"Format: {validation['format']} • Parser: {', '.join(validation['source_formats']) or 'local-text'} • Evidence integrity: PASS")
    else:
        st.info("Validation required. The file will not enter the SOC analysis engine until validation passes.")

    with acol:
        analyze_disabled = uploaded is None or not validation or st.session_state.validation_key != current_upload_key
        if st.button("2. Analyze Validated Evidence", type="primary", use_container_width=True, disabled=analyze_disabled):
            try:
                st.session_state.analysis_state = "ANALYZING"
                st.session_state.pipeline_stage = "ANALYZE"
                raw_bytes = uploaded.getvalue()
                if current_upload_digest != validation["sha256"]:
                    raise ValueError("Evidence changed after validation. Validate the current file again before analysis.")
                progress = st.progress(0, text="Starting evidence analysis…")
                preview = st.empty()
                preview_rows = []

                def publish_chunk(events, processed, total):
                    for event in events:
                        matches = detect(event)
                        primary = max(matches, key=lambda item: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(item.severity, 0), default=None)
                        preview_rows.append({
                            "event_id": f"EVT-{event.raw_sha256[:10].upper()}",
                            "timestamp": event.timestamp.isoformat(),
                            "severity": primary.severity if primary else event.severity,
                            "source_ip": event.source_ip or "N/A",
                            "target_endpoint": event.fields.get("path") or event.fields.get("endpoint") or event.destination_ip or event.event_type,
                            "attack_type": primary.title if primary else (event.action or event.event_type),
                        })
                    pct = processed / total if total else 1.0
                    progress.progress(pct, text=f"Analyzing evidence… {processed:,}/{total:,} records")
                    live = pd.DataFrame(preview_rows)
                    live_critical = int((live["severity"] == "CRITICAL").sum()) if not live.empty else 0
                    live_high = int(live["severity"].isin(["HIGH", "WARNING"]).sum()) if not live.empty else 0
                    with live_dashboard.container():
                        lm1, lm2, lm3, lm4 = st.columns(4)
                        lm1.metric("Analyzed Records", processed)
                        lm2.metric("Critical Anomalies", live_critical)
                        lm3.metric("High / Warning", live_high)
                        lm4.metric("Latest Event", preview_rows[-1]["event_id"] if preview_rows else "-")
                        st.caption("LIVE ANALYSIS FEED • records are being normalized and classified as the file is processed")
                        st.dataframe(live.tail(100), use_container_width=True, hide_index=True)
                    preview.dataframe(live.tail(200), use_container_width=True, hide_index=True)

                bundle = analyze_bytes_incremental(raw_bytes, uploaded.name, validation["format"], on_chunk=publish_chunk)
                progress.progress(1.0, text=f"Analysis complete • {bundle['records']:,} records")
                if bundle["sha256"] != validation["sha256"]:
                    raise ValueError("Evidence changed after validation. Validate the current file again before analysis.")
                commit_dashboard_state(st, bundle, source_name or uploaded.name)
                st.session_state.pipeline_history.append({"source": uploaded.name, "sha256": bundle["sha256"], "records": bundle["records"], "completed_at": bundle["completed_at"]})
                st.session_state.analysis_state = "COMPLETE"
                st.session_state.last_action = f"Analysis complete for validated evidence {uploaded.name}. Dashboard updated from the uploaded evidence."
                st.rerun()
            except Exception as exc:
                st.session_state.analysis_state = "FAILED"
                st.session_state.pipeline_stage = "FAILED"
                st.session_state.analysis_completed_at = datetime.now(timezone.utc).isoformat()
                detail = f"{type(exc).__name__}: {exc}"
                st.session_state.last_action = f"Analysis failed safely for {uploaded.name}: {detail}"
                st.error(f"Analysis rejected safely: {detail}")


st.markdown('</div>', unsafe_allow_html=True)


st.markdown('<div class="panel"><div class="pt">Local SOC Analytics Engine</div>', unsafe_allow_html=True)
st.caption("Offline ingestion • normalization • deterministic detection • correlation")

with st.expander("Analyze local log lines", expanded=False):
    sample = """2026-09-22T10:00:00+00:00 sshd: Failed password for user=admin from 10.10.1.7
2026-09-22T10:00:10+00:00 sshd: Failed password for user=admin from 10.10.1.7
2026-09-22T10:00:20+00:00 sshd: Failed password for user=admin from 10.10.1.7
2026-09-22T10:00:30+00:00 sshd: Failed password for user=admin from 10.10.1.7
2026-09-22T10:00:40+00:00 sshd: Failed password for user=admin from 10.10.1.7
2026-09-22T10:01:00+00:00 10.10.1.7 GET /search?q=' OR '1'='1' HTTP/1.1"""
    raw_lines = st.text_area("Paste local log sample", value=sample, height=180)
    if st.button("Analyze Locally", type="primary"):
        try:
            bundle = analyze_bytes(raw_lines.encode("utf-8"), "pasted-local.log", "TEXT")
            commit_dashboard_state(st, bundle, "Pasted local telemetry")
            st.session_state.pipeline_history.append({"source": "Pasted local telemetry", "sha256": bundle["sha256"], "records": bundle["records"], "completed_at": bundle["completed_at"]})
            st.success(f"Canonical pipeline analysis complete • {bundle['records']} records • risk {bundle['analysis']['risk_score']} • SHA-256 {bundle['sha256'][:16]}…")
            st.rerun()
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            st.error(f"Local analysis rejected safely: {exc}")


st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="panel"><div class="pt">Local SOC Capability Center</div>', unsafe_allow_html=True)
st.caption("Optional capabilities remain local-first and require explicit configuration or analyst approval.")
cap1, cap2, cap3 = st.columns(3)
with cap1:
    st.write("**Windows Event Logs**")
    st.write("Available:" , "YES" if windows_events_available() else "NO (non-Windows)")
    st.write("Native Security/Application/System collection is available on Windows.")
    if st.button("Ingest Windows Security Events", key="windows_ingest", disabled=not windows_events_available()):
        try:
            collected = __import__("windows_events").collect("Security", 100)
            bundle = analyze_bytes("\n".join(collected).encode("utf-8"), "windows-security.xml", "XML")
            commit_dashboard_state(st, bundle, "Windows Security Event Log")
            st.session_state.pipeline_history.append({"source": "Windows Security Event Log", "sha256": bundle["sha256"], "records": bundle["records"], "completed_at": bundle["completed_at"]})
            st.success(f"Windows events ingested into shared SOC context: {bundle['records']} records.")
            st.rerun()
        except Exception as exc:
            st.error(f"Windows Event ingestion failed safely: {type(exc).__name__}")
with cap2:
    st.write("**Offline Threat Intel**")
    ti = ThreatIntelCache()
    ti_ip = st.text_input("Lookup local IOC IP", value="", key="ti_ip")
    if st.button("Lookup IOC", key="ti_lookup"):
        try:
            intel = ti.lookup_ip(ti_ip)
            st.json(intel)
            if log and ti_ip == log.get("source_ip") and intel:
                st.session_state.last_action = f"Offline IOC enrichment attached to {log['event_id']}."
                audit_event("IOC_LOOKUP", ti_ip)
        except ValueError as exc:
            st.error(f"Invalid IP: {exc}")
with cap3:
    st.write("**Local AI / Analyst Guidance**")
    default_ai = (log or {}).get("description") or "Explain this security alert defensively."
    ai_text = st.text_area("Alert context", value=default_ai, key="ai_context")
    if st.button("Run Local AI", key="local_ai"):
        try:
            st.info(local_ai_explain(ai_text))
        except Exception as exc:
            st.error(f"Local AI unavailable: {type(exc).__name__}")

st.markdown("**Human-approved remediation**")
rp = propose(log or {})
st.json(rp)
approve = st.checkbox("I approve the proposed remediation", key="remediation_approval")
if st.button("Execute Approved Remediation", disabled=not approve, key="execute_remediation"):
    result = execute_approved({**rp, "approved": True})
    audit_event("REMEDIATION_EXECUTION", str(result))
    st.json(result)

st.markdown("**Firewall quarantine control**")
fw_ip = st.text_input("Source IP to quarantine", value=(log or {}).get("source_ip",""), key="fw_ip")
fw_apply = st.checkbox("Apply to local Windows firewall", value=False, key="fw_apply")
if st.button("Validate / Quarantine IP", key="fw_button"):
    try:
        result = block_ip(fw_ip, apply=fw_apply)
        audit_event("FIREWALL_ACTION", fw_ip)
        st.json(result)
    except ValueError as exc:
        st.error(f"Rejected: {exc}")

st.markdown("**Distributed local ingestion buffer**")
st.session_state.event_buffer.add({"source": st.session_state.pipeline_source, "timestamp": datetime.now(timezone.utc).isoformat(), "stage": st.session_state.pipeline_stage})
st.metric("Buffered events", len(st.session_state.event_buffer.snapshot()))
st.caption("The same bounded local buffer tracks dashboard/collector activity across reruns; capacity 50,000 events.")

st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="panel"><div class="pt">Unified SOC Operating Modes</div>', unsafe_allow_html=True)
st.caption("Every mode feeds the same canonical evidence → validation → analysis → correlation → risk → investigation → response → audit context. No mode maintains a separate detection engine.")
stages = stage_status()
mode_cols = st.columns(8)
for col, (name, status) in zip(mode_cols, stages.items()):
    with col:
        st.metric(name, status)
if st.session_state.pipeline_source != "No local evidence loaded":
    st.success(f"Shared context: {st.session_state.pipeline_source} • {len(st.session_state.logs):,} dashboard records • SHA-256 {str(st.session_state.analysis_evidence_sha256 or '')[:16]}…")
    st.caption("Dashboard, event inspector, incident/risk views, remediation proposal, exports and audit reference the same analyzed evidence.")
else:
    st.info("No shared evidence context yet. Use Demo Mode, paste local telemetry, or validate an uploaded evidence file.")
st.markdown('</div>', unsafe_allow_html=True)

st.caption(f"Last action: {st.session_state.last_action}  •  Reports: {st.session_state.incident_exports}  •  NETWORK DISCONNECTED  •  TELEMETRY LOCAL")
