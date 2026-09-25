from __future__ import annotations

import html
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from engine import detection_policy
from ingestion import ALLOWED_UPLOAD_TYPES, MAX_UPLOAD_BYTES
from audit import audit_event, verify_audit_chain
from distributed import EventBuffer
from firewall import block_ip
from remediation import propose, execute_approved
from threat_intel import ThreatIntelCache
from windows_events import available as windows_events_available
from local_ai import explain as local_ai_explain
from soc_pipeline import analyze_bytes, analyze_bytes_incremental, commit_dashboard_state, stage_status
from analytics import summary as analytics_summary, trend as analytics_trend, findings_dataframe, attack_matrix, rule_counts_dataframe
from reporting import export_bundle
from intelligence_fusion import extract_iocs
from soc_context import build_soc_context
from evidence_store import EvidenceStore
from security_operations import SecurityOperationsStore, telemetry_status

st.set_page_config(page_title="VANGUARD — SOC Intelligence Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

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
.stApp{background:#050a12;color:#e7edf5;font-family:"IBM Plex Sans","Segoe UI",Arial,sans-serif}
.stApp *{font-family:"IBM Plex Sans","Segoe UI",Arial,sans-serif}
code,pre,[data-testid="stCode"],.mono{font-family:"IBM Plex Mono","SFMono-Regular",Consolas,monospace!important}
.block-container{max-width:1560px;padding:1.25rem 2rem 2.5rem}
[data-testid="stAppViewContainer"]{background-image:linear-gradient(rgba(3,8,14,.78),rgba(3,8,14,.9)),url("data:image/svg+xml;charset=UTF-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%201920%201080%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22bg%22%20x2%3D%221%22%20y2%3D%221%22%3E%3Cstop%20stop-color%3D%22%23020812%22%2F%3E%3Cstop%20offset%3D%22.5%22%20stop-color%3D%22%23071522%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2302070d%22%2F%3E%3C%2FlinearGradient%3E%3CradialGradient%20id%3D%22glow%22%3E%3Cstop%20stop-color%3D%22%2300e5ff%22%20stop-opacity%3D%22.35%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2300e5ff%22%20stop-opacity%3D%220%22%2F%3E%3C%2FradialGradient%3E%3Cpattern%20id%3D%22grid%22%20width%3D%2248%22%20height%3D%2248%22%20patternUnits%3D%22userSpaceOnUse%22%3E%3Cpath%20d%3D%22M48%200H0V48%22%20fill%3D%22none%22%20stroke%3D%22%232c6680%22%20stroke-opacity%3D%22.18%22%2F%3E%3C%2Fpattern%3E%3C%2Fdefs%3E%3Crect%20width%3D%221920%22%20height%3D%221080%22%20fill%3D%22url(%23bg)%22%2F%3E%3Crect%20width%3D%221920%22%20height%3D%221080%22%20fill%3D%22url(%23grid)%22%2F%3E%3Ccircle%20cx%3D%221500%22%20cy%3D%22250%22%20r%3D%22480%22%20fill%3D%22url(%23glow)%22%2F%3E%3Ccircle%20cx%3D%22420%22%20cy%3D%22800%22%20r%3D%22360%22%20fill%3D%22url(%23glow)%22%20opacity%3D%22.35%22%2F%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%2339d9ff%22%20stroke-opacity%3D%22.35%22%20stroke-width%3D%222%22%3E%3Cpath%20d%3D%22M100%20820%20C360%20570%20570%20690%20790%20430%20S1210%20180%201800%20420%22%2F%3E%3Cpath%20d%3D%22M160%20900%20C450%20680%20660%20760%20900%20560%20S1350%20390%201810%20620%22%2F%3E%3Cpath%20d%3D%22M320%20160%20L680%20340%20L1040%20170%20L1390%20350%20L1710%20180%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%235ee38a%22%3E%3Ccircle%20cx%3D%22680%22%20cy%3D%22340%22%20r%3D%227%22%2F%3E%3Ccircle%20cx%3D%221040%22%20cy%3D%22170%22%20r%3D%227%22%2F%3E%3Ccircle%20cx%3D%221390%22%20cy%3D%22350%22%20r%3D%227%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%23ff4d5f%22%3E%3Ccircle%20cx%3D%22790%22%20cy%3D%22430%22%20r%3D%229%22%2F%3E%3Ccircle%20cx%3D%221210%22%20cy%3D%22180%22%20r%3D%229%22%2F%3E%3Ccircle%20cx%3D%221600%22%20cy%3D%22500%22%20r%3D%229%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%2307131e%22%20stroke%3D%22%2339d9ff%22%20stroke-opacity%3D%22.28%22%3E%3Crect%20x%3D%221160%22%20y%3D%22650%22%20width%3D%22620%22%20height%3D%22260%22%20rx%3D%2222%22%2F%3E%3Crect%20x%3D%221260%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3Crect%20x%3D%221420%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3Crect%20x%3D%221580%22%20y%3D%22710%22%20width%3D%22130%22%20height%3D%22100%22%20rx%3D%2210%22%2F%3E%3C%2Fg%3E%3Cg%20stroke%3D%22%235ee38a%22%20stroke-width%3D%224%22%20stroke-linecap%3D%22round%22%20opacity%3D%22.7%22%3E%3Cpath%20d%3D%22M1290%20780h70%22%2F%3E%3Cpath%20d%3D%22M1450%20760h70%22%2F%3E%3Cpath%20d%3D%22M1610%20790h70%22%2F%3E%3C%2Fg%3E%3Cg%20fill%3D%22%238aa5ba%22%20font-family%3D%22Arial%2Csans-serif%22%20font-size%3D%2228%22%20letter-spacing%3D%226%22%20opacity%3D%22.35%22%3E%3Ctext%20x%3D%221160%22%20y%3D%22620%22%3ESOC%20INTELLIGENCE%20%2F%20AIR-GAPPED%3C%2Ftext%3E%3Ctext%20x%3D%22110%22%20y%3D%22120%22%3EDETECT%20%E2%80%A2%20INVESTIGATE%20%E2%80%A2%20RESPOND%3C%2Ftext%3E%3C%2Fg%3E%3Cg%20opacity%3D%22.22%22%20stroke%3D%22%2300e5ff%22%20fill%3D%22none%22%3E%3Ccircle%20cx%3D%22960%22%20cy%3D%22520%22%20r%3D%22210%22%2F%3E%3Ccircle%20cx%3D%22960%22%20cy%3D%22520%22%20r%3D%22290%22%2F%3E%3Cpath%20d%3D%22M670%20520h580M960%20230v580%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E");background-size:cover;background-position:center top;background-attachment:fixed}
[data-testid="stHeader"]{background:rgba(5,8,12,.75)}
[data-testid="stMetric"]{background:linear-gradient(145deg,#101a24,#0a1118);border:1px solid #26384a;border-radius:14px;padding:8px 12px;box-shadow:0 8px 24px rgba(0,0,0,.22)}
.vbrand{display:flex;align-items:center;justify-content:center;gap:12px}.vmark{width:38px;height:38px;border:1px solid #00e5ff;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#00e5ff;font-family:"IBM Plex Mono",monospace!important;font-weight:800;font-size:1.25rem;box-shadow:0 0 22px rgba(0,229,255,.2),inset 0 0 14px rgba(0,229,255,.08)}.vwordmark{font-family:"IBM Plex Mono","SFMono-Regular",monospace!important;font-size:2.65rem;font-weight:800;letter-spacing:.22em;color:#f3f8fc;text-shadow:0 0 22px rgba(0,229,255,.18);margin-left:.12em}.vtag{font-family:"IBM Plex Mono",monospace!important;color:#00e5ff;font-size:.72rem;font-weight:800;letter-spacing:.18em;border:1px solid rgba(0,229,255,.35);padding:4px 7px;border-radius:5px}.vsubtitle{text-align:center;color:#9db1c4;font-size:.72rem;font-weight:700;letter-spacing:.16em;margin-top:9px}.vstatus{text-align:center;color:#65e6a0;font-size:.72rem;font-weight:800;letter-spacing:.12em;margin-top:11px}.vdot{color:#00e5ff;text-shadow:0 0 10px rgba(0,229,255,.8)}.vline{height:1px;max-width:560px;margin:15px auto 10px;background:linear-gradient(90deg,transparent,rgba(0,229,255,.55),transparent)}.vmeta{text-align:center;color:#587287;font-family:"IBM Plex Mono",monospace!important;font-size:.61rem;letter-spacing:.13em}.vh{border:1px solid #214257;border-radius:18px;padding:22px 26px;background:linear-gradient(135deg,rgba(16,30,43,.96),rgba(7,12,18,.98));margin-bottom:16px;box-shadow:0 14px 40px rgba(0,0,0,.28);position:relative;overflow:hidden}.vh:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(94,227,138,.05),transparent);pointer-events:none}.vk{display:flex;gap:10px;align-items:center;color:#8fa5ba;font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;margin-bottom:8px}.vt{font-size:1.55rem;font-weight:850;letter-spacing:.055em}.vs{color:#5ee38a;font-weight:700;margin-top:4px}.metric{border:1px solid #253444;border-radius:14px;padding:15px 17px;background:linear-gradient(145deg,#0e171f,#0a1017);box-shadow:0 8px 22px rgba(0,0,0,.18)}.mv{font-size:1.6rem;font-weight:850}.ml{color:#91a1b4;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}
.panel{border:1px solid #253444;border-radius:16px;padding:18px;background:rgba(9,15,22,.94);min-height:520px;box-shadow:0 12px 32px rgba(0,0,0,.18);backdrop-filter:blur(8px)}.pt{font-weight:850;text-transform:uppercase;letter-spacing:.1em;color:#d5e1ed;margin-bottom:12px;display:flex;align-items:center;gap:8px}.log{border:1px solid #1e2b38;border-left:4px solid #5ee38a;border-radius:10px;padding:11px 13px;margin:8px 0;background:linear-gradient(100deg,#0d151e,#0a1118);transition:transform .15s ease,border-color .15s ease}.log:hover{transform:translateX(2px);border-color:#35516a}.log.Critical{border-left-color:#ff4d5f}.log.Warning{border-left-color:#f6c453}.lh{display:flex;justify-content:space-between;gap:8px;font-size:.82rem}.sev{font-weight:800}.Critical .sev{color:#ff6675}.Warning .sev{color:#f6c453}.Low .sev{color:#5ee38a}.lm{color:#9aaabd;font-size:.76rem;margin-top:3px}.pill{display:inline-block;padding:3px 7px;border-radius:999px;background:#15202b;font-size:.7rem}.box{border:1px solid #253444;border-radius:11px;padding:13px;background:#080d13;margin:10px 0;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.ai{border-left:3px solid #7aa7ff;background:#0d1520;border-radius:8px;padding:12px}.q{color:#ff6675;font-weight:800}
@media (max-width:800px){.block-container{padding:.65rem}.vh{padding:18px 12px}.vwordmark{font-size:1.75rem;letter-spacing:.16em}.vsubtitle{font-size:.58rem;line-height:1.6}.vstatus{font-size:.6rem;line-height:1.7}.vmeta{font-size:.5rem}.vmark{width:32px;height:32px}.panel{min-height:auto;padding:12px}.log{font-size:.88rem}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

MAX_UI_ROWS = 200
LOG_PAGE_SIZE = 50

def render_table(rows, max_rows: int = MAX_UI_ROWS) -> None:
    """Render bounded evidence tables without Streamlit's PyArrow dataframe path."""
    if rows is None:
        st.info("No data available.")
        return
    if hasattr(rows, "to_dict"):
        rows = rows.to_dict("records")
    rows = list(rows)[-max_rows:]
    if not rows:
        st.info("No data available.")
        return
    columns = list(rows[0].keys())
    header = "".join(f"<th>{html.escape(str(col))}</th>" for col in columns)
    body = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(str(row.get(col, '')))}</td>" for col in columns)
        body.append(f"<tr>{cells}</tr>")
    st.markdown(
        '<div style="overflow:auto;max-height:520px;border:1px solid #243444;border-radius:10px;">'
        '<table style="width:100%;border-collapse:collapse;font-size:.78rem;">'
        f'<thead><tr>{header}</tr></thead><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


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
        "log_page": 0,
        "evidence_store_summary": None,
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

st.markdown('<div class="vh"><div class="vbrand"><div class="vmark">V</div><div class="vwordmark">VANGUARD</div><div class="vtag">SOC</div></div><div class="vsubtitle">SECURITY OPERATIONS, THREAT INTELLIGENCE, DETECTION &amp; INCIDENT RESPONSE PLATFORM</div><div class="vstatus"><span class="vdot">●</span> SECURED &nbsp;•&nbsp; AIR-GAPPED &nbsp;•&nbsp; OFFLINE &nbsp;•&nbsp; EVIDENCE PROCESSING ONLINE</div><div class="vline"></div><div class="vmeta">LOCAL SOC &nbsp;•&nbsp; DEFENSIVE ANALYTICS &nbsp;•&nbsp; EVIDENCE-FIRST OPERATIONS</div></div>', unsafe_allow_html=True)
st.markdown('<div class="box"><b>ANALYST WORKSPACE</b> &nbsp; Command overview → evidence ingestion → detection → investigation → approved response → audit. The engine analyzes the complete evidence set; the UI only pages the display to stay responsive.</div>', unsafe_allow_html=True)

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
        render_table(drill[["event_id", "timestamp", "severity", "source_ip", "target_endpoint", "attack_type"]])
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
    a1, a2, a3, a4, a5, a6 = st.columns(6)
    a1.metric("Analyzed Records", len(st.session_state.logs))
    a2.metric("Parsed", len(st.session_state.analysis_result["events"]) if st.session_state.analysis_result else 0)
    a3.metric("Raw Alerts", summary.get("raw_alerts", len(st.session_state.analysis_result["alerts"]) if st.session_state.analysis_result else 0))
    a4.metric("Analyst Findings", summary.get("finding_groups", len(st.session_state.analysis_result.get("analyst_alerts", [])) if st.session_state.analysis_result else 0))
    a5.metric("Incidents", len(st.session_state.analysis_result["incidents"]) if st.session_state.analysis_result else 0)
    a6.metric("Risk Score", summary["risk_score"])
    risk_breakdown = st.session_state.analysis_result.get("risk_breakdown", {}) if st.session_state.analysis_result else {}
    if risk_breakdown:
        st.caption(f"Risk model • {risk_breakdown.get('raw_alerts', 0):,} raw alerts → {risk_breakdown.get('finding_groups', 0):,} analyst finding groups • {risk_breakdown.get('incident_count', 0):,} correlated incidents")
    if st.session_state.get("evidence_store_summary"):
        es = st.session_state.evidence_store_summary
        st.caption(f"Local evidence store • {es.get('finding_groups', 0):,} persisted finding groups • {es.get('finding_occurrences', 0):,} preserved occurrences")
    # Evidence-grounded analytics: every figure below is derived only from the
    # currently loaded evidence set. Empty evidence produces no synthetic chart.
    evidence_metrics = analytics_summary(st.session_state.logs)
    soc_context = build_soc_context(st.session_state.logs, st.session_state.analysis_result)
    st.markdown("### SOC Operations Picture")
    st.caption("Evidence-derived operational context. Missing telemetry is shown as unavailable; no synthetic health or coverage values are generated.")

    sw1, sw2, sw3, sw4 = st.columns(4)
    window = soc_context["window"]
    quality = soc_context["quality"]
    dup = soc_context["duplicates"]
    baseline = soc_context["baseline"]
    sw1.metric("Observed Window", "AVAILABLE" if window["first_seen"] else "UNAVAILABLE")
    sw2.metric("Evidence Quality", f'{quality["timestamp_quality"]:.1f}%' if quality["timestamp_quality"] is not None else "UNAVAILABLE")
    sw3.metric("Duplicate Records", dup["duplicate_records"])
    sw4.metric("Baseline", baseline["state"].replace("_", " "))

    q1, q2 = st.columns(2)
    with q1:
        st.markdown("**Evidence Quality / Detection Context**")
        coverage_rows = [{"Dimension": k.replace("_", " ").title(), "Observed Coverage": ("UNAVAILABLE" if v is None else f"{v:.1f}%")} for k, v in quality["field_coverage"].items()]
        render_table(coverage_rows)
        if quality["future_timestamps"]:
            st.warning(f'{quality["future_timestamps"]:,} timestamp(s) are in the future relative to the analysis runtime.')
    with q2:
        st.markdown("**Telemetry Sources / Assets**")
        render_table(soc_context["sources"][:8])
        if soc_context["assets"]:
            with st.expander("Asset context", expanded=False):
                render_table(soc_context["assets"][:12])
        if soc_context["identities"]:
            with st.expander("Identity activity", expanded=False):
                render_table(soc_context["identities"][:12])
        if window["first_seen"] and window["last_seen"]:
            st.caption(f'Observed window: {window["first_seen"]} → {window["last_seen"]}')
        else:
            st.caption("Observed window: unavailable because no valid timestamps were found.")

    t1, t2 = st.columns(2)
    with t1:
        st.markdown("**Observed Event Timeline**")
        timeline = soc_context["timeline"]
        if timeline:
            render_table(timeline[-30:])
        else:
            st.info("No valid timestamped events are available for timeline reconstruction.")
    with t2:
        st.markdown("**Activity Baseline**")
        if baseline["state"] == "OBSERVED_BASELINE":
            st.metric("Median Events / Hour", baseline["median"])
            st.metric("Peak Events / Hour", baseline["peak"])
            st.caption(f'Peak period: {baseline["peak_period"]} • deviation from observed median: {baseline["peak_deviation_percent"]}%')
        else:
            st.info(f'Baseline not calculated: {baseline["buckets"]} observed time bucket(s). At least 3 are required.')

    st.markdown("**Source / Asset Context**")
    st.caption("Asset and identity values are derived only when present in the evidence. Missing ownership, business criticality and directory context remain unavailable.")
    if soc_context["incidents"]:
        with st.expander("Correlated incidents", expanded=False):
            render_table(soc_context["incidents"][:30])
    st.caption("Sources are derived from the loaded evidence. Asset identity, ownership and criticality remain unavailable unless the source logs provide them or an asset inventory is configured.")
    st.markdown("**Detection Coverage**")
    coverage = soc_context["coverage"]["observed_category_rates"]
    covdf = pd.DataFrame([{"category": k.replace("_", " ").title(), "observed_rate": v} for k, v in coverage.items() if v is not None])
    if not covdf.empty:
        st.bar_chart(covdf.set_index("category"))
    else:
        st.info("Detection coverage is unavailable because the evidence set is empty.")

    st.markdown("**Data Integrity**")
    duplicate_rate = "UNAVAILABLE" if dup["duplicate_rate"] is None else f'{dup["duplicate_rate"]:.1f}%'
    st.caption(f'{dup["unique_events"]:,} unique event fingerprints from {dup["records"]:,} records • duplicate rate: {duplicate_rate}')
    st.markdown("### Intelligence Analytics — Evidence Grounded")
    data_class = "SIMULATED / DEMO DATA — NOT OPERATIONAL INTELLIGENCE" if st.session_state.demo_mode else "OBSERVED LOCAL EVIDENCE — OPERATIONAL DATA VIEW"
    st.caption(
        f"Data classification: {data_class}. All figures are computed from the loaded evidence in this session. "
        "Vanguard does not invent zeroes, estimates, or live external telemetry. "
        f"Evidence SHA-256: {st.session_state.analysis_evidence_sha256 or 'NOT AVAILABLE'}"
    )
    im1, im2, im3, im4 = st.columns(4)
    im1.metric("Observed Records", evidence_metrics["records"])
    im2.metric("Unique Sources", evidence_metrics["unique_sources"])
    im3.metric("Unique Targets", evidence_metrics["unique_targets"])
    im4.metric("Alert Rate", f'{evidence_metrics["alert_rate_pct"]:.2f}%')
    if evidence_metrics["first_seen"] and evidence_metrics["last_seen"]:
        st.caption(
            f"Observed window: {evidence_metrics['first_seen']} → {evidence_metrics['last_seen']} • "
            f"source: {st.session_state.telemetry_source}"
        )

    if st.session_state.logs:
        chart_left, chart_right = st.columns(2)
        with chart_left:
            severity_df = pd.DataFrame.from_dict(
                evidence_metrics["severity_counts"], orient="index", columns=["events"]
            )
            severity_df.index.name = "severity"
            st.markdown("**Severity distribution — observed events**")
            st.bar_chart(severity_df, use_container_width=True)
        with chart_right:
            top_attacks = pd.DataFrame.from_dict(
                evidence_metrics["top_attack_types"], orient="index", columns=["events"]
            ).head(10)
            top_attacks.index.name = "attack_type"
            st.markdown("**Observed attack/event categories**")
            if not top_attacks.empty:
                st.bar_chart(top_attacks, use_container_width=True)
            else:
                st.info("No categorized attack/event data is present in the evidence.")

        trend_df = analytics_trend(st.session_state.logs)
        if not trend_df.empty:
            trend_view = trend_df.set_index("period")[["records", "alerts", "critical"]]
            st.markdown("**Evidence activity over time**")
            st.line_chart(trend_view, use_container_width=True)
        else:
            st.info("No valid timestamps are available for a time-series chart.")

        source_df = pd.DataFrame.from_dict(
            evidence_metrics["top_sources"], orient="index", columns=["events"]
        ).head(10)
        source_df.index.name = "source"
        if not source_df.empty:
            st.markdown("**Most active observed sources**")
            st.bar_chart(source_df, use_container_width=True)

        finding_df = findings_dataframe(st.session_state.analysis_result)
        if not finding_df.empty:
            attack_coverage = (
                finding_df.dropna(subset=["mitre_technique"])
                .query("mitre_technique != ''")
                .groupby("mitre_technique", as_index=True)["count"]
                .sum()
                .sort_values(ascending=False)
                .head(15)
                .to_frame("observed_findings")
            )
            if not attack_coverage.empty:
                st.markdown("**ATT&CK-linked observed findings**")
                st.bar_chart(attack_coverage, use_container_width=True)

        # IOC analytics are extracted from the evidence payload itself; they are
        # not external threat intelligence and are never presented as confirmed.
        iocs = extract_iocs(
            "\n".join(str(row.get("raw_payload", "")) for row in st.session_state.logs),
            source="loaded-evidence",
            observed_at=evidence_metrics["last_seen"],
        )
        if iocs:
            ioc_df = pd.DataFrame(
                [{"kind": item.kind, "count": 1} for item in iocs]
            ).groupby("kind").sum().sort_values("count", ascending=False)
            st.markdown("**IOCs extracted from loaded evidence**")
            st.bar_chart(ioc_df, use_container_width=True)
            st.caption(
                f"{len(iocs)} unique IOC(s) extracted from evidence. "
                "These are OBSERVED artifacts, not externally validated threat intelligence."
            )
    else:
        st.info("No evidence is loaded. Analytics remain empty rather than displaying synthetic or stale figures.")

    policy = detection_policy()
    st.caption(f"Detection policy • {policy['brute_force_failures']} failures / {policy['behavior_window_seconds']}s • {policy['scan_unique_destinations']} unique destinations / {policy['behavior_window_seconds']}s • correlation {policy['correlation_window_seconds']}s")
    st.caption(f"Parse coverage {summary['parse_coverage']:.1f}% • {summary['unique_sources']} unique source(s) • {summary['unique_destinations']} unique destination(s) • Completed {st.session_state.analysis_completed_at or 'now'}")
    if st.session_state.analysis_evidence_sha256:
        st.code(f"Evidence SHA-256: {st.session_state.analysis_evidence_sha256}", language="text")
    if summary["rule_counts"]:
        render_table([{"Detection Rule": k, "Matches": v} for k, v in sorted(summary["rule_counts"].items(), key=lambda x: (-x[1], x[0]))])
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
    else:
        total_pages = max(1, (len(view) + LOG_PAGE_SIZE - 1) // LOG_PAGE_SIZE)
        st.session_state.log_page = min(st.session_state.log_page, total_pages - 1)
        p1, p2, p3 = st.columns([1, 1, 2])
        with p1:
            if st.button("← Newer", disabled=st.session_state.log_page <= 0, use_container_width=True):
                st.session_state.log_page -= 1
                st.rerun()
        with p2:
            if st.button("Older →", disabled=st.session_state.log_page >= total_pages - 1, use_container_width=True):
                st.session_state.log_page += 1
                st.rerun()
        with p3:
            st.caption(f"Page {st.session_state.log_page + 1}/{total_pages} • {len(view):,} matching records • all records retained for analysis")
        start_row = st.session_state.log_page * LOG_PAGE_SIZE
        page_rows = view.iloc[start_row:start_row + LOG_PAGE_SIZE].to_dict("records")
        for row in page_rows:
            sev = row["severity"].title()
            state = " • QUARANTINED" if row["source_ip"] in st.session_state.quarantined_ips else ""
            st.markdown(f'<div class="log {sev}"><div class="lh"><span>{html.escape(row["timestamp"])} · <b>{html.escape(row["event_id"])}</b></span><span class="sev">{html.escape(row["severity"])}{state}</span></div><div><b>{html.escape(row["attack_type"])}</b> <span class="pill">{html.escape(row["source_ip"])}</span></div><div class="lm">Target: {html.escape(row["target_endpoint"])}</div></div>', unsafe_allow_html=True)
        page_options = [row["event_id"] for row in page_rows]
        current_page_index = page_options.index(st.session_state.selected_event) if st.session_state.selected_event in page_options else 0
        selected_page_event = st.selectbox("Select event for investigation", page_options, index=current_page_index)
        st.session_state.selected_event = selected_page_event
        if st.button("🔎 Open selected event in Tactical Inspector", type="primary", use_container_width=True):
            st.session_state.last_action = f"Event inspector opened for {selected_page_event}."
    st.markdown('</div>', unsafe_allow_html=True)

with right:
    log = selected_log()
    st.markdown('<div class="panel"><div class="pt">Tactical Analyst Inspector & Response</div>', unsafe_allow_html=True)
    if log is None:
        st.info("No telemetry available.")
    else:
        st.markdown(f'<div class="box"><b>Event ID</b><br>{html.escape(log["event_id"])}<br><br><b>Source IP</b><br>{html.escape(log["source_ip"])}<br><br><b>Target Endpoint</b><br>{html.escape(log["target_endpoint"])}</div>', unsafe_allow_html=True)
        findings = st.session_state.analysis_result.get("analyst_alerts", []) if st.session_state.analysis_result else []
        finding = next((item for item in findings if log.get("raw_sha256") in item.get("evidence_ids", [])), None)
        if finding:
            st.markdown(
                f'<div class="box"><b>Finding</b> {html.escape(finding["alert_id"])} • <b>{html.escape(finding["severity"])}</b> • Confidence {html.escape(finding["confidence"])}<br>'
                f'Rule {html.escape(finding["rule_id"])} v{html.escape(finding["rule_version"])} • MITRE {html.escape(finding.get("mitre_technique") or "Not mapped")}<br>'
                f'Occurrences {finding["count"]:,} • Sources {len(finding["sources"]):,} • Destinations {len(finding["destinations"]):,}</div>',
                unsafe_allow_html=True,
            )
        st.caption("RAW PAYLOAD • SANITIZED DISPLAY")
        st.code(log["raw_payload"], language="text")
        st.markdown(f'<div class="ai"><b>Deterministic defensive translation</b><br><br>{html.escape(log["description"])}</div>', unsafe_allow_html=True)
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


st.markdown('<div class="panel"><div class="pt">Log Analysis Center</div>', unsafe_allow_html=True)
st.caption(f"Local evidence analysis • up to {MAX_UPLOAD_BYTES / (1024**3):.0f} GiB per file • sanitized, hashed and analyzed offline. No separate validation/staging step is required.")

with st.expander("Analyze security logs", expanded=True):
    uploaded = st.file_uploader(
        "Choose a local log file",
        type=sorted(ALLOWED_UPLOAD_TYPES),
        accept_multiple_files=False,
        max_upload_size=1024,
        help="Local files up to 1 GiB. Uploaded content is never executed.",
    )
    fmt = st.selectbox("Format", ["AUTO", "TEXT / SYSLOG", "CSV", "JSON", "JSONL", "XML"])
    source_name = st.text_input("Source", value="Local evidence")

    if uploaded is None:
        st.info("Select a local evidence file, then click Analyze. No separate validation step is required.")
    else:
        raw_bytes = uploaded.getvalue()
        current_digest = __import__("hashlib").sha256(raw_bytes).hexdigest()
        size_mb = len(raw_bytes) / (1024 * 1024)
        st.caption(f"Evidence: {uploaded.name} • {size_mb:,.1f} MB • SHA-256 {current_digest[:16]}…")

        if st.button("Analyze Evidence", type="primary", use_container_width=True):
            run_id = None
            try:
                archive = EvidenceStore()
                archive.archive_evidence(raw_bytes, uploaded.name, fmt)
                run_id = archive.start_analysis_run(current_digest)
                st.session_state.analysis_state = "ANALYZING"
                st.session_state.pipeline_stage = "ANALYZE"
                progress = st.progress(0, text="Starting evidence analysis…")
                live_dashboard.empty()
                preview = st.empty()
                from collections import deque
                preview_rows = deque(maxlen=MAX_UI_ROWS)

                def publish_chunk(events, processed, total):
                    for event in events:
                        preview_rows.append({
                            "event_id": f"EVT-{event.raw_sha256[:10].upper()}",
                            "timestamp": event.timestamp.isoformat(),
                            "severity": event.severity or "LOW",
                            "source_ip": event.source_ip or "N/A",
                            "target_endpoint": event.fields.get("path") or event.fields.get("endpoint") or event.destination_ip or event.event_type,
                            "attack_type": event.action or event.event_type,
                        })
                    if total:
                        pct = min(0.99, processed / total)
                        progress.progress(pct, text=f"Analyzing evidence… {processed:,}/{total:,} records")
                    else:
                        progress.progress(0.0, text=f"Analyzing evidence… {processed:,} records processed • complete evidence scan in progress")
                    live = pd.DataFrame(list(preview_rows))
                    with live_dashboard.container():
                        lm1, lm2, lm3, lm4 = st.columns(4)
                        lm1.metric("Analyzed Records", processed)
                        lm2.metric("Critical Anomalies", int((live["severity"] == "CRITICAL").sum()) if not live.empty else 0)
                        lm3.metric("High / Warning", int(live["severity"].isin(["HIGH", "WARNING"]).sum()) if not live.empty else 0)
                        lm4.metric("Latest Event", preview_rows[-1]["event_id"] if preview_rows else "-")
                        st.caption("LIVE ANALYSIS FEED • records are being normalized while the evidence is analyzed")
                        render_table(live.tail(MAX_UI_ROWS))

                bundle = analyze_bytes_incremental(raw_bytes, uploaded.name, fmt, on_chunk=publish_chunk)
                if bundle["sha256"] != current_digest:
                    raise ValueError("Evidence changed during analysis. Please analyze the current file again.")
                progress.progress(1.0, text=f"Analysis complete • {bundle['records']:,} records")
                commit_dashboard_state(st, bundle, source_name or uploaded.name)
                st.session_state.pipeline_history.append({
                    "source": uploaded.name,
                    "sha256": bundle["sha256"],
                    "records": bundle["records"],
                    "completed_at": bundle["completed_at"],
                })
                archive.record_analysis_snapshot(run_id, current_digest, bundle["analysis"].get("analyst_alerts", []))
                archive.finish_analysis_run(run_id, "COMPLETE", bundle["records"], len(bundle["analysis"].get("analyst_alerts", [])), bundle["analysis"].get("risk_score"))
                st.session_state.analysis_state = "COMPLETE"
                st.session_state.last_action = f"Analysis complete for {uploaded.name}. Dashboard updated from the analyzed evidence and preserved in Evidence History."
                st.rerun()
            except Exception as exc:
                st.session_state.analysis_state = "FAILED"
                st.session_state.pipeline_stage = "FAILED"
                st.session_state.analysis_completed_at = datetime.now(timezone.utc).isoformat()
                detail = f"{type(exc).__name__}: {exc}"
                if run_id is not None:
                    try:
                        EvidenceStore().finish_analysis_run(run_id, "FAILED", error=detail)
                    except Exception:
                        pass
                st.session_state.last_action = f"Analysis failed safely for {uploaded.name}: {detail}"
                st.error(f"Analysis failed safely: {detail}")

st.markdown('</div>', unsafe_allow_html=True)



st.markdown('<div class="panel"><div class="pt">Evidence History & Replay</div>', unsafe_allow_html=True)
st.caption("Every accepted upload is preserved by SHA-256 in the local evidence archive with upload time, filename, format and analysis-run history. Previous evidence can be reloaded and analyzed again without changing the original evidence record.")
store = EvidenceStore()
history_rows = store.history(limit=100)
if history_rows:
    history_view = [{k: r[k] for k in ["id","filename","format","size_bytes","uploaded_at","evidence_sha256","status"]} for r in history_rows]
    render_table(history_view)
    upload_events = store.upload_history(limit=200)
    st.caption(f"Upload events preserved: {len(upload_events)} • identical files are deduplicated in the evidence archive but every upload event remains in history.")
    if upload_events:
        render_table(upload_events[:50])
    choices = [f"{r['id']} • {r['filename']} • {r['uploaded_at']} • {r['evidence_sha256'][:12]}…" for r in history_rows]
    selected_idx = st.selectbox("Select preserved evidence", range(len(choices)), format_func=lambda i: choices[i], key="history_select")
    selected = history_rows[selected_idx]
    runs = store.analysis_history(selected["evidence_sha256"], limit=20)
    st.markdown(f"**Analysis / scan count: {len(runs)}**")
    if runs:
        run_rows = []
        for run in runs:
            variation = store.analysis_variation(selected["evidence_sha256"], run["id"]) if run["status"] == "COMPLETE" else {"total_variations": 0, "added_count": 0, "removed_count": 0, "changed_count": 0}
            run_rows.append({**{k: run[k] for k in ["id","started_at","completed_at","status","records","finding_groups","risk_score","error"]}, "variations": variation["total_variations"], "added": variation["added_count"], "removed": variation["removed_count"], "changed": variation["changed_count"]})
        render_table(run_rows)
        latest_complete = next((r for r in runs if r["status"] == "COMPLETE"), None)
        if latest_complete:
            variation = store.analysis_variation(selected["evidence_sha256"], latest_complete["id"])
            st.markdown(f"**Latest scan variation vs run #{variation['baseline_run_id'] or 'baseline'}** • {variation['total_variations']} variation(s) — {variation['added_count']} added, {variation['removed_count']} removed, {variation['changed_count']} changed.")
            for label, key in [("Added findings","added"),("Removed findings","removed"),("Changed findings","changed")]:
                items = variation[key]
                if items:
                    with st.expander(f"{label} ({len(items)})", expanded=(key == "changed")):
                        if key == "changed":
                            render_table([{"finding": x["finding_key"], "rule": x["rule_id"], "reason": x["reason"], "differences": str(x["differences"])} for x in items])
                        else:
                            render_table([{"finding": x["finding_key"], "rule": x["rule_id"], "severity": x["severity"], "occurrences": x["occurrence_count"], "reason": x["reason"]} for x in items])
    if st.button("Analyze Selected Historical Evidence", type="primary", use_container_width=True):
        try:
            data, meta = store.load_evidence(selected["evidence_sha256"])
            rid = store.start_analysis_run(selected["evidence_sha256"])
            bundle = analyze_bytes(data, meta["filename"], meta["format"])
            commit_dashboard_state(st, bundle, meta["filename"])
            store.record_analysis_snapshot(rid, selected["evidence_sha256"], bundle["analysis"].get("analyst_alerts", []))
            store.finish_analysis_run(rid, "COMPLETE", bundle["records"], len(bundle["analysis"].get("analyst_alerts", [])), bundle["analysis"].get("risk_score"))
            st.session_state.last_action = f"Historical evidence replay completed for {meta['filename']}."
            st.rerun()
        except Exception as exc:
            if "rid" in locals():
                try:
                    store.finish_analysis_run(rid, "FAILED", error=f"{type(exc).__name__}: {exc}")
                except Exception:
                    pass
            st.error(f"Historical analysis failed safely: {type(exc).__name__}: {exc}")
else:
    st.info("No preserved evidence uploads yet. Analyze a local file to create the first immutable evidence-history entry.")
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

st.markdown('<div class="panel"><div class="pt">SOC Analytics & Report Center</div>', unsafe_allow_html=True)
st.caption("Offline evidence analytics • percentages, risk percentiles, trends and detection graphs. No external or estimated figures are added.")
if st.session_state.logs:
    ar = analytics_summary(st.session_state.logs)
    ac1, ac2, ac3, ac4, ac5, ac6 = st.columns(6)
    ac1.metric("Records", f"{ar['records']:,}")
    ac2.metric("Unique Sources", f"{ar['unique_sources']:,}")
    ac3.metric("Unique Targets", f"{ar['unique_targets']:,}")
    ac4.metric("Attack Types", f"{ar['unique_attack_types']:,}")
    ac5.metric("Alert Rate", f"{ar['alert_rate_pct']:.2f}%")
    ac6.metric("Critical Rate", f"{ar['critical_rate_pct']:.2f}%")

    st.markdown("**Evidence risk percentile profile**")
    rp = ar["risk_percentiles"]
    pc1, pc2, pc3, pc4, pc5 = st.columns(5)
    pc1.metric("Current Mean", f"{ar['risk_percentile_current']:.1f}")
    pc2.metric("P50", f"{rp['p50']:.1f}")
    pc3.metric("P75", f"{rp['p75']:.1f}")
    pc4.metric("P90", f"{rp['p90']:.1f}")
    pc5.metric("P95", f"{rp['p95']:.1f}")
    st.caption("Risk percentile values are derived from observed severity bands: CRITICAL 100, HIGH 80, WARNING 60, MEDIUM 40, LOW 20. They describe this evidence set; they are not external threat probabilities.")

    st.markdown("**Severity distribution (%)**")
    sev_pct_df = pd.DataFrame({
        "severity": list(ar["severity_percentages"].keys()),
        "percentage": list(ar["severity_percentages"].values()),
    })
    st.bar_chart(sev_pct_df.set_index("severity"), y="percentage")

    st.markdown("**Severity distribution (records)**")
    sevdf = pd.DataFrame({"severity": list(ar["severity_counts"].keys()), "count": list(ar["severity_counts"].values())})
    st.bar_chart(sevdf.set_index("severity"), y="count")

    st.markdown("**Security activity trend**")
    tr = analytics_trend(st.session_state.logs)
    if not tr.empty:
        trend_view = tr.set_index("period")[["records", "alerts", "critical"]]
        st.line_chart(trend_view)

    st.markdown("**Top attack types**")
    top_attack_df = pd.DataFrame(list(ar["top_attack_types"].items()), columns=["attack_type","count"])
    if not top_attack_df.empty:
        st.bar_chart(top_attack_df.set_index("attack_type"), y="count")

    with st.expander("Top sources / analytical detail", expanded=False):
        render_table([{"Source IP":k,"Events":v} for k,v in ar["top_sources"].items()])
        if st.session_state.analysis_result:
            st.json(st.session_state.analysis_result.get("risk_breakdown", {}))

    st.markdown("**Analyst findings & detection analytics**")
    fdf = findings_dataframe(st.session_state.analysis_result)
    if not fdf.empty:
        render_table(fdf.head(100))
    matrix = attack_matrix(st.session_state.logs)
    if not matrix.empty:
        with st.expander("Attack × severity matrix", expanded=False):
            render_table(matrix.reset_index().to_dict("records"))
    rdf = rule_counts_dataframe(st.session_state.analysis_result)
    if not rdf.empty:
        with st.expander("Detection rule volume", expanded=False):
            st.bar_chart(rdf.head(15).set_index("rule_id"), y="count")

    st.markdown("**Download / print reports**")
    st.caption("Each report is generated from the exact evidence currently displayed above. No external or estimated figures are added.")
    if st.session_state.analysis_evidence_sha256:
        st.success(f"REPORT READY • Evidence {st.session_state.analysis_evidence_sha256[:16]}… • {len(st.session_state.logs):,} observed records")
    else:
        st.warning("REPORT NOT VERIFIED • The current view has no evidence SHA-256. Load and analyze evidence before treating a report as operational.")
    report_source = st.session_state.telemetry_source or "Local evidence"
    bundle = export_bundle(st.session_state.logs, st.session_state.analysis_result, report_source)
    rc = st.columns(7)
    for col,key,label,mime in [
        (rc[0],"pdf","PDF","application/pdf"),
        (rc[1],"docx","Word","application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        (rc[2],"xlsx","Excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (rc[3],"pptx","PowerPoint","application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        (rc[4],"html","Print HTML","text/html"),
        (rc[5],"csv","CSV","text/csv"),
        (rc[6],"json","JSON","application/json"),
    ]:
        with col:
            if st.download_button(f"⬇ {label}", data=bundle[key], file_name=f"vanguard_soc_report.{key}", mime=mime, key=f"report_{key}"):
                audit_event("SOC_REPORT_EXPORT", f"{report_source}:{key}", st.session_state.analysis_evidence_sha256 or "")

st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="panel"><div class="pt">Security Operations Center</div>', unsafe_allow_html=True)
st.caption("Offline asset, identity, incident and telemetry-health registries. These records are defensive metadata only; no discovery or external network calls are performed.")
ops = SecurityOperationsStore()
oc1, oc2, oc3, oc4 = st.columns(4)
assets = ops.assets()
identities = ops.identities()
incidents = ops.incidents()
telemetry = ops.telemetry()
oc1.metric("Registered Assets", len(assets))
oc2.metric("Identities", len(identities))
oc3.metric("Incidents / Cases", len(incidents))
oc4.metric("Telemetry Sources", len(telemetry))

with st.expander("Asset Registry", expanded=False):
    if assets:
        render_table(assets)
    else:
        st.info("No assets registered. Import or enter authorized asset metadata.")
with st.expander("Identity Registry", expanded=False):
    if identities:
        render_table(identities)
    else:
        st.info("No identities registered.")
with st.expander("Incident & Case Register", expanded=True):
    if incidents:
        render_table(incidents)
    else:
        st.info("No incidents registered. Detection output remains evidence-based until a case is created.")
with st.expander("Telemetry Health", expanded=True):
    if telemetry:
        render_table(telemetry)
    else:
        st.info("No telemetry-health records yet. UNKNOWN means no telemetry is available; it is not treated as zero activity.")
    if st.session_state.logs:
        source_key = st.session_state.telemetry_source or "local-evidence"
        last_event = None
        observed_rate = None
        if st.session_state.logs:
            timestamps = [x.get("timestamp") for x in st.session_state.logs if x.get("timestamp")]
            last_event = max(timestamps) if timestamps else None
            observed_rate = float(len(st.session_state.logs))
        status, reason = telemetry_status(last_event, observed_rate, None)
        ops.record_telemetry_health(source_key, last_event=last_event, observed_rate=observed_rate, status=status, reason=reason)
        st.metric("Current source health", status)
        st.caption(reason)
st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="panel"><div class="pt">System Health & Integrity</div>', unsafe_allow_html=True)
h1, h2, h3 = st.columns(3)
with h1:
    st.metric("Evidence Store", "READY" if st.session_state.get("evidence_store_summary") else "IDLE")
with h2:
    audit_status = verify_audit_chain()
    st.metric("Audit Chain", "PASS" if audit_status["valid"] else "FAIL")
with h3:
    st.metric("Audit Records", int(audit_status.get("records", 0)))
st.caption("Offline runtime • local evidence store • append-only audit verification • no external telemetry.")
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
