from __future__ import annotations

import html
import json
import hashlib
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



def _format_audit_timestamp(value):
    if not value:
        return '—'
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return f"{dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} ({value})"
    except (TypeError, ValueError):
        return str(value)

def _analysis_duration(started_at, completed_at):
    if not started_at:
        return '—'
    try:
        start = datetime.fromisoformat(str(started_at).replace('Z', '+00:00'))
        end = datetime.fromisoformat(str(completed_at).replace('Z', '+00:00')) if completed_at else datetime.now(timezone.utc)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        seconds = max(0, int((end - start).total_seconds()))
        return f"{seconds//3600:02d}:{(seconds%3600)//60:02d}:{seconds%60:02d}"
    except (TypeError, ValueError):
        return '—'

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
.vbrand{display:flex;align-items:center;justify-content:center;gap:12px}.vmark{width:38px;height:38px;border:1px solid #00e5ff;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#00e5ff;font-family:"IBM Plex Mono",monospace!important;font-weight:800;font-size:1.25rem;box-shadow:0 0 22px rgba(0,229,255,.2),inset 0 0 14px rgba(0,229,255,.08)}.vwordmark{font-family:"IBM Plex Mono","SFMono-Regular",monospace!important;font-size:2.65rem;font-weight:800;letter-spacing:.22em;color:#f3f8fc;text-shadow:0 0 22px rgba(0,229,255,.18);margin-left:.12em}.vtag{font-family:"IBM Plex Mono",monospace!important;color:#00e5ff;font-size:.72rem;font-weight:800;letter-spacing:.18em;border:1px solid rgba(0,229,255,.35);padding:4px 7px;border-radius:5px}.vsubtitle{text-align:center;color:#9db1c4;font-size:.72rem;font-weight:700;letter-spacing:.16em;margin-top:9px}.vstatus{text-align:center;color:#65e6a0;font-size:.72rem;font-weight:800;letter-spacing:.12em;margin-top:11px}.vdot{color:#00e5ff;text-shadow:0 0 10px rgba(0,229,255,.8)}.vline{height:1px;max-width:560px;margin:15px auto 10px;background:linear-gradient(90deg,transparent,rgba(0,229,255,.55),transparent)}.vmeta{text-align:center;color:#587287;font-family:"IBM Plex Mono",monospace!important;font-size:.61rem;letter-spacing:.13em}.vh{border:1px solid #214257;border-radius:18px;padding:18px 26px;background:linear-gradient(135deg,rgba(16,30,43,.98),rgba(7,12,18,.99));margin-bottom:16px;box-shadow:0 14px 40px rgba(0,0,0,.28);position:sticky;top:0;z-index:9999;overflow:hidden;backdrop-filter:blur(12px)}.vh:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(94,227,138,.05),transparent);pointer-events:none}.vk{display:flex;gap:10px;align-items:center;color:#8fa5ba;font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;margin-bottom:8px}.vt{font-size:1.55rem;font-weight:850;letter-spacing:.055em}.vs{color:#5ee38a;font-weight:700;margin-top:4px}.metric{border:1px solid #253444;border-radius:14px;padding:15px 17px;background:linear-gradient(145deg,#0e171f,#0a1017);box-shadow:0 8px 22px rgba(0,0,0,.18)}.mv{font-size:1.6rem;font-weight:850}.ml{color:#91a1b4;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}
.panel{border:1px solid #253444;border-radius:16px;padding:18px;background:rgba(9,15,22,.94);min-height:520px;box-shadow:0 12px 32px rgba(0,0,0,.18);backdrop-filter:blur(8px)}.upload-panel{max-width:980px;min-height:0;padding:11px 14px;margin:0 auto 12px}.upload-panel .pt{margin-bottom:7px;font-size:.82rem;letter-spacing:.13em}.upload-panel [data-testid="stFileUploader"]{margin:0}.upload-panel [data-testid="stFileUploaderDropzone"]{min-height:76px!important;padding:9px 12px!important;border-radius:10px!important;border:1px dashed #31566c!important;background:linear-gradient(135deg,rgba(10,23,33,.92),rgba(7,14,21,.92))!important}.upload-panel [data-testid="stFileUploaderDropzoneInstructions"]{padding:0!important}.upload-panel [data-testid="stFileUploaderDropzoneInstructions"]>div{font-size:.76rem!important;line-height:1.25!important}.upload-panel [data-testid="stFileUploaderDropzoneInstructions"] small{font-size:.64rem!important}.upload-panel [data-testid="stFileUploader"] button{min-height:30px!important;padding:4px 10px!important;font-size:.72rem!important}.upload-panel [data-testid="stFileUploaderFile"]{padding:5px 8px!important;margin-top:5px!important}.upload-panel .stCaption{font-size:.66rem!important;margin:3px 0 6px!important}.upload-panel .upload-action-label{font-size:.62rem;font-weight:800;letter-spacing:.12em;color:#5ee38a;margin:3px 0 7px;text-align:center}.upload-panel .upload-action-placeholder{height:18px}.upload-panel .stButton>button{min-height:76px!important;border-radius:10px!important;font-size:.78rem!important;font-weight:850!important;letter-spacing:.04em}.upload-panel+.stElementContainer{margin-top:0}.export-panel{max-width:1180px;margin-left:auto;margin-right:auto;padding:14px 16px}.export-panel .stDownloadButton>button{min-height:42px;border-radius:9px;font-size:.78rem;font-weight:850;letter-spacing:.03em}.pt{font-weight:850;text-transform:uppercase;letter-spacing:.1em;color:#d5e1ed;margin-bottom:12px;display:flex;align-items:center;gap:8px}.log{border:1px solid #1e2b38;border-left:4px solid #5ee38a;border-radius:10px;padding:11px 13px;margin:8px 0;background:linear-gradient(100deg,#0d151e,#0a1118);transition:transform .15s ease,border-color .15s ease}.log:hover{transform:translateX(2px);border-color:#35516a}.log.Critical{border-left-color:#ff4d5f}.log.Warning{border-left-color:#f6c453}.lh{display:flex;justify-content:space-between;gap:8px;font-size:.82rem}.sev{font-weight:800}.Critical .sev{color:#ff6675}.Warning .sev{color:#f6c453}.Low .sev{color:#5ee38a}.lm{color:#9aaabd;font-size:.76rem;margin-top:3px}.pill{display:inline-block;padding:3px 7px;border-radius:999px;background:#15202b;font-size:.7rem}.box{border:1px solid #253444;border-radius:11px;padding:13px;background:#080d13;margin:10px 0;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.ai{border-left:3px solid #7aa7ff;background:#0d1520;border-radius:8px;padding:12px}.q{color:#ff6675;font-weight:800}
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
st.markdown('<div class="panel upload-panel"><div class="pt">LOG FILE UPLOAD</div>', unsafe_allow_html=True)
st.caption(f"Upload immediately below the Vanguard title • local evidence analysis • up to {MAX_UPLOAD_BYTES / (1024**3):.0f} GiB per file • sanitized, hashed and analyzed offline.")

upload_col, action_col = st.columns([4.8, 1.35], gap="small")
with upload_col:
    uploaded = st.file_uploader(
        "Choose a local log file",
        type=sorted(ALLOWED_UPLOAD_TYPES),
        accept_multiple_files=False,
        max_upload_size=1024,
        help="Local files up to 1 GiB. Uploaded content is never executed.",
    )

analyze_clicked = False
with action_col:
    if uploaded is not None:
        st.markdown('<div class="upload-action-label">READY</div>', unsafe_allow_html=True)
        analyze_clicked = st.button("Analyze", type="primary", use_container_width=True, help="Analyze the uploaded log file immediately.")
    else:
        st.markdown('<div class="upload-action-placeholder"></div>', unsafe_allow_html=True)

fmt = st.selectbox("Format", ["AUTO", "TEXT / SYSLOG", "CSV", "JSON", "JSONL", "XML"])
source_name = st.text_input("Source", value="Local evidence")

# This placeholder is created immediately after the upload panel so all live analysis output
# renders below the title and upload controls, never above them.
live_dashboard = st.empty()

if uploaded is None:
    st.info("Select a local evidence file. The Analyze button appears immediately beside the upload control.")
else:
    raw_bytes = uploaded.getvalue()
    current_digest = __import__("hashlib").sha256(raw_bytes).hexdigest()
    size_mb = len(raw_bytes) / (1024 * 1024)
    st.caption(f"Evidence: {uploaded.name} • {size_mb:,.1f} MB • SHA-256 {current_digest[:16]}…")

    if analyze_clicked:
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
                if bundle["sha256"] != current_digest:                    raise ValueError("Evidence changed during analysis. Please analyze the current file again.")
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

st.markdown('<div class="box" style="border-color:#00e5ff;"><b>PRIMARY WORKFLOW — EVIDENCE INTAKE</b> &nbsp; Upload → Preserve → Analyse → Investigate → Report. Start here for local security logs; accepted evidence is SHA-256 preserved before analysis.</div>', unsafe_allow_html=True)

# Export the exact analyzed dataset after analysis completes.
if st.session_state.logs and st.session_state.analysis_result:
    export_source = st.session_state.telemetry_source or "Local evidence"
    export_sha = st.session_state.analysis_evidence_sha256 or ""
    st.markdown('<div class="panel export-panel" style="min-height:0;margin-bottom:14px;">', unsafe_allow_html=True)
    st.markdown('<div class="pt">DOWNLOAD ANALYZED DATA</div>', unsafe_allow_html=True)
    st.caption("Lossless exports • all analyzed records and parsed fields • suitable for review, printing and archival.")
    export_cols = st.columns(3, gap="small")
    with export_cols[0]:
        pdf_bytes = __import__("reporting").make_pdf(st.session_state.logs, st.session_state.analysis_result, export_source)
        st.download_button("Download PDF", data=pdf_bytes, file_name=f"vanguard_analysis_{export_sha[:12]}.pdf", mime="application/pdf", use_container_width=True)
    with export_cols[1]:
        docx_bytes = __import__("reporting").make_docx(st.session_state.logs, st.session_state.analysis_result, export_source)
        st.download_button("Download Word", data=docx_bytes, file_name=f"vanguard_analysis_{export_sha[:12]}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", use_container_width=True)
    with export_cols[2]:
        xlsx_bytes = __import__("reporting").make_xlsx(st.session_state.logs, st.session_state.analysis_result, export_source)
        st.download_button("Download Excel", data=xlsx_bytes, file_name=f"vanguard_analysis_{export_sha[:12]}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
 
st.markdown(
    '<div class="box" style="border-color:#00e5ff;">'
    '<b>PRIMARY WORKFLOW — EVIDENCE INTAKE</b> &nbsp; '
    'Upload → Preserve → Analyse → Investigate → Report. '
    'Start here for local security logs; accepted evidence is SHA-256 preserved before analysis.'
    '</div>',
    unsafe_allow_html=True,
)
