from __future__ import annotations

import html
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from engine import analyze_events, correlate, detect, detect_behavior, parse_line
from ingestion import ALLOWED_UPLOAD_TYPES, MAX_RECORDS, MAX_UPLOAD_BYTES, infer_upload_format, lines_from_upload, safe_uploaded_text
from audit import audit_event
from distributed import EventBuffer
from firewall import block_ip
from remediation import propose, execute_approved
from threat_intel import ThreatIntelCache
from windows_events import available as windows_events_available
from local_ai import explain as local_ai_explain

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
[data-testid="stAppViewContainer"]{background:radial-gradient(circle at 10% 0%,#102033 0,#070b10 35%,#05080c 100%)}
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
        "incident_exports": 0,
        "last_action": "System initialized in air-gapped mode.",
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

st.markdown('<div class="vh"><div class="vk">🛡️ CISMIC 2026 • LOCAL SOC • DEFENSIVE ANALYTICS</div><div class="vt">VANGUARD-SIEM // Tactical Operations Console</div><div class="vs">● Status: SECURED (Air-Gapped Local Net) • EVIDENCE PROCESSING ONLINE</div></div>', unsafe_allow_html=True)

c1, c2 = st.columns([5, 1])
with c1:
    st.caption(f"Live local telemetry • {html.escape(st.session_state.telemetry_source)} • No hard-coded operational events")
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
metrics = st.columns(4)
critical = int((_df["severity"] == "CRITICAL").sum()) if not _df.empty else 0
high = int((_df["severity"].isin(["HIGH", "WARNING"])).sum()) if not _df.empty else 0
for col, value, label in zip(metrics, [len(_df), critical, high, len(st.session_state.quarantined_ips)], ["Total Log Entries", "Critical Anomalies", "High / Warning Alerts", "Quarantined Hosts"]):
    with col:
        st.markdown(f'<div class="metric"><div class="mv">{value}</div><div class="ml">{label}</div></div>', unsafe_allow_html=True)

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
    if st.button("Analyze Uploaded Log", type="primary", disabled=uploaded is None):
        try:
            st.session_state.analysis_state = "ANALYZING"
            st.session_state.last_action = f"Analyzing {uploaded.name} locally…"
            text, digest = safe_uploaded_text(uploaded.getvalue(), uploaded.name)
            actual_fmt = fmt
            if actual_fmt == "AUTO":
                actual_fmt = infer_upload_format(text, uploaded.name)
            if actual_fmt == "JSONL":
                st.info("Detected JSON Lines (one JSON object per line); processing as JSONL.")
            lines = lines_from_upload(text, "TEXT" if actual_fmt in {"TEXT / SYSLOG", "XML"} else actual_fmt)
            if not lines:
                raise ValueError("No non-empty records were found.")
            if len(lines) > MAX_RECORDS:
                raise ValueError(f"Record limit exceeded: maximum {MAX_RECORDS:,} records per upload.")
            events = [parse_line(line, actual_fmt) for line in lines]
            analysis = analyze_events(events)
            alerts = analysis["alerts"]
            incidents = analysis["incidents"]
            # Replace dashboard training data with the actual analyzed evidence.
            alerts_by_event = {}
            for alert in alerts:
                alerts_by_event.setdefault(id(alert.event), []).append(alert)
            live_logs = []
            for index, event in enumerate(events, start=1):
                event_alerts = alerts_by_event.get(id(event), [])
                primary = max(event_alerts, key=lambda a: {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(a.severity,0), default=None)
                live_logs.append({
                    "timestamp": event.timestamp.isoformat(),
                    "event_id": f"EVT-{event.raw_sha256[:10].upper()}" if event.raw_sha256 else f"EVT-LOCAL-{index:06d}",
                    "source_ip": event.source_ip or "N/A",
                    "severity": primary.severity if primary else (event.severity or "LOW"),
                    "target_endpoint": event.fields.get("path") or event.fields.get("endpoint") or event.destination_ip or event.event_type,
                    "attack_type": primary.title if primary else (event.action or event.event_type),
                    "raw_payload": event.message,
                    "description": primary.reason if primary else "No configured detection rule matched this event.",
                    "raw_sha256": event.raw_sha256,
                    "source_format": event.source_format,
                })
            st.session_state.logs = live_logs
            st.session_state.selected_event = live_logs[0]["event_id"] if live_logs else None
            st.session_state.telemetry_source = f"{uploaded.name} • {len(live_logs):,} records"
            st.session_state.demo_mode = False
            st.session_state.analysis_result = analysis
            st.session_state.analysis_summary = {
                "risk_score": analysis["risk_score"], "parse_coverage": analysis["parse_coverage"],
                "unique_sources": len(analysis["unique_sources"]), "unique_destinations": len(analysis["unique_destinations"]),
                "rule_counts": analysis["rule_counts"], "severity_counts": analysis["severity_counts"]}
            st.session_state.analysis_state = "COMPLETE"
            st.session_state.analysis_completed_at = datetime.now(timezone.utc).isoformat()
            st.session_state.analysis_evidence_sha256 = digest
            audit_event("EVIDENCE_ANALYSIS", source_name, digest)
            st.session_state.last_action = f"Analysis complete for {uploaded.name}. Dashboard updated from local evidence. SHA-256: {digest[:16]}…"
            st.rerun()
            u1, u2, u3, u4, u5 = st.columns(5)
            u1.metric("Records", len(lines))
            u2.metric("Parsed", len(events))
            u3.metric("Alerts", len(alerts))
            u4.metric("Incidents", len(incidents))
            u5.metric("Risk Score", analysis["risk_score"])
            s1, s2, s3 = st.columns(3)
            s1.metric("Parse Coverage", f"{analysis['parse_coverage']:.1f}%")
            s2.metric("Unique Sources", len(analysis["unique_sources"]))
            s3.metric("Unique Destinations", len(analysis["unique_destinations"]))
            st.markdown("#### Detection breakdown")
            if analysis["rule_counts"]:
                st.dataframe(pd.DataFrame([{"Rule": k, "Matches": v} for k, v in sorted(analysis["rule_counts"].items(), key=lambda x: (-x[1], x[0]))]), use_container_width=True, hide_index=True)
            else:
                st.info("No configured detection rules matched the uploaded telemetry.")
            if alerts:
                for alert in alerts:
                    st.warning(f"{alert.severity} • {alert.rule_id} • {alert.title} — {alert.reason}")
            else:
                st.info("No configured detection rules matched the uploaded telemetry.")
            for incident in incidents:
                sources = ", ".join(sorted(x for x in incident["sources"] if x))
                st.markdown(f'**{incident["incident_id"]}** • {incident["severity"]} • {len(incident["alerts"])} alert(s) • Sources: {sources}')
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            st.session_state.analysis_state = "FAILED"
            st.session_state.analysis_completed_at = datetime.now(timezone.utc).isoformat()
            st.session_state.last_action = f"Analysis failed safely for {uploaded.name}: {exc}"
            st.error(f"Upload rejected safely: {exc}")

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
        lines = [line for line in raw_lines.splitlines() if line.strip()]
        events = [parse_line(line, "local-text") for line in lines]
        alerts = []
        for event in events:
            alerts.extend(detect(event))
        alerts.extend(detect_behavior(events))
        incidents = correlate(alerts)
        st.session_state.last_action = f"Locally analyzed {len(events)} events and generated {len(alerts)} alerts."
        m1, m2, m3 = st.columns(3)
        m1.metric("Events Parsed", len(events))
        m2.metric("Alerts", len(alerts))
        m3.metric("Incidents", len(incidents))
        for alert in alerts:
            st.warning(f"{alert.severity} • {alert.rule_id} • {alert.title} — {alert.reason}")
        if not alerts:
            st.success("No configured detection rules matched the supplied local telemetry.")
        for incident in incidents:
            sources = ", ".join(sorted(x for x in incident["sources"] if x))
            st.markdown(f'**{incident["incident_id"]}** • {incident["severity"]} • {len(incident["alerts"])} correlated alert(s) • Sources: {sources}')

st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="panel"><div class="pt">Local SOC Capability Center</div>', unsafe_allow_html=True)
st.caption("Optional capabilities remain local-first and require explicit configuration or analyst approval.")
cap1, cap2, cap3 = st.columns(3)
with cap1:
    st.write("**Windows Event Logs**")
    st.write("Available:" , "YES" if windows_events_available() else "NO (non-Windows)")
    st.write("Native Security/Application/System collection is available on Windows.")
with cap2:
    st.write("**Offline Threat Intel**")
    ti = ThreatIntelCache()
    ti_ip = st.text_input("Lookup local IOC IP", value="", key="ti_ip")
    if st.button("Lookup IOC", key="ti_lookup"):
        try:
            st.json(ti.lookup_ip(ti_ip))
        except ValueError as exc:
            st.error(f"Invalid IP: {exc}")
with cap3:
    st.write("**Local AI / Analyst Guidance**")
    ai_text = st.text_area("Alert context", value="Explain this security alert defensively.", key="ai_context")
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
buffer = EventBuffer()
buffer.add({"source":"dashboard","timestamp":datetime.now(timezone.utc).isoformat()})
st.metric("Local buffer capacity", 50000)
st.caption("Bounded in-memory buffering prevents unbounded ingestion growth.")

st.markdown('</div>', unsafe_allow_html=True)

st.caption(f"Last action: {st.session_state.last_action}  •  Reports: {st.session_state.incident_exports}  •  NETWORK DISCONNECTED  •  TELEMETRY LOCAL")
