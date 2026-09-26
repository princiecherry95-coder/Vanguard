"""Authoritative Vanguard capability catalog.

The catalog is deliberately declarative: UI labels and documentation can expose
only capabilities represented here. 'AVAILABLE' means implemented locally;
'INTEGRATION' means an adapter boundary exists but an external product/feed is
not bundled; 'PLANNED' means design-only.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Capability:
    key: str
    name: str
    status: str
    description: str
    technology: str

CAPABILITIES = (
    Capability("siem_ingestion","SIEM evidence ingestion","AVAILABLE","Local text/syslog, CSV, JSON, JSONL and XML ingestion.","Python / Streamlit"),
    Capability("detection_engine","Detection engineering","AVAILABLE","Versioned deterministic detections with severity, confidence and MITRE mappings.","Python / detection registry"),
    Capability("evidence_chain","Evidence integrity","AVAILABLE","SHA-256 evidence provenance and append-only audit verification.","SHA-256 / SQLite"),
    Capability("threat_intel","Offline threat intelligence","AVAILABLE","Local IOC cache for IP, domain and hash intelligence.","SQLite/JSON local cache"),
    Capability("asset_identity","Asset and identity intelligence","AVAILABLE","Local asset, identity and telemetry-health registry.","SQLite"),
    Capability("incident_response","Incident and case management","AVAILABLE","Incident metadata, evidence references and approval-oriented workflow.","SQLite"),
    Capability("approved_response","Response controls","AVAILABLE","Human-approved remediation and local firewall control boundaries.","Python / OS adapters"),
    Capability("reporting","Security reporting","AVAILABLE","PDF, Word, Excel, PowerPoint and JSON exports from analyzed evidence.","ReportLab / python-docx / openpyxl"),
    Capability("network_endpoint","Network and endpoint telemetry","AVAILABLE","Suricata plus local Windows/event and collector boundaries.","Suricata / Windows Events / syslog"),
    Capability("ueba","UEBA observations","AVAILABLE","Persistent bounded anomaly observations linked to entities and evidence.","SQLite"),
    Capability("vulnerability","Vulnerability management","AVAILABLE","CVE/CVSS-style vulnerability records linked to local assets.","SQLite"),
    Capability("soar","SOAR playbook registry","AVAILABLE","Approval-required playbook definitions and run requests; execution remains gated.","SQLite"),
    Capability("compliance","Compliance evidence mapping","AVAILABLE","Framework/control mapping to evidence references.","SQLite"),
    Capability("stix_taxii","STIX/TAXII exchange","INTEGRATION","Reserved adapter boundary for authorized offline/imported intelligence.","STIX 2.1 / TAXII 2.1"),
    Capability("sigma_yara","Sigma/YARA integration","INTEGRATION","Reserved rule ingestion boundary for approved local rule packs.","Sigma / YARA"),
    Capability("graph_investigation","Graph investigation","PLANNED","Relationship graph across events, assets, identities, IOCs and cases.","Graph model"),
    Capability("rag_ai","Evidence-grounded AI/RAG","AVAILABLE","Local analyst guidance with evidence-first context and no mandatory cloud runtime.","Local AI / RAG boundary"),
    Capability("observability","Platform observability","AVAILABLE","Runtime health, telemetry status and bounded local operational metrics.","Python / SQLite"),
)

def capabilities(status: str | None = None) -> tuple[Capability, ...]:
    if status is None:
        return CAPABILITIES
    return tuple(item for item in CAPABILITIES if item.status == status)

def capability_summary() -> dict[str, int]:
    return {status: sum(1 for item in CAPABILITIES if item.status == status)
            for status in ("AVAILABLE","INTEGRATION","PLANNED")}
