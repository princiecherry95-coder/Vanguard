# Vanguard Intelligence Expansion

This roadmap defines a modular intelligence-fusion layer for CTI, OSINT, telemetry enrichment, investigations and evidence-backed analysis. The existing offline-first SIEM remains the core.

## Technology families

- STIX 2.1 / TAXII 2.1
- MITRE ATT&CK / CAPEC
- MISP / OpenCTI-compatible exchange
- Sigma / YARA result ingestion
- Zeek / Suricata telemetry
- Sysmon / osquery / Windows and Linux event telemetry
- CVE / CWE / CPE / CVSS and vendor advisories
- DNS / RDAP / certificate-transparency / passive-DNS intelligence
- Case-management and approval-gated response integrations
- Local RAG/LLM over verified evidence

## Architecture

COLLECT -> VALIDATE -> NORMALIZE -> PROVENANCE -> CORRELATE -> ENRICH -> GRAPH -> RISK -> INVESTIGATE -> APPROVE -> AUDIT

External intelligence must remain distinguishable from locally observed evidence. Every intelligence object should preserve source, observation time, confidence, reliability, provenance, expiry and analyst verification state.

Collectors should be passive and authorized. No exploitation, credential attacks or unauthorized scanning are part of the platform.

## Implementation phases

1. Intelligence data model and provenance
2. ATT&CK/STIX/TAXII ingestion and export
3. IOC extraction and correlation
4. Vulnerability and asset enrichment
5. OSINT passive-source adapters
6. Network and endpoint telemetry adapters
7. Graph-based investigation workspace
8. Intelligence requirements and case management
9. Evidence-linked local AI/RAG
10. Continuous CI, security testing and deployment verification
