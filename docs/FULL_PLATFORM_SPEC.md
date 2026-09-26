# Vanguard — Full SOC/DFIR Platform Specification

## Mission
Vanguard is an offline-first defensive security platform for controlled environments. It ingests authorized telemetry, preserves evidence, detects suspicious activity, correlates findings, supports investigations and produces auditable reports.

## Capability domains
1. **SIEM / telemetry:** text/syslog, CSV, JSON, JSONL, XML, Suricata, Windows events, local collectors, normalization, bounded ingestion and telemetry-health monitoring.
2. **Detection engineering:** versioned deterministic rules, severity/confidence, MITRE ATT&CK mapping, analyst guidance, alert grouping and future Sigma/YARA rule-pack adapters.
3. **Threat intelligence:** local IP/domain/hash cache, IOC provenance, confidence, expiry and future STIX/TAXII/MISP/OpenCTI exchange adapters.
4. **Asset & identity intelligence:** hosts, users, identities, ownership, criticality, state, last-seen and telemetry health.
5. **UEBA:** entity-linked anomaly observations, scores, evidence references and investigation context.
6. **Incident response / DFIR:** cases, evidence hashes, timelines, analyst notes, IOC extraction, chain of custody and report generation.
7. **SOAR:** playbook definitions and execution requests. Any disruptive action requires explicit authorization and must be audit-recorded.
8. **Vulnerability management:** asset-linked CVE/CVSS records, remediation state, due dates and evidence.
9. **AI security center:** local/evidence-grounded analyst assistance, RAG over approved material, source-linked answers and human approval for actions. AI must never fabricate evidence.
10. **Reporting:** PDF, Word, Excel, PowerPoint and JSON; exports preserve the complete analyzed dataset and are locally generated.
11. **Compliance:** evidence-linked controls for configurable frameworks such as NIST CSF, NIST 800-53, CIS Controls, ISO 27001 and PCI DSS.
12. **Observability:** ingestion health, parser failures, processing delay, runtime health, audit verification and bounded resource metrics.
13. **Security engineering:** least privilege, secure input handling, upload isolation, secrets hygiene, audit integrity, dependency/SAST/security scanning and CI gates.
14. **Graph investigations:** relationship model for events, entities, IOCs, assets, identities and cases; graph UI remains a future integration.
15. **Exchange integrations:** STIX/TAXII, MISP/OpenCTI, Sigma/YARA, vulnerability feeds and authorized ticket/notification systems are adapter boundaries, not mandatory runtime dependencies.

## Technology baseline
- Python 3.12
- Streamlit for the local analyst UI
- SQLite for offline metadata and evidence indexes
- ReportLab / python-docx / openpyxl / python-pptx for local reporting
- SHA-256 and append-only audit hash chains for integrity
- Suricata / Windows event / syslog collector boundaries
- MITRE ATT&CK terminology and mappings
- Optional local AI/RAG
- Future scale-out: FastAPI, PostgreSQL, OpenSearch, Redis, object storage, OpenTelemetry, Prometheus/Grafana and event streaming when deployment scale requires them.

## Data principles
- Local observations and external intelligence remain distinguishable.
- Every imported intelligence object should retain source, observation time, confidence, reliability, provenance and expiry.
- Raw evidence is immutable from the application's perspective after ingestion.
- Evidence exports must not silently truncate records or fields.
- Missing telemetry is represented as unknown/degraded rather than zero.
- All response actions are approval-gated.
- No unauthorized scanning, exploitation or credential attacks are part of Vanguard.

## Delivery gates
- Unit/regression tests
- Full-evidence retention tests
- Export generation tests
- Syntax/ruff/mypy checks
- Bandit and pip-audit
- CodeQL
- Streamlit health smoke test
- Security regression tests
- Manual browser verification for UI releases
