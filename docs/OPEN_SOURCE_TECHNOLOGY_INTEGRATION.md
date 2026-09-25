# Vanguard-SIEM Open-Source Technology Integration

## Purpose

Vanguard-SIEM remains an offline-first defensive analytics engine. Open-source projects are used as architectural and interoperability references; their code, services, and online threat feeds are not required at runtime.

## Technologies incorporated

### Suricata EVE JSON
Suricata EVE JSON is the native network-security evidence format supported by Vanguard-SIEM. The parser preserves timestamp, flow, source/destination, protocol, alert signature, category, action, severity and HTTP context where present.

### Sigma-style detection engineering
Vanguard's deterministic detection rules follow the same important operational principle as Sigma: detection logic should be readable, portable and explainable. Rules remain local Python rules today, with a planned adapter for importing reviewed Sigma YAML into the local rule engine.

### Wazuh / OpenSearch dashboard patterns
The redesigned SOC workspace borrows proven SIEM UX concepts: alert queues, severity-first triage, investigation context, evidence drill-down, detection visibility and analyst workflow separation. Vanguard does not require Wazuh or OpenSearch to run.

### CloudSOC-Copilot architecture patterns
The open-source CloudSOC-Copilot project demonstrates a useful separation of parser routing, normalized events, detection, risk, correlation, MITRE context, incident evidence and Streamlit analyst views. Vanguard adopts these architectural boundaries while keeping its own offline deterministic engine and security controls.

## UX decisions

- Command view prioritizes evidence state, risk, alert severity and analyst action.
- Evidence displays are bounded and paginated; the complete evidence set is not truncated by the UI.
- Raw evidence remains available through the selected event rather than forcing the browser to render hundreds of thousands of rows simultaneously.
- Response actions remain human-approved.
- Audit context is kept local and append-only.
- No cloud AI, cloud threat intelligence or external runtime dependency is introduced.

## Complete-evidence requirement

A 5,000-record chunk is a processing/update interval, not an analysis limit.

The incremental pipeline now streams records from the uploaded byte buffer for text/JSONL/CSV evidence, processes every record, retains the complete normalized event set for correlation and final analysis, and sends only a bounded preview to the UI.

For a 114,274-record Suricata JSONL evidence set, successful completion must report:

- Records: 114,274
- Parsed events: 114,274
- Dashboard source: the complete evidence set
- UI preview: bounded/paginated only
- Evidence SHA-256: calculated over the complete upload

Any discrepancy between uploaded record count and analyzed record count is a failure, not a successful partial analysis.
