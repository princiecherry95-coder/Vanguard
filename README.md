# Vanguard-SIEM

**Offline-first SOC Log Intelligence & Threat Detection Platform** for controlled defensive analytics.

Vanguard is designed for isolated environments where security telemetry must be ingested, normalized, detected, correlated and investigated locally without cloud runtime dependencies.

## Current architecture

RAW EVIDENCE → VALIDATION → NORMALIZATION → DETECTION → FINDINGS → GROUPING → CORRELATION → INCIDENTS → RESPONSE → AUDIT

### Analyst workspaces

COMMAND → TRIAGE → INVESTIGATE → EVIDENCE → DETECTIONS → RESPONSE → AUDIT → SYSTEM HEALTH

## SOC Analytics & Report Center

- Offline analytics: severity distribution, top attack types, top sources, hourly trends, unique-source/target metrics.
- Locally generated PDF, Word, Excel, PowerPoint and JSON reports from the analyzed evidence set.
- Report exports are audit-recorded and never require network access.
- Local tail-file and UDP syslog collectors for controlled continuous ingestion.
- Cross-platform local firewall adapter with explicit approval and platform capability reporting.

## Core capabilities

- Heterogeneous local log ingestion: text/syslog, CSV, JSON, JSONL and XML.
- Suricata EVE JSON normalization and deterministic signature detection.
- Authentication, web attack, privilege, scanning and behavioral detections.
- Versioned detection metadata with severity, confidence, category, MITRE ATT&CK mapping and analyst guidance.
- Evidence-preserving finding grouping to reduce alert fatigue.
- Full evidence analysis with bounded UI pagination.
- Local SQLite evidence/finding metadata store.
- SHA-256 evidence provenance.
- Append-only hash-chained audit records with verification.
- Human-approved response and Windows firewall controls.
- Optional local-only AI adapter; no Internet AI dependency.
- Offline local threat-intelligence cache.
- Cross-platform CI, pytest, Ruff, Bandit, dependency audit and CodeQL.

## Security model

- No cloud LLM or live external threat-intelligence dependency at runtime.
- Uploaded content is treated as untrusted data and is never executed.
- Credentials, bearer tokens and API-key-like values are redacted before display/audit storage.
- Disruptive response requires explicit analyst approval.
- Raw evidence is not published in the repository; test fixtures should be synthetic or sanitized.
- Local audit integrity is verified using a previous-record hash chain.

## Local setup

Use Python 3.11–3.14.

### Windows

~~~text
py -3.14 -m venv .venv
.venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
~~~

### macOS/Linux

~~~text
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
~~~

## Verification

~~~text
python -m pytest -q
python smoke_test.py
python runtime_smoke_test.py
~~~

For a production-style security check:

~~~text
python -m ruff check .
python -m bandit -q -r engine.py ingestion.py audit.py evidence_store.py detection_registry.py risk.py triage.py soc_pipeline.py -lll
python -m pip_audit -r requirements.txt
~~~

## Offline installation

Place approved wheels in a controlled local wheelhouse:

~~~text
python -m pip install --no-index --find-links ./wheelhouse -r requirements.txt
~~~

## Repository hygiene

Local virtual environments, raw evidence, audit databases and runtime caches are intentionally ignored by Git. The repository contains source, sanitized fixtures, tests, documentation and deployment configuration.

## Version

Current architecture baseline: **0.4.0**

## Enterprise security capability layer

Vanguard now exposes an explicit capability catalog and an offline SQLite enterprise-security registry covering cases, IOCs, vulnerabilities, UEBA observations, compliance evidence mappings and approval-required SOAR playbook runs. Implemented, integration-boundary and planned capabilities are deliberately separated so the UI and documentation do not claim unavailable integrations.

See [docs/FULL_PLATFORM_SPEC.md](docs/FULL_PLATFORM_SPEC.md) for the complete platform specification.
