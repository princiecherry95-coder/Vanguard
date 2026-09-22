# Vanguard-SIEM Project Rules

These rules are the standing engineering, cybersecurity, operational, and verification rules for Vanguard-SIEM. They are part of the repository contract and must be followed for future changes.

## 1. Mission
Vanguard-SIEM is an offline-first SOC log intelligence and defensive threat-detection platform for controlled defense environments. Its purpose is to ingest, validate, normalize, analyze, correlate, and explain security telemetry for human analysts.

## 2. Air-Gapped / Offline-First
- Runtime processing must work without Internet access.
- Do not introduce cloud LLMs, live external threat-intelligence APIs, telemetry uploads, or other external runtime dependencies.
- Detection and parsing logic must be locally executable and deterministic unless a locally hosted model is explicitly introduced and documented.
- Do not add runtime network calls merely to improve the dashboard.

## 3. Log Ingestion
Support heterogeneous local security telemetry, including Syslog, Windows Event Logs, Apache/Nginx, authentication logs, firewall traffic, CSV/JSON/JSONL/XML exports, and controlled simulated streams.
- Validate file type, size, record count, and encoding.
- Never execute uploaded content.
- Handle malformed records without crashing the complete ingestion pipeline.
- Preserve evidence provenance with bounded SHA-256 hashes where appropriate.

## 4. Parsing and Normalization
Extract, when present:
- timestamps
- source and destination IP addresses
- user/account identifiers
- process/PID information
- authentication results
- network/firewall decisions
- web requests and relevant error codes

Malformed or missing fields must not cause the whole event to be discarded.

## 5. Defensive Detection Coverage
The engine should support transparent, explainable detection for:
- single-source brute-force authentication
- distributed brute-force authentication
- unauthorized privilege escalation
- suspicious service-account activity
- suspicious outbound or lateral network patterns
- network scanning/reconnaissance
- SQL injection indicators
- XSS indicators
- path manipulation
- suspicious uploads
- malformed or attack-like web requests

Rules must state their trigger conditions and evidence.

## 6. Behavioral Analysis
Use bounded time windows and explicit thresholds for repeated failures, multi-source authentication activity, scanning, and related behavioral patterns. Thresholds must be documented and covered by regression tests.

## 7. Alert-Fatigue Reduction
Do not simply emit an alert for every matching line.
Use, where applicable:
- thresholds
- deduplication/suppression
- grouping
- temporal correlation
- incident creation
- severity escalation
- concise analyst context

Correlation must preserve the underlying evidence needed for investigation.

## 8. Explainability
Every alert must be explainable to an analyst:
- rule ID
- severity
- trigger condition
- relevant evidence
- time window/threshold where applicable
- concise reason for the alert
- safe analyst guidance where appropriate

Do not present deterministic rule output as machine-learning or generative AI inference unless an actual local model performs the inference.

## 9. Input and Secret Security
- Enforce bounded input sizes and field lengths.
- Sanitize dangerous control characters.
- Redact credentials, bearer tokens, API keys, passwords, and similar secrets before they are displayed or written to logs/audit records.
- Never hard-code real credentials or secrets.
- Do not log raw authentication secrets.
- Treat uploaded logs as untrusted input.

## 10. Evidence Integrity
Use SHA-256 evidence digests where needed to support provenance and integrity without exposing sensitive raw telemetry.

## 11. Analyst Control / Human-in-the-Loop
Analysts remain responsible for operational decisions.
- Inspection and response actions must be explicit.
- Session-state quarantine in the MVP must not be represented as real firewall enforcement.
- No irreversible or disruptive action should occur automatically unless separately engineered, authorized, and clearly documented.

## 12. Auditability
Record security-relevant analyst actions in the local audit trail.
- Audit records must be bounded.
- Audit records must not contain raw secrets.
- Audit records should include integrity hashes.
- The application must not silently rewrite historical audit entries.

## 13. Dashboard / UX
The dashboard must provide:
- clear SOC status and metrics
- severity visibility
- log/event inspection
- alert and incident context
- local ingestion
- local analytics
- evidence/report export where appropriate
- responsive, analyst-oriented UX

UI wording must accurately reflect what the system actually does.

## 14. Code Quality and Repository Integrity
- Prefer small, reviewable, incremental commits.
- Keep business/security logic transparent and locally inspectable.
- Avoid unexplained generated code or opaque security decisions.
- Update documentation when architecture, detection behavior, or security assumptions change.
- Never weaken security controls simply to make a test pass.

## 15. Testing and CI
Changes affecting security, ingestion, parsing, detection, audit, or runtime behavior must include or update regression tests.
The CI pipeline should cover:
- offline source smoke tests
- engine detection tests
- ingestion security tests
- audit security tests
- syntax validation
- Streamlit/browser application health where supported

Use explicit PASS / FAIL / BLOCKED / NOT VERIFIED status in engineering reports. Never claim a test passed unless it was actually run and verified.

## 16. Documentation
Maintain:
- problem statement
- architecture
- threat model
- explainable detection logic
- security assumptions and limitations
- operational verification evidence

## 17. Sensitive Telemetry
Do not publish raw military, security-sensitive, credential-bearing, or personally identifiable telemetry to a public repository unless explicitly authorized.
Prefer sanitized, synthetic, or minimized fixtures for tests and demonstrations.

## 18. Change Verification
For each substantive change:
1. inspect the existing implementation;
2. make the smallest safe change;
3. add/update regression coverage;
4. run applicable tests;
5. inspect the resulting diff/commit;
6. report what is PASS, FAIL, BLOCKED, or NOT VERIFIED.

## 19. Source-of-Truth
The repository source, tests, CI results, and documented architecture are the authoritative engineering record. Do not infer success from an unverified deployment, screenshot, or assumption.

## 20. Future Agent Instruction
Any coding agent or maintainer working on this repository must read this file before modifying Vanguard-SIEM and must preserve these rules unless an explicitly documented project decision supersedes them.
