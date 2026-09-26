# Vanguard-SIEM V2 Engineering Roadmap

## Delivered in this upgrade
- Repository hygiene baseline and dependency pinning.
- Versioned detection metadata with confidence, category, MITRE mapping and analyst guidance.
- Alert-fatigue reduction through evidence-preserving finding grouping.
- Local SQLite evidence/finding metadata store.
- Stronger append-only audit integrity with hash chaining.
- Analyst-centric workspace terminology.
- CI security, lint and reproducibility gates.
- Performance and parser regression coverage.

## Architecture target

RAW EVIDENCE → VALIDATION → NORMALIZATION → DETECTION → FINDINGS → GROUPING → CORRELATION → INCIDENTS → RESPONSE → AUDIT.

## Analyst workspaces

COMMAND → TRIAGE → INVESTIGATE → EVIDENCE → DETECTIONS → RESPONSE → AUDIT → SYSTEM HEALTH.

## Acceptance gates
1. All deterministic regression tests pass.
2. Security/lint checks pass.
3. Streamlit runtime health passes.
4. Full-evidence fixture analysis retains 100% record coverage.
5. No runtime external network dependency.
6. Audit-chain verification passes.
7. Repository contains no committed local virtual environment in the current tree.


## Enterprise capability expansion
- Offline enterprise-security registry for cases, IOCs, vulnerabilities, UEBA, compliance mappings and approval-gated playbook requests.
- Explicit capability catalog prevents the UI from presenting future integrations as installed functionality.
- Full platform specification: `docs/FULL_PLATFORM_SPEC.md`.

## Next integration boundaries
- STIX 2.1 / TAXII 2.1 exchange
- Sigma / YARA rule-pack import
- Graph investigation workspace
- Scale-out FastAPI/OpenSearch/Redis/event-streaming architecture when deployment volume requires it.
