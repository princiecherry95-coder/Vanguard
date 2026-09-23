# Evidence Validation Workflow

Vanguard-SIEM requires uploaded evidence to pass validation before analysis.

`UPLOAD → VALIDATE → ANALYZE → COMPLETE`

Validation checks file safety, supported format, record count, parser coverage, and per-record SHA-256 fingerprints. Analysis re-hashes the evidence and refuses to proceed if the evidence changed after validation.
