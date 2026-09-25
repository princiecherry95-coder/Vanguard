# Contributing to Vanguard-SIEM

## Change discipline

1. Read AGENTS.md.
2. Keep commits small and reviewable.
3. Do not add real security telemetry, credentials, or secrets.
4. Add or update regression tests for behavior changes.
5. Run the local test suite before opening a pull request.
6. Verify the application remains offline-first.
7. Document changes to detection behavior, evidence handling, or response controls.

## Validation

Recommended checks:

python -m pytest -q
python smoke_test.py
python runtime_smoke_test.py
python -m py_compile app.py engine.py ingestion.py audit.py soc_pipeline.py

For security-sensitive changes also run Ruff, Bandit and pip-audit.

## Detection changes

Every new detection should document rule ID/version, trigger condition, severity, confidence, relevant evidence, false-positive considerations, analyst guidance, and a regression fixture.
