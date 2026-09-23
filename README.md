# Vanguard-SIEM

**Tactical AI-Augmented Log Intelligence Console** — a standalone Streamlit MVP for an isolated, air-gapped hackathon environment.

## Features
- Dark enterprise SOC-style single-page console
- Offline embedded demo telemetry
- Pandas-backed log manipulation and filtering
- Critical / warning / low severity indicators
- Tactical event inspector with raw payload and plain-language defensive translation
- Session-state IP quarantine simulation
- JSON incident-report export
- Local evidence workflow: **UPLOAD → ANALYZE → COMPLETE**
- SHA-256 evidence integrity verification
- No CDN, remote API, telemetry, or live-internet runtime dependency

## Run locally on macOS

Use **Python 3.11** for the supported, repeatable local environment.

```bash
git clone https://github.com/princiecherry95-coder/Vanguard.git
cd Vanguard
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python smoke_test.py
python test_engine.py
python test_ingestion.py
python test_pipeline.py
python test_audit.py
python test_security.py
python runtime_smoke_test.py

streamlit run app.py
```

Open the local address shown by Streamlit, normally `http://localhost:8501`.

### macOS notes
- Core analysis is platform-neutral.
- Windows Event Log collection is detected at runtime and disabled on macOS.
- Firewall enforcement is Windows-only; non-Windows returns `UNSUPPORTED_PLATFORM` safely.
- Local AI is disabled by default and does not require Internet access.
- Evidence processing, hashing, parsing, detection, correlation and audit writing remain local.

## Air-gapped installation
Place approved Python wheels in a local `wheelhouse/` directory and install:
```bash
python -m pip install --no-index --find-links ./wheelhouse -r requirements.txt
```

## Security boundary
Quarantine actions require explicit analyst approval. Windows firewall changes are platform-gated; non-Windows systems do not execute Windows firewall commands. Incident reports are generated locally.

## CI
CI tests Ubuntu, macOS and Windows with Python 3.11. The runtime smoke test imports the runtime modules, performs deterministic local analysis, starts Streamlit and checks its local health endpoint.

## Repository
`princiecherry95-coder/Vanguard`
