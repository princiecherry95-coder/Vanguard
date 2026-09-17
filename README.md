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
- No CDN, remote API, telemetry, or live-internet runtime dependency

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

For a fully air-gapped deployment, place the required Python wheels in a local `wheelhouse/` directory on an authorized connected staging machine and install with:

```bash
pip install --no-index --find-links ./wheelhouse -r requirements.txt
```

Then run Streamlit on the isolated network.

## Security boundary

The **Quarantine IP** action is deliberately a local session-state simulation. It does **not** modify host firewalls, routing, DNS, network controls, or external infrastructure. Incident reports are generated locally and contain no external API calls.

## Repository

`princiecherry95-coder/Vanguard`
