"""Offline source-level smoke tests for Vanguard-SIEM.

These checks intentionally use only the Python standard library so they can run
before Streamlit/Pandas installation and in an air-gapped validation environment.
"""
from pathlib import Path


SOURCE = Path(__file__).with_name("app.py").read_text(encoding="utf-8")
REQUIRED = (
    "VANGUARD-SIEM // Tactical Operations Console",
    "Status: SECURED (Air-Gapped Local Net)",
    'st.toggle("⚡ Demo Mode"',
    '"Total Log Entries"',
    '"Critical Anomalies"',
    '"Warnings Flagged"',
    '"Quarantined Hosts"',
    "Live Security Log Stream",
    "Tactical AI Inspector & Playbook",
    "Quarantine IP",
    "Export Incident Report",
    "NETWORK DISCONNECTED",
    "external_apis",
    "html.escape",
)


def main() -> None:
    assert SOURCE.count('"event_id"') == 8, "Expected exactly 8 embedded demo events"
    assert SOURCE.count('"severity"') == 8, "Expected severity data for all 8 demo events"
    for marker in REQUIRED:
        assert marker in SOURCE, f"Missing required application marker: {marker}"
    assert "requests" not in SOURCE and "urllib.request" not in SOURCE, "Unexpected outbound HTTP client"
    assert "http://" not in SOURCE and "https://" not in SOURCE, "Unexpected runtime URL dependency"
    assert "subprocess" not in SOURCE and "os.system" not in SOURCE, "Unexpected command execution"
    assert SOURCE.index("st.set_page_config") < SOURCE.index("st.markdown(CSS"), "Page configuration must precede UI rendering"
    print("Vanguard-SIEM offline source smoke test: PASS")


if __name__ == "__main__":
    main()
