"""Offline source-level smoke tests for Vanguard-SIEM.

These checks intentionally use only the Python standard library so they can run
before Streamlit/Pandas installation and in an air-gapped validation environment.
"""
import ast
from pathlib import Path


SOURCE_PATH = Path(__file__).with_name("app.py")
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")
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
    "Log Ingestion Center",
    "st.file_uploader",
    "Analyze Uploaded Log",
)


def demo_event_count() -> int:
    tree = ast.parse(SOURCE, filename=str(SOURCE_PATH))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "MOCK_LOGS":
                    if not isinstance(node.value, (ast.List, ast.Tuple)):
                        raise AssertionError("MOCK_LOGS must be a list or tuple")
                    return len(node.value.elts)
    raise AssertionError("MOCK_LOGS definition not found")


def main() -> None:
    assert demo_event_count() == 8, "Expected exactly 8 embedded demo events"
    tree = ast.parse(SOURCE, filename=str(SOURCE_PATH))
    event_keys = severity_keys = 0
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "MOCK_LOGS":
                    for item in node.value.elts:
                        if isinstance(item, ast.Dict):
                            keys = {k.value for k in item.keys if isinstance(k, ast.Constant)}
                            event_keys += "event_id" in keys
                            severity_keys += "severity" in keys
    assert event_keys == 8, "Every embedded event must have an event_id"
    assert severity_keys == 8, "Every embedded event must have severity"
    for marker in REQUIRED:
        assert marker in SOURCE, f"Missing required application marker: {marker}"
    assert "requests" not in SOURCE and "urllib.request" not in SOURCE, "Unexpected outbound HTTP client"
    assert "http://" not in SOURCE and "https://" not in SOURCE, "Unexpected runtime URL dependency"
    assert "subprocess" not in SOURCE and "os.system" not in SOURCE, "Unexpected command execution"
    assert "MAX_RECORDS" in SOURCE and "ALLOWED_UPLOAD_TYPES" in SOURCE, "Missing bounded ingestion controls"
    assert SOURCE.index("st.set_page_config") < SOURCE.index("st.markdown(CSS"), "Page configuration must precede UI rendering"
    print("Vanguard-SIEM offline source smoke test: PASS")


if __name__ == "__main__":
    main()
