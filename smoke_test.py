"""Offline source smoke tests for Vanguard-SIEM."""
import ast
from pathlib import Path

SOURCE_PATH = Path(__file__).with_name("app.py")
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")

REQUIRED = (
    "VANGUARD-SIEM // SOC INTELLIGENCE CENTER",
    "Status: SECURED • AIR-GAPPED • OFFLINE • EVIDENCE PROCESSING ONLINE",
    'st.toggle("⚡ Demo Mode"',
    '"Total Log Entries"',
    '"Critical Anomalies"',
    '"High / Warning Alerts"',
    '"Quarantined Hosts"',
    "Live Security Log Stream",
    "Tactical Analyst Inspector & Response",
    "Quarantine IP",
    "Export Incident Report",
    "NETWORK DISCONNECTED",
    "Analyst Findings",
    "System Health & Integrity",
    "external_apis",
    "html.escape",
    "st.file_uploader",
    "Analyze Evidence",
    "No separate validation step is required",
    "analyze_bytes_incremental",
)

def demo_event_count() -> int:
    tree = ast.parse(SOURCE, filename=str(SOURCE_PATH))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "MOCK_LOGS":
                    return len(node.value.elts)
    raise AssertionError("MOCK_LOGS definition not found")

def main() -> None:
    assert demo_event_count() == 8
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
    assert event_keys == 8
    assert severity_keys == 8
    for marker in REQUIRED:
        assert marker in SOURCE, f"Missing required application marker: {marker}"
    assert "requests" not in SOURCE and "urllib.request" not in SOURCE
    assert "os.system" not in SOURCE
    assert SOURCE.index("st.set_page_config") < SOURCE.index("st.markdown(CSS")
    print("Vanguard-SIEM offline source smoke test: PASS")

if __name__ == "__main__":
    main()
