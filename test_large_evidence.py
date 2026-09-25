"""Large-evidence regression: analysis must exceed the legacy 5,000-record boundary."""
from soc_pipeline import analyze_bytes_incremental


def test_analysis_processes_25000_records_without_truncation():
    line = b'{"timestamp":"2026-09-25T10:00:00+00:00","event_type":"alert","src_ip":"10.10.1.7","dest_ip":"10.10.1.8","proto":"TCP","alert":{"action":"allowed","signature":"ET INFO Test Signature","category":"Informational","severity":3}}\n'
    payload = line * 25000
    result = analyze_bytes_incremental(payload, "large-suricata.jsonl", "JSONL", chunk_size=5000)
    assert result["records"] == 25000
    assert result["analysis"]["parse_coverage"] == 100.0
    assert len(result["analysis"]["events"]) == 25000


if __name__ == "__main__":
    test_analysis_processes_25000_records_without_truncation()
    print("Vanguard-SIEM large-evidence regression suite: PASS")
