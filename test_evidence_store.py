"""Regression tests for local evidence metadata persistence."""
from pathlib import Path
import tempfile

from evidence_store import EvidenceStore


def test_evidence_store_persists_findings_once():
    with tempfile.TemporaryDirectory() as directory:
        store = EvidenceStore(Path(directory) / "evidence.db")
        bundle = {
            "sha256": "a" * 64,
            "filename": "sample.jsonl",
            "format": "JSONL",
            "records": 2,
            "completed_at": "2026-09-25T00:00:00+00:00",
            "analysis": {},
        }
        finding = {
            "alert_id": "FND-000001",
            "rule_id": "SQL_INJECTION",
            "rule_version": "1.0",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "first_seen": "2026-09-25T00:00:00+00:00",
            "last_seen": "2026-09-25T00:00:01+00:00",
            "count": 2,
            "sources": ["10.0.0.1"],
            "destinations": ["10.0.0.2"],
            "mitre_technique": "T1190",
            "reason": "matched",
        }
        store.save_analysis(bundle, [finding])
        store.save_analysis(bundle, [finding])
        summary = store.summary(bundle["sha256"])
        assert summary["finding_groups"] == 1
        assert summary["finding_occurrences"] == 2


if __name__ == "__main__":
    test_evidence_store_persists_findings_once()
    print("Vanguard-SIEM evidence-store regression suite: PASS")
