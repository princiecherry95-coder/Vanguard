"""Audited report-download service for Vanguard-SIEM."""
from __future__ import annotations

from pathlib import Path

from audit import audit_event
from evidence_store import EvidenceStore


def record_export_download(
    store: EvidenceStore,
    evidence_sha256: str | None,
    analysis_run_id: int | None,
    format_name: str,
    filename: str,
    data: bytes,
) -> int:
    """Persist and audit a completed report download."""
    export_id = store.record_export_event(
        evidence_sha256=evidence_sha256,
        format_name=format_name,
        filename=Path(filename).name,
        data=data,
        analysis_run_id=analysis_run_id,
        source="REPORT_CENTER_DOWNLOAD",
    )
    audit_event(
        "REPORT_EXPORT",
        f"{str(format_name).upper()}:{Path(filename).name}",
        evidence_sha256 or "",
    )
    return export_id
