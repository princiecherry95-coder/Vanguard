"""Secure local log-ingestion helpers for Vanguard-SIEM.

No uploaded content is executed and no network access is performed.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json

MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
MAX_RECORDS = 1_000_000
ALLOWED_UPLOAD_TYPES = {"txt", "log", "csv", "json", "jsonl", "xml"}


def validate_upload_size(size: int) -> None:
    if size < 0:
        raise ValueError("Upload size cannot be negative.")
    if size > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 1 GiB safety limit.")


def safe_uploaded_text(data: bytes, filename: str) -> tuple[str, str]:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Upload content must be bytes.")
    validate_upload_size(len(data))
    name = filename or "uploaded.log"
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else "txt"
    if suffix not in ALLOWED_UPLOAD_TYPES:
        raise ValueError(f"Unsupported log format: .{suffix}")
    # Reject actual NUL bytes. The previous check only matched the four-byte
    # text sequence "\\x00", which did not detect binary NUL data.
    if b"\x00" in data:
        raise ValueError("Binary content detected. Upload a text log export, CSV, JSON, JSONL or XML file.")
    digest = hashlib.sha256(data).hexdigest()
    # Decode the complete bounded upload. Record-count enforcement happens after\n    # format-aware record splitting, so valid evidence is never silently truncated.\n    return bytes(data).decode("utf-8-sig", errors="replace"), digest


def infer_upload_format(text: str, filename: str = "") -> str:
    """Infer structured upload format from content, not only the file suffix."""
    stripped = text.lstrip()
    if not stripped:
        return "TEXT"
    try:
        json.loads(text)
        return "JSON"
    except json.JSONDecodeError:
        pass
    non_empty = [line for line in text.splitlines() if line.strip()]
    if non_empty:
        try:
            for line in non_empty:
                json.loads(line)
            return "JSONL"
        except json.JSONDecodeError:
            pass
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"
    return {"csv": "CSV", "jsonl": "JSONL", "json": "JSON", "xml": "XML"}.get(suffix, "TEXT")


def lines_from_upload(text: str, fmt: str) -> list[str]:
    fmt = fmt.upper()
    if fmt == "JSONL":
        return [line for line in text.splitlines() if line.strip()]
    if fmt == "JSON":
        parsed = json.loads(text)
        # Accept common export envelopes while preserving individual events.
        if isinstance(parsed, list):
            source = parsed
        elif isinstance(parsed, dict):
            source = None
            for key in ("events", "logs", "records", "data", "items", "results"):
                candidate = parsed.get(key)
                if isinstance(candidate, list):
                    source = candidate
                    break
            if source is None:
                source = [parsed]
        else:
            source = [parsed]
        return [json.dumps(item, ensure_ascii=False) for item in source]
    if fmt == "CSV":
        return [json.dumps(row, ensure_ascii=False) for row in csv.DictReader(io.StringIO(text))]
    return [line for line in text.splitlines() if line.strip()]
