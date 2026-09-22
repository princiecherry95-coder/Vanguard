"""Secure local log-ingestion helpers for Vanguard-SIEM.

No uploaded content is executed and no network access is performed.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 50_000
ALLOWED_UPLOAD_TYPES = {"txt", "log", "csv", "json", "jsonl", "xml"}


def safe_uploaded_text(data: bytes, filename: str) -> tuple[str, str]:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Upload content must be bytes.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 10 MB safety limit.")
    name = filename or "uploaded.log"
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else "txt"
    if suffix not in ALLOWED_UPLOAD_TYPES:
        raise ValueError(f"Unsupported log format: .{suffix}")
    # Reject actual NUL bytes. The previous check only matched the four-byte
    # text sequence "\\x00", which did not detect binary NUL data.
    if b"\x00" in data:
        raise ValueError("Binary content detected. Upload a text log export, CSV, JSON, JSONL or XML file.")
    digest = hashlib.sha256(data).hexdigest()
    return bytes(data).decode("utf-8-sig", errors="replace")[:MAX_RECORDS * 1024], digest


def lines_from_upload(text: str, fmt: str) -> list[str]:
    fmt = fmt.upper()
    if fmt == "JSONL":
        return [line for line in text.splitlines() if line.strip()]
    if fmt == "JSON":
        parsed = json.loads(text)
        source = parsed if isinstance(parsed, list) else [parsed]
        return [json.dumps(item, ensure_ascii=False) for item in source]
    if fmt == "CSV":
        return [json.dumps(row, ensure_ascii=False) for row in csv.DictReader(io.StringIO(text))]
    return [line for line in text.splitlines() if line.strip()]
