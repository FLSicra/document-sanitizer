"""Append-only audit log for sanitization operations."""
from __future__ import annotations
import datetime
import json
from collections import Counter
from pathlib import Path

_LOG_PATH = Path.home() / ".document_sanitizer" / "audit.jsonl"


def log_sanitization(source_path, output_path, detections: list) -> None:
    """Append one JSON-Lines record for a completed sanitization."""
    redacted = [d for d in detections if d.redact]
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": str(source_path),
        "output": str(output_path),
        "redacted_count": len(redacted),
        "entity_types": dict(Counter(d.entity_type for d in redacted)),
    }
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
