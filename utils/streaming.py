from __future__ import annotations
import zipfile
from pathlib import Path
from typing import Callable
from detectors.engine import analyze_text
from sanitizers.base import Detection

DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB per read
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
WINDOW_OVERLAP = 512  # char overlap between chunks to catch boundary-spanning entities
MAX_DECOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MB zip bomb guard


def is_large_file(path: Path) -> bool:
    return path.stat().st_size > LARGE_FILE_THRESHOLD


def check_zip_bomb(path: Path) -> None:
    """Raise ValueError if a ZIP-based document would decompress to an unsafe size."""
    if not zipfile.is_zipfile(str(path)):
        return
    total = 0
    with zipfile.ZipFile(str(path), 'r') as zf:
        for info in zf.infolist():
            total += info.file_size
            if total > MAX_DECOMPRESSED_SIZE:
                limit_mb = MAX_DECOMPRESSED_SIZE // (1024 * 1024)
                raise ValueError(
                    f"'{path.name}' exceeds the {limit_mb} MB decompressed size "
                    f"limit (possible zip bomb)"
                )


def stream_detect_text(
    path: Path,
    custom_terms: tuple[str, ...] = (),
    enabled_entities: frozenset[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int], None] | None = None,
) -> list[Detection]:
    """
    Detect PII in a large text file without loading it fully into memory.
    Uses a sliding window buffer so entities that straddle chunk boundaries
    are still caught. progress_callback receives 0-100 int values.
    """
    total_size = path.stat().st_size
    chars_read = 0
    detections: list[Detection] = []
    global_offset = 0      # absolute char offset of process_text start
    global_line_base = 0   # newlines seen before the current process_text

    buffer = ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chars_read += len(chunk)
            buffer += chunk

            if len(buffer) > WINDOW_OVERLAP:
                process_text = buffer[:-WINDOW_OVERLAP]
                for r in analyze_text(process_text, custom_terms, enabled_entities):
                    abs_start = global_offset + r.start
                    line_num = global_line_base + process_text[:r.start].count("\n") + 1
                    detections.append(Detection(
                        entity_type=r.entity_type,
                        original_value=process_text[r.start:r.end],
                        start=abs_start,
                        end=abs_start + (r.end - r.start),
                        score=r.score,
                        page_or_line=f"line {line_num}",
                    ))
                global_line_base += process_text.count("\n")
                global_offset += len(process_text)
                buffer = buffer[-WINDOW_OVERLAP:]

            if progress_callback and total_size > 0:
                # chars_read approximates bytes for ASCII-heavy UTF-8 content;
                # for multi-byte text the bar may advance slightly faster, which
                # is acceptable for a progress indicator.
                progress_callback(min(99, int(chars_read * 100 / total_size)))

        # Flush remaining buffer
        if buffer:
            for r in analyze_text(buffer, custom_terms, enabled_entities):
                abs_start = global_offset + r.start
                line_num = global_line_base + buffer[:r.start].count("\n") + 1
                detections.append(Detection(
                    entity_type=r.entity_type,
                    original_value=buffer[r.start:r.end],
                    start=abs_start,
                    end=abs_start + (r.end - r.start),
                    score=r.score,
                    page_or_line=f"line {line_num}",
                ))

    if progress_callback:
        progress_callback(100)

    return _deduplicate(detections)


def stream_sanitize_text(
    path: Path,
    detections: list[Detection],
    output_path: Path,
    session,
) -> None:
    """
    Write a sanitized copy of a large text file without loading it fully into memory.
    Reads the source sequentially, replacing detected spans with vault tokens as they
    are encountered. Uses O(detections) memory rather than O(file size).
    """
    to_redact = [d for d in detections if d.redact]
    to_redact.sort(key=lambda d: d.start)

    # Assign tokens before opening files so vault is populated even on error
    for d in to_redact:
        d.token = session.get_or_create_token(d) if session else "[REDACTED]"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    READ_SIZE = 1024 * 1024  # 1 MB read chunks for the tail

    with path.open("r", encoding="utf-8", errors="replace") as fin, \
         output_path.open("w", encoding="utf-8") as fout:
        pos = 0  # current char position in source file
        for d in to_redact:
            if d.start < pos:
                continue  # skip overlapping detections (dedup should prevent this)
            gap = d.start - pos
            if gap > 0:
                fout.write(fin.read(gap))
            fin.read(d.end - d.start)   # discard original span
            fout.write(d.token)
            pos = d.end
        # Write remainder in chunks
        while True:
            chunk = fin.read(READ_SIZE)
            if not chunk:
                break
            fout.write(chunk)


def _deduplicate(detections: list[Detection]) -> list[Detection]:
    """Remove overlapping detections, keeping the higher-score one."""
    detections.sort(key=lambda d: (d.start, -d.score))
    result: list[Detection] = []
    last_end = -1
    for d in detections:
        if d.start >= last_end:
            result.append(d)
            last_end = d.end
    return result


def sample_detections(
    detections: list[Detection],
    max_per_entity: int = 20,
) -> tuple[list[Detection], bool]:
    """
    Return a sampled subset for large-file preview.
    Returns (sampled_detections, was_truncated).
    """
    from collections import defaultdict
    by_entity: dict[str, list[Detection]] = defaultdict(list)
    for d in detections:
        by_entity[d.entity_type].append(d)

    sampled = []
    truncated = False
    for entity, items in by_entity.items():
        if len(items) > max_per_entity:
            truncated = True
            sampled.extend(items[:max_per_entity])
        else:
            sampled.extend(items)
    return sampled, truncated
