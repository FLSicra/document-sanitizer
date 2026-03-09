import bisect
import json
from collections import defaultdict
from pathlib import Path
from sanitizers.base import (
    Detection, SanitizeResult, Sanitizer, dedup_detections,
    extract_company_roots, find_company_root_hits,
    replace_detections_in_text,
)
from detectors.engine import analyze_text


def _build_line_offsets(text: str) -> list[int]:
    """Return sorted list of char offsets where each newline occurs."""
    offsets = []
    idx = -1
    while True:
        idx = text.find("\n", idx + 1)
        if idx == -1:
            break
        offsets.append(idx)
    return offsets


def _line_number(offsets: list[int], pos: int) -> int:
    """Convert a character offset to a 1-based line number using bisect."""
    return bisect.bisect_right(offsets, pos - 1) + 1


class TextSanitizer(Sanitizer):
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
        progress_callback=None,
    ) -> list[Detection]:
        from utils.streaming import is_large_file, stream_detect_text
        if is_large_file(self.path):
            return stream_detect_text(self.path, custom_terms, enabled_entities,
                                      progress_callback=progress_callback)

        text = self.path.read_text(encoding="utf-8", errors="replace")
        results = analyze_text(text, custom_terms, enabled_entities,
                               progress_callback=progress_callback)
        line_offsets = _build_line_offsets(text)
        detections = []
        for r in results:
            detections.append(Detection(
                entity_type=r.entity_type,
                original_value=text[r.start:r.end],
                start=r.start,
                end=r.end,
                score=r.score,
                page_or_line=f"line {_line_number(line_offsets, r.start)}",
            ))
        detections = dedup_detections(detections)
        roots = extract_company_roots(detections)
        if roots:
            extra = find_company_root_hits(text, roots, "")
            for d in extra:
                d.page_or_line = f"line {_line_number(line_offsets, d.start)}"
            detections = dedup_detections(detections + extra)
        return detections

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        try:
            from utils.streaming import is_large_file, stream_sanitize_text
            if is_large_file(self.path):
                stream_sanitize_text(self.path, detections, output_path, session)
                return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)

            text = self.path.read_text(encoding="utf-8", errors="replace")
            if session is not None:
                session.initialize_from_content([text])
            text = replace_detections_in_text(text, detections, session)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(text, encoding="utf-8")
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))


_MAX_DEPTH = 200


def _walk_strings(obj, path="", _depth=0):
    """Recursively yield (json_path, string_value) for all string leaves."""
    if _depth > _MAX_DEPTH:
        return
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else k, _depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]", _depth + 1)


def _replace_in_value(value: str, detections: list[Detection], session) -> str:
    """Thin wrapper around the shared replacement helper."""
    return replace_detections_in_text(value, detections, session)


class JsonSanitizer(Sanitizer):
    """Parses JSON, analyzes string values, re-serializes sanitized output."""

    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
        progress_callback=None,
    ) -> list[Detection]:
        from utils.streaming import is_large_file
        if is_large_file(self.path):
            return TextSanitizer(self.path).detect(custom_terms, enabled_entities,
                                                   progress_callback=progress_callback)

        text = self.path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return TextSanitizer(self.path).detect(custom_terms, enabled_entities,
                                                   progress_callback=progress_callback)

        strings = list(_walk_strings(data))
        if not strings:
            return []

        # Concatenate all string values with newline separators and analyze
        # in a single pass.  This avoids calling analyze_text() per-string
        # which is extremely slow for files with many values.
        parts = []
        string_ranges = []  # (json_path, global_start, global_end)
        offset = 0
        for json_path, value in strings:
            start = offset
            end = start + len(value)
            string_ranges.append((json_path, start, end))
            parts.append(value)
            offset = end + 1  # +1 for \n separator

        full_text = "\n".join(parts)
        results = analyze_text(full_text, custom_terms, enabled_entities,
                               progress_callback=progress_callback)

        # Map results back to individual string values using binary search
        range_starts = [s for _, s, _ in string_ranges]
        detections = []
        for r in results:
            idx = bisect.bisect_right(range_starts, r.start) - 1
            if idx < 0:
                continue
            json_path, str_start, str_end = string_ranges[idx]
            if r.end > str_end:
                continue  # spans across separator boundary, skip
            detections.append(Detection(
                entity_type=r.entity_type,
                original_value=full_text[r.start:r.end],
                start=r.start - str_start,
                end=r.end - str_start,
                score=r.score,
                page_or_line=json_path,
            ))

        detections = dedup_detections(detections)
        roots = extract_company_roots(detections)
        if roots:
            extra = []
            for json_path, value in strings:
                extra.extend(find_company_root_hits(value, roots, json_path))
            detections = dedup_detections(detections + extra)
        return detections

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        try:
            from utils.streaming import is_large_file
            if is_large_file(self.path):
                return TextSanitizer(self.path).sanitize(detections, output_path, session)

            text = self.path.read_text(encoding="utf-8", errors="replace")
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return TextSanitizer(self.path).sanitize(detections, output_path, session)

            if session is not None:
                session.initialize_from_content(
                    [v for _, v in _walk_strings(data)]
                )
            det_map: dict[str, list[Detection]] = defaultdict(list)
            for d in detections:
                if d.redact:
                    det_map[d.page_or_line].append(d)

            def replace_in_obj(obj, path="", _depth=0):
                if _depth > _MAX_DEPTH:
                    return obj
                if isinstance(obj, str):
                    dets = det_map.get(path, [])
                    return _replace_in_value(obj, dets, session) if dets else obj
                elif isinstance(obj, dict):
                    return {k: replace_in_obj(v, f"{path}.{k}" if path else k, _depth + 1)
                            for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [replace_in_obj(v, f"{path}[{i}]", _depth + 1) for i, v in enumerate(obj)]
                return obj

            sanitized = replace_in_obj(data)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(sanitized, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))
