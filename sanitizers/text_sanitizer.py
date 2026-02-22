import json
from collections import defaultdict
from pathlib import Path
from sanitizers.base import (
    Detection, SanitizeResult, Sanitizer, dedup_detections,
    extract_company_roots, find_company_root_hits,
)
from detectors.engine import analyze_text


class TextSanitizer(Sanitizer):
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
    ) -> list[Detection]:
        from utils.streaming import is_large_file, stream_detect_text
        if is_large_file(self.path):
            return stream_detect_text(self.path, custom_terms, enabled_entities)

        text = self.path.read_text(encoding="utf-8", errors="replace")
        results = analyze_text(text, custom_terms, enabled_entities)
        detections = []
        for r in results:
            line_num = text[:r.start].count("\n") + 1
            detections.append(Detection(
                entity_type=r.entity_type,
                original_value=text[r.start:r.end],
                start=r.start,
                end=r.end,
                score=r.score,
                page_or_line=f"line {line_num}",
            ))
        detections = dedup_detections(detections)
        roots = extract_company_roots(detections)
        if roots:
            # Text is one big context — use a single "doc" key for grouping
            extra = find_company_root_hits(text, roots, "")
            # Assign correct line numbers and page_or_line
            for d in extra:
                d.page_or_line = f"line {text[:d.start].count(chr(10)) + 1}"
            detections = dedup_detections(detections + extra)
        return detections

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        try:
            from utils.streaming import is_large_file, stream_sanitize_text
            if is_large_file(self.path):
                stream_sanitize_text(self.path, detections, output_path, session)
                return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)

            text = self.path.read_text(encoding="utf-8", errors="replace")
            to_redact = [d for d in detections if d.redact]
            to_redact.sort(key=lambda d: d.start, reverse=True)
            for d in to_redact:
                token = session.get_or_create_token(d) if session else "[REDACTED]"
                d.token = token
                text = text[:d.start] + token + text[d.end:]
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(text, encoding="utf-8")
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))


def _walk_strings(obj, path=""):
    """Recursively yield (json_path, string_value) for all string leaves."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def _replace_in_value(value: str, detections: list[Detection], session) -> str:
    to_redact = dedup_detections([d for d in detections if d.redact])
    to_redact.sort(key=lambda d: d.start, reverse=True)
    for d in to_redact:
        token = session.get_or_create_token(d) if session else "[REDACTED]"
        d.token = token
        value = value[:d.start] + token + value[d.end:]
    return value


class JsonSanitizer(Sanitizer):
    """Parses JSON, analyzes each string value individually, re-serializes sanitized output."""

    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
    ) -> list[Detection]:
        from utils.streaming import is_large_file
        if is_large_file(self.path):
            return TextSanitizer(self.path).detect(custom_terms, enabled_entities)

        text = self.path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return TextSanitizer(self.path).detect(custom_terms, enabled_entities)

        detections = []
        for json_path, value in _walk_strings(data):
            results = analyze_text(value, custom_terms, enabled_entities)
            for r in results:
                detections.append(Detection(
                    entity_type=r.entity_type,
                    original_value=value[r.start:r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                    page_or_line=json_path,
                ))

        detections = dedup_detections(detections)
        roots = extract_company_roots(detections)
        if roots:
            extra = []
            for json_path, value in _walk_strings(data):
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

            det_map: dict[str, list[Detection]] = defaultdict(list)
            for d in detections:
                if d.redact:
                    det_map[d.page_or_line].append(d)

            def replace_in_obj(obj, path=""):
                if isinstance(obj, str):
                    dets = det_map.get(path, [])
                    return _replace_in_value(obj, dets, session) if dets else obj
                elif isinstance(obj, dict):
                    return {k: replace_in_obj(v, f"{path}.{k}" if path else k)
                            for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [replace_in_obj(v, f"{path}[{i}]") for i, v in enumerate(obj)]
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
