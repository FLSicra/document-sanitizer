from pathlib import Path
import fitz  # PyMuPDF
from sanitizers.base import (
    Detection, SanitizeResult, Sanitizer, dedup_detections,
    extract_company_roots, find_company_root_hits,
)
from detectors.engine import analyze_text


class PDFSanitizer(Sanitizer):
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
    ) -> list[Detection]:
        pages = []
        doc = fitz.open(str(self.path))
        try:
            for page_num, page in enumerate(doc, start=1):
                pages.append((page.get_text(), f"page {page_num}"))
        finally:
            doc.close()

        detections = []
        for text, context in pages:
            results = analyze_text(text, custom_terms, enabled_entities)
            for r in results:
                detections.append(Detection(
                    entity_type=r.entity_type,
                    original_value=text[r.start:r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                    page_or_line=context,
                ))

        roots = extract_company_roots(detections)
        if roots:
            for text, context in pages:
                detections.extend(find_company_root_hits(text, roots, context))
            detections = dedup_detections(detections)
        return detections

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        try:
            doc = fitz.open(str(self.path))
            try:
                for page_num, page in enumerate(doc, start=1):
                    page_detections = [
                        d for d in detections
                        if d.redact and d.page_or_line == f"page {page_num}"
                    ]
                    for d in page_detections:
                        token = session.get_or_create_token(d) if session else "[REDACTED]"
                        d.token = token
                        quads = page.search_for(d.original_value)
                        for quad in quads:
                            rect = quad if isinstance(quad, fitz.Rect) else fitz.Rect(quad)
                            page.add_redact_annot(rect)
                    page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                doc.save(str(output_path), garbage=4, deflate=True)
            finally:
                doc.close()
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))
