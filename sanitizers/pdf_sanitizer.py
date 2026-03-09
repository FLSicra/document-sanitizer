from pathlib import Path
import fitz  # PyMuPDF
from sanitizers.base import (
    Detection, SanitizeResult, Sanitizer, dedup_detections,
    extract_company_roots, find_company_root_hits,
)
from detectors.engine import analyze_text


def _get_page_text(page, warnings: list[str] | None = None) -> str:
    """Return page text, falling back to OCR for image-only pages.

    OCR requires Tesseract to be installed on the system.  If it is not
    available (or any other error occurs), the function returns an empty
    string so that the rest of the pipeline continues unaffected.

    If *warnings* is provided, OCR failures are appended as human-readable
    messages so the caller can surface them to the user.
    """
    text = page.get_text()
    if text.strip():
        return text
    # Page has no extractable text — try OCR (Tesseract must be installed)
    try:
        tp = page.get_textpage_ocr(flags=3, full=True)
        return page.get_text(textpage=tp)
    except Exception:
        if warnings is not None:
            warnings.append(
                f"Page {page.number + 1}: no extractable text and OCR unavailable — page skipped"
            )
        return ""


class PDFSanitizer(Sanitizer):
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
        progress_callback=None,
    ) -> list[Detection]:
        pages = []
        ocr_warnings: list[str] = []
        doc = fitz.open(str(self.path))
        try:
            for page_num, page in enumerate(doc, start=1):
                pages.append((_get_page_text(page, ocr_warnings), f"page {page_num}"))
        finally:
            doc.close()
        # Store warnings for later use (e.g. shown after sanitization)
        self._ocr_warnings = ocr_warnings

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
                if session is not None:
                    session.initialize_from_content([page.get_text() for page in doc])
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
            result = SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
            result.warnings = getattr(self, '_ocr_warnings', [])
            return result
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))
