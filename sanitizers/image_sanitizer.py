from pathlib import Path
from sanitizers.base import Detection, SanitizeResult, Sanitizer
from PIL import Image


class ImageSanitizer(Sanitizer):
    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
    ) -> list[Detection]:
        """Images have no text content to detect PII in — only metadata."""
        return []

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        try:
            with Image.open(str(self.path)) as img:
                # Copy pixel data without metadata (avoids massive list allocation)
                clean = img.copy()
                clean.info = {}  # strip all metadata
                output_path.parent.mkdir(parents=True, exist_ok=True)
                # Preserve format
                fmt = img.format or "PNG"
                if fmt == "JPEG":
                    clean.save(str(output_path), format="JPEG", quality=95)
                else:
                    clean.save(str(output_path), format=fmt)
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=[])
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))
