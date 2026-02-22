from pathlib import Path
from typing import Type
from sanitizers.base import Sanitizer


_EXTENSION_MAP: dict[str, str] = {
    ".pdf": "PDFSanitizer",
    ".docx": "OfficeSanitizer",
    ".dotx": "OfficeSanitizer",
    ".xlsx": "OfficeSanitizer",
    ".xlsm": "OfficeSanitizer",
    ".pptx": "OfficeSanitizer",
    ".potx": "OfficeSanitizer",
    ".jpg": "ImageSanitizer",
    ".jpeg": "ImageSanitizer",
    ".png": "ImageSanitizer",
    ".tiff": "ImageSanitizer",
    ".tif": "ImageSanitizer",
    ".heic": "ImageSanitizer",
    ".odt": "ODFSanitizer",
    ".ods": "ODFSanitizer",
    ".odp": "ODFSanitizer",
    ".txt": "TextSanitizer",
    ".log": "TextSanitizer",
    ".csv": "TextSanitizer",
    ".json": "JsonSanitizer",
    ".yaml": "TextSanitizer",
    ".yml": "TextSanitizer",
    ".xml": "TextSanitizer",
    ".ini": "TextSanitizer",
    ".env": "TextSanitizer",
    ".toml": "TextSanitizer",
    ".md": "TextSanitizer",
}

SUPPORTED_EXTENSIONS = set(_EXTENSION_MAP.keys())


def _make_sanitizer(class_name: str, path: Path) -> Sanitizer:
    # Lazy imports to avoid circular deps and slow startup
    if class_name == "PDFSanitizer":
        from sanitizers.pdf_sanitizer import PDFSanitizer
        return PDFSanitizer(path)
    if class_name == "OfficeSanitizer":
        from sanitizers.office_sanitizer import OfficeSanitizer
        return OfficeSanitizer(path)
    if class_name == "ImageSanitizer":
        from sanitizers.image_sanitizer import ImageSanitizer
        return ImageSanitizer(path)
    if class_name == "ODFSanitizer":
        from sanitizers.odf_sanitizer import ODFSanitizer
        return ODFSanitizer(path)
    if class_name == "TextSanitizer":
        from sanitizers.text_sanitizer import TextSanitizer
        return TextSanitizer(path)
    if class_name == "JsonSanitizer":
        from sanitizers.text_sanitizer import JsonSanitizer
        return JsonSanitizer(path)
    raise RuntimeError(f"Unknown sanitizer class: {class_name}")


def get_sanitizer(path: Path) -> Sanitizer:
    """Return the appropriate Sanitizer instance for the given file path."""
    suffix = path.suffix.lower()
    class_name = _EXTENSION_MAP.get(suffix)
    if class_name is None:
        raise ValueError(f"Unsupported file type: {suffix}")
    return _make_sanitizer(class_name, path)


def is_supported(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_EXTENSIONS
