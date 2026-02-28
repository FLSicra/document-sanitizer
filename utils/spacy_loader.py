"""Resolve the spaCy model name/path for both normal and PyInstaller-frozen execution."""
import sys
from pathlib import Path


def get_spacy_model_name() -> str:
    """Return the model name or path to use with spacy.load()."""
    if not getattr(sys, 'frozen', False):
        return "en_core_web_lg"

    # In a frozen bundle, en_core_web_lg is bundled as a package under _MEIPASS.
    # spacy.load() by name still works if the package is importable — but as a
    # fallback, look for the model directory directly.
    try:
        import en_core_web_lg  # noqa: F401 — verifies it's importable
        return "en_core_web_lg"
    except ImportError:
        pass

    base = Path(sys._MEIPASS)
    model_root = base / "en_core_web_lg"
    if model_root.is_dir():
        # The versioned subdirectory contains config.cfg
        for entry in model_root.iterdir():
            if entry.is_dir() and (entry / "config.cfg").is_file():
                return str(entry)
        return str(model_root)
    return "en_core_web_lg"
