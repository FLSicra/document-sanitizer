"""Resolve the spaCy model name/path for both normal and PyInstaller-frozen execution."""
import os
import sys


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

    base = sys._MEIPASS
    model_root = os.path.join(base, "en_core_web_lg")
    if os.path.isdir(model_root):
        # The versioned subdirectory contains config.cfg
        for entry in os.listdir(model_root):
            candidate = os.path.join(model_root, entry)
            if os.path.isfile(os.path.join(candidate, "config.cfg")):
                return candidate
        return model_root
    return "en_core_web_lg"
