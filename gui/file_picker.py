from __future__ import annotations
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QWidget
from utils.file_router import SUPPORTED_EXTENSIONS
from utils.onedrive import get_onedrive_paths


def _build_filter() -> str:
    exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_EXTENSIONS))
    return f"Supported Files ({exts});;All Files (*)"


def pick_files(parent: QWidget) -> list[Path]:
    """Open multi-select file dialog. Returns list of selected paths."""
    paths, _ = QFileDialog.getOpenFileNames(
        parent,
        "Select files to sanitize",
        str(Path.home()),
        _build_filter(),
    )
    return [Path(p) for p in paths]


def pick_folder(parent: QWidget) -> Path | None:
    """Open folder dialog. Returns selected path or None."""
    folder = QFileDialog.getExistingDirectory(
        parent,
        "Select output folder",
        str(Path.home()),
    )
    return Path(folder) if folder else None


def get_onedrive_options() -> list[tuple[str, Path]]:
    """Return OneDrive quick-access options for the output combo box."""
    return get_onedrive_paths()
