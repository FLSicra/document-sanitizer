from __future__ import annotations
import os
import platform
from pathlib import Path


def get_onedrive_paths() -> list[tuple[str, Path]]:
    """
    Detect OneDrive mount points on the current platform.
    Returns list of (label, path) tuples.
    """
    system = platform.system()
    if system == "Windows":
        return _windows_onedrive()
    elif system == "Darwin":
        return _macos_onedrive()
    else:
        return _linux_onedrive()


def _windows_onedrive() -> list[tuple[str, Path]]:
    results = []
    user_profile = Path(os.environ.get("USERPROFILE", Path.home()))
    try:
        for entry in user_profile.iterdir():
            if entry.is_dir() and entry.name.startswith("OneDrive"):
                label = entry.name  # e.g. "OneDrive - Contoso" or "OneDrive"
                results.append((label, entry))
    except OSError:
        pass
    return results


def _macos_onedrive() -> list[tuple[str, Path]]:
    results = []
    home = Path.home()

    # Personal OneDrive
    personal = home / "OneDrive"
    if personal.is_dir():
        results.append(("OneDrive", personal))

    # Work accounts via CloudStorage
    cloud_storage = home / "Library" / "CloudStorage"
    if cloud_storage.is_dir():
        try:
            for entry in cloud_storage.iterdir():
                if entry.is_dir() and entry.name.startswith("OneDrive-"):
                    label = entry.name.replace("OneDrive-", "OneDrive - ").replace("_", " ")
                    results.append((label, entry))
        except OSError:
            pass

    return results


def _linux_onedrive() -> list[tuple[str, Path]]:
    results = []
    home = Path.home()
    onedrive = home / "OneDrive"
    if onedrive.is_dir():
        results.append(("OneDrive", onedrive))
    # rclone may mount as "OneDrive Personal" or similar
    try:
        for entry in home.iterdir():
            if entry.is_dir() and entry.name.startswith("OneDrive") and entry != onedrive:
                results.append((entry.name, entry))
    except OSError:
        pass
    return results
