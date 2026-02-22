#!/usr/bin/env python3
"""
Cross-platform launcher for Document Sanitizer.
Creates a virtual environment, installs dependencies, and runs the app.

Usage:
    python run.py          # first run: creates venv, installs deps, launches
    python run.py --reset  # recreate the venv from scratch
"""
import os
import sys
import subprocess
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
REQ_FILE = ROOT / "requirements.txt"


def get_python():
    """Return path to the venv Python executable."""
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def get_pip():
    """Return path to the venv pip executable."""
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "pip.exe"
    return VENV_DIR / "bin" / "pip"


def create_venv():
    print("[run.py] Creating virtual environment...")
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])


def install_deps():
    pip = str(get_pip())
    print("[run.py] Installing dependencies (this may take a few minutes)...")
    subprocess.check_call([pip, "install", "--upgrade", "pip"])
    subprocess.check_call([pip, "install", "-r", str(REQ_FILE)])


def ensure_spacy_model():
    """Download the spaCy model if it is not already installed."""
    python = str(get_python())
    result = subprocess.run(
        [python, "-c", "import en_core_web_lg"],
        capture_output=True,
    )
    if result.returncode != 0:
        print("[run.py] Downloading spaCy model en_core_web_lg...")
        subprocess.check_call(
            [python, "-m", "spacy", "download", "en_core_web_lg"]
        )


def main():
    if "--reset" in sys.argv and VENV_DIR.exists():
        import shutil
        print("[run.py] Removing existing virtual environment...")
        shutil.rmtree(VENV_DIR)

    if not VENV_DIR.exists():
        create_venv()
        install_deps()
        ensure_spacy_model()

    python = str(get_python())
    main_py = str(ROOT / "main.py")
    print("[run.py] Launching Document Sanitizer...")

    if platform.system() == "Windows":
        # os.execv is unreliable on Windows; use subprocess instead
        raise SystemExit(subprocess.call([python, main_py]))
    else:
        os.execv(python, [python, main_py])


if __name__ == "__main__":
    main()
