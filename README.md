# Document Sanitizer

A cross-platform desktop application for detecting and redacting Personally Identifiable Information (PII), credentials, and sensitive data from documents. Built with PySide6 and powered by [Presidio](https://github.com/microsoft/presidio) + [spaCy](https://spacy.io/).

Runs on **Windows**, **macOS**, and **Linux**.

## Features

- **Multi-format support** -- PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP, images (JPG, PNG, TIFF, HEIC), and text-based files (TXT, CSV, JSON, YAML, XML, Markdown, etc.)
- **Two-step workflow** -- Analyze files to preview detections, then selectively redact
- **Reversible redaction** -- Encrypted vault files allow authorized restoration of original values
- **Threaded processing** -- Background analysis and sanitization keep the UI responsive
- **Large file streaming** -- Files over 50 MB are processed in chunks to limit memory usage

## Detection Capabilities

| Category | Entities |
|----------|----------|
| **PII** | Person names, email addresses, phone numbers, locations |
| **Financial** | Credit card numbers, IBAN codes |
| **Cloud secrets** | AWS access keys/ARNs, Azure connection strings/client secrets/SAS tokens, GCP service accounts/API keys, JWT tokens, certificate thumbprints |
| **Infrastructure** | Internal hostnames, private IPs, file paths, M365 tenant URLs |
| **Norwegian identifiers** | National ID (fodselsnummer), D-number, bank accounts, phone numbers, postal addresses, passport numbers, vehicle registration |
| **Norwegian GDPR Art. 9** | Health data, biometric data, genetic data, political opinions, religious beliefs, sexual orientation, racial/ethnic origin, trade union membership |
| **Custom terms** | User-defined deny list with word-boundary matching |

Norwegian person names containing characters outside the English NER model's training data are detected via a dedicated supplemental recognizer.

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](../../releases) page:

| Platform | File | Install |
|----------|------|---------|
| **Windows** | `DocumentSanitizer_Setup.exe` | Run the installer |
| **macOS** | `DocumentSanitizer-macOS.dmg` | Open DMG, drag to Applications |
| **Linux** | `DocumentSanitizer-Linux` | `chmod +x DocumentSanitizer-Linux && ./DocumentSanitizer-Linux` |

### Quick start from source (any platform)

Requires Python 3.11+. The launcher creates a virtual environment and installs all dependencies automatically:

```bash
python run.py
```

Use `python run.py --reset` to recreate the virtual environment from scratch.

### Manual setup from source

```bash
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

> **Linux note:** PySide6 requires system libraries. On Ubuntu/Debian:
> ```bash
> sudo apt-get install libxcb-xinerama0 libxkbcommon-x11-0 libglib2.0-0 libegl1
> ```

## Building

### Executable (all platforms)

```bash
pip install -r requirements-dev.txt
pyinstaller document_sanitizer.spec
```

Output varies by platform:
- **Windows:** `dist/DocumentSanitizer.exe`
- **macOS:** `dist/DocumentSanitizer.app`
- **Linux:** `dist/DocumentSanitizer`

### Windows installer

Requires [Inno Setup 6](https://jrsoftware.org/isdl.php).

```bash
iscc installer.iss
```

Output: `dist/Output/DocumentSanitizer_Setup.exe`

### CI/CD

Push a version tag (e.g. `v1.0.0`) to trigger the GitHub Actions workflow, which builds and publishes release artifacts for all three platforms automatically.

## Usage

1. Click **Add Files** to select one or more documents
2. Click **Analyze** to scan for PII and sensitive data
3. Review the detection table -- uncheck any items you want to keep
4. Click **Sanitize** to redact checked items and save sanitized copies
5. Optionally set a vault password to enable future restoration

### Restoring documents

Use the **Restore** tab to reverse a sanitization:

1. Select the sanitized document
2. Select the corresponding `.vault` file
3. Enter the vault password
4. Choose an output path

## Vault encryption

Redaction tokens are encrypted using Fernet (AES-128-CBC + HMAC-SHA256) with a key derived via PBKDF2-SHA256 (100,000 iterations). The vault stores a deterministic mapping from tokens (e.g. `[PERSON_1]`) back to original values, allowing authorized users to restore documents.

## Project Structure

```
main.py                  Entry point
run.py                   Cross-platform launcher (auto venv setup)
gui/                     PySide6 UI (main window, preview panel, settings)
sanitizers/              Format-specific analyzers and redactors
detectors/               Presidio engine wrapper and custom recognizers
utils/                   File routing, streaming, spaCy loader
vault/                   Token encryption and document restoration
tests/                   Integration and unit tests
icons/                   Platform-specific app icons (icns, png)
linux/                   Linux desktop entry
.github/workflows/       CI/CD build pipeline
document_sanitizer.spec  PyInstaller build spec (cross-platform)
installer.iss            Inno Setup installer script (Windows)
```

## Dependencies

- **GUI**: PySide6
- **NLP/Detection**: presidio-analyzer, presidio-anonymizer, spaCy (en_core_web_lg)
- **Documents**: PyMuPDF, python-docx, openpyxl, python-pptx, odfpy, Pillow
- **Crypto**: cryptography (Fernet + PBKDF2)
