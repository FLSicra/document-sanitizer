# Changelog

All notable changes to Document Sanitizer are documented in this file.

## [1.1.0] - 2026-02-22

### Added

- **Cross-platform support** -- the application now runs on macOS and Linux in addition to Windows
- **macOS build** -- PyInstaller produces a native `.app` bundle, distributed as a `.dmg` disk image
- **Linux build** -- PyInstaller produces a standalone executable with stripped debug symbols
- **`run.py` launcher** -- cross-platform script that creates a virtual environment, installs dependencies, downloads the spaCy model, and launches the app automatically
- **GitHub Actions CI/CD** -- push a version tag (`v*`) to build and publish release artifacts for all three platforms
- **Platform-aware app icon** -- macOS dock and Linux taskbars now display the application icon correctly (`.icns` and `.png` formats added)
- **Linux desktop entry** -- `linux/document-sanitizer.desktop` for integration with Linux app launchers
- **`requirements-dev.txt`** -- separate file for build and test dependencies (PyInstaller, pytest)

### Changed

- **`document_sanitizer.spec`** -- refactored with platform conditionals for icon paths, macOS `.app` bundle (directory mode), and Linux binary stripping
- **`main.py`** -- added platform-aware icon loading for dock/taskbar display
- **`requirements.txt`** -- moved PyInstaller to dev dependencies; runtime file now contains only what end users need
- **`README.md`** -- updated to reflect cross-platform support with installation instructions for all three platforms

## [1.0.0] - 2026-02-22

### Added

- Initial release
- PII detection and redaction for 23 file formats (PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP, images, text files)
- 47 entity types including PII, cloud secrets, infrastructure identifiers, and Norwegian-specific identifiers
- Encrypted vault system for reversible redaction (Fernet AES-128-CBC + PBKDF2)
- Background threading for responsive UI during analysis and sanitization
- Large file streaming for documents over 50 MB
- Custom deny-list support with word-boundary matching
- Windows installer via Inno Setup
