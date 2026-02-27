# Changelog

All notable changes to Document Sanitizer are documented in this file.

## [1.4.0] - 2026-02-27

### Added

- **Column sorting on preview results** -- click any column header (File, Entity Type, Original Value, Page/Line, Confidence) to sort ascending/descending; Confidence column sorts numerically instead of alphabetically
- **Collapsible detection settings** -- all entity group sections (PII, Financial, Network & Paths, Norwegian Identifiers, etc.) are now collapsible dropdown panels with arrow indicators, replacing the previous always-expanded group boxes
- **Per-section scrollbars** -- each collapsible section has its own scroll area (capped at 150 px), keeping the settings panel compact even with many entity types
- **Light / Dark mode toggle** -- new toolbar button switches the entire application between a light palette and a dark palette
- **`gui/theme.py` module** -- centralised theme system with separate severity colour tables per mode and a `theme_changed` signal for live repainting

### Changed

- **`gui/preview_panel.py`** -- severity row colours now come from the theme module; detection references are stored in table items via `UserRole` data so row selection and context viewer work correctly after sorting
- **`gui/settings_panel.py`** -- replaced `QGroupBox` widgets with `CollapsibleSection`; header buttons use `palette()` references so they adapt automatically to light/dark mode
- **`gui/main_window.py`** -- added theme toggle button, applies light palette on startup, re-renders the preview table when theme changes

## [1.3.0] - 2026-02-26

### Added

- **SSB name-database cross-reference for PERSON/NRP** -- spaCy PERSON detections are now validated against the 5,600+ SSB name database; spans without a known name are suppressed, eliminating false positives on Norwegian common words
- **PERSON span trimming** -- spaCy's wide spans like "Tore har sagt" are trimmed to just the name portion ("Tore"), with multi-name spans split into separate results
- **NORWEGIAN_COMPANY uppercase suffix check** -- company detections now require the legal suffix (AS, DA, ASA, etc.) to be uppercase in the original text, preventing false matches on lowercase "da"/"sa" in ordinary Norwegian sentences
- **Norwegian common words list** -- ~350 common Norwegian words (pronouns, verbs, adjectives, adverbs, ordinals, nouns) used for LOCATION/COMPANY heuristic filtering
- **Proper-noun heuristic for LOCATION** -- LOCATION detections are suppressed unless the span contains a capitalized word that is not a common Norwegian word

### Changed

- **`detectors/engine.py`** -- completely rewritten false-positive suppression: two-tier strategy with name-database cross-reference for PERSON/NRP and proper-noun heuristic for LOCATION/COMPANY
- **`gui/preview_panel.py`** -- removed 500-row limit on preview table; all detections are now shown

## [1.2.0] - 2026-02-26

### Added

- **Massively expanded Norwegian name database** -- replaced 53 hardcoded first names with 1,968 first names and 3,694 surnames sourced from SSB (Statistics Norway) public statistics (Tables 10467 and 12891)
- **Scandinavian name coverage** -- added 42 common Swedish and Danish first names that English NER models typically miss
- **Aggressive standalone name detection** -- first names and surnames are now flagged even without a paired surname/first name, critical for transcriptions where people mention names casually
- **Tiered confidence scoring** -- known first + known surname: 0.85, name + capitalized word: 0.70, standalone name: 0.50
- **SSB data fetch utility** (`scripts/fetch_ssb_names.py`) -- one-time script to refresh name lists from SSB's public API
- **External name data files** (`data/`) -- names stored in text files for easy maintenance and updates

### Changed

- **`detectors/norwegian_names.py`** -- replaced regex-based `PatternRecognizer` with a custom `EntityRecognizer` using O(1) set-based lookup, significantly faster with thousands of names
- **`detectors/engine.py`** -- `NORWEGIAN_PERSON_NAME` now filtered through Norwegian stopwords to reduce false positives
- **`gui/settings_panel.py`** -- `NORWEGIAN_PERSON_NAME` now visible in the GUI entity settings
- **`gui/preview_panel.py`** -- Norwegian person names display with medium severity (orange) color
- **`document_sanitizer.spec`** -- name data files bundled in PyInstaller builds

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
