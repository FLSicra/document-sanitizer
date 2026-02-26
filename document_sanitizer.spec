# -*- mode: python ; coding: utf-8 -*-
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_all

# ── Data files and hidden imports (shared across all platforms) ───
datas = []
hiddenimports = []

# spaCy model — collect_all ensures the package is importable by name
tmp = collect_all('en_core_web_lg')
datas += tmp[0]; hiddenimports += tmp[2]
datas += collect_data_files('spacy')
datas += collect_data_files('spacy_lookups_data')

# Presidio
datas += collect_data_files('presidio_analyzer')
datas += collect_data_files('presidio_anonymizer')

datas += collect_data_files('numpy')

# Norwegian name data files (SSB-sourced first names, surnames, Scandinavian extras)
datas += [('data', 'data')]

hiddenimports += [
    'numpy',
    'numpy.core',
    'numpy.core._multiarray_umath',
    # spaCy internals
    'spacy.lang.en',
    'spacy.lang.xx',
    'spacy.lexeme',
    'spacy.tokens',
    'spacy.pipeline',
    'spacy.pipeline.ner',
    'spacy.pipeline.tok2vec',
    'spacy.pipeline.tagger',
    'spacy.pipeline.dep_parser',
    'en_core_web_lg',
    # Presidio
    'presidio_analyzer',
    'presidio_analyzer.predefined_recognizers',
    'presidio_anonymizer',
    # Office formats
    'docx',
    'openpyxl',
    'pptx',
    # PDF
    'fitz',
    # ODF
    'odf',
    # Image
    'PIL',
    'PIL.Image',
    # Crypto
    'cryptography',
    'cryptography.fernet',
    # Other
    'yaml',
]

# ── Platform-specific icon ────────────────────────────────────────
if sys.platform == 'darwin':
    icon_file = 'icons/app.icns'
elif sys.platform == 'win32':
    icon_file = 'app.ico'
else:
    icon_file = 'icons/app.png'

# ── Analysis (shared) ────────────────────────────────────────────
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'pandas', 'IPython'],
    noarchive=False,
)

pyz = PYZ(a.pure)

# ── macOS: .app bundle (directory mode via BUNDLE) ────────────────
if sys.platform == 'darwin':
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='DocumentSanitizer',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        icon=icon_file,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name='DocumentSanitizer',
    )
    app = BUNDLE(
        coll,
        name='DocumentSanitizer.app',
        icon=icon_file,
        bundle_identifier='com.docsanitizer.app',
        info_plist={
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
        },
    )

# ── Windows / Linux: single-file executable ───────────────────────
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='DocumentSanitizer',
        debug=False,
        bootloader_ignore_signals=False,
        strip=(sys.platform == 'linux'),
        upx=(sys.platform == 'win32'),
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        icon=icon_file,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
