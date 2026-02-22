# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_all

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

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='DocumentSanitizer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,   # windowed — no terminal popup
    icon='app.ico',
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
