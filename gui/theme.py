"""Centralised light / dark theme for Document Sanitizer.

Other modules read colours from here via ``get_severity_colors()`` and
``is_dark()``.  Call ``apply_theme()`` to switch the whole application
palette.  Connect to ``theme_changed`` to repaint custom widgets.
"""
from __future__ import annotations

from PySide6.QtCore import Signal, QObject
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


# ── severity colour tables (background, text) per mode ──────────────

_LIGHT_SEVERITY = {
    "high":   (QColor(255, 200, 200), QColor(0, 0, 0)),      # soft pink
    "medium": (QColor(255, 228, 181), QColor(0, 0, 0)),      # soft peach
    "low":    (QColor(255, 255, 204), QColor(0, 0, 0)),      # soft cream
}

_DARK_SEVERITY = {
    "high":   (QColor(120, 30, 30),  QColor(255, 255, 255)),  # muted red
    "medium": (QColor(120, 80, 20),  QColor(255, 255, 255)),  # muted amber
    "low":    (QColor(80, 80, 20),   QColor(255, 255, 255)),  # muted olive
}

# ── singleton notifier ──────────────────────────────────────────────

class _ThemeNotifier(QObject):
    theme_changed = Signal()

_notifier = _ThemeNotifier()
theme_changed: Signal = _notifier.theme_changed

# ── state ───────────────────────────────────────────────────────────

_dark = False


def is_dark() -> bool:
    return _dark


def get_severity_colors() -> dict[str, tuple[QColor, QColor]]:
    """Return ``{severity: (bg_color, text_color)}`` for the active theme."""
    return _DARK_SEVERITY if _dark else _LIGHT_SEVERITY


# ── palette builders ────────────────────────────────────────────────

def _light_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window,          QColor(240, 240, 240))
    p.setColor(QPalette.ColorRole.WindowText,       QColor(0, 0, 0))
    p.setColor(QPalette.ColorRole.Base,             QColor(255, 255, 255))
    p.setColor(QPalette.ColorRole.AlternateBase,    QColor(245, 245, 245))
    p.setColor(QPalette.ColorRole.Text,             QColor(0, 0, 0))
    p.setColor(QPalette.ColorRole.Button,           QColor(240, 240, 240))
    p.setColor(QPalette.ColorRole.ButtonText,       QColor(0, 0, 0))
    p.setColor(QPalette.ColorRole.BrightText,       QColor(255, 0, 0))
    p.setColor(QPalette.ColorRole.Highlight,        QColor(42, 130, 218))
    p.setColor(QPalette.ColorRole.HighlightedText,  QColor(255, 255, 255))
    p.setColor(QPalette.ColorRole.Mid,              QColor(180, 180, 180))
    p.setColor(QPalette.ColorRole.Midlight,         QColor(227, 227, 227))
    p.setColor(QPalette.ColorRole.ToolTipBase,      QColor(255, 255, 220))
    p.setColor(QPalette.ColorRole.ToolTipText,      QColor(0, 0, 0))
    return p


def _dark_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window,          QColor(45, 45, 45))
    p.setColor(QPalette.ColorRole.WindowText,       QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.Base,             QColor(30, 30, 30))
    p.setColor(QPalette.ColorRole.AlternateBase,    QColor(50, 50, 50))
    p.setColor(QPalette.ColorRole.Text,             QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.Button,           QColor(55, 55, 55))
    p.setColor(QPalette.ColorRole.ButtonText,       QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.BrightText,       QColor(255, 50, 50))
    p.setColor(QPalette.ColorRole.Highlight,        QColor(42, 130, 218))
    p.setColor(QPalette.ColorRole.HighlightedText,  QColor(255, 255, 255))
    p.setColor(QPalette.ColorRole.Mid,              QColor(80, 80, 80))
    p.setColor(QPalette.ColorRole.Midlight,         QColor(70, 70, 70))
    p.setColor(QPalette.ColorRole.ToolTipBase,      QColor(50, 50, 50))
    p.setColor(QPalette.ColorRole.ToolTipText,      QColor(220, 220, 220))
    # Disabled colours
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(120, 120, 120))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       QColor(120, 120, 120))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(120, 120, 120))
    return p


# ── public API ──────────────────────────────────────────────────────

def apply_theme(dark: bool) -> None:
    """Switch the whole application between light and dark mode."""
    global _dark
    _dark = dark
    app = QApplication.instance()
    if app is None:
        return
    app.setPalette(_dark_palette() if dark else _light_palette())
    app.setStyleSheet(
        "QToolTip { border: 1px solid palette(mid); }"
    )
    _notifier.theme_changed.emit()
