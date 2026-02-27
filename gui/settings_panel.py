from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QCheckBox, QLineEdit,
    QPushButton, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QScrollArea, QToolButton, QSizePolicy, QFrame,
)
from PySide6.QtCore import Signal, Qt

ENTITY_GROUPS = {
    "PII": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", "NRP"],
    "Financial": ["CREDIT_CARD", "IBAN_CODE"],
    "Network & Paths": ["IP_ADDRESS", "URL", "INTERNAL_HOSTNAME", "PRIVATE_IP", "FILE_PATH"],
    "Norwegian — Identifiers": [
        "NORWEGIAN_COMPANY",
        "NORWEGIAN_ORG_NUMBER",
        "NORWEGIAN_PERSON_NAME",
        "NORWEGIAN_NATIONAL_ID",
        "NORWEGIAN_D_NUMBER",
        "NORWEGIAN_BANK_ACCOUNT",
        "NORWEGIAN_PHONE",
        "NORWEGIAN_POSTAL_ADDRESS",
        "NORWEGIAN_PASSPORT",
        "NORWEGIAN_VEHICLE_REG",
    ],
    "Norwegian — Art. 9 Special": [
        "HEALTH_DATA",
        "BIOMETRIC_DATA",
        "GENETIC_DATA",
        "POLITICAL_OPINION",
        "RELIGIOUS_BELIEF",
        "SEXUAL_ORIENTATION",
        "RACIAL_ETHNIC_ORIGIN",
        "TRADE_UNION",
    ],
    "Cloud / Credentials": [
        "AWS_ACCESS_KEY", "AWS_ARN", "AWS_ACCOUNT_ID",
        "AZURE_CONNECTION_STRING", "AZURE_CLIENT_SECRET", "AZURE_UUID",
        "AZURE_RESOURCE_ID", "AZURE_TENANT_DOMAIN", "AZURE_RESOURCE_NAME",
        "GCP_SERVICE_ACCOUNT", "GCP_API_KEY", "GENERIC_SECRET",
    ],
    "Custom": ["CUSTOM_TERM"],
}

_SECTION_MAX_HEIGHT = 150


class CollapsibleSection(QWidget):
    """A section with a clickable header that collapses/expands its content.

    When expanded, the content is shown inside a QScrollArea with a
    maximum height so it doesn't dominate the panel.
    """

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._expanded = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header button
        self._toggle = QToolButton()
        self._toggle.setStyleSheet(
            "QToolButton { border: 1px solid palette(mid); border-radius: 3px;"
            "  padding: 4px 8px; font-weight: bold;"
            "  background: palette(button); color: palette(button-text); }"
            "QToolButton:hover { background: palette(midlight); }"
        )
        self._toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._toggle.setArrowType(Qt.ArrowType.RightArrow)
        self._toggle.setText(title)
        self._toggle.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._toggle.clicked.connect(self._on_toggle)
        layout.addWidget(self._toggle)

        # Scrollable content area
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setMaximumHeight(_SECTION_MAX_HEIGHT)
        self._scroll.setVisible(False)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(8, 4, 4, 4)
        self._content_layout.setSpacing(2)
        self._scroll.setWidget(self._content)

        layout.addWidget(self._scroll)

    @property
    def content_layout(self) -> QVBoxLayout:
        return self._content_layout

    def _on_toggle(self):
        self._expanded = not self._expanded
        self._toggle.setArrowType(
            Qt.ArrowType.DownArrow if self._expanded else Qt.ArrowType.RightArrow
        )
        self._scroll.setVisible(self._expanded)


class SettingsPanel(QWidget):
    settings_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checkboxes: dict[str, QCheckBox] = {}
        self._custom_terms: list[str] = []
        self._setup_ui()

    def _setup_ui(self):
        # Outer scroll area so the whole panel scrolls if needed
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Entity type groups as collapsible sections
        for group_name, entities in ENTITY_GROUPS.items():
            section = CollapsibleSection(group_name)
            for entity in entities:
                chk = QCheckBox(entity)
                chk.setChecked(True)
                chk.stateChanged.connect(lambda _: self.settings_changed.emit())
                self._checkboxes[entity] = chk
                section.content_layout.addWidget(chk)
            layout.addWidget(section)

        # Custom deny-list as collapsible section
        deny_section = CollapsibleSection("Custom Deny-List Terms")
        cl = deny_section.content_layout

        input_row = QHBoxLayout()
        self._term_input = QLineEdit()
        self._term_input.setPlaceholderText("Enter term and press Add...")
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add_term)
        self._term_input.returnPressed.connect(self._add_term)
        input_row.addWidget(self._term_input)
        input_row.addWidget(add_btn)
        cl.addLayout(input_row)

        self._term_list = QListWidget()
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_term)
        cl.addWidget(self._term_list)
        cl.addWidget(remove_btn)
        layout.addWidget(deny_section)

        layout.addStretch()
        scroll.setWidget(inner)
        outer_layout.addWidget(scroll)

    def _add_term(self):
        term = self._term_input.text().strip()
        if term and term not in self._custom_terms:
            self._custom_terms.append(term)
            self._term_list.addItem(QListWidgetItem(term))
            self._term_input.clear()
            self.settings_changed.emit()

    def _remove_term(self):
        items = self._term_list.selectedItems()
        for item in items:
            self._custom_terms.remove(item.text())
            self._term_list.takeItem(self._term_list.row(item))
        if items:
            self.settings_changed.emit()

    def get_enabled_entities(self) -> set[str]:
        return {e for e, chk in self._checkboxes.items() if chk.isChecked()}

    def get_custom_terms(self) -> list[str]:
        return list(self._custom_terms)
