from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QCheckBox, QLineEdit,
    QPushButton, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
)
from PySide6.QtCore import Signal

ENTITY_GROUPS = {
    "PII": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", "NRP"],
    "Financial": ["CREDIT_CARD", "IBAN_CODE"],
    "Network & Paths": ["IP_ADDRESS", "URL", "INTERNAL_HOSTNAME", "PRIVATE_IP", "FILE_PATH"],
    "Norwegian — Identifiers": [
        "NORWEGIAN_COMPANY",
        "NORWEGIAN_ORG_NUMBER",
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


class SettingsPanel(QWidget):
    settings_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checkboxes: dict[str, QCheckBox] = {}
        self._custom_terms: list[str] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Entity type groups
        for group_name, entities in ENTITY_GROUPS.items():
            group = QGroupBox(group_name)
            group_layout = QVBoxLayout(group)
            for entity in entities:
                chk = QCheckBox(entity)
                chk.setChecked(True)
                chk.stateChanged.connect(lambda _: self.settings_changed.emit())
                self._checkboxes[entity] = chk
                group_layout.addWidget(chk)
            layout.addWidget(group)

        # Custom deny-list
        deny_group = QGroupBox("Custom Deny-List Terms")
        deny_layout = QVBoxLayout(deny_group)

        input_row = QHBoxLayout()
        self._term_input = QLineEdit()
        self._term_input.setPlaceholderText("Enter term and press Add...")
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add_term)
        self._term_input.returnPressed.connect(self._add_term)
        input_row.addWidget(self._term_input)
        input_row.addWidget(add_btn)
        deny_layout.addLayout(input_row)

        self._term_list = QListWidget()
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_term)
        deny_layout.addWidget(self._term_list)
        deny_layout.addWidget(remove_btn)
        layout.addWidget(deny_group)

        layout.addStretch()

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
