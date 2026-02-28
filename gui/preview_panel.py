from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QCheckBox, QTextEdit, QSplitter, QPushButton,
    QHBoxLayout, QLabel,
)
from PySide6.QtCore import Qt
from sanitizers.base import Detection
from gui.theme import get_severity_colors

DETECTION_ROLE = Qt.ItemDataRole.UserRole + 1
FILENAME_ROLE = Qt.ItemDataRole.UserRole + 2
SORT_VALUE_ROLE = Qt.ItemDataRole.UserRole + 3


class _NumericSortItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by a numeric value stored in SORT_VALUE_ROLE."""
    def __lt__(self, other: QTableWidgetItem) -> bool:
        a = self.data(SORT_VALUE_ROLE)
        b = other.data(SORT_VALUE_ROLE) if other else None
        if a is not None and b is not None:
            return a < b
        return super().__lt__(other)

HIGH_SEVERITY_TYPES = {
    # Cloud secrets / financial
    "AWS_ACCESS_KEY", "AWS_ARN", "AZURE_CONNECTION_STRING", "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT", "GCP_API_KEY", "GENERIC_SECRET", "CREDIT_CARD", "IBAN_CODE",
    # Norwegian strong identifiers
    "NORWEGIAN_NATIONAL_ID", "NORWEGIAN_D_NUMBER", "NORWEGIAN_BANK_ACCOUNT",
    # GDPR Art. 9 special categories
    "HEALTH_DATA", "BIOMETRIC_DATA", "GENETIC_DATA", "POLITICAL_OPINION",
    "RELIGIOUS_BELIEF", "SEXUAL_ORIENTATION", "RACIAL_ETHNIC_ORIGIN", "TRADE_UNION",
}
MEDIUM_SEVERITY_TYPES = {
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", "NRP", "CUSTOM_TERM",
    "NORWEGIAN_COMPANY", "NORWEGIAN_ORG_NUMBER", "NORWEGIAN_PERSON_NAME",
    "NORWEGIAN_PHONE", "NORWEGIAN_POSTAL_ADDRESS", "NORWEGIAN_PASSPORT",
    "NORWEGIAN_VEHICLE_REG", "INTERNAL_HOSTNAME", "PRIVATE_IP", "FILE_PATH",
}


def _severity(entity_type: str) -> str:
    if entity_type in HIGH_SEVERITY_TYPES:
        return "high"
    if entity_type in MEDIUM_SEVERITY_TYPES:
        return "medium"
    return "low"


COLUMNS = ["File", "Entity Type", "Original Value", "Page/Line", "Confidence", "Redact"]
MAX_PREVIEW_ROWS = 0  # 0 = no limit; show all detections


class PreviewPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._detections: list[tuple[str, Detection]] = []  # (filename, detection)
        self._checkboxes: list[QCheckBox] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.horizontalHeader().setSortIndicatorShown(True)
        self._table.horizontalHeader().setSectionsClickable(True)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._splitter.addWidget(self._table)

        # Context pane
        ctx_widget = QWidget()
        ctx_layout = QVBoxLayout(ctx_widget)
        ctx_layout.setContentsMargins(4, 4, 4, 4)
        ctx_label = QLabel("Context")
        self._context_view = QTextEdit()
        self._context_view.setReadOnly(True)
        self._context_view.setMaximumHeight(120)
        ctx_layout.addWidget(ctx_label)
        ctx_layout.addWidget(self._context_view)
        self._splitter.addWidget(ctx_widget)

        layout.addWidget(self._splitter)

        self._truncation_label = QLabel("")
        self._truncation_label.setStyleSheet("color: #e65100; font-style: italic;")
        self._truncation_label.setVisible(False)
        layout.addWidget(self._truncation_label)

        btn_row = QHBoxLayout()
        self._select_all_btn = QPushButton("Select All")
        self._deselect_all_btn = QPushButton("Deselect All")
        self._select_all_btn.clicked.connect(self._select_all)
        self._deselect_all_btn.clicked.connect(self._deselect_all)
        btn_row.addWidget(self._select_all_btn)
        btn_row.addWidget(self._deselect_all_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    def load_detections(self, filename: str, detections: list[Detection]):
        """Append detections from a file into the table."""
        total = len(detections)
        if MAX_PREVIEW_ROWS > 0:
            display = detections[:MAX_PREVIEW_ROWS]
            if total > MAX_PREVIEW_ROWS:
                self._truncation_label.setText(
                    f"Showing {MAX_PREVIEW_ROWS} of {total} findings. "
                    f"All {total} will be redacted on sanitize."
                )
                self._truncation_label.setVisible(True)
            else:
                self._truncation_label.setVisible(False)
        else:
            display = detections
            self._truncation_label.setVisible(False)

        severity_colors = get_severity_colors()

        self._table.setSortingEnabled(False)
        self._table.setUpdatesEnabled(False)
        for d in display:
            det_index = len(self._detections)
            self._detections.append((filename, d))
            row = self._table.rowCount()
            self._table.insertRow(row)

            bg, fg = severity_colors[_severity(d.entity_type)]

            # Confidence uses _NumericSortItem for proper numeric sorting
            conf_item = _NumericSortItem(f"{d.score:.0%}")
            conf_item.setData(SORT_VALUE_ROLE, d.score)

            items = [
                QTableWidgetItem(filename),
                QTableWidgetItem(d.entity_type),
                QTableWidgetItem(d.original_value),
                QTableWidgetItem(str(d.page_or_line or "")),
                conf_item,
            ]
            for col, item in enumerate(items):
                item.setBackground(bg)
                item.setForeground(fg)
                # Store detection list index for retrieval after sorting
                item.setData(DETECTION_ROLE, det_index)
                item.setData(FILENAME_ROLE, filename)
                self._table.setItem(row, col, item)

            # Redact checkbox
            chk = QCheckBox()
            chk.setChecked(d.redact)
            chk.stateChanged.connect(lambda state, det=d: self._on_redact_changed(det, state))
            self._checkboxes.append(chk)
            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.addWidget(chk)
            chk_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            self._table.setCellWidget(row, len(COLUMNS) - 1, chk_widget)
        self._table.setUpdatesEnabled(True)
        self._table.setSortingEnabled(True)

    def clear(self):
        self._table.setRowCount(0)
        self._detections.clear()
        self._checkboxes.clear()
        self._context_view.clear()
        self._truncation_label.setVisible(False)

    def _on_redact_changed(self, detection: Detection, state: int):
        detection.redact = bool(state)

    def _detection_for_row(self, row: int):
        """Look up the Detection object for a (possibly re-sorted) table row."""
        item = self._table.item(row, 0)
        if item is None:
            return None
        det_index = item.data(DETECTION_ROLE)
        if det_index is not None and 0 <= det_index < len(self._detections):
            return self._detections[det_index][1]
        return None

    def _on_selection_changed(self):
        rows = self._table.selectedItems()
        if not rows:
            return
        row = self._table.currentRow()
        det = self._detection_for_row(row)
        if det is not None:
            self._context_view.setPlainText(
                f"Entity: {det.entity_type}\n"
                f"Value: {det.original_value}\n"
                f"Location: {det.page_or_line}\n"
                f"Confidence: {det.score:.0%}"
            )

    def _select_all(self):
        for _, det in self._detections:
            det.redact = True
        self._refresh_checkboxes(True)

    def _deselect_all(self):
        for _, det in self._detections:
            det.redact = False
        self._refresh_checkboxes(False)

    def _refresh_checkboxes(self, checked: bool):
        for chk in self._checkboxes:
            chk.blockSignals(True)
            chk.setChecked(checked)
            chk.blockSignals(False)
