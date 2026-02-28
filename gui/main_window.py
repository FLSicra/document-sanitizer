from __future__ import annotations
import os
import platform
from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QListWidget,
    QPushButton, QProgressBar, QLabel, QComboBox, QTabWidget,
    QStatusBar, QInputDialog, QMessageBox, QLineEdit, QFileDialog,
    QFrame, QSizePolicy, QSplitter,
)
from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtGui import QFont
from gui.file_picker import pick_files, pick_folder, get_onedrive_options
from gui.preview_panel import PreviewPanel
from gui.settings_panel import SettingsPanel
from gui import theme
from utils.file_router import get_sanitizer, is_supported
from vault.vault import SanitizeSession
from vault.restore import restore_file


class AnalyzeWorker(QObject):
    progress = Signal(int)
    file_done = Signal(str, list)       # filename + detections passed through signal
    finished = Signal()
    error = Signal(str, str)

    def __init__(self, paths: list[Path], custom_terms: tuple[str, ...], enabled_entities: frozenset[str]):
        super().__init__()
        self.paths = paths
        self.custom_terms = custom_terms
        self.enabled_entities = enabled_entities
        self._canceled = False

    def cancel(self):
        self._canceled = True

    def run(self):
        total = len(self.paths)
        for i, path in enumerate(self.paths):
            if self._canceled:
                break
            try:
                sanitizer = get_sanitizer(path)
                detections = sanitizer.detect(self.custom_terms, self.enabled_entities)
                self.file_done.emit(str(path), detections)
            except Exception as e:
                self.error.emit(path.name, f"{type(e).__name__}: {e}")
            self.progress.emit(int((i + 1) * 100 / total))
        self.finished.emit()


class SanitizeWorker(QObject):
    progress = Signal(int)
    file_done = Signal(str)
    finished = Signal()
    error = Signal(str, str)

    def __init__(
        self,
        files: list[Path],
        detections_map: dict[str, list],
        output_dir: Path,
        vault_password: str,
    ):
        super().__init__()
        self.files = files
        self.detections_map = detections_map
        self.output_dir = output_dir
        self.vault_password = vault_password
        self._canceled = False

    def cancel(self):
        self._canceled = True

    def run(self):
        password = self.vault_password
        self.vault_password = None  # clear from worker object immediately
        total = len(self.files)
        for i, file_path in enumerate(self.files):
            if self._canceled:
                break
            try:
                detections = self.detections_map.get(str(file_path), [])
                sanitizer = get_sanitizer(file_path)
                stem = file_path.stem + "_sanitized"
                out_path = self.output_dir / (stem + file_path.suffix)
                session = SanitizeSession()
                result = sanitizer.sanitize(detections, out_path, session)
                if result.success and password:
                    vault_path = self.output_dir / (stem + ".vault")
                    session.save_vault(vault_path, password)
                self.file_done.emit(file_path.name)
            except Exception as e:
                self.error.emit(file_path.name, f"{type(e).__name__}: {e}")
            self.progress.emit(int((i + 1) * 100 / total))
        self.finished.emit()


class RestoreWorker(QObject):
    finished = Signal()
    error = Signal(str)

    def __init__(self, sanitized_path: Path, vault_path: Path, password: str, output_path: Path):
        super().__init__()
        self.sanitized_path = sanitized_path
        self.vault_path = vault_path
        self.password = password
        self.output_path = output_path
        self._canceled = False

    def cancel(self):
        self._canceled = True

    def run(self):
        try:
            restore_file(self.sanitized_path, self.vault_path, self.password, self.output_path)
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            self.finished.emit()
            return
        self.finished.emit()


def _default_output_dir() -> Path:
    """Return a sensible default output directory across platforms."""
    if platform.system() == "Linux":
        xdg = os.environ.get("XDG_DOCUMENTS_DIR")
        if xdg:
            p = Path(xdg)
            if p.is_dir():
                return p
    docs = Path.home() / "Documents"
    if docs.is_dir():
        return docs
    return Path.home()


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.VLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    return line


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Document Sanitizer")
        self.resize(1280, 760)
        self._files: list[Path] = []
        self._detections_map: dict[str, list] = {}
        self._threads: list[QThread] = []
        self._workers: list[QObject] = []
        self._thread_worker_map: dict[QThread, QObject] = {}
        self._busy = False
        self._batch_errors: list[tuple[str, str]] = []  # (filename, error) pairs
        theme.apply_theme(False)  # start in light mode
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        self._tabs = QTabWidget()
        self.setCentralWidget(self._tabs)

        self._tabs.addTab(self._build_sanitize_tab(), "Sanitize")
        self._tabs.addTab(self._build_restore_tab(), "Restore")
        self.setStatusBar(QStatusBar())
        self._update_buttons()

    def _build_sanitize_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Toolbar row ──────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setFixedHeight(44)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(0, 0, 0, 0)
        tb_layout.setSpacing(6)

        self._add_btn = QPushButton("＋  Add Files…")
        self._add_btn.setFixedHeight(36)
        self._add_btn.clicked.connect(self._add_files)

        self._remove_btn = QPushButton("✕  Remove")
        self._remove_btn.setFixedHeight(36)
        self._remove_btn.clicked.connect(self._remove_file)

        tb_layout.addWidget(self._add_btn)
        tb_layout.addWidget(self._remove_btn)
        tb_layout.addWidget(_separator())

        # Step 1 — Analyze
        self._analyze_btn = QPushButton("① Analyze")
        self._analyze_btn.setFixedHeight(36)
        self._analyze_btn.setToolTip("Scan all files and preview what will be redacted")
        font = QFont()
        font.setBold(True)
        self._analyze_btn.setFont(font)
        self._analyze_btn.clicked.connect(self._run_analyze)
        tb_layout.addWidget(self._analyze_btn)

        # Step 2 — Sanitize
        self._sanitize_btn = QPushButton("② Sanitize  ▶")
        self._sanitize_btn.setFixedHeight(36)
        self._sanitize_btn.setToolTip("Redact all checked detections and save sanitized files")
        self._sanitize_btn.setFont(font)
        self._sanitize_btn.setStyleSheet(
            "QPushButton:enabled { background: #2e7d32; color: white; border-radius: 4px; }"
            "QPushButton:disabled { background: #ccc; color: #888; border-radius: 4px; }"
        )
        self._sanitize_btn.clicked.connect(self._run_sanitize)
        tb_layout.addWidget(self._sanitize_btn)

        tb_layout.addWidget(_separator())

        # Output folder
        tb_layout.addWidget(QLabel("Output:"))
        self._output_combo = QComboBox()
        self._output_combo.setEditable(True)
        self._output_combo.setFixedHeight(32)
        self._output_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        default_out = _default_output_dir()
        self._output_combo.addItem(str(default_out), str(default_out))
        for label, path in get_onedrive_options():
            self._output_combo.addItem(label, str(path))
        tb_layout.addWidget(self._output_combo, stretch=1)

        browse_btn = QPushButton("…")
        browse_btn.setFixedSize(32, 32)
        browse_btn.setToolTip("Browse for output folder")
        browse_btn.clicked.connect(self._browse_output)
        tb_layout.addWidget(browse_btn)

        tb_layout.addWidget(_separator())

        # Theme toggle
        self._theme_btn = QPushButton("Dark mode")
        self._theme_btn.setFixedHeight(36)
        self._theme_btn.setCheckable(True)
        self._theme_btn.setToolTip("Toggle between light and dark mode")
        self._theme_btn.clicked.connect(self._toggle_theme)
        tb_layout.addWidget(self._theme_btn)

        layout.addWidget(toolbar)

        # ── Status / progress row (hidden until needed) ───────────────
        self._status_row = QWidget()
        status_layout = QHBoxLayout(self._status_row)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(8)

        self._status_label = QLabel("Analyzing — please wait…")
        self._status_label.setStyleSheet("color: #1565c0; font-style: italic;")

        self._progress = QProgressBar()
        self._progress.setFixedHeight(18)
        self._progress.setTextVisible(True)
        self._progress.setFormat("%p%")

        status_layout.addWidget(self._status_label)
        status_layout.addWidget(self._progress, stretch=1)

        self._status_row.setVisible(False)
        layout.addWidget(self._status_row)

        # ── Main splitter: file list | preview | settings ─────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # File list panel
        file_panel = QWidget()
        file_panel.setMinimumWidth(160)
        file_panel.setMaximumWidth(260)
        fp_layout = QVBoxLayout(file_panel)
        fp_layout.setContentsMargins(0, 0, 0, 0)
        fp_layout.addWidget(QLabel("Files"))
        self._file_list = QListWidget()
        self._file_list.currentRowChanged.connect(self._on_file_selected)
        fp_layout.addWidget(self._file_list)
        splitter.addWidget(file_panel)

        # Preview panel (centre, takes most space)
        self._preview = PreviewPanel()
        splitter.addWidget(self._preview)

        # Settings panel (right side)
        settings_outer = QWidget()
        settings_outer.setMinimumWidth(200)
        settings_outer.setMaximumWidth(280)
        so_layout = QVBoxLayout(settings_outer)
        so_layout.setContentsMargins(0, 0, 0, 0)
        so_layout.addWidget(QLabel("Detection settings"))
        self._settings_panel = SettingsPanel()
        self._settings_panel.settings_changed.connect(self._on_settings_changed)
        so_layout.addWidget(self._settings_panel)
        splitter.addWidget(settings_outer)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        layout.addWidget(splitter)

        return tab

    def _build_restore_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        def _row(label: str, edit_attr: str, browse_slot) -> QHBoxLayout:
            layout.addWidget(QLabel(label))
            row = QHBoxLayout()
            edit = QLineEdit()
            setattr(self, edit_attr, edit)
            btn = QPushButton("Browse…")
            btn.setFixedWidth(80)
            btn.clicked.connect(browse_slot)
            row.addWidget(edit)
            row.addWidget(btn)
            return row

        layout.addLayout(_row("Sanitized file:", "_restore_doc_edit", self._browse_restore_doc))
        layout.addLayout(_row("Vault file (.vault):", "_restore_vault_edit", self._browse_restore_vault))
        layout.addLayout(_row("Save restored file as:", "_restore_out_edit", self._browse_restore_output))

        restore_btn = QPushButton("Restore Document")
        restore_btn.setFixedHeight(36)
        restore_btn.setFont(QFont())
        restore_btn.clicked.connect(self._run_restore)
        layout.addWidget(restore_btn)
        layout.addStretch()
        return tab

    # ------------------------------------------------------------------
    # Button state
    # ------------------------------------------------------------------

    def _update_buttons(self):
        has_files = bool(self._files)
        all_analyzed = has_files and all(str(f) in self._detections_map for f in self._files)
        self._add_btn.setEnabled(not self._busy)
        self._remove_btn.setEnabled(has_files and not self._busy)
        self._analyze_btn.setEnabled(has_files and not self._busy)
        self._sanitize_btn.setEnabled(all_analyzed and not self._busy)
        self._settings_panel.setEnabled(not self._busy)

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------

    @staticmethod
    def _norm_key(p: Path) -> str:
        """Return a case-normalized resolved path string for dedup on Windows."""
        return os.path.normcase(str(p.resolve()))

    def _add_files(self):
        paths = pick_files(self)
        existing = {self._norm_key(f) for f in self._files}
        for p in paths:
            key = self._norm_key(p)
            if key not in existing and is_supported(p):
                existing.add(key)
                self._files.append(p)
                self._file_list.addItem(p.name)
        self._update_buttons()

    def _remove_file(self):
        row = self._file_list.currentRow()
        if row >= 0:
            key = str(self._files[row])
            self._files.pop(row)
            self._file_list.takeItem(row)
            self._detections_map.pop(key, None)
            self._preview.clear()
        self._update_buttons()

    def _on_file_selected(self, row: int):
        if row < 0 or row >= len(self._files):
            return
        key = str(self._files[row])
        self._preview.clear()
        if key in self._detections_map:
            self._preview.load_detections(self._files[row].name, self._detections_map[key])

    # ------------------------------------------------------------------
    # Step 1 — Analyze
    # ------------------------------------------------------------------

    def _run_analyze(self):
        if not self._files:
            return
        # Re-analyze all (in case settings changed)
        self._detections_map.clear()
        self._preview.clear()
        self._batch_errors.clear()
        self._busy = True
        self._update_buttons()

        custom_terms = tuple(self._settings_panel.get_custom_terms())
        enabled_entities = frozenset(self._settings_panel.get_enabled_entities())
        worker = AnalyzeWorker(list(self._files), custom_terms, enabled_entities)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_analyze_progress)
        worker.file_done.connect(self._on_file_analyzed)
        worker.error.connect(self._on_analyze_error)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._on_analyze_finished)
        thread.finished.connect(self._cleanup_thread)
        self._thread_worker_map[thread] = worker
        self._threads.append(thread)
        self._workers.append(worker)

        self._status_label.setStyleSheet("color: #1565c0; font-style: italic;")
        self._status_label.setText(f"Analyzing {len(self._files)} file(s) — please wait…")
        self._status_row.setVisible(True)
        self._progress.setValue(0)
        self.statusBar().showMessage(f"Analyzing {len(self._files)} file(s)…")
        thread.start()

    def _on_analyze_progress(self, value: int):
        self._progress.setValue(value)

    def _on_file_analyzed(self, file_key: str, detections: list):
        self._detections_map[file_key] = detections
        done = len(self._detections_map)
        total = len(self._files)
        self._status_label.setText(
            f"Analyzing file {done} of {total} — please wait…"
        )
        # Show detections for currently selected file
        row = self._file_list.currentRow()
        if 0 <= row < len(self._files) and str(self._files[row]) == file_key:
            display_name = self._files[row].name
            self._preview.clear()
            self._preview.load_detections(display_name, detections)
        display_name = Path(file_key).name
        self.statusBar().showMessage(f"Analyzed: {display_name} — {len(detections)} finding(s)")

    def _on_analyze_error(self, filename: str, error: str):
        self._batch_errors.append((filename, error))
        self._status_label.setText(f"Error in {filename}")
        self._status_label.setStyleSheet("color: #c62828; font-style: italic;")

    def _cleanup_thread(self):
        """Remove a thread/worker pair only after the thread has fully stopped."""
        thread = self.sender()
        if not isinstance(thread, QThread):
            return
        worker = self._thread_worker_map.pop(thread, None)
        if thread in self._threads:
            self._threads.remove(thread)
        if worker and worker in self._workers:
            self._workers.remove(worker)
        thread.deleteLater()
        if worker:
            worker.deleteLater()

    def _on_analyze_finished(self):
        self._busy = False
        self._status_row.setVisible(False)
        total = sum(len(v) for v in self._detections_map.values())
        self.statusBar().showMessage(
            f"Analysis complete — {total} finding(s) across {len(self._files)} file(s). "
            f"Review the list, uncheck anything to keep, then click ② Sanitize."
        )
        # Show first file's detections if none selected
        if self._file_list.currentRow() < 0 and self._files:
            self._file_list.setCurrentRow(0)
        self._update_buttons()
        if self._batch_errors:
            summary = "\n".join(f"• {name}: {err}" for name, err in self._batch_errors)
            QMessageBox.warning(
                self, f"Analysis errors ({len(self._batch_errors)} file(s))",
                f"The following files could not be analyzed:\n\n{summary}",
            )
            self._batch_errors.clear()

    # ------------------------------------------------------------------
    # Step 2 — Sanitize
    # ------------------------------------------------------------------

    def _run_sanitize(self):
        if not self._files or not self._detections_map:
            return

        output_dir_str = self._output_combo.currentText().strip()
        if not output_dir_str:
            QMessageBox.warning(self, "No output folder", "Please select an output folder.")
            return
        output_dir = Path(output_dir_str)

        total_findings = sum(
            sum(1 for d in dets if d.redact)
            for dets in self._detections_map.values()
        )
        confirm = QMessageBox.question(
            self, "Confirm sanitization",
            f"This will redact {total_findings} item(s) across {len(self._files)} file(s)\n"
            f"and save sanitized copies to:\n{output_dir}\n\nProceed?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        password, ok = QInputDialog.getText(
            self, "Vault password",
            "Enter a password to encrypt the token vault\n(leave empty to skip vault):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return

        if password:
            if len(password) < 8:
                QMessageBox.warning(
                    self, "Weak password",
                    "Vault password must be at least 8 characters long.",
                )
                return
            confirm, ok2 = QInputDialog.getText(
                self, "Confirm vault password",
                "Re-enter the vault password to confirm:",
                QLineEdit.EchoMode.Password,
            )
            if not ok2 or confirm != password:
                QMessageBox.warning(
                    self, "Password mismatch",
                    "The passwords do not match. Sanitization cancelled.",
                )
                return

        self._batch_errors.clear()
        worker = SanitizeWorker(
            files=list(self._files),
            detections_map={k: list(d) for k, d in self._detections_map.items()},
            output_dir=output_dir,
            vault_password=password,
        )
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._progress.setValue)
        worker.file_done.connect(lambda name: self.statusBar().showMessage(f"Sanitized: {name}"))
        worker.error.connect(self._on_sanitize_error)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._on_sanitize_done)
        thread.finished.connect(self._cleanup_thread)

        self._busy = True
        self._update_buttons()
        self._status_label.setStyleSheet("color: #1565c0; font-style: italic;")
        self._status_label.setText(f"Sanitizing {len(self._files)} file(s) — please wait…")
        self._status_row.setVisible(True)
        self._progress.setValue(0)
        self._thread_worker_map[thread] = worker
        self._threads.append(thread)
        self._workers.append(worker)
        thread.start()

    def _on_sanitize_error(self, filename: str, error: str):
        self._batch_errors.append((filename, error))

    def _on_sanitize_done(self):
        self._busy = False
        self._status_row.setVisible(False)
        self._update_buttons()
        output_dir = Path(self._output_combo.currentText().strip())
        if self._batch_errors:
            summary = "\n".join(f"• {name}: {err}" for name, err in self._batch_errors)
            QMessageBox.warning(
                self, f"Sanitization errors ({len(self._batch_errors)} file(s))",
                f"Sanitization finished with errors:\n\n{summary}\n\n"
                f"Successfully processed files saved to:\n{output_dir}",
            )
            self._batch_errors.clear()
        else:
            QMessageBox.information(
                self, "Done",
                f"Sanitization complete.\nFiles saved to:\n{output_dir}"
            )

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _toggle_theme(self):
        dark = self._theme_btn.isChecked()
        self._theme_btn.setText("Light mode" if dark else "Dark mode")
        theme.apply_theme(dark)
        # Re-render the preview table so severity colours update
        row = self._file_list.currentRow()
        if 0 <= row < len(self._files):
            key = str(self._files[row])
            if key in self._detections_map:
                self._preview.clear()
                self._preview.load_detections(self._files[row].name, self._detections_map[key])

    def _on_settings_changed(self):
        from detectors.engine import invalidate_cache
        invalidate_cache()
        # Clear cached results so next Analyze picks up new settings
        self._detections_map.clear()
        self._preview.clear()
        self._update_buttons()

    def _browse_output(self):
        folder = pick_folder(self)
        if folder:
            self._output_combo.setCurrentText(str(folder))

    # ------------------------------------------------------------------
    # Restore tab
    # ------------------------------------------------------------------

    def _browse_restore_doc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select sanitized document")
        if path:
            self._restore_doc_edit.setText(path)

    def _browse_restore_vault(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select vault file", filter="Vault files (*.vault);;All (*)"
        )
        if path:
            self._restore_vault_edit.setText(path)

    def _browse_restore_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save restored file")
        if path:
            self._restore_out_edit.setText(path)

    def _run_restore(self):
        doc = self._restore_doc_edit.text().strip()
        vault = self._restore_vault_edit.text().strip()
        out = self._restore_out_edit.text().strip()
        if not doc or not vault or not out:
            QMessageBox.warning(self, "Missing fields", "Please fill in all three fields.")
            return
        password, ok = QInputDialog.getText(
            self, "Vault password", "Enter vault password:", QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        self._restore_error: str | None = None
        self._restore_out_path = out
        worker = RestoreWorker(Path(doc), Path(vault), password, Path(out))
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.error.connect(self._on_restore_error)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._on_restore_done)
        thread.finished.connect(self._cleanup_thread)
        self._thread_worker_map[thread] = worker
        self._threads.append(thread)
        self._workers.append(worker)
        self.statusBar().showMessage("Restoring document — please wait…")
        thread.start()

    def _on_restore_error(self, error: str):
        self._restore_error = error

    def _on_restore_done(self):
        if self._restore_error:
            QMessageBox.critical(self, "Restore failed", self._restore_error)
            self._restore_error = None
        else:
            QMessageBox.information(self, "Done", f"Restored file saved to:\n{self._restore_out_path}")
        self.statusBar().clearMessage()

    # ------------------------------------------------------------------
    # Window close — stop background threads safely
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        for w in self._workers:
            if hasattr(w, 'cancel'):
                w.cancel()
        for t in self._threads:
            t.quit()
            t.wait(5000)
        event.accept()
