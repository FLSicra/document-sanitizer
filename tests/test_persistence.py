"""
Tests for persistence fixes:
  - Theme persistence (Fix 1)
  - Profile saving (Fix 2)
  - Audit log (Fix 3)
  - Token conflict detection (Fix 4)
"""
import json
import datetime
from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# Fix 1 — Theme persistence
# ---------------------------------------------------------------------------

class TestThemePersistence:
    def test_qsettings_roundtrip(self, tmp_path, monkeypatch):
        """Writing dark_mode to QSettings and reading it back returns the same value."""
        from PySide6.QtCore import QSettings
        # Use a unique app name so we don't pollute real settings
        s = QSettings("DocumentSanitizerTest", "ThemeTest")
        s.setValue("dark_mode", True)
        s.sync()
        s2 = QSettings("DocumentSanitizerTest", "ThemeTest")
        assert s2.value("dark_mode", False, type=bool) is True
        # cleanup
        s.remove("dark_mode")

    def test_qsettings_default_is_light(self):
        """When dark_mode has never been saved, default is False (light mode)."""
        from PySide6.QtCore import QSettings
        s = QSettings("DocumentSanitizerTest", "ThemeDefaultTest")
        s.remove("dark_mode")
        assert s.value("dark_mode", False, type=bool) is False


# ---------------------------------------------------------------------------
# Fix 2 — Profile saving
# ---------------------------------------------------------------------------

class TestProfileSaving:
    def test_get_state_returns_all_entities_checked(self):
        """get_state() returns all entities as checked by default."""
        # We need a QApplication to create widgets
        import sys
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
        from gui.settings_panel import SettingsPanel, ENTITY_GROUPS
        panel = SettingsPanel()
        state = panel.get_state()
        all_entities = [e for entities in ENTITY_GROUPS.values() for e in entities]
        for entity in all_entities:
            assert state["entities"].get(entity) is True, f"{entity} should be checked by default"
        assert state["custom_terms"] == []

    def test_load_state_restores_unchecked(self):
        """load_state() unchecks entities and does not emit settings_changed."""
        import sys
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
        from gui.settings_panel import SettingsPanel
        panel = SettingsPanel()
        changed_count = [0]
        panel.settings_changed.connect(lambda: changed_count.__setitem__(0, changed_count[0] + 1))

        panel.load_state({
            "entities": {"PERSON": False, "EMAIL_ADDRESS": True},
            "custom_terms": ["secret-term"],
        })

        assert panel._checkboxes["PERSON"].isChecked() is False
        assert panel._checkboxes["EMAIL_ADDRESS"].isChecked() is True
        assert "secret-term" in panel._custom_terms
        # load_state must not fire settings_changed
        assert changed_count[0] == 0

    def test_state_roundtrip(self):
        """get_state / load_state roundtrip preserves values."""
        import sys
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
        from gui.settings_panel import SettingsPanel
        p1 = SettingsPanel()
        p1._checkboxes["PERSON"].setChecked(False)
        p1._custom_terms.append("internal-api")
        state = p1.get_state()

        p2 = SettingsPanel()
        p2.load_state(state)
        assert p2._checkboxes["PERSON"].isChecked() is False
        assert "internal-api" in p2._custom_terms


# ---------------------------------------------------------------------------
# Fix 3 — Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_log_creates_file(self, tmp_path, monkeypatch):
        """log_sanitization() writes a JSON-Lines record to the audit file."""
        from utils import audit_log
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setattr(audit_log, "_LOG_PATH", log_path)

        from sanitizers.base import Detection
        detections = [
            Detection("PERSON", "John Doe", 0, 8, 0.85, redact=True),
            Detection("EMAIL_ADDRESS", "j@example.com", 9, 22, 0.95, redact=True),
            Detection("LOCATION", "Oslo", 23, 27, 0.7, redact=False),
        ]
        audit_log.log_sanitization(Path("/src/doc.pdf"), Path("/out/doc_sanitized.pdf"), detections)

        assert log_path.exists()
        record = json.loads(log_path.read_text())
        assert record["redacted_count"] == 2
        assert record["entity_types"]["PERSON"] == 1
        assert record["entity_types"]["EMAIL_ADDRESS"] == 1
        assert "LOCATION" not in record["entity_types"]
        assert record["source"].endswith("doc.pdf")

    def test_log_appends(self, tmp_path, monkeypatch):
        """Multiple calls append separate lines."""
        from utils import audit_log
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setattr(audit_log, "_LOG_PATH", log_path)

        from sanitizers.base import Detection
        d = Detection("PERSON", "Jane", 0, 4, 0.9, redact=True)
        audit_log.log_sanitization(Path("/a.txt"), Path("/a_s.txt"), [d])
        audit_log.log_sanitization(Path("/b.txt"), Path("/b_s.txt"), [d])

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_log_has_utc_timestamp(self, tmp_path, monkeypatch):
        """Timestamps are ISO-8601 UTC."""
        from utils import audit_log
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setattr(audit_log, "_LOG_PATH", log_path)

        audit_log.log_sanitization(Path("/x.txt"), Path("/x_s.txt"), [])
        record = json.loads(log_path.read_text())
        ts = datetime.datetime.fromisoformat(record["timestamp"])
        assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# Fix 4 — Token conflict detection
# ---------------------------------------------------------------------------

class TestTokenConflict:
    def test_initialize_bumps_counters(self):
        """initialize_from_content raises counters past existing tokens in text."""
        from vault.vault import SanitizeSession
        session = SanitizeSession()
        session.initialize_from_content(["Hello [PERSON_3] and [EMAIL_ADDRESS_1] here."])
        # Next PERSON token must be _4, not _1
        from sanitizers.base import Detection
        d = Detection("PERSON", "Alice", 0, 5, 0.9)
        token = session.get_or_create_token(d)
        assert token == "[PERSON_4]"

    def test_initialize_multiple_texts(self):
        """initialize_from_content handles multiple text chunks."""
        from vault.vault import SanitizeSession
        session = SanitizeSession()
        session.initialize_from_content([
            "Page 1: [PERSON_2]",
            "Page 2: [PERSON_5] and [AWS_ACCESS_KEY_10]",
        ])
        from sanitizers.base import Detection
        d_person = Detection("PERSON", "Bob", 0, 3, 0.9)
        d_aws = Detection("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", 0, 20, 0.9)
        assert session.get_or_create_token(d_person) == "[PERSON_6]"
        assert session.get_or_create_token(d_aws) == "[AWS_ACCESS_KEY_11]"

    def test_no_conflict_in_clean_doc(self):
        """When doc has no existing tokens, numbering starts at 1."""
        from vault.vault import SanitizeSession
        session = SanitizeSession()
        session.initialize_from_content(["This document has no tokens in it."])
        from sanitizers.base import Detection
        d = Detection("EMAIL_ADDRESS", "a@b.com", 0, 7, 0.9)
        assert session.get_or_create_token(d) == "[EMAIL_ADDRESS_1]"

    def test_initialize_is_idempotent(self):
        """Calling initialize_from_content twice does not double-count."""
        from vault.vault import SanitizeSession
        session = SanitizeSession()
        text = "[PERSON_3]"
        session.initialize_from_content([text])
        session.initialize_from_content([text])
        from sanitizers.base import Detection
        d = Detection("PERSON", "Carol", 0, 5, 0.9)
        assert session.get_or_create_token(d) == "[PERSON_4]"
