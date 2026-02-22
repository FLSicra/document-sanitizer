import sys
import os
import platform


def main():
    # Ensure the project root is on sys.path when running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    # Load spaCy model eagerly to surface errors before the GUI starts
    try:
        import spacy
        from utils.spacy_loader import get_spacy_model_name
        spacy.load(get_spacy_model_name())
    except Exception as e:
        print(
            f"ERROR: Failed to load spaCy model: {e}\n"
            "Run: python -m spacy download en_core_web_lg",
            file=sys.stderr,
        )
        sys.exit(1)

    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QIcon
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Document Sanitizer")
    app.setOrganizationName("DocSanitizer")

    # Set application icon (platform-aware for dock/taskbar display)
    system = platform.system()
    if system == "Darwin":
        icon_file = os.path.join(base_dir, "icons", "app.icns")
    elif system == "Windows":
        icon_file = os.path.join(base_dir, "app.ico")
    else:
        icon_file = os.path.join(base_dir, "icons", "app.png")
    if os.path.exists(icon_file):
        app.setWindowIcon(QIcon(icon_file))

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
