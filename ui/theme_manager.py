"""
UI Theme Manager
Forces Light Theme styling across entire PySide6 application
"""

from PySide6.QtGui import QPalette, QColor
from PySide6.QtWidgets import QApplication


class LightThemeManager:
    """Handles enforcing light theme across the entire UI"""

    @staticmethod
    def apply_light_theme(app: QApplication):
        """Force application to always use light theme"""
        palette = QPalette()

        # Window colors
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 220))
        palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
        palette.setColor(QPalette.Text, QColor(0, 0, 0))
        palette.setColor(QPalette.Button, QColor(230, 230, 230))
        palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))

        app.setPalette(palette)

        # Apply stylesheet for consistency
        app.setStyleSheet(LightThemeManager.get_stylesheet())

    @staticmethod
    def get_stylesheet() -> str:
        """Returns CSS-style stylesheet for consistent UI look"""
        return """
        QMainWindow {
            background-color: #f0f0f0;
            color: #000000;
        }
        QWidget {
            background-color: #ffffff;
            color: #000000;
        }
        QPushButton {
            background-color: #e6e6e6;
            border: 1px solid #cccccc;
            padding: 6px;
            border-radius: 4px;
            color: #000000;
        }
        QPushButton:hover {
            background-color: #d9d9d9;
        }
        QPushButton:pressed {
            background-color: #cccccc;
        }
        QLineEdit, QTextEdit, QSpinBox, QComboBox {
            background-color: #ffffff;
            border: 1px solid #cccccc;
            padding: 5px;
            border-radius: 3px;
            color: #000000;
        }
        QScrollArea {
            background-color: #ffffff;
            border: 1px solid #cccccc;
        }
        QLabel {
            color: #000000;
        }
        QTabBar::tab {
            background: #e6e6e6;
            padding: 8px;
            border: 1px solid #cccccc;
            border-bottom: none;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            border-top: 2px solid #2a82da;
        }
        """
