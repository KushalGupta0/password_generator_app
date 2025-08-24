"""
Main Dashboard UI
Provides password generation & storage view with scrollable vault
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QTextEdit, QScrollArea, QFrame, QMessageBox
)
from PySide6.QtCore import Qt

from .theme_manager import LightThemeManager


class MainDashboard(QMainWindow):
    """Main application dashboard (after login)"""

    def __init__(self, user_id: int, generator=None, storage=None):
        super().__init__()
        self.user_id = user_id
        self.generator = generator
        self.storage = storage

        self.setWindowTitle("🔐 Password Generator Dashboard")
        self.setMinimumSize(1000, 700)

        LightThemeManager.apply_light_theme(self)

        # Root container
        container = QWidget()
        main_layout = QHBoxLayout(container)

        # Left: Generator Panel
        gen_panel = self._create_generation_panel()
        main_layout.addWidget(gen_panel, 2)

        # Right: Stored Passwords Panel
        storage_panel = self._create_storage_panel()
        main_layout.addWidget(storage_panel, 3)

        self.setCentralWidget(container)

        # Load existing stored passwords
        self._refresh_passwords_list()

    # ======================= GENERATION PANEL =======================

    def _create_generation_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        title = QLabel("🔑 Generate Password")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        # Password length
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(12)
        layout.addWidget(QLabel("Length:"))
        layout.addWidget(self.length_spin)

        # Complexity options
        self.chk_upper = QCheckBox("Include Uppercase")
        self.chk_lower = QCheckBox("Include Lowercase")
        self.chk_digit = QCheckBox("Include Digits")
        self.chk_special = QCheckBox("Include Special")
        self.chk_upper.setChecked(True)
        self.chk_lower.setChecked(True)
        self.chk_digit.setChecked(True)

        layout.addWidget(self.chk_upper)
        layout.addWidget(self.chk_lower)
        layout.addWidget(self.chk_digit)
        layout.addWidget(self.chk_special)

        # Generate button
        self.btn_generate = QPushButton("Generate")
        self.btn_generate.clicked.connect(self._handle_generate)
        layout.addWidget(self.btn_generate)

        # Generated password display
        self.generated_display = QLineEdit()
        self.generated_display.setReadOnly(True)
        layout.addWidget(QLabel("Generated Password:"))
        layout.addWidget(self.generated_display)

        # Save form (username + site optional + notes)
        layout.addWidget(QLabel("Username (required):"))
        self.save_username = QLineEdit()

        layout.addWidget(self.save_username)

        layout.addWidget(QLabel("Site (optional):"))
        self.save_site = QLineEdit()

        layout.addWidget(self.save_site)

        layout.addWidget(QLabel("Notes (optional):"))
        self.save_notes = QTextEdit()
        self.save_notes.setFixedHeight(60)
        layout.addWidget(self.save_notes)

        self.btn_save = QPushButton("💾 Save Password")
        self.btn_save.clicked.connect(self._handle_save)
        layout.addWidget(self.btn_save)

        layout.addStretch()
        return panel

    def _handle_generate(self):
        """Handle password generation"""
        complexity = {
            'uppercase': self.chk_upper.isChecked(),
            'lowercase': self.chk_lower.isChecked(),
            'digits': self.chk_digit.isChecked(),
            'special': self.chk_special.isChecked()
        }

        if self.generator:
            result = self.generator.generate_password(
                length=self.length_spin.value(),
                complexity=complexity
            )
            if result['success']:
                self.generated_password = result['password']
                self.generated_display.setText(self.generated_password)
            else:
                QMessageBox.critical(self, "Error", result.get("error", "Generation failed"))

    def _handle_save(self):
        """Save generated password to vault"""
        if not hasattr(self, "generated_password") or not self.generated_password:
            QMessageBox.warning(self, "Error", "No password generated yet.")
            return

        username = self.save_username.text().strip()
        site = self.save_site.text().strip()
        notes = self.save_notes.toPlainText().strip()

        if not username:
            QMessageBox.warning(self, "Error", "Username is required to save a password.")
            return

        if self.storage:
            result = self.storage.save_password(
                user_id=self.user_id,
                username_for_site=username,
                raw_password=self.generated_password,
                site_name=site,
                notes=notes,
                length=len(self.generated_password),
                complexity_used=str({
                    'upper': self.chk_upper.isChecked(),
                    'lower': self.chk_lower.isChecked(),
                    'digit': self.chk_digit.isChecked(),
                    'special': self.chk_special.isChecked()
                })
            )
            if result.get("success"):
                QMessageBox.information(self, "Success", result["message"])
                self._refresh_passwords_list()
            else:
                QMessageBox.critical(self, "Error", result.get("error", "Save failed"))

    # ======================= STORAGE PANEL =======================

    def _create_storage_panel(self) -> QWidget:
        wrapper = QWidget()
        layout = QVBoxLayout(wrapper)

        title = QLabel("🗄️ Stored Passwords")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        # Scroll area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)

        self.passwords_container = QWidget()
        self.passwords_layout = QVBoxLayout(self.passwords_container)
        self.passwords_layout.setAlignment(Qt.AlignTop)

        self.scroll.setWidget(self.passwords_container)
        layout.addWidget(self.scroll)

        return wrapper

    def _refresh_passwords_list(self):
        """Refresh displayed stored passwords metadata"""
        # Clear existing items
        for i in reversed(range(self.passwords_layout.count())):
            widget = self.passwords_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if self.storage:
            result = self.storage.get_user_passwords(self.user_id)
            if result.get("success"):
                entries = result.get("entries", [])
                for entry in entries:
                    self._add_password_widget(entry)

    def _add_password_widget(self, entry: dict):
        """Add a single stored password metadata block"""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("background: #ffffff; border: 1px solid #ccc; padding: 8px;")

        vbox = QVBoxLayout(frame)
        vbox.addWidget(QLabel(f"👤 Username: {entry['username_for_site']}"))
        if entry['site_name']:
            vbox.addWidget(QLabel(f"🌐 Site: {entry['site_name']}"))
        vbox.addWidget(QLabel(f"🔒 Length: {entry['password_length']} characters"))
        if entry.get("notes"):
            vbox.addWidget(QLabel(f"📝 Notes: {entry['notes']}"))
        vbox.addWidget(QLabel(f"⏱ Created: {entry['created_at']}"))

        self.passwords_layout.addWidget(frame)

