"""
Main Dashboard UI
Provides password generation & storage view with scrollable vault and logout functionality
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QTextEdit, QScrollArea, QFrame, QMessageBox
)
from PySide6.QtCore import Qt, Signal

from .theme_manager import LightThemeManager


class MainDashboard(QMainWindow):
    """Main application dashboard (after login)"""

    # Signal emitted when user requests logout
    logout_requested = Signal()

    def __init__(self, user_id: int, generator=None, storage=None):
        super().__init__()
        self.user_id = user_id
        self.generator = generator
        self.storage = storage

        self.setWindowTitle("🔐 Password Generator Dashboard")
        self.setMinimumSize(1000, 700)

        LightThemeManager.apply_light_theme(self)

        # Create main container with top bar
        main_container = QWidget()
        main_layout = QVBoxLayout(main_container)

        # Add top bar with user info and logout button
        top_bar = self._create_top_bar()
        main_layout.addWidget(top_bar)

        # Add main content area
        content_container = QWidget()
        content_layout = QHBoxLayout(content_container)

        # Left: Generator Panel
        gen_panel = self._create_generation_panel()
        content_layout.addWidget(gen_panel, 2)

        # Right: Stored Passwords Panel
        storage_panel = self._create_storage_panel()
        content_layout.addWidget(storage_panel, 3)

        main_layout.addWidget(content_container)
        self.setCentralWidget(main_container)

        # Load existing stored passwords
        self._refresh_passwords_list()

    # ======================= TOP BAR WITH LOGOUT =======================

    def _create_top_bar(self) -> QWidget:
        """Create top bar with user info and logout button"""
        top_bar = QWidget()
        top_bar.setFixedHeight(50)
        top_bar.setStyleSheet("background-color: #f5f5f5; border-bottom: 1px solid #cccccc;")
        
        layout = QHBoxLayout(top_bar)
        layout.setContentsMargins(15, 5, 15, 5)
        
        # User info label
        user_info = QLabel(f"👤 User ID: {self.user_id}")
        user_info.setStyleSheet("font-weight: bold; color: #2a82da; font-size: 14px;")
        layout.addWidget(user_info)
        
        # App title in center
        app_title = QLabel("🔐 Secure Password Generator")
        app_title.setStyleSheet("font-weight: bold; color: #333333; font-size: 16px;")
        app_title.setAlignment(Qt.AlignCenter)
        layout.addWidget(app_title)
        
        # Spacer
        layout.addStretch()
        
        # Logout button
        self.logout_btn = QPushButton("🚪 Logout")
        self.logout_btn.setFixedSize(100, 35)
        self.logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        self.logout_btn.clicked.connect(self._handle_logout)
        layout.addWidget(self.logout_btn)
        
        return top_bar

    def _handle_logout(self):
        """Handle logout button click with confirmation"""
        # Show confirmation dialog
        reply = QMessageBox.question(
            self, 
            "Confirm Logout", 
            "Are you sure you want to logout?\n\nAll unsaved changes will be lost.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.logout_requested.emit()

    # ======================= GENERATION PANEL =======================

    def _create_generation_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("🔑 Generate Password")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        # Password length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Password Length:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(12)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        layout.addLayout(length_layout)

        layout.addWidget(QLabel("Character Types:"))

        # Complexity options with improved styling
        self.chk_upper = QCheckBox("Include Uppercase Letters (A-Z)")
        self.chk_lower = QCheckBox("Include Lowercase Letters (a-z)")
        self.chk_digit = QCheckBox("Include Numbers (0-9)")
        self.chk_special = QCheckBox("Include Special Characters (!@#$%)")
        
        # Set default selections
        self.chk_upper.setChecked(True)
        self.chk_lower.setChecked(True)
        self.chk_digit.setChecked(True)

        # Style checkboxes
        checkbox_style = "QCheckBox { font-size: 13px; margin: 3px 0px; }"
        self.chk_upper.setStyleSheet(checkbox_style)
        self.chk_lower.setStyleSheet(checkbox_style)
        self.chk_digit.setStyleSheet(checkbox_style)
        self.chk_special.setStyleSheet(checkbox_style)

        layout.addWidget(self.chk_upper)
        layout.addWidget(self.chk_lower)
        layout.addWidget(self.chk_digit)
        layout.addWidget(self.chk_special)

        # Generate button
        self.btn_generate = QPushButton("🎲 Generate Password")
        self.btn_generate.setFixedHeight(40)
        self.btn_generate.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                font-weight: bold;
                font-size: 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        self.btn_generate.clicked.connect(self._handle_generate)
        layout.addWidget(self.btn_generate)

        # Generated password display
        layout.addWidget(QLabel("Generated Password:"))
        self.generated_display = QLineEdit()
        self.generated_display.setReadOnly(True)
        self.generated_display.setStyleSheet("font-family: monospace; font-size: 12px;")
        layout.addWidget(self.generated_display)

        # Save form section
        save_section = QLabel("💾 Save to Vault")
        save_section.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 15px;")
        layout.addWidget(save_section)

        layout.addWidget(QLabel("Username (required):"))
        self.save_username = QLineEdit()
        self.save_username.setPlaceholderText("e.g., john.doe@email.com")
        layout.addWidget(self.save_username)

        layout.addWidget(QLabel("Site Name (optional):"))
        self.save_site = QLineEdit()
        self.save_site.setPlaceholderText("e.g., Gmail, Facebook, GitHub")
        layout.addWidget(self.save_site)

        layout.addWidget(QLabel("Notes (optional):"))
        self.save_notes = QTextEdit()
        self.save_notes.setFixedHeight(60)
        self.save_notes.setPlaceholderText("Any additional information...")
        layout.addWidget(self.save_notes)

        self.btn_save = QPushButton("💾 Save to Vault")
        self.btn_save.setFixedHeight(35)
        self.btn_save.setStyleSheet("""
            QPushButton {
                background-color: #2a82da;
                color: white;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1e5ea8;
            }
        """)
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

        # Check if at least one character type is selected
        if not any(complexity.values()):
            QMessageBox.warning(self, "Invalid Selection", 
                              "Please select at least one character type.")
            return

        if self.generator:
            result = self.generator.generate_password(
                length=self.length_spin.value(),
                complexity=complexity
            )
            if result['success']:
                self.generated_password = result['password']
                self.generated_display.setText(self.generated_password)
            else:
                QMessageBox.critical(self, "Generation Error", 
                                   result.get("error", "Password generation failed"))
        else:
            QMessageBox.critical(self, "Error", "Password generator not available")

    def _handle_save(self):
        """Save generated password to vault"""
        if not hasattr(self, "generated_password") or not self.generated_password:
            QMessageBox.warning(self, "No Password", 
                              "Please generate a password first.")
            return

        username = self.save_username.text().strip()
        site = self.save_site.text().strip()
        notes = self.save_notes.toPlainText().strip()

        if not username:
            QMessageBox.warning(self, "Missing Information", 
                              "Username is required to save a password.")
            return

        if self.storage:
            result = self.storage.save_password(
                user_id=self.user_id,
                username_for_site=username,
                raw_password=self.generated_password,
                site_name=site if site else None,
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
                QMessageBox.information(self, "Success", "Password saved to vault successfully!")
                # Clear form fields
                self.save_username.clear()
                self.save_site.clear()
                self.save_notes.clear()
                self.generated_display.clear()
                if hasattr(self, 'generated_password'):
                    delattr(self, 'generated_password')
                # Refresh the password list
                self._refresh_passwords_list()
            else:
                QMessageBox.critical(self, "Save Error", 
                                   result.get("error", "Failed to save password"))
        else:
            QMessageBox.critical(self, "Error", "Password storage not available")

    # ======================= STORAGE PANEL =======================

    def _create_storage_panel(self) -> QWidget:
        wrapper = QWidget()
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("🗄️ Password Vault")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        # Scroll area for password entries
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("QScrollArea { border: 1px solid #cccccc; }")

        self.passwords_container = QWidget()
        self.passwords_layout = QVBoxLayout(self.passwords_container)
        self.passwords_layout.setAlignment(Qt.AlignTop)
        self.passwords_layout.setSpacing(10)

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
                if entries:
                    for entry in entries:
                        self._add_password_widget(entry)
                else:
                    # Show empty state
                    empty_label = QLabel("No passwords saved yet.\nGenerate and save your first password!")
                    empty_label.setAlignment(Qt.AlignCenter)
                    empty_label.setStyleSheet("color: #666666; font-style: italic; padding: 50px;")
                    self.passwords_layout.addWidget(empty_label)

    def _add_password_widget(self, entry: dict):
        """Add a single stored password metadata block"""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #dddddd;
                border-radius: 5px;
                padding: 10px;
                margin: 2px;
            }
            QFrame:hover {
                border: 1px solid #2a82da;
                box-shadow: 0px 2px 4px rgba(0,0,0,0.1);
            }
        """)

        vbox = QVBoxLayout(frame)
        vbox.setSpacing(5)

        # Username (main info)
        username_label = QLabel(f"👤 {entry['username_for_site']}")
        username_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2a82da;")
        vbox.addWidget(username_label)

        # Site name (if provided)
        if entry['site_name']:
            site_label = QLabel(f"🌐 {entry['site_name']}")
            site_label.setStyleSheet("font-size: 13px; color: #333333;")
            vbox.addWidget(site_label)

        # Password info
        length_label = QLabel(f"🔒 {entry['password_length']} characters")
        length_label.setStyleSheet("font-size: 12px; color: #666666;")
        vbox.addWidget(length_label)

        # Notes (if provided)
        if entry.get("notes"):
            notes_label = QLabel(f"📝 {entry['notes'][:50]}{'...' if len(entry['notes']) > 50 else ''}")
            notes_label.setStyleSheet("font-size: 11px; color: #888888; font-style: italic;")
            vbox.addWidget(notes_label)

        # Creation date
        created_label = QLabel(f"⏱ Created: {entry['created_at'][:16]}")
        created_label.setStyleSheet("font-size: 11px; color: #999999;")
        vbox.addWidget(created_label)

        self.passwords_layout.addWidget(frame)
