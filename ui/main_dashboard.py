"""
Main Dashboard UI
Provides password generation & storage view with scrollable vault and password viewing
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QTextEdit, QScrollArea, QFrame, QMessageBox, QInputDialog
)
from PySide6.QtCore import Qt, Signal

from .theme_manager import LightThemeManager


class MainDashboard(QMainWindow):
    """Main application dashboard (after login) with password viewing capability"""

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

        # Copy to clipboard button
        self.btn_copy = QPushButton("📋 Copy to Clipboard")
        self.btn_copy.setFixedHeight(30)
        self.btn_copy.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                font-size: 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        self.btn_copy.clicked.connect(self._copy_to_clipboard)
        layout.addWidget(self.btn_copy)

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
                QMessageBox.information(self, "Password Generated", 
                                      f"New password generated!\nStrength: {result.get('metadata', {}).get('strength_analysis', {}).get('strength', 'Good')}")
            else:
                QMessageBox.critical(self, "Generation Error", 
                                   result.get("error", "Password generation failed"))
        else:
            QMessageBox.critical(self, "Error", "Password generator not available")

    def _copy_to_clipboard(self):
        """Copy generated password to clipboard"""
        if hasattr(self, 'generated_password') and self.generated_password:
            from PySide6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_password)
            QMessageBox.information(self, "Copied", "Password copied to clipboard!")
        else:
            QMessageBox.warning(self, "No Password", "Generate a password first.")

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

        # Header with title and refresh button
        header_layout = QHBoxLayout()
        title = QLabel("🗄️ Password Vault")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setFixedSize(80, 30)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                font-size: 11px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        refresh_btn.clicked.connect(self._refresh_passwords_list)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)

        # Search functionality
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search passwords...")
        self.search_input.setFixedHeight(30)
        search_layout.addWidget(self.search_input)
        
        search_btn = QPushButton("🔍")
        search_btn.setFixedSize(30, 30)
        search_btn.clicked.connect(self._search_passwords)
        search_layout.addWidget(search_btn)
        
        clear_search_btn = QPushButton("✖")
        clear_search_btn.setFixedSize(30, 30)
        clear_search_btn.clicked.connect(self._clear_search)
        search_layout.addWidget(clear_search_btn)
        
        layout.addLayout(search_layout)

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

    def _search_passwords(self):
        """Search passwords by keyword"""
        keyword = self.search_input.text().strip()
        if not keyword:
            self._refresh_passwords_list()
            return
        
        if self.storage:
            result = self.storage.search_passwords(self.user_id, keyword)
            if result.get("success"):
                self._display_password_entries(result.get("results", []))
            else:
                QMessageBox.warning(self, "Search Error", "Failed to search passwords")

    def _clear_search(self):
        """Clear search and show all passwords"""
        self.search_input.clear()
        self._refresh_passwords_list()

    def _refresh_passwords_list(self):
        """Refresh displayed stored passwords metadata"""
        if self.storage:
            result = self.storage.get_user_passwords(self.user_id)
            if result.get("success"):
                entries = result.get("entries", [])
                self._display_password_entries(entries)

    def _display_password_entries(self, entries):
        """Display password entries in the scroll area"""
        # Clear existing items
        for i in reversed(range(self.passwords_layout.count())):
            widget = self.passwords_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if entries:
            for entry in entries:
                self._add_password_widget(entry)
        else:
            # Show empty state
            empty_label = QLabel("No passwords found.\nGenerate and save your first password!")
            empty_label.setAlignment(Qt.AlignCenter)
            empty_label.setStyleSheet("color: #666666; font-style: italic; padding: 50px;")
            self.passwords_layout.addWidget(empty_label)

    def _add_password_widget(self, entry: dict):
        """Add a single stored password metadata block with view button"""
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
                border: 2px solid #2a82da;
                background-color: #f8f9fa;
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
        created_label = QLabel(f"⏱ Created: {entry['created_at'][:16] if entry['created_at'] else 'Unknown'}")
        created_label.setStyleSheet("font-size: 11px; color: #999999;")
        vbox.addWidget(created_label)

        # Buttons layout
        button_layout = QHBoxLayout()
        
        # View password button
        view_btn = QPushButton("👁 View Password")
        view_btn.setFixedSize(120, 30)
        view_btn.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: white;
                border-radius: 4px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
        """)
        view_btn.clicked.connect(lambda: self._view_password(entry['password_id']))
        button_layout.addWidget(view_btn)

        # Copy username button
        copy_username_btn = QPushButton("📋 Copy Username")
        copy_username_btn.setFixedSize(120, 30)
        copy_username_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border-radius: 4px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        copy_username_btn.clicked.connect(lambda: self._copy_username(entry['username_for_site']))
        button_layout.addWidget(copy_username_btn)

        # Delete button
        delete_btn = QPushButton("🗑 Delete")
        delete_btn.setFixedSize(80, 30)
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border-radius: 4px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        delete_btn.clicked.connect(lambda: self._delete_password(entry['password_id']))
        button_layout.addWidget(delete_btn)

        button_layout.addStretch()
        vbox.addLayout(button_layout)

        self.passwords_layout.addWidget(frame)

    # ======================= PASSWORD ACTIONS =======================

    def _view_password(self, password_id: int):
        """Show password viewing dialog with master password prompt"""
        # Get master password
        master_password, ok = QInputDialog.getText(
            self, "Master Password Required", 
            "Enter your login password to view this password:",
            QLineEdit.Password
        )
        
        if ok and master_password:
            # Try to view password
            result = self.storage.view_password(self.user_id, password_id, master_password)
            
            if result['success']:
                # Show password in secure dialog
                password_dialog = QMessageBox(self)
                password_dialog.setWindowTitle("🔓 Stored Password")
                password_dialog.setIcon(QMessageBox.Information)
                
                # Create formatted message
                message = f"Site: {result.get('site_name', 'N/A')}\n"
                message += f"Username: {result.get('username_for_site', 'N/A')}\n"
                message += f"Password: {result['password']}\n\n"
                message += "⚠️ Password will be hidden when you close this dialog."
                
                password_dialog.setText(message)
                password_dialog.setStandardButtons(QMessageBox.Ok)
                
                # Auto-copy password to clipboard
                from PySide6.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(result['password'])
                
                password_dialog.setInformativeText("Password has been copied to clipboard.")
                password_dialog.exec()
                
            else:
                # Show error or info message
                if "recently generated" in result.get('error', '').lower():
                    QMessageBox.information(self, "Password Viewing", result['error'])
                else:
                    QMessageBox.warning(self, "Cannot View Password", result.get('error', 'Unable to view password'))

    def _copy_username(self, username: str):
        """Copy username to clipboard"""
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(username)
        QMessageBox.information(self, "Copied", f"Username '{username}' copied to clipboard!")

    def _delete_password(self, password_id: int):
        """Delete password with confirmation"""
        reply = QMessageBox.question(
            self, "Confirm Delete", 
            "Are you sure you want to delete this password?\n\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.storage:
                result = self.storage.delete_password(self.user_id, password_id)
                if result['success']:
                    QMessageBox.information(self, "Deleted", "Password deleted successfully!")
                    self._refresh_passwords_list()
                else:
                    QMessageBox.critical(self, "Delete Error", result.get('error', 'Failed to delete password'))
