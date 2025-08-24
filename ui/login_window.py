"""
Login & Register UI
Provides user login and registration interface (forced light theme)
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QTabWidget,
    QMessageBox
)
from PySide6.QtCore import Signal, Qt

from .theme_manager import LightThemeManager


class LoginWindow(QMainWindow):
    """Login and Registration interface"""

    # Signal emitted when user successfully logs in
    login_successful = Signal(int)  # will carry user_id

    def __init__(self, auth_manager=None):
        super().__init__()
        self.auth_manager = auth_manager

        self.setWindowTitle("🔐 Password Generator - Login")
        self.setFixedSize(400, 320)

        # Apply forced light theme
        LightThemeManager.apply_light_theme(self)

        # Tabs for Login & Register
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_login_tab(), "Login")
        self.tabs.addTab(self._create_register_tab(), "Register")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.addWidget(self.tabs)
        self.setCentralWidget(container)

    # ======================= LOGIN TAB =======================

    def _create_login_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        form = QFormLayout()
        self.login_username = QLineEdit()
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)

        form.addRow("Username:", self.login_username)
        form.addRow("Password:", self.login_password)

        layout.addLayout(form)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self._handle_login)
        layout.addWidget(self.login_btn, alignment=Qt.AlignCenter)

        return widget

    def _handle_login(self):
        username = self.login_username.text().strip()
        password = self.login_password.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please fill all fields")
            return

        # Authenticate via auth_manager
        if self.auth_manager:
            result = self.auth_manager.authenticate_user(username, password)
            if result.get("success"):
                QMessageBox.information(self, "Success", result["message"])
                self.login_successful.emit(result["user_id"])  # pass user_id to dashboard
                self.close()
            else:
                QMessageBox.critical(self, "Login Failed", result.get("error", "Unknown error"))

    # ======================= REGISTER TAB =======================

    def _create_register_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        form = QFormLayout()
        self.reg_username = QLineEdit()
        self.reg_email = QLineEdit()
        self.reg_password = QLineEdit()
        self.reg_password.setEchoMode(QLineEdit.Password)
        self.reg_confirm_password = QLineEdit()
        self.reg_confirm_password.setEchoMode(QLineEdit.Password)

        form.addRow("Username:", self.reg_username)
        form.addRow("Email (optional):", self.reg_email)
        form.addRow("Password:", self.reg_password)
        form.addRow("Confirm Password:", self.reg_confirm_password)

        layout.addLayout(form)

        self.reg_btn = QPushButton("Register")
        self.reg_btn.clicked.connect(self._handle_register)
        layout.addWidget(self.reg_btn, alignment=Qt.AlignCenter)

        return widget

    def _handle_register(self):
        username = self.reg_username.text().strip()
        email = self.reg_email.text().strip()
        password = self.reg_password.text().strip()
        confirm = self.reg_confirm_password.text().strip()

        if not username or not password or not confirm:
            QMessageBox.warning(self, "Error", "Please fill all required fields")
            return
        if password != confirm:
            QMessageBox.critical(self, "Error", "Passwords do not match")
            return

        if self.auth_manager:
            result = self.auth_manager.register_user(username, password, email)
            if result.get("success"):
                QMessageBox.information(self, "Success", result["message"])
                # Auto-switch back to login tab
                self.tabs.setCurrentIndex(0)
            else:
                QMessageBox.critical(self, "Registration Failed",
                                     result.get("error", "Unknown error"))
