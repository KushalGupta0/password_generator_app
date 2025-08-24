"""
Main Application Entry Point
Initializes database, core managers, and launches UI
"""

import sys
from PySide6.QtWidgets import QApplication

# Import UI
from ui import LoginWindow, MainDashboard, LightThemeManager

# Import Core
from core import AuthenticationManager, PasswordGenerator, PasswordStorageManager

# Import Database
from database import DatabaseManager


class PasswordGeneratorApp:
    """Main Application Controller"""

    def __init__(self):
        # Create app instance
        self.app = QApplication(sys.argv)

        # Force light theme
        LightThemeManager.apply_light_theme(self.app)

        # Init database
        self.db = DatabaseManager()
        self.db.initialize_database()

        # Core managers
        self.auth_manager = AuthenticationManager(self.db)
        self.generator = PasswordGenerator()
        self.storage = PasswordStorageManager(self.db)

        # Start login window
        self.show_login()

    # ---------------- LOGIN ----------------
    def show_login(self):
        self.login_window = LoginWindow(auth_manager=self.auth_manager)
        self.login_window.login_successful.connect(self.on_login_success)
        self.login_window.show()

    def on_login_success(self, user_id: int):
        """Called when login is successful"""
        self.login_window.close()
        self.show_dashboard(user_id)

    # ---------------- DASHBOARD ----------------
    def show_dashboard(self, user_id: int):
        self.dashboard = MainDashboard(
            user_id=user_id,
            generator=self.generator,
            storage=self.storage
        )
        self.dashboard.show()

    # ---------------- RUN ----------------
    def run(self):
        return self.app.exec()


if __name__ == "__main__":
    app = PasswordGeneratorApp()
    sys.exit(app.run())
