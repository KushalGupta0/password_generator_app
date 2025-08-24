"""
Main Application Entry Point
Initializes database, core managers, and launches UI with logout handling
"""

import sys
from PySide6.QtWidgets import QApplication, QMessageBox

# Import UI
from ui import LoginWindow, MainDashboard, LightThemeManager

# Import Core
from core import AuthenticationManager, PasswordGenerator, PasswordStorageManager

# Import Database
from database import DatabaseManager


class PasswordGeneratorApp:
    """Main Application Controller with complete session management"""

    def __init__(self):
        # Create app instance
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("Secure Password Generator")
        self.app.setApplicationVersion("1.0.0")

        # Force light theme across entire application
        LightThemeManager.apply_light_theme(self.app)

        # Initialize database
        self.db = DatabaseManager()
        if not self.db.initialize_database():
            QMessageBox.critical(None, "Database Error", 
                               "Failed to initialize database. Application will exit.")
            sys.exit(1)

        # Initialize core managers
        self.auth_manager = AuthenticationManager(self.db)
        self.generator = PasswordGenerator()
        self.storage = PasswordStorageManager(self.db)

        # Session management
        self.current_user_id = None
        self.current_session_token = None
        self.dashboard = None
        self.login_window = None

        # Start with login window
        self.show_login()

    # ======================= LOGIN FLOW =======================

    def show_login(self):
        """Show login window"""
        try:
            # Clean up any existing windows
            if self.dashboard:
                self.dashboard.close()
                self.dashboard = None

            # Create and show login window
            self.login_window = LoginWindow(auth_manager=self.auth_manager)
            self.login_window.login_successful.connect(self.on_login_success)
            self.login_window.show()

        except Exception as e:
            QMessageBox.critical(None, "Application Error", 
                               f"Failed to show login window: {str(e)}")
            sys.exit(1)

    def on_login_success(self, user_id: int):
        """Handle successful login"""
        try:
            # Store session information
            self.current_user_id = user_id
            # If you implement session tokens in the future:
            # self.current_session_token = session_token

            # Close login window
            if self.login_window:
                self.login_window.close()
                self.login_window = None

            # Show main dashboard
            self.show_dashboard(user_id)

        except Exception as e:
            QMessageBox.critical(None, "Login Error", 
                               f"Error during login process: {str(e)}")
            self.show_login()  # Fallback to login

    # ======================= DASHBOARD FLOW =======================

    def show_dashboard(self, user_id: int):
        """Show main application dashboard"""
        try:
            self.dashboard = MainDashboard(
                user_id=user_id,
                generator=self.generator,
                storage=self.storage
            )
            
            # Connect logout signal to logout handler
            self.dashboard.logout_requested.connect(self.handle_logout)
            
            # Show dashboard
            self.dashboard.show()

            print(f"Dashboard opened for user ID: {user_id}")  # Debug info

        except Exception as e:
            QMessageBox.critical(None, "Dashboard Error", 
                               f"Failed to open dashboard: {str(e)}")
            self.show_login()  # Fallback to login

    # ======================= LOGOUT FLOW =======================

    def handle_logout(self):
        """Handle user logout with proper cleanup"""
        try:
            print(f"Logging out user ID: {self.current_user_id}")  # Debug info

            # Perform session cleanup if using session tokens
            if self.current_session_token and self.auth_manager:
                logout_result = self.auth_manager.logout_user(self.current_session_token)
                print(f"Session cleanup result: {logout_result}")

            # Close dashboard
            if self.dashboard:
                self.dashboard.close()
                self.dashboard = None

            # Clean up session data
            self.current_user_id = None
            self.current_session_token = None

            # Show success message
            QMessageBox.information(None, "Logged Out", 
                                  "You have been successfully logged out.")

            # Return to login window
            self.show_login()

        except Exception as e:
            print(f"Error during logout: {e}")
            QMessageBox.warning(None, "Logout Warning", 
                              f"Logout completed but with errors: {str(e)}")
            # Even if there's an error, still show login
            self.show_login()

    # ======================= APPLICATION LIFECYCLE =======================

    def run(self):
        """Start the application event loop"""
        try:
            return self.app.exec()
        except Exception as e:
            QMessageBox.critical(None, "Application Error", 
                               f"Critical application error: {str(e)}")
            return 1

    def cleanup(self):
        """Clean up resources before application exit"""
        try:
            # Clean up session
            if self.current_session_token and self.auth_manager:
                self.auth_manager.logout_user(self.current_session_token)

            # Close all windows
            if self.dashboard:
                self.dashboard.close()
            if self.login_window:
                self.login_window.close()

            # Cleanup database connections if needed
            # self.db.cleanup()  # Implement if needed

        except Exception as e:
            print(f"Error during cleanup: {e}")


def main():
    """Main entry point"""
    app = None
    try:
        app = PasswordGeneratorApp()
        exit_code = app.run()
        return exit_code
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return 0
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1
    finally:
        if app:
            app.cleanup()


if __name__ == "__main__":
    sys.exit(main())
