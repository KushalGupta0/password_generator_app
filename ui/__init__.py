"""
UI Package - Password Generator Application
Contains all PySide6 user interface components
"""

from .theme_manager import LightThemeManager
from .login_window import LoginWindow
from .main_dashboard import MainDashboard

# Package metadata
__version__ = "1.0.0"
UI_PACKAGE_NAME = "password_generator.ui"

# Public exports
__all__ = [
    'LightThemeManager',
    'LoginWindow',
    'MainDashboard'
]

# Logging setup
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Package Documentation
"""
This UI package provides the graphical interface for the Password Generator application.

🎨 **LightThemeManager**
  - Forces application-wide light theme
  - Applies consistent widget styling
  - Prevents dark system themes from affecting UI

🔑 **LoginWindow**
  - Tab-based interface for Login and Register
  - Connects with AuthenticationManager for user flow
  - Emits `login_successful(user_id)` signal upon successful login

🗄️ **MainDashboard**
  - After login, provides main working interface
  - Left panel: Password generation (length, complexity, generate, save)
  - Right panel: Scrollable stored passwords metadata
  - Saves passwords securely through PasswordStorageManager

Example Usage
-------------
from ui import LoginWindow, MainDashboard, LightThemeManager

# Apply theme
LightThemeManager.apply_light_theme(app)

# Show login
login = LoginWindow(auth_manager)
login.show()

# On success, show dashboard
login.login_successful.connect(lambda uid: MainDashboard(uid, generator, storage).show())
"""
