"""
Password Generator Application Configuration
Contains all application constants, settings, and configuration parameters
"""

# Application Information
APP_TITLE = "Secure Password Generator"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Your Name"

# Database Configuration
DATABASE_FILE = "password_vault.db"
DATABASE_TIMEOUT = 30  # seconds

# Password Generation Settings
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSWORD_LENGTH = 12

# Character Sets for Password Generation
CHARACTER_SETS = {
    'lowercase': 'abcdefghijklmnopqrstuvwxyz',
    'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 
    'digits': '0123456789',
    'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
}

# Default Password Complexity
DEFAULT_COMPLEXITY = {
    'lowercase': True,
    'uppercase': True,
    'digits': True,
    'special': False
}

# UI Window Settings
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700
MIN_WINDOW_WIDTH = 800
MIN_WINDOW_HEIGHT = 600

# Login Window Settings
LOGIN_WINDOW_WIDTH = 400
LOGIN_WINDOW_HEIGHT = 350
LOGIN_WINDOW_MIN_WIDTH = 350
LOGIN_WINDOW_MIN_HEIGHT = 300

# UI Component Settings
SCROLL_AREA_MAX_HEIGHT = 500
PASSWORD_ENTRY_HEIGHT = 80
BUTTON_HEIGHT = 35
INPUT_FIELD_HEIGHT = 25

# Validation Rules
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MIN_LOGIN_PASSWORD_LENGTH = 6
MAX_SITE_NAME_LENGTH = 100

# Security Settings
BCRYPT_ROUNDS = 12  # Higher = more secure but slower
SESSION_TIMEOUT = 30  # minutes
MAX_LOGIN_ATTEMPTS = 5  # Maximum allowed login attempts

# UI Theme Colors (Light Theme)
THEME_COLORS = {
    'background': '#f0f0f0',
    'widget_background': '#ffffff',
    'button_background': '#e6e6e6',
    'button_hover': '#d9d9d9',
    'button_pressed': '#cccccc',
    'border': '#cccccc',
    'text': '#000000',
    'accent': '#2a82da',
    'success': '#28a745',
    'warning': '#ffc107',
    'danger': '#dc3545'
}

# Error Messages
ERROR_MESSAGES = {
    'invalid_login': 'Invalid username or password',
    'username_exists': 'Username already exists',
    'weak_password': 'Password must be at least 6 characters',
    'password_mismatch': 'Passwords do not match',
    'empty_fields': 'Please fill in all required fields',
    'database_error': 'Database operation failed',
    'generation_error': 'Failed to generate password'
}

# Success Messages
SUCCESS_MESSAGES = {
    'registration': 'Account created successfully!',
    'login': 'Welcome back!',
    'password_generated': 'Password generated successfully',
    'password_saved': 'Password saved to vault',
    'password_copied': 'Password copied to clipboard'
}

# Logging Configuration
LOG_LEVEL = 'INFO'
LOG_FILE = 'password_generator.log'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
