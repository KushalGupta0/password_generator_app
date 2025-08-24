"""
Core Package - Password Generator Application
Contains authentication, password generation, and storage logic
"""

from .auth_manager import AuthenticationManager, AuthenticationError, SessionError, RegistrationError
from .password_generator import PasswordGenerator
from .password_storage import PasswordStorageManager

# Package metadata
__version__ = "1.0.0"
CORE_PACKAGE_NAME = "password_generator.core"

# Exports
__all__ = [
    # Managers
    'AuthenticationManager',
    'PasswordGenerator',
    'PasswordStorageManager',
    
    # Exceptions
    'AuthenticationError',
    'SessionError',
    'RegistrationError'
]

# Package-level constants
DEFAULT_PASSWORD_POLICY = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_special': True
}

# Logging setup
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Package Documentation
"""
Core functionalities provided by this package:

🔐 **AuthenticationManager**
  - User registration & login
  - Password strength validation
  - Session management (tokens, expiration)
  - Account lockout protections

🎲 **PasswordGenerator**
  - Cryptographically secure password generation
  - Customizable complexity & character sets
  - Preset modes (basic, high_security, pin_code)
  - Entropy & security metadata

🗄️ **PasswordStorageManager**
  - Securely store generated passwords (hashed)
  - Fetch metadata for stored entries
  - Search, count & delete password records
  - Ensure no plaintext password exposure

⚠️ **Exceptions**
  - AuthenticationError → Raised for login/registration issues
  - SessionError → Raised for session validation issues
  - RegistrationError → Raised for account creation failures

Example Usage:
--------------
from core import AuthenticationManager, PasswordGenerator, PasswordStorageManager

# Initialize managers
auth = AuthenticationManager()
generator = PasswordGenerator()
storage = PasswordStorageManager()

# Register user
result = auth.register_user("john_doe", "StrongPass123!")

# Login
login_result = auth.authenticate_user("john_doe", "StrongPass123!")

# Generate password
gen_result = generator.generate_password(length=16)

# Save generated password
if gen_result['success']:
    storage.save_password(
        user_id=login_result['user_id'],
        username_for_site="john.doe@email.com",
        raw_password=gen_result['password'],
        site_name="Example",
        notes="Primary account"
    )
"""
