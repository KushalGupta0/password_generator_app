"""
Security Package - Password Generator Application
Provides comprehensive cryptographic and security utilities
"""

from .crypto_utils import (
    CryptoManager,
    PasswordValidator,
    SecurityError,
    crypto_manager,
    hash_password,
    verify_password,
    hash_generated_password,
    validate_password_strength
)

# Package version
__version__ = "1.0.0"

# Export main classes and functions
__all__ = [
    # Core classes
    'CryptoManager',
    'PasswordValidator', 
    'SecurityError',
    
    # Global instance
    'crypto_manager',
    
    # Convenience functions
    'hash_password',
    'verify_password',
    'hash_generated_password',
    'validate_password_strength',
    
    # Security utilities
    'generate_secure_password',
    'check_password_breach',
    'sanitize_input'
]

# Package-level constants
SECURITY_PACKAGE_NAME = "password_generator.security"
MIN_SECURE_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
SESSION_TIMEOUT_MINUTES = 30

# Initialize logging for the entire security package
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Additional security utilities
def generate_secure_password(length: int = 12, complexity: dict = None) -> str:
    """
    Generate a cryptographically secure password
    
    Args:
        length: Password length (default 12)
        complexity: Dict with character type requirements
    
    Returns:
        Secure random password string
    """
    import secrets
    import string
    
    if complexity is None:
        complexity = {
            'lowercase': True,
            'uppercase': True,
            'digits': True,
            'special': True
        }
    
    # Build character pool
    chars = ""
    if complexity.get('lowercase', True):
        chars += string.ascii_lowercase
    if complexity.get('uppercase', True):
        chars += string.ascii_uppercase
    if complexity.get('digits', True):
        chars += string.digits
    if complexity.get('special', False):
        chars += "!@#$%^&*()_+-="
    
    if not chars:
        chars = string.ascii_letters + string.digits
    
    # Ensure at least one character from each required type
    password = []
    if complexity.get('lowercase', True) and string.ascii_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if complexity.get('uppercase', True) and string.ascii_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if complexity.get('digits', True) and string.digits:
        password.append(secrets.choice(string.digits))
    if complexity.get('special', False):
        password.append(secrets.choice("!@#$%^&*()_+-="))
    
    # Fill remaining length
    while len(password) < length:
        password.append(secrets.choice(chars))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def check_password_breach(password_hash: str) -> dict:
    """
    Check if password appears in known breach databases
    Note: This is a placeholder - in production, integrate with HaveIBeenPwned API
    
    Args:
        password_hash: SHA-1 hash of password to check
    
    Returns:
        Dict with breach status and count
    """
    # Placeholder implementation
    # In production, implement proper API integration
    return {
        'is_breached': False,
        'breach_count': 0,
        'checked_at': None,
        'status': 'not_implemented'
    }


def sanitize_input(user_input: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        user_input: Raw user input string
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    """
    if not isinstance(user_input, str):
        return ""
    
    # Truncate to max length
    sanitized = user_input[:max_length]
    
    # Remove potential dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    # Strip whitespace
    return sanitized.strip()


def secure_delete_string(sensitive_string: str) -> None:
    """
    Attempt to securely delete sensitive string from memory
    Note: Python's garbage collection makes this difficult to guarantee
    
    Args:
        sensitive_string: String containing sensitive data
    """
    try:
        # Overwrite string memory (limited effectiveness in Python)
        if sensitive_string:
            # Create a new string of same length with random data
            import secrets
            overwrite_data = secrets.token_hex(len(sensitive_string))
            # This is more of a psychological security measure in Python
            sensitive_string = overwrite_data
            del overwrite_data
            del sensitive_string
    except Exception:
        pass  # Fail silently for security operations


# Security configuration validation
def validate_security_config() -> dict:
    """
    Validate current security configuration
    
    Returns:
        Dict with validation results and recommendations
    """
    from app_config import BCRYPT_ROUNDS, MIN_LOGIN_PASSWORD_LENGTH
    
    issues = []
    warnings = []
    
    # Check bcrypt rounds
    if BCRYPT_ROUNDS < 10:
        issues.append("bcrypt rounds too low - increase for better security")
    elif BCRYPT_ROUNDS > 15:
        warnings.append("bcrypt rounds very high - may impact performance")
    
    # Check minimum password length
    if MIN_LOGIN_PASSWORD_LENGTH < 8:
        issues.append("minimum password length too short")
    
    return {
        'is_secure': len(issues) == 0,
        'issues': issues,
        'warnings': warnings,
        'bcrypt_rounds': BCRYPT_ROUNDS,
        'min_password_length': MIN_LOGIN_PASSWORD_LENGTH
    }


# Package initialization
def _initialize_security_package():
    """Initialize security package with proper logging and validation"""
    logger = logging.getLogger(__name__)
    
    # Validate security configuration
    config_status = validate_security_config()
    if not config_status['is_secure']:
        logger.warning(f"Security configuration issues: {config_status['issues']}")
    
    # Log package initialization
    logger.info(f"Security package v{__version__} initialized")
    
    return True


# Auto-initialize on import
_security_initialized = _initialize_security_package()

# Package documentation
__doc__ = """
Security Package for Password Generator Application

This package provides comprehensive security utilities including:

🔐 **Password Security**:
    - Bcrypt hashing for authentication
    - SHA-256 hashing for generated passwords
    - Password strength validation
    - Entropy calculation

🛡️ **Cryptographic Operations**:
    - Secure token generation
    - Session management
    - Timing-attack resistant comparisons
    - Input sanitization

🔑 **Security Validation**:
    - Password breach checking (placeholder)
    - Common password detection
    - Pattern analysis
    - Security configuration validation

Example Usage:
    from security import hash_password, validate_password_strength
    
    # Hash a password
    result = hash_password("my_secure_password")
    hashed = result['hashed_password']
    salt = result['salt']
    
    # Validate password strength
    strength = validate_password_strength("TestPassword123!")
    if strength['is_strong']:
        print(f"Password strength: {strength['strength']}")
    
    # Generate secure password
    secure_pwd = generate_secure_password(16, {
        'lowercase': True,
        'uppercase': True, 
        'digits': True,
        'special': True
    })

Security Features:
    ✅ Configurable bcrypt rounds
    ✅ Multiple hashing algorithms
    ✅ Secure random generation
    ✅ Input validation and sanitization
    ✅ Memory security considerations
    ✅ Comprehensive password analysis
"""
