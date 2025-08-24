"""
Cryptography and Security Utilities
Handles password hashing, verification, and security operations
"""

import bcrypt
import secrets
import hashlib
import base64
import logging
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
import os

from app_config import BCRYPT_ROUNDS, SESSION_TIMEOUT


class CryptoManager:
    """Comprehensive cryptography manager for password security"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.bcrypt_rounds = BCRYPT_ROUNDS
    
    # ==================== PASSWORD HASHING ====================
    
    def hash_password(self, password: str, custom_salt: str = None) -> Dict[str, str]:
        """
        Hash password using bcrypt with optional custom salt
        Returns both hash and salt for storage
        """
        try:
            if not password:
                raise ValueError("Password cannot be empty")
            
            # Generate salt if not provided
            if custom_salt:
                salt = custom_salt.encode('utf-8')
            else:
                salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
            
            # Hash the password
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            return {
                'hashed_password': hashed.decode('utf-8'),
                'salt': salt.decode('utf-8') if isinstance(salt, bytes) else salt
            }
            
        except Exception as e:
            self.logger.error(f"Password hashing failed: {e}")
            raise SecurityError(f"Failed to hash password: {e}")
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored hash"""
        try:
            if not password or not hashed_password:
                return False
            
            # Convert string hash back to bytes for bcrypt
            hashed_bytes = hashed_password.encode('utf-8')
            password_bytes = password.encode('utf-8')
            
            return bcrypt.checkpw(password_bytes, hashed_bytes)
            
        except Exception as e:
            self.logger.error(f"Password verification failed: {e}")
            return False
    
    # ==================== GENERATED PASSWORD HASHING ====================
    
    def hash_generated_password(self, password: str) -> str:
        """Hash generated passwords for secure storage (one-way)"""
        try:
            if not password:
                raise ValueError("Generated password cannot be empty")
            
            # Use SHA-256 + salt for generated passwords (one-way hash)
            salt = secrets.token_hex(16)
            password_with_salt = f"{password}{salt}"
            
            # Create hash
            hash_object = hashlib.sha256(password_with_salt.encode('utf-8'))
            hashed = hash_object.hexdigest()
            
            # Combine salt and hash for storage
            return f"{salt}${hashed}"
            
        except Exception as e:
            self.logger.error(f"Generated password hashing failed: {e}")
            raise SecurityError(f"Failed to hash generated password: {e}")
    
    def verify_generated_password(self, password: str, stored_hash: str) -> bool:
        """Verify generated password against stored hash"""
        try:
            if not password or not stored_hash:
                return False
            
            # Split stored hash into salt and hash
            parts = stored_hash.split('$')
            if len(parts) != 2:
                return False
            
            salt, stored_hash_value = parts
            
            # Recreate hash with provided password
            password_with_salt = f"{password}{salt}"
            hash_object = hashlib.sha256(password_with_salt.encode('utf-8'))
            computed_hash = hash_object.hexdigest()
            
            return secrets.compare_digest(computed_hash, stored_hash_value)
            
        except Exception as e:
            self.logger.error(f"Generated password verification failed: {e}")
            return False
    
    # ==================== SECURE TOKEN GENERATION ====================
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        try:
            return secrets.token_urlsafe(length)
        except Exception as e:
            self.logger.error(f"Token generation failed: {e}")
            raise SecurityError(f"Failed to generate secure token: {e}")
    
    def generate_session_token(self) -> Dict[str, str]:
        """Generate session token with expiration"""
        try:
            token = self.generate_secure_token(48)
            expires_at = (datetime.now() + timedelta(minutes=SESSION_TIMEOUT)).isoformat()
            
            return {
                'token': token,
                'expires_at': expires_at
            }
            
        except Exception as e:
            self.logger.error(f"Session token generation failed: {e}")
            raise SecurityError(f"Failed to generate session token: {e}")
    
    # ==================== PASSWORD STRENGTH VALIDATION ====================
    
    def validate_password_strength(self, password: str) -> Dict[str, any]:
        """
        Validate password strength and return detailed analysis
        Returns strength score and recommendations
        """
        if not password:
            return {
                'is_strong': False,
                'score': 0,
                'feedback': ['Password cannot be empty']
            }
        
        feedback = []
        score = 0
        
        # Length check
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if has_lower:
            score += 15
        else:
            feedback.append("Add lowercase letters")
        
        if has_upper:
            score += 15
        else:
            feedback.append("Add uppercase letters")
        
        if has_digit:
            score += 15
        else:
            feedback.append("Add numbers")
        
        if has_special:
            score += 20
        else:
            feedback.append("Add special characters")
        
        # Pattern checks
        if not self._has_common_patterns(password):
            score += 10
        else:
            feedback.append("Avoid common patterns")
        
        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Medium"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'is_strong': score >= 60,
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_special': has_special,
            'length': len(password)
        }
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common weak patterns in passwords"""
        common_patterns = [
            "123", "abc", "qwerty", "password", "admin",
            "111", "000", "aaa", "zzz"
        ]
        
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in common_patterns)
    
    # ==================== SECURE COMPARISON ====================
    
    def secure_compare(self, value1: str, value2: str) -> bool:
        """Timing-attack resistant string comparison"""
        try:
            return secrets.compare_digest(value1.encode('utf-8'), value2.encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Secure comparison failed: {e}")
            return False
    
    # ==================== ENTROPY CALCULATION ====================
    
    def calculate_entropy(self, password: str) -> Dict[str, float]:
        """Calculate password entropy and time to crack estimates"""
        if not password:
            return {'entropy': 0, 'time_to_crack_seconds': 0}
        
        # Character set size calculation
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            charset_size += 32
        
        # Entropy calculation
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        # Time to crack estimation (assuming 1 billion guesses per second)
        possible_combinations = charset_size ** len(password)
        average_guesses = possible_combinations / 2
        time_to_crack_seconds = average_guesses / 1_000_000_000
        
        return {
            'entropy': round(entropy, 2),
            'charset_size': charset_size,
            'possible_combinations': possible_combinations,
            'time_to_crack_seconds': time_to_crack_seconds,
            'time_to_crack_human': self._format_time_duration(time_to_crack_seconds)
        }
    
    def _format_time_duration(self, seconds: float) -> str:
        """Format time duration in human-readable format"""
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds/86400)} days"
        else:
            years = int(seconds/31536000)
            if years > 1000000:
                return f"{years:,} years"
            else:
                return f"{years} years"
            
    def encrypt_password(self, password: str, master_password: str) -> Dict[str, str]:
        """Encrypt password using master password as key"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            import os
            
            # Generate salt
            salt = os.urandom(16)
            
            # Create key from master password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            f = Fernet(key)
            
            # Encrypt password
            encrypted = f.encrypt(password.encode())
            
            return {
                'encrypted_password': base64.b64encode(encrypted).decode(),
                'salt': base64.b64encode(salt).decode()
            }
            
        except Exception as e:
            raise SecurityError(f"Password encryption failed: {e}")

    def decrypt_password(self, encrypted_password: str, salt: str, master_password: str) -> str:
        """Decrypt password using master password"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            
            # Recreate key from master password and salt
            salt_bytes = base64.b64decode(salt.encode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            f = Fernet(key)
            
            # Decrypt password
            encrypted_bytes = base64.b64decode(encrypted_password.encode())
            decrypted = f.decrypt(encrypted_bytes)
            
            return decrypted.decode()
            
        except Exception as e:
            raise SecurityError(f"Password decryption failed: {e}")



class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass


class PasswordValidator:
    """Specialized password validation utilities"""
    
    @staticmethod
    def is_common_password(password: str) -> bool:
        """Check if password is in common passwords list"""
        common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "abc123", "123456789", "welcome", "login", "master",
            "monkey", "dragon", "pass", "mustang", "letmein"
        ]
        return password.lower() in common_passwords
    
    @staticmethod
    def has_sequential_chars(password: str) -> bool:
        """Check for sequential characters like 123 or abc"""
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) and 
                ord(password[i+1]) + 1 == ord(password[i+2])):
                return True
        return False
    
    @staticmethod
    def has_repeated_chars(password: str, max_repeats: int = 2) -> bool:
        """Check for excessive character repetition"""
        for i in range(len(password) - max_repeats):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False


# Global crypto manager instance
crypto_manager = CryptoManager()

# Convenience functions for common operations
def hash_password(password: str) -> Dict[str, str]:
    """Convenience function for password hashing"""
    return crypto_manager.hash_password(password)

def verify_password(password: str, hashed: str) -> bool:
    """Convenience function for password verification"""
    return crypto_manager.verify_password(password, hashed)

def hash_generated_password(password: str) -> str:
    """Convenience function for generated password hashing"""
    return crypto_manager.hash_generated_password(password)

def validate_password_strength(password: str) -> Dict[str, any]:
    """Convenience function for password strength validation"""
    return crypto_manager.validate_password_strength(password)
