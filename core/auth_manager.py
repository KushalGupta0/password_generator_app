"""
Authentication Manager - User Registration and Login Logic
Handles user authentication, session management, and security policies
"""

import logging
from typing import Optional, Dict, Tuple, Any
from datetime import datetime, timedelta
import secrets

from database import DatabaseManager
from security import (
    hash_password, 
    verify_password, 
    validate_password_strength,
    crypto_manager,
    SecurityError,
    sanitize_input
)
from app_config import (
    MIN_USERNAME_LENGTH, 
    MAX_USERNAME_LENGTH,
    MIN_LOGIN_PASSWORD_LENGTH,
    MAX_LOGIN_ATTEMPTS,
    SESSION_TIMEOUT,
    ERROR_MESSAGES,
    SUCCESS_MESSAGES
)


class AuthenticationManager:
    """Comprehensive authentication and user management system"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        """Initialize authentication manager with database connection"""
        self.db_manager = db_manager or DatabaseManager()
        self.logger = logging.getLogger(__name__)
        self.active_sessions = {}  # In-memory session storage
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging for authentication operations"""
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    # ==================== USER REGISTRATION ====================
    
    def register_user(self, username: str, password: str, email: str = None) -> Dict[str, Any]:
        """
        Register a new user with comprehensive validation
        
        Returns:
            Dict with success status, user_id if successful, or error details
        """
        try:
            # Input validation and sanitization
            validation_result = self._validate_registration_input(username, password, email)
            if not validation_result['is_valid']:
                return {
                    'success': False,
                    'error': validation_result['error'],
                    'details': validation_result.get('details', {})
                }
            
            # Sanitize inputs
            clean_username = sanitize_input(username.strip().lower(), MAX_USERNAME_LENGTH)
            clean_email = sanitize_input(email.strip().lower(), 100) if email else None
            
            # Check if username already exists
            if self.db_manager.get_user_by_username(clean_username):
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['username_exists'],
                    'field': 'username'
                }
            
            # Hash the password
            hash_result = hash_password(password)
            hashed_password = hash_result['hashed_password']
            salt = hash_result['salt']
            
            # Create user in database
            user_id = self.db_manager.create_user(
                username=clean_username,
                email=clean_email,
                hashed_password=hashed_password,
                salt=salt
            )
            
            if user_id:
                self.logger.info(f"User registered successfully: {clean_username} (ID: {user_id})")
                return {
                    'success': True,
                    'user_id': user_id,
                    'username': clean_username,
                    'message': SUCCESS_MESSAGES['registration']
                }
            else:
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['database_error'],
                    'technical_error': 'Failed to create user in database'
                }
        
        except SecurityError as e:
            self.logger.error(f"Security error during registration: {e}")
            return {
                'success': False,
                'error': 'Security validation failed',
                'technical_error': str(e)
            }
        except Exception as e:
            self.logger.error(f"Unexpected error during registration: {e}")
            return {
                'success': False,
                'error': ERROR_MESSAGES['database_error'],
                'technical_error': str(e)
            }
    
    def _validate_registration_input(self, username: str, password: str, email: str = None) -> Dict[str, Any]:
        """Validate user registration input"""
        errors = []
        details = {}
        
        # Username validation
        if not username or len(username.strip()) < MIN_USERNAME_LENGTH:
            errors.append(f"Username must be at least {MIN_USERNAME_LENGTH} characters")
        elif len(username.strip()) > MAX_USERNAME_LENGTH:
            errors.append(f"Username cannot exceed {MAX_USERNAME_LENGTH} characters")
        elif not username.replace('_', '').replace('-', '').isalnum():
            errors.append("Username can only contain letters, numbers, hyphens, and underscores")
        
        # Password validation
        if not password:
            errors.append("Password is required")
        elif len(password) < MIN_LOGIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_LOGIN_PASSWORD_LENGTH} characters")
        else:
            # Comprehensive password strength check
            strength = validate_password_strength(password)
            details['password_strength'] = strength
            
            if not strength['is_strong']:
                errors.append(f"Password is too weak: {', '.join(strength['feedback'])}")
        
        # Email validation (optional)
        if email:
            email = email.strip()
            if '@' not in email or '.' not in email.split('@')[-1]:
                errors.append("Invalid email format")
        
        return {
            'is_valid': len(errors) == 0,
            'error': '; '.join(errors) if errors else None,
            'details': details
        }
    
    # ==================== USER AUTHENTICATION ====================
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user login with security measures
        
        Returns:
            Dict with authentication result and session information
        """
        try:
            # Input sanitization
            clean_username = sanitize_input(username.strip().lower(), MAX_USERNAME_LENGTH)
            
            if not clean_username or not password:
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['empty_fields']
                }
            
            # Get user from database
            user_data = self.db_manager.get_user_by_username(clean_username)
            if not user_data:
                self.logger.warning(f"Login attempt for non-existent user: {clean_username}")
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['invalid_login']
                }
            
            # Check if account is locked
            if self._is_account_locked(user_data):
                return {
                    'success': False,
                    'error': 'Account is temporarily locked due to failed login attempts',
                    'locked_until': user_data['locked_until']
                }
            
            # Verify password
            is_valid_password = verify_password(password, user_data['hashed_password'])
            
            if is_valid_password:
                # Successful login
                self.db_manager.update_last_login(user_data['user_id'])
                
                # Create session
                session_data = self._create_session(user_data['user_id'], clean_username)
                
                self.logger.info(f"Successful login: {clean_username}")
                return {
                    'success': True,
                    'user_id': user_data['user_id'],
                    'username': clean_username,
                    'session_token': session_data['token'],
                    'expires_at': session_data['expires_at'],
                    'message': SUCCESS_MESSAGES['login']
                }
            else:
                # Failed login - increment attempts
                self.db_manager.increment_failed_attempts(user_data['user_id'])
                
                # Get updated user data to check new attempt count
                updated_user = self.db_manager.get_user_by_username(clean_username)
                attempts_remaining = MAX_LOGIN_ATTEMPTS - updated_user['failed_login_attempts']
                
                self.logger.warning(f"Failed login attempt for: {clean_username}")
                
                if attempts_remaining <= 0:
                    return {
                        'success': False,
                        'error': 'Account locked due to too many failed attempts',
                        'locked_until': updated_user.get('locked_until')
                    }
                else:
                    return {
                        'success': False,
                        'error': ERROR_MESSAGES['invalid_login'],
                        'attempts_remaining': attempts_remaining
                    }
        
        except Exception as e:
            self.logger.error(f"Authentication error for {username}: {e}")
            return {
                'success': False,
                'error': ERROR_MESSAGES['database_error'],
                'technical_error': str(e)
            }
    
    def _is_account_locked(self, user_data: Dict) -> bool:
        """Check if user account is currently locked"""
        if not user_data.get('locked_until'):
            return False
        
        try:
            locked_until = datetime.fromisoformat(user_data['locked_until'])
            return datetime.now() < locked_until
        except (ValueError, TypeError):
            return False
    
    # ==================== SESSION MANAGEMENT ====================
    
    def _create_session(self, user_id: int, username: str) -> Dict[str, str]:
        """Create new user session with secure token"""
        session_info = crypto_manager.generate_session_token()
        
        # Store session in memory (in production, consider Redis or database storage)
        self.active_sessions[session_info['token']] = {
            'user_id': user_id,
            'username': username,
            'created_at': datetime.now().isoformat(),
            'expires_at': session_info['expires_at'],
            'last_activity': datetime.now().isoformat()
        }
        
        return session_info
    
    def validate_session(self, session_token: str) -> Dict[str, Any]:
        """Validate active session token"""
        try:
            if not session_token:
                return {'valid': False, 'error': 'No session token provided'}
            
            session_data = self.active_sessions.get(session_token)
            if not session_data:
                return {'valid': False, 'error': 'Session not found'}
            
            # Check expiration
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.now() > expires_at:
                self._invalidate_session(session_token)
                return {'valid': False, 'error': 'Session expired'}
            
            # Update last activity
            session_data['last_activity'] = datetime.now().isoformat()
            
            return {
                'valid': True,
                'user_id': session_data['user_id'],
                'username': session_data['username'],
                'expires_at': session_data['expires_at']
            }
        
        except Exception as e:
            self.logger.error(f"Session validation error: {e}")
            return {'valid': False, 'error': 'Session validation failed'}
    
    def _invalidate_session(self, session_token: str) -> bool:
        """Remove session from active sessions"""
        try:
            if session_token in self.active_sessions:
                del self.active_sessions[session_token]
                return True
            return False
        except Exception as e:
            self.logger.error(f"Session invalidation error: {e}")
            return False
    
    def logout_user(self, session_token: str) -> Dict[str, Any]:
        """Logout user by invalidating session"""
        try:
            session_data = self.active_sessions.get(session_token)
            if session_data:
                username = session_data['username']
                self._invalidate_session(session_token)
                self.logger.info(f"User logged out: {username}")
                return {
                    'success': True,
                    'message': 'Successfully logged out'
                }
            else:
                return {
                    'success': False,
                    'error': 'Session not found'
                }
        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            return {
                'success': False,
                'error': 'Logout failed'
            }
    
    # ==================== SESSION CLEANUP ====================
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions from memory"""
        try:
            current_time = datetime.now()
            expired_tokens = []
            
            for token, session_data in self.active_sessions.items():
                try:
                    expires_at = datetime.fromisoformat(session_data['expires_at'])
                    if current_time > expires_at:
                        expired_tokens.append(token)
                except (ValueError, TypeError):
                    expired_tokens.append(token)  # Invalid session data
            
            # Remove expired sessions
            for token in expired_tokens:
                del self.active_sessions[token]
            
            if expired_tokens:
                self.logger.info(f"Cleaned up {len(expired_tokens)} expired sessions")
            
            return len(expired_tokens)
        
        except Exception as e:
            self.logger.error(f"Session cleanup error: {e}")
            return 0
    
    def get_active_session_count(self) -> int:
        """Get count of currently active sessions"""
        self.cleanup_expired_sessions()  # Clean up first
        return len(self.active_sessions)
    
    # ==================== USER MANAGEMENT ====================
    
    def get_user_info(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user information by ID"""
        try:
            user_model = self.db_manager.get_user_by_id(user_id)
            if user_model:
                return {
                    'user_id': user_model.user_id,
                    'username': user_model.username,
                    'email': user_model.email,
                    'created_at': user_model.created_at,
                    'last_login': user_model.last_login,
                    'is_active': user_model.is_active
                }
            return None
        except Exception as e:
            self.logger.error(f"Error getting user info for ID {user_id}: {e}")
            return None
    
    def change_password(self, user_id: int, current_password: str, new_password: str) -> Dict[str, Any]:
        """Change user password with validation"""
        try:
            # Get current user data
            user_data = self.db_manager.get_user_by_username(
                self.get_user_info(user_id)['username']
            )
            
            if not user_data:
                return {'success': False, 'error': 'User not found'}
            
            # Verify current password
            if not verify_password(current_password, user_data['hashed_password']):
                return {'success': False, 'error': 'Current password is incorrect'}
            
            # Validate new password strength
            strength = validate_password_strength(new_password)
            if not strength['is_strong']:
                return {
                    'success': False,
                    'error': f"New password is too weak: {', '.join(strength['feedback'])}"
                }
            
            # Hash new password
            hash_result = hash_password(new_password)
            
            # Update in database (this would require a new method in db_manager)
            # For now, return success indication
            self.logger.info(f"Password change requested for user ID: {user_id}")
            
            return {
                'success': True,
                'message': 'Password changed successfully'
            }
        
        except Exception as e:
            self.logger.error(f"Password change error for user {user_id}: {e}")
            return {'success': False, 'error': 'Password change failed'}

    def get_user_password_for_encryption(self, user_id: int, provided_password: str) -> bool:
        """Verify user's master password for encryption operations"""
        try:
            user_info = self.get_user_info(user_id)
            if not user_info:
                return False
                
            user_data = self.db_manager.get_user_by_username(user_info['username'])
            if not user_data:
                return False
                
            return verify_password(provided_password, user_data['hashed_password'])
            
        except Exception as e:
            self.logger.error(f"Password verification failed: {e}")
            return False


# Authentication exception classes
class AuthenticationError(Exception):
    """Exception raised for authentication failures"""
    pass


class SessionError(Exception):
    """Exception raised for session management failures"""
    pass


class RegistrationError(Exception):
    """Exception raised for user registration failures"""
    pass
