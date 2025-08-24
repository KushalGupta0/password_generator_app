"""
Password Storage Manager with Encryption Support
Handles secure storage and retrieval of generated passwords
"""

import logging
from typing import Dict, List, Optional, Any

from database import DatabaseManager, PasswordEntryModel
from security import (
    hash_generated_password,
    verify_password,
    crypto_manager,
    sanitize_input,
    SecurityError
)
from app_config import (
    ERROR_MESSAGES,
    SUCCESS_MESSAGES,
    MAX_SITE_NAME_LENGTH
)


class PasswordStorageManager:
    """Manages secure storage of generated passwords with encryption support"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db_manager = db_manager or DatabaseManager()
        self.logger = logging.getLogger(__name__)
        self.last_generated_cache = {}  # Cache for recently generated passwords
        self._setup_logging()
    
    def _setup_logging(self):
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    # ===================== SAVE WITH SIMPLE HASHING =====================
    
    def save_password(self,
                      user_id: int,
                      username_for_site: str,
                      raw_password: str,
                      site_name: Optional[str] = None,
                      site_url: Optional[str] = None,
                      length: Optional[int] = None,
                      complexity_used: Optional[str] = None,
                      notes: str = "") -> Dict[str, Any]:
        """
        Save password with hashing (temporary solution until encryption is fully implemented)
        """
        try:
            if not user_id or not username_for_site or not raw_password:
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['empty_fields']
                }
            
            # Sanitize inputs
            clean_username = sanitize_input(username_for_site.strip())
            clean_site_name = sanitize_input(site_name.strip() if site_name else "")
            clean_site_url = sanitize_input(site_url.strip() if site_url else "")
            clean_notes = sanitize_input(notes, 200) if notes else ""
            
            if len(clean_site_name) > MAX_SITE_NAME_LENGTH:
                return {
                    'success': False,
                    'error': f"Site name cannot exceed {MAX_SITE_NAME_LENGTH} chars"
                }
            
            # Hash the password using the security module
            hashed_password = hash_generated_password(raw_password)
            
            # Split hash into salt and encrypted part (hash_generated_password returns "salt$hash")
            if '$' in hashed_password:
                salt, encrypted_part = hashed_password.split('$', 1)
            else:
                # Fallback if format is different
                salt = "default_salt"
                encrypted_part = hashed_password
            
            # Save to database with all required parameters
            password_id = self.db_manager.save_password(
                user_id=user_id,
                username_for_site=clean_username,
                site_name=clean_site_name,
                site_url=clean_site_url,
                encrypted_password=encrypted_part,
                encryption_salt=salt,
                password_length=length or len(raw_password),
                complexity_used=str(complexity_used) if complexity_used else "default",
                notes=clean_notes
            )
            
            if password_id:
                # Cache the password for immediate viewing
                self.cache_last_generated(
                    user_id=user_id,
                    password_id=password_id,
                    password=raw_password,
                    username=clean_username,
                    site_name=clean_site_name
                )
                
                self.logger.info(f"Saved password for user {user_id}, site: {clean_site_name}")
                return {
                    'success': True,
                    'password_id': password_id,
                    'message': SUCCESS_MESSAGES['password_saved']
                }
            else:
                return {
                    'success': False,
                    'error': ERROR_MESSAGES['database_error']
                }
        
        except SecurityError as e:
            self.logger.error(f"Security error while saving password: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            self.logger.error(f"Failed to save password: {e}")
            return {'success': False, 'error': "Unexpected error"}
    
    # ===================== SAVE WITH ENCRYPTION (Future Implementation) =====================
    
    def save_password_encrypted(self,
                               user_id: int,
                               username_for_site: str,
                               raw_password: str,
                               master_password: str,
                               site_name: Optional[str] = None,
                               site_url: Optional[str] = None,
                               length: Optional[int] = None,
                               complexity_used: Optional[str] = None,
                               notes: str = "") -> Dict[str, Any]:
        """
        Save password with encryption (requires master password)
        This is for future implementation when full encryption is ready
        """
        try:
            # Sanitize inputs
            clean_username = sanitize_input(username_for_site.strip())
            clean_site_name = sanitize_input(site_name.strip() if site_name else "")
            clean_site_url = sanitize_input(site_url.strip() if site_url else "")
            clean_notes = sanitize_input(notes, 200) if notes else ""
            
            # Encrypt the password using master password
            encryption_result = crypto_manager.encrypt_password(raw_password, master_password)
            
            # Save to database
            password_id = self.db_manager.save_password(
                user_id=user_id,
                username_for_site=clean_username,
                site_name=clean_site_name,
                site_url=clean_site_url,
                encrypted_password=encryption_result['encrypted_password'],
                encryption_salt=encryption_result['salt'],
                password_length=length or len(raw_password),
                complexity_used=str(complexity_used) if complexity_used else "default",
                notes=clean_notes
            )
            
            if password_id:
                return {
                    'success': True,
                    'password_id': password_id,
                    'message': 'Password encrypted and saved successfully'
                }
            else:
                return {'success': False, 'error': 'Database save failed'}
                
        except Exception as e:
            self.logger.error(f"Encrypted save failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===================== FETCH =====================
    
    def get_user_passwords(self, user_id: int) -> Dict[str, Any]:
        """Fetch metadata about stored passwords for a given user"""
        try:
            entries: List[PasswordEntryModel] = self.db_manager.get_user_passwords(user_id)
            
            # Convert to dictionaries for JSON serialization
            results = []
            for entry in entries:
                results.append({
                    'password_id': entry.password_id,
                    'username_for_site': entry.username_for_site,
                    'site_name': entry.site_name,
                    'site_url': entry.site_url,
                    'password_length': entry.password_length,
                    'complexity_used': entry.complexity_used,
                    'notes': entry.notes,
                    'created_at': entry.created_at.isoformat() if entry.created_at else None,
                    'last_modified': entry.last_modified.isoformat() if entry.last_modified else None
                })
            
            return {
                'success': True,
                'entries': results,
                'count': len(results)
            }
        
        except Exception as e:
            self.logger.error(f"Failed to fetch passwords for user {user_id}: {e}")
            return {
                'success': False,
                'error': ERROR_MESSAGES['database_error']
            }
    
    # ===================== PASSWORD VIEWING =====================
    
    def view_password(self, user_id: int, password_id: int, master_password: str) -> Dict[str, Any]:
        """
        View stored password - currently supports only recently cached passwords
        Future: Will support full encryption/decryption
        """
        try:
            # Check if we have a cached password (for recently generated ones)
            if hasattr(self, 'last_generated_cache') and self.last_generated_cache:
                cached = self.last_generated_cache
                if (cached.get('password_id') == password_id and 
                    cached.get('user_id') == user_id):
                    return {
                        'success': True,
                        'password': cached['password'],
                        'username_for_site': cached.get('username', ''),
                        'site_name': cached.get('site_name', '')
                    }
            
            # For stored passwords that aren't cached, return helpful message
            return {
                'success': False,
                'error': 'Password viewing is limited to recently generated passwords.\n\n' +
                        'For security, stored passwords are hashed and cannot be decrypted.\n\n' +
                        'To view passwords:\n' +
                        '• Generate a new password to see it before saving\n' +
                        '• Consider using a clipboard manager\n' +
                        '• Regenerate with the same complexity settings'
            }
            
        except Exception as e:
            self.logger.error(f"Password view failed: {e}")
            return {'success': False, 'error': 'Password viewing failed'}
    
    def view_password_encrypted(self, user_id: int, password_id: int, master_password: str) -> Dict[str, Any]:
        """
        Decrypt and view stored password (future implementation)
        Requires full encryption setup
        """
        try:
            # Get encrypted password from database
            entry = self.db_manager.get_password_by_id(password_id, user_id)
            if not entry:
                return {'success': False, 'error': 'Password entry not found'}
            
            # Verify master password first
            from core.auth_manager import AuthenticationManager
            auth_manager = AuthenticationManager(self.db_manager)
            
            # This method needs to be implemented in auth_manager
            # if not auth_manager.verify_master_password(user_id, master_password):
            #     return {'success': False, 'error': 'Invalid master password'}
            
            # Decrypt password
            decrypted_password = crypto_manager.decrypt_password(
                entry['encrypted_password'],
                entry['encryption_salt'],
                master_password
            )
            
            return {
                'success': True,
                'password': decrypted_password,
                'username_for_site': entry['username_for_site'],
                'site_name': entry['site_name']
            }
            
        except Exception as e:
            self.logger.error(f"Password decryption failed: {e}")
            return {'success': False, 'error': 'Failed to decrypt password'}
    
    # ===================== CACHING =====================
    
    def cache_last_generated(self, user_id: int, password_id: int, password: str, 
                           username: str, site_name: str):
        """Cache the most recently generated password for viewing"""
        self.last_generated_cache = {
            'user_id': user_id,
            'password_id': password_id,
            'password': password,
            'username': username,
            'site_name': site_name,
            'cached_at': None  # Could add timestamp if needed
        }
        self.logger.debug(f"Cached password for viewing: password_id={password_id}")
    
    def clear_cache(self):
        """Clear the password cache"""
        self.last_generated_cache = {}
        self.logger.debug("Password cache cleared")
    
    # ===================== DELETE =====================
    
    def delete_password(self, user_id: int, password_id: int) -> Dict[str, Any]:
        """Soft delete a password (mark inactive)"""
        try:
            success = self.db_manager.delete_password(user_id, password_id)
            if success:
                # Clear from cache if it's the cached password
                if (hasattr(self, 'last_generated_cache') and 
                    self.last_generated_cache.get('password_id') == password_id):
                    self.clear_cache()
                
                return {
                    'success': True,
                    'message': f"Password ID {password_id} deleted"
                }
            else:
                return {
                    'success': False,
                    'error': "Password not found or couldn't be deleted"
                }
        
        except Exception as e:
            self.logger.error(f"Failed to delete password {password_id}: {e}")
            return {'success': False, 'error': "Unexpected error"}
    
    # ===================== SEARCH =====================
    
    def search_passwords(self, user_id: int, keyword: str) -> Dict[str, Any]:
        """Search stored passwords metadata (username, site, or notes)"""
        try:
            entries = self.db_manager.search_passwords(user_id, keyword)
            results = []
            for entry in entries:
                results.append({
                    'password_id': entry.password_id,
                    'username_for_site': entry.username_for_site,
                    'site_name': entry.site_name,
                    'site_url': entry.site_url,
                    'password_length': entry.password_length,
                    'complexity_used': entry.complexity_used,
                    'notes': entry.notes,
                    'created_at': entry.created_at.isoformat() if entry.created_at else None
                })
            
            return {
                'success': True,
                'results': results,
                'count': len(results)
            }
        
        except Exception as e:
            self.logger.error(f"Password search failed for user {user_id}: {e}")
            return {'success': False, 'error': "Unexpected error"}
    
    # ===================== COUNT =====================
    
    def count_stored_passwords(self, user_id: int) -> int:
        """Return total count of active passwords for a user"""
        try:
            return self.db_manager.get_password_count(user_id)
        except Exception as e:
            self.logger.error(f"Failed to count passwords for user {user_id}: {e}")
            return 0
    
    # ===================== STATISTICS =====================
    
    def get_user_password_stats(self, user_id: int) -> Dict[str, Any]:
        """Get password statistics for a user"""
        try:
            entries = self.db_manager.get_user_passwords(user_id)
            
            if not entries:
                return {
                    'total_passwords': 0,
                    'avg_length': 0,
                    'most_common_length': 0,
                    'oldest_password': None,
                    'newest_password': None
                }
            
            lengths = [entry.password_length for entry in entries]
            
            return {
                'total_passwords': len(entries),
                'avg_length': round(sum(lengths) / len(lengths), 1),
                'most_common_length': max(set(lengths), key=lengths.count),
                'oldest_password': min(entries, key=lambda x: x.created_at).created_at.isoformat(),
                'newest_password': max(entries, key=lambda x: x.created_at).created_at.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get password stats for user {user_id}: {e}")
            return {'total_passwords': 0, 'avg_length': 0}
