"""
Password Storage Manager
Handles secure storage and retrieval of generated passwords
"""

import logging
from typing import Dict, List, Optional, Any

from database import DatabaseManager, PasswordEntryModel
from security import (
    hash_generated_password,
    verify_password,
    sanitize_input,
    SecurityError
)
from app_config import (
    ERROR_MESSAGES,
    SUCCESS_MESSAGES,
    MAX_SITE_NAME_LENGTH
)


class PasswordStorageManager:
    """Manages secure storage of generated passwords with a database backend"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db_manager = db_manager or DatabaseManager()
        self.logger = logging.getLogger(__name__)
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
    
    # ===================== SAVE =====================
    
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
        Save a new generated password securely into the database.
        Password is hashed before storage - never stored in plaintext.
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
            
            # Hash the password
            hashed_password = hash_generated_password(raw_password)
            
            # Save to database
            password_id = self.db_manager.save_password(
                user_id=user_id,
                username_for_site=clean_username,
                site_name=clean_site_name,
                site_url=clean_site_url,
                hashed_password=hashed_password,
                password_length=length or len(raw_password),
                complexity_used=str(complexity_used) if complexity_used else "default",
                notes=clean_notes
            )
            
            if password_id:
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
    
    # ===================== FETCH =====================
    
    def get_user_passwords(self, user_id: int) -> Dict[str, Any]:
        """Fetch metadata about stored passwords for a given user."""
        try:
            entries: List[PasswordEntryModel] = self.db_manager.get_user_passwords(user_id)
            
            # Return only metadata (never give back raw passwords)
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
                    'created_at': entry.created_at,
                    'last_modified': entry.last_modified
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
    
    # ===================== DELETE =====================
    
    def delete_password(self, user_id: int, password_id: int) -> Dict[str, Any]:
        """Soft delete a password (mark inactive)."""
        try:
            success = self.db_manager.delete_password(user_id, password_id)
            if success:
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
        """Search stored passwords metadata (username, site, or notes)."""
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
                    'created_at': entry.created_at
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
        """Return total count of active passwords for a user."""
        try:
            return self.db_manager.get_password_count(user_id)
        except Exception as e:
            self.logger.error(f"Failed to count passwords for user {user_id}: {e}")
            return 0
