"""
Database Manager with Encryption Support
Handles all database operations for users and encrypted passwords
"""

import sqlite3
import logging
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from datetime import datetime

from .models import (
    ALL_TABLES, CREATE_INDEXES, CREATE_TRIGGERS, FOREIGN_KEY_CONSTRAINTS,
    USER_QUERIES, PASSWORD_QUERIES, MAINTENANCE_QUERIES,
    UserModel, PasswordEntryModel
)
from app_config import DATABASE_FILE


class DatabaseManager:
    """Comprehensive database manager for password generator application"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        """Initialize database manager"""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging for database operations"""
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            # Enable foreign key constraints
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    # ==================== DATABASE INITIALIZATION ====================
    
    def initialize_database(self) -> bool:
        """Initialize database with all tables, indexes, and constraints"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create all tables
                for table_sql in ALL_TABLES:
                    cursor.execute(table_sql)
                
                # Create indexes
                for index_sql in CREATE_INDEXES:
                    cursor.execute(index_sql)
                
                # Create triggers
                for trigger_sql in CREATE_TRIGGERS:
                    cursor.execute(trigger_sql)
                
                # Apply foreign key constraints
                for constraint_sql in FOREIGN_KEY_CONSTRAINTS:
                    cursor.execute(constraint_sql)
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            return False
    
    # ==================== USER MANAGEMENT ====================
    
    def create_user(self, username: str, email: str, hashed_password: str, salt: str) -> Optional[int]:
        """Create a new user account"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    USER_QUERIES['insert_user'],
                    (username, email, hashed_password, salt)
                )
                
                user_id = cursor.lastrowid
                conn.commit()
                
                self.logger.info(f"User created successfully: {username} (ID: {user_id})")
                return user_id
                
        except sqlite3.IntegrityError as e:
            if "username" in str(e).lower():
                self.logger.warning(f"Username already exists: {username}")
            elif "email" in str(e).lower():
                self.logger.warning(f"Email already exists: {email}")
            else:
                self.logger.error(f"User creation failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"User creation error: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username (for authentication)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['get_user_by_username'], (username,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'user_id': row['user_id'],
                        'username': row['username'],
                        'email': row['email'],
                        'hashed_password': row['hashed_password'],
                        'salt': row['salt'],
                        'failed_login_attempts': row['failed_login_attempts'],
                        'locked_until': row['locked_until'],
                        'is_active': row['is_active'],
                        'created_at': row['created_at'],
                        'last_login': row['last_login']
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user {username}: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[UserModel]:
        """Get user by ID (for user info display)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['get_user_by_id'], (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return UserModel(
                        user_id=row['user_id'],
                        username=row['username'],
                        email=row['email'],
                        created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                        last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                        is_active=bool(row['is_active'])
                    )
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user by ID {user_id}: {e}")
            return None
    
    def update_last_login(self, user_id: int) -> bool:
        """Update user's last login timestamp and reset failed attempts"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['update_last_login'], (user_id,))
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Failed to update last login for user {user_id}: {e}")
            return False
    
    def increment_failed_attempts(self, user_id: int) -> bool:
        """Increment failed login attempts for user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['update_failed_attempts'], (user_id,))
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Failed to increment failed attempts for user {user_id}: {e}")
            return False
    
    # ==================== PASSWORD MANAGEMENT ====================
    
    def save_password(self, user_id: int, username_for_site: str, site_name: str,
                     site_url: str, encrypted_password: str, encryption_salt: str,
                     password_length: int, complexity_used: str, notes: str = "") -> Optional[int]:
        """Save encrypted password to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    PASSWORD_QUERIES['insert_password'],
                    (user_id, username_for_site, site_name, site_url,
                     encrypted_password, encryption_salt, password_length, complexity_used, notes)
                )
                
                password_id = cursor.lastrowid
                conn.commit()
                
                self.logger.info(f"Password saved for user {user_id}, ID: {password_id}")
                return password_id
                
        except Exception as e:
            self.logger.error(f"Failed to save password for user {user_id}: {e}")
            return None
    
    def get_user_passwords(self, user_id: int) -> List[PasswordEntryModel]:
        """Get all active passwords for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['get_user_passwords'], (user_id,))
                rows = cursor.fetchall()
                
                passwords = []
                for row in rows:
                    passwords.append(PasswordEntryModel(
                        password_id=row['password_id'],
                        user_id=row['user_id'],
                        username_for_site=row['username_for_site'],
                        site_name=row['site_name'],
                        site_url=row['site_url'],
                        password_length=row['password_length'],
                        complexity_used=row['complexity_used'],
                        notes=row['notes'],
                        created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                        last_modified=datetime.fromisoformat(row['last_modified']) if row['last_modified'] else None,
                        is_active=bool(row['is_active'])
                    ))
                
                return passwords
                
        except Exception as e:
            self.logger.error(f"Failed to get passwords for user {user_id}: {e}")
            return []
    
    def get_password_by_id(self, password_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Get encrypted password entry by ID (for decryption)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['get_password_by_id'], (password_id, user_id))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'password_id': row['password_id'],
                        'user_id': row['user_id'],
                        'username_for_site': row['username_for_site'],
                        'site_name': row['site_name'],
                        'site_url': row['site_url'],
                        'encrypted_password': row['encrypted_password'],
                        'encryption_salt': row['encryption_salt'],
                        'password_length': row['password_length'],
                        'complexity_used': row['complexity_used'],
                        'notes': row['notes'],
                        'created_at': row['created_at'],
                        'last_modified': row['last_modified']
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get password {password_id}: {e}")
            return None
    
    def search_passwords(self, user_id: int, keyword: str) -> List[PasswordEntryModel]:
        """Search passwords by keyword in site name, username, or notes"""
        try:
            search_term = f"%{keyword}%"
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    PASSWORD_QUERIES['search_passwords'],
                    (user_id, search_term, search_term, search_term)
                )
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    results.append(PasswordEntryModel(
                        password_id=row['password_id'],
                        user_id=row['user_id'],
                        username_for_site=row['username_for_site'],
                        site_name=row['site_name'],
                        site_url=row['site_url'],
                        password_length=row['password_length'],
                        complexity_used=row['complexity_used'],
                        notes=row['notes'],
                        created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                        last_modified=datetime.fromisoformat(row['last_modified']) if row['last_modified'] else None,
                        is_active=bool(row['is_active'])
                    ))
                
                return results
                
        except Exception as e:
            self.logger.error(f"Password search failed for user {user_id}: {e}")
            return []
    
    def delete_password(self, user_id: int, password_id: int) -> bool:
        """Soft delete a password entry"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['delete_password'], (password_id, user_id))
                conn.commit()
                
                success = cursor.rowcount > 0
                if success:
                    self.logger.info(f"Password {password_id} deleted for user {user_id}")
                return success
                
        except Exception as e:
            self.logger.error(f"Failed to delete password {password_id}: {e}")
            return False
    
    def get_password_count(self, user_id: int) -> int:
        """Get count of active passwords for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['count_user_passwords'], (user_id,))
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            self.logger.error(f"Failed to count passwords for user {user_id}: {e}")
            return 0
    
    # ==================== DATABASE MAINTENANCE ====================
    
    def vacuum_database(self) -> bool:
        """Optimize database by running VACUUM"""
        try:
            with self.get_connection() as conn:
                conn.execute(MAINTENANCE_QUERIES['vacuum_database'])
                self.logger.info("Database vacuum completed")
                return True
                
        except Exception as e:
            self.logger.error(f"Database vacuum failed: {e}")
            return False
    
    def check_database_integrity(self) -> bool:
        """Check database integrity"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(MAINTENANCE_QUERIES['check_integrity'])
                result = cursor.fetchone()[0]
                
                if result == "ok":
                    self.logger.info("Database integrity check passed")
                    return True
                else:
                    self.logger.warning(f"Database integrity issues: {result}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Database integrity check failed: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(MAINTENANCE_QUERIES['get_user_stats'])
                stats = cursor.fetchone()
                
                return {
                    'total_users': stats['total_users'] or 0,
                    'total_passwords': stats['total_passwords'] or 0,
                    'avg_password_length': round(stats['avg_password_length'] or 0, 2)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {'total_users': 0, 'total_passwords': 0, 'avg_password_length': 0}
