"""
Database Manager - Handles all database operations
Manages SQLite database connections, queries, and data operations
"""

import sqlite3
import logging
import os
from typing import List, Dict, Optional, Tuple, Any
from contextlib import contextmanager
from datetime import datetime, timedelta

from .models import (
    ALL_TABLES, CREATE_INDEXES, USER_QUERIES, PASSWORD_QUERIES,
    SESSION_QUERIES, MAINTENANCE_QUERIES, UserModel, PasswordEntryModel,
    SCHEMA_VERSION
)
from app_config import DATABASE_FILE, DATABASE_TIMEOUT


class DatabaseManager:
    """Comprehensive database manager for password generator application"""
    
    def __init__(self, db_path: str = None):
        """Initialize database manager with optional custom database path"""
        self.db_path = db_path or DATABASE_FILE
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging for database operations"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections with proper error handling"""
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path, 
                timeout=DATABASE_TIMEOUT,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row  # Enable column access by name
            conn.execute("PRAGMA foreign_keys = ON;")  # Enable foreign key constraints
            yield conn
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def initialize_database(self) -> bool:
        """Initialize database with all required tables and indexes"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create all tables
                for table_sql in ALL_TABLES:
                    cursor.execute(table_sql)
                
                # Create indexes for performance
                for index_sql in CREATE_INDEXES:
                    cursor.execute(index_sql)
                
                # Insert schema version
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,)
                )
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return False
    
    # ==================== USER MANAGEMENT ====================
    
    def create_user(self, username: str, email: str, hashed_password: str, salt: str) -> Optional[int]:
        """Create a new user account"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute(USER_QUERIES['check_username_exists'], (username,))
                if cursor.fetchone()[0] > 0:
                    self.logger.warning(f"Username already exists: {username}")
                    return None
                
                # Insert new user
                cursor.execute(
                    USER_QUERIES['insert_user'],
                    (username, email, hashed_password, salt)
                )
                
                user_id = cursor.lastrowid
                conn.commit()
                self.logger.info(f"User created successfully: {username} (ID: {user_id})")
                return user_id
                
        except Exception as e:
            self.logger.error(f"Failed to create user {username}: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Retrieve user by username for authentication"""
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
                        'is_active': row['is_active']
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user {username}: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[UserModel]:
        """Retrieve user by ID"""
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
                        created_at=row['created_at'],
                        last_login=row['last_login'],
                        is_active=row['is_active']
                    )
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user ID {user_id}: {e}")
            return None
    
    def update_last_login(self, user_id: int) -> bool:
        """Update user's last login timestamp and reset failed attempts"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['update_last_login'], (user_id,))
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update last login for user {user_id}: {e}")
            return False
    
    def increment_failed_attempts(self, user_id: int) -> bool:
        """Increment failed login attempts and potentially lock account"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(USER_QUERIES['update_failed_attempts'], (user_id,))
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update failed attempts for user {user_id}: {e}")
            return False
    
    # ==================== PASSWORD STORAGE ====================
    
    def save_password(self, user_id: int, username_for_site: str, site_name: str,
                     site_url: str, hashed_password: str, password_length: int,
                     complexity_used: str, notes: str = "") -> Optional[int]:
        """Save a generated password to the database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    PASSWORD_QUERIES['insert_password'],
                    (user_id, username_for_site, site_name, site_url, 
                     hashed_password, password_length, complexity_used, notes)
                )
                
                password_id = cursor.lastrowid
                conn.commit()
                self.logger.info(f"Password saved for user {user_id}, site: {site_name}")
                return password_id
                
        except Exception as e:
            self.logger.error(f"Failed to save password for user {user_id}: {e}")
            return None
    
    def get_user_passwords(self, user_id: int) -> List[PasswordEntryModel]:
        """Retrieve all passwords for a specific user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['get_user_passwords'], (user_id,))
                rows = cursor.fetchall()
                
                passwords = []
                for row in rows:
                    password_entry = PasswordEntryModel(
                        password_id=row['password_id'],
                        user_id=user_id,
                        username_for_site=row['username_for_site'],
                        site_name=row['site_name'],
                        site_url=row['site_url'],
                        password_length=row['password_length'],
                        complexity_used=row['complexity_used'],
                        notes=row['notes'],
                        created_at=row['created_at'],
                        last_modified=row['last_modified']
                    )
                    passwords.append(password_entry)
                
                return passwords
                
        except Exception as e:
            self.logger.error(f"Failed to get passwords for user {user_id}: {e}")
            return []
    
    def search_passwords(self, user_id: int, search_term: str) -> List[PasswordEntryModel]:
        """Search user's passwords by site name, username, or notes"""
        try:
            search_pattern = f"%{search_term}%"
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    PASSWORD_QUERIES['search_passwords'],
                    (user_id, search_pattern, search_pattern, search_pattern)
                )
                rows = cursor.fetchall()
                
                passwords = []
                for row in rows:
                    password_entry = PasswordEntryModel(
                        password_id=row['password_id'],
                        user_id=user_id,
                        username_for_site=row['username_for_site'],
                        site_name=row['site_name'],
                        site_url=row['site_url'],
                        password_length=row['password_length'],
                        complexity_used=row['complexity_used'],
                        notes=row['notes'],
                        created_at=row['created_at']
                    )
                    passwords.append(password_entry)
                
                return passwords
                
        except Exception as e:
            self.logger.error(f"Failed to search passwords for user {user_id}: {e}")
            return []
    
    def delete_password(self, user_id: int, password_id: int) -> bool:
        """Soft delete a stored password"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    PASSWORD_QUERIES['delete_password'],
                    (password_id, user_id)
                )
                
                success = cursor.rowcount > 0
                conn.commit()
                
                if success:
                    self.logger.info(f"Password {password_id} deleted for user {user_id}")
                
                return success
                
        except Exception as e:
            self.logger.error(f"Failed to delete password {password_id}: {e}")
            return False
    
    def get_password_count(self, user_id: int) -> int:
        """Get total count of stored passwords for user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(PASSWORD_QUERIES['count_user_passwords'], (user_id,))
                return cursor.fetchone()[0]
                
        except Exception as e:
            self.logger.error(f"Failed to get password count for user {user_id}: {e}")
            return 0
    
    # ==================== DATABASE MAINTENANCE ====================
    
    def cleanup_expired_sessions(self) -> bool:
        """Remove expired sessions from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(SESSION_QUERIES['cleanup_expired_sessions'])
                removed_count = cursor.rowcount
                conn.commit()
                
                if removed_count > 0:
                    self.logger.info(f"Cleaned up {removed_count} expired sessions")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired sessions: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Optimize database by reclaiming space"""
        try:
            with self.get_connection() as conn:
                conn.execute(MAINTENANCE_QUERIES['vacuum_database'])
                self.logger.info("Database vacuumed successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to vacuum database: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics and health information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get database size
                cursor.execute(MAINTENANCE_QUERIES['get_database_size'])
                size_result = cursor.fetchone()
                db_size = size_result[0] if size_result else 0
                
                # Get table counts
                cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
                user_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM stored_passwords WHERE is_active = 1")
                password_count = cursor.fetchone()[0]
                
                return {
                    'database_size_bytes': db_size,
                    'active_users': user_count,
                    'stored_passwords': password_count,
                    'database_path': self.db_path,
                    'last_checked': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {}
    
    def check_database_integrity(self) -> bool:
        """Check database integrity"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(MAINTENANCE_QUERIES['check_integrity'])
                result = cursor.fetchone()[0]
                
                is_healthy = result == "ok"
                if is_healthy:
                    self.logger.info("Database integrity check passed")
                else:
                    self.logger.error(f"Database integrity check failed: {result}")
                
                return is_healthy
                
        except Exception as e:
            self.logger.error(f"Failed to check database integrity: {e}")
            return False
