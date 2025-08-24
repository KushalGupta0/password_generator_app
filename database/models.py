"""
Database Models and Schema Definitions
Includes SQL for creating tables and indexes
"""

# Schema Version
SCHEMA_VERSION = "1.0"

# USERS TABLE
CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP DEFAULT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP DEFAULT NULL
);
"""

# STORED PASSWORDS TABLE WITH ENCRYPTION COLUMNS
CREATE_STORED_PASSWORDS_TABLE = """
CREATE TABLE IF NOT EXISTS stored_passwords (
    password_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username_for_site TEXT NOT NULL,
    site_name TEXT,
    site_url TEXT,
    encrypted_password TEXT NOT NULL,
    encryption_salt TEXT NOT NULL,
    password_length INTEGER,
    complexity_used TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
"""

# SCHEMA VERSION TABLE
CREATE_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# ALL TABLES FOR INITIALIZATION
ALL_TABLES = [
    CREATE_USERS_TABLE,
    CREATE_STORED_PASSWORDS_TABLE,
    CREATE_SCHEMA_VERSION_TABLE
]

# INDEXES
CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
    "CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON stored_passwords(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_passwords_site ON stored_passwords(site_name);",
    "CREATE INDEX IF NOT EXISTS idx_passwords_created ON stored_passwords(created_at);"
]

# USER QUERIES
USER_QUERIES = {
    'insert_user': "INSERT INTO users (username, email, hashed_password, salt) VALUES (?, ?, ?, ?)",
    'get_user_by_username': "SELECT * FROM users WHERE username = ?",
    'get_user_by_id': "SELECT user_id, username, email, created_at, last_login, is_active FROM users WHERE user_id = ?",
    'update_last_login': "UPDATE users SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0 WHERE user_id = ?",
    'update_failed_attempts': "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = ?",
    'check_username_exists': "SELECT COUNT(*) FROM users WHERE username = ? AND is_active = 1",
    'lock_user_account': "UPDATE users SET locked_until = datetime('now', '+30 minutes') WHERE user_id = ?"
}

# PASSWORD QUERIES
PASSWORD_QUERIES = {
    'insert_password': """
        INSERT INTO stored_passwords 
        (user_id, username_for_site, site_name, site_url, encrypted_password, encryption_salt, password_length, complexity_used, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    'get_user_passwords': "SELECT * FROM stored_passwords WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC",
    'get_password_by_id': "SELECT * FROM stored_passwords WHERE password_id = ? AND user_id = ? AND is_active = 1",
    'search_passwords': "SELECT * FROM stored_passwords WHERE user_id = ? AND (site_name LIKE ? OR username_for_site LIKE ? OR notes LIKE ?) AND is_active = 1",
    'delete_password': "UPDATE stored_passwords SET is_active = 0 WHERE password_id = ? AND user_id = ?",
    'count_user_passwords': "SELECT COUNT(*) FROM stored_passwords WHERE user_id = ? AND is_active = 1",
    'update_password': """
        UPDATE stored_passwords 
        SET username_for_site = ?, site_name = ?, site_url = ?, notes = ?, last_modified = CURRENT_TIMESTAMP 
        WHERE password_id = ? AND user_id = ?
    """
}

# SESSION QUERIES FOR USER SESSIONS
SESSION_QUERIES = {
    'create_session': "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
    'get_session': "SELECT * FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP",
    'delete_session': "DELETE FROM sessions WHERE session_token = ?",
    'cleanup_expired_sessions': "DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP",
    'delete_user_sessions': "DELETE FROM sessions WHERE user_id = ?"
}

# MAINTENANCE QUERIES
MAINTENANCE_QUERIES = {
    'vacuum_database': "VACUUM",
    'get_database_size': "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()",
    'check_integrity': "PRAGMA integrity_check",
    'analyze_database': "ANALYZE",
    'get_table_info': "SELECT name FROM sqlite_master WHERE type='table'",
    'get_user_stats': """
        SELECT 
            COUNT(DISTINCT u.user_id) as total_users,
            COUNT(p.password_id) as total_passwords,
            AVG(p.password_length) as avg_password_length
        FROM users u 
        LEFT JOIN stored_passwords p ON u.user_id = p.user_id AND p.is_active = 1
        WHERE u.is_active = 1
    """
}

# DATA MODELS
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class UserModel:
    """User data model"""
    user_id: int
    username: str
    email: str
    created_at: Optional[datetime]
    last_login: Optional[datetime]
    is_active: bool

@dataclass
class PasswordEntryModel:
    """Password entry data model"""
    password_id: int
    user_id: int
    username_for_site: str
    site_name: Optional[str]
    site_url: Optional[str]
    password_length: int
    complexity_used: str
    notes: Optional[str]
    created_at: Optional[datetime]
    last_modified: Optional[datetime]
    is_active: bool = True

@dataclass
class SessionModel:
    """User session data model"""
    session_id: int
    user_id: int
    session_token: str
    created_at: datetime
    expires_at: datetime
    is_active: bool

# VALIDATION CONSTANTS
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 254
MAX_SITE_NAME_LENGTH = 100
MAX_NOTES_LENGTH = 500
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 128

# DATABASE CONSTRAINTS
FOREIGN_KEY_CONSTRAINTS = [
    "PRAGMA foreign_keys = ON;"
]

# TRIGGERS (Optional - for automatic timestamp updates)
CREATE_TRIGGERS = [
    """
    CREATE TRIGGER IF NOT EXISTS update_password_timestamp
    AFTER UPDATE ON stored_passwords
    BEGIN
        UPDATE stored_passwords 
        SET last_modified = CURRENT_TIMESTAMP 
        WHERE password_id = NEW.password_id;
    END;
    """
]

# DATABASE INITIALIZATION ORDER
INITIALIZATION_ORDER = [
    'tables',      # Create tables first
    'indexes',     # Then create indexes
    'triggers',    # Then create triggers
    'constraints'  # Finally apply constraints
]
