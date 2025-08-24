"""
Database Models and Schema Definitions
Contains all SQL table schemas, queries, and database structure
"""

# Table Creation Schemas
CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP NULL
);
"""

CREATE_STORED_PASSWORDS_TABLE = """
CREATE TABLE IF NOT EXISTS stored_passwords (
    password_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username_for_site TEXT NOT NULL,
    site_name TEXT,
    site_url TEXT,
    hashed_password TEXT NOT NULL,
    password_length INTEGER,
    complexity_used TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
"""

CREATE_USER_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
"""

# Indexes for Performance
CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
    "CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON stored_passwords(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_passwords_site_name ON stored_passwords(site_name);",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);"
]

# User Management Queries
USER_QUERIES = {
    'insert_user': """
        INSERT INTO users (username, email, hashed_password, salt, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """,
    
    'get_user_by_username': """
        SELECT user_id, username, email, hashed_password, salt, 
               failed_login_attempts, locked_until, is_active
        FROM users 
        WHERE username = ? AND is_active = 1
    """,
    
    'get_user_by_id': """
        SELECT user_id, username, email, created_at, last_login, is_active
        FROM users 
        WHERE user_id = ? AND is_active = 1
    """,
    
    'update_last_login': """
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0 
        WHERE user_id = ?
    """,
    
    'update_failed_attempts': """
        UPDATE users 
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE 
                WHEN failed_login_attempts + 1 >= 5 
                THEN datetime('now', '+30 minutes')
                ELSE locked_until 
            END
        WHERE user_id = ?
    """,
    
    'check_username_exists': """
        SELECT COUNT(*) FROM users WHERE username = ?
    """,
    
    'deactivate_user': """
        UPDATE users SET is_active = 0 WHERE user_id = ?
    """
}

# Password Storage Queries
PASSWORD_QUERIES = {
    'insert_password': """
        INSERT INTO stored_passwords 
        (user_id, username_for_site, site_name, site_url, hashed_password, 
         password_length, complexity_used, notes, created_at, last_modified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """,
    
    'get_user_passwords': """
        SELECT password_id, username_for_site, site_name, site_url,
               password_length, complexity_used, notes, created_at, last_modified
        FROM stored_passwords 
        WHERE user_id = ? AND is_active = 1
        ORDER BY created_at DESC
    """,
    
    'get_password_by_id': """
        SELECT password_id, user_id, username_for_site, site_name, site_url,
               hashed_password, password_length, complexity_used, notes,
               created_at, last_modified
        FROM stored_passwords 
        WHERE password_id = ? AND user_id = ? AND is_active = 1
    """,
    
    'update_password': """
        UPDATE stored_passwords 
        SET username_for_site = ?, site_name = ?, site_url = ?, 
            hashed_password = ?, password_length = ?, complexity_used = ?,
            notes = ?, last_modified = CURRENT_TIMESTAMP
        WHERE password_id = ? AND user_id = ?
    """,
    
    'delete_password': """
        UPDATE stored_passwords 
        SET is_active = 0, last_modified = CURRENT_TIMESTAMP
        WHERE password_id = ? AND user_id = ?
    """,
    
    'search_passwords': """
        SELECT password_id, username_for_site, site_name, site_url,
               password_length, complexity_used, notes, created_at
        FROM stored_passwords 
        WHERE user_id = ? AND is_active = 1 
        AND (site_name LIKE ? OR username_for_site LIKE ? OR notes LIKE ?)
        ORDER BY created_at DESC
    """,
    
    'count_user_passwords': """
        SELECT COUNT(*) FROM stored_passwords 
        WHERE user_id = ? AND is_active = 1
    """
}

# Session Management Queries
SESSION_QUERIES = {
    'create_session': """
        INSERT INTO user_sessions (user_id, session_token, expires_at)
        VALUES (?, ?, ?)
    """,
    
    'get_active_session': """
        SELECT session_id, user_id, expires_at
        FROM user_sessions 
        WHERE session_token = ? AND is_active = 1 
        AND expires_at > CURRENT_TIMESTAMP
    """,
    
    'deactivate_session': """
        UPDATE user_sessions 
        SET is_active = 0 
        WHERE session_token = ?
    """,
    
    'cleanup_expired_sessions': """
        UPDATE user_sessions 
        SET is_active = 0 
        WHERE expires_at <= CURRENT_TIMESTAMP
    """
}

# Database Maintenance Queries
MAINTENANCE_QUERIES = {
    'vacuum_database': "VACUUM;",
    
    'analyze_database': "ANALYZE;",
    
    'check_integrity': "PRAGMA integrity_check;",
    
    'get_database_size': """
        SELECT page_count * page_size as size 
        FROM pragma_page_count(), pragma_page_size();
    """,
    
    'get_table_info': """
        SELECT name, sql FROM sqlite_master 
        WHERE type='table' AND name NOT LIKE 'sqlite_%';
    """
}

# Data Models (Python Classes for Type Safety)
class UserModel:
    """User data model"""
    def __init__(self, user_id=None, username=None, email=None, 
                 created_at=None, last_login=None, is_active=True):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.created_at = created_at
        self.last_login = last_login
        self.is_active = is_active

class PasswordEntryModel:
    """Stored password data model"""
    def __init__(self, password_id=None, user_id=None, username_for_site=None,
                 site_name=None, site_url=None, password_length=None,
                 complexity_used=None, notes=None, created_at=None, last_modified=None):
        self.password_id = password_id
        self.user_id = user_id
        self.username_for_site = username_for_site
        self.site_name = site_name
        self.site_url = site_url
        self.password_length = password_length
        self.complexity_used = complexity_used
        self.notes = notes
        self.created_at = created_at
        self.last_modified = last_modified

# Database Schema Version
SCHEMA_VERSION = "1.0.0"
SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# All tables to create in order
ALL_TABLES = [
    CREATE_USERS_TABLE,
    CREATE_STORED_PASSWORDS_TABLE,
    CREATE_USER_SESSIONS_TABLE,
    SCHEMA_VERSION_TABLE
]
