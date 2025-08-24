"""
Database Package - Password Generator Application
Provides database management functionality for secure password storage
"""

from .db_manager import DatabaseManager
from .models import (
    UserModel, 
    PasswordEntryModel,
    USER_QUERIES,
    PASSWORD_QUERIES,
    SESSION_QUERIES,
    SCHEMA_VERSION
)

# Package version
__version__ = "1.0.0"

# Export main classes and functions
__all__ = [
    'DatabaseManager',
    'UserModel', 
    'PasswordEntryModel',
    'USER_QUERIES',
    'PASSWORD_QUERIES', 
    'SESSION_QUERIES',
    'SCHEMA_VERSION'
]

# Package-level constants
DATABASE_PACKAGE_NAME = "password_generator.database"
SUPPORTED_DB_VERSION = "1.0.0"

# Initialize logging for the entire database package
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Package documentation
"""
This database package provides:

🔐 **Secure Storage**: All passwords are hashed before storage
📊 **User Management**: Complete user registration and authentication
🗃️ **Password Vault**: Organized storage with metadata
🛡️ **Security Features**: Account locking, session management
🚀 **Performance**: Optimized queries with proper indexing
🔧 **Maintenance**: Database health monitoring and cleanup

Example Usage:
    from database import DatabaseManager
    
    db = DatabaseManager()
    db.initialize_database()
    
    # Create user
    user_id = db.create_user("username", "email@example.com", "hashed_pwd", "salt")
    
    # Store password
    db.save_password(user_id, "myusername", "example.com", "url", 
                    "hashed_password", 12, "complex", "notes")
    
    # Retrieve passwords
    passwords = db.get_user_passwords(user_id)
"""
