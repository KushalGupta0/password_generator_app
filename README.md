# 🔐 Secure Password Generator & Manager

A desktop application built with Python and PySide6 for generating cryptographically secure passwords and managing them safely.

![Python Version](https://img.shields.io/badge/PythonCryptographically secure** random generation using Python's `secrets` module
- **Customizable complexity**: uppercase, lowercase, digits, special characters
- **Length control**: 4 to 128 characters
- **Real-time strength analysis** with entropy calculations
- **Copy to clipboard** functionality

### 🗄️ Password Storage
- **Secure SQLite database** with hashed password storage
- **Metadata tracking**: site, username, notes, creation date
- **Search functionality** across stored passwords
- **Password viewing** for recently generated passwords only

### 🔐 Security Features
- **Bcrypt hashing** for user passwords with configurable rounds
- **Account lockout** protection against brute force attacks
- **Master password verification** for viewing stored passwords
- **Input sanitization** to prevent SQL injection attacks

### 🎨 User Interface
- **Clean, modern design** with forced light theme
- **Login/Register** tabbed interface
- **Dashboard** with generation panel and password vault
- **Real-time feedback** for all user actions

***

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Setup Steps

1. **Clone/Download the Project**
   ```bash
   git clone <repository-url>
   cd password_generator_app
   ```

2. **Create Virtual Environment**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # macOS/Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**
   ```bash
   python main.py
   ```

### Required Dependencies
```txt
PySide6>=6.5.0
bcrypt>=4.0.1
cryptography>=41.0.7
```

***

## 📖 Usage

### First Time Setup
1. Launch the application: `python main.py`
2. Click "Register" tab to create a new account
3. Enter username, email (optional), and strong password
4. Click "Register" then switch to "Login" tab
5. Login with your credentials

### Generating Passwords
1. **Set Length**: Use spinner to select 4-64 characters
2. **Choose Types**: Select uppercase, lowercase, digits, special characters
3. **Generate**: Click "🎲 Generate Password"
4. **Copy**: Click "📋 Copy to Clipboard"

### Saving Passwords
1. **Fill Form**: Enter username (required), site name, notes
2. **Save**: Click "💾 Save to Vault"
3. **View**: Password is cached for immediate viewing

### Managing Stored Passwords
1. **Search**: Use search bar to find passwords
2. **View Recent**: Click "👁 View Password" (requires master password)
3. **Copy Username**: Click "📋 Copy Username"
4. **Delete**: Click "🗑 Delete" with confirmation

***

## 📁 Project Structure

```
password_generator_app/
├── main.py                    # Application entry point
├── app_config.py              # Configuration constants
├── requirements.txt           # Dependencies
├── .gitignore                # Git ignore rules
│
├── core/                     # Core business logic
│   ├── __init__.py
│   ├── auth_manager.py       # User authentication
│   ├── password_generator.py # Password generation
│   └── password_storage.py   # Password storage management
│
├── database/                 # Database layer
│   ├── __init__.py
│   ├── db_manager.py         # Database operations
│   └── models.py             # Database schema & models
│
├── security/                 # Security utilities
│   ├── __init__.py
│   └── crypto_utils.py       # Encryption & hashing
│
└── ui/                       # User interface
    ├── __init__.py
    ├── theme_manager.py      # UI theming
    ├── login_window.py       # Login/register interface
    └── main_dashboard.py     # Main application UI
```

***

## ⚙️ Configuration

### Key Settings (app_config.py)
```python
# Password Generation
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSWORD_LENGTH = 12

# Security Settings
BCRYPT_ROUNDS = 12              # Password hashing strength
SESSION_TIMEOUT = 30            # Session timeout in minutes
MAX_LOGIN_ATTEMPTS = 5          # Lockout after failed attempts

# Database
DATABASE_FILE = "password_vault.db"
```

***

## 🛡️ Security Features

- **Secrets Module**: Cryptographically secure random generation
- **Bcrypt Hashing**: User passwords hashed with 12 rounds
- **SQLite with Constraints**: Protection against SQL injection
- **Input Sanitization**: All user inputs sanitized
- **Master Password Verification**: Required for viewing passwords
- **Session Management**: Secure session handling with timeouts

***

## 🚨 Known Limitations

1. **Password Viewing**: Only recently generated passwords can be viewed
2. **Database**: Passwords are securely hashed (cannot be decrypted by design)
3. **Single User**: Desktop application for individual use
4. **No Cloud Sync**: Local storage only

***

## 🔧 Troubleshooting

**Application Won't Start**
```bash
# Check Python version
python --version

# Verify dependencies
pip list

# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

**Import Errors**
```bash
# Ensure you're in the correct directory
pwd

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
```

***

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Commit: `git commit -m "Add feature"`
6. Push: `git push origin feature-name`
7. Open a Pull Request

***

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

***

## 🆘 Support

- **Issues**: Report bugs via GitHub Issues
- **Questions**: Check existing issues or create a new one
- **Email**: Contact for additional support

***

**Made with ❤️ and 🔐 for secure password management**

*Last Updated: August 24, 2025*

[1](https://docs.python-guide.org/writing/structure/)
[2](https://discuss.python.org/t/python-project-structure/36119)
[3](https://dagster.io/blog/python-project-best-practices)
[4](https://swimm.io/learn/code-documentation/documentation-in-python-methods-and-best-practices)
[5](https://www.docuwriter.ai/posts/python-documentation-best-practices-guide)
[6](https://realpython.com/python-project-documentation-with-mkdocs/)
[7](https://testdriven.io/blog/documenting-python/)
[8](https://packaging.python.org/tutorials/packaging-projects/)
[9](https://www.clariontech.com/blog/python-development-practices)