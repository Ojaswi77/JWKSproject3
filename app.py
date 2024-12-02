"""
Enhanced JWKS Server
A secure server implementation providing:
- Secure user account creation
- Advanced password management
- Secure key storage with encryption
- Request tracking
- Request frequency control
"""
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import sqlite3
import os
import uuid
from argon2 import PasswordHasher
from datetime import datetime
from dotenv import load_dotenv
import time
from collections import defaultdict
from contextlib import contextmanager

# Initialize environment
load_dotenv()

app = Flask(__name__)

# Secret key setup
SECRET_KEY = os.getenv('NOT_MY_KEY')
if not SECRET_KEY:
    raise ValueError("Secret key not found in environment!")

# Initialize security components
cipher = Fernet(SECRET_KEY.encode())
password_manager = PasswordHasher()

# Database settings
DB_NAME = 'totally_not_my_privateKeys.db'

def secure_encrypt(data):
    """
    Apply symmetric encryption to sensitive data.
    
    Parameters:
        data (str|bytes): Content to encrypt
    Returns:
        bytes: Encrypted content
    """
    if isinstance(data, str):
        data = data.encode()
    return cipher.encrypt(data)

def secure_decrypt(encrypted_data):
    """Decrypt previously encrypted data."""
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    result = cipher.decrypt(encrypted_data)
    return result.decode()

@contextmanager
def db_connection():
    """Database connection handler with automatic cleanup."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def setup_database():
    """
    Initialize database schema and test data.
    Sets up required tables and populates initial encrypted keys.
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Reset tables
        cursor.execute('DROP TABLE IF EXISTS keys')
        cursor.execute('DROP TABLE IF EXISTS auth_logs')
        cursor.execute('DROP TABLE IF EXISTS users')
        
        # Create fresh tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        ''')

        # Add test keys
        test_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6helU/xewSE=" 
        secured_key = secure_encrypt(test_key)
        
        # Add valid and expired keys
        cursor.execute(
            'INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)',
            (1, secured_key, int(time.time()) + 3600)
        )
        cursor.execute(
            'INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)',
            (2, secured_key, int(time.time()) - 3600)
        )

# Request frequency control
request_tracker = {}
def check_rate_limit(ip):
    """Monitor and control request frequency."""
    current_time = time.time()
    if ip not in request_tracker:
        request_tracker[ip] = []
    
    request_tracker[ip] = [t for t in request_tracker[ip] if t > current_time - 1]
    
    if len(request_tracker[ip]) >= 10:
        return True
        
    request_tracker[ip].append(current_time)
    return False

def record_auth_attempt(ip, user_id=None):
    """Log authentication attempts."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
            (ip, user_id)
        )

# Initialize database
setup_database()

@app.route('/register', methods=['POST'])
def register_user():
    """
    Create new user account.
    
    Expected input:
    {
        "username": string,
        "email": string
    }
    """
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({"error": "Incomplete registration data"}), 400
    
    new_password = str(uuid.uuid4())
    try:
        secure_hash = password_manager.hash(new_password)
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                (data['username'], secure_hash, data['email'])
            )
        return jsonify({"password": new_password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Account already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth', methods=['POST'])
def authenticate():
    """
    Process authentication requests.
    
    Expected input:
    {
        "username": string,
        "password": string
    }
    """
    if check_rate_limit(request.remote_addr):
        return jsonify({"error": "Request limit exceeded"}), 429
    
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Invalid credentials format"}), 400
    
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (data['username'],))
            user = cursor.fetchone()
            
            if not user:
                record_auth_attempt(request.remote_addr)
                return jsonify({"error": "Authentication failed"}), 401
            
            try:
                password_manager.verify(user['password_hash'], data['password'])
                with db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                        (user['id'],)
                    )
                record_auth_attempt(request.remote_addr, user['id'])
                return jsonify({"message": "Login successful"}), 200
            except Exception:
                record_auth_attempt(request.remote_addr)
                return jsonify({"error": "Authentication failed"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def system_health():
    """Check system status."""
    return jsonify({"status": "operational"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=8080)