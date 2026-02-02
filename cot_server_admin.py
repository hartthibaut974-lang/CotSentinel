#!/usr/bin/env python3
"""
CoT Server Admin - Administration Tool for TAK Server
Provides a complete web-based interface for TAK Server configuration and management

Copyright 2024-2025 BlackDot Technology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

DISCLAIMER:
This software is not affiliated with, endorsed by, or connected to the TAK Product
Center, U.S. Department of Defense, or any government agency. "TAK", "ATAK", "WinTAK",
and "iTAK" are products of the U.S. Government. This is an independent, open-source
administration tool designed to work with TAK Server.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, Response, g, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
import os
import sys
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import psycopg2
from pathlib import Path
import secrets
import logging
import zipfile
import io
import base64
import hashlib
import shutil
import socket
import functools
import threading
import time
import uuid
import re
import hmac

# QR Code generation (optional - graceful fallback if not installed)
try:
    import qrcode
    from qrcode.image.pure import PyPNGImage
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    logging.warning("qrcode library not installed - QR code generation disabled")

# ============================================================================
# SECURITY UTILITY FUNCTIONS
# ============================================================================

def safe_error_response(error, default_message="An error occurred"):
    """
    Create a safe error response without exposing internal details.
    Logs the full error but returns a sanitized message to the client.
    """
    logger.error(f"Error: {error}")
    return default_message

def validate_password(password):
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, None

def validate_username(username):
    """
    Validate username format.
    Returns (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 32:
        return False, "Username must be 32 characters or less"
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', username):
        return False, "Username must start with a letter and contain only letters, numbers, underscores, and hyphens"
    return True, None

def sanitize_filename_strict(filename):
    """Strictly sanitize filename - only allow alphanumeric, dash, underscore, dot"""
    if not filename:
        return None
    # Use secure_filename first
    filename = secure_filename(filename)
    # Additional sanitization
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    # Prevent directory traversal
    filename = filename.replace('..', '')
    # Ensure not empty after sanitization
    if not filename or filename.startswith('.'):
        return None
    return filename

def generate_csrf_token():
    """Generate a CSRF token for the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    session_token = session.get('csrf_token')
    if not session_token or not token:
        return False
    return hmac.compare_digest(session_token, token)

app = Flask(__name__)

# Configure app for running behind reverse proxy (nginx)
# This ensures correct handling of X-Forwarded-* headers
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,       # Number of proxies setting X-Forwarded-For
    x_proto=1,     # Number of proxies setting X-Forwarded-Proto
    x_host=1,      # Number of proxies setting X-Forwarded-Host
    x_port=1       # Number of proxies setting X-Forwarded-Port
)

# Secret key: use environment variable or generate secure random key
app.secret_key = os.environ.get('TAK_SECRET_KEY', secrets.token_hex(32))

# Session security settings
SESSION_TIMEOUT_MINUTES = int(os.environ.get('TAK_SESSION_TIMEOUT', '30'))
MAX_LOGIN_ATTEMPTS = int(os.environ.get('TAK_MAX_LOGIN_ATTEMPTS', '5'))
LOGIN_LOCKOUT_MINUTES = int(os.environ.get('TAK_LOGIN_LOCKOUT_MINUTES', '15'))
MAX_CONCURRENT_SESSIONS = int(os.environ.get('TAK_MAX_CONCURRENT_SESSIONS', '3'))

app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('TAK_HTTPS_ENABLED', 'true').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 100MB max upload
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cot-server-admin')

# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # XSS Protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    # Cache control for sensitive pages
    if request.endpoint and request.endpoint not in ['static']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response

def csrf_protect(f):
    """Decorator to enforce CSRF protection on routes"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not validate_csrf_token(token):
                audit.log(
                    action='csrf_validation_failed',
                    category=AuditLogger.CATEGORY_SECURITY,
                    level=AuditLogger.LEVEL_WARNING,
                    success=False,
                    details=f'Endpoint: {request.endpoint}'
                )
                return jsonify({'success': False, 'error': 'Invalid or missing CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_csrf_token():
    """Make CSRF token available in all templates"""
    return dict(csrf_token=generate_csrf_token)

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter"""
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = {}
        self._lock = threading.Lock()
    
    def is_allowed(self, key):
        """Check if request is allowed"""
        now = time.time()
        with self._lock:
            # Clean old entries
            cutoff = now - self.window_seconds
            self._requests = {k: [t for t in v if t > cutoff] 
                            for k, v in self._requests.items()}
            
            # Check and record
            if key not in self._requests:
                self._requests[key] = []
            
            if len(self._requests[key]) >= self.max_requests:
                return False
            
            self._requests[key].append(now)
            return True

# Global rate limiter - 60 requests per minute per IP
api_rate_limiter = RateLimiter(max_requests=60, window_seconds=60)

@app.before_request
def check_rate_limit():
    """Check rate limit on API endpoints"""
    if request.endpoint and request.endpoint.startswith('api_') or request.path.startswith('/api/'):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        if not api_rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return jsonify({'success': False, 'error': 'Rate limit exceeded. Please slow down.'}), 429

# Configuration
TAK_DIR = os.environ.get('TAK_DIR', '/opt/tak')
CONFIG_FILE = os.path.join(TAK_DIR, "CoreConfig.xml")
CERTS_DIR = os.path.join(TAK_DIR, "certs")
USERS_FILE = os.path.join(TAK_DIR, "users.json")
CREDENTIALS_FILE = os.path.join(TAK_DIR, ".credentials")
DATA_PACKAGES_DIR = os.path.join(TAK_DIR, "data-packages")
CONNECTION_PROFILES_DIR = os.path.join(TAK_DIR, "connection-profiles")
BACKUPS_DIR = os.path.join(TAK_DIR, "backups")
CRL_FILE = os.path.join(CERTS_DIR, "crl.pem")
CRL_INDEX_FILE = os.path.join(CERTS_DIR, "index.txt")
CRL_SERIAL_FILE = os.path.join(CERTS_DIR, "crlnumber")
AUDIT_LOG_FILE = os.path.join(TAK_DIR, "audit.log")
SESSIONS_FILE = os.path.join(TAK_DIR, ".sessions")
SECURITY_FILE = os.path.join(TAK_DIR, ".security")

# Allowed file extensions for data packages
ALLOWED_EXTENSIONS = {'zip', 'dpk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================================
# AUDIT LOGGING SYSTEM
# ============================================================================

class AuditLogger:
    """Thread-safe audit logging system"""
    
    # Audit event categories
    CATEGORY_AUTH = 'authentication'
    CATEGORY_USER = 'user_management'
    CATEGORY_CERT = 'certificate'
    CATEGORY_CONFIG = 'configuration'
    CATEGORY_BACKUP = 'backup'
    CATEGORY_SYSTEM = 'system'
    CATEGORY_SECURITY = 'security'
    
    # Severity levels
    LEVEL_INFO = 'info'
    LEVEL_WARNING = 'warning'
    LEVEL_CRITICAL = 'critical'
    
    def __init__(self, log_file):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Ensure audit log file exists with proper permissions"""
        if not os.path.exists(self.log_file):
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, 'w') as f:
                f.write('')
            os.chmod(self.log_file, 0o600)
    
    def log(self, action, category, level=LEVEL_INFO, user=None, target=None, 
            details=None, success=True, ip_address=None):
        """Log an audit event"""
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'category': category,
                'level': level,
                'user': user or (current_user.id if current_user and current_user.is_authenticated else 'anonymous'),
                'ip_address': ip_address or self._get_client_ip(),
                'target': target,
                'success': success,
                'details': details,
                'session_id': session.get('session_id', 'unknown')
            }
            
            with self._lock:
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps(event) + '\n')
            
            # Also log to application logger for critical events
            if level == self.LEVEL_CRITICAL:
                logger.warning(f"AUDIT CRITICAL: {action} by {event['user']} from {event['ip_address']}")
            
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def _get_client_ip(self):
        """Get client IP address, accounting for proxy"""
        if request:
            # Check for forwarded IP (when behind proxy)
            forwarded = request.headers.get('X-Forwarded-For', '')
            if forwarded:
                return forwarded.split(',')[0].strip()
            return request.remote_addr
        return 'unknown'
    
    def get_logs(self, limit=100, offset=0, category=None, user=None, 
                 start_date=None, end_date=None, level=None):
        """Retrieve audit logs with filtering"""
        logs = []
        try:
            with self._lock:
                with open(self.log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                event = json.loads(line)
                                logs.append(event)
                            except json.JSONDecodeError:
                                continue
            
            # Apply filters
            if category:
                logs = [l for l in logs if l.get('category') == category]
            if user:
                logs = [l for l in logs if l.get('user') == user]
            if level:
                logs = [l for l in logs if l.get('level') == level]
            if start_date:
                logs = [l for l in logs if l.get('timestamp', '') >= start_date]
            if end_date:
                logs = [l for l in logs if l.get('timestamp', '') <= end_date]
            
            # Sort by timestamp descending (newest first)
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Apply pagination
            total = len(logs)
            logs = logs[offset:offset + limit]
            
            return {'logs': logs, 'total': total}
        except Exception as e:
            logger.error(f"Failed to read audit logs: {e}")
            return {'logs': [], 'total': 0}
    
    def get_stats(self, days=7):
        """Get audit log statistics"""
        try:
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            logs = self.get_logs(limit=10000)['logs']
            recent = [l for l in logs if l.get('timestamp', '') >= cutoff]
            
            stats = {
                'total_events': len(recent),
                'by_category': {},
                'by_level': {},
                'by_user': {},
                'failed_logins': 0,
                'successful_logins': 0
            }
            
            for log in recent:
                cat = log.get('category', 'unknown')
                level = log.get('level', 'info')
                user = log.get('user', 'unknown')
                
                stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
                stats['by_level'][level] = stats['by_level'].get(level, 0) + 1
                stats['by_user'][user] = stats['by_user'].get(user, 0) + 1
                
                if log.get('action') == 'login_attempt':
                    if log.get('success'):
                        stats['successful_logins'] += 1
                    else:
                        stats['failed_logins'] += 1
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get audit stats: {e}")
            return {}

# Initialize audit logger
audit = AuditLogger(AUDIT_LOG_FILE)

def audit_log(action, category=AuditLogger.CATEGORY_SYSTEM, level=AuditLogger.LEVEL_INFO):
    """Decorator to automatically audit function calls"""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            target = None
            success = True
            details = None
            
            try:
                result = f(*args, **kwargs)
                
                # Try to extract target from kwargs or result
                if 'filename' in kwargs:
                    target = kwargs['filename']
                elif 'client_name' in kwargs:
                    target = kwargs['client_name']
                
                # Check if result indicates failure
                if isinstance(result, tuple) and len(result) > 1:
                    response, status_code = result
                    if status_code >= 400:
                        success = False
                
                return result
            except Exception as e:
                success = False
                details = str(e)
                raise
            finally:
                audit.log(
                    action=action,
                    category=category,
                    level=level,
                    target=target,
                    success=success,
                    details=details
                )
        return wrapper
    return decorator

# ============================================================================
# SESSION SECURITY SYSTEM
# ============================================================================

class SessionManager:
    """Manages user sessions with security features"""
    
    def __init__(self, sessions_file, security_file):
        self.sessions_file = sessions_file
        self.security_file = security_file
        self._lock = threading.Lock()
        self._ensure_files()
    
    def _ensure_files(self):
        """Ensure session files exist"""
        for f in [self.sessions_file, self.security_file]:
            if not os.path.exists(f):
                os.makedirs(os.path.dirname(f), exist_ok=True)
                with open(f, 'w') as file:
                    json.dump({}, file)
                os.chmod(f, 0o600)
    
    def _load_sessions(self):
        """Load active sessions"""
        try:
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            return {}
    
    def _save_sessions(self, sessions):
        """Save active sessions"""
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f, indent=2)
    
    def _load_security(self):
        """Load security data (login attempts, lockouts)"""
        try:
            with open(self.security_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            return {'login_attempts': {}, 'lockouts': {}}
    
    def _save_security(self, data):
        """Save security data"""
        with open(self.security_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_session(self, username, ip_address, user_agent):
        """Create a new session for a user"""
        session_id = str(uuid.uuid4())
        
        with self._lock:
            sessions = self._load_sessions()
            
            # Get user's current sessions
            user_sessions = [s for s in sessions.values() if s.get('username') == username]
            
            # Enforce max concurrent sessions
            if len(user_sessions) >= MAX_CONCURRENT_SESSIONS:
                # Remove oldest session
                oldest = min(user_sessions, key=lambda x: x.get('created', ''))
                for sid, sdata in list(sessions.items()):
                    if sdata.get('username') == username and sdata.get('created') == oldest.get('created'):
                        del sessions[sid]
                        audit.log(
                            action='session_force_expired',
                            category=AuditLogger.CATEGORY_SECURITY,
                            level=AuditLogger.LEVEL_WARNING,
                            user=username,
                            details=f'Max concurrent sessions ({MAX_CONCURRENT_SESSIONS}) exceeded'
                        )
                        break
            
            # Create new session
            sessions[session_id] = {
                'username': username,
                'ip_address': ip_address,
                'user_agent': user_agent[:200] if user_agent else 'unknown',
                'created': datetime.now().isoformat(),
                'last_activity': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
            }
            
            self._save_sessions(sessions)
        
        return session_id
    
    def validate_session(self, session_id):
        """Validate a session and update last activity"""
        if not session_id:
            return False
        
        with self._lock:
            sessions = self._load_sessions()
            
            if session_id not in sessions:
                return False
            
            sess = sessions[session_id]
            
            # Check expiration
            expires = datetime.fromisoformat(sess['expires'])
            if datetime.now() > expires:
                del sessions[session_id]
                self._save_sessions(sessions)
                return False
            
            # Update last activity and extend expiration
            sess['last_activity'] = datetime.now().isoformat()
            sess['expires'] = (datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
            sessions[session_id] = sess
            self._save_sessions(sessions)
            
            return True
    
    def end_session(self, session_id):
        """End a specific session"""
        with self._lock:
            sessions = self._load_sessions()
            if session_id in sessions:
                del sessions[session_id]
                self._save_sessions(sessions)
                return True
        return False
    
    def end_all_user_sessions(self, username, except_session=None):
        """End all sessions for a user (optionally except current)"""
        with self._lock:
            sessions = self._load_sessions()
            to_remove = [
                sid for sid, sdata in sessions.items() 
                if sdata.get('username') == username and sid != except_session
            ]
            for sid in to_remove:
                del sessions[sid]
            self._save_sessions(sessions)
        return len(to_remove)
    
    def get_active_sessions(self, username=None):
        """Get all active sessions, optionally filtered by user"""
        with self._lock:
            sessions = self._load_sessions()
            
            # Clean expired sessions
            now = datetime.now()
            valid_sessions = {}
            for sid, sdata in sessions.items():
                expires = datetime.fromisoformat(sdata.get('expires', '2000-01-01'))
                if now < expires:
                    valid_sessions[sid] = sdata
            
            if len(valid_sessions) != len(sessions):
                self._save_sessions(valid_sessions)
            
            if username:
                return {sid: s for sid, s in valid_sessions.items() if s.get('username') == username}
            return valid_sessions
    
    def record_login_attempt(self, username, ip_address, success):
        """Record a login attempt for rate limiting"""
        with self._lock:
            security = self._load_security()
            
            key = f"{username}:{ip_address}"
            now = datetime.now()
            
            if key not in security['login_attempts']:
                security['login_attempts'][key] = []
            
            # Add this attempt
            security['login_attempts'][key].append({
                'timestamp': now.isoformat(),
                'success': success
            })
            
            # Keep only attempts from last lockout period
            cutoff = (now - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
            security['login_attempts'][key] = [
                a for a in security['login_attempts'][key] 
                if a['timestamp'] >= cutoff
            ]
            
            # Check if should be locked out
            failed_attempts = [a for a in security['login_attempts'][key] if not a['success']]
            if len(failed_attempts) >= MAX_LOGIN_ATTEMPTS:
                security['lockouts'][key] = (now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
                audit.log(
                    action='account_locked',
                    category=AuditLogger.CATEGORY_SECURITY,
                    level=AuditLogger.LEVEL_CRITICAL,
                    user=username,
                    ip_address=ip_address,
                    details=f'Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts'
                )
            
            self._save_security(security)
    
    def is_locked_out(self, username, ip_address):
        """Check if a user/IP is locked out"""
        with self._lock:
            security = self._load_security()
            key = f"{username}:{ip_address}"
            
            if key in security['lockouts']:
                lockout_until = datetime.fromisoformat(security['lockouts'][key])
                if datetime.now() < lockout_until:
                    return True, lockout_until
                else:
                    # Lockout expired, remove it
                    del security['lockouts'][key]
                    self._save_security(security)
            
            return False, None
    
    def clear_lockout(self, username, ip_address=None):
        """Clear lockout for a user (admin function)"""
        with self._lock:
            security = self._load_security()
            
            if ip_address:
                key = f"{username}:{ip_address}"
                if key in security['lockouts']:
                    del security['lockouts'][key]
            else:
                # Clear all lockouts for this user
                to_remove = [k for k in security['lockouts'] if k.startswith(f"{username}:")]
                for k in to_remove:
                    del security['lockouts'][k]
            
            self._save_security(security)
    
    def get_failed_attempts(self, username, ip_address):
        """Get number of recent failed login attempts"""
        with self._lock:
            security = self._load_security()
            key = f"{username}:{ip_address}"
            
            if key not in security['login_attempts']:
                return 0
            
            cutoff = (datetime.now() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
            recent = [a for a in security['login_attempts'][key] 
                     if a['timestamp'] >= cutoff and not a['success']]
            return len(recent)

# Initialize session manager
session_mgr = SessionManager(SESSIONS_FILE, SECURITY_FILE)

@app.before_request
def check_session_validity():
    """Check session validity on each request"""
    # Skip for static files and login page
    if request.endpoint in ['login', 'static', None]:
        return
    
    if current_user and current_user.is_authenticated:
        session_id = session.get('session_id')
        if session_id and not session_mgr.validate_session(session_id):
            logout_user()
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            audit.log(
                action='session_expired',
                category=AuditLogger.CATEGORY_AUTH,
                level=AuditLogger.LEVEL_INFO
            )
            return redirect(url_for('login'))

def load_credentials():
    """Load credentials from environment variables or credentials file"""
    creds = {
        'db_password': os.environ.get('TAK_DB_PASSWORD'),
        'cert_password': os.environ.get('TAK_CERT_PASSWORD'),
        'web_admin_password': os.environ.get('TAK_WEB_ADMIN_PASSWORD')
    }
    
    # Fall back to credentials file if env vars not set
    if os.path.exists(CREDENTIALS_FILE) and not all(creds.values()):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if key == 'tak_db_password' and not creds['db_password']:
                            creds['db_password'] = value
                        elif key == 'tak_cert_password' and not creds['cert_password']:
                            creds['cert_password'] = value
                        elif key == 'cot_admin_password' and not creds['web_admin_password']:
                            creds['web_admin_password'] = value
        except Exception as e:
            print(f"Warning: Could not load credentials file: {e}")
    
    return creds

# Load credentials
_credentials = load_credentials()

# Database configuration - uses environment variable or credentials file
DB_CONFIG = {
    'host': os.environ.get('TAK_DB_HOST', 'localhost'),
    'database': os.environ.get('TAK_DB_NAME', 'takserver'),
    'user': os.environ.get('TAK_DB_USER', 'takserver'),
    'password': _credentials.get('db_password') or os.environ.get('TAK_DB_PASSWORD', '')
}

# Certificate password for generating client certs
CERT_PASSWORD = _credentials.get('cert_password') or os.environ.get('TAK_CERT_PASSWORD', '')

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

# User storage (in production, use a proper database)
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

@login_manager.user_loader
def load_user(username):
    users = load_users()
    if username in users:
        return User(username)
    return None

# Routes
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', 'unknown')
        
        # Check if account is locked out
        is_locked, lockout_until = session_mgr.is_locked_out(username, ip_address)
        if is_locked:
            remaining = (lockout_until - datetime.now()).seconds // 60 + 1
            flash(f'Account temporarily locked. Try again in {remaining} minutes.', 'error')
            audit.log(
                action='login_blocked',
                category=AuditLogger.CATEGORY_AUTH,
                level=AuditLogger.LEVEL_WARNING,
                user=username,
                ip_address=ip_address,
                success=False,
                details='Account locked due to too many failed attempts'
            )
            return render_template('login.html')
        
        users = load_users()
        
        # Create default admin user if no users exist
        if not users:
            default_password = _credentials.get('web_admin_password') or secrets.token_urlsafe(16)
            users['admin'] = {'password': generate_password_hash(default_password), 'role': 'admin'}
            save_users(users)
            logger.info(f"Default admin user created. Check {CREDENTIALS_FILE} for password.")
        
        # Validate credentials
        if username in users and check_password_hash(users[username]['password'], password):
            # Successful login
            user = User(username)
            login_user(user, remember=False)
            session.permanent = True
            
            # Create session
            session_id = session_mgr.create_session(username, ip_address, user_agent)
            session['session_id'] = session_id
            session['login_time'] = datetime.now().isoformat()
            
            # Record successful login
            session_mgr.record_login_attempt(username, ip_address, True)
            
            # Audit log
            audit.log(
                action='login_success',
                category=AuditLogger.CATEGORY_AUTH,
                level=AuditLogger.LEVEL_INFO,
                user=username,
                ip_address=ip_address,
                success=True,
                details=f'User agent: {user_agent[:100]}'
            )
            
            logger.info(f"User '{username}' logged in from {ip_address}")
            
            # Redirect to originally requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('index'))
        
        # Failed login
        session_mgr.record_login_attempt(username, ip_address, False)
        failed_count = session_mgr.get_failed_attempts(username, ip_address)
        remaining_attempts = MAX_LOGIN_ATTEMPTS - failed_count
        
        audit.log(
            action='login_failed',
            category=AuditLogger.CATEGORY_AUTH,
            level=AuditLogger.LEVEL_WARNING,
            user=username,
            ip_address=ip_address,
            success=False,
            details=f'Invalid credentials. {remaining_attempts} attempts remaining.'
        )
        
        if remaining_attempts > 0:
            flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'error')
        else:
            flash(f'Account locked for {LOGIN_LOCKOUT_MINUTES} minutes due to too many failed attempts.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.id if current_user and current_user.is_authenticated else 'unknown'
    session_id = session.get('session_id')
    
    # End the session
    if session_id:
        session_mgr.end_session(session_id)
    
    # Audit log
    audit.log(
        action='logout',
        category=AuditLogger.CATEGORY_AUTH,
        level=AuditLogger.LEVEL_INFO,
        user=username,
        success=True
    )
    
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/api/system/status')
@login_required
def system_status():
    """Get system and TAK Server status"""
    try:
        # Check if TAK Server is running
        tak_status = subprocess.run(['systemctl', 'is-active', 'takserver'], 
                                   capture_output=True, text=True)
        tak_running = tak_status.stdout.strip() == 'active'
        
        # Check PostgreSQL status
        pg_status = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                  capture_output=True, text=True)
        pg_running = pg_status.stdout.strip() == 'active'
        
        # Get system info
        uptime = subprocess.run(['uptime', '-p'], capture_output=True, text=True).stdout.strip()
        memory = subprocess.run(['free', '-h'], capture_output=True, text=True).stdout
        
        # Get connected clients count from database
        connected_clients = 0
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM cot_router WHERE last_event_time > NOW() - INTERVAL '5 minutes'")
            result = cur.fetchone()
            connected_clients = result[0] if result else 0
            cur.close()
            conn.close()
        except (psycopg2.Error, TypeError, IndexError):
            # Database not available or query failed - continue with 0 clients
            connected_clients = 0
        
        return jsonify({
            'success': True,
            'tak_server': {
                'running': tak_running,
                'status': 'Running' if tak_running else 'Stopped'
            },
            'postgresql': {
                'running': pg_running,
                'status': 'Running' if pg_running else 'Stopped'
            },
            'system': {
                'uptime': uptime,
                'memory': memory
            },
            'stats': {
                'connected_clients': connected_clients
            }
        })
    except Exception as e:
        logger.error(f"System status error: {e}")
        return jsonify({'success': False, 'error': 'Failed to get system status'}), 500

@app.route('/api/server/control/<action>', methods=['POST'])
@login_required
def server_control(action):
    """Control TAK Server (start/stop/restart)"""
    try:
        # Whitelist validation for action
        ALLOWED_ACTIONS = {'start', 'stop', 'restart'}
        if action not in ALLOWED_ACTIONS:
            audit.log(
                action='server_control_invalid',
                category=AuditLogger.CATEGORY_SYSTEM,
                level=AuditLogger.LEVEL_WARNING,
                target='takserver',
                success=False,
                details=f'Invalid action attempted: {action}'
            )
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        result = subprocess.run(
            ['systemctl', action, 'takserver'],
            capture_output=True,
            text=True,
            timeout=30  # Add timeout to prevent hanging
        )
        
        if result.returncode == 0:
            audit.log(
                action=f'server_{action}',
                category=AuditLogger.CATEGORY_SYSTEM,
                level=AuditLogger.LEVEL_INFO,
                target='takserver',
                success=True
            )
            logger.info(f"TAK Server {action} executed by {current_user.id}")
            return jsonify({
                'success': True,
                'message': f'TAK Server {action} command executed successfully'
            })
        else:
            audit.log(
                action=f'server_{action}',
                category=AuditLogger.CATEGORY_SYSTEM,
                level=AuditLogger.LEVEL_WARNING,
                target='takserver',
                success=False,
                details=result.stderr[:200] if result.stderr else 'Unknown error'
            )
            # Don't expose detailed error messages to client
            return jsonify({
                'success': False,
                'error': f'Failed to {action} TAK Server'
            }), 500
    except subprocess.TimeoutExpired:
        logger.error(f"Server control timeout: {action}")
        return jsonify({'success': False, 'error': 'Operation timed out'}), 504
    except Exception as e:
        logger.error(f"Server control error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/config/get')
@login_required
def get_config():
    """Get current TAK Server configuration"""
    try:
        if os.path.exists(CONFIG_FILE):
            tree = ET.parse(CONFIG_FILE)
            root = tree.getroot()
            
            # Extract key configuration elements
            config = {
                'network': [],
                'repository': {},
                'security': {},
                'raw_xml': ET.tostring(root, encoding='unicode')
            }
            
            # Parse network inputs
            network = root.find('network')
            if network is not None:
                for inp in network.findall('input'):
                    config['network'].append({
                        'protocol': inp.get('protocol'),
                        'port': inp.get('port'),
                        'auth': inp.get('auth', 'none')
                    })
            
            # Parse repository
            repo = root.find('repository')
            if repo is not None:
                conn = repo.find('connection')
                if conn is not None:
                    config['repository'] = {
                        'url': conn.get('url'),
                        'username': conn.get('username'),
                        'enabled': repo.get('enable', 'false')
                    }
            
            return jsonify({'success': True, 'config': config})
        else:
            return jsonify({'success': False, 'error': 'Config file not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/update', methods=['POST'])
@login_required
def update_config():
    """Update TAK Server configuration"""
    try:
        data = request.json
        
        if 'raw_xml' in data:
            # Validate XML before saving
            try:
                ET.fromstring(data['raw_xml'])
            except ET.ParseError as e:
                return jsonify({'success': False, 'error': f'Invalid XML: {str(e)}'}), 400
            
            # Backup current config
            backup_file = f"{CONFIG_FILE}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if os.path.exists(CONFIG_FILE):
                subprocess.run(['cp', CONFIG_FILE, backup_file])
            
            # Write new config
            with open(CONFIG_FILE, 'w') as f:
                f.write(data['raw_xml'])
            
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully',
                'backup': backup_file
            })
        else:
            return jsonify({'success': False, 'error': 'No configuration data provided'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certs/list')
@login_required
def list_certificates():
    """List all certificates"""
    try:
        certs = []
        if os.path.exists(CERTS_DIR):
            for file in os.listdir(CERTS_DIR):
                if file.endswith('.crt') or file.endswith('.pem'):
                    filepath = os.path.join(CERTS_DIR, file)
                    stat = os.stat(filepath)
                    certs.append({
                        'name': file,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        
        return jsonify({'success': True, 'certificates': certs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certs/generate', methods=['POST'])
@login_required
def generate_certificate():
    """Generate a new client certificate"""
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        client_name = data.get('client_name', '').strip()
        
        if not client_name:
            return jsonify({'success': False, 'error': 'Client name is required'}), 400
        
        # Validate client name length
        if len(client_name) > 64:
            return jsonify({'success': False, 'error': 'Client name too long (max 64 characters)'}), 400
        
        # Sanitize client name - only alphanumeric, dash, underscore
        original_name = client_name
        client_name = ''.join(c for c in client_name if c.isalnum() or c in '-_')
        
        if not client_name:
            return jsonify({'success': False, 'error': 'Invalid client name - must contain alphanumeric characters'}), 400
        
        cert_file = os.path.join(CERTS_DIR, f"{client_name}.crt")
        key_file = os.path.join(CERTS_DIR, f"{client_name}.key")
        p12_file = os.path.join(CERTS_DIR, f"{client_name}.p12")
        
        # Check if certificate already exists
        if os.path.exists(cert_file):
            audit.log(
                action='cert_generate_failed',
                category=AuditLogger.CATEGORY_CERT,
                level=AuditLogger.LEVEL_WARNING,
                target=client_name,
                success=False,
                details='Certificate already exists'
            )
            return jsonify({'success': False, 'error': 'Certificate already exists'}), 409
        
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', key_file, '4096'
        ], check=True, capture_output=True, timeout=60)
        
        # Generate certificate signing request
        csr_file = os.path.join(CERTS_DIR, f"{client_name}.csr")
        subprocess.run([
            'openssl', 'req', '-new', '-key', key_file, '-out', csr_file,
            '-subj', f'/C=US/ST=State/L=City/O=TAK/CN={client_name}'
        ], check=True, capture_output=True, timeout=30)
        
        # Sign certificate with CA
        ca_cert = os.path.join(CERTS_DIR, 'ca.crt')
        ca_key = os.path.join(CERTS_DIR, 'ca.key')
        
        # Verify CA files exist
        if not os.path.exists(ca_cert) or not os.path.exists(ca_key):
            return jsonify({'success': False, 'error': 'CA certificate not found'}), 500
        
        subprocess.run([
            'openssl', 'x509', '-req', '-days', '365',
            '-in', csr_file, '-CA', ca_cert, '-CAkey', ca_key,
            '-set_serial', str(int(datetime.now().timestamp())),
            '-out', cert_file
        ], check=True, capture_output=True, timeout=30)
        
        # Create PKCS12 bundle for easy client import
        # Use configured password or generate a random one (never use hardcoded default)
        if CERT_PASSWORD:
            cert_pass = CERT_PASSWORD
        else:
            cert_pass = secrets.token_urlsafe(12)
            logger.warning(f"No certificate password configured - generated random password for {client_name}")
        
        subprocess.run([
            'openssl', 'pkcs12', '-export',
            '-in', cert_file, '-inkey', key_file,
            '-out', p12_file, '-password', f'pass:{cert_pass}'
        ], check=True, capture_output=True, timeout=30)
        
        # Clean up CSR
        if os.path.exists(csr_file):
            os.remove(csr_file)
        
        # Audit log successful generation
        audit.log(
            action='cert_generated',
            category=AuditLogger.CATEGORY_CERT,
            level=AuditLogger.LEVEL_INFO,
            target=client_name,
            success=True
        )
        
        logger.info(f"Certificate generated for '{client_name}' by {current_user.id}")
        
        return jsonify({
            'success': True,
            'message': f'Certificate generated for {client_name}',
            'files': {
                'certificate': f'{client_name}.crt',
                'key': f'{client_name}.key',
                'p12': f'{client_name}.p12'
            }
        })
    except subprocess.CalledProcessError as e:
        logger.error(f"Certificate generation failed for '{client_name}': {e}")
        audit.log(
            action='cert_generate_failed',
            category=AuditLogger.CATEGORY_CERT,
            level=AuditLogger.LEVEL_WARNING,
            target=client_name if 'client_name' in dir() else 'unknown',
            success=False,
            details='OpenSSL command failed'
        )
        return jsonify({'success': False, 'error': 'Certificate generation failed'}), 500
    except subprocess.TimeoutExpired:
        logger.error("Certificate generation timed out")
        return jsonify({'success': False, 'error': 'Operation timed out'}), 504
    except Exception as e:
        logger.error(f"Certificate generation error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/certs/download/<filename>')
@login_required
def download_certificate(filename):
    """Download a certificate file"""
    try:
        # Sanitize filename to prevent directory traversal
        original_filename = filename
        filename = os.path.basename(filename)
        
        # Additional validation - only allow certain extensions
        allowed_extensions = {'.crt', '.key', '.p12', '.pem'}
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            audit.log(
                action='cert_download_blocked',
                category=AuditLogger.CATEGORY_CERT,
                level=AuditLogger.LEVEL_WARNING,
                target=original_filename,
                success=False,
                details='Invalid file extension'
            )
            return jsonify({'success': False, 'error': 'Invalid file type'}), 400
        
        filepath = os.path.join(CERTS_DIR, filename)
        
        # Verify the resolved path is within CERTS_DIR (defense in depth)
        real_certs_dir = os.path.realpath(CERTS_DIR)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_certs_dir + os.sep):
            audit.log(
                action='cert_download_blocked',
                category=AuditLogger.CATEGORY_SECURITY,
                level=AuditLogger.LEVEL_CRITICAL,
                target=original_filename,
                success=False,
                details='Path traversal attempt detected'
            )
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Audit log successful download
        audit.log(
            action='cert_downloaded',
            category=AuditLogger.CATEGORY_CERT,
            level=AuditLogger.LEVEL_INFO,
            target=filename,
            success=True
        )
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        logger.error(f"Certificate download error: {e}")
        return jsonify({'success': False, 'error': 'Download failed'}), 500

# ============================================================================
# CERTIFICATE REVOCATION
# ============================================================================

def init_crl_infrastructure():
    """Initialize CRL infrastructure if not exists"""
    try:
        # Create index file if not exists
        if not os.path.exists(CRL_INDEX_FILE):
            with open(CRL_INDEX_FILE, 'w') as f:
                pass  # Empty file
        
        # Create serial number file if not exists
        if not os.path.exists(CRL_SERIAL_FILE):
            with open(CRL_SERIAL_FILE, 'w') as f:
                f.write('1000\n')
        
        # Create OpenSSL config for CRL if not exists
        openssl_conf = os.path.join(CERTS_DIR, 'openssl-crl.cnf')
        if not os.path.exists(openssl_conf):
            conf_content = f'''[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {CERTS_DIR}
database = {CRL_INDEX_FILE}
certificate = {os.path.join(CERTS_DIR, 'ca.crt')}
private_key = {os.path.join(CERTS_DIR, 'ca.key')}
crlnumber = {CRL_SERIAL_FILE}
default_crl_days = 30
default_md = sha256
'''
            with open(openssl_conf, 'w') as f:
                f.write(conf_content)
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize CRL infrastructure: {e}")
        return False

def get_cert_serial(cert_path):
    """Get serial number from a certificate"""
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-serial', '-noout'],
            capture_output=True, text=True, check=True
        )
        # Output is like "serial=1234ABCD"
        serial = result.stdout.strip().split('=')[1]
        return serial
    except Exception as e:
        logger.error(f"Failed to get certificate serial: {e}")
        return None

def get_cert_info(cert_path):
    """Get certificate information"""
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-subject', '-serial', '-dates'],
            capture_output=True, text=True, check=True
        )
        lines = result.stdout.strip().split('\n')
        info = {}
        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                info[key.strip()] = value.strip()
        return info
    except Exception as e:
        logger.error(f"Failed to get certificate info: {e}")
        return None

@app.route('/api/certs/revoke', methods=['POST'])
@login_required
def revoke_certificate():
    """Revoke a client certificate"""
    try:
        data = request.json
        cert_name = data.get('cert_name', '').strip()
        reason = data.get('reason', 'unspecified')
        
        if not cert_name:
            return jsonify({'success': False, 'error': 'Certificate name is required'}), 400
        
        # Sanitize certificate name
        cert_name = ''.join(c for c in cert_name if c.isalnum() or c in '-_.')
        
        # Find the certificate file
        cert_file = os.path.join(CERTS_DIR, cert_name)
        if not cert_name.endswith('.crt'):
            cert_file = os.path.join(CERTS_DIR, f"{cert_name}.crt")
        
        if not os.path.exists(cert_file):
            return jsonify({'success': False, 'error': 'Certificate not found'}), 404
        
        # Don't allow revoking CA certificate
        if 'ca.crt' in cert_file or 'ca-' in cert_file:
            return jsonify({'success': False, 'error': 'Cannot revoke CA certificate'}), 403
        
        # Initialize CRL infrastructure
        init_crl_infrastructure()
        
        # Get certificate serial
        serial = get_cert_serial(cert_file)
        if not serial:
            return jsonify({'success': False, 'error': 'Could not read certificate serial'}), 500
        
        # Check if already revoked
        revoked_file = os.path.join(CERTS_DIR, 'revoked.json')
        revoked_certs = {}
        if os.path.exists(revoked_file):
            with open(revoked_file, 'r') as f:
                revoked_certs = json.load(f)
        
        base_name = os.path.basename(cert_file)
        if base_name in revoked_certs:
            return jsonify({'success': False, 'error': 'Certificate already revoked'}), 409
        
        # Valid revocation reasons per RFC 5280
        valid_reasons = [
            'unspecified', 'keyCompromise', 'caCompromise', 'affiliationChanged',
            'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL'
        ]
        if reason not in valid_reasons:
            reason = 'unspecified'
        
        # Add to revoked list
        cert_info = get_cert_info(cert_file)
        revoked_certs[base_name] = {
            'serial': serial,
            'revoked_at': datetime.now().isoformat(),
            'reason': reason,
            'subject': cert_info.get('subject', '') if cert_info else '',
            'not_after': cert_info.get('notAfter', '') if cert_info else ''
        }
        
        with open(revoked_file, 'w') as f:
            json.dump(revoked_certs, f, indent=2)
        
        # Move certificate to revoked directory
        revoked_dir = os.path.join(CERTS_DIR, 'revoked')
        os.makedirs(revoked_dir, exist_ok=True)
        
        # Move all related files (.crt, .key, .p12)
        base_name_no_ext = os.path.splitext(base_name)[0]
        for ext in ['.crt', '.key', '.p12', '.pem']:
            src = os.path.join(CERTS_DIR, f"{base_name_no_ext}{ext}")
            if os.path.exists(src):
                dst = os.path.join(revoked_dir, f"{base_name_no_ext}{ext}")
                shutil.move(src, dst)
        
        # Regenerate CRL
        regenerate_crl()
        
        logger.info(f"Certificate revoked: {base_name} (reason: {reason})")
        
        return jsonify({
            'success': True,
            'message': f'Certificate {base_name} has been revoked',
            'serial': serial,
            'reason': reason
        })
    except Exception as e:
        logger.error(f"Certificate revocation failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def regenerate_crl():
    """Regenerate the Certificate Revocation List"""
    try:
        ca_cert = os.path.join(CERTS_DIR, 'ca.crt')
        ca_key = os.path.join(CERTS_DIR, 'ca.key')
        
        if not os.path.exists(ca_cert) or not os.path.exists(ca_key):
            logger.warning("CA certificate or key not found, cannot generate CRL")
            return False
        
        # Load revoked certificates
        revoked_file = os.path.join(CERTS_DIR, 'revoked.json')
        if not os.path.exists(revoked_file):
            return True  # No revoked certs, no CRL needed
        
        with open(revoked_file, 'r') as f:
            revoked_certs = json.load(f)
        
        if not revoked_certs:
            return True
        
        # Create a simple CRL using openssl
        # First, create the index.txt format
        index_content = ""
        for cert_name, info in revoked_certs.items():
            # Format: R\t<expiry>\t<revoke_time>\t<serial>\tunknown\t<subject>
            revoke_time = datetime.fromisoformat(info['revoked_at']).strftime('%y%m%d%H%M%SZ')
            serial = info['serial']
            subject = info.get('subject', f'/CN={cert_name}')
            index_content += f"R\t\t{revoke_time}\t{serial}\tunknown\t{subject}\n"
        
        with open(CRL_INDEX_FILE, 'w') as f:
            f.write(index_content)
        
        # Generate CRL
        openssl_conf = os.path.join(CERTS_DIR, 'openssl-crl.cnf')
        subprocess.run([
            'openssl', 'ca', '-gencrl',
            '-config', openssl_conf,
            '-out', CRL_FILE
        ], capture_output=True, check=True)
        
        logger.info("CRL regenerated successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to regenerate CRL: {e}")
        return False

@app.route('/api/certs/revoked')
@login_required
def list_revoked_certificates():
    """List all revoked certificates"""
    try:
        revoked_file = os.path.join(CERTS_DIR, 'revoked.json')
        if not os.path.exists(revoked_file):
            return jsonify({'success': True, 'revoked': []})
        
        with open(revoked_file, 'r') as f:
            revoked_certs = json.load(f)
        
        # Convert to list format
        revoked_list = []
        for cert_name, info in revoked_certs.items():
            revoked_list.append({
                'name': cert_name,
                'serial': info.get('serial', ''),
                'revoked_at': info.get('revoked_at', ''),
                'reason': info.get('reason', 'unspecified'),
                'subject': info.get('subject', '')
            })
        
        # Sort by revocation date, newest first
        revoked_list.sort(key=lambda x: x['revoked_at'], reverse=True)
        
        return jsonify({'success': True, 'revoked': revoked_list})
    except Exception as e:
        logger.error(f"Failed to list revoked certificates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certs/crl')
@login_required
def get_crl():
    """Get the current CRL"""
    try:
        if not os.path.exists(CRL_FILE):
            # Try to generate it
            regenerate_crl()
        
        if os.path.exists(CRL_FILE):
            return send_file(CRL_FILE, as_attachment=True, download_name='crl.pem')
        else:
            return jsonify({'success': False, 'error': 'CRL not available'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certs/unrevoke', methods=['POST'])
@login_required
def unrevoke_certificate():
    """Restore a revoked certificate (remove from revocation list)"""
    try:
        data = request.json
        cert_name = data.get('cert_name', '').strip()
        
        if not cert_name:
            return jsonify({'success': False, 'error': 'Certificate name is required'}), 400
        
        revoked_file = os.path.join(CERTS_DIR, 'revoked.json')
        if not os.path.exists(revoked_file):
            return jsonify({'success': False, 'error': 'No revoked certificates'}), 404
        
        with open(revoked_file, 'r') as f:
            revoked_certs = json.load(f)
        
        if cert_name not in revoked_certs:
            return jsonify({'success': False, 'error': 'Certificate not in revocation list'}), 404
        
        # Remove from revoked list
        del revoked_certs[cert_name]
        
        with open(revoked_file, 'w') as f:
            json.dump(revoked_certs, f, indent=2)
        
        # Move certificate back from revoked directory
        revoked_dir = os.path.join(CERTS_DIR, 'revoked')
        base_name_no_ext = os.path.splitext(cert_name)[0]
        
        for ext in ['.crt', '.key', '.p12', '.pem']:
            src = os.path.join(revoked_dir, f"{base_name_no_ext}{ext}")
            if os.path.exists(src):
                dst = os.path.join(CERTS_DIR, f"{base_name_no_ext}{ext}")
                shutil.move(src, dst)
        
        # Regenerate CRL
        regenerate_crl()
        
        logger.info(f"Certificate unrevoked: {cert_name}")
        
        return jsonify({
            'success': True,
            'message': f'Certificate {cert_name} has been restored'
        })
    except Exception as e:
        logger.error(f"Certificate unrevocation failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# BACKUP & RESTORE
# ============================================================================

# Backup page
@app.route('/backups')
@login_required
def backups_page():
    return render_template('backups.html')

@app.route('/api/backups/create', methods=['POST'])
@login_required
def create_backup():
    """Create a full system backup"""
    try:
        os.makedirs(BACKUPS_DIR, exist_ok=True)
        
        data = request.json or {}
        backup_name = data.get('name', '').strip()
        include_db = data.get('include_database', True)
        include_certs = data.get('include_certificates', True)
        include_config = data.get('include_config', True)
        include_packages = data.get('include_packages', False)
        
        # Generate backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if backup_name:
            backup_name = ''.join(c for c in backup_name if c.isalnum() or c in '-_')
            backup_filename = f"tak_backup_{backup_name}_{timestamp}.zip"
        else:
            backup_filename = f"tak_backup_{timestamp}.zip"
        
        backup_path = os.path.join(BACKUPS_DIR, backup_filename)
        
        # Create backup manifest
        manifest = {
            'created': datetime.now().isoformat(),
            'version': '1.0',
            'hostname': socket.gethostname(),
            'contents': {
                'database': include_db,
                'certificates': include_certs,
                'config': include_config,
                'packages': include_packages
            },
            'files': []
        }
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Backup certificates
            if include_certs and os.path.exists(CERTS_DIR):
                for root, dirs, files in os.walk(CERTS_DIR):
                    # Skip revoked directory in main backup (include separately)
                    if 'revoked' in dirs:
                        dirs.remove('revoked')
                    for file in files:
                        filepath = os.path.join(root, file)
                        arcname = os.path.join('certs', os.path.relpath(filepath, CERTS_DIR))
                        zf.write(filepath, arcname)
                        manifest['files'].append(arcname)
                
                # Also backup revoked certificates info
                revoked_dir = os.path.join(CERTS_DIR, 'revoked')
                if os.path.exists(revoked_dir):
                    for file in os.listdir(revoked_dir):
                        filepath = os.path.join(revoked_dir, file)
                        if os.path.isfile(filepath):
                            arcname = os.path.join('certs', 'revoked', file)
                            zf.write(filepath, arcname)
                            manifest['files'].append(arcname)
            
            # Backup configuration
            if include_config:
                if os.path.exists(CONFIG_FILE):
                    zf.write(CONFIG_FILE, 'config/CoreConfig.xml')
                    manifest['files'].append('config/CoreConfig.xml')
                
                if os.path.exists(CREDENTIALS_FILE):
                    zf.write(CREDENTIALS_FILE, 'config/.credentials')
                    manifest['files'].append('config/.credentials')
                
                if os.path.exists(USERS_FILE):
                    zf.write(USERS_FILE, 'config/users.json')
                    manifest['files'].append('config/users.json')
                
                # Backup any additional config files
                for cfg_file in ['installation-info.txt', 'server.json']:
                    cfg_path = os.path.join(TAK_DIR, cfg_file)
                    if os.path.exists(cfg_path):
                        zf.write(cfg_path, f'config/{cfg_file}')
                        manifest['files'].append(f'config/{cfg_file}')
            
            # Backup database
            if include_db:
                try:
                    db_backup_file = f'/tmp/tak_db_backup_{timestamp}.sql'
                    result = subprocess.run(
                        ['sudo', '-u', 'postgres', 'pg_dump', 'takserver'],
                        capture_output=True, text=True, timeout=300
                    )
                    if result.returncode == 0:
                        zf.writestr('database/takserver.sql', result.stdout)
                        manifest['files'].append('database/takserver.sql')
                        manifest['database_size'] = len(result.stdout)
                    else:
                        manifest['database_error'] = result.stderr
                except subprocess.TimeoutExpired:
                    manifest['database_error'] = 'Database backup timed out'
                except Exception as e:
                    manifest['database_error'] = str(e)
            
            # Backup data packages
            if include_packages and os.path.exists(DATA_PACKAGES_DIR):
                for file in os.listdir(DATA_PACKAGES_DIR):
                    filepath = os.path.join(DATA_PACKAGES_DIR, file)
                    if os.path.isfile(filepath):
                        arcname = os.path.join('data-packages', file)
                        zf.write(filepath, arcname)
                        manifest['files'].append(arcname)
            
            # Write manifest
            zf.writestr('manifest.json', json.dumps(manifest, indent=2))
        
        # Get backup size
        backup_size = os.path.getsize(backup_path)
        
        logger.info(f"Backup created: {backup_filename} ({format_file_size(backup_size)})")
        
        return jsonify({
            'success': True,
            'message': 'Backup created successfully',
            'filename': backup_filename,
            'size': backup_size,
            'size_human': format_file_size(backup_size),
            'file_count': len(manifest['files'])
        })
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backups/list')
@login_required
def list_backups():
    """List all available backups"""
    try:
        os.makedirs(BACKUPS_DIR, exist_ok=True)
        backups = []
        
        for filename in os.listdir(BACKUPS_DIR):
            if filename.endswith('.zip'):
                filepath = os.path.join(BACKUPS_DIR, filename)
                stat = os.stat(filepath)
                
                # Try to read manifest
                manifest = None
                try:
                    with zipfile.ZipFile(filepath, 'r') as zf:
                        if 'manifest.json' in zf.namelist():
                            manifest = json.loads(zf.read('manifest.json').decode())
                except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, UnicodeDecodeError):
                    # Corrupt zip or invalid manifest - continue without manifest
                    pass
                
                backups.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'size_human': format_file_size(stat.st_size),
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'manifest': manifest
                })
        
        # Sort by creation date, newest first
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({'success': True, 'backups': backups})
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backups/download/<filename>')
@login_required
def download_backup(filename):
    """Download a backup file"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(BACKUPS_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Backup not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backups/delete/<filename>', methods=['DELETE'])
@login_required
def delete_backup(filename):
    """Delete a backup file"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(BACKUPS_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Backup not found'}), 404
        
        os.remove(filepath)
        logger.info(f"Backup deleted: {filename}")
        
        return jsonify({'success': True, 'message': f'Backup {filename} deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backups/restore', methods=['POST'])
@login_required
def restore_backup():
    """Restore from a backup file"""
    try:
        data = request.json
        filename = data.get('filename', '').strip()
        restore_db = data.get('restore_database', True)
        restore_certs = data.get('restore_certificates', True)
        restore_config = data.get('restore_config', True)
        
        if not filename:
            return jsonify({'success': False, 'error': 'Backup filename is required'}), 400
        
        filename = secure_filename(filename)
        backup_path = os.path.join(BACKUPS_DIR, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'error': 'Backup file not found'}), 404
        
        # Create a pre-restore backup first
        pre_restore_backup = f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        pre_restore_path = os.path.join(BACKUPS_DIR, pre_restore_backup)
        
        restored_items = []
        errors = []
        
        with zipfile.ZipFile(backup_path, 'r') as zf:
            # Read manifest
            manifest = None
            if 'manifest.json' in zf.namelist():
                manifest = json.loads(zf.read('manifest.json').decode())
            
            # Restore certificates
            if restore_certs:
                cert_files = [f for f in zf.namelist() if f.startswith('certs/')]
                for cert_file in cert_files:
                    try:
                        # Determine destination
                        rel_path = cert_file[6:]  # Remove 'certs/' prefix
                        if rel_path:  # Skip empty paths
                            dest_path = os.path.join(CERTS_DIR, rel_path)
                            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                            
                            # Extract file
                            with zf.open(cert_file) as src:
                                with open(dest_path, 'wb') as dst:
                                    dst.write(src.read())
                            
                            # Set appropriate permissions for key files
                            if dest_path.endswith('.key'):
                                os.chmod(dest_path, 0o600)
                            
                            restored_items.append(f"Certificate: {rel_path}")
                    except Exception as e:
                        errors.append(f"Failed to restore {cert_file}: {str(e)}")
            
            # Restore configuration
            if restore_config:
                config_files = [f for f in zf.namelist() if f.startswith('config/')]
                for config_file in config_files:
                    try:
                        rel_path = config_file[7:]  # Remove 'config/' prefix
                        if rel_path:
                            if rel_path == 'CoreConfig.xml':
                                dest_path = CONFIG_FILE
                            elif rel_path == '.credentials':
                                dest_path = CREDENTIALS_FILE
                            elif rel_path == 'users.json':
                                dest_path = USERS_FILE
                            else:
                                dest_path = os.path.join(TAK_DIR, rel_path)
                            
                            with zf.open(config_file) as src:
                                with open(dest_path, 'wb') as dst:
                                    dst.write(src.read())
                            
                            # Set permissions for credentials file
                            if '.credentials' in dest_path:
                                os.chmod(dest_path, 0o600)
                            
                            restored_items.append(f"Config: {rel_path}")
                    except Exception as e:
                        errors.append(f"Failed to restore {config_file}: {str(e)}")
            
            # Restore database
            if restore_db and 'database/takserver.sql' in zf.namelist():
                try:
                    sql_content = zf.read('database/takserver.sql').decode()
                    
                    # Write to temp file
                    temp_sql = f'/tmp/restore_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sql'
                    with open(temp_sql, 'w') as f:
                        f.write(sql_content)
                    
                    # Restore database
                    result = subprocess.run(
                        ['sudo', '-u', 'postgres', 'psql', 'takserver', '-f', temp_sql],
                        capture_output=True, text=True, timeout=300
                    )
                    
                    os.remove(temp_sql)
                    
                    if result.returncode == 0:
                        restored_items.append("Database: takserver")
                    else:
                        errors.append(f"Database restore warning: {result.stderr}")
                        restored_items.append("Database: takserver (with warnings)")
                except Exception as e:
                    errors.append(f"Database restore failed: {str(e)}")
        
        # Determine success
        success = len(restored_items) > 0
        
        logger.info(f"Restore completed from {filename}: {len(restored_items)} items restored, {len(errors)} errors")
        
        return jsonify({
            'success': success,
            'message': f'Restore completed: {len(restored_items)} items restored',
            'restored': restored_items,
            'errors': errors,
            'restart_required': restore_config or restore_db
        })
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backups/upload', methods=['POST'])
@login_required
def upload_backup():
    """Upload a backup file for restoration"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.zip'):
            return jsonify({'success': False, 'error': 'Invalid file type. Only .zip files allowed'}), 400
        
        os.makedirs(BACKUPS_DIR, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(BACKUPS_DIR, filename)
        
        # Check if file already exists
        if os.path.exists(filepath):
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            filepath = os.path.join(BACKUPS_DIR, filename)
        
        file.save(filepath)
        
        # Verify it's a valid backup
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                has_manifest = 'manifest.json' in zf.namelist()
                file_count = len(zf.namelist())
        except zipfile.BadZipFile:
            os.remove(filepath)
            return jsonify({'success': False, 'error': 'Invalid ZIP file'}), 400
        
        logger.info(f"Backup uploaded: {filename}")
        
        return jsonify({
            'success': True,
            'message': 'Backup uploaded successfully',
            'filename': filename,
            'has_manifest': has_manifest,
            'file_count': file_count
        })
    except Exception as e:
        logger.error(f"Backup upload failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs')
@login_required
def get_logs():
    """Get TAK Server logs"""
    try:
        lines = request.args.get('lines', 100, type=int)
        
        result = subprocess.run(
            ['journalctl', '-u', 'takserver', '-n', str(lines), '--no-pager'],
            capture_output=True, text=True
        )
        
        return jsonify({
            'success': True,
            'logs': result.stdout
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/list')
@login_required
def list_users():
    """List all admin users"""
    try:
        users = load_users()
        user_list = [{'username': u, 'role': users[u].get('role', 'user')} 
                     for u in users.keys()]
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/create', methods=['POST'])
@login_required
def create_user():
    """Create a new admin user"""
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')  # Don't strip - might remove intentional spaces
        role = data.get('role', 'user')
        
        # Validate username
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 400
        
        # Validate password complexity
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 400
        
        # Validate and sanitize role
        if role not in ['admin', 'user']:
            role = 'user'
        
        users = load_users()
        
        if username in users:
            audit.log(
                action='user_create_failed',
                category=AuditLogger.CATEGORY_USER,
                level=AuditLogger.LEVEL_WARNING,
                target=username,
                success=False,
                details='User already exists'
            )
            return jsonify({'success': False, 'error': 'User already exists'}), 409
        
        users[username] = {
            'password': generate_password_hash(password),
            'role': role,
            'created_at': datetime.now().isoformat(),
            'created_by': current_user.id if current_user.is_authenticated else 'system'
        }
        save_users(users)
        
        # Audit log successful creation
        audit.log(
            action='user_created',
            category=AuditLogger.CATEGORY_USER,
            level=AuditLogger.LEVEL_INFO,
            target=username,
            success=True,
            details=f'Role: {role}'
        )
        
        logger.info(f"User '{username}' created with role '{role}'")
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
    except Exception as e:
        logger.error(f"User creation error: {e}")
        return jsonify({'success': False, 'error': 'Failed to create user'}), 500

@app.route('/api/users/delete/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    """Delete an admin user"""
    try:
        # Validate username format
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            return jsonify({'success': False, 'error': 'Invalid username format'}), 400
        
        # Prevent deleting the primary admin account
        if username == 'admin':
            audit.log(
                action='user_delete_blocked',
                category=AuditLogger.CATEGORY_USER,
                level=AuditLogger.LEVEL_WARNING,
                target=username,
                success=False,
                details='Attempted to delete admin account'
            )
            return jsonify({'success': False, 'error': 'Cannot delete admin user'}), 403
        
        # Prevent self-deletion
        if current_user.is_authenticated and username == current_user.id:
            audit.log(
                action='user_delete_blocked',
                category=AuditLogger.CATEGORY_USER,
                level=AuditLogger.LEVEL_WARNING,
                target=username,
                success=False,
                details='Attempted self-deletion'
            )
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 403
        
        users = load_users()
        
        if username not in users:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Delete the user
        del users[username]
        save_users(users)
        
        # Terminate all sessions for the deleted user
        terminated = session_mgr.end_all_user_sessions(username)
        
        # Audit log
        audit.log(
            action='user_deleted',
            category=AuditLogger.CATEGORY_USER,
            level=AuditLogger.LEVEL_WARNING,
            target=username,
            success=True,
            details=f'Terminated {terminated} active sessions'
        )
        
        logger.info(f"User '{username}' deleted, {terminated} sessions terminated")
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
    except Exception as e:
        logger.error(f"User deletion error: {e}")
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500

@app.route('/api/database/stats')
@login_required
def database_stats():
    """Get database statistics"""
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        stats = {}
        
        # Get table counts - using whitelist validation for table names
        ALLOWED_TABLES = {'cot_router', 'mission', 'resource'}
        for table in ALLOWED_TABLES:
            try:
                # Table name is from whitelist, safe to use
                cur.execute("SELECT COUNT(*) FROM " + table)
                result = cur.fetchone()
                stats[table] = result[0] if result else 0
            except psycopg2.Error as db_err:
                logger.debug(f"Table {table} query failed: {db_err}")
                stats[table] = 0
        
        # Get database size
        cur.execute("SELECT pg_size_pretty(pg_database_size('takserver'))")
        result = cur.fetchone()
        stats['database_size'] = result[0] if result else 'Unknown'
        
        return jsonify({'success': True, 'stats': stats})
    except psycopg2.OperationalError as e:
        logger.error(f"Database connection failed: {e}")
        return jsonify({'success': False, 'error': 'Database connection failed'}), 503
    except psycopg2.Error as e:
        logger.error(f"Database query error: {e}")
        return jsonify({'success': False, 'error': 'Database query failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in database_stats: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# Configuration page
@app.route('/config')
@login_required
def config_page():
    return render_template('config.html')

# Certificates page
@app.route('/certificates')
@login_required
def certificates_page():
    return render_template('certificates.html')

# Users page
@app.route('/users')
@login_required
def users_page():
    return render_template('users.html')

# Logs page
@app.route('/logs')
@login_required
def logs_page():
    return render_template('logs.html')

# ============================================================================
# DATA PACKAGES MANAGEMENT
# ============================================================================

# Data packages page
@app.route('/data-packages')
@login_required
def data_packages_page():
    return render_template('data_packages.html')

@app.route('/api/data-packages/list')
@login_required
def list_data_packages():
    """List all data packages"""
    try:
        os.makedirs(DATA_PACKAGES_DIR, exist_ok=True)
        packages = []
        
        for filename in os.listdir(DATA_PACKAGES_DIR):
            if filename.endswith(('.zip', '.dpk')):
                filepath = os.path.join(DATA_PACKAGES_DIR, filename)
                stat = os.stat(filepath)
                
                # Calculate file hash for integrity
                with open(filepath, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()[:12]
                
                # Try to get package info from manifest
                package_info = {
                    'filename': filename,
                    'size': stat.st_size,
                    'size_human': format_file_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'hash': file_hash,
                    'contents': []
                }
                
                # List contents if it's a zip
                try:
                    with zipfile.ZipFile(filepath, 'r') as zf:
                        package_info['contents'] = zf.namelist()[:20]  # First 20 files
                        package_info['file_count'] = len(zf.namelist())
                except (zipfile.BadZipFile, OSError):
                    package_info['file_count'] = 0
                
                packages.append(package_info)
        
        # Sort by modification time, newest first
        packages.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({'success': True, 'packages': packages})
    except Exception as e:
        logger.error(f"Error listing data packages: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def format_file_size(size):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

@app.route('/api/data-packages/upload', methods=['POST'])
@login_required
def upload_data_package():
    """Upload a new data package"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type. Only .zip and .dpk files allowed'}), 400
        
        os.makedirs(DATA_PACKAGES_DIR, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(DATA_PACKAGES_DIR, filename)
        
        # Check if file already exists
        if os.path.exists(filepath):
            # Add timestamp to make unique
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            filepath = os.path.join(DATA_PACKAGES_DIR, filename)
        
        file.save(filepath)
        
        # Verify it's a valid zip file
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                file_count = len(zf.namelist())
        except zipfile.BadZipFile:
            os.remove(filepath)
            return jsonify({'success': False, 'error': 'Invalid ZIP file'}), 400
        
        logger.info(f"Data package uploaded: {filename}")
        
        return jsonify({
            'success': True,
            'message': f'Package uploaded successfully',
            'filename': filename,
            'file_count': file_count
        })
    except Exception as e:
        logger.error(f"Error uploading data package: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data-packages/download/<filename>')
@login_required
def download_data_package(filename):
    """Download a data package"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(DATA_PACKAGES_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Package not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading data package: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data-packages/delete/<filename>', methods=['DELETE'])
@login_required
def delete_data_package(filename):
    """Delete a data package"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(DATA_PACKAGES_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Package not found'}), 404
        
        os.remove(filepath)
        logger.info(f"Data package deleted: {filename}")
        
        return jsonify({'success': True, 'message': f'Package {filename} deleted'})
    except Exception as e:
        logger.error(f"Error deleting data package: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data-packages/contents/<filename>')
@login_required
def get_package_contents(filename):
    """Get detailed contents of a data package"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(DATA_PACKAGES_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Package not found'}), 404
        
        contents = []
        with zipfile.ZipFile(filepath, 'r') as zf:
            for info in zf.infolist():
                contents.append({
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'is_dir': info.is_dir()
                })
        
        return jsonify({'success': True, 'contents': contents})
    except Exception as e:
        logger.error(f"Error getting package contents: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# CONNECTION PROFILES & QR CODES
# ============================================================================

# Connection profiles page
@app.route('/connection-profiles')
@login_required
def connection_profiles_page():
    return render_template('connection_profiles.html', qr_available=QR_AVAILABLE)

def get_server_info():
    """Get server connection information"""
    # Try to get the server's IP address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except (socket.error, OSError):
        server_ip = "127.0.0.1"
    
    # Get hostname
    try:
        hostname = socket.gethostname()
    except socket.error:
        hostname = "takserver"
    
    # Load credentials for cert password
    creds = load_credentials()
    cert_password = creds.get('cert_password')
    if not cert_password:
        # No password configured - this should be set during installation
        cert_password = ''
        logger.warning("No certificate password configured in credentials")
    
    return {
        'server_ip': server_ip,
        'hostname': hostname,
        'tak_port': 8089,
        'https_port': 443,
        'cert_password': cert_password
    }

@app.route('/api/connection-profiles/server-info')
@login_required
def api_server_info():
    """Get server connection information"""
    try:
        info = get_server_info()
        
        # List available client certificates
        certs = []
        if os.path.exists(CERTS_DIR):
            for f in os.listdir(CERTS_DIR):
                if f.endswith('.p12') and f not in ['takserver.p12']:
                    certs.append(f.replace('.p12', ''))
        
        info['available_certs'] = certs
        info['qr_available'] = QR_AVAILABLE
        
        return jsonify({'success': True, 'info': info})
    except Exception as e:
        logger.error(f"Error getting server info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connection-profiles/generate', methods=['POST'])
@login_required
def generate_connection_profile():
    """Generate a connection profile for a client"""
    try:
        data = request.json
        client_name = data.get('client_name', '').strip()
        include_cert = data.get('include_cert', True)
        
        if not client_name:
            return jsonify({'success': False, 'error': 'Client name is required'}), 400
        
        # Sanitize client name
        client_name = ''.join(c for c in client_name if c.isalnum() or c in '-_')
        
        server_info = get_server_info()
        
        # Check if certificate exists
        p12_file = os.path.join(CERTS_DIR, f"{client_name}.p12")
        if include_cert and not os.path.exists(p12_file):
            return jsonify({
                'success': False, 
                'error': f'Certificate for {client_name} not found. Generate it first in Certificates page.'
            }), 404
        
        os.makedirs(CONNECTION_PROFILES_DIR, exist_ok=True)
        
        # Generate TAK Server connection preference file (.pref)
        pref_content = generate_tak_pref_file(client_name, server_info)
        
        # Create the profile package
        profile_filename = f"{client_name}_profile.zip"
        profile_path = os.path.join(CONNECTION_PROFILES_DIR, profile_filename)
        
        with zipfile.ZipFile(profile_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add the preference file
            zf.writestr(f"{client_name}.pref", pref_content)
            
            # Add the certificate if requested
            if include_cert and os.path.exists(p12_file):
                zf.write(p12_file, f"{client_name}.p12")
            
            # Add CA certificate
            ca_cert = os.path.join(CERTS_DIR, 'ca.crt')
            if os.path.exists(ca_cert):
                zf.write(ca_cert, 'ca.crt')
            
            # Add README
            readme = generate_profile_readme(client_name, server_info)
            zf.writestr('README.txt', readme)
        
        logger.info(f"Connection profile generated: {profile_filename}")
        
        return jsonify({
            'success': True,
            'message': f'Profile generated for {client_name}',
            'filename': profile_filename
        })
    except Exception as e:
        logger.error(f"Error generating connection profile: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_tak_pref_file(client_name, server_info):
    """Generate TAK .pref file content (ATAK/WinTAK compatible)"""
    pref_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<preferences>
    <preference version="1" name="com.atakmap.app_preferences">
        <!-- Server Connection -->
        <entry key="locationCallsign" class="class java.lang.String">{client_name}</entry>
        
        <!-- TAK Server Connection Settings -->
        <entry key="cot_streams" class="class java.lang.String">
            {{
                "count": 1,
                "description0": "TAK Server",
                "enabled0": true,
                "connectString0": "{server_info['server_ip']}:{server_info['tak_port']}:ssl"
            }}
        </entry>
        
        <!-- Certificate Settings -->
        <entry key="certificateLocation" class="class java.lang.String">{client_name}.p12</entry>
        <entry key="clientPassword" class="class java.lang.String">{server_info['cert_password']}</entry>
        <entry key="caLocation" class="class java.lang.String">ca.crt</entry>
        <entry key="caPassword" class="class java.lang.String">{server_info['cert_password']}</entry>
        
        <!-- Connection Behavior -->
        <entry key="autostart" class="class java.lang.Boolean">true</entry>
        <entry key="stream_reconnect" class="class java.lang.Boolean">true</entry>
    </preference>
</preferences>
'''
    return pref_xml

def generate_profile_readme(client_name, server_info):
    """Generate README for the connection profile package"""
    readme = f'''TAK Server Connection Profile
============================
Client: {client_name}
Server: {server_info['server_ip']}
Port: {server_info['tak_port']} (SSL/TLS)

This package contains:
- {client_name}.pref - Connection settings file
- {client_name}.p12 - Client certificate (password: {server_info['cert_password']})
- ca.crt - Certificate Authority certificate

INSTALLATION INSTRUCTIONS
=========================

For ATAK (Android):
1. Copy this entire ZIP to your Android device
2. In ATAK, go to Settings > Network Preferences > Manage Server Connections
3. Tap "Import" and select this ZIP file
4. Enter certificate password when prompted: {server_info['cert_password']}

For WinTAK (Windows):
1. Extract this ZIP file
2. In WinTAK, go to Settings > Network Preferences
3. Import the .pref file
4. When prompted, select the .p12 certificate file
5. Enter password: {server_info['cert_password']}

For iTAK (iOS):
1. AirDrop or email the .p12 file to your iOS device
2. Install the certificate profile when prompted
3. Enter password: {server_info['cert_password']}
4. In iTAK, configure server: {server_info['server_ip']}:{server_info['tak_port']}

TROUBLESHOOTING
===============
- Ensure your device can reach {server_info['server_ip']} on port {server_info['tak_port']}
- Certificate password is: {server_info['cert_password']}
- Check firewall settings on both server and client

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
'''
    return readme

@app.route('/api/connection-profiles/download/<filename>')
@login_required
def download_connection_profile(filename):
    """Download a connection profile"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(CONNECTION_PROFILES_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Profile not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading profile: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connection-profiles/list')
@login_required
def list_connection_profiles():
    """List all generated connection profiles"""
    try:
        os.makedirs(CONNECTION_PROFILES_DIR, exist_ok=True)
        profiles = []
        
        for filename in os.listdir(CONNECTION_PROFILES_DIR):
            if filename.endswith('.zip'):
                filepath = os.path.join(CONNECTION_PROFILES_DIR, filename)
                stat = os.stat(filepath)
                profiles.append({
                    'filename': filename,
                    'client_name': filename.replace('_profile.zip', ''),
                    'size': format_file_size(stat.st_size),
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        profiles.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({'success': True, 'profiles': profiles})
    except Exception as e:
        logger.error(f"Error listing profiles: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connection-profiles/delete/<filename>', methods=['DELETE'])
@login_required
def delete_connection_profile(filename):
    """Delete a connection profile"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(CONNECTION_PROFILES_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Profile not found'}), 404
        
        os.remove(filepath)
        logger.info(f"Connection profile deleted: {filename}")
        
        return jsonify({'success': True, 'message': f'Profile deleted'})
    except Exception as e:
        logger.error(f"Error deleting profile: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connection-profiles/qr/<client_name>')
@login_required
def generate_qr_code(client_name):
    """Generate QR code for quick mobile configuration"""
    try:
        if not QR_AVAILABLE:
            return jsonify({
                'success': False, 
                'error': 'QR code generation not available. Install qrcode library.'
            }), 503
        
        client_name = secure_filename(client_name)
        server_info = get_server_info()
        
        # Create connection string for QR code
        # Format: tak://server:port?cert=name&pass=password
        qr_data = f"tak://{server_info['server_ip']}:{server_info['tak_port']}?client={client_name}&pass={server_info['cert_password']}"
        
        # Also include a simple JSON format for more info
        qr_json = json.dumps({
            'type': 'tak-connection',
            'server': server_info['server_ip'],
            'port': server_info['tak_port'],
            'protocol': 'ssl',
            'client': client_name,
            'cert_password': server_info['cert_password']
        })
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_json)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for embedding in HTML
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'qr_data': qr_json,
            'qr_image': f'data:image/png;base64,{img_base64}',
            'server_info': server_info
        })
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connection-profiles/qr-image/<client_name>')
@login_required
def get_qr_image(client_name):
    """Get QR code as PNG image file"""
    try:
        if not QR_AVAILABLE:
            return jsonify({'success': False, 'error': 'QR code generation not available'}), 503
        
        client_name = secure_filename(client_name)
        server_info = get_server_info()
        
        qr_json = json.dumps({
            'type': 'tak-connection',
            'server': server_info['server_ip'],
            'port': server_info['tak_port'],
            'protocol': 'ssl',
            'client': client_name,
            'cert_password': server_info['cert_password']
        })
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_json)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return Response(
            buffer.getvalue(),
            mimetype='image/png',
            headers={'Content-Disposition': f'inline; filename={client_name}_qr.png'}
        )
    except Exception as e:
        logger.error(f"Error generating QR image: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Health check endpoint (no auth required - used by nginx/monitoring)
@app.route('/api/health')
def health_check():
    """Simple health check endpoint for load balancers and monitoring"""
    try:
        # Basic checks
        checks = {
            'app': 'ok',
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if TAK Server service is running
        tak_status = subprocess.run(['systemctl', 'is-active', 'takserver'], 
                                   capture_output=True, text=True)
        checks['takserver'] = 'ok' if tak_status.stdout.strip() == 'active' else 'down'
        
        # Check PostgreSQL
        pg_status = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                  capture_output=True, text=True)
        checks['postgresql'] = 'ok' if pg_status.stdout.strip() == 'active' else 'down'
        
        # Overall status
        all_ok = all(v == 'ok' for k, v in checks.items() if k not in ['timestamp'])
        
        return jsonify({
            'status': 'healthy' if all_ok else 'degraded',
            'checks': checks
        }), 200 if all_ok else 503
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503

# ============================================================================
# AUDIT LOG ROUTES
# ============================================================================

@app.route('/audit-log')
@login_required
def audit_log_page():
    """Audit log viewer page"""
    return render_template('audit_log.html')

@app.route('/api/audit/logs')
@login_required
def get_audit_logs():
    """Get audit logs with filtering"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        category = request.args.get('category')
        user = request.args.get('user')
        level = request.args.get('level')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        result = audit.get_logs(
            limit=limit,
            offset=offset,
            category=category,
            user=user,
            level=level,
            start_date=start_date,
            end_date=end_date
        )
        
        return jsonify({
            'success': True,
            'logs': result['logs'],
            'total': result['total'],
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/audit/stats')
@login_required
def get_audit_stats():
    """Get audit log statistics"""
    try:
        days = request.args.get('days', 7, type=int)
        stats = audit.get_stats(days=days)
        return jsonify({'success': True, 'stats': stats, 'days': days})
    except Exception as e:
        logger.error(f"Error getting audit stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/audit/export')
@login_required
def export_audit_logs():
    """Export audit logs as JSON"""
    try:
        result = audit.get_logs(limit=10000)
        
        # Create JSON export
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'exported_by': current_user.id,
            'total_records': result['total'],
            'logs': result['logs']
        }
        
        # Create in-memory file
        output = io.BytesIO()
        output.write(json.dumps(export_data, indent=2).encode())
        output.seek(0)
        
        # Log the export
        audit.log(
            action='audit_log_exported',
            category=AuditLogger.CATEGORY_SYSTEM,
            level=AuditLogger.LEVEL_INFO,
            details=f'Exported {result["total"]} audit records'
        )
        
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'audit_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    except Exception as e:
        logger.error(f"Error exporting audit logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# SESSION MANAGEMENT ROUTES
# ============================================================================

@app.route('/security')
@login_required
def security_page():
    """Security settings and session management page"""
    return render_template('security.html')

@app.route('/api/sessions/active')
@login_required
def get_active_sessions():
    """Get all active sessions"""
    try:
        # Only admins can see all sessions
        users = load_users()
        is_admin = users.get(current_user.id, {}).get('role') == 'admin'
        
        if is_admin:
            sessions = session_mgr.get_active_sessions()
        else:
            sessions = session_mgr.get_active_sessions(current_user.id)
        
        # Format for display
        session_list = []
        for sid, sdata in sessions.items():
            session_list.append({
                'session_id': sid[:8] + '...',  # Truncate for display
                'full_session_id': sid,
                'username': sdata.get('username'),
                'ip_address': sdata.get('ip_address'),
                'user_agent': sdata.get('user_agent', 'unknown')[:50],
                'created': sdata.get('created'),
                'last_activity': sdata.get('last_activity'),
                'expires': sdata.get('expires'),
                'is_current': sid == session.get('session_id')
            })
        
        # Sort by last activity
        session_list.sort(key=lambda x: x.get('last_activity', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'sessions': session_list,
            'total': len(session_list)
        })
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/terminate', methods=['POST'])
@login_required
def terminate_session():
    """Terminate a specific session"""
    try:
        data = request.json
        target_session_id = data.get('session_id')
        
        if not target_session_id:
            return jsonify({'success': False, 'error': 'Session ID required'}), 400
        
        # Get session info before terminating
        sessions = session_mgr.get_active_sessions()
        target_session = sessions.get(target_session_id)
        
        if not target_session:
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        # Check permissions
        users = load_users()
        is_admin = users.get(current_user.id, {}).get('role') == 'admin'
        is_own_session = target_session.get('username') == current_user.id
        
        if not is_admin and not is_own_session:
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        # Don't allow terminating current session via this endpoint
        if target_session_id == session.get('session_id'):
            return jsonify({'success': False, 'error': 'Use logout to end current session'}), 400
        
        # Terminate the session
        session_mgr.end_session(target_session_id)
        
        # Audit log
        audit.log(
            action='session_terminated',
            category=AuditLogger.CATEGORY_SECURITY,
            level=AuditLogger.LEVEL_WARNING,
            target=target_session.get('username'),
            details=f'Session terminated by {current_user.id}'
        )
        
        return jsonify({
            'success': True,
            'message': f'Session terminated for {target_session.get("username")}'
        })
    except Exception as e:
        logger.error(f"Error terminating session: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sessions/terminate-all', methods=['POST'])
@login_required
def terminate_all_sessions():
    """Terminate all sessions for a user (except current)"""
    try:
        data = request.json
        target_username = data.get('username', current_user.id)
        
        # Check permissions
        users = load_users()
        is_admin = users.get(current_user.id, {}).get('role') == 'admin'
        is_self = target_username == current_user.id
        
        if not is_admin and not is_self:
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        # Terminate all sessions except current
        current_session_id = session.get('session_id') if is_self else None
        count = session_mgr.end_all_user_sessions(target_username, except_session=current_session_id)
        
        # Audit log
        audit.log(
            action='all_sessions_terminated',
            category=AuditLogger.CATEGORY_SECURITY,
            level=AuditLogger.LEVEL_WARNING,
            target=target_username,
            details=f'{count} sessions terminated by {current_user.id}'
        )
        
        return jsonify({
            'success': True,
            'message': f'{count} sessions terminated for {target_username}'
        })
    except Exception as e:
        logger.error(f"Error terminating sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/security/lockouts')
@login_required
def get_lockouts():
    """Get current account lockouts (admin only)"""
    try:
        users = load_users()
        if users.get(current_user.id, {}).get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Load security data
        try:
            with open(SECURITY_FILE, 'r') as f:
                security = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            security = {'lockouts': {}}
        
        lockouts = []
        now = datetime.now()
        
        for key, lockout_until in security.get('lockouts', {}).items():
            expires = datetime.fromisoformat(lockout_until)
            if now < expires:
                username, ip = key.split(':', 1)
                lockouts.append({
                    'username': username,
                    'ip_address': ip,
                    'locked_until': lockout_until,
                    'remaining_minutes': (expires - now).seconds // 60 + 1
                })
        
        return jsonify({'success': True, 'lockouts': lockouts})
    except Exception as e:
        logger.error(f"Error getting lockouts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/security/clear-lockout', methods=['POST'])
@login_required
def clear_user_lockout():
    """Clear lockout for a user (admin only)"""
    try:
        users = load_users()
        if users.get(current_user.id, {}).get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.json
        username = data.get('username')
        ip_address = data.get('ip_address')
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'}), 400
        
        session_mgr.clear_lockout(username, ip_address)
        
        # Audit log
        audit.log(
            action='lockout_cleared',
            category=AuditLogger.CATEGORY_SECURITY,
            level=AuditLogger.LEVEL_INFO,
            target=username,
            details=f'Lockout cleared by {current_user.id}'
        )
        
        return jsonify({'success': True, 'message': f'Lockout cleared for {username}'})
    except Exception as e:
        logger.error(f"Error clearing lockout: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/security/settings')
@login_required
def get_security_settings():
    """Get current security settings"""
    try:
        return jsonify({
            'success': True,
            'settings': {
                'session_timeout_minutes': SESSION_TIMEOUT_MINUTES,
                'max_login_attempts': MAX_LOGIN_ATTEMPTS,
                'login_lockout_minutes': LOGIN_LOCKOUT_MINUTES,
                'max_concurrent_sessions': MAX_CONCURRENT_SESSIONS
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def check_https_configured():
    """Check if HTTPS is configured via nginx"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                               capture_output=True, text=True, timeout=10)
        nginx_running = result.stdout.strip() == 'active'
        
        cert_exists = os.path.exists(os.path.join(CERTS_DIR, 'web-admin.crt'))
        
        return nginx_running and cert_exists
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return False


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(TAK_DIR, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)
    
    # Initialize default admin user if no users exist
    if not os.path.exists(USERS_FILE):
        # Use password from credentials file/env, or generate a secure one
        initial_password = _credentials.get('web_admin_password') or secrets.token_urlsafe(16)
        users = {
            'admin': {
                'password': generate_password_hash(initial_password),
                'role': 'admin'
            }
        }
        save_users(users)
        logger.info("=" * 50)
        logger.info("Default admin user created:")
        logger.info("Username: admin")
        if _credentials.get('web_admin_password'):
            logger.info(f"Password: See {CREDENTIALS_FILE}")
        else:
            logger.info(f"Password: {initial_password}")
            logger.info("(Save this password - it won't be shown again!)")
        logger.info("=" * 50)
    
    # Check HTTPS configuration
    https_configured = check_https_configured()
    if https_configured:
        logger.info("HTTPS is configured via nginx reverse proxy")
        logger.info("Access the web interface at: https://<server-ip>")
    else:
        logger.warning("HTTPS is NOT configured - running in HTTP mode")
        logger.warning("Run setup_https.sh to enable HTTPS")
        logger.info("Access the web interface at: http://<server-ip>:5000")
    
    # Run the application (binds to localhost only when behind proxy)
    bind_host = '127.0.0.1' if https_configured else '0.0.0.0'
    logger.info(f"Starting Flask on {bind_host}:5000")
    
    app.run(host=bind_host, port=5000, debug=False)
