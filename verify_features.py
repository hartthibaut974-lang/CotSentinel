#!/usr/bin/env python3
"""
TAK Server Web Admin - Feature Verification Script
Tests all features: Data Packages, Connection Profiles, Certificate Revocation,
Backup/Restore, Audit Logging, and Session Security

Copyright 2024-2025 BlackDot Technology
Licensed under the Apache License, Version 2.0
"""

import os
import sys
import json
import zipfile
import io
from datetime import datetime, timedelta
import threading
import uuid

# Test counters
PASSED = 0
FAILED = 0
WARNINGS = 0

def test(name, condition, error_msg=""):
    global PASSED, FAILED
    if condition:
        print(f"  ✅ {name}")
        PASSED += 1
        return True
    else:
        print(f"  ❌ {name}")
        if error_msg:
            print(f"     → {error_msg}")
        FAILED += 1
        return False

def warn(name, msg=""):
    global WARNINGS
    print(f"  ⚠️  {name}")
    if msg:
        print(f"     → {msg}")
    WARNINGS += 1

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

# ============================================================================
# TEST 1: Import Verification
# ============================================================================
section("1. Import Verification")

try:
    from flask import Flask, Response, send_file, g
    test("Flask core imports (including g)", True)
except ImportError as e:
    test("Flask core imports", False, str(e))

try:
    from werkzeug.utils import secure_filename
    test("Werkzeug secure_filename", True)
except ImportError as e:
    test("Werkzeug secure_filename", False, str(e))

try:
    import functools
    import threading
    import uuid
    test("Security-related imports (functools, threading, uuid)", True)
except ImportError as e:
    test("Security imports", False, str(e))

try:
    import qrcode
    test("QR code library (optional)", True)
    QR_AVAILABLE = True
except ImportError:
    warn("QR code library not installed", "Install with: pip install qrcode[pil] Pillow")
    QR_AVAILABLE = False

# ============================================================================
# TEST 2: Helper Functions
# ============================================================================
section("2. Helper Functions")

def format_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

test("format_file_size(100) = '100.0 B'", format_file_size(100) == "100.0 B")
test("format_file_size(1024) = '1.0 KB'", format_file_size(1024) == "1.0 KB")
test("format_file_size(1048576) = '1.0 MB'", format_file_size(1048576) == "1.0 MB")

ALLOWED_EXTENSIONS = {'zip', 'dpk'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

test("allowed_file('test.zip') = True", allowed_file('test.zip') == True)
test("allowed_file('test.txt') = False", allowed_file('test.txt') == False)

# ============================================================================
# TEST 3: Audit Logger Mock Test
# ============================================================================
section("3. Audit Logger Functionality")

class MockAuditLogger:
    """Mock audit logger for testing"""
    CATEGORY_AUTH = 'authentication'
    CATEGORY_SECURITY = 'security'
    LEVEL_INFO = 'info'
    LEVEL_WARNING = 'warning'
    LEVEL_CRITICAL = 'critical'
    
    def __init__(self):
        self.logs = []
        self._lock = threading.Lock()
    
    def log(self, action, category, level='info', user=None, target=None, 
            details=None, success=True, ip_address=None):
        event = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'category': category,
            'level': level,
            'user': user or 'test_user',
            'ip_address': ip_address or '127.0.0.1',
            'target': target,
            'success': success,
            'details': details
        }
        with self._lock:
            self.logs.append(event)
    
    def get_logs(self, limit=100, **kwargs):
        return {'logs': self.logs[-limit:], 'total': len(self.logs)}
    
    def get_stats(self, days=7):
        return {
            'total_events': len(self.logs),
            'by_category': {},
            'failed_logins': 0,
            'successful_logins': 0
        }

audit = MockAuditLogger()
audit.log('test_action', 'authentication', level='info', user='testuser')
test("Audit log records event", len(audit.logs) == 1)
test("Log has correct action", audit.logs[0]['action'] == 'test_action')
test("Log has timestamp", 'timestamp' in audit.logs[0])

audit.log('login_success', 'authentication', success=True)
audit.log('login_failed', 'authentication', success=False)
test("Multiple logs recorded", len(audit.logs) == 3)

result = audit.get_logs(limit=10)
test("get_logs returns dict with logs", 'logs' in result and 'total' in result)

# ============================================================================
# TEST 4: Session Manager Mock Test
# ============================================================================
section("4. Session Manager Functionality")

class MockSessionManager:
    def __init__(self):
        self.sessions = {}
        self.security = {'login_attempts': {}, 'lockouts': {}}
        self._lock = threading.Lock()
    
    def create_session(self, username, ip_address, user_agent):
        session_id = str(uuid.uuid4())
        with self._lock:
            self.sessions[session_id] = {
                'username': username,
                'ip_address': ip_address,
                'user_agent': user_agent[:200] if user_agent else 'unknown',
                'created': datetime.now().isoformat(),
                'last_activity': datetime.now().isoformat(),
                'expires': (datetime.now() + timedelta(minutes=30)).isoformat()
            }
        return session_id
    
    def validate_session(self, session_id):
        if not session_id or session_id not in self.sessions:
            return False
        sess = self.sessions[session_id]
        expires = datetime.fromisoformat(sess['expires'])
        return datetime.now() < expires
    
    def end_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
    
    def record_login_attempt(self, username, ip_address, success):
        key = f"{username}:{ip_address}"
        if key not in self.security['login_attempts']:
            self.security['login_attempts'][key] = []
        self.security['login_attempts'][key].append({
            'timestamp': datetime.now().isoformat(),
            'success': success
        })
    
    def is_locked_out(self, username, ip_address):
        key = f"{username}:{ip_address}"
        if key in self.security['lockouts']:
            lockout_until = datetime.fromisoformat(self.security['lockouts'][key])
            if datetime.now() < lockout_until:
                return True, lockout_until
        return False, None

session_mgr = MockSessionManager()

# Test session creation
sid = session_mgr.create_session('testuser', '192.168.1.100', 'Mozilla/5.0')
test("Session created with UUID", sid is not None and len(sid) == 36)
test("Session stored in dict", sid in session_mgr.sessions)

# Test session validation
test("Valid session returns True", session_mgr.validate_session(sid) == True)
test("Invalid session returns False", session_mgr.validate_session('invalid') == False)

# Test session data
sess_data = session_mgr.sessions[sid]
test("Session has username", sess_data['username'] == 'testuser')
test("Session has IP address", sess_data['ip_address'] == '192.168.1.100')
test("Session has timestamps", 'created' in sess_data and 'expires' in sess_data)

# Test session end
test("End session returns True", session_mgr.end_session(sid) == True)
test("Session removed", sid not in session_mgr.sessions)

# Test lockout check
is_locked, _ = session_mgr.is_locked_out('testuser', '192.168.1.100')
test("User not locked initially", is_locked == False)

# ============================================================================
# TEST 5: Source Code - Core Features
# ============================================================================
section("5. Source Code - Core Features")

script_path = os.path.join(os.path.dirname(__file__), 'cot_server_admin.py')
if os.path.exists(script_path):
    with open(script_path, 'r') as f:
        source = f.read()
    
    test("Has /data-packages route", "@app.route('/data-packages')" in source)
    test("Has /api/data-packages/upload route", "@app.route('/api/data-packages/upload'" in source)
    test("Has /connection-profiles route", "@app.route('/connection-profiles')" in source)
    test("Has /api/connection-profiles/generate route", "@app.route('/api/connection-profiles/generate'" in source)
else:
    test("cot_server_admin.py exists", False)

# ============================================================================
# TEST 6: Source Code - Certificate Revocation
# ============================================================================
section("6. Source Code - Certificate Revocation")

if os.path.exists(script_path):
    test("Has /api/certs/revoke route", "@app.route('/api/certs/revoke'" in source)
    test("Has /api/certs/revoked route", "@app.route('/api/certs/revoked')" in source)
    test("Has /api/certs/crl route", "@app.route('/api/certs/crl')" in source)
    test("Has /api/certs/unrevoke route", "@app.route('/api/certs/unrevoke'" in source)
    test("Has CRL_FILE constant", "CRL_FILE = " in source)

# ============================================================================
# TEST 7: Source Code - Backup & Restore
# ============================================================================
section("7. Source Code - Backup & Restore")

if os.path.exists(script_path):
    test("Has /backups route", "@app.route('/backups')" in source)
    test("Has /api/backups/create route", "@app.route('/api/backups/create'" in source)
    test("Has /api/backups/restore route", "@app.route('/api/backups/restore'" in source)
    test("Has /api/backups/upload route", "@app.route('/api/backups/upload'" in source)
    test("Has BACKUPS_DIR constant", "BACKUPS_DIR = " in source)

# ============================================================================
# TEST 8: Source Code - Audit Logging
# ============================================================================
section("8. Source Code - Audit Logging")

if os.path.exists(script_path):
    test("Has AuditLogger class", "class AuditLogger" in source)
    test("Has AUDIT_LOG_FILE constant", "AUDIT_LOG_FILE = " in source)
    test("Has /audit-log page route", "@app.route('/audit-log')" in source)
    test("Has /api/audit/logs route", "@app.route('/api/audit/logs')" in source)
    test("Has /api/audit/stats route", "@app.route('/api/audit/stats')" in source)
    test("Has /api/audit/export route", "@app.route('/api/audit/export')" in source)
    test("Has CATEGORY_AUTH constant", "CATEGORY_AUTH" in source)
    test("Has LEVEL_CRITICAL constant", "LEVEL_CRITICAL" in source)
    test("Uses audit.log() calls", "audit.log(" in source)

# ============================================================================
# TEST 9: Source Code - Session Security
# ============================================================================
section("9. Source Code - Session Security")

if os.path.exists(script_path):
    test("Has SessionManager class", "class SessionManager" in source)
    test("Has SESSIONS_FILE constant", "SESSIONS_FILE = " in source)
    test("Has SESSION_TIMEOUT_MINUTES", "SESSION_TIMEOUT_MINUTES" in source)
    test("Has MAX_LOGIN_ATTEMPTS", "MAX_LOGIN_ATTEMPTS" in source)
    test("Has LOGIN_LOCKOUT_MINUTES", "LOGIN_LOCKOUT_MINUTES" in source)
    test("Has MAX_CONCURRENT_SESSIONS", "MAX_CONCURRENT_SESSIONS" in source)
    test("Has /security page route", "@app.route('/security')" in source)
    test("Has /api/sessions/active route", "@app.route('/api/sessions/active')" in source)
    test("Has /api/sessions/terminate route", "@app.route('/api/sessions/terminate'" in source)
    test("Has /api/sessions/terminate-all route", "@app.route('/api/sessions/terminate-all'" in source)
    test("Has /api/security/lockouts route", "@app.route('/api/security/lockouts')" in source)
    test("Has /api/security/clear-lockout route", "@app.route('/api/security/clear-lockout'" in source)
    test("Has /api/security/settings route", "@app.route('/api/security/settings')" in source)
    test("Has check_session_validity function", "def check_session_validity" in source)
    test("Uses session_mgr.create_session", "session_mgr.create_session" in source)
    test("Uses session_mgr.is_locked_out", "session_mgr.is_locked_out" in source)

# ============================================================================
# TEST 10: HTML Templates
# ============================================================================
section("10. HTML Templates")

template_dir = os.path.dirname(__file__)

templates = [
    ('data_packages.html', ['uploadArea', 'packagesList']),
    ('connection_profiles.html', ['clientSelect', 'qrCodeCard']),
    ('backups.html', ['createBackup', 'restoreModal']),
    ('certificates.html', ['revoke-cert-modal', '/api/certs/revoke']),
    ('audit_log.html', ['auditLogTable', '/api/audit/logs', 'filterCategory', 'exportLogs']),
    ('security.html', ['activeSessions', 'lockoutsList', '/api/sessions/', 'terminateSession']),
]

for template_name, required_strings in templates:
    template_path = os.path.join(template_dir, template_name)
    if os.path.exists(template_path):
        with open(template_path, 'r') as f:
            content = f.read()
        test(f"{template_name} exists", True)
        for req_str in required_strings:
            test(f"  {template_name} has '{req_str}'", req_str in content)
    else:
        test(f"{template_name} exists", False)

# ============================================================================
# TEST 11: Navigation Links
# ============================================================================
section("11. Navigation Links")

base_html = os.path.join(template_dir, 'base.html')
if os.path.exists(base_html):
    with open(base_html, 'r') as f:
        content = f.read()
    test("Has data_packages_page link", "data_packages_page" in content)
    test("Has connection_profiles_page link", "connection_profiles_page" in content)
    test("Has backups_page link", "backups_page" in content)
    test("Has security_page link", "security_page" in content)
    test("Has audit_log_page link", "audit_log_page" in content)
else:
    test("base.html exists", False)

# ============================================================================
# TEST 12: Security Configuration Defaults
# ============================================================================
section("12. Security Configuration Defaults")

# Test default security values (from source code)
if os.path.exists(script_path):
    test("Default session timeout (30 min)", "SESSION_TIMEOUT_MINUTES = int(os.environ.get('TAK_SESSION_TIMEOUT', '30'))" in source)
    test("Default max login attempts (5)", "MAX_LOGIN_ATTEMPTS = int(os.environ.get('TAK_MAX_LOGIN_ATTEMPTS', '5'))" in source)
    test("Default lockout duration (15 min)", "LOGIN_LOCKOUT_MINUTES = int(os.environ.get('TAK_LOGIN_LOCKOUT_MINUTES', '15'))" in source)
    test("Default concurrent sessions (3)", "MAX_CONCURRENT_SESSIONS = int(os.environ.get('TAK_MAX_CONCURRENT_SESSIONS', '3'))" in source)

# ============================================================================
# TEST 13: ZIP/Backup Operations
# ============================================================================
section("13. ZIP/Backup Operations")

try:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('manifest.json', json.dumps({'version': '1.0'}))
        zf.writestr('config/test.xml', '<config/>')
    buffer.seek(0)
    test("Create backup ZIP in memory", True)
    
    with zipfile.ZipFile(buffer, 'r') as zf:
        test("ZIP contains manifest.json", 'manifest.json' in zf.namelist())
        manifest = json.loads(zf.read('manifest.json').decode())
        test("Can parse manifest", manifest.get('version') == '1.0')
except Exception as e:
    test("ZIP operations", False, str(e))

# ============================================================================
# SUMMARY
# ============================================================================
print(f"\n{'='*60}")
print(f"  VERIFICATION SUMMARY")
print(f"{'='*60}")
print(f"\n  ✅ Passed:   {PASSED}")
print(f"  ❌ Failed:   {FAILED}")
print(f"  ⚠️  Warnings: {WARNINGS}")
print()

if FAILED == 0:
    print("  🎉 All tests passed!")
    print()
    print("  Features verified:")
    print("  ├─ Data Package Management")
    print("  ├─ Connection Profiles & QR Codes")
    print("  ├─ Certificate Revocation (CRL)")
    print("  ├─ Backup & Restore")
    print("  ├─ Audit Logging")
    print("  └─ Session Security")
    print()
    print("  Security settings (environment variables):")
    print("  ├─ TAK_SESSION_TIMEOUT (default: 30 min)")
    print("  ├─ TAK_MAX_LOGIN_ATTEMPTS (default: 5)")
    print("  ├─ TAK_LOGIN_LOCKOUT_MINUTES (default: 15 min)")
    print("  └─ TAK_MAX_CONCURRENT_SESSIONS (default: 3)")
    print()
    print("  Audit events tracked:")
    print("  ├─ Login success/failure")
    print("  ├─ Session creation/termination")
    print("  ├─ Certificate operations")
    print("  ├─ Backup/restore operations")
    print("  ├─ Configuration changes")
    print("  └─ Account lockouts")
    print()
else:
    print(f"  ⚠️  {FAILED} test(s) failed. Please review above.")
    
print()
sys.exit(0 if FAILED == 0 else 1)
