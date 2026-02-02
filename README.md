# CoT Server Admin

**Administration tool for TAK Server on Raspberry Pi 5**

Web-based administration interface for managing TAK Server deployments. Zero command-line configuration required after initial setup.

> ⚠️ **Disclaimer**: This software is not affiliated with, endorsed by, or connected to the TAK Product Center, U.S. Department of Defense, or any government agency. "TAK", "ATAK", "WinTAK", and "iTAK" are products of the U.S. Government. This is an independent, open-source administration tool that works with TAK Server.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [CoT Server Admin](#web-admin-interface)
- [Configuration](#configuration)
- [Certificate Management](#certificate-management)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Advanced Usage](#advanced-usage)

## 🎯 Overview

This deployment package provides:
- **Automated TAK Server installation** on Raspberry Pi 5
- **CoT Server Admin** - Web-based administration interface (no command line needed!)
- **Complete certificate management**
- **Real-time monitoring and logs**
- **User management**
- **Configuration editor**

## ✨ Features

### Deployment Script (`deploy_tak_server.sh`)
- Automated installation of TAK Server and all dependencies
- PostgreSQL database setup with PostGIS extension
- SSL certificate generation
- Systemd service configuration
- Firewall configuration
- Automatic backup creation

### CoT Server Admin (`cot_server_admin.py`)
- **Dashboard**: Real-time system status and statistics
- **Configuration**: Edit TAK Server settings via web interface
- **Certificates**: Generate, download, and revoke client certificates
- **Certificate Revocation**: One-click revoke with CRL generation
- **Connection Profiles**: One-click profile generation for ATAK/WinTAK/iTAK
- **QR Codes**: Scannable QR codes for quick mobile configuration
- **Data Packages**: Upload and manage data packages for TAK clients
- **Backup & Restore**: Full system backup with one-click restore
- **Users**: Manage admin users
- **Security**: Session management, lockouts, and security settings
- **Audit Log**: Comprehensive activity logging with search/filter/export
- **Logs**: View and filter TAK Server logs in real-time

### Security Features
- **HTTPS Support**: Nginx reverse proxy with TLS encryption
- **Random Passwords**: Secure auto-generated credentials
- **Session Security**: Configurable timeouts, concurrent session limits
- **Rate Limiting**: Account lockout after failed login attempts
- **Audit Logging**: Track all admin actions with timestamps and IPs
- **Certificate Revocation List (CRL)**: Proper PKI certificate lifecycle

## 📦 Prerequisites

### Hardware
- Raspberry Pi 5 with 16GB RAM (recommended)
- microSD card (64GB+ recommended)
- Network connection
- Power supply

### Software
- Raspberry Pi OS (64-bit) - Latest version
- Internet connection for downloading packages
- Root/sudo access

### TAK Server Software
You'll need to obtain the official TAK Server release from https://tak.gov
- Version 5.2-RELEASE-27 or later
- Requires DoD PKI certificate or registration

## 🚀 Installation

### Step 1: Prepare Your Files

1. Copy all deployment files to your Raspberry Pi:
```bash
scp deploy_tak_server.sh pi@your-raspberry-pi-ip:~/
scp install_web_admin.sh pi@your-raspberry-pi-ip:~/
scp cot_server_admin.py pi@your-raspberry-pi-ip:~/
scp cot-server-admin.service pi@your-raspberry-pi-ip:~/
scp -r templates/ pi@your-raspberry-pi-ip:~/
```

2. SSH into your Raspberry Pi:
```bash
ssh pi@your-raspberry-pi-ip
```

### Step 2: Deploy TAK Server

Make the deployment script executable and run it:

```bash
chmod +x deploy_tak_server.sh
sudo ./deploy_tak_server.sh
```

The script will:
- Update system packages
- Install Java, PostgreSQL, and dependencies
- Configure the database
- Generate SSL certificates
- Create TAK Server configuration
- Set up firewall rules

**Note**: The script creates a placeholder structure for TAK Server. You'll need to download the official TAK Server release from https://tak.gov and extract it to `/opt/tak/takserver-5.2-RELEASE-27/`

### Step 3: Install CoT Server Admin

Make the installation script executable and run it:

```bash
chmod +x install_web_admin.sh
sudo ./install_web_admin.sh
```

This will:
- Set up the web application
- Create a Python virtual environment
- Install required packages
- Configure systemd service
- Start the web interface

### Step 4: Enable HTTPS (Recommended)

**⚠️ IMPORTANT: The web admin handles sensitive credentials. HTTPS is strongly recommended.**

Run the HTTPS setup script:

```bash
chmod +x setup_https.sh
sudo ./setup_https.sh
```

The script will:
- Generate a self-signed SSL certificate (or use Let's Encrypt)
- Configure nginx as a reverse proxy
- Redirect HTTP to HTTPS
- Secure the Flask application

You'll be prompted to choose:
1. **Self-signed certificate** - Best for internal/testing (browsers will show warning)
2. **Let's Encrypt** - Best for public-facing servers with a domain name
3. **Existing certificate** - Use your own CA-signed certificate

After setup, verify HTTPS is working:

```bash
chmod +x verify_https.sh
sudo ./verify_https.sh
```

### Step 5: Access Web Interface

After installation, access the web interface at:

**With HTTPS enabled (recommended):**
```
https://[your-raspberry-pi-ip]
```

**Without HTTPS (not recommended for production):**
```
http://[your-raspberry-pi-ip]:5000
```

**Default Login Credentials:**
- Username: `admin`
- Password: Check `/opt/tak/.credentials` or `/opt/tak/installation-info.txt`

Passwords are randomly generated during installation for security. You can override them by setting environment variables before running the deployment script:
```bash
export TAK_DB_PASSWORD="your_db_password"
export TAK_CERT_PASSWORD="your_cert_password"
export TAK_WEB_ADMIN_PASSWORD="your_admin_password"
sudo -E ./deploy_tak_server.sh
```

**⚠️ IMPORTANT: Store your credentials securely and change them regularly in production!**

## 🌐 CoT Server Admin

### Dashboard
- View system status (TAK Server, PostgreSQL)
- Monitor connected clients
- Control server (start/stop/restart)
- View database statistics
- Quick actions

### Configuration
- Edit CoreConfig.xml directly through web interface
- Automatic backup before saving
- XML validation
- View network inputs and database settings
- No command line required!

### Certificates
- Generate new client certificates with one click
- Download certificates (.crt, .key, .p12)
- View existing certificates
- PKCS12 bundle generation for easy client installation

### Connection Profiles
- **One-Click Profiles**: Generate complete connection packages for any client
- **QR Code Support**: Scan to configure - no manual entry needed
- **Multi-Platform**: Includes instructions for ATAK, WinTAK, and iTAK
- **Bundled Certificates**: Packages include client cert, CA cert, and connection settings

### Data Packages
- **Upload**: Drag-and-drop upload of .zip and .dpk files (up to 100MB)
- **Manage**: View, download, and delete packages
- **Inspect**: Browse package contents without extracting
- **Distribute**: Make packages available for TAK clients to download

### Users
- Create/delete admin users
- Assign roles (admin/user)
- Change passwords
- Manage access to web interface

### Logs
- Real-time log viewing
- Filter logs by keyword
- Auto-refresh every 10 seconds
- Download logs
- Color-coded log levels

## ⚙️ Configuration

### Network Ports

Default ports configured by the deployment:

| Port | Protocol | Purpose |
|------|----------|---------|
| 8089 | TCP/UDP | TAK Server client connections |
| 8443 | TCP | TAK Server web interface |
| 5000 | TCP | CoT Server Admin |
| 5432 | TCP | PostgreSQL (localhost only) |

### Firewall

The deployment script configures UFW (Uncomplicated Firewall) with appropriate rules. To modify:

1. Via Web Interface: Navigate to Configuration → Network Settings (coming soon)
2. Via Command Line:
```bash
sudo ufw allow 8089/tcp
sudo ufw allow 8089/udp
```

### Database

**Connection Details:**
- Host: localhost
- Database: takserver
- Username: takserver
- Password: See `/opt/tak/.credentials`

**To change database password:**
```bash
sudo -u postgres psql
ALTER USER takserver WITH PASSWORD 'new_password';
```
Then update `/opt/tak/CoreConfig.xml` and `/opt/tak/.credentials`, then restart TAK Server.

## 🔐 Certificate Management

### Generating Client Certificates

1. Log into CoT Server Admin
2. Navigate to **Certificates** → **Generate New Certificate**
3. Enter client name (e.g., "user1", "device1")
4. Click **Generate**
5. Download the `.p12` file

### Installing Certificates on Clients

**For ATAK (Android):**
1. Transfer the `.p12` file to your device
2. Open ATAK → Settings → Network Preferences
3. Import certificate (password: see `/opt/tak/.credentials` for `TAK_CERT_PASSWORD`)

**For WinTAK:**
1. Download `.p12` file
2. Double-click to install in Windows
3. Enter certificate password from `/opt/tak/.credentials`

**For iTAK (iOS):**
1. Email `.p12` to yourself
2. Open on iOS device
3. Install profile
4. Enter certificate password from `/opt/tak/.credentials`

### Certificate Locations

All certificates are stored in `/opt/tak/certs/`:
- `ca.crt` - Certificate Authority
- `ca.key` - CA private key
- `takserver.crt` - Server certificate
- `takserver.key` - Server private key
- `[client].crt` - Client certificates
- `[client].key` - Client private keys
- `[client].p12` - Client PKCS12 bundles
- `crl.pem` - Certificate Revocation List
- `revoked/` - Revoked certificate storage

### Certificate Revocation

To revoke a compromised or outdated certificate:

1. Navigate to **Certificates** in the CoT Server Admin
2. Find the certificate in the Active Certificates list
3. Click the **🚫 Revoke** button
4. Select a revocation reason:
   - **Key Compromise** - Private key was exposed
   - **Affiliation Changed** - User left organization
   - **Superseded** - Replaced with new certificate
   - **Cessation of Operation** - No longer needed
5. Confirm revocation

Revoked certificates are:
- Moved to `/opt/tak/certs/revoked/`
- Added to the CRL (Certificate Revocation List)
- No longer accepted by TAK Server

To restore a revoked certificate, use the **↩️ Restore** button in the Revoked Certificates section.

## 💾 Backup & Restore

### Creating Backups

1. Navigate to **Backups** in the CoT Server Admin
2. Optionally enter a backup name
3. Select what to include:
   - ✅ **Certificates** - CA, client certs, keys, CRL
   - ✅ **Configuration** - CoreConfig.xml, credentials, users
   - ✅ **Database** - PostgreSQL takserver database
   - ☐ **Data Packages** - Uploaded .zip/.dpk files
4. Click **Create Backup**
5. The backup is automatically downloaded

### Backup Contents

Backups are ZIP files containing:
```
tak_backup_20240115_120000.zip
├── manifest.json         # Backup metadata
├── certs/               # All certificates
│   ├── ca.crt
│   ├── ca.key
│   └── [client files]
├── config/              # Configuration files
│   ├── CoreConfig.xml
│   ├── .credentials
│   └── users.json
└── database/            # Database dump
    └── takserver.sql
```

### Restoring from Backup

1. Navigate to **Backups**
2. Upload a backup file (if from another system)
3. Find the backup in the list
4. Click **🔄 Restore**
5. Select what to restore
6. Confirm restoration

⚠️ **Warning:** Restoring overwrites current data. A pre-restore backup is created automatically.

After restoring configuration or database changes:
```bash
sudo systemctl restart takserver
sudo systemctl restart cot-server-admin
```

### Command-Line Backup

For automated backups, use:
```bash
# Create backup
curl -X POST -H "Content-Type: application/json" \
  -d '{"include_database":true,"include_certificates":true,"include_config":true}' \
  https://localhost/api/backups/create

# Or use the manual backup script
sudo /opt/tak/backup.sh
```

## 🛡️ Security Settings

### Session Security

The web admin includes configurable session security:

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| Session Timeout | `TAK_SESSION_TIMEOUT` | 30 min | Inactive session expiration |
| Max Login Attempts | `TAK_MAX_LOGIN_ATTEMPTS` | 5 | Failed attempts before lockout |
| Lockout Duration | `TAK_LOGIN_LOCKOUT_MINUTES` | 15 min | Account lockout period |
| Concurrent Sessions | `TAK_MAX_CONCURRENT_SESSIONS` | 3 | Max sessions per user |

To customize, set environment variables before starting:
```bash
export TAK_SESSION_TIMEOUT=60
export TAK_MAX_LOGIN_ATTEMPTS=3
sudo systemctl restart cot-server-admin
```

### Session Management

1. Navigate to **Security** in the CoT Server Admin
2. View all active sessions with IP addresses and user agents
3. Terminate individual sessions or all sessions for a user
4. View and clear account lockouts

### Account Lockout

After exceeding `MAX_LOGIN_ATTEMPTS`, the account is locked:
- Lockout applies to the username + IP combination
- Lockout duration is configurable
- Admins can manually clear lockouts from the Security page

## 📜 Audit Logging

All administrative actions are logged for security and compliance.

### Logged Events

| Category | Events |
|----------|--------|
| Authentication | Login success/failure, logout, session expiry |
| Security | Account lockout, session termination, lockout cleared |
| Certificates | Generate, revoke, unrevoke, download |
| Backup | Create, restore, delete backups |
| Configuration | Settings changes |
| Users | Create, delete, password changes |

### Viewing Audit Logs

1. Navigate to **Audit Log** in the CoT Server Admin
2. Filter by:
   - Category (authentication, security, certificates, etc.)
   - Level (info, warning, critical)
   - User
   - Date range
3. Export logs as JSON for external analysis

### Audit Log Location

```
/opt/tak/audit.log
```

Each log entry contains:
- Timestamp
- User who performed the action
- Action type and category
- Target (if applicable)
- Success/failure status
- IP address
- Session ID
- Additional details

### Log Retention

Logs are stored indefinitely. For compliance requirements, implement log rotation:
```bash
# Add to /etc/logrotate.d/tak-audit
/opt/tak/audit.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
}
```

## 🔧 Troubleshooting

### TAK Server Won't Start

1. Check logs:
```bash
sudo journalctl -u takserver -f
```

2. Verify PostgreSQL is running:
```bash
sudo systemctl status postgresql
```

3. Check configuration:
```bash
sudo cat /opt/tak/CoreConfig.xml
```

### CoT Server Admin Not Accessible

1. Check service status:
```bash
sudo systemctl status cot-server-admin
```

2. View logs:
```bash
sudo journalctl -u cot-server-admin -f
```

3. Verify port 5000 is not in use:
```bash
sudo netstat -tulpn | grep 5000
```

### Database Connection Issues

1. Test database connection:
```bash
psql -h localhost -U takserver -d takserver
```

2. Check PostgreSQL logs:
```bash
sudo tail -f /var/log/postgresql/postgresql-15-main.log
```

### Certificate Generation Fails

1. Verify OpenSSL is installed:
```bash
openssl version
```

2. Check CA certificate exists:
```bash
ls -la /opt/tak/certs/ca.crt
```

3. Check permissions:
```bash
sudo ls -la /opt/tak/certs/
```

### Common Error Messages

**"Failed to connect to database"**
- Solution: Ensure PostgreSQL is running and credentials are correct

**"Port already in use"**
- Solution: Stop conflicting service or change port in configuration

**"Certificate already exists"**
- Solution: Use a different client name or delete existing certificate

## 🔒 Security Considerations

### Initial Setup Security

1. **Credentials are randomly generated:**
   - All passwords are auto-generated during installation
   - Stored in `/opt/tak/.credentials` (chmod 600)
   - Review and securely store these credentials

2. **Configure firewall:**
   - Only expose necessary ports
   - Consider restricting admin interface to local network

3. **SSL/TLS:**
   - Use strong certificates in production
   - Consider using Let's Encrypt for web interface

4. **Regular updates:**
```bash
sudo apt update && sudo apt upgrade
```

5. **Secure the credentials file:**
```bash
# Verify permissions
ls -la /opt/tak/.credentials
# Should show: -rw------- (600)
```

### Audit Logging

The system maintains comprehensive audit logs of all administrative actions:

**Events Tracked:**
- Authentication (login success/failure, logout)
- User management (create, delete, modify)
- Certificate operations (generate, revoke, unrevoke)
- Configuration changes
- Backup and restore operations
- Security events (lockouts, session terminations)

**Accessing Audit Logs:**
1. Navigate to **📜 Audit Log** in the web interface
2. Use filters to search by category, user, level, or date range
3. Export logs for compliance or analysis

**Log File Location:** `/opt/tak/audit.log`

**Log Format (JSON Lines):**
```json
{
  "timestamp": "2025-02-02T12:00:00.000000",
  "action": "login_success",
  "category": "authentication",
  "level": "info",
  "user": "admin",
  "ip_address": "192.168.1.100",
  "target": null,
  "success": true,
  "details": "User agent: Mozilla/5.0...",
  "session_id": "abc123..."
}
```

### Session Security

Configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TAK_SESSION_TIMEOUT` | 30 | Session timeout in minutes |
| `TAK_MAX_LOGIN_ATTEMPTS` | 5 | Failed attempts before lockout |
| `TAK_LOGIN_LOCKOUT_MINUTES` | 15 | Lockout duration in minutes |
| `TAK_MAX_CONCURRENT_SESSIONS` | 3 | Max sessions per user |

**Features:**
- **Automatic Session Expiry**: Sessions expire after inactivity
- **Rate Limiting**: Accounts lock after too many failed logins
- **Concurrent Session Control**: Oldest session terminated when limit exceeded
- **Session Management**: Admins can view and terminate any session
- **Lockout Management**: Admins can clear lockouts manually

**To customize settings**, add to `/opt/cot-server-admin/env`:
```bash
TAK_SESSION_TIMEOUT=60
TAK_MAX_LOGIN_ATTEMPTS=3
TAK_LOGIN_LOCKOUT_MINUTES=30
TAK_MAX_CONCURRENT_SESSIONS=2
```

Then restart the service:
```bash
sudo systemctl restart cot-server-admin
```

### Production Recommendations

1. **Use reverse proxy (nginx)** for web interface with SSL
2. **Implement IP whitelisting** for admin interface
3. **Review audit logs regularly** for suspicious activity
4. **Configure session timeouts** appropriate for your environment
5. **Regular backups** of database and certificates
6. **Monitor failed login attempts** via Security page
7. **Use strong certificate passwords** (change from default)

### Backup Strategy

**Via Web Interface (Recommended):**
1. Navigate to **💾 Backups**
2. Select components to backup
3. Click **Create Backup**
4. Download or store on server

**Manual backup script** (create `/opt/tak/backup.sh`):
```bash
#!/bin/bash
BACKUP_DIR="/opt/tak/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR
cp -r /opt/tak/certs $BACKUP_DIR/
cp /opt/tak/CoreConfig.xml $BACKUP_DIR/
sudo -u postgres pg_dump takserver > $BACKUP_DIR/database.sql
```

## 🚀 Advanced Usage

### Custom Configuration

Edit configuration via Web Interface:
1. Navigate to **Configuration**
2. Modify XML directly
3. Click **Save** (automatic backup created)
4. Restart TAK Server

### API Integration

The web admin interface provides REST APIs:

**System & Control:**
```bash
# Get system status
curl http://localhost:5000/api/system/status

# Control server
curl -X POST http://localhost:5000/api/server/control/restart

# List certificates
curl http://localhost:5000/api/certs/list
```

**Audit Logging:**
```bash
# Get audit logs (with filters)
curl "http://localhost:5000/api/audit/logs?limit=100&category=authentication"

# Get audit statistics
curl http://localhost:5000/api/audit/stats

# Export audit logs
curl http://localhost:5000/api/audit/export -o audit_export.json
```

**Session Management:**
```bash
# Get active sessions
curl http://localhost:5000/api/sessions/active

# Terminate a specific session
curl -X POST http://localhost:5000/api/sessions/terminate \
  -H "Content-Type: application/json" \
  -d '{"session_id": "abc123..."}'

# Terminate all sessions for a user
curl -X POST http://localhost:5000/api/sessions/terminate-all \
  -H "Content-Type: application/json" \
  -d '{"username": "admin"}'

# Get security settings
curl http://localhost:5000/api/security/settings

# Get account lockouts
curl http://localhost:5000/api/security/lockouts

# Clear a lockout
curl -X POST http://localhost:5000/api/security/clear-lockout \
  -H "Content-Type: application/json" \
  -d '{"username": "user1"}'
```

**Note:** All API endpoints require authentication via session cookie.

### Service Management

**TAK Server:**
```bash
sudo systemctl start takserver
sudo systemctl stop takserver
sudo systemctl restart takserver
sudo systemctl status takserver
```

**CoT Server Admin:**
```bash
sudo systemctl start cot-server-admin
sudo systemctl stop cot-server-admin
sudo systemctl restart cot-server-admin
sudo systemctl status cot-server-admin
```

**PostgreSQL:**
```bash
sudo systemctl start postgresql
sudo systemctl stop postgresql
sudo systemctl restart postgresql
```

### Start All Services

```bash
sudo /opt/tak/start-all.sh
```

## 📝 File Locations

| Component | Location |
|-----------|----------|
| TAK Server | `/opt/tak/` |
| Configuration | `/opt/tak/CoreConfig.xml` |
| Certificates | `/opt/tak/certs/` |
| Revoked Certs | `/opt/tak/certs/revoked/` |
| CRL | `/opt/tak/certs/crl.pem` |
| Credentials | `/opt/tak/.credentials` |
| Audit Log | `/opt/tak/audit.log` |
| Sessions | `/opt/tak/.sessions` |
| Security Data | `/opt/tak/.security` |
| Backups | `/opt/tak/backups/` |
| Data Packages | `/opt/tak/data-packages/` |
| Connection Profiles | `/opt/tak/connection-profiles/` |
| CoT Server Admin | `/opt/cot-server-admin/` |
| Logs | `journalctl -u takserver` |
| Database | PostgreSQL default location |

## 🤝 Support

For TAK Server specific issues, refer to:
- TAK.gov documentation: https://tak.gov
- TAK Server forums and community

For deployment script issues:
- Check logs: `journalctl -u takserver -f`
- Review `/opt/tak/installation-info.txt`

## 📄 License

Copyright 2024-2025 BlackDot Technology

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

### Disclaimer

This software ("CoT Server Admin") is an independent, open-source project and is **not affiliated with, endorsed by, sponsored by, or connected to**:
- The TAK Product Center
- U.S. Department of Defense
- U.S. Air Force Research Laboratory
- Department of Homeland Security
- Any other U.S. Government agency

"TAK" (Team Awareness Kit / Tactical Assault Kit), "ATAK" (Android Team Awareness Kit), "WinTAK", "iTAK", and related names are products of the U.S. Government. This project provides third-party administration tools that are designed to work with TAK Server software.

TAK Server itself has its own licensing requirements from [TAK.gov](https://tak.gov).

## 🎉 Credits

CoT Server Admin - Administration tool for TAK Server on Raspberry Pi 5.

---

**Last Updated:** February 2025  
**Version:** 1.5.0  
**Tested On:** Raspberry Pi 5 (16GB), Raspberry Pi OS (64-bit)

## 📝 Changelog

### v1.5.1 - Security Foundation + Rebranding
- **Rebranding**: Renamed to "CoT Server Admin" with proper disclaimers
- **Audit Logging**: Comprehensive activity logging with search, filter, and export
- **Session Security**: Configurable timeouts, concurrent session limits, rate limiting
- **Account Lockouts**: Automatic lockout after failed login attempts
- **Session Management**: View and terminate active sessions

### v1.4.0 - Certificate Lifecycle & Backup
- Certificate Revocation with CRL generation
- Full system backup & restore

### v1.3.0 - Data Packages & Profiles
- Data Package management
- Connection profile generation with QR codes

### v1.2.0 - HTTPS Support
- Nginx reverse proxy with TLS encryption
- Let's Encrypt support

### v1.1.0 - Security Hardening
- Secure credential generation
- Apache 2.0 licensing
