# CoT Server Admin - Complete Setup & Installation Guide

**Administration Tool for TAK Server on Raspberry Pi 5**

> ⚠️ **Disclaimer**: This software is not affiliated with, endorsed by, or connected to the TAK Product Center, U.S. Department of Defense, or any government agency. "TAK", "ATAK", "WinTAK", and "iTAK" are products of the U.S. Government.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Hardware Setup](#3-hardware-setup)
4. [Software Installation](#4-software-installation)
5. [TAK Server Download](#5-tak-server-download)
6. [Initial Configuration](#6-initial-configuration)
7. [HTTPS Setup (Recommended)](#7-https-setup-recommended)
8. [Certificate Management](#8-certificate-management)
9. [Client Configuration](#9-client-configuration)
10. [Advanced Features](#10-advanced-features)
11. [Maintenance & Operations](#11-maintenance--operations)
12. [Troubleshooting](#12-troubleshooting)
13. [Security Best Practices](#13-security-best-practices)

---

## 1. Overview

### What is CoT Server Admin?

CoT Server Admin is a web-based administration interface that simplifies the deployment and management of TAK Server on Raspberry Pi 5. It provides:

- **Zero command-line configuration** after initial setup
- **Web-based dashboard** for monitoring and control
- **Certificate management** with one-click generation
- **Connection profiles** with QR codes for easy client setup
- **Backup and restore** functionality
- **Audit logging** for security compliance
- **Session security** with rate limiting and lockouts

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Network                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────┐     ┌──────────────────────────────┐     │
│   │  TAK Clients │     │      Raspberry Pi 5          │     │
│   │              │     │  ┌────────────────────────┐  │     │
│   │  • ATAK      │────▶│  │     TAK Server         │  │     │
│   │  • WinTAK    │     │  │     (Port 8089/8443)   │  │     │
│   │  • iTAK      │     │  └────────────────────────┘  │     │
│   │              │     │  ┌────────────────────────┐  │     │
│   └──────────────┘     │  │   CoT Server Admin     │  │     │
│                        │  │     (Port 5000/443)    │  │     │
│   ┌──────────────┐     │  └────────────────────────┘  │     │
│   │    Admin     │────▶│  ┌────────────────────────┐  │     │
│   │   Browser    │     │  │     PostgreSQL         │  │     │
│   └──────────────┘     │  │     (Database)         │  │     │
│                        │  └────────────────────────┘  │     │
│                        └──────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Raspberry Pi | Pi 5 (4GB) | Pi 5 (8GB or 16GB) |
| Storage | 32GB microSD | 64GB+ microSD (Class 10/A2) |
| Power Supply | Official 27W USB-C | Official 27W USB-C |
| Network | Ethernet or WiFi | Gigabit Ethernet |
| Cooling | Passive heatsink | Active cooling case |

### Software Requirements

- **Operating System**: Raspberry Pi OS (64-bit) - Bookworm or later
- **Internet Access**: Required for initial setup and package downloads
- **TAK.gov Account**: Required to download TAK Server software

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 22 | TCP | SSH access (optional) |
| 5000 | TCP | CoT Server Admin (HTTP) |
| 443 | TCP | CoT Server Admin (HTTPS) |
| 8089 | TCP | TAK Server (SSL client connections) |
| 8443 | TCP | TAK Server (Web interface) |
| 8446 | TCP | TAK Server (Federation) |

### Skills Required

- Basic familiarity with Raspberry Pi
- Ability to connect via SSH or use terminal
- Basic networking knowledge (IP addresses, ports)

---

## 3. Hardware Setup

### Step 3.1: Prepare the Raspberry Pi

1. **Flash Raspberry Pi OS**
   ```
   - Download Raspberry Pi Imager from raspberrypi.com
   - Select "Raspberry Pi OS (64-bit)"
   - Click the gear icon for advanced options:
     ✓ Set hostname: tak-server
     ✓ Enable SSH (use password authentication)
     ✓ Set username: pi
     ✓ Set password: [your secure password]
     ✓ Configure WiFi (if not using Ethernet)
     ✓ Set locale settings
   - Flash to microSD card
   ```

2. **Initial Boot**
   ```
   - Insert microSD card into Raspberry Pi
   - Connect Ethernet cable (recommended)
   - Connect power supply
   - Wait 2-3 minutes for first boot
   ```

3. **Find Your Pi's IP Address**
   ```bash
   # Option 1: Check your router's connected devices
   
   # Option 2: If you have a display connected
   hostname -I
   
   # Option 3: Network scan (from another computer)
   # Linux/Mac:
   arp -a | grep raspberry
   # or
   nmap -sn 192.168.1.0/24
   ```

### Step 3.2: Connect via SSH

```bash
# From your computer
ssh pi@YOUR_PI_IP

# Example:
ssh pi@192.168.1.100
```

### Step 3.3: Update the System

```bash
# Update package lists and upgrade
sudo apt update && sudo apt upgrade -y

# Reboot if kernel was updated
sudo reboot
```

---

## 4. Software Installation

### Step 4.1: Transfer Installation Files

**Option A: Direct Download (if Pi has internet)**
```bash
# SSH into your Pi
ssh pi@YOUR_PI_IP

# Create directory and download
mkdir -p ~/cot-server-admin
cd ~/cot-server-admin

# Transfer the zip file (from your computer)
# Exit SSH first, then:
scp CoT_Server_Admin_v1.5.zip pi@YOUR_PI_IP:~/cot-server-admin/
```

**Option B: Transfer from your computer**
```bash
# From your computer (not the Pi)
scp CoT_Server_Admin_v1.5.zip pi@YOUR_PI_IP:~/

# Then SSH in and extract
ssh pi@YOUR_PI_IP
cd ~
unzip CoT_Server_Admin_v1.5.zip -d cot-server-admin
cd cot-server-admin
```

### Step 4.2: Verify Files

```bash
cd ~/cot-server-admin
ls -la

# You should see:
# - cot_server_admin.py
# - deploy_tak_server.sh
# - install_cot_server_admin.sh
# - install_all.sh
# - setup_https.sh
# - Various .html template files
# - README.md
```

### Step 4.3: Run the Installation

**Option A: Complete Installation (Recommended)**
```bash
# Make scripts executable
chmod +x *.sh

# Run complete installation
sudo ./install_all.sh
```

This will:
1. Install all dependencies (Java, PostgreSQL, Python, etc.)
2. Configure the database
3. Set up TAK Server directory structure
4. Install CoT Server Admin web interface
5. Configure firewall rules
6. Start all services

**Option B: Step-by-Step Installation**
```bash
# Step 1: Deploy TAK Server infrastructure
chmod +x *.sh
sudo ./deploy_tak_server.sh

# Step 2: Install web admin interface
sudo ./install_cot_server_admin.sh
```

### Step 4.4: Verify Installation

```bash
# Check services are running
sudo systemctl status cot-server-admin
sudo systemctl status postgresql

# Get your Pi's IP address
hostname -I

# View generated credentials
sudo cat /opt/tak/.credentials
```

**Expected Output:**
```
TAK Server Credentials
======================
Generated: 2025-02-02 10:30:45

Database Password: xK9#mP2$vL5nQ8wR
Certificate Password: bH7@jN4*cF6yT3zA
Web Admin Password: mW5&pR8!qS2xV9eK

IMPORTANT: Store these credentials securely!
```

---

## 5. TAK Server Download

### Step 5.1: Create TAK.gov Account

1. Visit https://tak.gov
2. Click "Register" or "Create Account"
3. Fill out the registration form
4. Verify your email address
5. Wait for account approval (may take 1-3 business days)

### Step 5.2: Download TAK Server

1. Log into https://tak.gov
2. Navigate to "Products" → "TAK Server"
3. Download the latest version (e.g., `takserver-docker-5.2-RELEASE-27.zip`)
4. Note: Download the **Docker** version for easier setup

### Step 5.3: Transfer to Raspberry Pi

```bash
# From your computer
scp takserver-docker-5.2-RELEASE-27.zip pi@YOUR_PI_IP:~/

# SSH into Pi
ssh pi@YOUR_PI_IP

# Extract TAK Server
cd ~
unzip takserver-docker-5.2-RELEASE-27.zip

# Move to correct location
sudo mkdir -p /opt/tak
sudo mv takserver-docker-5.2-RELEASE-27 /opt/tak/
sudo chown -R root:root /opt/tak/takserver-docker-5.2-RELEASE-27
```

### Step 5.4: Initial TAK Server Setup

The deployment script has prepared everything. Start TAK Server:

```bash
# Via command line
sudo systemctl start takserver

# Check status
sudo systemctl status takserver
```

Or use the web interface (see next section).

---

## 6. Initial Configuration

### Step 6.1: Access CoT Server Admin

1. Open a web browser on your computer
2. Navigate to: `http://YOUR_PI_IP:5000`
   - Example: `http://192.168.1.100:5000`

3. Login with:
   - **Username**: `admin`
   - **Password**: Found in `/opt/tak/.credentials` (Web Admin Password)

### Step 6.2: Dashboard Overview

After logging in, you'll see the Dashboard with:

```
┌─────────────────────────────────────────────────────────────┐
│  🛰️ CoT Server Admin                                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ TAK Server   │  │  Database    │  │  Web Admin   │       │
│  │   ● Active   │  │   ● Active   │  │   ● Active   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                              │
│  System Information                                          │
│  ├─ CPU: 12%                                                │
│  ├─ Memory: 1.2GB / 8GB                                     │
│  ├─ Disk: 8.5GB / 64GB                                      │
│  └─ Uptime: 2 days, 3 hours                                 │
│                                                              │
│  Quick Actions                                               │
│  [Start TAK] [Stop TAK] [Restart TAK] [View Logs]           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Step 6.3: Configure TAK Server Settings

1. Click **"Configuration"** in the sidebar
2. Review and adjust key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| Server Name | tak-server | Displayed to clients |
| SSL Port | 8089 | Client connection port |
| Web Port | 8443 | Web UI port |
| Max Connections | 100 | Maximum concurrent clients |
| Federation Port | 8446 | For multi-server setups |

3. Click **"Save Configuration"**
4. Restart TAK Server when prompted

### Step 6.4: Change Default Passwords

**IMPORTANT**: Change the default admin password immediately!

1. Click **"Users"** in the sidebar
2. Click on the **admin** user
3. Click **"Change Password"**
4. Enter a strong new password
5. Click **"Update"**

---

## 7. HTTPS Setup (Recommended)

### Why HTTPS?

- Encrypts all traffic between your browser and the admin interface
- Prevents credential interception on the network
- Required for some browser features

### Step 7.1: Run HTTPS Setup

```bash
# SSH into your Pi
ssh pi@YOUR_PI_IP

# Run the HTTPS setup script
cd ~/cot-server-admin
sudo ./setup_https.sh
```

### Step 7.2: Choose Certificate Option

The script will prompt you:

```
HTTPS Setup Options:
1. Self-signed certificate (quick, works immediately)
2. Let's Encrypt certificate (requires domain name)

Enter choice [1-2]:
```

**Option 1: Self-Signed (Recommended for local networks)**
- Works immediately
- Browser will show security warning (can be bypassed)
- Good for testing and internal use

**Option 2: Let's Encrypt (For public access)**
- Requires a domain name pointing to your Pi
- Requires ports 80 and 443 open to the internet
- Certificates auto-renew

### Step 7.3: Verify HTTPS

```bash
# Run verification script
sudo ./verify_https.sh
```

**Expected Output:**
```
HTTPS Verification Results
==========================
✅ Nginx is running
✅ SSL certificate is valid
✅ HTTPS redirect is working
✅ CoT Server Admin is accessible

Access your server at:
  https://192.168.1.100
```

### Step 7.4: Access via HTTPS

1. Open browser to: `https://YOUR_PI_IP`
2. If using self-signed certificate:
   - Click "Advanced" → "Proceed to site"
   - This is safe for your own server

---

## 8. Certificate Management

### Understanding TAK Certificates

TAK uses mutual TLS authentication:
- **Server Certificate**: Identifies the TAK Server
- **Client Certificates**: Identifies each TAK client (ATAK, WinTAK, etc.)
- **CA Certificate**: Signs all certificates (trust anchor)

### Step 8.1: Generate Client Certificates

1. In CoT Server Admin, click **"Certificates"**
2. Click **"Generate New Certificate"**
3. Fill in the form:
   ```
   Common Name: john_doe
   Organization: My Team
   Validity (days): 365
   ```
4. Click **"Generate"**
5. Download the `.p12` file

### Step 8.2: Certificate Files Explained

| File | Purpose | Used By |
|------|---------|---------|
| `username.p12` | Client certificate bundle | ATAK, WinTAK, iTAK |
| `truststore.p12` | CA certificate (trust) | TAK clients |
| `server.crt` | Server's public certificate | Reference only |

### Step 8.3: Bulk Certificate Generation

For multiple team members:

1. Click **"Certificates"** → **"Bulk Generate"**
2. Enter names (one per line):
   ```
   john_doe
   jane_smith
   team_lead
   operator_1
   operator_2
   ```
3. Click **"Generate All"**
4. Download the ZIP file containing all certificates

### Step 8.4: Revoke a Certificate

If a device is lost or compromised:

1. Click **"Certificates"**
2. Find the certificate in the list
3. Click the **"Revoke"** button
4. Confirm the revocation
5. The CRL (Certificate Revocation List) is automatically updated

---

## 9. Client Configuration

### 9.1 ATAK (Android)

#### Method 1: Using Connection Profile (Easiest)

1. In CoT Server Admin, click **"Connection Profiles"**
2. Select **"ATAK"** from the dropdown
3. Enter the user's certificate name
4. Click **"Generate Profile"**
5. **Scan the QR code** with ATAK:
   - Open ATAK → Menu → Settings → Network Preferences
   - Tap "Import" → "Scan QR Code"

#### Method 2: Manual Configuration

1. **Transfer files to Android device:**
   - `username.p12` (client certificate)
   - `truststore.p12` (server trust)

2. **Import into ATAK:**
   ```
   ATAK → Menu → Settings → Network Preferences
   → Manage Server Connections → Add
   
   Description: My TAK Server
   Address: YOUR_PI_IP
   Port: 8089
   Protocol: SSL
   
   → Advanced → Certificates
   → Import Client Certificate: username.p12
   → Import CA Certificate: truststore.p12
   → Enter certificate password
   ```

3. **Connect:**
   - Toggle the connection ON
   - Green indicator = connected

### 9.2 WinTAK (Windows)

#### Step-by-Step Setup

1. **Download certificate files:**
   - `username.p12`
   - `truststore.p12`

2. **Import certificates into Windows:**
   ```
   Double-click username.p12
   → Store Location: Current User
   → Enter password from CoT Server Admin
   → Place in "Personal" store
   
   Repeat for truststore.p12
   → Place in "Trusted Root Certification Authorities"
   ```

3. **Configure WinTAK:**
   ```
   WinTAK → Settings → Network
   → Server Connections → Add
   
   Name: My TAK Server
   Address: YOUR_PI_IP
   Port: 8089
   Protocol: TLS
   
   → Select client certificate
   → Select CA certificate
   ```

4. **Connect and verify**

### 9.3 iTAK (iOS)

1. **Transfer certificate files** via:
   - AirDrop
   - Email attachment
   - iCloud Drive

2. **Install certificates:**
   - Tap the `.p12` file
   - Follow prompts to install profile
   - Enter certificate password

3. **Configure iTAK:**
   ```
   iTAK → Settings → Servers → Add Server
   
   Host: YOUR_PI_IP
   Port: 8089
   Protocol: SSL
   
   Select installed certificates
   ```

### 9.4 Connection Troubleshooting

| Problem | Solution |
|---------|----------|
| "Connection refused" | Check TAK Server is running, port 8089 is open |
| "Certificate error" | Verify certificate password, check expiration |
| "Untrusted certificate" | Import truststore.p12 on client |
| "Authentication failed" | Certificate may be revoked, regenerate |

---

## 10. Advanced Features

### 10.1 Data Package Management

Data packages distribute files (maps, overlays, configs) to TAK clients.

**Upload a Data Package:**
1. Click **"Data Packages"**
2. Drag and drop a `.zip` or `.dpk` file
3. Or click **"Browse"** to select file
4. Package appears in the list

**Distribute to Clients:**
- Clients automatically sync data packages when connected
- Or manually push via **"Send to Clients"**

### 10.2 Backup & Restore

**Create a Backup:**
1. Click **"Backups"**
2. Click **"Create Backup"**
3. Select what to include:
   - ✓ Certificates
   - ✓ Configuration
   - ✓ Database
   - ✓ Data Packages
4. Click **"Create"**
5. Download the backup `.zip` file

**Restore from Backup:**
1. Click **"Backups"**
2. Click **"Upload Backup"**
3. Select your backup file
4. Click **"Restore"**
5. Confirm the restore operation

### 10.3 Audit Logging

All administrative actions are logged for security compliance.

**View Audit Logs:**
1. Click **"Audit Log"**
2. Filter by:
   - Date range
   - Action type (login, certificate, config change)
   - User
   - Severity level

**Export Logs:**
1. Set your filters
2. Click **"Export"**
3. Download JSON file for analysis

### 10.4 Session Security

**View Active Sessions:**
1. Click **"Security"**
2. See all logged-in admin sessions
3. Terminate suspicious sessions if needed

**Security Settings:**
| Setting | Default | Description |
|---------|---------|-------------|
| Session Timeout | 30 min | Auto-logout after inactivity |
| Max Login Attempts | 5 | Before account lockout |
| Lockout Duration | 15 min | Time until unlock |
| Max Concurrent Sessions | 3 | Per user |

### 10.5 Federation (Multi-Server)

For connecting multiple TAK Servers:

1. Click **"Configuration"**
2. Enable **"Federation"**
3. Configure federation settings:
   - Federation Port: 8446
   - Federation Name: unique identifier
4. Exchange federation certificates between servers

---

## 11. Maintenance & Operations

### 11.1 Service Management

**Via Web Interface:**
- Dashboard → Quick Actions → Start/Stop/Restart

**Via Command Line:**
```bash
# TAK Server
sudo systemctl start takserver
sudo systemctl stop takserver
sudo systemctl restart takserver
sudo systemctl status takserver

# CoT Server Admin
sudo systemctl start cot-server-admin
sudo systemctl stop cot-server-admin
sudo systemctl restart cot-server-admin
sudo systemctl status cot-server-admin

# PostgreSQL Database
sudo systemctl start postgresql
sudo systemctl stop postgresql
sudo systemctl status postgresql
```

### 11.2 Log Files

| Log | Location | Command |
|-----|----------|---------|
| TAK Server | Journal | `journalctl -u takserver -f` |
| CoT Admin | Journal | `journalctl -u cot-server-admin -f` |
| Nginx | `/var/log/nginx/` | `tail -f /var/log/nginx/error.log` |
| Audit | `/opt/tak/audit.log` | `tail -f /opt/tak/audit.log` |

### 11.3 Updates

**Update CoT Server Admin:**
```bash
# Backup current installation
sudo cp -r /opt/cot-server-admin /opt/cot-server-admin.bak

# Transfer new files
scp CoT_Server_Admin_v1.6.zip pi@YOUR_PI_IP:~/

# Extract and update
ssh pi@YOUR_PI_IP
cd ~
unzip CoT_Server_Admin_v1.6.zip -d cot-server-admin-new
sudo cp cot-server-admin-new/*.py /opt/cot-server-admin/
sudo cp cot-server-admin-new/*.html /opt/cot-server-admin/templates/

# Restart service
sudo systemctl restart cot-server-admin
```

**Update TAK Server:**
1. Download new version from TAK.gov
2. Create backup via web interface
3. Stop TAK Server
4. Extract new version
5. Restore configuration
6. Start TAK Server

### 11.4 Disk Space Management

```bash
# Check disk usage
df -h

# Find large files
du -sh /opt/tak/*

# Clean old backups (keep last 5)
ls -t /opt/tak/backups/*.zip | tail -n +6 | xargs rm -f

# Clean old logs
sudo journalctl --vacuum-time=7d
```

---

## 12. Troubleshooting

### 12.1 Common Issues

#### Web Interface Won't Load

```bash
# Check if service is running
sudo systemctl status cot-server-admin

# Check for errors
sudo journalctl -u cot-server-admin -n 50

# Restart service
sudo systemctl restart cot-server-admin

# Check port is listening
sudo netstat -tlnp | grep 5000
```

#### TAK Server Won't Start

```bash
# Check status
sudo systemctl status takserver

# View detailed logs
sudo journalctl -u takserver -n 100

# Common issues:
# - Java not installed: sudo apt install default-jdk
# - Port already in use: sudo lsof -i :8089
# - Database not running: sudo systemctl start postgresql
```

#### Certificate Generation Fails

```bash
# Check certificate directory permissions
ls -la /opt/tak/certs/

# Verify OpenSSL is installed
openssl version

# Check disk space
df -h /opt/tak/
```

#### Clients Can't Connect

1. **Verify TAK Server is running:**
   ```bash
   sudo systemctl status takserver
   ```

2. **Check firewall:**
   ```bash
   sudo ufw status
   # Should show 8089 ALLOW
   ```

3. **Test port from another machine:**
   ```bash
   nc -zv YOUR_PI_IP 8089
   ```

4. **Verify certificate validity:**
   - Check expiration date in web interface
   - Ensure certificate isn't revoked

### 12.2 Reset Procedures

#### Reset Admin Password

```bash
# SSH into Pi
ssh pi@YOUR_PI_IP

# Stop the service
sudo systemctl stop cot-server-admin

# Reset password (creates new random password)
cd /opt/cot-server-admin
sudo python3 -c "
from cot_server_admin import generate_password_hash
import secrets
new_pass = secrets.token_urlsafe(12)
print(f'New admin password: {new_pass}')
# Update in database or users file
"

# Restart service
sudo systemctl start cot-server-admin
```

#### Complete Reset

```bash
# WARNING: This removes all data!

# Stop services
sudo systemctl stop cot-server-admin
sudo systemctl stop takserver

# Remove data (keeps configuration)
sudo rm -rf /opt/tak/certs/clients/*
sudo rm -rf /opt/tak/backups/*
sudo rm -f /opt/tak/audit.log

# Reset database
sudo -u postgres psql -c "DROP DATABASE IF EXISTS tak;"
sudo -u postgres psql -c "CREATE DATABASE tak;"

# Restart
sudo systemctl start takserver
sudo systemctl start cot-server-admin
```

---

## 13. Security Best Practices

### 13.1 Network Security

1. **Use HTTPS** for admin interface (see Section 7)
2. **Firewall rules** - only open necessary ports:
   ```bash
   sudo ufw default deny incoming
   sudo ufw allow ssh
   sudo ufw allow 443/tcp    # HTTPS admin
   sudo ufw allow 8089/tcp   # TAK clients
   sudo ufw enable
   ```
3. **VPN access** - consider placing admin interface behind VPN
4. **Regular updates**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

### 13.2 Authentication Security

1. **Strong passwords** - minimum 12 characters with complexity
2. **Change default credentials** immediately after installation
3. **Review active sessions** regularly
4. **Enable account lockout** (enabled by default)
5. **Monitor audit logs** for suspicious activity

### 13.3 Certificate Security

1. **Short validity periods** - 90-365 days recommended
2. **Unique certificates** per user/device
3. **Immediate revocation** when devices are lost/compromised
4. **Secure storage** of CA private key
5. **Regular CRL updates** (automatic with CoT Server Admin)

### 13.4 Backup Security

1. **Encrypt backups** before storing off-device
2. **Regular backup schedule** - daily or weekly
3. **Test restores** periodically
4. **Store backups off-site** (not just on the Pi)
5. **Secure transfer** - use SFTP or encrypted channels

### 13.5 Physical Security

1. **Secure location** for Raspberry Pi
2. **Disable unused ports** (USB, HDMI if not needed)
3. **SD card encryption** (optional, impacts performance)
4. **Access logging** at physical location

---

## Quick Reference Card

### URLs
| Service | URL |
|---------|-----|
| Admin (HTTP) | `http://YOUR_PI_IP:5000` |
| Admin (HTTPS) | `https://YOUR_PI_IP` |
| TAK Server | `https://YOUR_PI_IP:8443` |

### Default Credentials
| Service | Username | Password Location |
|---------|----------|-------------------|
| CoT Admin | admin | `/opt/tak/.credentials` |
| Database | tak | `/opt/tak/.credentials` |

### Important Commands
```bash
# View credentials
sudo cat /opt/tak/.credentials

# Service status
sudo systemctl status cot-server-admin takserver postgresql

# View logs
sudo journalctl -u cot-server-admin -f
sudo journalctl -u takserver -f

# Restart services
sudo systemctl restart cot-server-admin takserver
```

### File Locations
| Purpose | Path |
|---------|------|
| CoT Admin | `/opt/cot-server-admin/` |
| TAK Server | `/opt/tak/` |
| Certificates | `/opt/tak/certs/` |
| Backups | `/opt/tak/backups/` |
| Audit Log | `/opt/tak/audit.log` |
| Credentials | `/opt/tak/.credentials` |

---

## Support & Resources

### Official Resources
- TAK.gov: https://tak.gov
- TAK Documentation: Available after TAK.gov login
- TAK Community Discord: Links available on TAK.gov

### This Project
- GitHub: [Your repository URL]
- Issues: [Your issues URL]
- License: Apache 2.0

---

**Document Version**: 1.5.0  
**Last Updated**: February 2025  
**Compatible With**: CoT Server Admin v1.5, TAK Server 5.x

---

*This documentation is provided for the CoT Server Admin project, an independent open-source tool. It is not affiliated with or endorsed by the TAK Product Center or U.S. Government.*
