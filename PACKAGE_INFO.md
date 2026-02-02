# TAK Server Deployment Package

## 📦 Package Contents

This package contains everything needed to deploy TAK Server on Raspberry Pi 5 with a complete web-based administration interface.

### Main Installation Scripts

| File | Purpose |
|------|---------|
| `install_all.sh` | **Master installer** - Runs complete installation |
| `deploy_tak_server.sh` | Deploys TAK Server and dependencies |
| `install_web_admin.sh` | Installs web administration interface |

### Application Files

| File | Purpose |
|------|---------|
| `cot_server_admin.py` | Main web application (Flask) |
| `cot-server-admin.service` | Systemd service file for web interface |
| `requirements.txt` | Python dependencies |

### Templates (Web Interface)

| File | Purpose |
|------|---------|
| `templates/base.html` | Base layout template |
| `templates/login.html` | Login page |
| `templates/dashboard.html` | Main dashboard |
| `templates/config.html` | Configuration editor |
| `templates/certificates.html` | Certificate management |
| `templates/users.html` | User management |
| `templates/logs.html` | Log viewer |

### Documentation

| File | Purpose |
|------|---------|
| `README.md` | **Complete documentation** |
| `QUICKSTART.md` | Quick start guide (5-minute setup) |
| `PACKAGE_INFO.md` | This file |

## 🚀 Installation Methods

### Method 1: Complete Installation (Recommended)
```bash
sudo ./install_all.sh
```
Runs all installation steps automatically.

### Method 2: Step-by-Step
```bash
# Step 1: Deploy TAK Server
sudo ./deploy_tak_server.sh

# Step 2: Install Web Interface
sudo ./install_web_admin.sh
```

### Method 3: Manual Component Installation
Useful for troubleshooting or custom setups. See README.md for details.

## 📋 Prerequisites

- **Hardware**: Raspberry Pi 5 (16GB RAM recommended)
- **OS**: Raspberry Pi OS (64-bit), latest version
- **Network**: Internet connection for package downloads
- **Access**: Root/sudo privileges
- **Storage**: 64GB+ microSD card recommended

## 🎯 What Gets Installed

### System Packages
- OpenJDK 17 (Java runtime for TAK Server)
- PostgreSQL 15 with PostGIS extension
- Python 3 with pip and venv
- Nginx (web server)
- UFW (firewall)
- OpenSSL (certificate generation)

### TAK Server Components
- TAK Server framework (requires separate download from tak.gov)
- PostgreSQL database configured for TAK
- SSL/TLS certificates
- Configuration files
- Systemd service

### CoT Server Admin
- Flask web application
- User authentication system
- RESTful API endpoints
- Real-time monitoring
- Certificate management tools

## 🔐 Security Features

### Automatic Setup
- Firewall configuration (UFW)
- SSL certificate generation
- Secure database passwords
- User authentication

### Default Credentials
**Web Interface:**
- Username: `admin`
- Password: See `/opt/tak/.credentials`

**Database:**
- Username: `takserver`
- Password: See `/opt/tak/.credentials`

**Certificate Password:**
- Default: `atakatak`

⚠️ **Change all default credentials immediately after installation!**

## 📂 Installation Locations

After installation, files will be located at:

```
/opt/tak/                           # TAK Server directory
├── CoreConfig.xml                  # Main configuration
├── certs/                          # SSL certificates
│   ├── ca.crt                      # Certificate Authority
│   ├── ca.key                      # CA private key
│   └── *.p12                       # Client certificates
├── logs/                           # Log files
├── data/                           # Server data
└── start-all.sh                    # Convenience startup script

/opt/cot-server-admin/                 # Web interface
├── venv/                           # Python virtual environment
├── templates/                      # HTML templates
└── cot_server_admin.py               # Main application

/etc/systemd/system/               # Service files
├── takserver.service              # TAK Server service
└── cot-server-admin.service          # Web interface service
```

## 🌐 Network Ports

| Port | Protocol | Service | Purpose |
|------|----------|---------|---------|
| 5000 | TCP | Web Admin | Administration interface |
| 8089 | TCP/UDP | TAK Server | Client connections |
| 8443 | TCP | TAK Server | Web interface |
| 5432 | TCP | PostgreSQL | Database (localhost only) |

## 📊 Service Management

### TAK Server
```bash
sudo systemctl start takserver      # Start
sudo systemctl stop takserver       # Stop
sudo systemctl restart takserver    # Restart
sudo systemctl status takserver     # Check status
sudo journalctl -u takserver -f     # View logs
```

### CoT Server Admin
```bash
sudo systemctl start cot-server-admin      # Start
sudo systemctl stop cot-server-admin       # Stop
sudo systemctl restart cot-server-admin    # Restart
sudo systemctl status cot-server-admin     # Check status
sudo journalctl -u cot-server-admin -f     # View logs
```

### All Services
```bash
sudo /opt/tak/start-all.sh          # Start everything
```

## 🔧 Customization

### Changing Web Admin Port
Edit `/opt/cot-server-admin/cot_server_admin.py`:
```python
app.run(host='0.0.0.0', port=5000)  # Change 5000 to your desired port
```

Then restart:
```bash
sudo systemctl restart cot-server-admin
```

### Changing Database Password
```bash
sudo -u postgres psql
ALTER USER takserver WITH PASSWORD 'new_password';
```

Update `/opt/tak/CoreConfig.xml` with new password.

### Adding SSL to Web Interface
Use nginx as reverse proxy with Let's Encrypt. See README.md for details.

## 📚 Getting Started

1. **Transfer package to Raspberry Pi:**
   ```bash
   scp -r tak-server-deploy/ pi@YOUR_PI_IP:~/
   ```

2. **SSH into Raspberry Pi:**
   ```bash
   ssh pi@YOUR_PI_IP
   cd tak-server-deploy
   ```

3. **Run installation:**
   ```bash
   sudo ./install_all.sh
   ```

4. **Download TAK Server:**
   - Visit https://tak.gov
   - Download TAK Server 5.2-RELEASE-27
   - Extract to `/opt/tak/takserver-5.2-RELEASE-27/`

5. **Access web interface:**
   - Open browser to `http://YOUR_PI_IP:5000`
   - Login with admin / (see .credentials file)
   - Start TAK Server from Dashboard

6. **Generate client certificates:**
   - Navigate to Certificates page
   - Click "Generate New Certificate"
   - Download .p12 file for clients

## 🆘 Troubleshooting

### Installation Fails
- Check internet connection
- Verify sufficient disk space: `df -h`
- Review error messages in terminal
- Check logs: `sudo journalctl -xe`

### Web Interface Won't Load
- Verify service is running: `sudo systemctl status cot-server-admin`
- Check firewall: `sudo ufw status`
- View logs: `sudo journalctl -u cot-server-admin -f`

### TAK Server Won't Start
- Check PostgreSQL: `sudo systemctl status postgresql`
- Verify configuration: `sudo cat /opt/tak/CoreConfig.xml`
- View logs: `sudo journalctl -u takserver -f`

## 📞 Support Resources

- **TAK Server Official**: https://tak.gov
- **Documentation**: README.md (included)
- **Quick Start**: QUICKSTART.md (included)
- **Installation Info**: `/opt/tak/installation-info.txt` (after install)

## 📝 Version Information

- **Package Version**: 1.0.0
- **TAK Server Version**: 5.2-RELEASE-27 (compatible)
- **Python Version**: 3.9+
- **PostgreSQL Version**: 15
- **Target Platform**: Raspberry Pi 5 / Raspberry Pi OS 64-bit

## 📄 License

This deployment package is provided as-is. TAK Server itself has separate licensing requirements from TAK.gov.

## ✨ Features Summary

✅ Zero command-line configuration after initial setup
✅ Complete web-based administration
✅ Automatic certificate generation
✅ Real-time monitoring and logs
✅ User management
✅ Database statistics
✅ Configuration backup
✅ Firewall configuration
✅ Service management
✅ One-command installation

---

**Ready to deploy? Run `sudo ./install_all.sh` to begin!** 🚀
