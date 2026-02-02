# 🛰️ TAK Server Deployment Package - Complete!

Your complete TAK Server deployment system for Raspberry Pi 5 has been created successfully!

## 📦 What You've Got

A complete, production-ready TAK Server deployment system with:

✅ **Automated Installation Scripts**
- One-command installation (`install_all.sh`)
- Zero command-line configuration needed after setup
- Automatic dependency installation
- Database setup and configuration
- SSL certificate generation

✅ **Web-Based Administration Interface**
- Beautiful, modern web UI
- Real-time server monitoring
- Configuration editor (no SSH needed!)
- Certificate generation with one click
- User management system
- Live log viewer with filtering
- Complete REST API

✅ **Security Features**
- Automatic firewall configuration
- SSL/TLS certificate generation
- User authentication
- Role-based access control
- Password hashing
- Secure database setup

✅ **Complete Documentation**
- Comprehensive README with all details
- Quick start guide (5-minute setup)
- Package information
- Troubleshooting guide

## 📂 Package Structure

```
tak-server-deploy/
├── install_all.sh              ⭐ Master installer
├── deploy_tak_server.sh        🔧 TAK Server deployment
├── install_web_admin.sh        🌐 Web interface installer
├── cot_server_admin.py            💻 Main web application
├── cot-server-admin.service       ⚙️  Systemd service
├── requirements.txt            📋 Python dependencies
├── README.md                   📖 Full documentation
├── QUICKSTART.md               🚀 Quick start guide
├── PACKAGE_INFO.md             ℹ️  Package details
└── templates/                  🎨 Web interface templates
    ├── base.html
    ├── login.html
    ├── dashboard.html
    ├── config.html
    ├── certificates.html
    ├── users.html
    └── logs.html
```

## 🚀 Quick Installation (3 Steps)

### Step 1: Transfer to Raspberry Pi
```bash
# From your computer:
scp -r tak-server-deploy/ pi@YOUR_PI_IP:~/
```

### Step 2: Run Installation
```bash
# SSH into your Pi:
ssh pi@YOUR_PI_IP
cd tak-server-deploy

# Run the master installer:
sudo ./install_all.sh
```

### Step 3: Access Web Interface
Open your browser to: `http://YOUR_PI_IP:5000`

**Login:**
- Username: `admin`
- Password: See `/opt/tak/.credentials`

## 🎯 What the Installation Does

### Automatic Setup (No Manual Steps!)

1. **System Preparation**
   - Updates all packages
   - Installs Java 17, PostgreSQL 15, Python 3
   - Configures system dependencies

2. **Database Setup**
   - Creates TAK Server database
   - Configures PostgreSQL with PostGIS
   - Sets up secure credentials
   - Optimizes for Raspberry Pi

3. **Security Configuration**
   - Generates CA certificate
   - Creates server certificates
   - Generates admin certificates
   - Configures firewall (UFW)

4. **TAK Server Setup**
   - Creates directory structure
   - Generates configuration files
   - Sets up systemd services
   - Configures network ports

5. **Web Interface Installation**
   - Creates Python virtual environment
   - Installs Flask and dependencies
   - Sets up templates
   - Configures auto-start service

## 🌐 Web Interface Features

### Dashboard
- Real-time server status (Running/Stopped)
- Connected clients count
- System uptime and resources
- Database statistics
- One-click server controls (Start/Stop/Restart)

### Configuration Editor
- Edit CoreConfig.xml in browser
- Syntax highlighting
- XML validation
- Automatic backups before saving
- View current network and database settings

### Certificate Management
- Generate client certificates with one click
- Download in multiple formats (.crt, .key, .p12)
- View all existing certificates
- PKCS12 bundles for easy client installation
- Default password: `atakatak`

### User Management
- Create/delete admin users
- Assign roles (admin/user)
- Change passwords
- View all users

### Log Viewer
- Real-time log streaming
- Auto-refresh every 10 seconds
- Filter logs by keyword
- Color-coded log levels
- Download logs as file
- Last 50/100/500 lines view

## 🔐 Security Notes

### Default Credentials (CHANGE THESE!)

**CoT Server Admin:**
- Username: `admin`
- Password: See `/opt/tak/.credentials`

**Database:**
- Username: `takserver`
- Password: See `/opt/tak/.credentials`

**Client Certificates:**
- Password: `atakatak`

### Important First Steps:
1. Change web admin password immediately
2. Change database password
3. Consider using stronger certificate passwords
4. Review firewall rules for your environment

## 📊 Network Configuration

The installation configures these ports:

| Port | Protocol | Purpose |
|------|----------|---------|
| 5000 | TCP | CoT Server Admin |
| 8089 | TCP/UDP | TAK Server client connections |
| 8443 | TCP | TAK Server web interface |
| 5432 | TCP | PostgreSQL (localhost only) |

All ports are automatically opened in the firewall.

## 🔧 Service Management

After installation, manage services via:

**Web Interface (Easiest):**
- Dashboard → Start/Stop/Restart buttons

**Command Line:**
```bash
# TAK Server
sudo systemctl start takserver
sudo systemctl stop takserver
sudo systemctl restart takserver
sudo systemctl status takserver

# Web Admin
sudo systemctl start cot-server-admin
sudo systemctl stop cot-server-admin
sudo systemctl status cot-server-admin

# View logs
sudo journalctl -u takserver -f
sudo journalctl -u cot-server-admin -f
```

## 📱 Connecting Clients

### Generate Certificate
1. Access Web Interface
2. Go to "Certificates"
3. Click "Generate New Certificate"
4. Enter client name (e.g., "user1")
5. Download the `.p12` file

### ATAK (Android)
1. Transfer `.p12` file to device
2. Open ATAK → Settings → Network Preferences
3. Import certificate (password: `atakatak`)
4. Set server: `YOUR_PI_IP:8089`

### WinTAK
1. Install `.p12` certificate in Windows
2. Configure WinTAK connection
3. Server: `YOUR_PI_IP:8089`

### iTAK (iOS)
1. Email `.p12` file to yourself
2. Open on iOS device and install
3. Enter password: `atakatak`
4. Configure server in iTAK

## 📚 Documentation Files

- **README.md** - Complete documentation (read this first!)
- **QUICKSTART.md** - 5-minute setup guide
- **PACKAGE_INFO.md** - Detailed package information
- **Installation logs** - Created at `/opt/tak/installation-info.txt` after install

## 🆘 Troubleshooting

### Installation Issues
Check installation logs:
```bash
sudo journalctl -xe
```

### Web Interface Won't Load
```bash
sudo systemctl status cot-server-admin
sudo systemctl restart cot-server-admin
sudo journalctl -u cot-server-admin -f
```

### TAK Server Won't Start
```bash
sudo systemctl status takserver
sudo journalctl -u takserver -f
```

### Database Issues
```bash
sudo systemctl status postgresql
sudo -u postgres psql -c "\l"
```

## 🎉 Next Steps

1. **Run Installation**
   ```bash
   sudo ./install_all.sh
   ```

2. **Download TAK Server**
   - Visit https://tak.gov
   - Download TAK Server 5.2-RELEASE-27
   - Extract to `/opt/tak/takserver-5.2-RELEASE-27/`

3. **Access Web Interface**
   - Browser: `http://YOUR_PI_IP:5000`
   - Login: admin / (see `/opt/tak/.credentials`)

4. **Review Generated Credentials**
   - Run: `sudo cat /opt/tak/.credentials`

5. **Start TAK Server**
   - Web Interface → Dashboard → Click "Start"

6. **Generate Certificates**
   - Web Interface → Certificates → Generate

7. **Connect Clients**
   - Use generated `.p12` files

## 💡 Pro Tips

- Use the web interface for everything - no SSH needed!
- The dashboard auto-refreshes every 30 seconds
- Logs auto-refresh every 10 seconds
- Configuration changes are automatically backed up
- All services start automatically on boot
- The system is optimized for Raspberry Pi 5's 16GB RAM

## 📞 Support

- TAK Server Official: https://tak.gov
- TAK Server Forums: Check tak.gov for community links
- Documentation: Included in this package

## 🏆 Features You'll Love

✨ **Zero Command Line** - Everything through web interface
🚀 **One-Click Actions** - Start/stop/restart with a button
🔐 **Secure by Default** - Automatic SSL and firewall
📊 **Real-Time Monitoring** - Live status and statistics
📝 **Live Logs** - Stream logs in your browser
🎫 **Easy Certificates** - Generate and download instantly
👥 **User Management** - Create multiple admin users
⚙️ **Config Editor** - Edit XML without SSH
💾 **Auto Backups** - Configuration backed up automatically
🔄 **Auto Updates** - System keeps itself current

## 🎊 You're All Set!

Your TAK Server deployment package is ready to go. Just copy it to your Raspberry Pi and run `sudo ./install_all.sh`!

**Estimated installation time: 5-10 minutes**

---

Created with ❤️ for TAK Server deployments on Raspberry Pi 5
