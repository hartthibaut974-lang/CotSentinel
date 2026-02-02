# Quick Start Guide - TAK Server on Raspberry Pi 5

## 🚀 5-Minute Setup

### Prerequisites
- Raspberry Pi 5 with Raspberry Pi OS installed
- Network connection
- SSH access

### Step 1: Transfer Files (30 seconds)
```bash
# On your computer, copy files to Pi
scp -r tak-server-deploy/ pi@YOUR_PI_IP:~/
```

### Step 2: Deploy TAK Server (3 minutes)
```bash
# SSH into your Pi
ssh pi@YOUR_PI_IP

# Run deployment
cd tak-server-deploy
chmod +x deploy_tak_server.sh install_web_admin.sh
sudo ./deploy_tak_server.sh
```

### Step 3: Install Web Interface (1 minute)
```bash
sudo ./install_web_admin.sh
```

### Step 4: Access Web Interface
Open browser to: `http://YOUR_PI_IP:5000`

**Login:**
- Username: `admin`
- Password: See `/opt/tak/.credentials`

### Step 5: Download TAK Server
1. Visit https://tak.gov
2. Download TAK Server 5.2-RELEASE-27
3. Extract to `/opt/tak/takserver-5.2-RELEASE-27/`

### Step 6: Start TAK Server
Via Web Interface:
1. Go to Dashboard
2. Click "Start" button

Or via command line:
```bash
sudo systemctl start takserver
```

## ✅ Verification

### Check Status
Web Interface → Dashboard → View all services status

### Generate Test Certificate
Web Interface → Certificates → Generate New Certificate

### View Logs
Web Interface → Logs → Real-time log viewer

## 🎯 Next Steps

1. **Change default passwords** (Web Interface → Users)
2. **Configure network settings** (Web Interface → Configuration)
3. **Generate client certificates** (Web Interface → Certificates)
4. **Connect ATAK clients** using generated certificates

## 📱 Connecting Your First Client

### ATAK (Android)
1. Generate certificate in Web Interface
2. Download `.p12` file
3. Transfer to device
4. ATAK → Settings → Network → Import certificate
5. Enter server IP and port 8089

### WinTAK
1. Generate certificate in Web Interface
2. Download `.p12` file
3. Install certificate in Windows
4. Configure WinTAK to connect to your server

## 🆘 Quick Troubleshooting

**Web interface won't load?**
```bash
sudo systemctl status cot-server-admin
sudo systemctl restart cot-server-admin
```

**TAK Server won't start?**
```bash
sudo journalctl -u takserver -f
```

**Database issues?**
```bash
sudo systemctl status postgresql
```

## 📚 Full Documentation

For detailed information, see `README.md`

## 🔗 Important URLs

- Web Admin: `http://YOUR_PI_IP:5000`
- TAK Server: `https://YOUR_PI_IP:8443`
- TAK.gov: https://tak.gov

---

**That's it! Your TAK Server is ready to use! 🎉**
