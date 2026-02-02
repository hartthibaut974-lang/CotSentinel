# CoT Server Admin - Quick Reference

## 5-Minute Quick Start

### 1. Transfer & Extract Files
```bash
scp CoT_Server_Admin_v1.5.zip pi@YOUR_PI_IP:~/
ssh pi@YOUR_PI_IP
unzip CoT_Server_Admin_v1.5.zip -d cot-server-admin
cd cot-server-admin
```

### 2. Run Installation
```bash
chmod +x *.sh
sudo ./install_all.sh
```

### 3. Get Your Credentials
```bash
sudo cat /opt/tak/.credentials
```

### 4. Access Web Interface
```
URL: http://YOUR_PI_IP:5000
User: admin
Pass: (from credentials file)
```

### 5. Download TAK Server
1. Go to https://tak.gov (requires account)
2. Download TAK Server 5.x
3. Extract to `/opt/tak/`

### 6. Generate Client Certificates
1. Web Interface → Certificates → Generate New
2. Download .p12 file
3. Import into ATAK/WinTAK/iTAK

---

## Essential Commands

| Action | Command |
|--------|---------|
| View credentials | `sudo cat /opt/tak/.credentials` |
| Check all services | `sudo systemctl status cot-server-admin takserver postgresql` |
| Restart web admin | `sudo systemctl restart cot-server-admin` |
| Restart TAK Server | `sudo systemctl restart takserver` |
| View admin logs | `sudo journalctl -u cot-server-admin -f` |
| View TAK logs | `sudo journalctl -u takserver -f` |
| Enable HTTPS | `sudo ./setup_https.sh` |

---

## Network Ports

| Port | Service | Protocol |
|------|---------|----------|
| 5000 | Web Admin (HTTP) | TCP |
| 443 | Web Admin (HTTPS) | TCP |
| 8089 | TAK Client Connections | TCP |
| 8443 | TAK Web Interface | TCP |

---

## File Locations

| Purpose | Path |
|---------|------|
| Web Admin App | `/opt/cot-server-admin/` |
| TAK Server | `/opt/tak/` |
| Certificates | `/opt/tak/certs/` |
| Backups | `/opt/tak/backups/` |
| Credentials | `/opt/tak/.credentials` |
| Audit Log | `/opt/tak/audit.log` |

---

## ATAK Quick Connect

1. **Generate Profile**: Web Interface → Connection Profiles → ATAK
2. **Scan QR Code**: ATAK → Settings → Network → Import → Scan QR
3. **Done!** Green indicator = connected

---

## Troubleshooting

**Web interface won't load:**
```bash
sudo systemctl restart cot-server-admin
sudo journalctl -u cot-server-admin -n 50
```

**TAK Server won't start:**
```bash
sudo journalctl -u takserver -n 50
sudo systemctl restart takserver
```

**Clients can't connect:**
```bash
sudo ufw status                    # Check firewall
sudo systemctl status takserver    # Check TAK running
nc -zv YOUR_PI_IP 8089            # Test port (from client)
```

---

## Security Checklist

- [ ] Changed default admin password
- [ ] Enabled HTTPS (`sudo ./setup_https.sh`)
- [ ] Reviewed firewall rules
- [ ] Created individual user certificates
- [ ] Set up regular backups
- [ ] Reviewed audit logs

---

*CoT Server Admin v1.5 | Not affiliated with TAK Product Center or U.S. Government*
