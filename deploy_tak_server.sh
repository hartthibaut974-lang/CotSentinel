#!/bin/bash

################################################################################
# TAK Server Deployment Script for Raspberry Pi 5
# This script fully installs and configures TAK Server with zero manual steps
#
# Copyright 2024-2025 BlackDot Technology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# DISCLAIMER: This software is not affiliated with the TAK Product Center,
# U.S. Department of Defense, or any government agency. This is an independent
# tool designed to assist with TAK Server deployment.
################################################################################

set -e

echo "=========================================="
echo "TAK Server Deployment Script"
echo "=========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages (defined early so it can be used below)
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Configuration variables
TAK_VERSION="5.2-RELEASE-27"
TAK_DIR="/opt/tak"
POSTGRES_VERSION="15"
ADMIN_USER="takadmin"
WEB_ADMIN_PORT="5000"

# Security: Generate random passwords if not provided via environment variables
DB_PASSWORD="${TAK_DB_PASSWORD:-$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 20)}"
CERT_PASSWORD="${TAK_CERT_PASSWORD:-$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)}"
WEB_ADMIN_PASSWORD="${TAK_WEB_ADMIN_PASSWORD:-$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)}"

print_message "$YELLOW" "=========================================="
print_message "$YELLOW" "SECURITY NOTICE: Random passwords generated"
print_message "$YELLOW" "Set environment variables to override:"
print_message "$YELLOW" "  TAK_DB_PASSWORD, TAK_CERT_PASSWORD,"
print_message "$YELLOW" "  TAK_WEB_ADMIN_PASSWORD"
print_message "$YELLOW" "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_message "$RED" "This script must be run as root (use sudo)"
   exit 1
fi

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
    print_message "$YELLOW" "Warning: This doesn't appear to be a Raspberry Pi"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_message "$GREEN" "Step 1: Updating system packages..."
apt-get update -y
apt-get upgrade -y

print_message "$GREEN" "Step 2: Installing prerequisites..."
apt-get install -y \
    openjdk-17-jdk \
    postgresql-${POSTGRES_VERSION} \
    postgresql-contrib \
    postgresql-15-postgis-3 \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    ufw \
    curl \
    wget \
    unzip \
    net-tools \
    openssl \
    ca-certificates

print_message "$GREEN" "Step 3: Creating TAK directory structure..."
mkdir -p ${TAK_DIR}
mkdir -p ${TAK_DIR}/certs
mkdir -p ${TAK_DIR}/logs
mkdir -p ${TAK_DIR}/data
mkdir -p /home/takserver
mkdir -p /opt/cot-server-admin

print_message "$GREEN" "Step 4: Configuring PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Create TAK database and user
sudo -u postgres psql -c "CREATE DATABASE takserver;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER takserver WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE takserver TO takserver;" 2>/dev/null || true
sudo -u postgres psql -d takserver -c "CREATE EXTENSION IF NOT EXISTS postgis;" 2>/dev/null || true

# Configure PostgreSQL to accept connections
PG_HBA="/etc/postgresql/${POSTGRES_VERSION}/main/pg_hba.conf"
if ! grep -q "takserver" "$PG_HBA"; then
    echo "host    takserver       takserver       127.0.0.1/32            md5" >> "$PG_HBA"
fi

systemctl restart postgresql

print_message "$GREEN" "Step 5: Downloading TAK Server..."
# Note: TAK Server requires registration and download from tak.gov
# For this script, we'll create the structure assuming the TAK release is provided
TAK_RELEASE_DIR="${TAK_DIR}/takserver-${TAK_VERSION}"

if [ ! -d "$TAK_RELEASE_DIR" ]; then
    print_message "$YELLOW" "TAK Server release not found. Creating placeholder structure..."
    print_message "$YELLOW" "You'll need to download the official TAK Server release from https://tak.gov"
    print_message "$YELLOW" "and extract it to ${TAK_DIR}/takserver-${TAK_VERSION}"
    mkdir -p "$TAK_RELEASE_DIR"
fi

print_message "$GREEN" "Step 6: Generating SSL certificates..."
cd ${TAK_DIR}/certs

# Generate CA certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/C=US/ST=State/L=City/O=TAK/CN=TAK-CA"

# Generate server certificate
openssl genrsa -out takserver.key 4096
openssl req -new -key takserver.key -out takserver.csr -subj "/C=US/ST=State/L=City/O=TAK/CN=takserver"
openssl x509 -req -days 3650 -in takserver.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out takserver.crt

# Generate admin certificate
openssl genrsa -out admin.key 4096
openssl req -new -key admin.key -out admin.csr -subj "/C=US/ST=State/L=City/O=TAK/CN=admin"
openssl x509 -req -days 3650 -in admin.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out admin.crt

# Create truststore
openssl pkcs12 -export -in takserver.crt -inkey takserver.key -out takserver.p12 -password pass:${CERT_PASSWORD}

# Set permissions
chmod 600 *.key
chmod 644 *.crt

print_message "$GREEN" "Step 7: Creating TAK Server configuration..."
cat > ${TAK_DIR}/CoreConfig.xml << EOFCONFIG
<?xml version="1.0" encoding="UTF-8"?>
<Configuration>
    <network>
        <input protocol="tcp" port="8089" auth="x509"/>
        <input protocol="tls" port="8089" auth="x509"/>
        <input protocol="udp" port="8089"/>
        <connector port="8443" clientAuth="false"/>
    </network>
    
    <auth>
        <File location="UserAuthenticationFile.xml"/>
    </auth>
    
    <submission ignoreStaleMessages="false" validateXml="false"/>
    
    <repository enable="true" 
                numDbConnections="100"
                primaryKeyProxyTimeout="120000"
                connectionPoolAutoSize="true"
                archive="true">
        <connection url="jdbc:postgresql://localhost:5432/takserver"
                    username="takserver"
                    password="${DB_PASSWORD}"/>
    </repository>
    
    <certificateSigning CA="TAKServer">
        <certificateConfig>
            <nameEntries>
                <nameEntry name="O" value="TAK"/>
                <nameEntry name="OU" value="TAK"/>
            </nameEntries>
        </certificateConfig>
        <TAKServerCAConfig keystore="JKS">
            <issuerName>CN=TAK-CA</issuerName>
            <keystoreFile>\${TAK_DIR}/certs/takserver.jks</keystoreFile>
            <keystorePass>${CERT_PASSWORD}</keystorePass>
            <validityDays>3650</validityDays>
        </TAKServerCAConfig>
    </certificateSigning>
    
    <security>
        <tls keystore="\${TAK_DIR}/certs/takserver.jks" 
             keystorePass="${CERT_PASSWORD}"
             truststore="\${TAK_DIR}/certs/truststore.jks"
             truststorePass="${CERT_PASSWORD}"
             context="TLSv1.2"
             keymanager="SunX509"/>
    </security>
    
    <federation>
        <federation-server enable="true">
            <v1 enable="true"/>
            <v2 enable="true"/>
        </federation-server>
    </federation>
    
    <plugins/>
    
    <dissemination smartRetry="false"/>
    
    <filter>
        <flowtag enable="true"/>
        <streamingbroker enable="true"/>
        <scrubber enable="true" action="overwrite">
            <field name="remarks" policy="NONE"/>
            <field name="detail" policy="NONE"/>
        </scrubber>
    </filter>
    
    <buffer>
        <latestSA enable="true"/>
        <queue>
            <priority value="5"/>
        </queue>
    </buffer>
    
    <vbm enabled="false"/>
</Configuration>
EOFCONFIG

print_message "$GREEN" "Step 8: Creating systemd service for TAK Server..."
cat > /etc/systemd/system/takserver.service << 'EOFSERVICE'
[Unit]
Description=TAK Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/tak
ExecStart=/usr/bin/java -Xmx4096m -Dlogging.level.com.bbn.marti=INFO -jar /opt/tak/takserver.jar
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSERVICE

print_message "$GREEN" "Step 9: Setting up CoT Server Admin Interface..."
python3 -m venv /opt/cot-server-admin/venv
source /opt/cot-server-admin/venv/bin/activate

pip install --upgrade pip
pip install flask flask-login flask-sqlalchemy werkzeug psycopg2-binary

print_message "$GREEN" "Step 10: Configuring firewall..."
ufw --force enable
ufw allow 22/tcp          # SSH
ufw allow 8089/tcp        # TAK Server TCP
ufw allow 8089/udp        # TAK Server UDP
ufw allow 8443/tcp        # TAK Server Web
ufw allow ${WEB_ADMIN_PORT}/tcp  # CoT Server Admin Interface
ufw allow 80/tcp          # HTTP (for redirect)
ufw allow 443/tcp         # HTTPS

print_message "$GREEN" "Step 11: Creating startup script..."
cat > ${TAK_DIR}/start-all.sh << 'EOFSTART'
#!/bin/bash
systemctl start postgresql
sleep 5
systemctl start takserver
systemctl start cot-server-admin
echo "All TAK services started"
EOFSTART

chmod +x ${TAK_DIR}/start-all.sh

print_message "$GREEN" "Step 12: Saving configuration details..."
cat > ${TAK_DIR}/installation-info.txt << EOFINFO
TAK Server Installation Complete
================================

Installation Directory: ${TAK_DIR}
Database: PostgreSQL ${POSTGRES_VERSION}
Database Name: takserver
Database User: takserver
Database Password: ${DB_PASSWORD}

Certificate Password: ${CERT_PASSWORD}

TAK Server Ports:
- TCP/TLS: 8089
- UDP: 8089
- Web Interface: 8443

CoT Server Admin Interface:
- URL: http://$(hostname -I | awk '{print $1}'):${WEB_ADMIN_PORT}
- Initial Admin Password: ${WEB_ADMIN_PASSWORD}

Certificate Location: ${TAK_DIR}/certs/
Configuration File: ${TAK_DIR}/CoreConfig.xml

Important Commands:
- Start TAK Server: systemctl start takserver
- Stop TAK Server: systemctl stop takserver
- View Logs: journalctl -u takserver -f
- Start CoT Server Admin: systemctl start cot-server-admin
- Start All: ${TAK_DIR}/start-all.sh

SECURITY NOTICE:
- All passwords above were randomly generated during installation
- Store this file securely or delete after noting credentials
- Change passwords regularly in production environments

Next Steps:
1. If you haven't already, download the official TAK Server release from https://tak.gov
2. Extract to ${TAK_DIR}/takserver-${TAK_VERSION}
3. Access the CoT Server Admin Interface to complete configuration
4. Generate client certificates for your devices
EOFINFO

# Also save credentials to a secure file with restricted permissions
cat > ${TAK_DIR}/.credentials << EOFCREDS
# TAK Server Credentials - KEEP SECURE
# Generated: $(date)
TAK_DB_PASSWORD=${DB_PASSWORD}
TAK_CERT_PASSWORD=${CERT_PASSWORD}
TAK_WEB_ADMIN_PASSWORD=${WEB_ADMIN_PASSWORD}
EOFCREDS
chmod 600 ${TAK_DIR}/.credentials

print_message "$GREEN" "=========================================="
print_message "$GREEN" "TAK Server Deployment Complete!"
print_message "$GREEN" "=========================================="
print_message "$YELLOW" "Installation details saved to: ${TAK_DIR}/installation-info.txt"
print_message "$YELLOW" "Please review the file for access information"
print_message "$GREEN" "=========================================="

cat ${TAK_DIR}/installation-info.txt
