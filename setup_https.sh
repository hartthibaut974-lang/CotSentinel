#!/bin/bash

################################################################################
# TAK Server Web Admin - HTTPS Setup Script
# Configures nginx reverse proxy with SSL/TLS
#
# Copyright 2024 BlackDot Technology
# Licensed under the Apache License, Version 2.0
################################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}==>${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

print_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

# Configuration
TAK_DIR="/opt/tak"
CERTS_DIR="${TAK_DIR}/certs"
NGINX_CONF="/etc/nginx/sites-available/tak-admin"
NGINX_ENABLED="/etc/nginx/sites-enabled/tak-admin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       TAK Server Web Admin - HTTPS Setup                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Detect hostname/IP
DETECTED_IP=$(hostname -I | awk '{print $1}')
DETECTED_HOSTNAME=$(hostname -f 2>/dev/null || hostname)

print_message "Detected IP: ${DETECTED_IP}"
print_message "Detected Hostname: ${DETECTED_HOSTNAME}"
echo ""

# Ask for certificate type
echo "Select SSL certificate type:"
echo "  1) Self-signed certificate (recommended for internal/testing)"
echo "  2) Let's Encrypt (requires public domain and port 80 access)"
echo "  3) Use existing certificate"
echo ""
read -p "Enter choice [1-3] (default: 1): " CERT_CHOICE
CERT_CHOICE=${CERT_CHOICE:-1}

case $CERT_CHOICE in
    1)
        print_message "Generating self-signed certificate..."
        
        # Get certificate details
        read -p "Enter server hostname/IP for certificate [${DETECTED_IP}]: " CERT_CN
        CERT_CN=${CERT_CN:-$DETECTED_IP}
        
        read -p "Enter organization name [TAK Server]: " CERT_ORG
        CERT_ORG=${CERT_ORG:-"TAK Server"}
        
        read -p "Certificate validity in days [365]: " CERT_DAYS
        CERT_DAYS=${CERT_DAYS:-365}
        
        # Generate private key
        openssl genrsa -out ${CERTS_DIR}/web-admin.key 4096
        
        # Generate certificate with SAN (Subject Alternative Name)
        cat > /tmp/web-admin-ssl.cnf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = State
L = City
O = ${CERT_ORG}
OU = CoT Server Admin
CN = ${CERT_CN}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CERT_CN}
DNS.2 = localhost
IP.1 = ${DETECTED_IP}
IP.2 = 127.0.0.1
EOF
        
        # Generate self-signed certificate
        openssl req -new -x509 -days ${CERT_DAYS} \
            -key ${CERTS_DIR}/web-admin.key \
            -out ${CERTS_DIR}/web-admin.crt \
            -config /tmp/web-admin-ssl.cnf
        
        rm /tmp/web-admin-ssl.cnf
        
        print_message "Self-signed certificate generated"
        print_warning "Browsers will show a security warning for self-signed certificates"
        print_warning "This is normal for internal/testing deployments"
        ;;
        
    2)
        print_message "Setting up Let's Encrypt..."
        
        # Install certbot if not present
        if ! command -v certbot &> /dev/null; then
            print_message "Installing certbot..."
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        fi
        
        read -p "Enter your domain name (e.g., tak.example.com): " DOMAIN_NAME
        read -p "Enter your email for Let's Encrypt notifications: " LE_EMAIL
        
        if [[ -z "$DOMAIN_NAME" || -z "$LE_EMAIL" ]]; then
            print_error "Domain name and email are required for Let's Encrypt"
            exit 1
        fi
        
        # Create webroot directory
        mkdir -p /var/www/html/.well-known/acme-challenge
        
        # Get certificate
        certbot certonly --webroot -w /var/www/html \
            -d ${DOMAIN_NAME} \
            --email ${LE_EMAIL} \
            --agree-tos \
            --non-interactive
        
        # Create symlinks to Let's Encrypt certs
        ln -sf /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem ${CERTS_DIR}/web-admin.crt
        ln -sf /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem ${CERTS_DIR}/web-admin.key
        
        # Set up auto-renewal
        cat > /etc/cron.d/tak-certbot << EOF
0 0,12 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"
EOF
        
        CERT_CN=${DOMAIN_NAME}
        print_message "Let's Encrypt certificate obtained for ${DOMAIN_NAME}"
        ;;
        
    3)
        print_message "Using existing certificate..."
        
        read -p "Enter path to certificate file (.crt/.pem): " EXISTING_CERT
        read -p "Enter path to private key file (.key): " EXISTING_KEY
        
        if [[ ! -f "$EXISTING_CERT" || ! -f "$EXISTING_KEY" ]]; then
            print_error "Certificate or key file not found"
            exit 1
        fi
        
        cp "$EXISTING_CERT" ${CERTS_DIR}/web-admin.crt
        cp "$EXISTING_KEY" ${CERTS_DIR}/web-admin.key
        
        CERT_CN="custom"
        print_message "Existing certificate copied to ${CERTS_DIR}/"
        ;;
        
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

# Set proper permissions on certificates
chmod 600 ${CERTS_DIR}/web-admin.key
chmod 644 ${CERTS_DIR}/web-admin.crt
chown root:root ${CERTS_DIR}/web-admin.key ${CERTS_DIR}/web-admin.crt

print_message "Configuring nginx..."

# Remove default nginx site if it exists
rm -f /etc/nginx/sites-enabled/default

# Copy nginx configuration
if [[ -f "${SCRIPT_DIR}/nginx-tak-admin.conf" ]]; then
    cp "${SCRIPT_DIR}/nginx-tak-admin.conf" ${NGINX_CONF}
else
    # Inline configuration if file not found
    cat > ${NGINX_CONF} << 'EOFNGINX'
# TAK Server Web Admin - Nginx HTTPS Reverse Proxy Configuration
server {
    listen 80;
    listen [::]:80;
    server_name _;
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    ssl_certificate /opt/tak/certs/web-admin.crt;
    ssl_certificate_key /opt/tak/certs/web-admin.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    access_log /var/log/nginx/tak-admin-access.log;
    error_log /var/log/nginx/tak-admin-error.log;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOFNGINX
fi

# Enable the site
ln -sf ${NGINX_CONF} ${NGINX_ENABLED}

# Test nginx configuration
print_message "Testing nginx configuration..."
nginx -t

if [[ $? -ne 0 ]]; then
    print_error "Nginx configuration test failed!"
    exit 1
fi

# Restart nginx
print_message "Restarting nginx..."
systemctl restart nginx
systemctl enable nginx

# Update firewall
print_message "Updating firewall rules..."
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

# Optionally close port 5000 (Flask direct access)
echo ""
read -p "Block direct access to Flask on port 5000? (recommended) [Y/n]: " BLOCK_5000
BLOCK_5000=${BLOCK_5000:-Y}

if [[ "$BLOCK_5000" =~ ^[Yy]$ ]]; then
    ufw delete allow 5000/tcp >/dev/null 2>&1 || true
    print_message "Port 5000 blocked - access only via HTTPS on port 443"
fi

# Update credentials file with HTTPS URL
if [[ -f "${TAK_DIR}/.credentials" ]]; then
    sed -i '/^WEB_ADMIN_URL=/d' ${TAK_DIR}/.credentials
    echo "WEB_ADMIN_URL=https://${DETECTED_IP}" >> ${TAK_DIR}/.credentials
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              HTTPS Setup Complete!                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "🔒 Your CoT Server Admin is now accessible via HTTPS:"
echo ""
echo "   https://${DETECTED_IP}"
echo ""
if [[ "$CERT_CHOICE" == "1" ]]; then
    echo "⚠️  Self-signed certificate notice:"
    echo "   - Browsers will show a security warning"
    echo "   - Click 'Advanced' → 'Proceed' to continue"
    echo "   - This is normal for internal deployments"
    echo ""
fi
echo "📋 Certificate Information:"
echo "   Certificate: ${CERTS_DIR}/web-admin.crt"
echo "   Private Key: ${CERTS_DIR}/web-admin.key"
echo ""
echo "🔧 Service Commands:"
echo "   Check status:  systemctl status nginx"
echo "   View logs:     tail -f /var/log/nginx/tak-admin-error.log"
echo "   Restart:       systemctl restart nginx"
echo ""
