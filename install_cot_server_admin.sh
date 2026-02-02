#!/bin/bash

################################################################################
# CoT Server Admin Installation Script
# Administration tool for TAK Server
#
# Copyright 2024-2025 BlackDot Technology
# Licensed under the Apache License, Version 2.0
#
# DISCLAIMER: This software is not affiliated with the TAK Product Center,
# U.S. Department of Defense, or any government agency.
################################################################################

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}$1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

print_message "Installing CoT Server Admin..."

# Create directory
mkdir -p /opt/cot-server-admin/templates
mkdir -p /opt/cot-server-admin/static/css
mkdir -p /opt/cot-server-admin/static/js

# Copy files
print_message "Copying application files..."
cp cot_server_admin.py /opt/cot-server-admin/
cp *.html /opt/cot-server-admin/templates/

# Set up Python virtual environment
print_message "Setting up Python virtual environment..."
cd /opt/cot-server-admin
python3 -m venv venv
source venv/bin/activate

# Install dependencies
print_message "Installing Python dependencies..."
pip install --upgrade pip
pip install flask flask-login flask-sqlalchemy werkzeug psycopg2-binary qrcode pillow

# Copy systemd service file
print_message "Installing systemd service..."
cp cot-server-admin.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable and start service
systemctl enable cot-server-admin
systemctl start cot-server-admin

# Get IP address
IP=$(hostname -I | awk '{print $1}')

print_message "=========================================="
print_message "CoT Server Admin Installation Complete!"
print_message "=========================================="
echo ""
echo "Access the web interface at: http://${IP}:5000"
echo ""
echo "Login Credentials:"
echo "  Username: admin"
echo "  Password: See /opt/tak/.credentials file"
echo ""
echo "View credentials: sudo cat /opt/tak/.credentials"
echo ""
echo "Service Management:"
echo "  Start:   systemctl start cot-server-admin"
echo "  Stop:    systemctl stop cot-server-admin"
echo "  Status:  systemctl status cot-server-admin"
echo "  Logs:    journalctl -u cot-server-admin -f"
echo ""
print_message "=========================================="
