#!/bin/bash

################################################################################
# CoT Server Admin Complete Installation Script
# Administration tool for TAK Server - Master installation script
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
RED='\033[0;31m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}==>${NC} $1"
}

print_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║          CoT Server Admin Installation                     ║"
echo "║          Administration Tool for TAK Server                ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

print_message "This script will:"
echo "  1. Install and configure TAK Server"
echo "  2. Set up PostgreSQL database"
echo "  3. Generate SSL certificates"
echo "  4. Install CoT Server Admin (web interface)"
echo "  5. Configure all services"
echo ""

read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

echo ""
print_message "Step 1/2: Deploying TAK Server..."
echo "================================================"
if [ -f "./deploy_tak_server.sh" ]; then
    chmod +x deploy_tak_server.sh
    ./deploy_tak_server.sh
    print_message "✓ TAK Server deployment complete"
else
    print_error "deploy_tak_server.sh not found!"
    exit 1
fi

echo ""
print_message "Step 2/2: Installing CoT Server Admin..."
echo "================================================"
if [ -f "./install_cot_server_admin.sh" ]; then
    chmod +x install_cot_server_admin.sh
    ./install_cot_server_admin.sh
    print_message "✓ CoT Server Admin installation complete"
else
    print_error "install_cot_server_admin.sh not found!"
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║          Installation Complete! 🎉                        ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Get IP address
IP=$(hostname -I | awk '{print $1}')

echo "🌐 Access CoT Server Admin at:"
echo ""
echo "   http://${IP}:5000"
echo ""
echo "📋 Login Credentials:"
echo "   Username: admin"
echo "   Password: See /opt/tak/.credentials file"
echo ""
echo "⚠️  IMPORTANT: Credentials are stored in /opt/tak/.credentials"
echo "   This file was generated with secure random passwords."
echo ""
echo "🔒 RECOMMENDED: Enable HTTPS for secure access:"
echo "   sudo ./setup_https.sh"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo ""
echo "1. Enable HTTPS (strongly recommended):"
echo "   sudo ./setup_https.sh"
echo ""
echo "2. Download TAK Server from https://tak.gov"
echo "   Extract to: /opt/tak/takserver-5.2-RELEASE-27/"
echo ""
echo "3. Review credentials: sudo cat /opt/tak/.credentials"
echo ""
echo "4. Generate client certificates in Web Interface"
echo ""
echo "5. Configure your TAK clients to connect to:"
echo "   Server: ${IP}"
echo "   Port: 8089"
echo ""
echo "📚 For detailed documentation, see README.md"
echo "🚀 For quick start guide, see QUICKSTART.md"
echo ""
echo "📊 View installation details:"
echo "   cat /opt/tak/installation-info.txt"
echo ""
echo "🔍 Verify HTTPS setup:"
echo "   sudo ./verify_https.sh"
echo ""

print_message "CoT Server Admin ready! 🛰️"
echo ""
