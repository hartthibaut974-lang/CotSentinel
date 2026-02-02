#!/bin/bash

################################################################################
# TAK Server Web Admin - HTTPS Verification Script
# Tests the HTTPS configuration and connectivity
#
# Copyright 2024 BlackDot Technology
# Licensed under the Apache License, Version 2.0
################################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS="${GREEN}✓ PASS${NC}"
FAIL="${RED}✗ FAIL${NC}"
WARN="${YELLOW}⚠ WARN${NC}"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       TAK Server Web Admin - HTTPS Verification            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Test 1: Check nginx is installed
echo -n "1. Nginx installed: "
if command -v nginx &> /dev/null; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL"
    ((TESTS_FAILED++))
fi

# Test 2: Check nginx is running
echo -n "2. Nginx service running: "
if systemctl is-active --quiet nginx; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL - Run: sudo systemctl start nginx"
    ((TESTS_FAILED++))
fi

# Test 3: Check SSL certificate exists
echo -n "3. SSL certificate exists: "
if [[ -f /opt/tak/certs/web-admin.crt ]]; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
    
    # Check certificate expiry
    echo -n "   Certificate expiry: "
    EXPIRY=$(openssl x509 -enddate -noout -in /opt/tak/certs/web-admin.crt 2>/dev/null | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    
    if [[ $DAYS_LEFT -gt 30 ]]; then
        echo -e "${GREEN}${DAYS_LEFT} days remaining${NC}"
    elif [[ $DAYS_LEFT -gt 0 ]]; then
        echo -e "${YELLOW}${DAYS_LEFT} days remaining - consider renewal${NC}"
        ((TESTS_WARNED++))
    else
        echo -e "${RED}EXPIRED${NC}"
        ((TESTS_FAILED++))
    fi
else
    echo -e "$FAIL - Run: sudo ./setup_https.sh"
    ((TESTS_FAILED++))
fi

# Test 4: Check SSL private key exists
echo -n "4. SSL private key exists: "
if [[ -f /opt/tak/certs/web-admin.key ]]; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
    
    # Check key permissions
    echo -n "   Key permissions (should be 600): "
    PERMS=$(stat -c %a /opt/tak/certs/web-admin.key 2>/dev/null)
    if [[ "$PERMS" == "600" ]]; then
        echo -e "$PASS"
        ((TESTS_PASSED++))
    else
        echo -e "$WARN - Currently $PERMS"
        ((TESTS_WARNED++))
    fi
else
    echo -e "$FAIL"
    ((TESTS_FAILED++))
fi

# Test 5: Check nginx configuration
echo -n "5. Nginx configuration valid: "
if nginx -t 2>&1 | grep -q "successful"; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL"
    nginx -t 2>&1 | head -5
    ((TESTS_FAILED++))
fi

# Test 6: Check nginx site enabled
echo -n "6. TAK admin site enabled: "
if [[ -L /etc/nginx/sites-enabled/tak-admin ]]; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL - Symlink missing"
    ((TESTS_FAILED++))
fi

# Test 7: Check Flask app is running
echo -n "7. Flask application running: "
if systemctl is-active --quiet cot-server-admin; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL - Run: sudo systemctl start cot-server-admin"
    ((TESTS_FAILED++))
fi

# Test 8: Check Flask is listening
echo -n "8. Flask listening on port 5000: "
if netstat -tuln 2>/dev/null | grep -q ":5000 " || ss -tuln 2>/dev/null | grep -q ":5000 "; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL"
    ((TESTS_FAILED++))
fi

# Test 9: Check nginx is listening on 443
echo -n "9. Nginx listening on port 443: "
if netstat -tuln 2>/dev/null | grep -q ":443 " || ss -tuln 2>/dev/null | grep -q ":443 "; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL"
    ((TESTS_FAILED++))
fi

# Test 10: Check HTTP redirect works
echo -n "10. HTTP to HTTPS redirect: "
REDIRECT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1/ 2>/dev/null)
if [[ "$REDIRECT" == "301" ]]; then
    echo -e "$PASS"
    ((TESTS_PASSED++))
else
    echo -e "$WARN - Got HTTP $REDIRECT (expected 301)"
    ((TESTS_WARNED++))
fi

# Test 11: Check HTTPS connection works
echo -n "11. HTTPS connection works: "
HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -k https://127.0.0.1/ 2>/dev/null)
if [[ "$HTTPS_CODE" == "200" || "$HTTPS_CODE" == "302" ]]; then
    echo -e "$PASS (HTTP $HTTPS_CODE)"
    ((TESTS_PASSED++))
else
    echo -e "$FAIL - Got HTTP $HTTPS_CODE"
    ((TESTS_FAILED++))
fi

# Test 12: Check health endpoint
echo -n "12. Health endpoint responding: "
HEALTH=$(curl -s -k --max-time 5 https://127.0.0.1/api/health 2>/dev/null)
if echo "$HEALTH" | grep -q '"status"'; then
    STATUS=$(echo "$HEALTH" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    if [[ "$STATUS" == "healthy" ]]; then
        echo -e "$PASS (status: healthy)"
        ((TESTS_PASSED++))
    else
        echo -e "$WARN (status: $STATUS)"
        ((TESTS_WARNED++))
    fi
else
    echo -e "$FAIL - No response"
    ((TESTS_FAILED++))
fi

# Test 13: Verify SSL certificate chain
echo -n "13. SSL certificate verification: "
SSL_VERIFY=$(echo | openssl s_client -connect 127.0.0.1:443 -servername localhost 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
if [[ -n "$SSL_VERIFY" ]]; then
    echo -e "$PASS"
    echo "   $SSL_VERIFY"
    ((TESTS_PASSED++))
else
    echo -e "$WARN - Could not verify (may be self-signed)"
    ((TESTS_WARNED++))
fi

# Test 14: Check firewall rules
echo -n "14. Firewall allows HTTPS (443): "
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "443.*ALLOW"; then
        echo -e "$PASS"
        ((TESTS_PASSED++))
    else
        echo -e "$WARN - Port 443 may not be allowed"
        ((TESTS_WARNED++))
    fi
else
    echo -e "$WARN - UFW not installed"
    ((TESTS_WARNED++))
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Results Summary:"
echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
echo -e "  ${YELLOW}Warnings:${NC} $TESTS_WARNED"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  HTTPS is properly configured and working!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Access your CoT Server Admin at:"
    echo ""
    echo "  🔒 https://${SERVER_IP}"
    echo ""
else
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  Some tests failed. Please review the issues above.${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Troubleshooting commands:"
    echo "  sudo systemctl status nginx"
    echo "  sudo systemctl status cot-server-admin"
    echo "  sudo nginx -t"
    echo "  sudo tail -f /var/log/nginx/tak-admin-error.log"
    echo ""
fi

exit $TESTS_FAILED
