#!/bin/bash
# SRP Test Script

set -e

BIN="/home/omena0/Github/SRP/build/srp"
TEST_DIR="/tmp/srp_test"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "=== SRP Test Suite ==="
echo

# Test 1: Register users
echo "Test 1: Register users"
$BIN register alice secret123
$BIN register bob password456
echo "✓ Users registered"
echo

# Test 2: Attempt duplicate registration
echo "Test 2: Attempt duplicate registration (should fail)"
$BIN register alice secret123 2>&1 | grep -q "error: user already exists"
echo "✓ Duplicate prevention works"
echo

# Test 3: Check logins file
echo "Test 3: Check logins file"
if grep -q "^alice:" logins.conf && grep -q "^bob:" logins.conf; then
    echo "✓ Logins file contains both users"
fi
echo

# Test 4: Invalid password
echo "Test 4: Invalid password (should fail)"
$BIN deletelogin alice wrongpassword 2>&1 | grep -q "error: invalid password"
echo "✓ Password verification works"
echo

# Test 5: Valid deletion
echo "Test 5: Valid deletion"
$BIN deletelogin alice secret123
echo "✓ User deleted successfully"
echo

# Test 6: Verify deletion
echo "Test 6: Verify deletion"
if ! grep -q "^alice:" logins.conf 2>/dev/null; then
    echo "✓ User removed from logins file"
fi
echo

# Test 7: Create config files
echo "Test 7: Create server config"
cat > srps.conf << 'EOF'
host=127.0.0.1:6969
min_port=20000
max_port=21000
ports_per_login=10
logins_per_ip=3
restricted_ports=20022,20080,20443
EOF
echo "✓ Server config created"
echo

# Test 8: Test serve command
echo "Test 8: Test serve command"
$BIN serve | grep -q "Loaded logins"
echo "✓ Serve command works"
echo

# Test 9: Test claim port validation
echo "Test 9: Test claim port validation"
$BIN claim 19999 2>&1 | grep -q "error: port out of range"
echo "✓ Port range validation works"
echo

# Test 10: Test restricted port check
echo "Test 10: Test restricted port check"
$BIN claim 20022 2>&1 | grep -q "error: port is restricted"
echo "✓ Restricted port check works"
echo

echo "=== All Tests Passed ==="
