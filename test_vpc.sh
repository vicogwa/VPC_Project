#!/bin/bash
# Automated VPC testing script

set -e

echo "==================================="
echo "VPC Testing Suite"
echo "==================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
PASS=0
FAIL=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((FAIL++))
    fi
}

echo ""
echo "=== Test 1: VPC Creation ==="
sudo python3 vpcctl.py create-vpc --name vpc1 --cidr 10.0.0.0/16
sudo python3 vpcctl.py create-vpc --name vpc2 --cidr 10.1.0.0/16
test_result $? "Create two VPCs"

echo ""
echo "=== Test 2: Subnet Creation ==="
sudo python3 vpcctl.py add-subnet --vpc vpc1 --name public-1 --cidr 10.0.1.0/24 --type public
sudo python3 vpcctl.py add-subnet --vpc vpc1 --name private-1 --cidr 10.0.2.0/24 --type private
sudo python3 vpcctl.py add-subnet --vpc vpc2 --name public-2 --cidr 10.1.1.0/24 --type public
test_result $? "Create subnets in both VPCs"

echo ""
echo "=== Test 3: NAT Gateway Setup ==="
# Detect internet interface
INET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Using interface: $INET_IFACE"
sudo python3 vpcctl.py setup-nat --vpc vpc1 --interface $INET_IFACE
test_result $? "Setup NAT for vpc1"

echo ""
echo "=== Test 4: Communication within same VPC ==="
sudo ip netns exec public-1 ping -c 3 10.0.2.2 > /dev/null 2>&1
test_result $? "Ping from public-1 to private-1 (same VPC)"

echo ""
echo "=== Test 5: Internet access from public subnet ==="
sudo ip netns exec public-1 ping -c 3 8.8.8.8 > /dev/null 2>&1
test_result $? "Public subnet has internet access"

echo ""
echo "=== Test 6: Internet access from private subnet (should fail) ==="
sudo ip netns exec private-1 ping -c 2 -W 2 8.8.8.8 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    test_result 0 "Private subnet blocked from internet"
else
    test_result 1 "Private subnet
test_result 1 "Private subnet should NOT have internet access"
fi

echo ""
echo "=== Test 7: VPC Isolation (should fail without peering) ==="
sudo ip netns exec public-1 ping -c 2 -W 2 10.1.1.2 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    test_result 0 "VPCs are isolated by default"
else
    test_result 1 "VPCs should be isolated"
fi

echo ""
echo "=== Test 8: VPC Peering ==="
sudo python3 vpcctl.py peer-vpcs --vpc1 vpc1 --vpc2 vpc2
test_result $? "Create VPC peering"

echo ""
echo "=== Test 9: Communication after peering ==="
sleep 2
sudo ip netns exec public-1 ping -c 3 10.1.1.2 > /dev/null 2>&1
test_result $? "Ping across VPCs after peering"

echo ""
echo "=== Test 10: Deploy Workloads ==="
sudo python3 vpcctl.py deploy --subnet public-1 --port 8080 > /dev/null 2>&1 &
sleep 2
sudo python3 vpcctl.py deploy --subnet private-1 --port 8081 > /dev/null 2>&1 &
sleep 2
test_result $? "Deploy web servers in subnets"

echo ""
echo "=== Test 11: Workload Connectivity within VPC ==="
sudo ip netns exec public-1 curl -s http://10.0.2.2:8081 > /dev/null 2>&1
test_result $? "Access private subnet workload from public subnet"

echo ""
echo "=== Test 12: Security Groups ==="
# Create security group that allows HTTP but blocks SSH
sudo python3 vpcctl.py create-sg --subnet private-1 --rules '[{"port":8081,"protocol":"tcp","action":"allow"},{"port":22,"protocol":"tcp","action":"deny"}]'
sudo python3 vpcctl.py apply-sg --subnet private-1
sleep 1

# Test HTTP access (should work)
sudo ip netns exec public-1 curl -s http://10.0.2.2:8081 > /dev/null 2>&1
HTTP_RESULT=$?

# Test SSH access (should fail)
sudo ip netns exec public-1 timeout 2 nc -zv 10.0.2.2 22 > /dev/null 2>&1
SSH_RESULT=$?

if [ $HTTP_RESULT -eq 0 ] && [ $SSH_RESULT -ne 0 ]; then
    test_result 0 "Security group enforced (HTTP allowed, SSH blocked)"
else
    test_result 1 "Security group enforcement failed"
fi

echo ""
echo "=== Test 13: List VPCs ==="
sudo python3 vpcctl.py list
test_result $? "List all VPCs and subnets"

echo ""
echo "==================================="
echo "Test Summary"
echo "==================================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo "==================================="

# Cleanup prompt
echo ""
read -p "Run cleanup? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./cleanup.sh
fi
