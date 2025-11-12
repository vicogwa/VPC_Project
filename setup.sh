#!/bin/bash
# Initial environment setup script

echo "=== VPC Project Setup ==="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "ERROR: This project requires Linux (use WSL2 on Windows)"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Update package list
echo "Updating package list..."
apt update

# Install required packages
echo "Installing required networking tools..."
apt install -y iproute2 iptables bridge-utils net-tools python3 curl netcat-openbsd

# Verify installations
echo ""
echo "Verifying installations..."

command -v ip >/dev/null 2>&1 || { echo "ERROR: ip command not found"; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "ERROR: iptables not found"; exit 1; }
command -v brctl >/dev/null 2>&1 || { echo "ERROR: brctl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }

echo "✓ All tools installed successfully"

# Make scripts executable
echo ""
echo "Making scripts executable..."
chmod +x vpcctl.py
chmod +x cleanup.sh
chmod +x test_vpc.sh

# Initialize config files
echo ""
echo "Initializing configuration files..."
if [ ! -f vpc_config.json ]; then
    echo '{"vpcs": {}, "peerings": []}' > vpc_config.json
    echo "✓ Created vpc_config.json"
fi

if [ ! -f security_groups.json ]; then
    echo '{}' > security_groups.json
    echo "✓ Created security_groups.json"
fi

# Enable IP forwarding
echo ""
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo ""
echo "=== Setup Complete ==="
echo ""
echo "You can now use the vpcctl tool:"
echo "  sudo python3 vpcctl.py create-vpc --name vpc1 --cidr 10.0.0.0/16"
echo ""
echo "Run tests with:"
echo "  sudo ./test_vpc.sh"
echo ""
echo "Clean up with:"
echo "  sudo ./cleanup.sh"
