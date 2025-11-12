#!/bin/bash
# Complete VPC cleanup script

echo "=== Starting VPC Cleanup ==="

# Check if config file exists
if [ ! -f vpc_config.json ]; then
    echo "No VPC configuration found"
    exit 0
fi

# Read all VPC names from config
VPC_NAMES=$(python3 -c "
import json
with open('vpc_config.json', 'r') as f:
    config = json.load(f)
    print(' '.join(config.get('vpcs', {}).keys()))
")

# Delete each VPC
for vpc in $VPC_NAMES; do
    echo "Deleting VPC: $vpc"
    sudo python3 vpcctl.py delete-vpc --name $vpc
done

# Flush all iptables rules
echo "Flushing iptables rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X

# Delete any remaining namespaces
echo "Cleaning up remaining namespaces..."
sudo ip -all netns delete 2>/dev/null

# Remove config files
echo "Removing configuration files..."
rm -f vpc_config.json security_groups.json

echo "=== Cleanup Complete ==="
