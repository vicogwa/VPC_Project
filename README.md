# VPC_Project
=======
# Build Your Own Virtual Private Cloud (VPC) on Linux

## Overview

This project demonstrates how to build a fully functional Virtual Private Cloud (VPC) using native Linux networking primitives. By leveraging network namespaces, bridges, veth pairs, and iptables, I recreate the fundamental architecture of cloud VPCs like AWS VPC or Azure VNet.

### What I Built

- **Multiple isolated VPCs** with custom CIDR ranges
- **Public and private subnets** with different connectivity rules
- **NAT Gateway** for internet access from public subnets
- **VPC Peering** for controlled inter-VPC communication
- **Security Groups** implemented via iptables
- **Automated CLI tool** (`vpcctl`) for managing all resources

## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         Host System (Linux/WSL2)                │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    VPC 1 (10.0.0.0/16)                    │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │        Bridge: vpc-vpc1 (10.0.0.1) [VPC Router]     │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │            │                              │               │  │
│  │       veth-pair                      veth-pair            │  │
│  │            │                              │               │  │
│  │  ┌──────────────────┐          ┌──────────────────┐       │  │
│  │  │  Public Subnet   │          │  Private Subnet  │       │  │
│  │  │  10.0.1.0/24     │          │  10.0.2.0/24     │       │  │
│  │  │  NS: public-1    │          │  NS: private-1   │       │  │
│  │  │  IP: 10.0.1.2    │────────► │  IP: 10.0.2.2    │       │  │
│  │  │  [Web Server]    │          │  [Database]      │       │  │
│  │  │  ✓ Internet      │          │  ✗ No Internet   │       │  │
│  │  └──────────────────┘          └──────────────────┘       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                    NAT Gateway                                  │
│                  (iptables MASQUERADE)                          │
│                          │                                      │
│                  ┌───────┴────────┐                             │
│                  │  eth0/wlan0    │                             │
│                  │  (Internet)    │                             │
│                  └────────────────┘                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    VPC 2 (10.1.0.0/16)                    │  │
│  │                    [Isolated by Default]                  │  │
│  │                                                           │  │
│  │          VPC Peering via veth pair                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Network Namespaces**: Isolated network stacks (simulate EC2 instances)
2. **Linux Bridges**: Layer 2 virtual switches (VPC routers)
3. **Veth Pairs**: Virtual ethernet cables connecting namespaces to bridges
4. **iptables**: Firewall rules (Security Groups) and NAT
5. **Routing Tables**: Control packet flow between subnets

## Prerequisites

### Windows Users (WSL2)

1. **Install WSL2**:
```powershell
wsl --install
wsl --set-default-version 2
```

2. **Install Ubuntu 22.04**:
   - Open Microsoft Store
   - Search "Ubuntu 22.04"
   - Install and launch

3. **Navigate to project directory**:
```bash
# In WSL terminal
cd /mnt/c/Users/YourName/vpc-project
# OR
cd ~/vpc-project
```

### Linux Users

Ensure you have a Linux kernel 3.8+ with namespace support.

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/vpc-project.git
cd vpc-project
```

### Step 2: Run Setup Script
```bash
sudo ./setup.sh
```

This installs:
- `iproute2` (ip command)
- `iptables` (firewall)
- `bridge-utils` (bridge management)
- `net-tools` (networking utilities)
- `python3` (CLI tool runtime)

## Usage Guide

### Create a VPC
```bash
sudo python3 vpcctl.py create-vpc --name vpc1 --cidr 10.0.0.0/16
```

**What happens:**
1. Creates a Linux bridge named `vpc-vpc1`
2. Assigns IP `10.0.0.1` to the bridge (VPC router)
3. Stores configuration in `vpc_config.json`

### Add Subnets

**Public Subnet** (with internet access):
```bash
sudo python3 vpcctl.py add-subnet \
  --vpc vpc1 \
  --name public-1 \
  --cidr 10.0.1.0/24 \
  --type public
```

**Private Subnet** (internal only):
```bash
sudo python3 vpcctl.py add-subnet \
  --vpc vpc1 \
  --name private-1 \
  --cidr 10.0.2.0/24 \
  --type private
```

**What happens:**
1. Creates network namespace (isolated environment)
2. Creates veth pair (virtual cable)
3. Connects one end to namespace, other to bridge
4. Assigns IP address (10.0.1.2 or 10.0.2.2)
5. Sets default route via bridge IP

### Setup NAT Gateway
```bash
# Find your internet interface
ip route | grep default

# Setup NAT (replace eth0 with your interface)
sudo python3 vpcctl.py setup-nat --vpc vpc1 --interface eth0
```

**What happens:**
1. Enables IP forwarding: `sysctl -w net.ipv4.ip_forward=1`
2. Adds MASQUERADE rule for public subnets
3. Allows forwarding between bridge and internet interface

### Deploy Workloads

**Deploy web server in public subnet:**
```bash
sudo python3 vpcctl.py deploy --subnet public-1 --port 8080
```

**Access from host:**
```bash
curl http://10.0.1.2:8080
```

**Deploy in private subnet:**
```bash
sudo python3 vpcctl.py deploy --subnet private-1 --port 8081
```

### Create Security Groups

**Define rules in JSON:**
```bash
sudo python3 vpcctl.py create-sg --subnet private-1 --rules '[
  {"port": 8081, "protocol": "tcp", "action": "allow", "source": "10.0.1.0/24"},
  {"port": 22, "protocol": "tcp", "action": "deny"}
]'
```

**Apply security group:**
```bash
sudo python3 vpcctl.py apply-sg --subnet private-1
```

**What happens:**
1. Sets default DROP policy in namespace
2. Creates iptables rules for each ingress rule
3. Allows established connections
4. Blocks all other traffic

### Create Multiple VPCs
```bash
# Create second VPC
sudo python3 vpcctl.py create-vpc --name vpc2 --cidr 10.1.0.0/16
sudo python3 vpcctl.py add-subnet --vpc vpc2 --name public-2 --cidr 10.1.1.0/24 --type public
```

**Test isolation:**
```bash
# Try to ping vpc2 from vpc1 (should fail)
sudo ip netns exec public-1 ping 10.1.1.2
```

### VPC Peering

**Establish peering connection:**
```bash
sudo python3 vpcctl.py peer-vpcs --vpc1 vpc1 --vpc2 vpc2
```

**What happens:**
1. Creates veth pair connecting bridges
2. Adds static routes in all namespaces
3. Adds iptables forwarding rules

**Test connectivity:**
```bash
# Now this should work
sudo ip netns exec public-1 ping 10.1.1.2
```

### List All VPCs
```bash
sudo python3 vpcctl.py list
```

Output:
```
=== VPC List ===

VPC: vpc1
  CIDR: 10.0.0.0/16
  Bridge: vpc-vpc1 (10.0.0.1)
  Subnets:
    - public-1 (10.0.1.0/24) [public] IP: 10.0.1.2
    - private-1 (10.0.2.0/24) [private] IP: 10.0.2.2
  NAT Gateway: eth0
  Workloads:
    - public-1: http://10.0.1.2:8080

=== VPC Peerings ===
  vpc1 <-> vpc2
```

### Delete VPC
```bash
sudo python3 vpcctl.py delete-vpc --name vpc1
```

**What happens:**
1. Stops all workloads (kills processes)
2. Deletes all namespaces
3. Removes peering connections
4. Cleans iptables rules
5. Deletes bridge interface
6. Updates configuration files

## Testing & Validation

### Automated Test Suite

Run all tests:
```bash
sudo ./test_vpc.sh
```

### Manual Testing

**Test 1: Communication within same VPC**
```bash
# From public subnet, ping private subnet
sudo ip netns exec public-1 ping -c 3 10.0.2.2
```
Expected: ✓ Success

**Test 2: Internet access from public subnet**
```bash
sudo ip netns exec public-1 ping -c 3 8.8.8.8
```
Expected: ✓ Success

**Test 3: Internet access from private subnet**
```bash
sudo ip netns exec private-1 ping -c 3 8.8.8.8
```
Expected: ✗ Failure (timeout)

**Test 4: VPC isolation**
```bash
# Before peering
sudo ip netns exec public-1 ping -c 2 10.1.1.2
```
Expected: ✗ Failure

**Test 5: VPC communication after peering**
```bash
# After peering
sudo python3 vpcctl.py peer-vpcs --vpc1 vpc1 --vpc2 vpc2
sudo ip netns exec public-1 ping -c 3 10.1.1.2
```
Expected: ✓ Success

**Test 6: Security group enforcement**
```bash
# HTTP allowed
sudo ip netns exec public-1 curl http://10.0.2.2:8081

# SSH blocked
sudo ip netns exec public-1 timeout 2 ssh 10.0.2.2
```
Expected: HTTP works, SSH times out

**Test 7: Workload accessibility**
```bash
# From host machine
curl http://10.0.1.2:8080  # Public subnet - works
curl http://10.0.2.2:8081  # Private subnet - fails
```

## Troubleshooting

### Problem: "Operation not permitted"
**Solution**: Run with sudo:
```bash
sudo python3 vpcctl.py <command>
```

### Problem: Cannot ping 8.8.8.8 from public subnet
**Solution**: Check NAT configuration and internet interface:
```bash
# Verify interface name
ip route | grep default

# Re-setup NAT with correct interface
sudo python3 vpcctl.py setup-nat --vpc vpc1 --interface <your-interface>
```

### Problem: Namespace not found
**Solution**: List namespaces and verify:
```bash
sudo ip netns list
```

### Problem: Bridge already exists
**Solution**: Delete existing bridge:
```bash
sudo ip link delete vpc-vpc1
```

### Problem: iptables rules conflict
**Solution**: Flush rules and restart:
```bash
sudo iptables -F
sudo iptables -t nat -F
```

## Cleanup

### Clean single VPC:
```bash
sudo python3 vpcctl.py delete-vpc --name vpc1
```

### Clean everything:
```bash
sudo ./cleanup.sh
```

This removes:
- All VPCs and subnets
- All network namespaces
- All iptables rules
- All configuration files

## How It Works (Technical Deep Dive)

### Network Namespaces
Linux network namespaces provide isolated network stacks. Each namespace has:
- Its own network interfaces
- Its own routing table
- Its own iptables rules
```bash
# Create namespace
sudo ip netns add ns1

# Execute command in namespace
sudo ip netns exec ns1 ip addr
```

### Veth Pairs
Virtual Ethernet (veth) pairs are like virtual cables with two ends:
```bash
# Create veth pair
sudo ip link add veth0 type veth peer name veth1

# Move one end to namespace
sudo ip link set veth0 netns ns1
```

### Linux Bridges
Bridges are virtual Layer 2 switches that forward packets between interfaces:
```bash
# Create bridge
sudo ip link add br0 type bridge

# Attach interface to bridge
sudo ip link set veth1 master br0
```

### Routing
Each namespace needs a default route to communicate outside:
```bash
# In namespace, set default gateway
sudo ip netns exec ns1 ip route add default via 10.0.0.1
```

### NAT with iptables
Network Address Translation (NAT) allows private IPs to access the internet:
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Add MASQUERADE rule (replaces source IP with host IP)
sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o eth0 -j MASQUERADE
```

### Security Groups
Implemented using iptables in each namespace:
```bash
# Default drop
sudo ip netns exec ns1 iptables -P INPUT DROP

# Allow specific port
sudo ip netns exec ns1 iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

## Project Structure
```
vpc-project/
├── vpcctl.py              # Main CLI tool 
├── vpc_config.json        # VPC state (auto-generated)
├── security_groups.json   # Firewall policies
├── cleanup.sh             # Cleanup automation
├── test_vpc.sh            # Automated tests
├── setup.sh               # Environment setup
└── README.md              # This file
```

## Key Learning Outcomes

1. **Network Isolation**: How cloud providers isolate customer networks
2. **Software-Defined Networking**: Implementing network features in software
3. **Linux Networking Stack**: Deep understanding of namespaces, bridges, veth pairs
4. **Firewall Management**: Implementing security policies with iptables
5. **NAT and Routing**: How packets flow between networks
6. **Infrastructure as Code**: Automating network infrastructure

## Next Steps

- **Add DNS resolution**: Implement custom DNS in namespaces
- **Load Balancing**: Create a simple load balancer between subnets
- **VPN Gateway**: Implement encrypted tunnel to VPC
- **Monitoring**: Add network traffic monitoring and logging
- **Container Integration**: Deploy Docker containers in subnets

## References

- [Linux Network Namespaces](https://man7.org/linux/man-pages/man8/ip-netns.8.html)
- [iptables Documentation](https://netfilter.org/documentation/)
- [Linux Bridge](https://wiki.linuxfoundation.org/networking/bridge)
- [AWS VPC Documentation](https://docs.aws.amazon.com/vpc/)

---

**Happy Learning! 🚀**

