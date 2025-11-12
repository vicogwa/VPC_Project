#!/usr/bin/env python3
"""
VPC Control Tool - Build Your Own VPC on Linux
Manages virtual private clouds using Linux networking primitives
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime
import os

CONFIG_FILE = "vpc_config.json"
SG_FILE = "security_groups.json"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log(action, resource, status="SUCCESS"):
    """Log all operations with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {action}: {resource} - {status}")

def run_command(cmd, check=True, capture=False):
    """Execute shell command with error handling"""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, check=check, 
                                  capture_output=True, text=True)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=check)
            return True
    except subprocess.CalledProcessError as e:
        log("ERROR", cmd, f"FAILED: {e}")
        return False

def load_config():
    """Load VPC configuration from JSON file"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {"vpcs": {}, "peerings": []}

def save_config(config):
    """Save VPC configuration to JSON file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def load_security_groups():
    """Load security group policies"""
    if os.path.exists(SG_FILE):
        with open(SG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_security_groups(sg_config):
    """Save security group policies"""
    with open(SG_FILE, 'w') as f:
        json.dump(sg_config, f, indent=2)

def resource_exists(resource_type, name):
    """Check if network resource exists"""
    if resource_type == "bridge":
        result = run_command(f"ip link show {name}", check=False, capture=True)
        return bool(result)
    elif resource_type == "namespace":
        result = run_command(f"ip netns list | grep -w {name}", check=False, capture=True)
        return bool(result)
    return False

# ============================================================================
# PART 1: CORE VPC CREATION
# ============================================================================

def create_vpc(vpc_name, cidr_block):
    """
    Create a new VPC with specified CIDR range
    
    Process:
    1. Check if VPC already exists (idempotency)
    2. Create Linux bridge as VPC router
    3. Add iptables rules to block cross-VPC traffic by default
    4. Store metadata in config file
    """
    config = load_config()
    
    # Idempotency check
    if vpc_name in config["vpcs"]:
        log("CREATE VPC", vpc_name, "ALREADY EXISTS")
        return
    
    bridge_name = f"vpc-{vpc_name}"
    
    # Check if bridge already exists at system level
    if resource_exists("bridge", bridge_name):
        log("CREATE VPC", vpc_name, "BRIDGE ALREADY EXISTS")
        return
    
    # Create bridge (NO IP assigned yet - will be done per subnet)
    run_command(f"ip link add name {bridge_name} type bridge")
    run_command(f"ip link set {bridge_name} up")
    
    # Add isolation rules: Block traffic between this VPC and all other VPCs
    for existing_vpc_name, existing_vpc in config["vpcs"].items():
        existing_bridge = existing_vpc["bridge"]
        
        # Block traffic from new VPC to existing VPC
        run_command(f"iptables -I FORWARD -i {bridge_name} -o {existing_bridge} -j DROP")
        run_command(f"iptables -I FORWARD -i {existing_bridge} -o {bridge_name} -j DROP")
        
        log("VPC ISOLATION", f"{vpc_name} ↔ {existing_vpc_name} blocked")
    
    # Store in config
    config["vpcs"][vpc_name] = {
        "cidr": cidr_block,
        "bridge": bridge_name,
        "bridge_ips": {},
        "subnets": {},
        "nat_gateway": None,
        "workloads": {}
    }
    save_config(config)
    
    log("CREATE VPC", f"{vpc_name} ({cidr_block})")
    print(f"  Bridge: {bridge_name}")

def add_subnet(vpc_name, subnet_name, subnet_cidr, subnet_type):
    """
    Add a subnet to existing VPC
    
    Process:
    1. Create network namespace (isolated network stack)
    2. Assign gateway IP to bridge for this subnet
    3. Create veth pair (virtual ethernet cable)
    4. Move one end to namespace, attach other to bridge
    5. Assign IP address to namespace interface
    6. Configure default route via bridge gateway
    """
    config = load_config()
    
    if vpc_name not in config["vpcs"]:
        log("ADD SUBNET", subnet_name, "VPC NOT FOUND")
        return
    
    # Idempotency check
    if subnet_name in config["vpcs"][vpc_name]["subnets"]:
        log("ADD SUBNET", subnet_name, "ALREADY EXISTS")
        return
    
    vpc = config["vpcs"][vpc_name]
    bridge_name = vpc["bridge"]
    
    # Calculate IPs for this subnet
    import ipaddress
    network = ipaddress.ip_network(subnet_cidr, strict=False)
    hosts = list(network.hosts())
    
    gateway_ip = str(hosts[0])      # First IP = gateway (e.g., 10.0.1.1)
    subnet_ip = str(hosts[1])       # Second IP = namespace (e.g., 10.0.1.2)
    
    # Assign gateway IP to bridge for this subnet
    run_command(f"ip addr add {gateway_ip}/24 dev {bridge_name}")
    
    # Use GLOBAL counter across ALL VPCs for unique interface names
    total_subnets = sum(len(v["subnets"]) for v in config["vpcs"].values())
    veth_ns = f"veth{total_subnets}"
    veth_br = f"vbr{total_subnets}"
    
    # Create namespace
    if not resource_exists("namespace", subnet_name):
        run_command(f"ip netns add {subnet_name}")
    
    # Create veth pair
    run_command(f"ip link add {veth_ns} type veth peer name {veth_br}")
    
    # Move one end to namespace
    run_command(f"ip link set {veth_ns} netns {subnet_name}")
    
    # Attach other end to bridge
    run_command(f"ip link set {veth_br} master {bridge_name}")
    run_command(f"ip link set {veth_br} up")
    
    # Configure interface in namespace
    run_command(f"ip netns exec {subnet_name} ip addr add {subnet_ip}/24 dev {veth_ns}")
    run_command(f"ip netns exec {subnet_name} ip link set {veth_ns} up")
    run_command(f"ip netns exec {subnet_name} ip link set lo up")
    
    # Set default route via gateway (now reachable!)
    run_command(f"ip netns exec {subnet_name} ip route add default via {gateway_ip}")
    
    # Store in config
    config["vpcs"][vpc_name]["subnets"][subnet_name] = {
        "cidr": subnet_cidr,
        "type": subnet_type,
        "namespace": subnet_name,
        "ip": subnet_ip,
        "gateway_ip": gateway_ip,
        "veth_pair": [veth_ns, veth_br],
    }
    
    # Store bridge IP for this subnet
    if "bridge_ips" not in config["vpcs"][vpc_name]:
        config["vpcs"][vpc_name]["bridge_ips"] = {}
    config["vpcs"][vpc_name]["bridge_ips"][subnet_name] = gateway_ip
    
    save_config(config)
    
    log("ADD SUBNET", f"{subnet_name} ({subnet_cidr}) to {vpc_name}")
    print(f"  Type: {subnet_type}")
    print(f"  IP: {subnet_ip}")
    print(f"  Gateway: {gateway_ip}")
    print(f"  Interfaces: {veth_ns} <-> {veth_br}")

# ============================================================================
# PART 2: ROUTING AND NAT GATEWAY
# ============================================================================

def setup_nat_gateway(vpc_name, internet_interface):
    """
    Configure NAT for public subnets to access internet
    
    Process:
    1. Enable IP forwarding on host
    2. Add iptables MASQUERADE rule for each public subnet
    3. Allow forwarding between bridge and internet interface
    4. Store NAT configuration
    """
    config = load_config()
    
    if vpc_name not in config["vpcs"]:
        log("SETUP NAT", vpc_name, "VPC NOT FOUND")
        return
    
    vpc = config["vpcs"][vpc_name]
    bridge_name = vpc["bridge"]
    
    # Enable IP forwarding
    run_command("sysctl -w net.ipv4.ip_forward=1")
    
    # Add NAT rules for public subnets only
    public_subnets = []
    for subnet_name, subnet in vpc["subnets"].items():
        if subnet["type"] == "public":
            subnet_cidr = subnet["cidr"]
            public_subnets.append(subnet_cidr)
            
            # Add MASQUERADE rule (NAT)
            run_command(f"iptables -t nat -A POSTROUTING -s {subnet_cidr} -o {internet_interface} -j MASQUERADE")
            log("NAT RULE", f"{subnet_cidr} -> {internet_interface}")
    
    # Allow forwarding between bridge and internet
    run_command(f"iptables -A FORWARD -i {bridge_name} -o {internet_interface} -j ACCEPT")
    run_command(f"iptables -A FORWARD -i {internet_interface} -o {bridge_name} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    
    # Store NAT config
    config["vpcs"][vpc_name]["nat_gateway"] = {
        "interface": internet_interface,
        "public_subnets": public_subnets
    }
    save_config(config)
    
    log("SETUP NAT", f"{vpc_name} via {internet_interface}")
    print(f"  Public subnets with internet: {', '.join(public_subnets)}")

# ============================================================================
# PART 3: VPC ISOLATION & PEERING
# ============================================================================

def create_vpc_peering(vpc1_name, vpc2_name):
    """
    Establish peering connection between two VPCs
    
    Process:
    1. Remove isolation rules between VPCs
    2. Create veth pair to connect the two bridges
    3. Add static routes in all subnets of both VPCs
    4. Add iptables ACCEPT rules for forwarding
    5. Store peering configuration
    """
    config = load_config()
    
    if vpc1_name not in config["vpcs"] or vpc2_name not in config["vpcs"]:
        log("VPC PEERING", f"{vpc1_name} <-> {vpc2_name}", "VPC NOT FOUND")
        return
    
    # Check if peering already exists
    for peering in config["peerings"]:
        if (peering["vpc1"] == vpc1_name and peering["vpc2"] == vpc2_name) or \
           (peering["vpc1"] == vpc2_name and peering["vpc2"] == vpc1_name):
            log("VPC PEERING", f"{vpc1_name} <-> {vpc2_name}", "ALREADY EXISTS")
            return
    
    vpc1 = config["vpcs"][vpc1_name]
    vpc2 = config["vpcs"][vpc2_name]
    
    # Remove isolation rules (DROP rules)
    run_command(f"iptables -D FORWARD -i {vpc1['bridge']} -o {vpc2['bridge']} -j DROP", check=False)
    run_command(f"iptables -D FORWARD -i {vpc2['bridge']} -o {vpc1['bridge']} -j DROP", check=False)
    
    # Shorter names for peering interfaces
    peer_veth1 = f"peer{vpc1_name[:4]}1"
    peer_veth2 = f"peer{vpc2_name[:4]}2"
    
    # Create veth pair
    run_command(f"ip link add {peer_veth1} type veth peer name {peer_veth2}")
    
    # Attach to bridges
    run_command(f"ip link set {peer_veth1} master {vpc1['bridge']}")
    run_command(f"ip link set {peer_veth2} master {vpc2['bridge']}")
    run_command(f"ip link set {peer_veth1} up")
    run_command(f"ip link set {peer_veth2} up")
    
    # Add routes in VPC1 subnets to reach VPC2
    for subnet_name, subnet_info in vpc1["subnets"].items():
        gateway_ip = subnet_info["gateway_ip"]
        run_command(f"ip netns exec {subnet_name} ip route add {vpc2['cidr']} via {gateway_ip}")
    
    # Add routes in VPC2 subnets to reach VPC1
    for subnet_name, subnet_info in vpc2["subnets"].items():
        gateway_ip = subnet_info["gateway_ip"]
        run_command(f"ip netns exec {subnet_name} ip route add {vpc1['cidr']} via {gateway_ip}")
    
    # Add ACCEPT forwarding rules
    run_command(f"iptables -A FORWARD -i {vpc1['bridge']} -o {vpc2['bridge']} -j ACCEPT")
    run_command(f"iptables -A FORWARD -i {vpc2['bridge']} -o {vpc1['bridge']} -j ACCEPT")
    
    # Store peering
    config["peerings"].append({
        "vpc1": vpc1_name,
        "vpc2": vpc2_name,
        "veth_pair": [peer_veth1, peer_veth2]
    })
    save_config(config)
    
    log("VPC PEERING", f"{vpc1_name} <-> {vpc2_name}")
    print(f"  {vpc1_name} ({vpc1['cidr']}) can now reach {vpc2_name} ({vpc2['cidr']})")

def deploy_workload(subnet_name, port=8080):
    """
    Deploy Python HTTP server in subnet namespace
    
    Process:
    1. Start Python's built-in HTTP server in background
    2. Capture process ID for cleanup
    3. Store workload information
    4. Return access URL
    """
    config = load_config()
    
    # Find subnet in any VPC
    subnet_info = None
    vpc_name = None
    for vname, vpc in config["vpcs"].items():
        if subnet_name in vpc["subnets"]:
            subnet_info = vpc["subnets"][subnet_name]
            vpc_name = vname
            break
    
    if not subnet_info:
        log("DEPLOY WORKLOAD", subnet_name, "SUBNET NOT FOUND")
        return
    
    # Start HTTP server in background
    cmd = f"ip netns exec {subnet_name} python3 -m http.server {port} > /dev/null 2>&1 &"
    run_command(cmd)
    
    # Get PID
    import time
    time.sleep(1)  # Give server time to start
    pid_cmd = f"ps aux | grep 'netns exec {subnet_name}' | grep http.server | grep -v grep | awk '{{print $2}}' | head -1"
    pid = run_command(pid_cmd, capture=True)
    
    # Store workload info
    config["vpcs"][vpc_name]["workloads"][subnet_name] = {
        "port": port,
        "pid": pid if pid else "unknown",
        "ip": subnet_info["ip"]
    }
    save_config(config)
    
    log("DEPLOY WORKLOAD", f"{subnet_name} on port {port}")
    print(f"  Access URL: http://{subnet_info['ip']}:{port}")
    print(f"  From subnet: sudo ip netns exec {subnet_name} curl http://{subnet_info['ip']}:{port}")

# ============================================================================
# PART 4: FIREWALL & SECURITY GROUPS
# ============================================================================

def create_security_group(subnet_name, ingress_rules):
    """
    Create security group policy for subnet
    
    Process:
    1. Find subnet in configuration
    2. Create policy with ingress rules
    3. Store in security_groups.json
    """
    sg_config = load_security_groups()
    
    config = load_config()
    subnet_info = None
    for vpc in config["vpcs"].values():
        if subnet_name in vpc["subnets"]:
            subnet_info = vpc["subnets"][subnet_name]
            break
    
    if not subnet_info:
        log("CREATE SG", subnet_name, "SUBNET NOT FOUND")
        return
    
    sg_config[subnet_name] = {
        "subnet": subnet_info["cidr"],
        "ingress": ingress_rules
    }
    
    save_security_groups(sg_config)
    log("CREATE SG", subnet_name)
    print(f"  Rules: {len(ingress_rules)} ingress rules defined")

def apply_security_group(subnet_name, policy_file=None):
    """
    Apply firewall rules to subnet based on JSON policy
    
    Process:
    1. Read policy from security_groups.json
    2. Set default DROP policy in namespace
    3. Apply each ingress rule using iptables
    4. Allow established connections
    """
    if policy_file is None:
        policy_file = SG_FILE
    
    sg_config = load_security_groups()
    
    if subnet_name not in sg_config:
        log("APPLY SG", subnet_name, "NO POLICY FOUND")
        return
    
    policy = sg_config[subnet_name]
    
    # Set default policies (deny all)
    run_command(f"ip netns exec {subnet_name} iptables -P INPUT DROP")
    run_command(f"ip netns exec {subnet_name} iptables -P FORWARD DROP")
    run_command(f"ip netns exec {subnet_name} iptables -P OUTPUT ACCEPT")
    
    # Allow established connections
    run_command(f"ip netns exec {subnet_name} iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    
    # Allow loopback
    run_command(f"ip netns exec {subnet_name} iptables -A INPUT -i lo -j ACCEPT")
    
    # Apply ingress rules
    if "ingress" in policy:
        for rule in policy["ingress"]:
            port = rule.get("port")
            protocol = rule.get("protocol", "tcp")
            action = rule.get("action", "allow")
            source = rule.get("source", "0.0.0.0/0")
            
            target = "ACCEPT" if action == "allow" else "DROP"
            
            if port:
                cmd = f"ip netns exec {subnet_name} iptables -A INPUT -p {protocol} --dport {port} -s {source} -j {target}"
            else:
                cmd = f"ip netns exec {subnet_name} iptables -A INPUT -s {source} -j {target}"
            
            run_command(cmd)
            log("FIREWALL RULE", f"{subnet_name}: {action} {protocol}/{port} from {source}")
    
    log("APPLY SG", subnet_name)
    print(f"  Applied {len(policy.get('ingress', []))} rules")

# ============================================================================
# PART 5: CLEANUP & AUTOMATION
# ============================================================================

def delete_vpc(vpc_name):
    """
    Delete entire VPC and all resources
    
    Process:
    1. Stop all workloads (kill processes)
    2. Delete all subnets (namespaces)
    3. Remove peering connections
    4. Clean iptables rules
    5. Delete bridge interface
    6. Update configuration
    """
    config = load_config()
    
    if vpc_name not in config["vpcs"]:
        log("DELETE VPC", vpc_name, "NOT FOUND")
        return
    
    vpc = config["vpcs"][vpc_name]
    bridge_name = vpc["bridge"]
    
    # Stop workloads
    for subnet_name, workload in vpc.get("workloads", {}).items():
        pid = workload.get("pid")
        if pid and pid != "unknown":
            run_command(f"kill {pid}", check=False)
            log("STOP WORKLOAD", f"{subnet_name} (PID: {pid})")
    
    # Delete subnets (namespaces)
    for subnet_name in vpc["subnets"]:
        if resource_exists("namespace", subnet_name):
            run_command(f"ip netns del {subnet_name}")
            log("DELETE NAMESPACE", subnet_name)
    
    # Remove peering connections
    peerings_to_remove = []
    for i, peering in enumerate(config["peerings"]):
        if peering["vpc1"] == vpc_name or peering["vpc2"] == vpc_name:
            veth1, veth2 = peering["veth_pair"]
            run_command(f"ip link del {veth1}", check=False)
            log("DELETE PEERING", f"{peering['vpc1']} <-> {peering['vpc2']}")
            peerings_to_remove.append(i)
    
    for i in reversed(peerings_to_remove):
        config["peerings"].pop(i)
    
    # Clean iptables NAT rules
    if vpc.get("nat_gateway"):
        for subnet_cidr in vpc["nat_gateway"].get("public_subnets", []):
            interface = vpc["nat_gateway"]["interface"]
            run_command(f"iptables -t nat -D POSTROUTING -s {subnet_cidr} -o {interface} -j MASQUERADE", check=False)
    
    # Clean forwarding rules
    run_command(f"iptables -D FORWARD -i {bridge_name} -j ACCEPT", check=False)
    
    # Remove isolation rules with all other VPCs
    for other_vpc_name, other_vpc in config["vpcs"].items():
        if other_vpc_name != vpc_name:
            other_bridge = other_vpc["bridge"]
            run_command(f"iptables -D FORWARD -i {bridge_name} -o {other_bridge} -j DROP", check=False)
            run_command(f"iptables -D FORWARD -i {other_bridge} -o {bridge_name} -j DROP", check=False)
    
    # Delete bridge
    run_command(f"ip link set {bridge_name} down", check=False)
    run_command(f"ip link del {bridge_name}", check=False)
    log("DELETE BRIDGE", bridge_name)
    
    # Remove from config
    del config["vpcs"][vpc_name]
    save_config(config)
    
    log("DELETE VPC", vpc_name)

def list_vpcs():
    """List all VPCs and their subnets"""
    config = load_config()
    
    if not config["vpcs"]:
        print("No VPCs found")
        return
    
    print("\n=== VPC List ===")
    for vpc_name, vpc in config["vpcs"].items():
        print(f"\nVPC: {vpc_name}")
        print(f"  CIDR: {vpc['cidr']}")
        print(f"  Bridge: {vpc['bridge']}")
        print(f"  Subnets:")
        for subnet_name, subnet in vpc["subnets"].items():
            print(f"    - {subnet_name} ({subnet['cidr']}) [{subnet['type']}]")
            print(f"      IP: {subnet['ip']}, Gateway: {subnet['gateway_ip']}")
        if vpc.get("nat_gateway"):
            print(f"  NAT Gateway: {vpc['nat_gateway']['interface']}")
        if vpc.get("workloads"):
            print(f"  Workloads:")
            for wl_name, wl in vpc["workloads"].items():
                print(f"    - {wl_name}: http://{wl.get('ip', 'N/A')}:{wl['port']}")
    
    if config["peerings"]:
        print("\n=== VPC Peerings ===")
        for peering in config["peerings"]:
            print(f"  {peering['vpc1']} <-> {peering['vpc2']}")

# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='VPC Control Tool - Manage Virtual Private Clouds on Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create VPC:       sudo python3 vpcctl.py create-vpc --name vpc1 --cidr 10.0.0.0/16
  Add subnet:       sudo python3 vpcctl.py add-subnet --vpc vpc1 --name public-1 --cidr 10.0.1.0/24 --type public
  Setup NAT:        sudo python3 vpcctl.py setup-nat --vpc vpc1 --interface eth0
  Deploy workload:  sudo python3 vpcctl.py deploy --subnet public-1 --port 8080
  List VPCs:        sudo python3 vpcctl.py list
  Delete VPC:       sudo python3 vpcctl.py delete-vpc --name vpc1
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # create-vpc
    create_vpc_parser = subparsers.add_parser('create-vpc', help='Create a new VPC')
    create_vpc_parser.add_argument('--name', required=True, help='VPC name')
    create_vpc_parser.add_argument('--cidr', required=True, help='CIDR block (e.g., 10.0.0.0/16)')
    
    # add-subnet
    add_subnet_parser = subparsers.add_parser('add-subnet', help='Add subnet to VPC')
    add_subnet_parser.add_argument('--vpc', required=True, help='VPC name')
    add_subnet_parser.add_argument('--name', required=True, help='Subnet name')
    add_subnet_parser.add_argument('--cidr', required=True, help='Subnet CIDR')
    add_subnet_parser.add_argument('--type', required=True, choices=['public', 'private'], help='Subnet type')
    
    # setup-nat
    setup_nat_parser = subparsers.add_parser('setup-nat', help='Setup NAT gateway')
    setup_nat_parser.add_argument('--vpc', required=True, help='VPC name')
    setup_nat_parser.add_argument('--interface', required=True, help='Internet interface (e.g., eth0)')
    
    # peer-vpcs
    peer_parser = subparsers.add_parser('peer-vpcs', help='Create VPC peering')
    peer_parser.add_argument('--vpc1', required=True, help='First VPC')
    peer_parser.add_argument('--vpc2', required=True, help='Second VPC')
    
    # deploy
    deploy_parser = subparsers.add_parser('deploy', help='Deploy workload in subnet')
    deploy_parser.add_argument('--subnet', required=True, help='Subnet name')
    deploy_parser.add_argument('--port', type=int, default=8080, help='Port number')
    
    # create-sg
    create_sg_parser = subparsers.add_parser('create-sg', help='Create security group')
    create_sg_parser.add_argument('--subnet', required=True, help='Subnet name')
    create_sg_parser.add_argument('--rules', required=True, help='JSON rules')
    
    # apply-sg
    apply_sg_parser = subparsers.add_parser('apply-sg', help='Apply security group')
    apply_sg_parser.add_argument('--subnet', required=True, help='Subnet name')
    
    # delete-vpc
    delete_vpc_parser = subparsers.add_parser('delete-vpc', help='Delete VPC')
    delete_vpc_parser.add_argument('--name', required=True, help='VPC name')
    
    # list
    list_parser = subparsers.add_parser('list', help='List all VPCs')
    
    args = parser.parse_args()
    
    if args.command == 'create-vpc':
        create_vpc(args.name, args.cidr)
    elif args.command == 'add-subnet':
        add_subnet(args.vpc, args.name, args.cidr, args.type)
    elif args.command == 'setup-nat':
        setup_nat_gateway(args.vpc, args.interface)
    elif args.command == 'peer-vpcs':
        create_vpc_peering(args.vpc1, args.vpc2)
    elif args.command == 'deploy':
        deploy_workload(args.subnet, args.port)
    elif args.command == 'create-sg':
        rules = json.loads(args.rules)
        create_security_group(args.subnet, rules)
    elif args.command == 'apply-sg':
        apply_security_group(args.subnet)
    elif args.command == 'delete-vpc':
        delete_vpc(args.name)
    elif args.command == 'list':
        list_vpcs()
    else:
        parser.print_help()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        sys.exit(1)
    main()
