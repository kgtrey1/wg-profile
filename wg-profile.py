#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import re

def get_next_available_ip(config_path, min_ip=101, max_ip=254):
    with open(config_path, 'r') as f:
        config_data = f.read()
    address_pattern = re.compile(r'Address\s*=\s*(\d+\.\d+\.\d+)\.\d+\/\d+')
    address_match = address_pattern.search(config_data)
    if not address_match:
        raise ValueError("Base IP could not be determined from the Address field in the configuration.")
    base_ip = address_match.group(1)  # Extract base IP, e.g., '10.13.37'
    ip_pattern = re.compile(r'AllowedIPs\s*=\s*' + re.escape(base_ip) + r'\.(\d+)')
    assigned_numbers = sorted(int(match) for match in ip_pattern.findall(config_data) if int(match) >= min_ip)
    for ip in range(min_ip, max_ip + 1):
        if ip not in assigned_numbers:
            return f"{base_ip}.{ip}"
    return None

def write_file(path: str, content: str, append: bool = False):
    try:
        with open(path, "a" if append else "w") as file:
            if (append):
                file.write('\n')
            file.write(content + "\n")
        return 0
    except PermissionError:
        print("Permission denied. Run the script as root (sudo).")
    except Exception as e:
        print(f"An error occurred: {e}")
    sys.exit(-1)

def init(ip: str, port: int):
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key.encode()).decode().strip()
    server_conf = '''[Interface]
Address = {0}/24
SaveConfig = true
ListenPort = {1}
PrivateKey = {2}'''.format(ip, port, private_key)
    write_file("/etc/wireguard/private.key", private_key)
    write_file("/etc/wireguard/public.key", public_key)
    write_file("/etc/wireguard/wg0.conf", server_conf)
    os.chmod("/etc/wireguard/private.key", 0o600)
    os.chmod("/etc/wireguard/public.key", 0o640)
    print("WireGuard configuration has been succesfully set.")

def create(allowed_ips: str, endpoint: str, comment):
    cl_private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    cl_public_key = subprocess.check_output(["wg", "pubkey"], input=cl_private_key.encode()).decode().strip()
    sv_public_key = subprocess.check_output(["cat", "/etc/wireguard/public.key"]).decode().strip()
    preshared_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    ip = get_next_available_ip('/etc/wireguard/wg0.conf')


    sv_peer = '''{3}[Peer]
PublicKey = {0}
PresharedKey = {1}
AllowedIPs = {2}'''.format(cl_public_key, preshared_key, f"{ip}/32", f"# {comment}\n"if comment else "")
    write_file('/etc/wireguard/wg0.conf', sv_peer, True)
    client = '''[Interface]
PrivateKey = {0}
Address = {1}
DNS = 1.1.1.1

[Peer]
PublicKey = {2}
PresharedKey = {3}
AllowedIPs = {4}
Endpoint = {5}
PersistentKeepalive = 25'''.format(cl_private_key, ip, sv_public_key, preshared_key, allowed_ips, endpoint)
    print("Client configuration:")
    print(client)

def parse_args():
    parser = argparse.ArgumentParser(description="Manage your WireGuard access without a headache.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")
    init_parser = subparsers.add_parser('init', help="Initialize WireGuard")
    init_parser.add_argument('--ip', type=str, default='10.0.0.1', help="The IP of the WireGuard main server")
    init_parser.add_argument('--port', type=int, default='51820', help="The port of the WireGuard main server")
    create_parser = subparsers.add_parser('create', help="Create a new peer")
    create_parser.add_argument('--allowedIPs', type=str, required=True, help="The IPs the peer will be able to reach.")
    create_parser.add_argument('--endpoint', type=str, required=True, help="Server endpoint in the format ip:port")
    create_parser.add_argument('--comment', type=str, required=False, help="Add a comment above the new peer")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.command == "create":
        create(args.allowedIPs, args.endpoint, args.comment)
    elif args.command == "init":
        init(args.ip, args.port)
