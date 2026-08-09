import socket
import json
from scapy.all import ARP, Ether, srp, conf, get_if_addr

def get_local_subnet():
    """Detects the local IP and assumes a /24 subnet for scanning."""
    try:
        # Get the IP address associated with the default interface
        local_ip = get_if_addr(conf.iface)
        # Assuming a /24 subnet which is standard for most local networks (e.g., 192.168.1.0/24)
        subnet = local_ip.rsplit('.', 1)[0] + '.0/24'
        return subnet
    except Exception as e:
        print(f"Failed to auto-detect subnet: {e}")
        # Fallback to a very common default
        return "192.168.1.0/24"

def scan_network(target_ip):
    """Sends ARP requests to the target IP/subnet and returns active devices."""
    print(f"Scanning local network on {target_ip}...")
    
    # 1. Create ARP packet asking for the target IP
    arp = ARP(pdst=target_ip)
    
    # 2. Create the Ethernet broadcast packet (ff:ff:ff:ff:ff:ff)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Stack the packets
    packet = ether/arp
    
    # 4. Send packets and receive answers
    # timeout=3: Wait 3 seconds for responses
    # verbose=False: Don't print scapy's default output
    result = srp(packet, timeout=3, verbose=False)[0]

    clients = []
    for sent, received in result:
        # For each response, extract the IP and MAC address
        clients.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'type': 'Discovered Device',
            'status': 'Online'
        })

    return clients

if __name__ == "__main__":
    # Detect the subnet to scan
    subnet_to_scan = get_local_subnet()
    
    # Perform the ARP scan
    discovered_devices = scan_network(subnet_to_scan)
    
    # Format and print the result as JSON
    print("\n--- Scan Results ---")
    json_output = json.dumps(discovered_devices, indent=4)
    print(json_output)
