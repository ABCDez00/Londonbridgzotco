# Londonbridgzotco#
/usr/bin/env python3

from scapy.all import *

# Define the firewall rules
firewall_rules = {
    "allow": [
        {"ip": "192.168.0.1/24", "port": 80},
        {"ip": "192.168.0.1/24", "port": 443}
    ],
    "deny": [
        {"ip": "192.168.0.0/24", "port": 22}
    ]
}

def firewall_packet_handler(packet):
    """
    Handles incoming packets and checks them against the firewall rules.
    """
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    # Check if the packet matches any allow rules
    for rule in firewall_rules["allow"]:
        if src_ip == rule["ip"] and src_port == rule["port"]:
            return True
        if dst_ip == rule["ip"] and dst_port == rule["port"]:
            return True

    # Check if the packet matches any deny rules
    for rule in firewall_rules["deny"]:
        if src_ip == rule["ip"] and src_port == rule["port"]:
            return False
        if dst_ip == rule["ip"] and dst_port == rule["port"]:
            return False

    # If no rules match, allow the packet
    return True

def main():
    """
    Main function to start the firewall.
    """
    try:
        # Start sniffing packets
        sniff(filter="tcp", prn=firewall_packet_handler, store=0)
    except KeyboardInterrupt:
        print("Firewall stopped.")

if __name__ == "__main__":
    main()
