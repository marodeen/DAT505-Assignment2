from scapy.all import *
import time
import random

def slow_port_scan(target_ip, port_range):
    for port in port_range:
        # Craft a TCP SYN packet
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=0)
        
        # Check if there's a response
        if response is not None and response.haslayer(TCP):
            # If the SYN-ACK flag is set, the port is open
            if response.getlayer(TCP).flags == 0x12:
                print(f"Port {port} is open.")
            # Send RST to close the connection
            sr(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
        
        # Random delay between each packet to avoid rate-based detection
        time.sleep(random.uniform(1, 5))  # Delay between 1 and 5 seconds

if __name__ == "__main__":
    target_ip = "192.168.0.124"
    port_range = range(20, 30)   # Port range to scan (example: 20-30)
    slow_port_scan(target_ip, port_range)

