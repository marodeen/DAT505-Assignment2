from scapy.all import *

def send_covert_icmp(target_ip, message):
    payload = message.encode()
    
    packet = IP(dst=target_ip) / ICMP(type=8) / Raw(load=payload)
    send(packet, verbose=False)
    print(f"Sent ICMP covert message to {target_ip}")

if __name__ == "__main__":
    target_ip = "192.168.0.124"
    message = "Covert Channel Using ICMP"
    send_covert_icmp(target_ip, message)

