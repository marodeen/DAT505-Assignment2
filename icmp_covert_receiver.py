from scapy.all import *

def extract_covert_data(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        # Extract the payload from the ICMP packet
        covert_data = packet[Raw].load.decode()
        print(f"Received covert message: {covert_data}")
        with open("covert_data_log.txt", "a") as log_file:
            log_file.write(covert_data + "\n")

if __name__ == "__main__":
    print("Listening for ICMP covert messages...")
    sniff(filter="icmp", prn=extract_covert_data)

