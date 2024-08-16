from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP

# Initialize a list to store captured packets
packets = []

def packet_handler(packet):
    print(packet.summary())

    # Store the packet for later saving to a file
    packets.append(packet)

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    if TCP in packet:
        tcp = packet[TCP]
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")

        if tcp.dport == 80 or tcp.sport == 80:
            if Raw in packet:
                print(f"HTTP Packet: {packet[Raw].load}")

        elif tcp.dport == 443 or tcp.sport == 443:
            print("HTTPS: Encrypted content")

        elif tcp.dport == 3389 or tcp.sport == 3389:
            print("RDP Packet")

    elif UDP in packet:
        udp = packet[UDP]
        print(f"Source Port: {udp.sport}")
        print(f"Destination Port: {udp.dport}")

def main():
    # Start sniffing and call packet_handler for each captured packet
    sniff(prn=packet_handler, filter="tcp port 80 or tcp port 443 or tcp port 3389", store=False)
    
    # Save the captured packets to a .pcap file
    wrpcap('packets.pcap', packets)
    print("Packets saved to packets.pcap")

if __name__ == "__main__":
    main()
