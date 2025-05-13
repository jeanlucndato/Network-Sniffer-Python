import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

def handle_packet(packet, log):
    timestamp = packet.time
    protocol = "Unknown"
    src_ip = "Unknown"
    dst_ip = "Unknown"
    src_port = "Unknown"
    dst_port = "Unknown"

    if Ether in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"

            log.write(f"[{timestamp:.6f}] ETH: {eth_src} -> {eth_dst}, IP: {src_ip} -> {dst_ip}, Proto: {protocol}, Sport: {src_port}, Dport: {dst_port}\n")
        else:
            log.write(f"[{timestamp:.6f}] ETH: {eth_src} -> {eth_dst}, Protocol Type: {packet[Ether].type}\n")

def main(interface):
    logfile_name = f"network_sniffer_{interface}.log"
    with open(logfile_name, 'w') as logfile:
        print(f"Sniffing all traffic on '{interface}', logging to '{logfile_name}'...")
        try:
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            print("\nSniffing terminated by user.")
        except Exception as e:
            print(f"Error during sniffing: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_sniffer.py <interface>")
        sys.exit(1)
    interface_name = sys.argv[1]
    main(interface_name)