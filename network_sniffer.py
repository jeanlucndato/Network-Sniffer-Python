import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
import time
import os # Pour gérer les chemins de fichiers

# Mappage pour les types Ethernet courants (non exhaustif)
ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86dd: "IPv6",
    0x8847: "MPLS",
    # Ajoutez d'autres si nécessaire
}

def get_ether_type_name(eth_type):
    return ETHER_TYPES.get(eth_type, f"Unknown ({hex(eth_type)})")

def handle_packet(packet, log):
    # Utilisez time.time() pour une précision en secondes flottantes
    timestamp = time.time()
    
    # Initialisation avec des chaînes vides pour une meilleure lisibilité si non applicable
    protocol_name = ""
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    
    eth_src = "N/A"
    eth_dst = "N/A"

    if Ether in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                protocol_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol_name = "ICMP"
            else:
                # Gérer d'autres protocoles IP non couverts
                protocol_name = f"IP Proto: {packet[IP].proto}" # Affiche le numéro de protocole IP

            log.write(f"[{timestamp:.6f}] ETH: {eth_src} -> {eth_dst}, IP: {src_ip} -> {dst_ip}, Proto: {protocol_name}, Sport: {src_port}, Dport: {dst_port}\n")
        else:
            # Paquets Ethernet sans IP (ex: ARP)
            ether_type_val = packet[Ether].type
            ether_type_name = get_ether_type_name(ether_type_val)
            log.write(f"[{timestamp:.6f}] ETH: {eth_src} -> {eth_dst}, Type: {ether_type_name}\n")
    else:
        # Paquets sans couche Ethernet (rare sur des interfaces standard)
        log.write(f"[{timestamp:.6f}] Non-Ethernet Packet: {packet.summary()}\n")


def main(interface):
    # Utiliser un horodatage pour le nom du fichier de log
    current_time_str = time.strftime("%Y%m%d_%H%M%S")
    logfile_name = os.path.join(os.getcwd(), f"network_sniffer_{interface}_{current_time_str}.log") # Place le log dans le répertoire courant

    # Ouvrir le fichier en mode 'a' pour ajouter les nouvelles entrées (s'il existe déjà)
    # ou créer un nouveau fichier si le nom horodaté le garantit
    with open(logfile_name, 'a') as logfile:
        print(f"Sniffing all traffic on '{interface}', logging to '{logfile_name}'...")
        try:
            # prn=lambda pkt: handle_packet(pkt, logfile) est correct
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