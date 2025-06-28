from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            print("    Protocol: TCP")
        elif packet.haslayer(UDP):
            print("    Protocol: UDP")

sniff(prn=packet_callback, count=10)

