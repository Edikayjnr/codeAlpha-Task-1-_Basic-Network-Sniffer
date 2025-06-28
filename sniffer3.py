from scapy.all import sniff, Ether, IP, TCP, UDP, Raw

def packet_callback(packet):
    print("="*40)
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"[Ethernet] {eth.src} -> {eth.dst}")
    
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"[IP] {ip.src} -> {ip.dst}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"[TCP] Port {tcp.sport} -> {tcp.dport}")
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"[UDP] Port {udp.sport} -> {udp.dport}")

    if packet.haslayer(Raw):
        print(f"[Payload] {packet[Raw].load}")

sniff(prn=packet_callback, count=10)

