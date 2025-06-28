import matplotlib.pyplot as plt
import networkx as nx
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw

# Initialize directed graph
G = nx.DiGraph()

def packet_callback(packet):
    # Print packet details
    print("=" * 40)
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"[Ethernet] {eth.src} -> {eth.dst}")
    
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"[IP] {ip.src} -> {ip.dst}")
        src = ip.src
        dst = ip.dst
        
        # Add edge with protocol information
        protocol = ""
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"
        
        # Update graph
        if G.has_edge(src, dst):
            G[src][dst]['weight'] += 1
            G[src][dst]['protocols'].add(protocol)
        else:
            G.add_edge(src, dst, weight=1, protocols={protocol})

# Capture packets and build graph
sniff(prn=packet_callback, count=10)

# Prepare edge labels with protocol information
edge_labels = {}
for u, v, d in G.edges(data=True):
    protocols = '/'.join(d['protocols'])
    edge_labels[(u, v)] = f"{d['weight']} pkts ({protocols})"

# Draw graph with improved layout
plt.figure(figsize=(12, 8))
pos = nx.spring_layout(G, k=0.5, iterations=50)
nx.draw_networkx_nodes(G, pos, node_size=3000, node_color='skyblue', alpha=0.9)
nx.draw_networkx_edges(G, pos, width=2, edge_color='gray', arrowsize=25)
nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=9)

plt.title("Packet Flow Graph (Tarrific Visualization)", fontsize=14)
plt.axis('off')
plt.tight_layout()
plt.show()

