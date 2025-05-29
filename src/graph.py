import pyshark
import networkx as nx
import matplotlib.pyplot as plt
import nest_asyncio

nest_asyncio.apply()

#Read the pcap file
pcap_file = "../data/capture_output.pcap"
cap = pyshark.FileCapture(pcap_file)

# Extract network relationships
G = nx.DiGraph()  # Directed graph
for packet in cap:
    try:
        if 'IP' in packet:
            src = packet.ip.src
            dst = packet.ip.dst
            proto = packet.highest_layer
            G.add_edge(src, dst, protocol=proto)
    except AttributeError:
        continue

# Visualize the network graph
plt.figure(figsize=(10, 8))
pos = nx.spring_layout(G)  # Layout for the nodes
nx.draw(G, pos, with_labels=True, node_size=700, node_color='lightblue', font_size=10, font_weight='bold')
edge_labels = nx.get_edge_attributes(G, 'protocol')
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='red', font_size=8)
plt.title("Network Diagram from PCAP")
plt.show()``