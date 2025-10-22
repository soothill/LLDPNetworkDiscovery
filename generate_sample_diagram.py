#!/usr/bin/env python3
"""
Generate a sample network topology diagram for documentation
"""

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# Create directed graph
G = nx.Graph()

# Add sample devices
devices = {
    'core-sw-01': 'arista',
    'core-sw-02': 'arista',
    'edge-router': 'mikrotik',
    'access-sw-01': 'aruba',
    'access-sw-02': 'aruba',
    'linux-server-01': 'linux',
    'linux-server-02': 'linux',
    'ruijie-ap-01': 'ruijie',
    'proxmox-host-01': 'proxmox'
}

for device, dtype in devices.items():
    G.add_node(device, device_type=dtype)

# Add sample connections with port info and speeds
connections = [
    ('core-sw-01', 'core-sw-02', 'Eth1', 'Eth1', '10G'),
    ('core-sw-01', 'edge-router', 'Eth48', 'ether1', '10G'),
    ('core-sw-02', 'edge-router', 'Eth48', 'ether2', '10G'),
    ('core-sw-01', 'access-sw-01', 'Eth10', '1/1/1', '10G'),
    ('core-sw-02', 'access-sw-02', 'Eth10', '1/1/1', '10G'),
    ('access-sw-01', 'linux-server-01', '1/1/10', 'ens18', '1G'),
    ('access-sw-01', 'linux-server-02', '1/1/11', 'ens18', '1G'),
    ('access-sw-01', 'ruijie-ap-01', '1/1/5', 'Gi0/1', '1G'),
    ('access-sw-02', 'proxmox-host-01', '1/1/20', 'vmbr0', '10G'),
    ('core-sw-01', 'proxmox-host-01', 'Eth15', 'ens19', '10G'),
]

edge_labels = {}
for local_dev, remote_dev, local_port, remote_port, speed in connections:
    G.add_edge(local_dev, remote_dev)
    edge_key = (local_dev, remote_dev)
    edge_labels[edge_key] = f"{local_port} [{speed}]\n↕\n{remote_port} [{speed}]"

# Create visualization
plt.figure(figsize=(20, 14))

# Use spring layout for better spacing
pos = nx.spring_layout(G, k=3, iterations=50, seed=42)

# Define colors for different device types
color_map = {
    'linux': '#3498db',      # Blue
    'mikrotik': '#e74c3c',   # Red
    'arista': '#2ecc71',     # Green
    'aruba': '#f39c12',      # Orange
    'ruijie': '#9b59b6',     # Purple
    'proxmox': '#1abc9c'     # Turquoise
}

# Get node colors based on device type
node_colors = []
for node in G.nodes():
    device_type = G.nodes[node].get('device_type', 'unknown')
    node_colors.append(color_map.get(device_type, '#95a5a6'))

# Draw nodes
nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                       node_size=4000, alpha=0.9,
                       edgecolors='black', linewidths=3)

# Draw edges with different colors/widths based on speed
edge_colors = []
edge_widths = []
for local_dev, remote_dev, local_port, remote_port, speed in connections:
    if speed == '10G':
        edge_colors.append('#2ecc71')  # Green for 10G
        edge_widths.append(4)
    elif speed == '1G':
        edge_colors.append('#3498db')  # Blue for 1G
        edge_widths.append(2)
    elif speed == '40G':
        edge_colors.append('#f39c12')  # Orange for 40G
        edge_widths.append(5)
    elif speed == '100G':
        edge_colors.append('#e67e22')  # Dark orange for 100G
        edge_widths.append(6)
    elif speed == '400G':
        edge_colors.append('#e74c3c')  # Red for 400G
        edge_widths.append(7)
    else:
        edge_colors.append('#7f8c8d')  # Gray for unknown
        edge_widths.append(2)

# Draw edges with custom colors and widths
for i, (local_dev, remote_dev, _, _, _) in enumerate(connections):
    nx.draw_networkx_edges(G, pos, [(local_dev, remote_dev)],
                           width=edge_widths[i], alpha=0.7,
                           edge_color=[edge_colors[i]])

# Draw labels
nx.draw_networkx_labels(G, pos, font_size=11, font_weight='bold', font_family='sans-serif')

# Draw edge labels (port information)
nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=9,
                              bbox=dict(boxstyle='round,pad=0.4',
                                      facecolor='white', alpha=0.8, edgecolor='gray'))

# Create legend for device types
legend_elements = [
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['linux'],
               markersize=15, label='Linux Server', markeredgecolor='black', markeredgewidth=2),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['mikrotik'],
               markersize=15, label='MikroTik Router', markeredgecolor='black', markeredgewidth=2),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['arista'],
               markersize=15, label='Arista Switch', markeredgecolor='black', markeredgewidth=2),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['aruba'],
               markersize=15, label='HP Aruba Switch', markeredgecolor='black', markeredgewidth=2),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['ruijie'],
               markersize=15, label='Ruijie AP', markeredgecolor='black', markeredgewidth=2),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['proxmox'],
               markersize=15, label='Proxmox Host', markeredgecolor='black', markeredgewidth=2),
]

# Create legend for link speeds
speed_legend_elements = [
    plt.Line2D([0], [1], color='#3498db', linewidth=2, label='1 Gbps'),
    plt.Line2D([0], [1], color='#2ecc71', linewidth=4, label='10 Gbps'),
    plt.Line2D([0], [1], color='#f39c12', linewidth=5, label='40 Gbps'),
    plt.Line2D([0], [1], color='#e67e22', linewidth=6, label='100 Gbps'),
    plt.Line2D([0], [1], color='#e74c3c', linewidth=7, label='400 Gbps'),
]

# Add both legends
first_legend = plt.legend(handles=legend_elements, loc='upper left', fontsize=11,
                          title='Device Types', title_fontsize=12, framealpha=0.9)
plt.gca().add_artist(first_legend)
plt.legend(handles=speed_legend_elements, loc='upper right', fontsize=11,
           title='Link Speeds', title_fontsize=12, framealpha=0.9)

plt.title('LLDP Network Topology Discovery - Sample Output', fontsize=18, fontweight='bold', pad=20)
plt.axis('off')
plt.tight_layout()

# Save to file
output_file = 'sample_network_topology.png'
plt.savefig(output_file, dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
print(f"Sample network topology diagram saved to {output_file}")
