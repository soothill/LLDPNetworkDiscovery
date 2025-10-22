#!/usr/bin/env python3
“””
LLDP Network Topology Report Generator
Connects to network devices and retrieves LLDP information to create a topology report.

Features:

- Multiple authentication methods (password, SSH key, SSH key + password)
- Device-specific credentials (override defaults per device)
- Support for mixed network environments
- CSV and HTML report generation
- Network topology visualization (static diagrams and interactive HTML)

Output Formats:

1. CSV Report - Tabular data for spreadsheet analysis
1. HTML Table Report - Formatted table view in browser
1. PNG/SVG Network Diagram - Static topology diagram (requires Graphviz)
1. Interactive HTML Diagram - Drag-and-drop network visualization (vis.js)

Installation:
pip install netmiko graphviz

System Requirements for Diagrams:

- Debian/Ubuntu: apt install graphviz
- RHEL/CentOS: yum install graphviz
- macOS: brew install graphviz

Supports multiple authentication methods:

- Password authentication
- SSH key authentication
- SSH key + password (for privilege/enable mode)

Device-Specific Credentials:
You can specify different usernames/passwords for different devices:

- In Python: {‘ip’: ‘192.168.1.1’, ‘type’: ‘linux’, ‘username’: ‘root’, ‘password’: ‘pass123’}
- In JSON: {“ip”: “192.168.1.1”, “type”: “linux”, “username”: “root”, “password”: “pass123”}
- Omitted credentials will use the defaults entered at runtime

SSH Key Setup:

1. Generate SSH key pair (if not already done):
   ssh-keygen -t rsa -b 4096
1. Copy public key to network devices:
- Cisco:
  conf t
  ip ssh pubkey-chain
  username <username>
  key-string
  <paste public key>
  exit
- MikroTik:
  /user ssh-keys import user=<username> public-key-file=id_rsa.pub
- HP/Aruba:
  crypto key pubkey-chain ssh
  user-key <username> rsa
  key-string
  <paste public key>
  exit

Supported device types:

- cisco_ios, cisco_nxos
- mikrotik_routeros
- hp_procurve, aruba_os
- arista_eos
- linux (including Proxmox, Ubuntu, Debian, etc.)

Linux LLDP Requirements:

- Install lldpd package: apt-get install lldpd (Debian/Ubuntu/Proxmox)
  yum install lldpd (RHEL/CentOS)
- Enable and start service: systemctl enable –now lldpd
  “””

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import getpass

try:
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
print(“ERROR: netmiko library not found. Install it with: pip install netmiko”)
exit(1)

try:
import graphviz
GRAPHVIZ_AVAILABLE = True
except ImportError:
GRAPHVIZ_AVAILABLE = False
print(“WARNING: graphviz library not found. Install for diagram generation: pip install graphviz”)
print(”         Also install Graphviz system package: apt install graphviz (Debian/Ubuntu)”)
print(”                                              yum install graphviz (RHEL/CentOS)”)
print(”                                              brew install graphviz (macOS)”)
print()

class LLDPReporter:
def **init**(self, username: str, password: str = None, enable_secret: str = None,
key_file: str = None, use_keys: bool = False):
“””
Initialize the LLDP Reporter with credentials.

```
    Args:
        username: SSH username
        password: SSH password (required if not using keys)
        enable_secret: Enable/privilege password (optional)
        key_file: Path to SSH private key file (optional)
        use_keys: Whether to use SSH key authentication
    """
    self.username = username
    self.password = password
    self.enable_secret = enable_secret or password
    self.key_file = key_file
    self.use_keys = use_keys
    self.results = []
    
def connect_device(self, device_ip: str, device_type: str = 'cisco_ios', 
                  device_username: str = None, device_password: str = None,
                  device_enable_secret: str = None) -> Dict:
    """
    Connect to a network device and return connection handler.
    
    Args:
        device_ip: IP address of the device
        device_type: Type of device (cisco_ios, linux, etc.)
        device_username: Device-specific username (overrides default)
        device_password: Device-specific password (overrides default)
        device_enable_secret: Device-specific enable secret (overrides default)
    """
    # Use device-specific credentials if provided, otherwise use defaults
    username = device_username if device_username else self.username
    password = device_password if device_password else self.password
    enable_secret = device_enable_secret if device_enable_secret else self.enable_secret
    
    device = {
        'device_type': device_type,
        'ip': device_ip,
        'username': username,
        'timeout': 30,
    }
    
    # Use SSH key authentication if specified
    if self.use_keys and self.key_file:
        device['use_keys'] = True
        device['key_file'] = self.key_file
        # Still include password/secret if provided (some devices need both)
        if password:
            device['password'] = password
        if enable_secret:
            device['secret'] = enable_secret
    else:
        # Use password authentication
        device['password'] = password
        device['secret'] = enable_secret
    
    return device

def get_lldp_neighbors(self, device_ip: str, device_type: str = 'cisco_ios',
                      device_username: str = None, device_password: str = None,
                      device_enable_secret: str = None) -> List[Dict]:
    """Retrieve LLDP neighbor information from a device."""
    try:
        print(f"Connecting to {device_ip}...")
        device = self.connect_device(device_ip, device_type, device_username, 
                                    device_password, device_enable_secret)
        connection = ConnectHandler(**device)
        
        # Get hostname based on device type
        if device_type == 'mikrotik_routeros':
            hostname_output = connection.send_command("/system identity print")
            hostname = hostname_output.split(':')[-1].strip() if ':' in hostname_output else device_ip
        elif device_type == 'linux':
            hostname_output = connection.send_command("hostname")
            hostname = hostname_output.strip() if hostname_output else device_ip
        elif device_type.startswith('hp') or device_type.startswith('aruba'):
            hostname_output = connection.send_command("show system | include System Name")
            hostname = hostname_output.split(':')[-1].strip() if ':' in hostname_output else device_ip
        else:
            hostname_output = connection.send_command("show run | include hostname")
            hostname = hostname_output.split()[-1] if hostname_output else device_ip
        
        # Get LLDP neighbors detail based on device type
        if device_type == 'mikrotik_routeros':
            lldp_output = connection.send_command("/interface lldp print detail")
            neighbors = self.parse_lldp_mikrotik(lldp_output, hostname, device_ip)
        elif device_type == 'linux':
            # Try lldpctl first (most common), fall back to lldpcli
            lldp_output = connection.send_command("lldpctl")
            if "command not found" in lldp_output.lower() or "not found" in lldp_output.lower():
                lldp_output = connection.send_command("lldpcli show neighbors details")
            neighbors = self.parse_lldp_linux(lldp_output, hostname, device_ip)
        elif device_type.startswith('hp') or device_type.startswith('aruba'):
            lldp_output = connection.send_command("show lldp info remote-device")
            neighbors = self.parse_lldp_hparuba(lldp_output, hostname, device_ip)
        elif device_type.startswith('cisco') or device_type.startswith('arista'):
            lldp_output = connection.send_command("show lldp neighbors detail")
            neighbors = self.parse_lldp_cisco(lldp_output, hostname, device_ip)
        else:
            lldp_output = connection.send_command("show lldp neighbors detail")
            neighbors = self.parse_lldp_cisco(lldp_output, hostname, device_ip)
        
        connection.disconnect()
        return neighbors
        
    except NetmikoTimeoutException:
        print(f"ERROR: Connection timeout to {device_ip}")
        return []
    except NetmikoAuthenticationException:
        print(f"ERROR: Authentication failed for {device_ip}")
        return []
    except Exception as e:
        print(f"ERROR: Failed to get LLDP info from {device_ip}: {str(e)}")
        return []

def parse_lldp_cisco(self, output: str, hostname: str, device_ip: str) -> List[Dict]:
    """Parse Cisco LLDP output into structured data."""
    neighbors = []
    current_neighbor = {}
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Local interface
        if line.startswith('Local Intf:'):
            if current_neighbor:
                neighbors.append(current_neighbor)
            current_neighbor = {
                'source_device': hostname,
                'source_ip': device_ip,
                'local_port': line.split(':')[1].strip(),
                'neighbor_device': '',
                'neighbor_port': '',
                'neighbor_ip': '',
                'capabilities': ''
            }
        
        # Remote port
        elif line.startswith('Port id:'):
            current_neighbor['neighbor_port'] = line.split(':')[1].strip()
        
        # Remote device name
        elif line.startswith('System Name:'):
            current_neighbor['neighbor_device'] = line.split(':')[1].strip()
        
        # Management IP
        elif 'Management Addresses:' in line or 'IP:' in line:
            # Try to extract IP address
            parts = line.split()
            for part in parts:
                if '.' in part and part.replace('.', '').replace('/', '').isdigit():
                    current_neighbor['neighbor_ip'] = part.split('/')[0]
                    break
        
        # Capabilities
        elif line.startswith('System Capabilities:'):
            current_neighbor['capabilities'] = line.split(':')[1].strip()
    
    # Add last neighbor
    if current_neighbor and current_neighbor.get('local_port'):
        neighbors.append(current_neighbor)
    
    return neighbors

def parse_lldp_mikrotik(self, output: str, hostname: str, device_ip: str) -> List[Dict]:
    """Parse MikroTik LLDP output into structured data."""
    neighbors = []
    current_neighbor = {}
    
    for line in output.split('\n'):
        line = line.strip()
        
        # MikroTik LLDP format uses key=value pairs
        if 'interface=' in line.lower():
            if current_neighbor and current_neighbor.get('local_port'):
                neighbors.append(current_neighbor)
            
            # Extract interface name
            for part in line.split():
                if part.startswith('interface='):
                    local_port = part.split('=', 1)[1]
                    current_neighbor = {
                        'source_device': hostname,
                        'source_ip': device_ip,
                        'local_port': local_port,
                        'neighbor_device': '',
                        'neighbor_port': '',
                        'neighbor_ip': '',
                        'capabilities': ''
                    }
                    break
        
        elif current_neighbor:
            # System name
            if 'system-name=' in line.lower():
                for part in line.split():
                    if part.startswith('system-name='):
                        current_neighbor['neighbor_device'] = part.split('=', 1)[1]
                        break
            
            # Port ID
            elif 'port-id=' in line.lower():
                for part in line.split():
                    if part.startswith('port-id='):
                        current_neighbor['neighbor_port'] = part.split('=', 1)[1]
                        break
            
            # Management address
            elif 'address=' in line.lower() and '.' in line:
                for part in line.split():
                    if part.startswith('address='):
                        addr = part.split('=', 1)[1]
                        if '.' in addr:
                            current_neighbor['neighbor_ip'] = addr
                        break
            
            # Capabilities
            elif 'system-caps=' in line.lower() or 'capabilities=' in line.lower():
                for part in line.split():
                    if 'caps=' in part.lower():
                        current_neighbor['capabilities'] = part.split('=', 1)[1]
                        break
    
    # Add last neighbor
    if current_neighbor and current_neighbor.get('local_port'):
        neighbors.append(current_neighbor)
    
    return neighbors

def parse_lldp_hparuba(self, output: str, hostname: str, device_ip: str) -> List[Dict]:
    """Parse HP/Aruba LLDP output into structured data."""
    neighbors = []
    current_neighbor = {}
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Look for local port
        if 'LocalPort' in line or 'Local Port' in line:
            parts = line.split()
            if len(parts) >= 2:
                if current_neighbor and current_neighbor.get('local_port'):
                    neighbors.append(current_neighbor)
                
                current_neighbor = {
                    'source_device': hostname,
                    'source_ip': device_ip,
                    'local_port': parts[-1] if parts else '',
                    'neighbor_device': '',
                    'neighbor_port': '',
                    'neighbor_ip': '',
                    'capabilities': ''
                }
        
        elif current_neighbor:
            # System name
            if 'SysName' in line or 'System Name' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    current_neighbor['neighbor_device'] = parts[1].strip()
            
            # Port description or Port ID
            elif 'PortDescr' in line or 'Port Descr' in line or 'PortId' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    current_neighbor['neighbor_port'] = parts[1].strip()
            
            # Management address
            elif 'Address' in line or 'MgmtAddress' in line:
                parts = line.split()
                for part in parts:
                    if '.' in part and len(part.split('.')) == 4:
                        current_neighbor['neighbor_ip'] = part
                        break
            
            # Capabilities
            elif 'Capability' in line or 'System Capabilities' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    current_neighbor['capabilities'] = parts[1].strip()
    
    # Add last neighbor
    if current_neighbor and current_neighbor.get('local_port'):
        neighbors.append(current_neighbor)
    
    return neighbors

def parse_lldp_linux(self, output: str, hostname: str, device_ip: str) -> List[Dict]:
    """Parse Linux lldpctl output into structured data."""
    neighbors = []
    current_neighbor = {}
    in_chassis = False
    in_port = False
    
    for line in output.split('\n'):
        line_stripped = line.strip()
        
        # New interface/neighbor entry
        if line_stripped.startswith('Interface:'):
            if current_neighbor and current_neighbor.get('local_port'):
                neighbors.append(current_neighbor)
            
            # Extract interface name
            parts = line_stripped.split(',')
            if parts:
                interface = parts[0].replace('Interface:', '').strip()
                current_neighbor = {
                    'source_device': hostname,
                    'source_ip': device_ip,
                    'local_port': interface,
                    'neighbor_device': '',
                    'neighbor_port': '',
                    'neighbor_ip': '',
                    'capabilities': ''
                }
                in_chassis = False
                in_port = False
        
        elif current_neighbor:
            # Section markers
            if line_stripped.startswith('Chassis:'):
                in_chassis = True
                in_port = False
            elif line_stripped.startswith('Port:'):
                in_chassis = False
                in_port = True
            
            # Parse chassis information
            elif in_chassis:
                if 'SysName:' in line_stripped:
                    current_neighbor['neighbor_device'] = line_stripped.split(':', 1)[1].strip()
                elif 'MgmtIP:' in line_stripped or 'MgmtAddr:' in line_stripped:
                    addr = line_stripped.split(':', 1)[1].strip()
                    # Extract just the IP if there's additional info
                    if ' ' in addr:
                        addr = addr.split()[0]
                    current_neighbor['neighbor_ip'] = addr
                elif 'Capability:' in line_stripped:
                    cap = line_stripped.split(':', 1)[1].strip()
                    if current_neighbor['capabilities']:
                        current_neighbor['capabilities'] += ', ' + cap
                    else:
                        current_neighbor['capabilities'] = cap
            
            # Parse port information
            elif in_port:
                if 'PortID:' in line_stripped:
                    port = line_stripped.split(':', 1)[1].strip()
                    # Clean up port ID (remove 'ifname', 'mac', etc.)
                    port = port.replace('ifname', '').replace('mac', '').strip()
                    current_neighbor['neighbor_port'] = port
                elif 'PortDescr:' in line_stripped and not current_neighbor['neighbor_port']:
                    # Use port description if no port ID found
                    current_neighbor['neighbor_port'] = line_stripped.split(':', 1)[1].strip()
    
    # Add last neighbor
    if current_neighbor and current_neighbor.get('local_port'):
        neighbors.append(current_neighbor)
    
    return neighbors

def scan_devices(self, device_list: List[Dict]):
    """Scan multiple devices and collect LLDP information."""
    for device in device_list:
        device_ip = device.get('ip')
        device_type = device.get('type', 'cisco_ios')
        device_username = device.get('username')
        device_password = device.get('password')
        device_enable_secret = device.get('enable_secret')
        
        neighbors = self.get_lldp_neighbors(
            device_ip, 
            device_type,
            device_username,
            device_password,
            device_enable_secret
        )
        self.results.extend(neighbors)
        print(f"Found {len(neighbors)} LLDP neighbors on {device_ip}")

def generate_csv_report(self, filename: str = None):
    """Generate CSV report of LLDP neighbors."""
    if not filename:
        filename = f"lldp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    if not self.results:
        print("No LLDP data to report")
        return
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['source_device', 'source_ip', 'local_port', 
                     'neighbor_device', 'neighbor_port', 'neighbor_ip', 'capabilities']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in self.results:
            writer.writerow(row)
    
    print(f"\nCSV report generated: {filename}")

def generate_html_report(self, filename: str = None):
    """Generate HTML report of LLDP neighbors."""
    if not filename:
        filename = f"lldp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    if not self.results:
        print("No LLDP data to report")
        return
    
    html_content = f"""
```

<!DOCTYPE html>

<html>
<head>
    <title>LLDP Network Topology Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .info {{ margin-bottom: 20px; color: #666; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th {{ background-color: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ border: 1px solid #ddd; padding: 8px; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #ddd; }}
    </style>
</head>
<body>
    <h1>LLDP Network Topology Report</h1>
    <div class="info">
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Connections:</strong> {len(self.results)}</p>
    </div>

```
<table>
    <tr>
        <th>Source Device</th>
        <th>Source IP</th>
        <th>Local Port</th>
        <th>Neighbor Device</th>
        <th>Neighbor Port</th>
        <th>Neighbor IP</th>
        <th>Capabilities</th>
    </tr>
```

“””

```
    for item in self.results:
        html_content += f"""
    <tr>
        <td>{item.get('source_device', 'N/A')}</td>
        <td>{item.get('source_ip', 'N/A')}</td>
        <td>{item.get('local_port', 'N/A')}</td>
        <td>{item.get('neighbor_device', 'N/A')}</td>
        <td>{item.get('neighbor_port', 'N/A')}</td>
        <td>{item.get('neighbor_ip', 'N/A')}</td>
        <td>{item.get('capabilities', 'N/A')}</td>
    </tr>
```

“””

```
    html_content += """
</table>
```

</body>
</html>
"""

```
    with open(filename, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {filename}")

def get_device_type_from_capabilities(self, capabilities: str) -> str:
    """Determine device type from LLDP capabilities."""
    capabilities_lower = capabilities.lower()
    
    if 'router' in capabilities_lower:
        return 'router'
    elif 'switch' in capabilities_lower or 'bridge' in capabilities_lower:
        return 'switch'
    elif 'phone' in capabilities_lower:
        return 'phone'
    elif 'wlan' in capabilities_lower or 'access' in capabilities_lower:
        return 'ap'
    elif 'station' in capabilities_lower or 'host' in capabilities_lower:
        return 'host'
    else:
        return 'unknown'

def generate_network_diagram(self, filename: str = None, format: str = 'png'):
    """
    Generate a network topology diagram using Graphviz.
    
    Args:
        filename: Output filename (without extension)
        format: Output format (png, svg, pdf)
    """
    if not GRAPHVIZ_AVAILABLE:
        print("ERROR: Graphviz is not available. Cannot generate network diagram.")
        print("Install with: pip install graphviz")
        return
    
    if not self.results:
        print("No LLDP data to visualize")
        return
    
    if not filename:
        filename = f"network_topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create directed graph
    dot = graphviz.Digraph(comment='Network Topology')
    dot.attr(rankdir='TB', splines='ortho', nodesep='1.0', ranksep='1.5')
    dot.attr('node', fontname='Arial', fontsize='10')
    dot.attr('edge', fontname='Arial', fontsize='8')
    
    # Track all devices and connections
    devices = {}
    connections = set()
    
    # First pass: collect all unique devices
    for item in self.results:
        source = item.get('source_device', 'Unknown')
        source_ip = item.get('source_ip', '')
        neighbor = item.get('neighbor_device', 'Unknown')
        neighbor_ip = item.get('neighbor_ip', '')
        capabilities = item.get('capabilities', '')
        
        if source not in devices:
            devices[source] = {
                'ip': source_ip,
                'type': 'switch',  # Assume source devices are switches
                'capabilities': ''
            }
        
        if neighbor not in devices:
            device_type = self.get_device_type_from_capabilities(capabilities)
            devices[neighbor] = {
                'ip': neighbor_ip,
                'type': device_type,
                'capabilities': capabilities
            }
    
    # Define node styles based on device type
    node_styles = {
        'router': {'shape': 'cylinder', 'fillcolor': '#FF6B6B', 'style': 'filled'},
        'switch': {'shape': 'box', 'fillcolor': '#4ECDC4', 'style': 'filled,rounded'},
        'host': {'shape': 'ellipse', 'fillcolor': '#95E1D3', 'style': 'filled'},
        'phone': {'shape': 'house', 'fillcolor': '#FFE66D', 'style': 'filled'},
        'ap': {'shape': 'diamond', 'fillcolor': '#C7CEEA', 'style': 'filled'},
        'unknown': {'shape': 'box', 'fillcolor': '#E0E0E0', 'style': 'filled'}
    }
    
    # Add nodes
    for device, info in devices.items():
        device_type = info['type']
        style = node_styles.get(device_type, node_styles['unknown'])
        
        label = device
        if info['ip']:
            label += f"\n{info['ip']}"
        
        dot.node(device, label=label, **style)
    
    # Second pass: add connections
    for item in self.results:
        source = item.get('source_device', 'Unknown')
        neighbor = item.get('neighbor_device', 'Unknown')
        local_port = item.get('local_port', '')
        neighbor_port = item.get('neighbor_port', '')
        
        # Create unique connection identifier (bidirectional)
        conn_key = tuple(sorted([source, neighbor]))
        
        if conn_key not in connections:
            connections.add(conn_key)
            
            # Create edge label with port information
            edge_label = ''
            if local_port and neighbor_port:
                edge_label = f"{local_port} ↔ {neighbor_port}"
            elif local_port:
                edge_label = local_port
            
            # Add edge
            dot.edge(source, neighbor, label=edge_label, 
                    dir='none', penwidth='2.0')
    
    # Generate the diagram
    try:
        output_file = dot.render(filename, format=format, cleanup=True)
        print(f"\nNetwork diagram generated: {output_file}")
    except Exception as e:
        print(f"ERROR: Failed to generate network diagram: {str(e)}")

def generate_interactive_html_diagram(self, filename: str = None):
    """Generate an interactive HTML network diagram using vis.js."""
    if not self.results:
        print("No LLDP data to visualize")
        return
    
    if not filename:
        filename = f"network_diagram_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # Track all devices and connections
    devices = {}
    connections = []
    
    # Collect devices
    for item in self.results:
        source = item.get('source_device', 'Unknown')
        source_ip = item.get('source_ip', '')
        neighbor = item.get('neighbor_device', 'Unknown')
        neighbor_ip = item.get('neighbor_ip', '')
        capabilities = item.get('capabilities', '')
        
        if source not in devices:
            devices[source] = {
                'id': source,
                'label': f"{source}\n{source_ip}",
                'ip': source_ip,
                'type': 'switch',
                'group': 'switch'
            }
        
        if neighbor not in devices:
            device_type = self.get_device_type_from_capabilities(capabilities)
            devices[neighbor] = {
                'id': neighbor,
                'label': f"{neighbor}\n{neighbor_ip}" if neighbor_ip else neighbor,
                'ip': neighbor_ip,
                'type': device_type,
                'group': device_type
            }
    
    # Collect connections
    seen_connections = set()
    for item in self.results:
        source = item.get('source_device', 'Unknown')
        neighbor = item.get('neighbor_device', 'Unknown')
        local_port = item.get('local_port', '')
        neighbor_port = item.get('neighbor_port', '')
        
        conn_key = tuple(sorted([source, neighbor]))
        if conn_key not in seen_connections:
            seen_connections.add(conn_key)
            
            label = ''
            if local_port and neighbor_port:
                label = f"{local_port} ↔ {neighbor_port}"
            elif local_port:
                label = local_port
            
            connections.append({
                'from': source,
                'to': neighbor,
                'label': label,
                'title': f"{source}:{local_port} ↔ {neighbor}:{neighbor_port}"
            })
    
    # Generate HTML with vis.js
    html_content = f"""
```

<!DOCTYPE html>

<html>
<head>
    <title>Interactive Network Topology</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
        }}
        #header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        #mynetwork {{
            width: 100%;
            height: 800px;
            border: 1px solid lightgray;
        }}
        #info {{
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .legend {{
            display: flex;
            justify-content: center;
            gap: 30px;
            padding: 15px;
            background-color: white;
            border-bottom: 1px solid #ddd;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid #333;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>Network Topology - LLDP Discovery</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Devices: {len(devices)} | Connections: {len(connections)}</p>
    </div>

```
<div class="legend">
    <div class="legend-item">
        <div class="legend-color" style="background-color: #FF6B6B;"></div>
        <span>Router</span>
    </div>
    <div class="legend-item">
        <div class="legend-color" style="background-color: #4ECDC4;"></div>
        <span>Switch</span>
    </div>
    <div class="legend-item">
        <div class="legend-color" style="background-color: #95E1D3;"></div>
        <span>Host</span>
    </div>
    <div class="legend-item">
        <div class="legend-color" style="background-color: #FFE66D;"></div>
        <span>Phone</span>
    </div>
    <div class="legend-item">
        <div class="legend-color" style="background-color: #C7CEEA;"></div>
        <span>Access Point</span>
    </div>
    <div class="legend-item">
        <div class="legend-color" style="background-color: #E0E0E0;"></div>
        <span>Unknown</span>
    </div>
</div>

<div id="mynetwork"></div>

<div id="info">
    <h3>Instructions:</h3>
    <ul>
        <li><strong>Click and drag</strong> nodes to rearrange the layout</li>
        <li><strong>Scroll</strong> to zoom in/out</li>
        <li><strong>Click on a node</strong> to see device details</li>
        <li><strong>Hover over connections</strong> to see port information</li>
    </ul>
</div>

<script type="text/javascript">
    // Network data
    var nodes = new vis.DataSet({json.dumps([devices[d] for d in devices], indent=8)});
    
    var edges = new vis.DataSet({json.dumps(connections, indent=8)});

    // Network container
    var container = document.getElementById('mynetwork');
    
    var data = {{
        nodes: nodes,
        edges: edges
    }};
    
    // Configuration
    var options = {{
        nodes: {{
            shape: 'box',
            margin: 10,
            widthConstraint: {{
                maximum: 150
            }},
            font: {{
                size: 14,
                face: 'Arial'
            }}
        }},
        edges: {{
            width: 2,
            color: {{
                color: '#848484',
                highlight: '#2c3e50'
            }},
            smooth: {{
                type: 'continuous'
            }},
            font: {{
                size: 10,
                align: 'middle'
            }}
        }},
        groups: {{
            router: {{
                color: {{background: '#FF6B6B', border: '#d63031'}},
                shape: 'box'
            }},
            switch: {{
                color: {{background: '#4ECDC4', border: '#26a69a'}},
                shape: 'box'
            }},
            host: {{
                color: {{background: '#95E1D3', border: '#66bb6a'}},
                shape: 'ellipse'
            }},
            phone: {{
                color: {{background: '#FFE66D', border: '#fbc02d'}},
                shape: 'diamond'
            }},
            ap: {{
                color: {{background: '#C7CEEA', border: '#7986cb'}},
                shape: 'star'
            }},
            unknown: {{
                color: {{background: '#E0E0E0', border: '#9E9E9E'}},
                shape: 'box'
            }}
        }},
        physics: {{
            enabled: true,
            barnesHut: {{
                gravitationalConstant: -8000,
                centralGravity: 0.3,
                springLength: 200,
                springConstant: 0.04
            }},
            stabilization: {{
                iterations: 150
            }}
        }},
        interaction: {{
            hover: true,
            tooltipDelay: 200
        }}
    }};
    
    // Initialize network
    var network = new vis.Network(container, data, options);
    
    // Event handling
    network.on("click", function (params) {{
        if (params.nodes.length > 0) {{
            var nodeId = params.nodes[0];
            var node = nodes.get(nodeId);
            alert('Device: ' + node.id + '\\nIP: ' + (node.ip || 'N/A') + '\\nType: ' + node.type);
        }}
    }});
</script>
```

</body>
</html>
"""

```
    with open(filename, 'w') as f:
        f.write(html_content)
    
    print(f"Interactive HTML diagram generated: {filename}")
    print(f"Open this file in a web browser to view the interactive network topology")
```

def load_device_list(filename: str) -> List[Dict]:
“”“Load device list from JSON file.”””
with open(filename, ‘r’) as f:
return json.load(f)

def main():
“”“Main function to run the LLDP reporter.”””
print(”=” * 60)
print(“LLDP Network Topology Report Generator”)
print(”=” * 60)
print()

```
# Choose authentication method
print("Authentication Method:")
print("1. Password authentication")
print("2. SSH key authentication")
print("3. SSH key + password (for privilege mode)")
auth_choice = input("Select method (1-3) [1]: ").strip() or "1"
print()

username = input("Enter username: ")

if auth_choice == "2":
    # SSH key only
    key_file = input("Enter path to SSH private key [~/.ssh/id_rsa]: ").strip()
    if not key_file:
        key_file = str(Path.home() / ".ssh" / "id_rsa")
    
    # Expand ~ to home directory
    key_file = str(Path(key_file).expanduser())
    
    if not Path(key_file).exists():
        print(f"ERROR: SSH key file not found: {key_file}")
        return
    
    reporter = LLDPReporter(
        username=username,
        key_file=key_file,
        use_keys=True
    )
    
elif auth_choice == "3":
    # SSH key + password for enable mode
    key_file = input("Enter path to SSH private key [~/.ssh/id_rsa]: ").strip()
    if not key_file:
        key_file = str(Path.home() / ".ssh" / "id_rsa")
    
    key_file = str(Path(key_file).expanduser())
    
    if not Path(key_file).exists():
        print(f"ERROR: SSH key file not found: {key_file}")
        return
    
    enable_secret = getpass.getpass("Enter enable/privilege password: ")
    
    reporter = LLDPReporter(
        username=username,
        password=enable_secret,
        enable_secret=enable_secret,
        key_file=key_file,
        use_keys=True
    )
    
else:
    # Password authentication (default)
    password = getpass.getpass("Enter password: ")
    enable_secret = getpass.getpass("Enter enable secret (press Enter to use password): ")
    if not enable_secret:
        enable_secret = password
    
    reporter = LLDPReporter(
        username=username,
        password=password,
        enable_secret=enable_secret
    )

# Example device list - modify this or load from file
# You can specify device-specific credentials that override the defaults
device_list = [
    {'ip': '192.168.1.1', 'type': 'cisco_ios'},  # Uses default credentials
    {'ip': '192.168.1.2', 'type': 'cisco_ios', 'username': 'netadmin'},  # Custom username
    {'ip': '192.168.1.3', 'type': 'mikrotik_routeros', 'username': 'admin', 'password': 'mikrotik123'},  # Custom username and password
    {'ip': '192.168.1.4', 'type': 'hp_procurve'},
    {'ip': '192.168.1.5', 'type': 'aruba_os'},
    {'ip': '192.168.1.10', 'type': 'linux', 'username': 'root'},  # Proxmox host with root
    {'ip': '192.168.1.11', 'type': 'linux', 'username': 'ubuntu'},  # Ubuntu server
    # Add more devices here
]

# Alternatively, load from JSON file
# Example devices.json format (supports device-specific credentials):
# [
#   {"ip": "192.168.1.1", "type": "cisco_ios"},
#   {"ip": "192.168.1.2", "type": "cisco_ios", "username": "netadmin"},
#   {"ip": "192.168.1.3", "type": "mikrotik_routeros", "username": "admin", "password": "mikrotik123"},
#   {"ip": "192.168.1.4", "type": "hp_procurve"},
#   {"ip": "192.168.1.5", "type": "aruba_os"},
#   {"ip": "192.168.1.10", "type": "linux", "username": "root"},
#   {"ip": "192.168.1.11", "type": "linux", "username": "ubuntu"}
# ]
#
# Optional fields per device:
# - username: Override default username for this device
# - password: Override default password for this device
# - enable_secret: Override default enable secret for this device
#
# Uncomment the following lines to use a JSON file:
# try:
#     device_list = load_device_list('devices.json')
# except FileNotFoundError:
#     print("devices.json not found, using default device list")

print(f"\nScanning {len(device_list)} devices...")
print()

# Scan all devices
reporter.scan_devices(device_list)

# Generate reports
print("\nGenerating reports...")
reporter.generate_csv_report()
reporter.generate_html_report()

# Generate network diagrams
print("\nGenerating network topology visualizations...")

# Generate static diagram (Graphviz)
if GRAPHVIZ_AVAILABLE:
    print("\nGenerating static network diagram...")
    reporter.generate_network_diagram(format='png')  # Also supports 'svg', 'pdf'
    reporter.generate_network_diagram(format='svg')  # SVG for scalability
else:
    print("\nSkipping static diagram generation (Graphviz not available)")

# Generate interactive HTML diagram
print("\nGenerating interactive network diagram...")
reporter.generate_interactive_html_diagram()

print("\n" + "=" * 60)
print("Reports Generated:")
print("- CSV report (for spreadsheet analysis)")
print("- HTML table report (for viewing in browser)")
if GRAPHVIZ_AVAILABLE:
    print("- PNG network diagram (static visualization)")
    print("- SVG network diagram (scalable visualization)")
print("- Interactive HTML diagram (browser-based, drag-and-drop)")
print("=" * 60)

print("\nDone!")
```

if **name** == “**main**”:
main()
