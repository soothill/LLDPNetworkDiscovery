# LLDP Network Discovery Tool

A comprehensive Python tool for discovering and visualizing network topology using LLDP (Link Layer Discovery Protocol) across heterogeneous network environments.

## Features

- **Multi-Vendor Support**: Works with Linux, MikroTik, Arista EOS, HP Aruba, Ruijie, and Proxmox devices
- **SSH-Based Discovery**: Securely connects to devices via SSH with per-device credential configuration
- **Port Speed Detection**: Automatically detects and displays network port speeds (1G, 10G, etc.)
- **Connectivity Testing**: Built-in testing mode to verify device accessibility before discovery
- **Network Visualization**: Generates beautiful graphical network topology diagrams with port speeds
- **Multiple Output Formats**: Exports topology data in JSON and PNG formats
- **Flexible Authentication**: Supports both password and SSH key-based authentication
- **Detailed Logging**: Verbose mode for troubleshooting and debugging

## Requirements

- Python 3.7 or higher
- Network devices with LLDP enabled
- SSH access to all network devices
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/soothill/LLDPNetworkDiscovery.git
cd LLDPNetworkDiscovery
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

### Create Configuration File

Generate a sample configuration file:
```bash
python lldp_discovery.py --create-config
```

This creates `devices.json` with the following structure:

```json
{
  "devices": [
    {
      "hostname": "linux-server-01",
      "ip_address": "192.168.1.10",
      "device_type": "linux",
      "username": "admin",
      "password": "your_password_here",
      "port": 22
    },
    {
      "hostname": "mikrotik-router-01",
      "ip_address": "192.168.1.1",
      "device_type": "mikrotik",
      "username": "admin",
      "password": "your_password_here",
      "port": 22
    }
  ]
}
```

### Configuration Parameters

- **hostname**: Friendly name for the device (used in visualization)
- **ip_address**: IP address or hostname for SSH connection
- **device_type**: Device platform - `linux`, `mikrotik`, `arista`, `aruba`, `ruijie`, or `proxmox`
- **username**: SSH username (can be different per device)
- **password**: SSH password (optional if using SSH keys)
- **ssh_key**: Path to SSH private key file (optional)
- **port**: SSH port (default: 22)

### Device-Specific Requirements

#### Linux
- Requires `lldpd` or `lldpad` package installed
- LLDP daemon must be running
- Commands used: `sudo lldpctl`, `sudo ethtool`
- **IMPORTANT**: User must have sudo privileges for `lldpctl` and `ethtool`

**Sudo Configuration** (required):

Create the sudoers file:
```bash
sudo visudo -f /etc/sudoers.d/lldp
```

Add this line (supports both /usr/bin and /usr/sbin paths):
```bash
# Replace 'username' with your SSH username
username ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool
```

**Quick one-line setup:**
```bash
echo 'username ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool' | sudo tee /etc/sudoers.d/lldp
sudo chmod 0440 /etc/sudoers.d/lldp
```

**For multiple users (group-based):**
```bash
%netadmin ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool
```

#### MikroTik RouterOS
- IP neighbor discovery enabled (default)
- Command used: `/ip neighbor print detail`
- Works with LLDP, CDP, and MikroTik discovery protocols
- No special configuration needed

#### Arista EOS
- LLDP enabled by default
- Command used: `show lldp neighbors detail`

#### HP Aruba
- LLDP must be enabled
- Command used: `show lldp neighbors detail`

#### Ruijie Switches and Access Points
- LLDP must be enabled
- Supports both switches and wireless access points
- Command used: `show lldp neighbors detail`

#### Proxmox Hosts
- Requires `lldpd` package installed (typically included by default)
- LLDP daemon must be running
- Commands used: `sudo lldpctl`, `sudo ethtool`
- **IMPORTANT**: User must have sudo privileges (same as Linux above)

## Usage

### Test Device Connectivity

Test all devices in configuration:
```bash
python lldp_discovery.py --test-all devices.json
```

Test a specific device:
```bash
python lldp_discovery.py --test linux-server-01 devices.json
```

### Discover Network Topology

Run full discovery with default output files:
```bash
python lldp_discovery.py devices.json
```

This will:
1. Connect to all configured devices
2. Collect LLDP neighbor information
3. Generate `topology.json` with connection data
4. Create `network_topology.png` visualization

### Custom Output Files

Specify custom output file names:
```bash
python lldp_discovery.py devices.json --output my_topology.json --graph my_network.png
```

### Skip Graphical Output

Generate only JSON output:
```bash
python lldp_discovery.py devices.json --no-graph
```

### Verbose Mode

Enable detailed logging for troubleshooting:
```bash
python lldp_discovery.py -v devices.json
```

## Command-Line Options

```
usage: lldp_discovery.py [-h] [--create-config] [--test-all] [--test HOSTNAME]
                         [--output OUTPUT] [--graph GRAPH] [--no-graph]
                         [--verbose] [config]

positional arguments:
  config                JSON configuration file with device information

optional arguments:
  -h, --help            show this help message and exit
  --create-config       Create a sample configuration file
  --test-all            Test connectivity to all configured devices
  --test HOSTNAME       Test connectivity to a specific device
  --output OUTPUT, -o OUTPUT
                        Output JSON file for topology data (default: topology.json)
  --graph GRAPH, -g GRAPH
                        Output file for network visualization (default: network_topology.png)
  --no-graph            Skip generating graphical visualization
  --verbose, -v         Enable verbose logging
```

## Output Files

### JSON Output (`topology.json`)

```json
{
  "devices": [
    "linux-server-01",
    "mikrotik-router-01"
  ],
  "connections": [
    {
      "local_device": "linux-server-01",
      "local_port": "eth0",
      "remote_device": "mikrotik-router-01",
      "remote_port": "ether1",
      "remote_description": "Router Port 1"
    }
  ]
}
```

### Graphical Output

The tool generates a network topology diagram with:
- **Color-coded nodes** by device type
- **Port labels** on all connections
- **Legend** showing device types
- **High-resolution PNG** (300 DPI) suitable for documentation

## Security Considerations

1. **Credential Storage**: The configuration file contains sensitive credentials. Protect it appropriately:
   ```bash
   chmod 600 devices.json
   ```

2. **SSH Keys**: Use SSH key authentication when possible instead of passwords:
   ```json
   {
     "hostname": "secure-device",
     "username": "admin",
     "ssh_key": "/home/user/.ssh/id_rsa",
     "...": "..."
   }
   ```

3. **Network Access**: Ensure the machine running this tool has network access to all target devices

## Troubleshooting

### Connection Issues

If devices fail to connect:
1. Use `--test-all` to identify problematic devices
2. Enable verbose mode with `-v` for detailed error messages
3. Verify SSH credentials and network connectivity
4. Check firewall rules allow SSH access

### No LLDP Neighbors Found

If discovery completes but finds no neighbors:
1. Verify LLDP is enabled on all devices
2. Check that devices are actually connected
3. Allow time for LLDP advertisements (typically 30 seconds)
4. Use verbose mode to see raw command output

### Visualization Issues

If graph generation fails:
- Ensure `networkx` and `matplotlib` are installed
- Try `--no-graph` to skip visualization
- Check you have write permissions in the output directory

## Examples

### Example 1: Basic Discovery
```bash
# Create config
python lldp_discovery.py --create-config

# Edit devices.json with your device details

# Test connectivity
python lldp_discovery.py --test-all devices.json

# Run discovery
python lldp_discovery.py devices.json
```

### Example 2: Automated Monitoring
```bash
# Run discovery daily and save with timestamp
#!/bin/bash
DATE=$(date +%Y%m%d)
python lldp_discovery.py devices.json \
  --output "topology_${DATE}.json" \
  --graph "network_${DATE}.png"
```

### Example 3: Quick Check
```bash
# Test specific device before full discovery
python lldp_discovery.py --test core-switch-01 devices.json && \
python lldp_discovery.py devices.json
```

## Architecture

The tool consists of several key components:

- **SSHConnection**: Handles SSH connectivity with error handling and timeouts
- **LLDPParser**: Vendor-specific parsers for LLDP output formats
- **LLDPDiscovery**: Main orchestrator for discovery process
- **Visualization**: NetworkX-based graph generation with matplotlib

## Supported LLDP Commands

| Platform | Command |
|----------|---------|
| Linux | `lldpctl` |
| MikroTik | `/interface lldp print detail` |
| Arista EOS | `show lldp neighbors detail` |
| HP Aruba | `show lldp neighbors detail` |
| Ruijie | `show lldp neighbors detail` |
| Proxmox | `lldpctl` |

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Adding New Device Types

To add support for a new device type:

1. Add a new parser method in the `LLDPParser` class
2. Add the device type to the command dictionary in `collect_lldp_neighbors()`
3. Update the documentation

## License

Copyright (c) 2025 Darren Soothill. All rights reserved.

## Author

**Darren Soothill**

## Changelog

### Version 1.0.0 (2025)
- Initial release
- Support for Linux, MikroTik, Arista, and HP Aruba devices
- Network topology visualization
- JSON export functionality
- Connectivity testing features
