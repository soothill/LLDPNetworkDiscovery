# LLDP Network Topology Generator

A comprehensive Python tool for discovering and visualizing network topology using LLDP (Link Layer Discovery Protocol). This tool connects to network devices, retrieves LLDP information, and generates multiple report formats including interactive network diagrams.

## Features

- **Multiple Authentication Methods**
  - Password authentication
  - SSH key authentication
  - SSH key + password (for privilege/enable mode)

- **Device-Specific Credentials**
  - Override default credentials per device
  - Support for mixed network environments with different authentication requirements

- **Multi-Vendor Support**
  - Cisco IOS, Cisco NX-OS
  - MikroTik RouterOS
  - HP ProCurve, Aruba OS
  - Arista EOS
  - Linux systems (Ubuntu, Debian, Proxmox, etc.)

- **Multiple Output Formats**
  - CSV reports for spreadsheet analysis
  - HTML table reports for browser viewing
  - Static PNG/SVG network diagrams (using Graphviz)
  - Interactive HTML diagrams with drag-and-drop functionality (using vis.js)

## Requirements

### Python Dependencies

```bash
pip install netmiko graphviz
```

### System Dependencies (for diagram generation)

**Debian/Ubuntu:**
```bash
apt install graphviz
```

**RHEL/CentOS:**
```bash
yum install graphviz
```

**macOS:**
```bash
brew install graphviz
```

### Linux LLDP Requirements

If you're scanning Linux servers (including Proxmox), install and enable LLDP:

**Debian/Ubuntu/Proxmox:**
```bash
apt-get install lldpd
systemctl enable --now lldpd
```

**RHEL/CentOS:**
```bash
yum install lldpd
systemctl enable --now lldpd
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/LLDPNetworkDiscovery.git
cd LLDPNetworkDiscovery
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install Graphviz (optional, for static diagrams):
```bash
# See System Dependencies section above
```

## Usage

### Basic Usage

1. Edit the `device_list` in the `main()` function of `Lldpdiscovery.py`, or create a `devices.json` file (see below)

2. Run the script:
```bash
python3 Lldpdiscovery.py
```

3. Choose your authentication method and enter credentials when prompted

4. The script will generate reports in the current directory

### Device List Configuration

#### Option 1: Edit the Python file

Modify the `device_list` in `Lldpdiscovery.py`:

```python
device_list = [
    {'ip': '192.168.1.1', 'type': 'cisco_ios'},
    {'ip': '192.168.1.2', 'type': 'mikrotik_routeros'},
    {'ip': '192.168.1.3', 'type': 'hp_procurve'},
    {'ip': '192.168.1.10', 'type': 'linux'},
]
```

#### Option 2: Create a JSON file

Create `devices.json`:

```json
[
  {"ip": "192.168.1.1", "type": "cisco_ios"},
  {"ip": "192.168.1.2", "type": "mikrotik_routeros", "username": "admin", "password": "secret"},
  {"ip": "192.168.1.3", "type": "hp_procurve"},
  {"ip": "192.168.1.10", "type": "linux", "username": "root"}
]
```

Then uncomment the JSON loading section in `main()`.

### Supported Device Types

- `cisco_ios` - Cisco IOS devices
- `cisco_nxos` - Cisco Nexus devices
- `mikrotik_routeros` - MikroTik routers
- `hp_procurve` - HP ProCurve switches
- `aruba_os` - Aruba switches
- `arista_eos` - Arista switches
- `linux` - Linux servers (Ubuntu, Debian, Proxmox, etc.)

### Device-Specific Credentials

You can specify different credentials for different devices:

```python
device_list = [
    {'ip': '192.168.1.1', 'type': 'cisco_ios'},  # Uses default credentials
    {'ip': '192.168.1.2', 'type': 'cisco_ios', 'username': 'netadmin'},  # Custom username
    {'ip': '192.168.1.3', 'type': 'mikrotik_routeros', 'username': 'admin', 'password': 'mikrotik123'},  # Full custom
    {'ip': '192.168.1.10', 'type': 'linux', 'username': 'root', 'enable_secret': 'rootpass'},
]
```

## SSH Key Authentication

### 1. Generate SSH Key Pair (if not already done)

```bash
ssh-keygen -t rsa -b 4096
```

### 2. Copy Public Key to Network Devices

**Cisco:**
```
conf t
ip ssh pubkey-chain
  username <username>
    key-string
      <paste public key>
    exit
```

**MikroTik:**
```
/user ssh-keys import user=<username> public-key-file=id_rsa.pub
```

**HP/Aruba:**
```
crypto key pubkey-chain ssh
  user-key <username> rsa
    key-string
      <paste public key>
    exit
```

**Linux:**
```bash
ssh-copy-id username@device-ip
```

### 3. Run the Script

When prompted, select option 2 (SSH key authentication) or 3 (SSH key + password).

## Output Files

The script generates the following files:

- **CSV Report**: `lldp_report_YYYYMMDD_HHMMSS.csv`
  - Tabular data for import into spreadsheets

- **HTML Table Report**: `lldp_report_YYYYMMDD_HHMMSS.html`
  - Formatted table view for browsers

- **PNG Network Diagram**: `network_topology_YYYYMMDD_HHMMSS.png`
  - Static topology diagram (requires Graphviz)

- **SVG Network Diagram**: `network_topology_YYYYMMDD_HHMMSS.svg`
  - Scalable vector diagram (requires Graphviz)

- **Interactive HTML Diagram**: `network_diagram_YYYYMMDD_HHMMSS.html`
  - Interactive, drag-and-drop network visualization

## Interactive Diagram Features

The interactive HTML diagram includes:

- **Drag and drop** nodes to rearrange layout
- **Zoom** in/out with mouse scroll
- **Click nodes** to see device details
- **Hover over connections** to see port information
- **Color-coded device types**:
  - Red: Routers
  - Teal: Switches
  - Green: Hosts/Servers
  - Yellow: IP Phones
  - Purple: Access Points
  - Gray: Unknown devices

## Troubleshooting

### Connection Timeout

```
ERROR: Connection timeout to 192.168.1.1
```

**Solutions:**
- Verify the IP address is reachable (`ping 192.168.1.1`)
- Check that SSH is enabled on the device
- Verify firewall rules allow SSH connections
- Increase the timeout value in `connect_device()` method

### Authentication Failed

```
ERROR: Authentication failed for 192.168.1.1
```

**Solutions:**
- Verify username and password are correct
- Check if SSH keys are properly configured
- For Cisco devices, verify enable secret is correct
- Check if the account is locked or disabled

### LLDP Not Found on Linux

```
ERROR: lldpctl: command not found
```

**Solution:**
```bash
# Debian/Ubuntu
apt-get install lldpd
systemctl enable --now lldpd

# RHEL/CentOS
yum install lldpd
systemctl enable --now lldpd
```

### Graphviz Not Found

```
WARNING: graphviz library not found
```

**Solution:**
```bash
# Install Python package
pip install graphviz

# Install system package
apt install graphviz      # Debian/Ubuntu
yum install graphviz      # RHEL/CentOS
brew install graphviz     # macOS
```

## Security Considerations

- Store credentials securely (use environment variables or encrypted vaults)
- Use SSH keys instead of passwords when possible
- Limit SSH access to management networks only
- Review device-specific credential overrides in your device list
- Do not commit `devices.json` with credentials to version control

## Example Workflow

1. **Initial Setup:**
```bash
git clone https://github.com/yourusername/LLDPNetworkDiscovery.git
cd LLDPNetworkDiscovery
pip install -r requirements.txt
apt install graphviz  # or yum/brew
```

2. **Create Device List:**
```bash
nano devices.json
# Add your devices
```

3. **Run Discovery:**
```bash
python3 Lldpdiscovery.py
# Select authentication method
# Enter credentials
```

4. **View Results:**
```bash
# Open interactive diagram in browser
firefox network_diagram_*.html

# Or view CSV in spreadsheet
libreoffice lldp_report_*.csv
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Author

Darren Soothill

## Acknowledgments

- [Netmiko](https://github.com/ktbyers/netmiko) - Multi-vendor SSH library
- [Graphviz](https://graphviz.org/) - Graph visualization software
- [vis.js](https://visjs.org/) - Interactive network visualization library

## Support

If you encounter any issues or have questions:

1. Check the Troubleshooting section above
2. Review existing GitHub Issues
3. Create a new Issue with detailed information about your problem

---

**Happy Network Mapping!** 🗺️
