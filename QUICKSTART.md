# Quick Start Guide

Get up and running with LLDP Network Discovery in 5 minutes!

## Prerequisites

- Python 3.7 or higher
- Network devices with LLDP enabled
- SSH access to your network devices

## Installation

### Option 1: Automated Setup (Recommended)

Run the setup script to automatically install all dependencies:

```bash
./setup.sh
```

This script will:
- Check Python and pip versions
- Install system dependencies
- Create a Python virtual environment
- Install all required Python packages
- Create a sample configuration file
- Make the script executable

### Option 2: Manual Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. **Copy the example configuration:**
   ```bash
   cp devices.example.json devices.json
   ```

2. **Edit `devices.json` with your device details:**
   ```bash
   nano devices.json
   ```

   Replace the example values with your actual device information:
   ```json
   {
     "devices": [
       {
         "hostname": "my-switch",
         "ip_address": "192.168.1.10",
         "device_type": "arista",
         "username": "admin",
         "password": "your_password",
         "port": 22
       }
     ]
   }
   ```

   Supported device types:
   - `linux` - Linux servers with lldpd/lldpad
   - `mikrotik` - MikroTik RouterOS
   - `arista` - Arista EOS
   - `aruba` - HP Aruba switches
   - `ruijie` - Ruijie switches and access points
   - `proxmox` - Proxmox VE hosts

## Usage

### Step 1: Test Connectivity

Before running full discovery, test connectivity to all devices:

```bash
python lldp_discovery.py --test-all devices.json
```

Expected output:
```
Testing connection to my-switch (192.168.1.10)...
✓ my-switch - Connection successful
Test Results: 1/1 devices accessible
```

### Step 2: Discover Network Topology

Run the discovery:

```bash
python lldp_discovery.py devices.json
```

This will:
1. Connect to each device via SSH
2. Collect LLDP neighbor information
3. Generate two output files:
   - `topology.json` - JSON data of all connections
   - `network_topology.png` - Visual network diagram

### Step 3: View Results

**View the network diagram:**
```bash
open network_topology.png  # macOS
xdg-open network_topology.png  # Linux
```

**View the JSON data:**
```bash
cat topology.json | python -m json.tool
```

## Common Use Cases

### Test a Single Device

```bash
python lldp_discovery.py --test my-switch devices.json
```

### Generate Only JSON (No Graph)

```bash
python lldp_discovery.py devices.json --no-graph
```

### Custom Output Files

```bash
python lldp_discovery.py devices.json \
  --output my_topology.json \
  --graph my_network.png
```

### Verbose Mode (Debugging)

```bash
python lldp_discovery.py -v devices.json
```

## Troubleshooting

### "Authentication failed"
- Check username and password in `devices.json`
- Verify SSH is enabled on the device
- Try using SSH key authentication instead

### "No LLDP neighbors found"
- Verify LLDP is enabled on all devices
- Check physical connections are up
- Wait 30-60 seconds for LLDP advertisements

### "Command not found: lldpctl" (Linux)
Install LLDP daemon:
```bash
# Debian/Ubuntu
sudo apt-get install lldpd

# RHEL/CentOS
sudo yum install lldpd

# Start the service
sudo systemctl start lldpd
sudo systemctl enable lldpd
```

### "Connection timeout"
- Verify network connectivity: `ping <device_ip>`
- Check firewall allows SSH (port 22)
- Increase timeout in code if needed

## Device-Specific Setup

### Linux Servers

```bash
# Install LLDP daemon
sudo apt-get install lldpd  # Debian/Ubuntu
sudo yum install lldpd       # RHEL/CentOS

# Start service
sudo systemctl start lldpd
sudo systemctl enable lldpd

# Verify it's working
lldpctl
```

### MikroTik RouterOS

```bash
# Enable LLDP on interfaces
/interface lldp set ether1 disabled=no
/interface lldp set ether2 disabled=no

# Verify
/interface lldp print detail
```

### Arista EOS

LLDP is enabled by default. Verify with:
```bash
show lldp neighbors
```

### HP Aruba

Enable LLDP:
```bash
configure
lldp run
show lldp neighbors-information
```

### Ruijie Switches and Access Points

Enable LLDP:
```bash
# Enter configuration mode
configure terminal

# Enable LLDP globally
lldp enable

# Enable LLDP on specific interfaces
interface GigabitEthernet 0/1
lldp enable

# Verify
show lldp neighbors detail
```

### Proxmox Hosts

LLDP is typically pre-installed on Proxmox VE. If not:
```bash
# Install LLDP daemon
apt-get update
apt-get install lldpd

# Start and enable service
systemctl start lldpd
systemctl enable lldpd

# Verify it's working
lldpctl
```

## Example Network Discovery Session

```bash
# 1. Setup
./setup.sh
source venv/bin/activate

# 2. Configure
cp devices.example.json devices.json
nano devices.json  # Edit with your devices

# 3. Test
python lldp_discovery.py --test-all devices.json

# 4. Discover
python lldp_discovery.py devices.json

# 5. View
open network_topology.png
```

## Security Best Practices

1. **Protect your configuration file:**
   ```bash
   chmod 600 devices.json
   ```

2. **Use SSH keys instead of passwords:**
   ```json
   {
     "hostname": "secure-device",
     "username": "admin",
     "ssh_key": "/home/user/.ssh/id_rsa"
   }
   ```

3. **Don't commit credentials to git:**
   The `.gitignore` file already excludes `devices.json`

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Automate discovery with cron jobs
- Integrate with monitoring systems
- Export topology to other formats

## Getting Help

- Check the [README.md](README.md) for detailed documentation
- Run `python lldp_discovery.py --help` for all options
- Use verbose mode (`-v`) to see detailed error messages

---

**Copyright (c) 2025 Darren Soothill**
