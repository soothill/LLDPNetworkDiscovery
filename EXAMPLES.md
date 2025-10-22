# Examples and Sample Outputs

This document provides examples of using the LLDP Network Discovery Tool and shows sample outputs.

## Table of Contents
- [Basic Usage Examples](#basic-usage-examples)
- [Sample Configuration](#sample-configuration)
- [Sample Output](#sample-output)
- [Real-World Scenarios](#real-world-scenarios)

## Basic Usage Examples

### Example 1: First Time Setup

```bash
# Step 1: Clone the repository
git clone https://github.com/soothill/LLDPNetworkDiscovery.git
cd LLDPNetworkDiscovery

# Step 2: Run automated setup
./setup.sh

# Step 3: Activate virtual environment
source venv/bin/activate

# Step 4: Create configuration
cp devices.example.json devices.json
nano devices.json  # Edit with your device info

# Step 5: Test connectivity
python lldp_discovery.py --test-all devices.json

# Step 6: Discover topology
python lldp_discovery.py devices.json
```

### Example 2: Daily Network Documentation

```bash
#!/bin/bash
# daily_network_scan.sh

source /path/to/LLDPNetworkDiscovery/venv/bin/activate
cd /path/to/LLDPNetworkDiscovery

DATE=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./scans/${DATE}"

mkdir -p "${OUTPUT_DIR}"

python lldp_discovery.py devices.json \
  --output "${OUTPUT_DIR}/topology.json" \
  --graph "${OUTPUT_DIR}/network.png" \
  > "${OUTPUT_DIR}/discovery.log" 2>&1

echo "Network scan completed: ${OUTPUT_DIR}"
```

### Example 3: Monitoring Specific Segments

```bash
# Scan only core switches
python lldp_discovery.py core_switches.json -o core_topology.json

# Scan only access layer
python lldp_discovery.py access_switches.json -o access_topology.json

# Scan DMZ devices
python lldp_discovery.py dmz_devices.json -o dmz_topology.json
```

## Sample Configuration

### Simple Network (Mixed Vendors)

```json
{
  "devices": [
    {
      "hostname": "core-switch-01",
      "ip_address": "10.0.0.1",
      "device_type": "arista",
      "username": "netadmin",
      "password": "SecurePass123!",
      "port": 22
    },
    {
      "hostname": "core-switch-02",
      "ip_address": "10.0.0.2",
      "device_type": "arista",
      "username": "netadmin",
      "password": "SecurePass123!",
      "port": 22
    },
    {
      "hostname": "access-switch-01",
      "ip_address": "10.0.1.1",
      "device_type": "aruba",
      "username": "admin",
      "password": "ArubaPass456!",
      "port": 22
    },
    {
      "hostname": "edge-router",
      "ip_address": "10.0.0.254",
      "device_type": "mikrotik",
      "username": "admin",
      "ssh_key": "/home/netadmin/.ssh/id_rsa",
      "port": 22
    },
    {
      "hostname": "monitoring-server",
      "ip_address": "10.0.2.10",
      "device_type": "linux",
      "username": "root",
      "ssh_key": "/home/netadmin/.ssh/monitoring_key",
      "port": 22
    },
    {
      "hostname": "ruijie-ap-wifi-01",
      "ip_address": "10.0.3.10",
      "device_type": "ruijie",
      "username": "admin",
      "password": "RuijiePass789!",
      "port": 22
    },
    {
      "hostname": "proxmox-host-01",
      "ip_address": "10.0.4.10",
      "device_type": "proxmox",
      "username": "root",
      "ssh_key": "/home/netadmin/.ssh/proxmox_key",
      "port": 22
    }
  ]
}
```

### Enterprise Data Center

```json
{
  "devices": [
    {
      "hostname": "dc1-spine-01",
      "ip_address": "172.16.0.1",
      "device_type": "arista",
      "username": "dcadmin",
      "ssh_key": "/root/.ssh/dc_key"
    },
    {
      "hostname": "dc1-spine-02",
      "ip_address": "172.16.0.2",
      "device_type": "arista",
      "username": "dcadmin",
      "ssh_key": "/root/.ssh/dc_key"
    },
    {
      "hostname": "dc1-leaf-01",
      "ip_address": "172.16.1.1",
      "device_type": "arista",
      "username": "dcadmin",
      "ssh_key": "/root/.ssh/dc_key"
    },
    {
      "hostname": "dc1-leaf-02",
      "ip_address": "172.16.1.2",
      "device_type": "arista",
      "username": "dcadmin",
      "ssh_key": "/root/.ssh/dc_key"
    },
    {
      "hostname": "oob-switch",
      "ip_address": "192.168.100.1",
      "device_type": "aruba",
      "username": "oobadmin",
      "password": "OOBSecure789!"
    }
  ]
}
```

## Sample Output

### Test Connectivity Output

```
$ python lldp_discovery.py --test-all devices.json

============================================================
Testing connectivity to all devices...
============================================================
2025-10-22 10:30:15 - INFO - Testing connection to core-switch-01 (10.0.0.1)...
2025-10-22 10:30:16 - INFO - Successfully connected to core-switch-01 (10.0.0.1)
2025-10-22 10:30:16 - INFO - ✓ core-switch-01 - Connection successful
2025-10-22 10:30:16 - INFO - Testing connection to core-switch-02 (10.0.0.2)...
2025-10-22 10:30:17 - INFO - Successfully connected to core-switch-02 (10.0.0.2)
2025-10-22 10:30:17 - INFO - ✓ core-switch-02 - Connection successful
2025-10-22 10:30:17 - INFO - Testing connection to access-switch-01 (10.0.1.1)...
2025-10-22 10:30:18 - INFO - Successfully connected to access-switch-01 (10.0.1.1)
2025-10-22 10:30:18 - INFO - ✓ access-switch-01 - Connection successful
2025-10-22 10:30:18 - INFO - Testing connection to edge-router (10.0.0.254)...
2025-10-22 10:30:19 - INFO - Successfully connected to edge-router (10.0.0.254)
2025-10-22 10:30:19 - INFO - ✓ edge-router - Connection successful
============================================================
Test Results: 4/4 devices accessible
============================================================
```

### Discovery Output

```
$ python lldp_discovery.py devices.json

2025-10-22 10:35:10 - INFO - Loaded 4 devices from configuration
============================================================
Starting LLDP network discovery...
============================================================
2025-10-22 10:35:10 - INFO - Collecting LLDP data from core-switch-01...
2025-10-22 10:35:11 - INFO - Successfully connected to core-switch-01 (10.0.0.1)
2025-10-22 10:35:12 - INFO - Found 3 LLDP neighbors on core-switch-01
2025-10-22 10:35:12 - INFO - Collecting LLDP data from core-switch-02...
2025-10-22 10:35:13 - INFO - Successfully connected to core-switch-02 (10.0.0.2)
2025-10-22 10:35:14 - INFO - Found 3 LLDP neighbors on core-switch-02
2025-10-22 10:35:14 - INFO - Collecting LLDP data from access-switch-01...
2025-10-22 10:35:15 - INFO - Successfully connected to access-switch-01 (10.0.1.1)
2025-10-22 10:35:16 - INFO - Found 2 LLDP neighbors on access-switch-01
2025-10-22 10:35:16 - INFO - Collecting LLDP data from edge-router...
2025-10-22 10:35:17 - INFO - Successfully connected to edge-router (10.0.0.254)
2025-10-22 10:35:18 - INFO - Found 1 LLDP neighbors on edge-router
============================================================
Discovery complete. Found 9 neighbor relationships
============================================================

============================================================
NETWORK TOPOLOGY SUMMARY
============================================================

access-switch-01:
  1/1/1           -> core-switch-01        (Ethernet1)
  1/1/2           -> core-switch-02        (Ethernet1)

core-switch-01:
  Ethernet1       -> access-switch-01      (1/1/1)
  Ethernet2       -> core-switch-02        (Ethernet48)
  Ethernet48      -> edge-router           (ether1)

core-switch-02:
  Ethernet1       -> access-switch-01      (1/1/2)
  Ethernet2       -> core-switch-01        (Ethernet2)
  Ethernet48      -> edge-router           (ether2)

edge-router:
  ether1          -> core-switch-01        (Ethernet48)
  ether2          -> core-switch-02        (Ethernet48)

============================================================
2025-10-22 10:35:18 - INFO - Topology exported to topology.json
2025-10-22 10:35:20 - INFO - Network topology visualization saved to network_topology.png
```

### JSON Output (topology.json)

```json
{
  "devices": [
    "core-switch-01",
    "core-switch-02",
    "access-switch-01",
    "edge-router"
  ],
  "connections": [
    {
      "local_device": "core-switch-01",
      "local_port": "Ethernet1",
      "remote_device": "access-switch-01",
      "remote_port": "1/1/1",
      "remote_description": "Access Switch Port 1"
    },
    {
      "local_device": "core-switch-01",
      "local_port": "Ethernet2",
      "remote_device": "core-switch-02",
      "remote_port": "Ethernet2",
      "remote_description": "Core Interconnect"
    },
    {
      "local_device": "core-switch-01",
      "local_port": "Ethernet48",
      "remote_device": "edge-router",
      "remote_port": "ether1",
      "remote_description": "WAN Connection"
    },
    {
      "local_device": "core-switch-02",
      "local_port": "Ethernet1",
      "remote_device": "access-switch-01",
      "remote_port": "1/1/2",
      "remote_description": "Access Switch Port 2"
    },
    {
      "local_device": "core-switch-02",
      "local_port": "Ethernet2",
      "remote_device": "core-switch-01",
      "remote_port": "Ethernet2",
      "remote_description": "Core Interconnect"
    },
    {
      "local_device": "core-switch-02",
      "local_port": "Ethernet48",
      "remote_device": "edge-router",
      "remote_port": "ether2",
      "remote_description": "WAN Connection"
    },
    {
      "local_device": "access-switch-01",
      "local_port": "1/1/1",
      "remote_device": "core-switch-01",
      "remote_port": "Ethernet1",
      "remote_description": "Uplink to Core 1"
    },
    {
      "local_device": "access-switch-01",
      "local_port": "1/1/2",
      "remote_device": "core-switch-02",
      "remote_port": "Ethernet1",
      "remote_description": "Uplink to Core 2"
    },
    {
      "local_device": "edge-router",
      "local_port": "ether1",
      "remote_device": "core-switch-01",
      "remote_port": "Ethernet48",
      "remote_description": null
    }
  ]
}
```

## Real-World Scenarios

### Scenario 1: New Network Audit

**Situation**: You've just joined a company and need to document the existing network.

**Solution**:
```bash
# 1. Collect device list from existing documentation
# 2. Create devices.json with all known devices
# 3. Test connectivity
python lldp_discovery.py --test-all devices.json

# 4. Discover and document
python lldp_discovery.py devices.json

# 5. Generate dated archive
DATE=$(date +%Y%m%d)
mkdir -p "audits/${DATE}"
cp topology.json "audits/${DATE}/"
cp network_topology.png "audits/${DATE}/"
```

### Scenario 2: Change Management Verification

**Situation**: After network maintenance, verify all connections are restored correctly.

**Solution**:
```bash
# Before maintenance
python lldp_discovery.py devices.json -o before_maintenance.json -g before.png

# After maintenance
python lldp_discovery.py devices.json -o after_maintenance.json -g after.png

# Compare
diff before_maintenance.json after_maintenance.json
```

### Scenario 3: Troubleshooting Missing Connections

**Situation**: A connection should exist but isn't showing up in the topology.

**Solution**:
```bash
# Run with verbose mode to see detailed output
python lldp_discovery.py -v devices.json

# Test specific device
python lldp_discovery.py --test problematic-switch devices.json

# SSH to device manually and check LLDP
# For Arista:
ssh admin@switch-ip "show lldp neighbors"

# For Linux:
ssh admin@server-ip "lldpctl"
```

### Scenario 4: Multi-Site Network

**Situation**: Document networks across multiple sites.

**Solution**:
```bash
# Create separate configs per site
cp devices.example.json site1_devices.json
cp devices.example.json site2_devices.json
cp devices.example.json site3_devices.json

# Discovery per site
python lldp_discovery.py site1_devices.json -o site1_topology.json -g site1.png
python lldp_discovery.py site2_devices.json -o site2_topology.json -g site2.png
python lldp_discovery.py site3_devices.json -o site3_topology.json -g site3.png
```

### Scenario 5: Automated Weekly Reports

**Situation**: Generate weekly topology reports for documentation.

**Cron job** (`crontab -e`):
```bash
# Run every Monday at 6 AM
0 6 * * 1 /opt/lldp-discovery/weekly_report.sh
```

**Script** (`weekly_report.sh`):
```bash
#!/bin/bash

cd /opt/lldp-discovery
source venv/bin/activate

WEEK=$(date +%Y-W%V)
OUTPUT_DIR="./reports/${WEEK}"

mkdir -p "${OUTPUT_DIR}"

python lldp_discovery.py devices.json \
  --output "${OUTPUT_DIR}/topology.json" \
  --graph "${OUTPUT_DIR}/network_topology.png" \
  > "${OUTPUT_DIR}/discovery.log" 2>&1

# Email report
echo "Weekly network topology report attached" | \
  mail -s "Network Topology Report - Week ${WEEK}" \
       -a "${OUTPUT_DIR}/network_topology.png" \
       -a "${OUTPUT_DIR}/topology.json" \
       network-team@company.com
```

## Advanced Usage

### Using with Configuration Management

**Ansible Integration**:
```yaml
---
- name: Discover network topology
  hosts: localhost
  tasks:
    - name: Run LLDP discovery
      command: python lldp_discovery.py devices.json
      args:
        chdir: /opt/lldp-discovery

    - name: Fetch topology data
      fetch:
        src: /opt/lldp-discovery/topology.json
        dest: ./network-topology/{{ inventory_hostname }}/
        flat: yes
```

### Parsing Results with Python

```python
import json

# Load topology data
with open('topology.json', 'r') as f:
    topology = json.load(f)

# Find all connections for a specific device
device_name = "core-switch-01"
device_connections = [
    conn for conn in topology['connections']
    if conn['local_device'] == device_name
]

print(f"Connections for {device_name}:")
for conn in device_connections:
    print(f"  {conn['local_port']} -> {conn['remote_device']}:{conn['remote_port']}")
```

### Integration with Monitoring Systems

```python
#!/usr/bin/env python3
"""
Send topology data to monitoring system
"""
import json
import requests

# Load topology
with open('topology.json', 'r') as f:
    topology = json.load(f)

# Send to monitoring API
response = requests.post(
    'https://monitoring.company.com/api/topology',
    json=topology,
    headers={'Authorization': 'Bearer YOUR_API_TOKEN'}
)

print(f"Status: {response.status_code}")
```

---

**Copyright (c) 2025 Darren Soothill**
