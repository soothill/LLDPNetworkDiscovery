#!/usr/bin/env python3
"""Standalone test for Proxmox LLDP parser logic"""

import re
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class LLDPNeighbor:
    local_device: str
    local_port: str
    remote_device: str
    remote_port: str
    remote_description: Optional[str] = None

def parse_proxmox(output: str, hostname: str) -> List[LLDPNeighbor]:
    """Parse LLDP output from Proxmox hosts - standalone version for testing"""

    # Parse all LLDP entries first (including self-connections)
    all_neighbors = []
    current_interface = None
    remote_system = None
    remote_port = None
    remote_desc = None

    for line in output.split('\n'):
        line = line.strip()

        if line.startswith('Interface:'):
            # Save previous neighbor if complete
            if current_interface and remote_system:
                all_neighbors.append({
                    'local_interface': current_interface,
                    'remote_system': remote_system,
                    'remote_port': remote_port or '',
                    'remote_desc': remote_desc
                })

            # Extract interface name
            iface_part = line.split(':')[1].strip()
            current_interface = iface_part.split(',')[0].strip()
            remote_system = None
            remote_port = None
            remote_desc = None

        elif 'SysName:' in line or 'System Name:' in line:
            if 'SysName:' in line:
                remote_system = line.split('SysName:')[1].strip()
            else:
                remote_system = line.split('System Name:')[1].strip()

        elif 'PortID:' in line or 'Port ID:' in line:
            if 'PortID:' in line:
                remote_port_raw = line.split('PortID:')[1].strip()
            else:
                remote_port_raw = line.split('Port ID:')[1].strip()
            # Remove "mac " prefix if present
            remote_port = remote_port_raw.replace('mac ', '').replace('ifname ', '')

        elif 'PortDescr:' in line and not remote_port:
            remote_port = line.split('PortDescr:')[1].strip()

        elif 'Port Description:' in line:
            remote_desc = line.split('Port Description:')[1].strip()

    # Add last neighbor
    if current_interface and remote_system:
        all_neighbors.append({
            'local_interface': current_interface,
            'remote_system': remote_system,
            'remote_port': remote_port or '',
            'remote_desc': remote_desc
        })

    print(f"Proxmox: Parsed {len(all_neighbors)} total LLDP entries from {hostname}")

    # Now analyze Proxmox bridge topology
    # Build a map of interfaces to their LLDP neighbors
    interface_map = {}
    for entry in all_neighbors:
        interface_map[entry['local_interface']] = entry

    # Identify VM tap interfaces and their connected VMs
    bridges = {}  # Maps bridge ID (VMID) to list of VM connections

    for iface, entry in interface_map.items():
        # Detect tap interfaces (VM side)
        if iface.startswith('tap'):
            # Extract VMID from tap interface (e.g., tap100i0 -> 100)
            match = re.match(r'tap(\d+)i(\d+)', iface)
            if match:
                vmid = match.group(1)
                vm_name = entry['remote_system']

                if vm_name != hostname:  # Not a self-connection
                    # Associate with bridge
                    if vmid not in bridges:
                        bridges[vmid] = []
                    bridges[vmid].append({
                        'vm_name': vm_name,
                        'vm_interface': iface,
                        'vm_port': entry['remote_port']
                    })

    # Count unique VMs across all bridges
    all_vms = set()
    for vms_list in bridges.values():
        all_vms.update(vm['vm_name'] for vm in vms_list)

    print(f"Proxmox: Found {len(all_vms)} unique VMs connected through {len(bridges)} bridges")

    # Build final neighbor list
    neighbors = []
    seen_external = set()

    # Add external connections (physical interfaces connecting to switches/routers)
    for iface, entry in interface_map.items():
        # Physical interfaces or bridge interfaces connecting externally
        if (iface.startswith('eno') or iface.startswith('ens') or iface.startswith('eth') or
            iface.startswith('vmbr')):
            remote_sys = entry['remote_system']

            # Skip self-connections and duplicates
            if remote_sys != hostname:
                conn_key = (iface, remote_sys, entry['remote_port'])
                if conn_key not in seen_external:
                    seen_external.add(conn_key)
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=iface,
                        remote_device=remote_sys,
                        remote_port=entry['remote_port'],
                        remote_description=entry['remote_desc']
                    ))

    # Add bridge connections with VM information
    # Create separate nodes for bridges and VMs in the topology:
    # Proxmox -> Bridge-X -> VM
    for vmid, vms in bridges.items():
        if len(vms) > 0:  # Only show bridges with VMs
            bridge_name = f"Bridge-{vmid}"

            # Deduplicate VM names (VMs with multiple NICs will have multiple tap interfaces)
            vm_names = sorted(set(vm['vm_name'] for vm in vms))

            # Connection 1: Proxmox host -> Bridge
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=f"fwbr{vmid}",
                remote_device=bridge_name,
                remote_port="bridge",
                remote_description=f"Proxmox virtual bridge {vmid}"
            ))

            # Connection 2: Bridge -> Each VM
            for vm_name in vm_names:
                neighbors.append(LLDPNeighbor(
                    local_device=bridge_name,
                    local_port=f"vmbr{vmid}",
                    remote_device=vm_name,
                    remote_port="virtual",
                    remote_description=f"VM connected via bridge {vmid}"
                ))

    print(f"Proxmox: Returning {len(neighbors)} neighbors ({len(seen_external)} external, {len(bridges)} bridges)")
    return neighbors


# Sample lldpctl output from Proxmox server
SAMPLE_OUTPUT = """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eno1np0, via: LLDP, RID: 3, Time: 1 day, 02:56:44
  Chassis:
    SysName:      Aruba-1930
  Port:
    PortID:       ifname 22
    PortDescr:    22
-------------------------------------------------------------------------------
Interface:    ens785f1np1, via: LLDP, RID: 3, Time: 1 day, 02:56:44
  Chassis:
    SysName:      Aruba-1930
  Port:
    PortID:       ifname 26
    PortDescr:    26
-------------------------------------------------------------------------------
Interface:    ens785f1np1, via: LLDP, RID: 8, Time: 0 day, 05:26:03
  Chassis:
    SysName:      docker
  Port:
    PortID:       mac 6a:6b:89:59:3c:59
    PortDescr:    ens16
-------------------------------------------------------------------------------
Interface:    tap100i0, via: LLDP, RID: 2, Time: 12 days, 01:00:15
  Chassis:
    SysName:      testvm
  Port:
    PortID:       mac bc:24:11:1b:45:84
    PortDescr:    ens18
-------------------------------------------------------------------------------
Interface:    tap106i0, via: LLDP, RID: 6, Time: 3 days, 14:32:47
  Chassis:
    SysName:      syslog
  Port:
    PortID:       mac bc:24:11:09:9e:a3
    PortDescr:    ens18
-------------------------------------------------------------------------------
Interface:    tap106i1, via: LLDP, RID: 6, Time: 3 days, 14:32:47
  Chassis:
    SysName:      syslog
  Port:
    PortID:       mac bc:24:11:c1:1f:42
    PortDescr:    ens19
-------------------------------------------------------------------------------
Interface:    tap107i0, via: LLDP, RID: 9, Time: 0 day, 03:35:05
  Chassis:
    SysName:      nvmeof
  Port:
    PortID:       mac bc:24:11:e0:46:31
    PortDescr:    ens18
-------------------------------------------------------------------------------
Interface:    tap113i0, via: LLDP, RID: 7, Time: 0 day, 22:30:38
  Chassis:
    SysName:      openmediavault.soothill.com
  Port:
    PortID:       mac bc:24:11:02:b8:84
    PortDescr:    ens18
-------------------------------------------------------------------------------
Interface:    tap113i1, via: LLDP, RID: 7, Time: 0 day, 22:30:38
  Chassis:
    SysName:      openmediavault.soothill.com
  Port:
    PortID:       mac bc:24:11:30:a1:4f
    PortDescr:    ens19
-------------------------------------------------------------------------------
Interface:    tap118i0, via: LLDP, RID: 5, Time: 12 days, 00:54:38
  Chassis:
    SysName:      observium
  Port:
    PortID:       mac bc:24:11:a8:f2:46
    PortDescr:    ens18
-------------------------------------------------------------------------------
Interface:    tap250i0, via: LLDP, RID: 11, Time: 0 day, 03:27:51
  Chassis:
    SysName:      wificontroller.soothill.com
  Port:
    PortID:       mac 52:54:00:3a:e3:58
    PortDescr:    ens18
-------------------------------------------------------------------------------
"""

def main():
    print("Testing Proxmox LLDP Parser")
    print("=" * 80)

    hostname = "proxmox.soothill.com"
    neighbors = parse_proxmox(SAMPLE_OUTPUT, hostname)

    print(f"\nParsed {len(neighbors)} neighbors:\n")

    # Separate connections by type
    external = []  # Physical connections (eno*, ens*, eth*)
    proxmox_to_bridge = []  # Proxmox -> Bridge connections
    bridge_to_vm = []  # Bridge -> VM connections

    for n in neighbors:
        if n.local_port.startswith('fwbr'):
            # Proxmox host -> Bridge
            proxmox_to_bridge.append(n)
        elif n.local_device.startswith('Bridge-'):
            # Bridge -> VM
            bridge_to_vm.append(n)
        else:
            # Physical/external connections
            external.append(n)

    print("External Connections:")
    print("-" * 80)
    for n in external:
        print(f"  {n.local_device:20} {n.local_port:15} -> {n.remote_device:30} (port: {n.remote_port})")

    print("\nProxmox -> Bridge Connections:")
    print("-" * 80)
    for n in proxmox_to_bridge:
        print(f"  {n.local_device:20} {n.local_port:15} -> {n.remote_device}")

    print("\nBridge -> VM Connections:")
    print("-" * 80)
    for n in bridge_to_vm:
        print(f"  {n.local_device:20} {n.local_port:15} -> {n.remote_device}")

    print("\n" + "=" * 80)
    print(f"Total: {len(external)} external, {len(proxmox_to_bridge)} bridges, {len(bridge_to_vm)} VMs")

    # Validation
    print("\nValidation:")
    expected_vms = ['testvm', 'syslog', 'nvmeof', 'openmediavault.soothill.com',
                    'observium', 'wificontroller.soothill.com']

    # VMs are now in bridge_to_vm connections
    found_vms = set(n.remote_device for n in bridge_to_vm)

    print(f"  Expected VMs: {len(expected_vms)}")
    print(f"  Found VMs: {len(found_vms)}")
    print(f"  Found VM list: {sorted(found_vms)}")

    missing = set(expected_vms) - found_vms
    if missing:
        print(f"  ⚠ Missing VMs: {missing}")
    else:
        print("  ✓ All expected VMs found!")

    # Check topology structure
    print("\nTopology Structure:")
    print(f"  ✓ {len(external)} external connections")
    print(f"  ✓ {len(proxmox_to_bridge)} Proxmox->Bridge connections")
    print(f"  ✓ {len(bridge_to_vm)} Bridge->VM connections")

    return len(external) > 0 and len(proxmox_to_bridge) > 0 and len(bridge_to_vm) > 0

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
