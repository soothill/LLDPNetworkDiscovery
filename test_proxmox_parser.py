#!/usr/bin/env python3
"""Test script for Proxmox LLDP parser"""

import sys
sys.path.insert(0, '.')

from lldp_discovery import LLDPParser

# Sample lldpctl output from Proxmox server
SAMPLE_OUTPUT = """-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eno1np0, via: LLDP, RID: 3, Time: 1 day, 02:56:44
  Chassis:
    ChassisID:    mac 64:e8:81:26:db:32
    SysName:      Aruba-1930
    SysDescr:     HPE Networking Instant On Switch 24p Gigabit 4p SFP+ 1930 JL682A, InstantOn_1930_3.1.0.0 (9)
    MgmtIP:       10.10.201.10
  Port:
    PortID:       ifname 22
    PortDescr:    22
    TTL:          120
-------------------------------------------------------------------------------
Interface:    ens785f1np1, via: LLDP, RID: 3, Time: 1 day, 02:56:44
  Chassis:
    ChassisID:    mac 64:e8:81:26:db:32
    SysName:      Aruba-1930
  Port:
    PortID:       ifname 26
    PortDescr:    26
    TTL:          120
-------------------------------------------------------------------------------
Interface:    ens785f1np1, via: LLDP, RID: 8, Time: 0 day, 05:26:03
  Chassis:
    ChassisID:    mac 6a:6b:89:59:3c:59
    SysName:      docker
    SysDescr:     Ubuntu 24.04.3 LTS Linux 6.8.0-85-generic
  Port:
    PortID:       mac 6a:6b:89:59:3c:59
    PortDescr:    ens16
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap100i0, via: LLDP, RID: 2, Time: 12 days, 01:00:15
  Chassis:
    ChassisID:    mac bc:24:11:1b:45:84
    SysName:      testvm
    SysDescr:     Ubuntu 24.04.1 LTS
  Port:
    PortID:       mac bc:24:11:1b:45:84
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    fwpr100p0, via: LLDP, RID: 1, Time: 12 days, 01:00:20
  Chassis:
    ChassisID:    mac a4:bf:01:26:e0:ba
    SysName:      proxmox.soothill.com
    SysDescr:     Debian GNU/Linux 12 (bookworm)
  Port:
    PortID:       mac 66:2d:c7:a0:38:e6
    PortDescr:    fwln100i0
    TTL:          120
-------------------------------------------------------------------------------
Interface:    fwpr100p0, via: LLDP, RID: 2, Time: 0 day, 22:38:17
  Chassis:
    ChassisID:    mac bc:24:11:1b:45:84
    SysName:      testvm
    SysDescr:     Ubuntu 24.04.1 LTS
  Port:
    PortID:       mac bc:24:11:1b:45:84
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap106i0, via: LLDP, RID: 6, Time: 3 days, 14:32:47
  Chassis:
    ChassisID:    mac bc:24:11:09:9e:a3
    SysName:      syslog
    SysDescr:     Ubuntu 24.04.3 LTS
  Port:
    PortID:       mac bc:24:11:09:9e:a3
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap106i1, via: LLDP, RID: 6, Time: 3 days, 14:32:47
  Chassis:
    ChassisID:    mac bc:24:11:09:9e:a3
    SysName:      syslog
    SysDescr:     Ubuntu 24.04.3 LTS
  Port:
    PortID:       mac bc:24:11:c1:1f:42
    PortDescr:    ens19
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap107i0, via: LLDP, RID: 9, Time: 0 day, 03:35:05
  Chassis:
    ChassisID:    mac bc:24:11:e0:46:31
    SysName:      nvmeof
    SysDescr:     Ubuntu 24.04.3 LTS
  Port:
    PortID:       mac bc:24:11:e0:46:31
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap113i0, via: LLDP, RID: 7, Time: 0 day, 22:30:38
  Chassis:
    ChassisID:    mac bc:24:11:02:b8:84
    SysName:      openmediavault.soothill.com
    SysDescr:     Debian GNU/Linux 12 (bookworm)
  Port:
    PortID:       mac bc:24:11:02:b8:84
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap113i1, via: LLDP, RID: 7, Time: 0 day, 22:30:38
  Chassis:
    ChassisID:    mac bc:24:11:02:b8:84
    SysName:      openmediavault.soothill.com
    SysDescr:     Debian GNU/Linux 12 (bookworm)
  Port:
    PortID:       mac bc:24:11:30:a1:4f
    PortDescr:    ens19
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap118i0, via: LLDP, RID: 5, Time: 12 days, 00:54:38
  Chassis:
    ChassisID:    mac bc:24:11:a8:f2:46
    SysName:      observium
    SysDescr:     Ubuntu 24.04.3 LTS
  Port:
    PortID:       mac bc:24:11:a8:f2:46
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
Interface:    tap250i0, via: LLDP, RID: 11, Time: 0 day, 03:27:51
  Chassis:
    ChassisID:    mac 52:54:00:3a:e3:58
    SysName:      wificontroller.soothill.com
    SysDescr:     Ubuntu 24.04.3 LTS
  Port:
    PortID:       mac 52:54:00:3a:e3:58
    PortDescr:    ens18
    TTL:          120
-------------------------------------------------------------------------------
"""

def main():
    print("Testing Proxmox LLDP Parser")
    print("=" * 80)

    hostname = "proxmox.soothill.com"
    neighbors = LLDPParser.parse_proxmox(SAMPLE_OUTPUT, hostname)

    print(f"\nParsed {len(neighbors)} neighbors:\n")

    # Separate external connections from bridge connections
    external = []
    bridges = []

    for n in neighbors:
        if n.local_port.startswith('fwbr'):
            bridges.append(n)
        else:
            external.append(n)

    print("External Connections:")
    print("-" * 80)
    for n in external:
        print(f"  {n.local_port:15} -> {n.remote_device:30} (port: {n.remote_port})")

    print("\nBridge Connections (VMs):")
    print("-" * 80)
    for n in bridges:
        print(f"  {n.local_port:15} -> {n.remote_device}")
        print(f"                     Description: {n.remote_description}")

    print("\n" + "=" * 80)
    print(f"Total: {len(external)} external connections, {len(bridges)} bridges with VMs")

    # Validation
    print("\nValidation:")
    expected_vms = ['testvm', 'syslog', 'nvmeof', 'openmediavault.soothill.com',
                    'observium', 'wificontroller.soothill.com']
    found_vms = set()
    for n in bridges:
        # Extract VM names from bridge description
        if 'VMs:' in n.remote_device:
            vm_part = n.remote_device.split('VMs:')[1].strip(' )')
            vms = [vm.strip() for vm in vm_part.split(',')]
            found_vms.update(vms)

    print(f"  Expected VMs: {len(expected_vms)}")
    print(f"  Found VMs: {len(found_vms)}")

    missing = set(expected_vms) - found_vms
    if missing:
        print(f"  Missing VMs: {missing}")
    else:
        print("  ✓ All expected VMs found!")

if __name__ == '__main__':
    main()
