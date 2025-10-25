#!/usr/bin/env python3
"""Test the _is_physical_interface filter for Proxmox interfaces"""

def _is_physical_interface(interface_name: str) -> bool:
    """Check if an interface is physical (not virtual like VLAN, bridge, tunnel)

    Special handling for Proxmox interfaces:
    - fwbr* (Proxmox firewall bridges showing VM connections) are allowed
    - fwpr*, fwln* (internal bridge ports) are excluded
    - tap* (VM tap devices) are excluded
    """
    if not interface_name:
        return False

    interface_lower = interface_name.lower()

    # Proxmox firewall bridge interfaces (fwbr*) are special - they represent
    # VM connections and should be shown in the topology
    if interface_lower.startswith('fwbr'):
        return True  # Allow Proxmox bridge pseudo-devices

    # Proxmox internal interfaces should be filtered
    proxmox_internal_patterns = [
        'fwpr',      # Proxmox firewall proxy port
        'fwln',      # Proxmox firewall link
        'tap',       # Proxmox VM TAP device
        'vmbr',      # Proxmox virtual bridge (actual bridge, not our pseudo-device)
    ]

    for pattern in proxmox_internal_patterns:
        if interface_lower.startswith(pattern):
            return False

    # Virtual interface patterns to exclude
    virtual_patterns = [
        'vlan',      # VLAN interfaces
        'bridge',    # Bridge interfaces
        'tunnel',    # Tunnel interfaces
        'loopback',  # Loopback
        'lo',        # Loopback (short form)
        'null',      # Null interface
        'bond',      # Bonded interfaces
        'lag',       # Link aggregation
        'port-channel',  # Port channel
        'veth',      # Virtual ethernet
        'docker',    # Docker interfaces
        'virbr',     # Virtual bridge
        'wg',        # WireGuard
        'tun',       # Tunnel
    ]

    # Check if interface name contains any virtual pattern
    for pattern in virtual_patterns:
        if pattern in interface_lower:
            return False

    # Also check for interfaces starting with 'br' (common bridge naming)
    # but not 'fwbr' which we already allowed above
    if interface_lower.startswith('br'):
        return False

    return True


def main():
    test_cases = [
        # Proxmox bridge pseudo-devices (should PASS)
        ('fwbr100', True, 'Proxmox bridge for VM 100'),
        ('fwbr106', True, 'Proxmox bridge for VM 106'),
        ('fwbr250', True, 'Proxmox bridge for VM 250'),

        # Proxmox internal interfaces (should be FILTERED)
        ('tap100i0', False, 'Proxmox tap device'),
        ('tap106i1', False, 'Proxmox tap device'),
        ('fwpr100p0', False, 'Proxmox firewall proxy'),
        ('fwln100i0', False, 'Proxmox firewall link'),
        ('vmbr0', False, 'Proxmox virtual bridge'),

        # Physical interfaces (should PASS)
        ('eno1np0', True, 'Physical interface'),
        ('ens785f1np1', True, 'Physical interface'),
        ('eth0', True, 'Physical interface'),
        ('enp0s3', True, 'Physical interface'),

        # Virtual interfaces (should be FILTERED)
        ('vlan100', False, 'VLAN interface'),
        ('br0', False, 'Bridge interface'),
        ('docker0', False, 'Docker interface'),
        ('virbr0', False, 'Virtual bridge'),
        ('lo', False, 'Loopback'),
        ('tunnel0', False, 'Tunnel'),
    ]

    print("Testing _is_physical_interface filter\n")
    print("=" * 80)

    passed = 0
    failed = 0

    for interface, expected, description in test_cases:
        result = _is_physical_interface(interface)
        status = "✓ PASS" if result == expected else "✗ FAIL"

        if result == expected:
            passed += 1
        else:
            failed += 1

        action = "ALLOW" if result else "FILTER"
        expected_action = "ALLOW" if expected else "FILTER"

        print(f"{status:8} | {interface:15} | {action:8} (expected: {expected_action:8}) | {description}")

    print("=" * 80)
    print(f"\nResults: {passed} passed, {failed} failed")

    if failed > 0:
        print("\n⚠ Some tests failed!")
        return 1
    else:
        print("\n✓ All tests passed!")
        return 0


if __name__ == '__main__':
    exit(main())
