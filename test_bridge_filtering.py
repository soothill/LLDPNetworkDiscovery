#!/usr/bin/env python3
"""
Test that Bridge pseudo-device connections pass through the normalization filter
"""

import sys
import logging
from lldp_discovery import LLDPDiscovery, DeviceConfig, LLDPNeighbor

# Configure logging
logging.basicConfig(level=logging.WARNING)

def test_bridge_filtering():
    """Test that Bridge->VM connections are not filtered out"""

    # Create a minimal discovery instance
    devices = [
        DeviceConfig(hostname="proxmox.test.com", ip="192.168.1.10",
                    device_type="proxmox", username="test", password="test")
    ]

    discovery = LLDPDiscovery(devices)

    # Manually add neighbors simulating what parse_proxmox creates
    discovery.neighbors = [
        # External connection (should pass - physical interface)
        LLDPNeighbor(
            local_device="proxmox.test.com",
            local_port="eno1",
            remote_device="switch1",
            remote_port="port1"
        ),
        # Proxmox -> Bridge (should pass - fwbr is allowed)
        LLDPNeighbor(
            local_device="proxmox.test.com",
            local_port="fwbr100",
            remote_device="Bridge-100",
            remote_port="bridge"
        ),
        # Bridge -> VM (should pass - Bridge- devices bypass filter)
        LLDPNeighbor(
            local_device="Bridge-100",
            local_port="vmbr100",  # This would normally be filtered!
            remote_device="testvm",
            remote_port="virtual"
        ),
        # Virtual interface on real device (should be filtered)
        LLDPNeighbor(
            local_device="proxmox.test.com",
            local_port="vmbr0",  # Real vmbr interface - should filter
            remote_device="somedevice",
            remote_port="eth0"
        ),
    ]

    print(f"Before filter: {len(discovery.neighbors)} neighbors")
    for n in discovery.neighbors:
        print(f"  {n.local_device}:{n.local_port} -> {n.remote_device}:{n.remote_port}")

    # Run the normalization/filtering
    discovery._normalize_neighbor_hostnames()

    print(f"\nAfter filter: {len(discovery.neighbors)} neighbors")
    for n in discovery.neighbors:
        print(f"  {n.local_device}:{n.local_port} -> {n.remote_device}:{n.remote_port}")

    # Verify results
    assert len(discovery.neighbors) == 3, f"Expected 3 neighbors, got {len(discovery.neighbors)}"

    # Check that we have the right connections
    local_devices = [n.local_device for n in discovery.neighbors]
    assert "proxmox.test.com" in local_devices, "Missing external connection"
    assert "Bridge-100" in local_devices, "Missing Bridge->VM connection"

    # Verify the Bridge->VM connection specifically
    bridge_connections = [n for n in discovery.neighbors if n.local_device == "Bridge-100"]
    assert len(bridge_connections) == 1, f"Expected 1 Bridge->VM connection, got {len(bridge_connections)}"
    assert bridge_connections[0].remote_device == "testvm", "Bridge should connect to testvm"

    print("\n" + "=" * 80)
    print("✓ All filtering tests passed!")
    print("  - External connections: preserved")
    print("  - Proxmox->Bridge connections: preserved (fwbr allowed)")
    print("  - Bridge->VM connections: preserved (Bridge- devices bypass filter)")
    print("  - Virtual interfaces on real devices: filtered (vmbr blocked)")
    print("=" * 80)

if __name__ == "__main__":
    test_bridge_filtering()
