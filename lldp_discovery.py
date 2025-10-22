#!/usr/bin/env python3
"""
LLDP Network Discovery Tool
Discovers network topology using LLDP across Linux, MikroTik, Arista, HP Aruba, Ruijie, and Proxmox devices

Copyright (c) 2025 Darren Soothill
All rights reserved.
"""

import paramiko
import json
import re
import argparse
import sys
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import logging

# For graphical output
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False
    print("Warning: networkx/matplotlib not available. Install with: pip install networkx matplotlib")


@dataclass
class LLDPNeighbor:
    """Represents an LLDP neighbor connection"""
    local_device: str
    local_port: str
    remote_device: str
    remote_port: str
    remote_description: Optional[str] = None
    local_port_speed: Optional[str] = None
    remote_port_speed: Optional[str] = None

    def __hash__(self):
        return hash((self.local_device, self.local_port, self.remote_device, self.remote_port))


@dataclass
class DeviceConfig:
    """Device configuration for SSH connection"""
    hostname: str
    ip_address: str
    device_type: str  # linux, mikrotik, arista, aruba, ruijie, proxmox
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    port: int = 22


class SSHConnection:
    """Handles SSH connections to network devices"""

    def __init__(self, device: DeviceConfig, timeout: int = 10):
        self.device = device
        self.timeout = timeout
        self.client = None
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """Establish SSH connection to device"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_params = {
                'hostname': self.device.ip_address,
                'username': self.device.username,
                'port': self.device.port,
                'timeout': self.timeout,
                'look_for_keys': False,
                'allow_agent': False
            }

            if self.device.ssh_key:
                connect_params['key_filename'] = self.device.ssh_key
            elif self.device.password:
                connect_params['password'] = self.device.password
            else:
                self.logger.error(f"No authentication method provided for {self.device.hostname}")
                return False

            self.client.connect(**connect_params)
            self.logger.info(f"Successfully connected to {self.device.hostname} ({self.device.ip_address})")
            return True

        except paramiko.AuthenticationException:
            self.logger.error(f"Authentication failed for {self.device.hostname}")
            return False
        except paramiko.SSHException as e:
            self.logger.error(f"SSH error connecting to {self.device.hostname}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error connecting to {self.device.hostname}: {e}")
            return False

    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute command on remote device"""
        if not self.client:
            return "", "Not connected", 1

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            exit_code = stdout.channel.recv_exit_status()
            return stdout.read().decode('utf-8'), stderr.read().decode('utf-8'), exit_code
        except Exception as e:
            self.logger.error(f"Error executing command on {self.device.hostname}: {e}")
            return "", str(e), 1

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.logger.debug(f"Closed connection to {self.device.hostname}")


class PortSpeedDetector:
    """Detects port speeds for different device types"""

    @staticmethod
    def get_port_speeds_linux(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Linux interfaces using ethtool"""
        speeds = {}
        for port in ports:
            # Try ethtool first
            stdout, stderr, exit_code = ssh.execute_command(f"ethtool {port} 2>/dev/null | grep -i speed")
            if exit_code == 0 and stdout:
                # Parse "Speed: 1000Mb/s" or "Speed: 10000Mb/s"
                match = re.search(r'Speed:\s*(\d+)Mb/s', stdout, re.IGNORECASE)
                if match:
                    speed_mbps = int(match.group(1))
                    speeds[port] = PortSpeedDetector._format_speed(speed_mbps)
                    continue

            # Fallback: try /sys/class/net
            stdout, stderr, exit_code = ssh.execute_command(f"cat /sys/class/net/{port}/speed 2>/dev/null")
            if exit_code == 0 and stdout.strip().isdigit():
                speed_mbps = int(stdout.strip())
                if speed_mbps > 0:
                    speeds[port] = PortSpeedDetector._format_speed(speed_mbps)
                    continue

            speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def get_port_speeds_mikrotik(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for MikroTik interfaces"""
        speeds = {}
        stdout, stderr, exit_code = ssh.execute_command('/interface print detail without-paging')

        if exit_code == 0:
            current_interface = None
            for line in stdout.split('\n'):
                line = line.strip()

                # Match interface name
                name_match = re.search(r'name="?([^"\s]+)"?', line)
                if name_match:
                    current_interface = name_match.group(1)

                # Match running speed
                if current_interface and 'running=' in line:
                    speed_match = re.search(r'running=(\S+)', line)
                    if speed_match and current_interface in ports:
                        running = speed_match.group(1).lower()
                        if 'yes' in running or 'true' in running:
                            # Get actual rate
                            rate_match = re.search(r'rate=(\S+)', line)
                            if rate_match:
                                speeds[current_interface] = rate_match.group(1)
                            else:
                                speeds[current_interface] = "Link Up"

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def get_port_speeds_arista(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Arista EOS interfaces"""
        speeds = {}
        stdout, stderr, exit_code = ssh.execute_command('show interfaces status')

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse output like: "Et1    connected    1        full    1G     1000baseT"
                parts = line.split()
                if len(parts) >= 6:
                    interface = parts[0]
                    # Match any port in our list
                    for port in ports:
                        if port in interface or interface in port:
                            speed = parts[5]  # Speed column
                            speeds[port] = speed
                            break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def get_port_speeds_aruba(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for HP Aruba interfaces"""
        speeds = {}
        stdout, stderr, exit_code = ssh.execute_command('show interfaces brief')

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse Aruba output
                parts = line.split()
                if len(parts) >= 3:
                    port_name = parts[0]
                    for port in ports:
                        if port in port_name or port_name in port:
                            # Speed is usually in format like "1000FDx" or "10GigFD"
                            if 'Up' in line:
                                speed_match = re.search(r'(\d+(?:G|M)?(?:ig)?(?:FD|HD|x)?)', line)
                                if speed_match:
                                    speeds[port] = speed_match.group(1)
                                else:
                                    speeds[port] = "Link Up"
                            break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def get_port_speeds_ruijie(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Ruijie interfaces"""
        speeds = {}
        stdout, stderr, exit_code = ssh.execute_command('show interfaces status')

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse Ruijie output similar to Cisco format
                parts = line.split()
                if len(parts) >= 4:
                    interface = parts[0]
                    for port in ports:
                        if port in interface or interface in port:
                            # Speed is typically in format like "1000" or "10G"
                            if 'connected' in line.lower() or 'up' in line.lower():
                                speed_match = re.search(r'(\d+(?:G|M)?)', line)
                                if speed_match:
                                    speed_str = speed_match.group(1)
                                    # Convert to standard format
                                    if speed_str.isdigit():
                                        speeds[port] = PortSpeedDetector._format_speed(int(speed_str))
                                    else:
                                        speeds[port] = speed_str
                            break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def get_port_speeds_proxmox(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Proxmox hosts (same as Linux)"""
        return PortSpeedDetector.get_port_speeds_linux(ssh, ports)

    @staticmethod
    def _format_speed(speed_mbps: int) -> str:
        """Format speed in Mbps to human-readable format"""
        if speed_mbps >= 1000:
            if speed_mbps % 1000 == 0:
                return f"{speed_mbps // 1000}G"
            else:
                return f"{speed_mbps / 1000:.1f}G"
        else:
            return f"{speed_mbps}M"


class LLDPParser:
    """Parse LLDP output from different device types"""

    @staticmethod
    def parse_linux(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from Linux (lldpctl)"""
        neighbors = []

        # Parse lldpctl output
        current_interface = None
        remote_system = None
        remote_port = None
        remote_desc = None

        for line in output.split('\n'):
            line = line.strip()

            # Match interface name
            if line.startswith('Interface:'):
                if current_interface and remote_system and remote_port:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_interface,
                        remote_device=remote_system,
                        remote_port=remote_port,
                        remote_description=remote_desc
                    ))
                current_interface = line.split(':')[1].strip().rstrip(',')
                remote_system = None
                remote_port = None
                remote_desc = None

            elif 'SysName:' in line:
                remote_system = line.split('SysName:')[1].strip()
            elif 'PortID:' in line:
                remote_port = line.split('PortID:')[1].strip()
            elif 'PortDescr:' in line:
                remote_desc = line.split('PortDescr:')[1].strip()

        # Add last neighbor
        if current_interface and remote_system and remote_port:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_interface,
                remote_device=remote_system,
                remote_port=remote_port,
                remote_description=remote_desc
            ))

        return neighbors

    @staticmethod
    def parse_mikrotik(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from MikroTik"""
        neighbors = []

        # Parse MikroTik /interface lldp print detail
        lines = output.split('\n')
        current_neighbor = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if line.startswith('0') or re.match(r'^\d+\s+', line):
                # Start of new neighbor entry
                if current_neighbor and 'interface' in current_neighbor and 'system-name' in current_neighbor:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_neighbor.get('interface', ''),
                        remote_device=current_neighbor.get('system-name', ''),
                        remote_port=current_neighbor.get('port-id', ''),
                        remote_description=current_neighbor.get('port-description')
                    ))
                current_neighbor = {}

            if ':' in line:
                key, value = line.split(':', 1)
                current_neighbor[key.strip().lower()] = value.strip()

        # Add last neighbor
        if current_neighbor and 'interface' in current_neighbor and 'system-name' in current_neighbor:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_neighbor.get('interface', ''),
                remote_device=current_neighbor.get('system-name', ''),
                remote_port=current_neighbor.get('port-id', ''),
                remote_description=current_neighbor.get('port-description')
            ))

        return neighbors

    @staticmethod
    def parse_arista(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from Arista EOS"""
        neighbors = []

        # Parse "show lldp neighbors detail" output
        lines = output.split('\n')
        current_neighbor = {}

        for line in lines:
            line = line.strip()

            if line.startswith('Interface'):
                if current_neighbor and 'local_port' in current_neighbor:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_neighbor.get('local_port', ''),
                        remote_device=current_neighbor.get('remote_device', ''),
                        remote_port=current_neighbor.get('remote_port', ''),
                        remote_description=current_neighbor.get('remote_desc')
                    ))
                current_neighbor = {}
                # Parse: "Interface Ethernet1 detected 1 LLDP neighbors"
                match = re.search(r'Interface\s+(\S+)', line)
                if match:
                    current_neighbor['local_port'] = match.group(1)

            elif 'System Name:' in line or 'Neighbor Device ID:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_device'] = parts[1].strip().strip('"')

            elif 'Port ID:' in line or 'Neighbor Port ID:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_port'] = parts[1].strip().strip('"')

            elif 'Port Description:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_desc'] = parts[1].strip().strip('"')

        # Add last neighbor
        if current_neighbor and 'local_port' in current_neighbor:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_neighbor.get('local_port', ''),
                remote_device=current_neighbor.get('remote_device', ''),
                remote_port=current_neighbor.get('remote_port', ''),
                remote_description=current_neighbor.get('remote_desc')
            ))

        return neighbors

    @staticmethod
    def parse_aruba(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from HP Aruba"""
        neighbors = []

        # Parse "show lldp neighbors detail" output
        lines = output.split('\n')
        current_neighbor = {}

        for line in lines:
            line = line.strip()

            if line.startswith('Local Port'):
                if current_neighbor and 'local_port' in current_neighbor:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_neighbor.get('local_port', ''),
                        remote_device=current_neighbor.get('remote_device', ''),
                        remote_port=current_neighbor.get('remote_port', ''),
                        remote_description=current_neighbor.get('remote_desc')
                    ))
                current_neighbor = {}
                # Parse: "Local Port : 1/1/1"
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['local_port'] = parts[1].strip()

            elif 'System Name' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_device'] = parts[1].strip()

            elif 'Port ID' in line and 'remote_port' not in current_neighbor:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_port'] = parts[1].strip()

            elif 'Port Descr' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_desc'] = parts[1].strip()

        # Add last neighbor
        if current_neighbor and 'local_port' in current_neighbor:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_neighbor.get('local_port', ''),
                remote_device=current_neighbor.get('remote_device', ''),
                remote_port=current_neighbor.get('remote_port', ''),
                remote_description=current_neighbor.get('remote_desc')
            ))

        return neighbors

    @staticmethod
    def parse_ruijie(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from Ruijie switches and access points"""
        neighbors = []

        # Parse "show lldp neighbors detail" or "show lldp neighbor-information" output
        lines = output.split('\n')
        current_neighbor = {}

        for line in lines:
            line = line.strip()

            # Ruijie format: "Local Interface: GigabitEthernet 0/1"
            if line.startswith('Local Interface') or line.startswith('Local Port'):
                if current_neighbor and 'local_port' in current_neighbor:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_neighbor.get('local_port', ''),
                        remote_device=current_neighbor.get('remote_device', ''),
                        remote_port=current_neighbor.get('remote_port', ''),
                        remote_description=current_neighbor.get('remote_desc')
                    ))
                current_neighbor = {}
                # Parse interface name
                parts = line.split(':', 1)
                if len(parts) == 2:
                    port = parts[1].strip()
                    # Normalize port format (e.g., "GigabitEthernet 0/1" -> "Gi0/1")
                    port = re.sub(r'GigabitEthernet\s+', 'Gi', port)
                    port = re.sub(r'TenGigabitEthernet\s+', 'Te', port)
                    current_neighbor['local_port'] = port

            elif 'Chassis ID' in line or 'System Name' in line:
                parts = line.split(':', 1)
                if len(parts) == 2 and not current_neighbor.get('remote_device'):
                    current_neighbor['remote_device'] = parts[1].strip()

            elif 'Port ID' in line and 'remote_port' not in current_neighbor:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    port = parts[1].strip()
                    # Normalize port format
                    port = re.sub(r'GigabitEthernet\s+', 'Gi', port)
                    port = re.sub(r'TenGigabitEthernet\s+', 'Te', port)
                    current_neighbor['remote_port'] = port

            elif 'Port Description' in line or 'Port Desc' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_neighbor['remote_desc'] = parts[1].strip()

        # Add last neighbor
        if current_neighbor and 'local_port' in current_neighbor:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_neighbor.get('local_port', ''),
                remote_device=current_neighbor.get('remote_device', ''),
                remote_port=current_neighbor.get('remote_port', ''),
                remote_description=current_neighbor.get('remote_desc')
            ))

        return neighbors

    @staticmethod
    def parse_proxmox(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from Proxmox hosts (using lldpctl)"""
        # Proxmox uses lldpd, so we can reuse the Linux parser
        return LLDPParser.parse_linux(output, hostname)


class LLDPDiscovery:
    """Main LLDP discovery orchestrator"""

    def __init__(self, config_file: str, verbose: bool = False):
        self.config_file = config_file
        self.devices: List[DeviceConfig] = []
        self.neighbors: List[LLDPNeighbor] = []
        self.logger = self._setup_logging(verbose)

    def _setup_logging(self, verbose: bool) -> logging.Logger:
        """Setup logging configuration"""
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)

    def load_config(self) -> bool:
        """Load device configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)

            for device_data in config_data.get('devices', []):
                device = DeviceConfig(**device_data)
                self.devices.append(device)

            self.logger.info(f"Loaded {len(self.devices)} devices from configuration")
            return True

        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_file}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return False

    def test_device(self, device: DeviceConfig) -> bool:
        """Test SSH connectivity to a device"""
        self.logger.info(f"Testing connection to {device.hostname} ({device.ip_address})...")

        ssh = SSHConnection(device)
        if not ssh.connect():
            return False

        # Test command execution
        test_commands = {
            'linux': 'uname -a',
            'mikrotik': '/system identity print',
            'arista': 'show version',
            'aruba': 'show version',
            'ruijie': 'show version',
            'proxmox': 'uname -a'
        }

        command = test_commands.get(device.device_type, 'echo test')
        stdout, stderr, exit_code = ssh.execute_command(command)

        ssh.close()

        if exit_code == 0:
            self.logger.info(f"✓ {device.hostname} - Connection successful")
            return True
        else:
            self.logger.error(f"✗ {device.hostname} - Command execution failed")
            return False

    def test_all_devices(self) -> Dict[str, bool]:
        """Test connectivity to all configured devices"""
        results = {}

        self.logger.info("=" * 60)
        self.logger.info("Testing connectivity to all devices...")
        self.logger.info("=" * 60)

        for device in self.devices:
            results[device.hostname] = self.test_device(device)

        # Summary
        self.logger.info("=" * 60)
        success_count = sum(1 for v in results.values() if v)
        self.logger.info(f"Test Results: {success_count}/{len(results)} devices accessible")
        self.logger.info("=" * 60)

        return results

    def collect_lldp_neighbors(self, device: DeviceConfig) -> List[LLDPNeighbor]:
        """Collect LLDP neighbors from a specific device"""
        self.logger.info(f"Collecting LLDP data from {device.hostname}...")

        ssh = SSHConnection(device)
        if not ssh.connect():
            return []

        # Device-specific LLDP commands
        lldp_commands = {
            'linux': 'lldpctl',
            'mikrotik': '/interface lldp print detail',
            'arista': 'show lldp neighbors detail',
            'aruba': 'show lldp neighbors detail',
            'ruijie': 'show lldp neighbors detail',
            'proxmox': 'lldpctl'
        }

        command = lldp_commands.get(device.device_type)
        if not command:
            self.logger.error(f"Unknown device type: {device.device_type}")
            ssh.close()
            return []

        stdout, stderr, exit_code = ssh.execute_command(command)

        if exit_code != 0:
            self.logger.warning(f"LLDP command failed on {device.hostname}: {stderr}")
            ssh.close()
            return []

        # Parse output based on device type
        parsers = {
            'linux': LLDPParser.parse_linux,
            'mikrotik': LLDPParser.parse_mikrotik,
            'arista': LLDPParser.parse_arista,
            'aruba': LLDPParser.parse_aruba,
            'ruijie': LLDPParser.parse_ruijie,
            'proxmox': LLDPParser.parse_proxmox
        }

        parser = parsers.get(device.device_type)
        neighbors = parser(stdout, device.hostname)

        # Get port speeds for local ports
        if neighbors:
            local_ports = list(set([n.local_port for n in neighbors]))
            self.logger.debug(f"Detecting speeds for ports: {local_ports}")

            speed_detectors = {
                'linux': PortSpeedDetector.get_port_speeds_linux,
                'mikrotik': PortSpeedDetector.get_port_speeds_mikrotik,
                'arista': PortSpeedDetector.get_port_speeds_arista,
                'aruba': PortSpeedDetector.get_port_speeds_aruba,
                'ruijie': PortSpeedDetector.get_port_speeds_ruijie,
                'proxmox': PortSpeedDetector.get_port_speeds_proxmox
            }

            speed_detector = speed_detectors.get(device.device_type)
            if speed_detector:
                port_speeds = speed_detector(ssh, local_ports)

                # Assign speeds to neighbors
                for neighbor in neighbors:
                    neighbor.local_port_speed = port_speeds.get(neighbor.local_port, "Unknown")
                    self.logger.debug(f"{neighbor.local_port} speed: {neighbor.local_port_speed}")

        ssh.close()
        self.logger.info(f"Found {len(neighbors)} LLDP neighbors on {device.hostname}")
        return neighbors

    def discover_topology(self) -> bool:
        """Discover network topology by collecting LLDP data from all devices"""
        self.logger.info("=" * 60)
        self.logger.info("Starting LLDP network discovery...")
        self.logger.info("=" * 60)

        self.neighbors = []

        for device in self.devices:
            neighbors = self.collect_lldp_neighbors(device)
            self.neighbors.extend(neighbors)

        self.logger.info("=" * 60)
        self.logger.info(f"Discovery complete. Found {len(self.neighbors)} neighbor relationships")
        self.logger.info("=" * 60)

        return len(self.neighbors) > 0

    def export_to_json(self, output_file: str):
        """Export discovered topology to JSON"""
        data = {
            'devices': [device.hostname for device in self.devices],
            'connections': [asdict(neighbor) for neighbor in self.neighbors]
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"Topology exported to {output_file}")

    def visualize_topology(self, output_file: str = 'network_topology.png'):
        """Generate graphical visualization of network topology"""
        if not GRAPHVIZ_AVAILABLE:
            self.logger.error("Visualization requires networkx and matplotlib")
            return

        # Create directed graph
        G = nx.Graph()  # Using undirected graph since LLDP is bidirectional

        # Add all devices as nodes
        for device in self.devices:
            G.add_node(device.hostname, device_type=device.device_type)

        # Add edges with port information
        edge_labels = {}
        for neighbor in self.neighbors:
            # Create edge
            G.add_edge(neighbor.local_device, neighbor.remote_device)

            # Store port information for edge labels
            edge_key = (neighbor.local_device, neighbor.remote_device)
            if edge_key not in edge_labels:
                edge_labels[edge_key] = f"{neighbor.local_port}\n↕\n{neighbor.remote_port}"

        # Create visualization
        plt.figure(figsize=(16, 12))

        # Use spring layout for better spacing
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

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
                              node_size=3000, alpha=0.9,
                              edgecolors='black', linewidths=2)

        # Draw edges
        nx.draw_networkx_edges(G, pos, width=2, alpha=0.6, edge_color='#7f8c8d')

        # Draw labels
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')

        # Draw edge labels (port information)
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=8,
                                     bbox=dict(boxstyle='round,pad=0.3',
                                             facecolor='white', alpha=0.7))

        # Create legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['linux'],
                      markersize=10, label='Linux'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['mikrotik'],
                      markersize=10, label='MikroTik'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['arista'],
                      markersize=10, label='Arista'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['aruba'],
                      markersize=10, label='HP Aruba'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['ruijie'],
                      markersize=10, label='Ruijie'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map['proxmox'],
                      markersize=10, label='Proxmox'),
        ]
        plt.legend(handles=legend_elements, loc='upper left', fontsize=10)

        plt.title('LLDP Network Topology', fontsize=16, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()

        # Save to file
        plt.savefig(output_file, dpi=300, bbox_inches='tight',
                   facecolor='white', edgecolor='none')
        self.logger.info(f"Network topology visualization saved to {output_file}")

        # Optionally display
        # plt.show()

    def print_topology_summary(self):
        """Print a text summary of the discovered topology"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("NETWORK TOPOLOGY SUMMARY")
        self.logger.info("=" * 60)

        # Group by local device
        device_connections = defaultdict(list)
        for neighbor in self.neighbors:
            device_connections[neighbor.local_device].append(neighbor)

        for device in sorted(device_connections.keys()):
            self.logger.info(f"\n{device}:")
            for neighbor in sorted(device_connections[device], key=lambda x: x.local_port):
                speed_info = f"[{neighbor.local_port_speed}]" if neighbor.local_port_speed else ""
                self.logger.info(f"  {neighbor.local_port:15} {speed_info:8} -> {neighbor.remote_device:20} ({neighbor.remote_port})")

        self.logger.info("\n" + "=" * 60)


def create_sample_config(filename: str = 'devices.json'):
    """Create a sample configuration file"""
    sample_config = {
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
            },
            {
                "hostname": "arista-switch-01",
                "ip_address": "192.168.1.20",
                "device_type": "arista",
                "username": "admin",
                "password": "your_password_here",
                "port": 22
            },
            {
                "hostname": "aruba-switch-01",
                "ip_address": "192.168.1.30",
                "device_type": "aruba",
                "username": "admin",
                "password": "your_password_here",
                "port": 22
            },
            {
                "hostname": "ruijie-ap-01",
                "ip_address": "192.168.1.40",
                "device_type": "ruijie",
                "username": "admin",
                "password": "your_password_here",
                "port": 22
            },
            {
                "hostname": "proxmox-host-01",
                "ip_address": "192.168.1.50",
                "device_type": "proxmox",
                "username": "root",
                "password": "your_password_here",
                "port": 22
            }
        ]
    }

    with open(filename, 'w') as f:
        json.dump(sample_config, f, indent=2)

    print(f"Sample configuration file created: {filename}")
    print("Please edit this file with your actual device information.")


def main():
    parser = argparse.ArgumentParser(
        description='LLDP Network Discovery Tool - Discover and visualize network topology',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create sample configuration file
  %(prog)s --create-config

  # Test connectivity to all devices
  %(prog)s --test-all devices.json

  # Test specific device
  %(prog)s --test linux-server-01 devices.json

  # Discover and visualize network topology
  %(prog)s devices.json

  # Discover with custom output files
  %(prog)s devices.json --output topology.json --graph network.png

  # Verbose mode for debugging
  %(prog)s -v devices.json
        """
    )

    parser.add_argument('config', nargs='?', help='JSON configuration file with device information')
    parser.add_argument('--create-config', action='store_true',
                       help='Create a sample configuration file')
    parser.add_argument('--test-all', action='store_true',
                       help='Test connectivity to all configured devices')
    parser.add_argument('--test', metavar='HOSTNAME',
                       help='Test connectivity to a specific device')
    parser.add_argument('--output', '-o', default='topology.json',
                       help='Output JSON file for topology data (default: topology.json)')
    parser.add_argument('--graph', '-g', default='network_topology.png',
                       help='Output file for network visualization (default: network_topology.png)')
    parser.add_argument('--no-graph', action='store_true',
                       help='Skip generating graphical visualization')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Handle config file creation
    if args.create_config:
        create_sample_config()
        return 0

    # Require config file for other operations
    if not args.config:
        parser.print_help()
        return 1

    # Initialize discovery
    discovery = LLDPDiscovery(args.config, verbose=args.verbose)

    if not discovery.load_config():
        return 1

    # Test mode
    if args.test_all:
        discovery.test_all_devices()
        return 0

    if args.test:
        # Find specific device
        device = next((d for d in discovery.devices if d.hostname == args.test), None)
        if not device:
            print(f"Error: Device '{args.test}' not found in configuration")
            return 1
        success = discovery.test_device(device)
        return 0 if success else 1

    # Main discovery mode
    if not discovery.discover_topology():
        print("Warning: No LLDP neighbors discovered")

    # Print summary
    discovery.print_topology_summary()

    # Export to JSON
    discovery.export_to_json(args.output)

    # Generate visualization
    if not args.no_graph:
        discovery.visualize_topology(args.graph)

    return 0


if __name__ == '__main__':
    sys.exit(main())
