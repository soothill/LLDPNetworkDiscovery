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
from math import cos, sin

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

    def execute_command(self, command: str, request_pty: bool = None) -> Tuple[str, str, int]:
        """Execute command on remote device

        Args:
            command: Command to execute
            request_pty: Whether to request a pseudo-TTY. If None, auto-detect based on command.
        """
        if not self.client:
            return "", "Not connected", 1

        # Auto-detect PTY requirement if not specified
        if request_pty is None:
            # Only request PTY for sudo commands (needed for Linux/Proxmox)
            request_pty = 'sudo' in command

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout, get_pty=request_pty)

            # Normal flow: wait for exit status first, then read output
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')

            # When get_pty=True, stderr is redirected to stdout, so we need to handle this
            # If stderr is empty but command failed, the error is in stdout
            if request_pty and exit_code != 0 and not stderr_data and stdout_data:
                # Check if stdout contains error messages
                if 'permission denied' in stdout_data.lower() or 'command not found' in stdout_data.lower():
                    stderr_data = stdout_data

            return stdout_data, stderr_data, exit_code
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
            # Try ethtool first (with sudo for permission)
            stdout, stderr, exit_code = ssh.execute_command(f"sudo ethtool {port} 2>/dev/null | grep -i speed")
            if exit_code == 0 and stdout:
                # Parse "Speed: 1000Mb/s" or "Speed: 10000Mb/s"
                match = re.search(r'Speed:\s*(\d+)Mb/s', stdout, re.IGNORECASE)
                if match:
                    speed_mbps = int(match.group(1))
                    speeds[port] = PortSpeedDetector._format_speed(speed_mbps)
                    continue

            # Fallback: try /sys/class/net (usually readable without sudo)
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

        # Use ethernet print command for speed info
        stdout, stderr, exit_code = ssh.execute_command('/interface ethernet print detail without-paging')

        if exit_code == 0:
            current_interface = None
            current_rate = None

            for line in stdout.split('\n'):
                line = line.strip()

                # Match interface name (e.g., "name=ether1" or just line starting with number)
                name_match = re.search(r'name[=:]\s*"?([^"\s,]+)"?', line)
                if name_match:
                    # Save previous interface if we had one
                    if current_interface and current_rate and current_interface in ports:
                        speeds[current_interface] = current_rate

                    current_interface = name_match.group(1)
                    current_rate = None

                # Match rate/speed (can be "rate:", "rate=", or "speed:")
                if current_interface:
                    # Try different patterns for speed
                    speed_patterns = [
                        r'rate[=:]\s*(\d+[MG])',
                        r'speed[=:]\s*(\d+[MG])',
                        r'actual-rate[=:]\s*(\d+[MG])',
                        r'(\d+Mbps|\d+Gbps)'
                    ]

                    for pattern in speed_patterns:
                        rate_match = re.search(pattern, line, re.IGNORECASE)
                        if rate_match:
                            rate_str = rate_match.group(1)
                            # Normalize format
                            if 'Mbps' in rate_str or 'Gbps' in rate_str:
                                rate_str = rate_str.replace('bps', '').replace('M', 'M').replace('G', 'G')
                            current_rate = rate_str
                            break

            # Save last interface
            if current_interface and current_rate and current_interface in ports:
                speeds[current_interface] = current_rate

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
        """Parse LLDP output from MikroTik using /ip neighbor print detail

        Expected format (detail with key=value pairs):
         0 interface=ether1 address=10.10.201.5 mac-address=94:F1:28:8A:93:A1 identity="2930F-48"
           platform="HP Aruba" version="..." interface-name="1/1/1"
        """
        neighbors = []
        lines = output.split('\n')

        print(f"DEBUG: Parsing MikroTik detail output for {hostname}")
        print(f"DEBUG: Output length: {len(output)} chars")
        print(f"DEBUG: First 500 chars: {output[:500]}")

        current_entry = {}
        for line in lines:
            line = line.strip()

            # Skip empty lines and headers
            if not line or line.startswith('Flags:'):
                continue

            # New entry starts with a number
            if re.match(r'^\d+\s', line):
                # Save previous entry if complete
                if current_entry.get('interface') and current_entry.get('identity'):
                    print(f"DEBUG: Adding neighbor - Interface: {current_entry['interface']}, Identity: {current_entry['identity']}")
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_entry['interface'],
                        remote_device=current_entry['identity'],
                        remote_port=current_entry.get('interface-name', ''),
                        remote_description=current_entry.get('platform', '')
                    ))

                # Start new entry
                current_entry = {}
                # Remove the leading number
                line = re.sub(r'^\d+\s+', '', line)

            # Parse key=value pairs (handles quoted values)
            for match in re.finditer(r'(\S+?)=(".*?"|\'.*?\'|\S+)', line):
                key = match.group(1)
                value = match.group(2).strip('"\'')  # Remove quotes
                current_entry[key] = value
                print(f"DEBUG: Parsed {key}={value}")

        # Don't forget the last entry
        if current_entry.get('interface') and current_entry.get('identity'):
            print(f"DEBUG: Adding neighbor - Interface: {current_entry['interface']}, Identity: {current_entry['identity']}")
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_entry['interface'],
                remote_device=current_entry['identity'],
                remote_port=current_entry.get('interface-name', ''),
                remote_description=current_entry.get('platform', '')
            ))

        print(f"DEBUG: Total neighbors found for {hostname}: {len(neighbors)}")
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
        self.hostname_map = {}  # Maps LLDP identities to configured hostnames

    def _setup_logging(self, verbose: bool) -> logging.Logger:
        """Setup logging configuration"""
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)

    def _normalize_hostname(self, name: str) -> str:
        """Normalize a hostname for comparison

        Removes common suffixes and converts to lowercase for matching
        """
        if not name:
            return ""

        # Convert to lowercase
        normalized = name.lower().strip()

        # Remove common domain suffixes
        for suffix in ['.local', '.lan', '.home', '.internal']:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break

        # Remove manufacturer prefixes (e.g., "MikroTik " prefix)
        for prefix in ['mikrotik ', 'cisco ', 'hp ', 'arista ', 'aruba ']:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break

        return normalized

    def _find_matching_hostname(self, lldp_identity: str) -> str:
        """Find the configured hostname that matches an LLDP identity

        Returns the configured hostname, or the original LLDP identity if no match
        """
        normalized_identity = self._normalize_hostname(lldp_identity)

        # Check if we already have this mapping cached
        if lldp_identity in self.hostname_map:
            return self.hostname_map[lldp_identity]

        # Try to find a matching configured device
        for device in self.devices:
            normalized_device = self._normalize_hostname(device.hostname)

            # Exact match after normalization
            if normalized_identity == normalized_device:
                self.hostname_map[lldp_identity] = device.hostname
                return device.hostname

            # Partial match (identity contains device name or vice versa)
            if normalized_identity in normalized_device or normalized_device in normalized_identity:
                self.hostname_map[lldp_identity] = device.hostname
                return device.hostname

        # No match found, return original identity
        self.hostname_map[lldp_identity] = lldp_identity
        return lldp_identity

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
            'linux': 'sudo lldpctl',
            'mikrotik': '/ip neighbor print detail without-paging where identity!=""',
            'arista': 'show lldp neighbors detail',
            'aruba': 'show lldp neighbors detail',
            'ruijie': 'show lldp neighbors detail',
            'proxmox': 'sudo lldpctl'
        }

        command = lldp_commands.get(device.device_type)
        if not command:
            self.logger.error(f"Unknown device type: {device.device_type}")
            ssh.close()
            return []

        # Don't use PTY - it causes interactive mode issues
        request_pty = False  # Don't use PTY for any device by default (only sudo needs it)
        stdout, stderr, exit_code = ssh.execute_command(command, request_pty=request_pty)

        if exit_code != 0:
            self.logger.error(f"LLDP command failed on {device.hostname}")
            self.logger.error(f"  Command: {command}")
            self.logger.error(f"  Exit code: {exit_code}")
            self.logger.error(f"  Stderr: {stderr}")
            self.logger.error(f"  Stdout: {stdout[:500]}")  # First 500 chars of stdout for context

            # Special handling for Linux/Proxmox sudo issues
            # Check both stderr and stdout (PTY mode redirects stderr to stdout)
            combined_output = (stderr + stdout).lower()
            if device.device_type in ['linux', 'proxmox'] and ('sudo' in combined_output or 'permission denied' in combined_output or 'lldpctl' in combined_output):
                self.logger.error("")
                self.logger.error("=" * 60)
                self.logger.error("SUDO CONFIGURATION REQUIRED")
                self.logger.error("=" * 60)
                self.logger.error(f"The user '{device.username}' needs sudo access for lldpctl on {device.hostname}")
                self.logger.error("")
                self.logger.error("Step 1: Create sudoers file for lldp:")
                self.logger.error("  sudo visudo -f /etc/sudoers.d/lldp")
                self.logger.error("")
                self.logger.error("Step 2: Add this line (supports both /usr/bin and /usr/sbin paths):")
                self.logger.error(f"  {device.username} ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool")
                self.logger.error("")
                self.logger.error("Step 3: Save and exit (Ctrl+X, then Y in nano; :wq in vi)")
                self.logger.error("")
                self.logger.error("Alternative - Quick command (run on the Linux host):")
                self.logger.error(f"  echo '{device.username} ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool' | sudo tee /etc/sudoers.d/lldp")
                self.logger.error("  sudo chmod 0440 /etc/sudoers.d/lldp")
                self.logger.error("")
                self.logger.error("For multiple users, use a group instead:")
                self.logger.error("  %netadmin ALL=(ALL) NOPASSWD: /usr/bin/lldpctl, /usr/sbin/lldpctl, /usr/bin/ethtool, /usr/sbin/ethtool")
                self.logger.error("=" * 60)
                self.logger.error("")

            ssh.close()
            return []

        self.logger.debug(f"LLDP command succeeded on {device.hostname}")
        self.logger.debug(f"  Output length: {len(stdout)} chars")

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

        # Normalize hostnames in neighbor relationships
        self._normalize_neighbor_hostnames()

        self.logger.info("=" * 60)
        self.logger.info(f"Discovery complete. Found {len(self.neighbors)} neighbor relationships")
        self.logger.info("=" * 60)

        return len(self.neighbors) > 0

    def _is_physical_interface(self, interface_name: str) -> bool:
        """Check if an interface is physical (not virtual like VLAN, bridge, tunnel)"""
        if not interface_name:
            return False

        interface_lower = interface_name.lower()

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
            'tap',       # TAP device
        ]

        # Check if interface name contains any virtual pattern
        for pattern in virtual_patterns:
            if pattern in interface_lower:
                return False

        return True

    def _normalize_neighbor_hostnames(self):
        """Normalize LLDP identities to match configured hostnames and filter virtual interfaces"""
        filtered_neighbors = []

        for neighbor in self.neighbors:
            # Filter out virtual interfaces
            if not self._is_physical_interface(neighbor.local_port):
                self.logger.debug(f"Filtering virtual interface: {neighbor.local_device}:{neighbor.local_port}")
                continue

            # Normalize local device (should already match, but just in case)
            neighbor.local_device = self._find_matching_hostname(neighbor.local_device)

            # Normalize remote device (this is where LLDP identities may differ)
            original_remote = neighbor.remote_device
            neighbor.remote_device = self._find_matching_hostname(neighbor.remote_device)

            if original_remote != neighbor.remote_device:
                self.logger.debug(f"Normalized '{original_remote}' -> '{neighbor.remote_device}'")

            filtered_neighbors.append(neighbor)

        # Replace neighbors list with filtered version
        original_count = len(self.neighbors)
        self.neighbors = filtered_neighbors
        filtered_count = original_count - len(filtered_neighbors)

        if filtered_count > 0:
            self.logger.info(f"Filtered {filtered_count} virtual interface connections")

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

    def _get_speed_class(self, speed_str: Optional[str]) -> str:
        """Determine CSS class based on speed string"""
        if not speed_str or speed_str == "Unknown":
            return ""

        # Extract numeric value
        if "400G" in speed_str:
            return "speed-400g"
        elif "100G" in speed_str:
            return "speed-100g"
        elif "40G" in speed_str:
            return "speed-40g"
        elif "10G" in speed_str:
            return "speed-10g"
        elif "G" in speed_str:
            return "speed-1g"
        else:
            return ""

    def generate_html_visualization(self, output_file: str = 'network_topology.html'):
        """Generate interactive HTML visualization of network topology"""
        if not self.neighbors:
            self.logger.error("No topology data to visualize")
            return

        # Gather device statistics
        device_type_counts = defaultdict(int)
        for device in self.devices:
            device_type_counts[device.device_type] += 1

        # Build device info for tooltips
        device_info = {}
        for device in self.devices:
            device_info[device.hostname] = {
                'type': device.device_type,
                'ip': device.ip_address
            }

        # Build connection list with speeds
        connections = []
        processed_pairs = set()
        for neighbor in self.neighbors:
            pair = tuple(sorted([neighbor.local_device, neighbor.remote_device]))
            if pair not in processed_pairs:
                speed_local = f" [{neighbor.local_port_speed}]" if neighbor.local_port_speed else ""
                speed_remote = f" [{neighbor.remote_port_speed}]" if neighbor.remote_port_speed else ""
                connections.append({
                    'local_device': neighbor.local_device,
                    'local_port': neighbor.local_port,
                    'remote_device': neighbor.remote_device,
                    'remote_port': neighbor.remote_port,
                    'local_speed': neighbor.local_port_speed,
                    'remote_speed': neighbor.remote_port_speed,
                    'speed_class': self._get_speed_class(neighbor.local_port_speed)
                })
                processed_pairs.add(pair)

        # Generate HTML
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLDP Network Topology</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
            overflow-x: hidden;
        }}

        .container {{
            display: flex;
            height: 100vh;
        }}

        .sidebar {{
            width: 320px;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(20px);
            border-right: 1px solid rgba(148, 163, 184, 0.1);
            padding: 2rem;
            overflow-y: auto;
        }}

        .header {{
            margin-bottom: 2rem;
        }}

        h1 {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: #94a3b8;
            font-size: 0.875rem;
        }}

        .card {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
        }}

        .card-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}

        .card-icon {{
            font-size: 1.25rem;
        }}

        .card-title {{
            font-size: 1rem;
            font-weight: 600;
        }}

        .legend-items {{
            display: flex;
            flex-direction: column;
            gap: 0.625rem;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.875rem;
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }}

        .legend-item:hover {{
            background: rgba(255, 255, 255, 0.08);
            transform: translateX(4px);
        }}

        .legend-color {{
            width: 36px;
            height: 36px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }}

        .legend-info {{
            flex: 1;
        }}

        .legend-label {{
            font-weight: 500;
            color: #fff;
            font-size: 0.95rem;
        }}

        .legend-count {{
            font-size: 0.8rem;
            opacity: 0.6;
            margin-top: 0.125rem;
        }}

        /* Speed Legend Table */
        .speed-legend-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }}

        .speed-legend-table tr {{
            transition: background 0.2s ease;
        }}

        .speed-legend-table tr:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}

        .speed-line-cell {{
            width: 50px;
            padding: 0.6rem 0.75rem;
            vertical-align: middle;
        }}

        .speed-label-cell {{
            padding: 0.6rem 0.75rem;
            font-size: 0.9rem;
            font-weight: 500;
            color: rgba(226, 232, 240, 0.95);
            vertical-align: middle;
        }}

        .speed-line {{
            height: 0;
            border-radius: 2px;
        }}

        .speed-line.speed-1g {{
            border-top: 2px solid rgba(96, 165, 250, 0.9);
        }}

        .speed-line.speed-10g {{
            border-top: 3px solid rgba(52, 211, 153, 0.9);
        }}

        .speed-line.speed-40g {{
            border-top: 4px solid rgba(251, 191, 36, 0.9);
        }}

        .speed-line.speed-100g {{
            border-top: 5px solid rgba(249, 115, 22, 0.9);
        }}

        .speed-line.speed-400g {{
            border-top: 6px solid rgba(239, 68, 68, 0.9);
            filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.4));
        }}

        .connection-list {{
            max-height: 400px;
            overflow-y: auto;
        }}

        .connection-item {{
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 6px;
            margin-bottom: 0.5rem;
            font-size: 0.85rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }}

        .main-content {{
            flex: 1;
            padding: 2rem;
            overflow: hidden;
        }}

        .topology-container {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 16px;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        svg {{
            max-width: 100%;
            max-height: 100%;
        }}

        .node {{
            cursor: pointer;
            transition: all 0.3s ease;
        }}

        .node:hover {{
            filter: brightness(1.2);
        }}

        .node circle {{
            filter: drop-shadow(0 4px 12px rgba(0, 0, 0, 0.4));
        }}

        .node text {{
            fill: #fff;
            font-weight: 600;
            font-size: 14px;
            text-anchor: middle;
            pointer-events: none;
        }}

        .link {{
            stroke: rgba(148, 163, 184, 0.4);
            stroke-width: 2;
            transition: all 0.3s ease;
        }}

        .link.speed-1g {{
            stroke: rgba(96, 165, 250, 0.5);
            stroke-width: 2;
        }}

        .link.speed-10g {{
            stroke: rgba(52, 211, 153, 0.6);
            stroke-width: 3;
        }}

        .link.speed-40g {{
            stroke: rgba(251, 191, 36, 0.7);
            stroke-width: 4;
        }}

        .link.speed-100g {{
            stroke: rgba(249, 115, 22, 0.8);
            stroke-width: 5;
        }}

        .link.speed-400g {{
            stroke: rgba(239, 68, 68, 0.9);
            stroke-width: 6;
            filter: drop-shadow(0 0 8px rgba(239, 68, 68, 0.5));
        }}

        .port-label {{
            fill: #94a3b8;
            font-size: 11px;
            text-anchor: middle;
        }}

        .tooltip {{
            position: absolute;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(148, 163, 184, 0.2);
            padding: 1rem;
            border-radius: 8px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 1000;
        }}

        .tooltip.show {{
            opacity: 1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="header">
                <h1>Network Topology</h1>
                <p class="subtitle">LLDP Discovery Results</p>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">🖥️</div>
                    <h3 class="card-title">Device Types</h3>
                </div>
                <div class="legend-items">
'''

        # Add device type legend items
        device_colors = {
            'linux': '#3498db',
            'mikrotik': '#e74c3c',
            'arista': '#2ecc71',
            'aruba': '#f39c12',
            'ruijie': '#9b59b6',
            'proxmox': '#1abc9c'
        }

        device_labels = {
            'linux': 'Linux',
            'mikrotik': 'MikroTik',
            'arista': 'Arista EOS',
            'aruba': 'HP Aruba',
            'ruijie': 'Ruijie',
            'proxmox': 'Proxmox VE'
        }

        for dtype, count in sorted(device_type_counts.items()):
            color = device_colors.get(dtype, '#95a5a6')
            label = device_labels.get(dtype, dtype.title())
            device_word = "device" if count == 1 else "devices"
            html_content += f'''                    <div class="legend-item" data-type="{dtype}">
                        <div class="legend-color" style="background: {color};"></div>
                        <div class="legend-info">
                            <div class="legend-label">{label}</div>
                            <div class="legend-count">{count} {device_word}</div>
                        </div>
                    </div>
'''

        html_content += '''                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">⚡</div>
                    <h3 class="card-title">Link Speeds</h3>
                </div>
                <table class="speed-legend-table">
                    <tbody>
                        <tr>
                            <td class="speed-line-cell">
                                <div class="speed-line speed-1g"></div>
                            </td>
                            <td class="speed-label-cell">1 Gbps</td>
                        </tr>
                        <tr>
                            <td class="speed-line-cell">
                                <div class="speed-line speed-10g"></div>
                            </td>
                            <td class="speed-label-cell">10 Gbps</td>
                        </tr>
                        <tr>
                            <td class="speed-line-cell">
                                <div class="speed-line speed-40g"></div>
                            </td>
                            <td class="speed-label-cell">40 Gbps</td>
                        </tr>
                        <tr>
                            <td class="speed-line-cell">
                                <div class="speed-line speed-100g"></div>
                            </td>
                            <td class="speed-label-cell">100 Gbps</td>
                        </tr>
                        <tr>
                            <td class="speed-line-cell">
                                <div class="speed-line speed-400g"></div>
                            </td>
                            <td class="speed-label-cell">400 Gbps</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">🔌</div>
                    <h3 class="card-title">Connections</h3>
                </div>
                <div class="connection-list">
'''

        # Add connection items
        for conn in connections:
            speed_local = f" [{conn['local_speed']}]" if conn['local_speed'] else ""
            speed_remote = f" [{conn['remote_speed']}]" if conn['remote_speed'] else ""
            html_content += f'''                    <div class="connection-item">{conn['local_device']}:{conn['local_port']}{speed_local} ↔ {conn['remote_device']}:{conn['remote_port']}{speed_remote}</div>
'''

        html_content += '''                </div>
            </div>
        </div>

        <div class="main-content">
            <div class="topology-container">
                <svg width="1000" height="800" viewBox="0 0 1000 800">
                    <defs>
                        <filter id="glow">
                            <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
                            <feMerge>
                                <feMergeNode in="coloredBlur"/>
                                <feMergeNode in="SourceGraphic"/>
                            </feMerge>
                        </filter>
                    </defs>

                    <g id="links">
'''

        # Simple circular layout for nodes
        num_devices = len(self.devices)
        center_x, center_y = 500, 400
        radius = 300
        device_positions = {}

        for i, device in enumerate(sorted(self.devices, key=lambda d: d.hostname)):
            angle = (2 * 3.14159 * i) / num_devices - (3.14159 / 2)  # Start from top
            x = center_x + radius * cos(angle)
            y = center_y + radius * sin(angle)
            device_positions[device.hostname] = (x, y)

        # Draw links
        for conn in connections:
            if conn['local_device'] in device_positions and conn['remote_device'] in device_positions:
                x1, y1 = device_positions[conn['local_device']]
                x2, y2 = device_positions[conn['remote_device']]
                speed_class = conn['speed_class']

                html_content += f'''                        <line class="link {speed_class}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>
'''

                # Add port labels at midpoint
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                speed_label = f" [{conn['local_speed']}]" if conn['local_speed'] else ""
                html_content += f'''                        <text class="port-label" x="{mid_x}" y="{mid_y - 5}">{conn['local_port']}{speed_label}</text>
'''

        html_content += '''                    </g>

                    <g id="nodes">
'''

        # Draw nodes
        for device in sorted(self.devices, key=lambda d: d.hostname):
            if device.hostname in device_positions:
                x, y = device_positions[device.hostname]
                color = device_colors.get(device.device_type, '#95a5a6')

                html_content += f'''                        <g class="node" data-device="{device.hostname}">
                            <circle cx="{x}" cy="{y}" r="40" fill="{color}" filter="url(#glow)"/>
                            <text x="{x}" y="{y + 5}">{device.hostname[:12]}</text>
                        </g>
'''

        html_content += '''                    </g>
                </svg>
            </div>
        </div>
    </div>

    <div class="tooltip" id="tooltip"></div>

    <script>
        const tooltip = document.getElementById('tooltip');

        // Build connection map from topology data
        const deviceConnections = {};
'''

        # Build JavaScript connection map from actual discovered neighbors
        for neighbor in self.neighbors:
            local_dev = neighbor.local_device
            if local_dev not in [d.hostname for d in self.devices]:
                continue

            if 'deviceConnections' not in locals():
                deviceConnections = defaultdict(list)

            conn_info = {
                'local': neighbor.local_port,
                'remote': neighbor.remote_device,
                'remotePort': neighbor.remote_port,
                'speed': neighbor.local_port_speed or 'Unknown'
            }

            # Add to JavaScript
            html_content += f'''
        if (!deviceConnections['{local_dev}']) deviceConnections['{local_dev}'] = [];
        deviceConnections['{local_dev}'].push({{
            local: '{neighbor.local_port}',
            remote: '{neighbor.remote_device}',
            remotePort: '{neighbor.remote_port}',
            speed: '{neighbor.local_port_speed or "Unknown"}'
        }});'''

        html_content += '''

        // Add interactivity
        document.querySelectorAll('.node').forEach(node => {
            node.addEventListener('mouseenter', (e) => {
                const deviceName = e.currentTarget.getAttribute('data-device');
                const connections = deviceConnections[deviceName] || [];

                // Build connected interfaces list
                let connectionsHTML = '';
                if (connections.length > 0) {
                    connectionsHTML = connections.map(conn =>
                        `<div style="margin-left: 1rem; font-size: 0.85rem; color: rgba(226, 232, 240, 0.8); margin-top: 0.25rem;">
                            ${conn.local} [${conn.speed}] → ${conn.remote}:${conn.remotePort}
                        </div>`
                    ).join('');
                } else {
                    connectionsHTML = '<div style="margin-left: 1rem; font-size: 0.85rem; color: rgba(226, 232, 240, 0.6);">No connections</div>';
                }

                tooltip.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 0.5rem; font-size: 1.1rem;">${deviceName}</div>
                    <div style="font-weight: 500; margin-bottom: 0.25rem;">Connections:</div>
                    ${connectionsHTML}
                `;
                tooltip.classList.add('show');
            });

            node.addEventListener('mousemove', (e) => {
                const padding = 8;

                // Get actual tooltip dimensions
                const tooltipRect = tooltip.getBoundingClientRect();
                const tooltipWidth = tooltipRect.width || 300;
                const tooltipHeight = tooltipRect.height || 200;

                let left = e.clientX + padding;
                let top = e.clientY + padding;

                // Check if tooltip would go off right edge
                if (left + tooltipWidth > window.innerWidth) {
                    // Position to left of cursor instead
                    left = e.clientX - tooltipWidth - padding;
                }

                // Check if tooltip would go off bottom edge
                if (top + tooltipHeight > window.innerHeight) {
                    // Position above cursor instead
                    top = e.clientY - tooltipHeight - padding;
                }

                // Ensure tooltip doesn't go off left edge
                if (left < padding) {
                    left = padding;
                }

                // Ensure tooltip doesn't go off top edge
                if (top < padding) {
                    top = padding;
                }

                tooltip.style.left = left + 'px';
                tooltip.style.top = top + 'px';
            });

            node.addEventListener('mouseleave', () => {
                tooltip.classList.remove('show');
            });
        });
    </script>
</body>
</html>
'''

        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Interactive HTML visualization saved to {output_file}")


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
    parser.add_argument('--html', default='network_topology.html',
                       help='Generate interactive HTML visualization (default: network_topology.html, use --no-html to disable)')
    parser.add_argument('--no-html', action='store_true',
                       help='Skip generating HTML visualization')
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

    # Generate HTML visualization by default (unless --no-html is specified)
    if not args.no_html and args.html:
        discovery.generate_html_visualization(args.html)

    return 0


if __name__ == '__main__':
    sys.exit(main())
