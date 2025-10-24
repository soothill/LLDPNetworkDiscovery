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
from datetime import datetime

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
    enable_password: Optional[str] = None  # For devices requiring enable mode (Aruba, Cisco, etc.)


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
            # Use AutoAddPolicy to accept unknown host keys (common for network devices)
            # This is safe for network discovery tools
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Also load system host keys to avoid "Invalid key" errors with known hosts
            try:
                self.client.load_system_host_keys()
            except Exception as e:
                self.logger.debug(f"Could not load system host keys: {e}")

            # Enable legacy algorithms for older network devices
            # Get the default transport to modify security options
            transport = self.client.get_transport() if hasattr(self.client, 'get_transport') else None

            connect_params = {
                'hostname': self.device.ip_address,
                'username': self.device.username,
                'port': self.device.port,
                'timeout': self.timeout,
                'look_for_keys': False,
                'allow_agent': False,
                'disabled_algorithms': {
                    # Don't disable anything - allow all algorithms including legacy ones
                }
            }

            # Define keyboard-interactive handler for HP Aruba switches
            def auth_handler(title, instructions, prompt_list):
                """Handle keyboard-interactive authentication (used by HP Aruba)"""
                answers = []
                for prompt in prompt_list:
                    self.logger.debug(f"Keyboard-interactive prompt: {prompt}")
                    # Return the password for any prompt (typically "Password: ")
                    if self.device.password:
                        answers.append(self.device.password)
                    else:
                        answers.append('')
                return answers

            if self.device.ssh_key:
                connect_params['key_filename'] = self.device.ssh_key
                self.logger.debug(f"Using SSH key authentication: {self.device.ssh_key}")
            elif self.device.password:
                # Provide password parameter - paramiko will try both password and keyboard-interactive
                connect_params['password'] = self.device.password
                self.logger.debug(f"Using password authentication with keyboard-interactive support (password length: {len(self.device.password)})")
            else:
                self.logger.error(f"No authentication method provided for {self.device.hostname}")
                return False

            # Suppress paramiko's internal logging temporarily to avoid verbose errors
            paramiko_logger = logging.getLogger("paramiko")
            original_level = paramiko_logger.level
            paramiko_logger.setLevel(logging.CRITICAL)

            # First attempt with legacy algorithm support
            try:
                self.client.connect(**connect_params)
                # Restore logging level on success
                paramiko_logger.setLevel(original_level)
            except paramiko.SSHException as e:
                # Restore logging level
                paramiko_logger.setLevel(original_level)
                if 'no acceptable host key' in str(e).lower() or 'incompatible' in str(e).lower():
                    self.logger.info(f"First connection attempt failed. Retrying {self.device.hostname} with legacy SSH algorithms...")

                    # Close and recreate client
                    self.client.close()
                    self.client = paramiko.SSHClient()
                    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Manually enable legacy algorithms by modifying Transport class defaults
                    # This is a workaround for older devices
                    import paramiko.transport as transport_module
                    from paramiko.pkey import PKey

                    # Store original values
                    original_preferred_keys = transport_module.Transport._preferred_keys
                    original_preferred_kex = transport_module.Transport._preferred_kex
                    original_key_info = transport_module.Transport._key_info.copy()

                    # Suppress paramiko logging for retry attempt
                    paramiko_logger.setLevel(logging.CRITICAL)

                    try:
                        # CRITICAL: Re-enable ssh-dss in _key_info (disabled in paramiko 2.9+)
                        # HP Aruba 2930F switches (Mocana SSH 5.8) REQUIRE ssh-dss!
                        dss_enabled = False
                        if 'ssh-dss' not in transport_module.Transport._key_info:
                            try:
                                from paramiko.dsskey import DSSKey
                                transport_module.Transport._key_info['ssh-dss'] = DSSKey
                                self.logger.info("✓ Re-enabled ssh-dss host key algorithm (REQUIRED for HP Aruba 2930F)")
                                dss_enabled = True
                            except ImportError:
                                self.logger.error("✗ Could not import DSSKey - ssh-dss will not be available!")
                                self.logger.error("   HP Aruba 2930F switches REQUIRE ssh-dss!")
                                self.logger.error("   Try: pip install paramiko==2.8.1")
                        else:
                            self.logger.debug("ssh-dss already available in _key_info")
                            dss_enabled = True

                        # Also enable ssh-rsa for other HP Aruba models
                        rsa_enabled = False
                        if 'ssh-rsa' not in transport_module.Transport._key_info:
                            try:
                                from paramiko.rsakey import RSAKey
                                transport_module.Transport._key_info['ssh-rsa'] = RSAKey
                                self.logger.debug("Re-enabled ssh-rsa host key algorithm")
                                rsa_enabled = True
                            except ImportError:
                                self.logger.debug("Could not import RSAKey")
                        else:
                            rsa_enabled = True

                        # Build list of available host key algorithms
                        # CRITICAL: ssh-dss MUST be FIRST for HP Aruba 2930F (Mocana SSH 5.8)!
                        available_keys = [
                            'ssh-dss',  # FIRST - Required for HP Aruba 2930F
                            'ssh-rsa',  # Second - For other HP Aruba models
                            'rsa-sha2-512',
                            'rsa-sha2-256',
                            'ssh-ed25519',
                            'ecdsa-sha2-nistp256',
                            'ecdsa-sha2-nistp384',
                            'ecdsa-sha2-nistp521',
                        ]

                        # Filter to only include keys that are actually available
                        final_keys = []
                        for key in available_keys:
                            if key in transport_module.Transport._key_info:
                                final_keys.append(key)
                                self.logger.debug(f"  ✓ {key} - available")
                            else:
                                self.logger.debug(f"  ✗ {key} - not available in _key_info")

                        if not final_keys:
                            self.logger.error("No host key algorithms available!")
                            raise

                        if 'ssh-dss' not in final_keys:
                            self.logger.error("WARNING: ssh-dss not in final key list - HP Aruba 2930F connection may fail!")

                        transport_module.Transport._preferred_keys = tuple(final_keys)
                        self.logger.info(f"Enabled {len(final_keys)} host key algorithms (ssh-dss={'YES' if 'ssh-dss' in final_keys else 'NO'}, ssh-rsa={'YES' if 'ssh-rsa' in final_keys else 'NO'})")

                        # Build list of available KEX algorithms
                        # CRITICAL: diffie-hellman-group14-sha1 MUST be available for HP Aruba 2930F
                        available_kex = []

                        # Try to add group14-sha1 FIRST (REQUIRED for HP Aruba 2930F - Mocana SSH 5.8)
                        try:
                            from paramiko.kex_group14 import KexGroup14SHA1
                            available_kex.append('diffie-hellman-group14-sha1')
                            self.logger.info("✓ Added diffie-hellman-group14-sha1 KEX (REQUIRED for HP Aruba 2930F)")
                        except ImportError:
                            # It might still be available even if we can't import the class
                            available_kex.append('diffie-hellman-group14-sha1')
                            self.logger.info("✓ Added diffie-hellman-group14-sha1 KEX (fallback)")

                        # Then add modern KEX algorithms
                        available_kex.extend([
                            'ecdh-sha2-nistp256',
                            'ecdh-sha2-nistp384',
                            'ecdh-sha2-nistp521',
                            'diffie-hellman-group16-sha512',
                            'diffie-hellman-group-exchange-sha256',
                            'diffie-hellman-group14-sha256',
                        ])

                        # Add group-exchange-sha1
                        available_kex.append('diffie-hellman-group-exchange-sha1')

                        # Try to add group1-sha1 (very old, often removed)
                        try:
                            from paramiko.kex_group1 import KexGroup1
                            available_kex.append('diffie-hellman-group1-sha1')
                            self.logger.debug("Added diffie-hellman-group1-sha1 KEX algorithm")
                        except ImportError:
                            self.logger.debug("diffie-hellman-group1-sha1 not available (very old algorithm)")

                        transport_module.Transport._preferred_kex = tuple(available_kex)
                        self.logger.debug(f"Enabled {len(available_kex)} KEX algorithms: {', '.join(available_kex[:3])}... (showing first 3)")

                        # Also enable legacy ciphers and MACs for very old devices
                        # Store original cipher and MAC preferences
                        original_ciphers = transport_module.Transport._preferred_ciphers
                        original_macs = transport_module.Transport._preferred_macs

                        # Add legacy ciphers (AES in CBC mode, 3DES)
                        legacy_ciphers = list(original_ciphers) if original_ciphers else []
                        legacy_ciphers.extend([
                            'aes128-cbc',
                            'aes192-cbc',
                            'aes256-cbc',
                            '3des-cbc',
                        ])
                        # Remove duplicates while preserving order
                        seen = set()
                        legacy_ciphers = [x for x in legacy_ciphers if not (x in seen or seen.add(x))]
                        transport_module.Transport._preferred_ciphers = tuple(legacy_ciphers)

                        # Add legacy MACs
                        legacy_macs = list(original_macs) if original_macs else []
                        legacy_macs.extend([
                            'hmac-sha1',
                            'hmac-sha1-96',
                            'hmac-md5',
                        ])
                        # Remove duplicates while preserving order
                        seen = set()
                        legacy_macs = [x for x in legacy_macs if not (x in seen or seen.add(x))]
                        transport_module.Transport._preferred_macs = tuple(legacy_macs)

                        self.logger.debug(f"Added {len(legacy_ciphers)} ciphers and {len(legacy_macs)} MACs (including legacy)")

                        # Retry connection with legacy algorithms
                        self.logger.debug(f"Attempting connection with {len(final_keys)} host key algorithms and {len(available_kex)} KEX algorithms")
                        self.client.connect(**connect_params)
                        self.logger.info(f"✓ Successfully connected to {self.device.hostname} using legacy SSH algorithms")
                    finally:
                        # Restore original values
                        transport_module.Transport._preferred_keys = original_preferred_keys
                        transport_module.Transport._preferred_kex = original_preferred_kex
                        transport_module.Transport._key_info = original_key_info
                        transport_module.Transport._preferred_ciphers = original_ciphers
                        transport_module.Transport._preferred_macs = original_macs
                        # Restore paramiko logging level
                        paramiko_logger.setLevel(original_level)
                else:
                    raise
            self.logger.debug(f"Successfully connected to {self.device.hostname} ({self.device.ip_address})")
            return True

        except paramiko.AuthenticationException as auth_err:
            # Try explicit keyboard-interactive authentication as a fallback
            # HP Aruba switches often require this method
            self.logger.debug(f"Standard auth failed, trying keyboard-interactive: {auth_err}")

            if self.device.password:
                try:
                    self.logger.info(f"Retrying {self.device.hostname} with explicit keyboard-interactive authentication...")

                    # Get transport from the existing connection attempt
                    transport = self.client.get_transport()
                    if transport and transport.is_active():
                        # Define handler for keyboard-interactive auth
                        def handler(title, instructions, prompt_list):
                            if prompt_list:
                                self.logger.debug(f"Keyboard-interactive prompts: {[p[0] for p in prompt_list]}")
                            return [self.device.password] * len(prompt_list)

                        # Try keyboard-interactive auth
                        transport.auth_interactive(self.device.username, handler)
                        self.logger.info(f"✓ Successfully authenticated to {self.device.hostname} using keyboard-interactive")
                        return True
                except Exception as ki_err:
                    self.logger.debug(f"Keyboard-interactive auth also failed: {ki_err}")

            # If we get here, authentication truly failed
            self.logger.error("")
            self.logger.error("=" * 70)
            self.logger.error(f"✗ AUTHENTICATION FAILED - {self.device.hostname}")
            self.logger.error("=" * 70)
            self.logger.error(f"Device: {self.device.hostname} ({self.device.ip_address})")
            self.logger.error(f"Username: {self.device.username}")
            self.logger.error(f"Auth error: {auth_err}")
            self.logger.error("")
            self.logger.error("Possible causes:")
            self.logger.error("  1. Incorrect password")
            self.logger.error("  2. Invalid SSH key")
            self.logger.error("  3. User account disabled or locked")
            self.logger.error("  4. SSH authentication method not allowed on device")
            self.logger.error("")
            self.logger.error("Troubleshooting:")
            self.logger.error("  • Verify credentials in devices.json")
            self.logger.error("  • Check SSH key permissions: chmod 600 <keyfile>")
            self.logger.error("  • Test manually: ssh {0}@{1}".format(self.device.username, self.device.ip_address))
            self.logger.error("=" * 70)
            self.logger.error("")
            return False
        except paramiko.SSHException as e:
            if 'no acceptable host key' in str(e).lower() or 'incompatible' in str(e).lower():
                # This shouldn't happen as we already handled it above, but just in case
                self.logger.error("")
                self.logger.error("=" * 70)
                self.logger.error(f"✗ SSH COMPATIBILITY ERROR - {self.device.hostname}")
                self.logger.error("=" * 70)
                self.logger.error(f"Device: {self.device.hostname} ({self.device.ip_address})")
                self.logger.error(f"Error: Incompatible SSH algorithms")
                self.logger.error("")
                self.logger.error("This device uses legacy SSH algorithms that are not supported.")
                self.logger.error("")
                self.logger.error("Solutions:")
                self.logger.error("  1. Update device firmware to support modern SSH algorithms")
                self.logger.error("  2. Install older paramiko version: pip install paramiko==2.8.1")
                self.logger.error("  3. Configure SSH client to allow legacy algorithms")
                self.logger.error("")
                self.logger.error("For HP Aruba switches, ensure firmware is up to date:")
                self.logger.error("  • KB.16.10 or newer recommended")
                self.logger.error("  • WC.16.11 or newer for Aruba OS-CX")
                self.logger.error("")
                self.logger.error("Manual test commands to try:")
                self.logger.error(f"  ssh -oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group14-sha1 {self.device.username}@{self.device.ip_address}")
                self.logger.error(f"  ssh -oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group1-sha1 {self.device.username}@{self.device.ip_address}")
                self.logger.error("")
                self.logger.error("To see which algorithms work, run:")
                self.logger.error(f"  ssh -vvv {self.device.username}@{self.device.ip_address} 2>&1 | grep 'kex\\|host key\\|cipher\\|mac'")
                self.logger.error("=" * 70)
                self.logger.error("")
            else:
                self.logger.error("")
                self.logger.error("=" * 70)
                self.logger.error(f"✗ SSH CONNECTION ERROR - {self.device.hostname}")
                self.logger.error("=" * 70)
                self.logger.error(f"Device: {self.device.hostname} ({self.device.ip_address})")
                self.logger.error(f"Error: {e}")
                self.logger.error("")
                self.logger.error("Troubleshooting:")
                self.logger.error("  • Verify device is reachable: ping {0}".format(self.device.ip_address))
                self.logger.error("  • Check SSH is enabled on device")
                self.logger.error("  • Verify SSH port (default: 22)")
                self.logger.error("  • Check firewall rules")
                self.logger.error("=" * 70)
                self.logger.error("")
            return False
        except Exception as e:
            error_str = str(e).lower()
            if 'invalid key' in error_str or 'bad key' in error_str:
                self.logger.error("")
                self.logger.error("=" * 70)
                self.logger.error(f"✗ HOST KEY ERROR - {self.device.hostname}")
                self.logger.error("=" * 70)
                self.logger.error(f"Device: {self.device.hostname} ({self.device.ip_address})")
                self.logger.error(f"Error: {e}")
                self.logger.error("")
                self.logger.error("This error usually means there's a problem with the SSH host key.")
                self.logger.error("")
                self.logger.error("Solutions:")
                self.logger.error("  1. Remove the old host key from known_hosts:")
                self.logger.error(f"     ssh-keygen -R {self.device.ip_address}")
                self.logger.error("")
                self.logger.error("  2. Or remove the specific line from:")
                self.logger.error(f"     ~/.ssh/known_hosts")
                self.logger.error("")
                self.logger.error("  3. Then retry - the tool will auto-accept the new key")
                self.logger.error("")
                self.logger.error("This often happens when:")
                self.logger.error("  • Device was reinstalled/reset")
                self.logger.error("  • IP address was reassigned to different device")
                self.logger.error("  • Host key format changed (e.g., RSA to DSS)")
                self.logger.error("=" * 70)
                self.logger.error("")
            else:
                self.logger.error("")
                self.logger.error("=" * 70)
                self.logger.error(f"✗ CONNECTION ERROR - {self.device.hostname}")
                self.logger.error("=" * 70)
                self.logger.error(f"Device: {self.device.hostname} ({self.device.ip_address})")
                self.logger.error(f"Error: {e}")
                self.logger.error("")
                self.logger.error("Please check:")
                self.logger.error("  • Network connectivity to device")
                self.logger.error("  • Device configuration in devices.json")
                self.logger.error("  • Device is powered on and accessible")
                self.logger.error("=" * 70)
                self.logger.error("")
            return False

    def enter_enable_mode(self) -> bool:
        """Enter enable/privileged mode on devices that require it (Aruba, Cisco, etc.)"""
        if not self.device.enable_password:
            return True  # No enable password configured, assume already in correct mode

        try:
            # Use invoke_shell for interactive enable mode
            shell = self.client.invoke_shell()
            shell.settimeout(5)

            # Wait for initial prompt
            import time
            time.sleep(1)
            output = shell.recv(4096).decode('utf-8', errors='ignore')
            self.logger.debug(f"Initial prompt: {output[:100]}")

            # Check if there's a banner requiring space/enter to continue
            if '-- more --' in output.lower() or 'press any key' in output.lower():
                self.logger.debug("Detected banner screen in enable mode, sending space to continue")
                shell.send(' ')
                time.sleep(0.5)
                output += shell.recv(4096).decode('utf-8', errors='ignore')

            # Send enable command
            shell.send('enable\n')
            time.sleep(0.5)
            output = shell.recv(4096).decode('utf-8', errors='ignore')

            # Check if password prompt appeared
            if 'password' in output.lower():
                shell.send(self.device.enable_password + '\n')
                time.sleep(0.5)
                output = shell.recv(4096).decode('utf-8', errors='ignore')

                # Check for success (# prompt) or failure
                if '#' in output:
                    self.logger.debug(f"Successfully entered enable mode on {self.device.hostname}")
                    shell.close()
                    return True
                else:
                    self.logger.error(f"Enable password may be incorrect for {self.device.hostname}")
                    shell.close()
                    return False
            elif '#' in output:
                # Already in enable mode
                self.logger.debug(f"Already in enable mode on {self.device.hostname}")
                shell.close()
                return True
            else:
                self.logger.warning(f"Unexpected response when entering enable mode on {self.device.hostname}")
                shell.close()
                return True  # Continue anyway

        except Exception as e:
            self.logger.error(f"Error entering enable mode on {self.device.hostname}: {e}")
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

    def execute_shell_commands(self, commands: List[str], enable_mode: bool = False) -> List[Tuple[str, str, int]]:
        """Execute multiple commands in the same shell session (for devices like Aruba)

        Args:
            commands: List of commands to execute
            enable_mode: Whether device requires enable mode

        Returns:
            List of (stdout, stderr, exit_code) tuples, one per command
        """
        if not self.client:
            return [(("", "Not connected", 1))] * len(commands)

        results = []

        try:
            import time
            shell = self.client.invoke_shell(width=200, height=100)
            shell.settimeout(3)

            # Wait for prompt and clear any initial output
            time.sleep(1)
            try:
                initial_output = shell.recv(65535).decode('utf-8', errors='ignore')
                self.logger.debug(f"Initial shell output: {initial_output[:200]}")

                # Check if there's a banner requiring space/enter to continue
                if '-- more --' in initial_output.lower() or 'press any key' in initial_output.lower():
                    self.logger.debug("Detected banner screen, sending space to continue")
                    shell.send(' ')
                    time.sleep(0.5)
                    try:
                        shell.recv(65535)
                    except:
                        pass

                # Check for Arista "press RETURN" prompt
                if 'press return' in initial_output.lower() or 'press enter' in initial_output.lower():
                    self.logger.debug("Detected Arista 'press RETURN' prompt, sending enter")
                    shell.send('\n')
                    time.sleep(0.5)
                    try:
                        shell.recv(65535)  # Discard prompt continuation
                    except:
                        pass
            except:
                initial_output = ""

            # Enter enable mode if needed (within same shell session)
            if enable_mode and self.device.enable_password:
                self.logger.debug("Entering enable mode within shell session")
                try:
                    shell.send('enable\n')
                    time.sleep(0.5)
                    enable_output = shell.recv(65535).decode('utf-8', errors='ignore')
                    self.logger.debug(f"Enable response: {enable_output[:100]}")

                    if 'password' in enable_output.lower():
                        shell.send(self.device.enable_password + '\n')
                        time.sleep(0.5)
                        try:
                            shell.recv(65535)
                            self.logger.debug("Enable password sent")
                        except:
                            pass
                except Exception as e:
                    self.logger.warning(f"Error entering enable mode: {e}")

            # Disable terminal paging for Aruba/Arista/Ruijie devices
            if self.device.device_type in ['aruba', 'ruijie']:
                self.logger.debug("Disabling paging with 'no page' command")
                try:
                    shell.send('no page\n')
                    time.sleep(0.5)
                    shell.recv(65535)
                except Exception as e:
                    self.logger.debug(f"Error disabling paging (non-critical): {e}")
            elif self.device.device_type == 'arista':
                self.logger.debug("Disabling paging with 'terminal length 0' command")
                try:
                    shell.send('terminal length 0\n')
                    time.sleep(0.5)
                    shell.recv(65535)
                except Exception as e:
                    self.logger.debug(f"Error disabling paging (non-critical): {e}")

            # Execute each command in sequence
            for command in commands:
                self.logger.debug(f"Sending command: {command}")
                shell.send(command + '\n')
                time.sleep(1.0)

                # Collect output with timeout
                output = ""
                start_time = time.time()
                max_wait = 20
                last_output_time = start_time

                while (time.time() - start_time) < max_wait:
                    try:
                        chunk = shell.recv(65535).decode('utf-8', errors='ignore')
                        if chunk:
                            output += chunk
                            last_output_time = time.time()

                            lines = output.strip().split('\n')
                            if lines and (lines[-1].strip().endswith('>') or lines[-1].strip().endswith('#')):
                                self.logger.debug(f"Found prompt, command complete")
                                break
                        else:
                            if (time.time() - last_output_time) > 2:
                                self.logger.debug("No data for 2 seconds, assuming command complete")
                                break
                            time.sleep(0.1)
                    except Exception as e:
                        if output and (time.time() - last_output_time) > 1:
                            self.logger.debug(f"Recv timeout/exception after getting data: {e}")
                            break
                        time.sleep(0.1)

                # Strip ANSI escape sequences (common in Arista output)
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                output = ansi_escape.sub('', output)

                # Clean up output
                lines = output.split('\n')
                if len(lines) > 2:
                    cleaned_output = '\n'.join(lines[1:-1])
                else:
                    cleaned_output = output

                exit_code = 0 if cleaned_output.strip() else 1
                results.append((cleaned_output, "", exit_code))

            shell.close()
            return results

        except Exception as e:
            self.logger.error(f"Error executing shell commands on {self.device.hostname}: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            # Return error results for all remaining commands
            return results + [("", str(e), 1)] * (len(commands) - len(results))

    def execute_shell_command(self, command: str, enable_mode: bool = False) -> Tuple[str, str, int]:
        """Execute command using interactive shell (for devices like Aruba that need it)

        Args:
            command: Command to execute
            enable_mode: Whether device requires enable mode (will enter it if needed)
        """
        if not self.client:
            return "", "Not connected", 1

        try:
            import time
            shell = self.client.invoke_shell(width=200, height=100)
            shell.settimeout(3)  # Short timeout for non-blocking reads

            # Wait for prompt and clear any initial output
            time.sleep(1)
            try:
                initial_output = shell.recv(65535).decode('utf-8', errors='ignore')
                self.logger.debug(f"Initial shell output: {initial_output[:200]}")

                # Check if there's a banner requiring space/enter to continue
                # Common on HP Aruba switches
                if '-- more --' in initial_output.lower() or 'press any key' in initial_output.lower():
                    self.logger.debug("Detected banner screen, sending space to continue")
                    shell.send(' ')
                    time.sleep(0.5)
                    try:
                        shell.recv(65535)  # Discard banner continuation
                    except:
                        pass

                # Check for Arista "press RETURN" prompt
                if 'press return' in initial_output.lower() or 'press enter' in initial_output.lower():
                    self.logger.debug("Detected Arista 'press RETURN' prompt, sending enter")
                    shell.send('\n')
                    time.sleep(0.5)
                    try:
                        shell.recv(65535)  # Discard prompt continuation
                    except:
                        pass
            except:
                initial_output = ""

            # Enter enable mode if needed (within same shell session)
            if enable_mode and self.device.enable_password:
                self.logger.debug("Entering enable mode within shell session")
                try:
                    shell.send('enable\n')
                    time.sleep(0.5)
                    enable_output = shell.recv(65535).decode('utf-8', errors='ignore')
                    self.logger.debug(f"Enable response: {enable_output[:100]}")

                    if 'password' in enable_output.lower():
                        shell.send(self.device.enable_password + '\n')
                        time.sleep(0.5)
                        try:
                            shell.recv(65535)  # Discard password response
                            self.logger.debug("Enable password sent")
                        except:
                            pass
                except Exception as e:
                    self.logger.warning(f"Error entering enable mode: {e}")

            # Disable terminal paging for Aruba/Arista/Ruijie devices
            if self.device.device_type in ['aruba', 'ruijie']:
                self.logger.debug("Disabling paging with 'no page' command")
                try:
                    shell.send('no page\n')
                    time.sleep(0.5)
                    shell.recv(65535)  # Discard output
                except Exception as e:
                    self.logger.debug(f"Error disabling paging (non-critical): {e}")
            elif self.device.device_type == 'arista':
                self.logger.debug("Disabling paging with 'terminal length 0' command")
                try:
                    shell.send('terminal length 0\n')
                    time.sleep(0.5)
                    shell.recv(65535)  # Discard output
                except Exception as e:
                    self.logger.debug(f"Error disabling paging (non-critical): {e}")

            # Send command
            self.logger.debug(f"Sending command: {command}")
            shell.send(command + '\n')
            time.sleep(1.0)  # Give command more time to start executing

            # Collect output with timeout
            output = ""
            start_time = time.time()
            max_wait = 20  # Maximum 20 seconds for command
            last_output_time = start_time
            self.logger.debug("Collecting command output...")

            while (time.time() - start_time) < max_wait:
                try:
                    chunk = shell.recv(65535).decode('utf-8', errors='ignore')
                    if chunk:
                        output += chunk
                        last_output_time = time.time()

                        # Check if we got a prompt back (last line ends with > or #)
                        lines = output.strip().split('\n')
                        if lines and (lines[-1].strip().endswith('>') or lines[-1].strip().endswith('#')):
                            self.logger.debug(f"Found prompt, command complete")
                            break
                    else:
                        # No data received, check if we've been idle too long
                        if (time.time() - last_output_time) > 2:
                            self.logger.debug("No data for 2 seconds, assuming command complete")
                            break
                        time.sleep(0.1)
                except Exception as e:
                    # Timeout or no more data
                    if output and (time.time() - last_output_time) > 1:
                        self.logger.debug(f"Recv timeout/exception after getting data: {e}")
                        break
                    time.sleep(0.1)

            shell.close()

            self.logger.debug(f"Raw output length: {len(output)}")
            self.logger.debug(f"Raw output (first 500 chars): {output[:500]}")

            # Strip ANSI escape sequences (common in Arista output)
            # Pattern matches: ESC[...m (colors), ESC[K (erase line), ESC[...digit (cursor movement)
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            output = ansi_escape.sub('', output)

            # Clean up output - remove command echo and prompt
            lines = output.split('\n')
            # Remove first line (command echo) and last line (prompt)
            if len(lines) > 2:
                cleaned_output = '\n'.join(lines[1:-1])
            else:
                cleaned_output = output

            # Assume success if we got output
            exit_code = 0 if cleaned_output.strip() else 1

            return cleaned_output, "", exit_code

        except Exception as e:
            self.logger.error(f"Error executing shell command on {self.device.hostname}: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return "", str(e), 1

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.logger.debug(f"Closed connection to {self.device.hostname}")


class PortSpeedDetector:
    """Detects port speeds for different device types"""

    # Class variable to track if log has been initialized for this run
    _log_initialized = False

    @staticmethod
    def _clean_port_names(ports: List[str]) -> Dict[str, List[str]]:
        """
        Clean port names by removing suffixes like ",bridge", ",trunk", etc.
        Returns mapping of clean_name -> [list of original_names]

        Multiple ports may have the same clean name (e.g., "eth0,bridge" and "eth0,vlan100")
        so we need to map one clean name to multiple original names.
        """
        port_mapping = {}
        for port in ports:
            # Extract just the interface name before any comma
            clean_port = port.split(',')[0]
            if clean_port not in port_mapping:
                port_mapping[clean_port] = []
            port_mapping[clean_port].append(port)
        return port_mapping

    @staticmethod
    def _log_speed_detection(device_hostname: str, device_type: str, command: str, output: str, ports: List[str], parsed_speeds: Dict[str, str]):
        """Log speed detection details to a debug file for analysis"""
        try:
            log_filename = "speed_detection_debug.log"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Version identifier for debugging
            LOG_VERSION = "v2.7-d3-visualization-rewrite"

            # On first write of the run, clear the log file
            write_mode = 'w' if not PortSpeedDetector._log_initialized else 'a'
            if not PortSpeedDetector._log_initialized:
                PortSpeedDetector._log_initialized = True

            with open(log_filename, write_mode) as f:
                f.write("\n" + "=" * 100 + "\n")
                f.write(f"LOG VERSION: {LOG_VERSION}\n")
                f.write(f"TIMESTAMP: {timestamp}\n")
                f.write(f"DEVICE: {device_hostname} ({device_type})\n")
                f.write(f"COMMAND: {command}\n")
                f.write(f"PORTS REQUESTED: {', '.join(ports)}\n")
                f.write("-" * 100 + "\n")
                # Output parameter may already contain headers (e.g., "DEBUG INFO:\n...")
                f.write(output if output else "(empty output)\n")
                f.write("\n")
                f.write("-" * 100 + "\n")
                f.write("PARSED SPEEDS:\n")
                f.write("-" * 100 + "\n")
                for port, speed in sorted(parsed_speeds.items()):
                    f.write(f"  {port:20s} -> {speed}\n")
                f.write("=" * 100 + "\n\n")
        except Exception as e:
            # Don't fail if logging fails
            print(f"WARNING: Failed to write debug log: {e}")
            pass

    @staticmethod
    def get_port_speeds_linux(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Linux interfaces using ethtool"""
        speeds = {}
        all_output = []

        # Clean port names - remove suffixes like ",bridge"
        # Multiple ports may map to same clean name (e.g., "eth0,bridge" and "eth0,vlan100" -> "eth0")
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        for clean_port, original_ports in port_mapping.items():
            detected_speed = None

            # Try ethtool first (with sudo for permission)
            stdout, stderr, exit_code = ssh.execute_command(f"sudo ethtool {clean_port} 2>/dev/null | grep -i speed")
            all_output.append(f"Port {clean_port} (for {', '.join(original_ports)}) ethtool:\n{stdout if stdout else '(no output)'}\n")

            if exit_code == 0 and stdout:
                # Parse "Speed: 1000Mb/s" or "Speed: 10000Mb/s"
                match = re.search(r'Speed:\s*(\d+)Mb/s', stdout, re.IGNORECASE)
                if match:
                    speed_mbps = int(match.group(1))
                    detected_speed = PortSpeedDetector._format_speed(speed_mbps)

            # Fallback: try /sys/class/net (usually readable without sudo)
            if not detected_speed:
                stdout, stderr, exit_code = ssh.execute_command(f"cat /sys/class/net/{clean_port}/speed 2>/dev/null")
                all_output.append(f"Port {clean_port} /sys/class/net:\n{stdout if stdout else '(no output)'}\n")

                if exit_code == 0 and stdout.strip().isdigit():
                    speed_mbps = int(stdout.strip())
                    if speed_mbps > 0:
                        detected_speed = PortSpeedDetector._format_speed(speed_mbps)

            # Apply detected speed to ALL original port names that share this clean name
            if detected_speed:
                for original_port in original_ports:
                    speeds[original_port] = detected_speed
            else:
                for original_port in original_ports:
                    speeds[original_port] = "Unknown"

        # Log the detection results
        PortSpeedDetector._log_speed_detection(
            ssh.device.hostname, "Linux",
            "ethtool / /sys/class/net/*/speed",
            "\n".join(all_output),
            ports, speeds
        )

        return speeds

    @staticmethod
    def get_port_speeds_mikrotik(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for MikroTik interfaces"""
        speeds = {}
        debug_info = []

        # Clean port names - remove suffixes like ",bridge", ",trunk", ",OfficeAruba"
        port_mapping = PortSpeedDetector._clean_port_names(ports)
        debug_info.append(f"Port mapping: {port_mapping}")

        # Use ethernet print command for speed info
        stdout, stderr, exit_code = ssh.execute_command('/interface ethernet print detail without-paging')

        if exit_code == 0:
            current_interface = None
            current_speed = None
            advertise_speeds = []  # Accumulate across multiple lines
            in_advertise = False

            for line in stdout.split('\n'):
                line = line.strip()

                # Match interface name (e.g., "name=ether1" or "name=sfp-sfpplus1")
                name_match = re.search(r'name[=:]\s*"?([^"\s,]+)"?', line)
                if name_match:
                    # Save previous interface if we had one
                    if current_interface and current_speed:
                        # Check if this interface is in our cleaned port list
                        if current_interface in port_mapping:
                            debug_info.append(f"Saving {current_interface} = {current_speed} to ports: {port_mapping[current_interface]}")
                            # Apply to all original ports that map to this clean name
                            for original_port in port_mapping[current_interface]:
                                speeds[original_port] = current_speed
                        else:
                            debug_info.append(f"Skipping {current_interface} (not in port_mapping)")

                    current_interface = name_match.group(1)
                    current_speed = None
                    advertise_speeds = []
                    in_advertise = False
                    debug_info.append(f"Found interface: {current_interface}")

                # Match speed= field (actual negotiated speed)
                # Examples: "speed=10G-baseCR", "speed=40G-baseCR4", "speed=2.5G-baseT"
                if current_interface:
                    speed_match = re.search(r'speed=(\d+(?:\.\d+)?[GM])-base', line, re.IGNORECASE)
                    if speed_match:
                        speed_value = speed_match.group(1).upper()
                        # Normalize: "10G" stays "10G", "2.5G" stays "2.5G"
                        current_speed = speed_value
                        in_advertise = False  # Stop looking for advertise continuation
                        debug_info.append(f"  Found speed for {current_interface}: {current_speed}")
                        continue

                    # Check if we're starting or continuing an advertise= field
                    # Advertise can span multiple lines, so we accumulate speeds
                    if 'advertise=' in line:
                        in_advertise = True
                        advertise_speeds = []  # Reset for this interface

                    # If we're in advertise mode (current or continuation line)
                    if in_advertise and not current_speed:
                        # Check if this line has a new field= pattern (not advertise continuation)
                        # MikroTik continuation lines just have values, not field= patterns
                        if '=' in line and not line.startswith('advertise='):
                            # This is a new field, stop accumulating advertise speeds
                            # But first, finalize the advertised speed if we have any
                            if advertise_speeds:
                                def speed_value(s):
                                    num = float(re.search(r'([\d.]+)', s).group(1))
                                    return num * 1000 if 'G' in s else num
                                highest = max(advertise_speeds, key=speed_value)
                                current_speed = f"{highest} (adv)"
                                debug_info.append(f"  Found advertised speed for {current_interface}: {current_speed} from {advertise_speeds}")
                            in_advertise = False
                        else:
                            # Continue accumulating speeds from this line
                            for adv_match in re.finditer(r'(\d+(?:\.\d+)?)[GM]-base', line, re.IGNORECASE):
                                speed_str = adv_match.group(0)
                                num_match = re.search(r'(\d+(?:\.\d+)?[GM])', speed_str, re.IGNORECASE)
                                if num_match:
                                    advertise_speeds.append(num_match.group(1).upper())

            # Save last interface - check if we need to finalize advertise speeds first
            if current_interface:
                if not current_speed and advertise_speeds:
                    def speed_value(s):
                        num = float(re.search(r'([\d.]+)', s).group(1))
                        return num * 1000 if 'G' in s else num
                    highest = max(advertise_speeds, key=speed_value)
                    current_speed = f"{highest} (adv)"
                    debug_info.append(f"  Found advertised speed for last interface {current_interface}: {current_speed} from {advertise_speeds}")

                if current_speed:
                    if current_interface in port_mapping:
                        debug_info.append(f"Saving last interface {current_interface} = {current_speed} to ports: {port_mapping[current_interface]}")
                        # Apply to all original ports that map to this clean name
                        for original_port in port_mapping[current_interface]:
                            speeds[original_port] = current_speed
                    else:
                        debug_info.append(f"Skipping last interface {current_interface} (not in port_mapping)")

        # Fill in unknowns for originally requested ports
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        # Log the detection results with debug info
        log_output = ""
        if debug_info:
            log_output = "DEBUG INFO:\n" + "-" * 100 + "\n" + "\n".join(debug_info) + "\n" + "-" * 100 + "\n\n"
        log_output += "RAW OUTPUT:\n" + "-" * 100 + "\n"
        log_output += stdout if exit_code == 0 else "(command failed)"

        PortSpeedDetector._log_speed_detection(
            ssh.device.hostname, "MikroTik",
            "/interface ethernet print detail without-paging",
            log_output,
            ports, speeds
        )

        return speeds

    @staticmethod
    def get_port_speeds_arista(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Arista EOS interfaces"""
        speeds = {}
        debug_info = []

        # Clean port names - remove suffixes
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        # Normalize Arista port names: "Ethernet1/1" -> "Et1/1"
        # Arista uses abbreviated names in output
        normalized_mapping = {}
        for clean_port, original_ports in port_mapping.items():
            # Convert "Ethernet" to "Et", "Management" to "Ma"
            normalized = clean_port.replace('Ethernet', 'Et').replace('Management', 'Ma')
            normalized_mapping[normalized] = original_ports

        debug_info.append(f"Port mapping after normalization: {normalized_mapping}")

        # Use shell command for Arista devices (requires enable mode)
        stdout, stderr, exit_code = ssh.execute_shell_command('show interfaces status', enable_mode=True)

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse Arista output - format varies based on whether there's a description
                # With desc:    "Et3/3      MikroTik10GCRS326           connected    trunk    full   10G    40GBASE-CR4"
                # Without desc: "Et1/1      \"Uplink to 2930F\"           notconnect   1        full   10G    Not Present"
                # No desc:      "Et8/1                                  notconnect   1        full   10G    Not Present"
                # Port channel: "Po1        Link-to-Office-10G-Switch   notconnect   trunk    full   unconf N/A"

                # Skip header line and empty lines
                if not line.strip() or line.startswith('Port') or line.startswith('-'):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                interface = parts[0]

                # ONLY process ports we're actually looking for (i.e., ports with LLDP neighbors)
                if interface not in normalized_mapping:
                    continue

                detected_speed = None

                # The speed column is not at a fixed position due to variable-length descriptions
                # Look for speed patterns in the entire line: "10G", "40G", "1G", "100M", "a-1G" (auto), "unconf"
                # Speed appears after duplex (full/half/a-full/a-half) and before Type column

                # First check for "unconf" (unconfigured port channel)
                if 'unconf' in line:
                    detected_speed = "Unknown"
                    debug_info.append(f"Port {interface} is unconfigured (port channel)")
                else:
                    # Look for speed pattern after the duplex field
                    # Match patterns like: "full   10G", "a-full a-10G", "full   40G"
                    # This ensures we match the speed column, not VLAN numbers or other data
                    speed_match = re.search(r'(?:full|half|a-full|a-half)\s+(?:a-)?(\d+(?:\.\d+)?[GM])\b', line, re.IGNORECASE)

                    if speed_match:
                        detected_speed = speed_match.group(1).upper()
                        debug_info.append(f"Found speed for {interface}: {detected_speed} from line: {line.strip()}")
                    elif 'connected' in line.lower():
                        # If connected but no speed found, mark as Link Up
                        detected_speed = "Link Up"
                        debug_info.append(f"Port {interface} is connected but no speed found: {line.strip()}")
                    elif 'notconnect' in line.lower():
                        detected_speed = "Down"
                        debug_info.append(f"Port {interface} is not connected")
                    else:
                        detected_speed = "Unknown"
                        debug_info.append(f"Port {interface} status unknown: {line.strip()}")

                # Apply to all original ports that map to this normalized name
                for original_port in normalized_mapping[interface]:
                    speeds[original_port] = detected_speed
                    debug_info.append(f"  Mapped {interface} -> {original_port} = {detected_speed}")

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"
                debug_info.append(f"Port {port} not found in output, marked as Unknown")

        # Log the detection results with debug info
        log_output = ""
        if debug_info:
            log_output = "DEBUG INFO:\n" + "-" * 100 + "\n" + "\n".join(debug_info) + "\n" + "-" * 100 + "\n\n"
        log_output += stdout if exit_code == 0 else "(command failed)"

        PortSpeedDetector._log_speed_detection(
            ssh.device.hostname, "Arista",
            "show interfaces status",
            log_output,
            ports, speeds
        )

        return speeds

    @staticmethod
    def get_port_speeds_aruba(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for HP Aruba interfaces"""
        speeds = {}

        # Clean port names - remove suffixes
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        # Use shell command for Aruba devices (requires enable mode)
        stdout, stderr, exit_code = ssh.execute_shell_command('show interfaces brief', enable_mode=True)

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse Aruba output format
                # Example: "9    Up     Yes    Enabled  Auto    1000FDx  None"
                # Example: "25   Down   No     Disabled Auto    None     None"
                parts = line.split()
                if len(parts) >= 3:
                    port_name = parts[0]
                    for clean_port, original_ports in port_mapping.items():
                        # Match port number (e.g., "9" matches port "9")
                        if port_name == clean_port or clean_port in port_name or port_name in clean_port:
                            detected_speed = None
                            # Look for speed pattern like "1000FDx", "10GigFD", "1000FD", etc.
                            # Speed patterns: 10M, 100M, 1000M, 10G, 1000FDx, 10GigFD, etc.
                            speed_match = re.search(r'(\d+(?:Gig|G|M)(?:FDx|FD|HDx|HD)?)', line, re.IGNORECASE)
                            if speed_match:
                                speed_str = speed_match.group(1)
                                # Normalize: "1000FDx" -> "1G", "10GigFD" -> "10G"
                                # Extract numeric part
                                num_match = re.search(r'(\d+)', speed_str)
                                if num_match:
                                    speed_num = int(num_match.group(1))
                                    if 'G' in speed_str.upper() or 'GIG' in speed_str.upper():
                                        detected_speed = f"{speed_num}G"
                                    elif speed_num >= 1000:
                                        # 1000M = 1G
                                        detected_speed = f"{speed_num // 1000}G"
                                    else:
                                        detected_speed = f"{speed_num}M"
                            elif 'Up' in line:
                                detected_speed = "Link Up"
                            else:
                                detected_speed = "Down"

                            # Apply to all original ports that map to this clean name
                            for original_port in original_ports:
                                speeds[original_port] = detected_speed
                            break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        # Log the detection results
        PortSpeedDetector._log_speed_detection(
            ssh.device.hostname, "HP Aruba",
            "show interfaces brief",
            stdout if exit_code == 0 else "(command failed)",
            ports, speeds
        )

        return speeds

    @staticmethod
    def get_port_speeds_ruijie(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Ruijie interfaces"""
        speeds = {}

        # Clean port names - remove suffixes
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        # Use shell command for Ruijie devices (requires enable mode)
        stdout, stderr, exit_code = ssh.execute_shell_command('show interfaces status', enable_mode=True)

        if exit_code == 0:
            for line in stdout.split('\n'):
                # Parse Ruijie output similar to Cisco format
                # Example: "Gi1/0/1  connected    trunk      1          a-full  a-1000"
                # Example: "Gi1/0/2  notconnect   1          auto    auto"
                parts = line.split()
                if len(parts) >= 2 and not line.startswith('Port'):
                    interface = parts[0]
                    for clean_port, original_ports in port_mapping.items():
                        if clean_port in interface or interface in clean_port:
                            # Look for speed patterns
                            # Common formats: "a-1000", "1000", "10G", "a-10G", "auto"
                            speed_patterns = [
                                r'\b(?:a-)?(\d+(?:\.\d+)?[GM])\b',  # "a-10G", "10G", "1G"
                                r'\b(?:a-)(\d{2,5})\b',              # "a-1000", "a-100"
                                r'\b(\d{2,5})(?:\s|$)'               # "1000 ", "100 "
                            ]

                            detected_speed = None
                            for pattern in speed_patterns:
                                speed_match = re.search(pattern, line, re.IGNORECASE)
                                if speed_match:
                                    speed_str = speed_match.group(1)
                                    # Convert to standard format
                                    if speed_str.isdigit():
                                        # Numeric value (e.g., "1000" -> "1G")
                                        detected_speed = PortSpeedDetector._format_speed(int(speed_str))
                                    else:
                                        # Already has suffix (e.g., "10G")
                                        detected_speed = speed_str.upper()
                                    break

                            if not detected_speed:
                                if 'connected' in line.lower():
                                    detected_speed = "Link Up"
                                else:
                                    detected_speed = "Down"

                            # Apply to all original ports that map to this clean name
                            for original_port in original_ports:
                                speeds[original_port] = detected_speed
                            break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        # Log the detection results
        PortSpeedDetector._log_speed_detection(
            ssh.device.hostname, "Ruijie",
            "show interfaces status",
            stdout if exit_code == 0 else "(command failed)",
            ports, speeds
        )

        return speeds

    @staticmethod
    def get_port_speeds_proxmox(ssh: SSHConnection, ports: List[str]) -> Dict[str, str]:
        """Get port speeds for Proxmox hosts (same as Linux)"""
        return PortSpeedDetector.get_port_speeds_linux(ssh, ports)

    @staticmethod
    def parse_arista_speeds(output: str, ports: List[str]) -> Dict[str, str]:
        """Parse Arista speed output from pre-collected 'show interfaces status' output"""
        speeds = {}

        # Clean port names - remove suffixes like ",trunk"
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        for line in output.split('\n'):
            # Parse output like: "Et1    connected    1        full    1G     1000baseT"
            # Format: Port       Name    Status       Vlan       Duplex  Speed Type
            parts = line.split()
            if len(parts) >= 2 and not line.startswith('Port'):
                interface = parts[0]
                # Match any port in our list
                for clean_port, original_ports in port_mapping.items():
                    if clean_port in interface or interface in clean_port:
                        detected_speed = None
                        # Look for speed pattern in the line (e.g., "1G", "10G", "100M")
                        speed_match = re.search(r'\b(\d+(?:\.\d+)?[GM](?:b(?:ps)?)?)\b', line, re.IGNORECASE)
                        if speed_match:
                            detected_speed = speed_match.group(1).upper()
                        elif 'connected' in line.lower():
                            detected_speed = "Link Up"
                        else:
                            detected_speed = "Unknown"

                        # Apply to all original ports that map to this clean name
                        for original_port in original_ports:
                            speeds[original_port] = detected_speed
                        break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def parse_aruba_speeds(output: str, ports: List[str]) -> Dict[str, str]:
        """Parse HP Aruba speed output from pre-collected 'show interfaces brief' output"""
        speeds = {}

        # Clean port names - remove suffixes like ",trunk", ",OfficeAruba"
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        for line in output.split('\n'):
            # Parse Aruba output format
            # Example: "  1            100/1000T  | No        Yes     Up     100FDx     MDIX off  0"
            # Example: "  11           100/1000T  | No        Yes     Up     1000FDx    MDI  off  0"
            # Example: "  49-Trk3*     SFP+DAC    | No        Yes     Up     10GigFD    NA   off  0"
            # Example: "  25           100/1000T  | No        Yes     Down   None       MDIX off  0"

            # Skip header lines
            if 'Port' in line and 'Type' in line:
                continue

            parts = line.split()
            if len(parts) >= 3:
                port_name = parts[0]

                # Extract just the port number from names like "49-Trk3*" or "6-Trk2"
                # Match the base port number at the start
                port_num_match = re.match(r'^(\d+)', port_name)
                if not port_num_match:
                    continue

                base_port = port_num_match.group(1)

                for clean_port, original_ports in port_mapping.items():
                    # Match port number: "9" matches "9", "49" matches "49-Trk3*"
                    if base_port == clean_port or clean_port == port_name:
                        detected_speed = None

                        # Look for speed pattern with duplex indicator to avoid matching port type
                        # Must have FDx, FD, HDx, HD, or GigFD to be a valid speed
                        # Examples: "100FDx", "1000FDx", "10GigFD", "100HDx"
                        speed_match = re.search(r'(\d+)(?:Gig)?(FDx|FD|HDx|HD)\b', line, re.IGNORECASE)

                        if speed_match:
                            speed_num = int(speed_match.group(1))
                            speed_str = speed_match.group(0)  # Full match like "1000FDx" or "10GigFD"

                            # Normalize speeds
                            if 'GIG' in speed_str.upper():
                                # "10GigFD" -> "10G"
                                detected_speed = f"{speed_num}G"
                            elif speed_num >= 1000:
                                # "1000FDx" -> "1G"
                                detected_speed = f"{speed_num // 1000}G"
                            else:
                                # "100FDx" -> "100M"
                                detected_speed = f"{speed_num}M"
                        elif 'None' in line and ('Up' in line or 'Down' in line):
                            # Speed shown as "None" - link status only
                            if 'Down' in line:
                                detected_speed = "Down"
                            else:
                                detected_speed = "Link Up"
                        elif 'Up' in line:
                            detected_speed = "Link Up"
                        elif 'Down' in line:
                            detected_speed = "Down"
                        else:
                            detected_speed = "Unknown"

                        # Apply to all original ports that map to this clean name
                        for original_port in original_ports:
                            speeds[original_port] = detected_speed
                        break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

    @staticmethod
    def parse_ruijie_speeds(output: str, ports: List[str]) -> Dict[str, str]:
        """Parse Ruijie speed output from pre-collected 'show interfaces status' output"""
        speeds = {}

        # Clean port names - remove suffixes like ",trunk"
        port_mapping = PortSpeedDetector._clean_port_names(ports)

        for line in output.split('\n'):
            # Parse Ruijie output similar to Cisco format
            # Example: "Gi1/0/1  connected    trunk      1          a-full  a-1000"
            # Example: "Gi1/0/2  notconnect   1          auto    auto"
            parts = line.split()
            if len(parts) >= 2 and not line.startswith('Port'):
                interface = parts[0]
                for clean_port, original_ports in port_mapping.items():
                    if clean_port in interface or interface in clean_port:
                        detected_speed = None
                        # Look for speed patterns
                        # Common formats: "a-1000", "1000", "10G", "a-10G", "auto"
                        speed_patterns = [
                            r'\b(?:a-)?(\d+(?:\.\d+)?[GM])\b',  # "a-10G", "10G", "1G"
                            r'\b(?:a-)(\d{2,5})\b',              # "a-1000", "a-100"
                            r'\b(\d{2,5})(?:\s|$)'               # "1000 ", "100 "
                        ]

                        speed_found = False
                        for pattern in speed_patterns:
                            speed_match = re.search(pattern, line, re.IGNORECASE)
                            if speed_match:
                                speed_str = speed_match.group(1)
                                # Convert to standard format
                                if speed_str.isdigit():
                                    # Numeric value (e.g., "1000" -> "1G")
                                    detected_speed = PortSpeedDetector._format_speed(int(speed_str))
                                else:
                                    # Already has suffix (e.g., "10G")
                                    detected_speed = speed_str.upper()
                                speed_found = True
                                break

                        if not speed_found:
                            if 'connected' in line.lower():
                                detected_speed = "Link Up"
                            else:
                                detected_speed = "Down"

                        # Apply to all original ports that map to this clean name
                        for original_port in original_ports:
                            speeds[original_port] = detected_speed
                        break

        # Fill in unknowns
        for port in ports:
            if port not in speeds:
                speeds[port] = "Unknown"

        return speeds

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

        # Debug: Write raw output to file for inspection
        import logging
        logger = logging.getLogger(__name__)

        # Save raw LLDP output for debugging
        try:
            with open(f"linux_lldp_debug_{hostname}.txt", 'w') as f:
                f.write(output)
            logger.debug(f"Saved Linux LLDP output to linux_lldp_debug_{hostname}.txt")
        except:
            pass

        # Parse lldpctl output
        current_interface = None
        remote_system = None
        remote_port = None
        remote_desc = None

        for line in output.split('\n'):
            line = line.strip()

            # Match interface name - handles both formats:
            # "Interface: eth0, via: LLDP, RID: 1, Time: 0 day, 00:12:34"
            # "LLDP neighbors:"
            if line.startswith('Interface:'):
                # Save previous neighbor if complete
                if current_interface and remote_system:
                    neighbors.append(LLDPNeighbor(
                        local_device=hostname,
                        local_port=current_interface,
                        remote_device=remote_system,
                        remote_port=remote_port or '',
                        remote_description=remote_desc
                    ))
                    logger.debug(f"Linux: Found neighbor {remote_system} on {current_interface}")

                # Extract interface name - handle "Interface: eth0, via: LLDP, ..."
                iface_part = line.split(':')[1].strip()
                # Take everything before the first comma if present
                current_interface = iface_part.split(',')[0].strip()
                remote_system = None
                remote_port = None
                remote_desc = None
                logger.debug(f"Linux: Processing interface {current_interface}")

            # Handle various SysName formats
            elif 'SysName:' in line or 'System Name:' in line:
                if 'SysName:' in line:
                    remote_system = line.split('SysName:')[1].strip()
                else:
                    remote_system = line.split('System Name:')[1].strip()
                logger.debug(f"Linux: Found SysName: {remote_system}")

            # Handle various PortID formats
            elif 'PortID:' in line or 'Port ID:' in line or 'PortDescr:' in line:
                if 'PortID:' in line:
                    remote_port = line.split('PortID:')[1].strip()
                elif 'Port ID:' in line:
                    remote_port = line.split('Port ID:')[1].strip()
                elif 'PortDescr:' in line and not remote_port:
                    # Use PortDescr as fallback if no PortID found
                    remote_port = line.split('PortDescr:')[1].strip()
                logger.debug(f"Linux: Found PortID: {remote_port}")

            # Port Description
            elif 'Port Description:' in line or 'PortDescr:' in line:
                if 'Port Description:' in line:
                    remote_desc = line.split('Port Description:')[1].strip()
                elif 'PortDescr:' in line and not remote_desc:
                    remote_desc = line.split('PortDescr:')[1].strip()

        # Add last neighbor
        if current_interface and remote_system:
            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=current_interface,
                remote_device=remote_system,
                remote_port=remote_port or '',
                remote_description=remote_desc
            ))
            logger.debug(f"Linux: Found neighbor (last) {remote_system} on {current_interface}")

        logger.info(f"Linux: Parsed {len(neighbors)} LLDP neighbors from {hostname}")
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

        # Debug: Write raw output to file for inspection
        import logging
        logger = logging.getLogger(__name__)

        # Save raw LLDP output for debugging
        try:
            with open(f"arista_lldp_debug_{hostname}.txt", 'w') as f:
                f.write(output)
            logger.debug(f"Saved Arista LLDP output to arista_lldp_debug_{hostname}.txt")
        except:
            pass

        for line in lines:
            line = line.strip()

            if line.startswith('Interface'):
                if current_neighbor and 'local_port' in current_neighbor:
                    # Only add neighbor if we have both device and port info
                    if current_neighbor.get('remote_device') and current_neighbor.get('remote_port'):
                        neighbors.append(LLDPNeighbor(
                            local_device=hostname,
                            local_port=current_neighbor.get('local_port', ''),
                            remote_device=current_neighbor.get('remote_device', ''),
                            remote_port=current_neighbor.get('remote_port', ''),
                            remote_description=current_neighbor.get('remote_desc')
                        ))
                    else:
                        logger.debug(f"Skipping incomplete Arista neighbor: {current_neighbor}")
                current_neighbor = {}
                # Parse: "Interface Ethernet1 detected 1 LLDP neighbors"
                match = re.search(r'Interface\s+(\S+)', line)
                if match:
                    current_neighbor['local_port'] = match.group(1)

            elif 'System Name:' in line or 'Neighbor Device ID:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    device_name = parts[1].strip().strip('"')
                    # Only set if non-empty
                    if device_name:
                        current_neighbor['remote_device'] = device_name

            elif 'Port ID:' in line or 'Neighbor Port ID:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    port_id = parts[1].strip().strip('"')
                    # Only set if non-empty
                    if port_id:
                        current_neighbor['remote_port'] = port_id

            elif 'Port Description:' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    port_desc = parts[1].strip().strip('"')
                    if port_desc:
                        current_neighbor['remote_desc'] = port_desc

        # Add last neighbor (only if complete)
        if current_neighbor and 'local_port' in current_neighbor:
            if current_neighbor.get('remote_device') and current_neighbor.get('remote_port'):
                neighbors.append(LLDPNeighbor(
                    local_device=hostname,
                    local_port=current_neighbor.get('local_port', ''),
                    remote_device=current_neighbor.get('remote_device', ''),
                    remote_port=current_neighbor.get('remote_port', ''),
                    remote_description=current_neighbor.get('remote_desc')
                ))
            else:
                logger.debug(f"Skipping incomplete Arista neighbor (last): {current_neighbor}")

        logger.info(f"Arista: Parsed {len(neighbors)} complete LLDP neighbors from {hostname}")
        return neighbors

    @staticmethod
    def parse_aruba(output: str, hostname: str) -> List[LLDPNeighbor]:
        """Parse LLDP output from HP Aruba - table format from 'show lldp info remote-device'"""
        neighbors = []
        seen_connections = set()  # Track (local_port, remote_device) to avoid duplicates

        # Parse table format:
        # LocalPort | ChassisId          PortId             PortDescr SysName
        # --------- + ------------------ ------------------ --------- ------------------
        # 1         | b8a44f-a8586b      b8 a4 4f a8 58 6b  eth0      axis-b8a44fa8586b
        # Note: Aruba lists multiple entries per port for VLANs - we only want physical links

        lines = output.split('\n')
        in_table = False

        for line in lines:
            # Skip header and separator lines
            if 'LocalPort' in line and 'ChassisId' in line:
                in_table = True
                continue
            if '---' in line or not line.strip():
                continue
            if not in_table:
                continue

            # Split by | to get columns
            parts = line.split('|')
            if len(parts) < 2:
                continue

            # Parse: LocalPort | ChassisId PortId PortDescr SysName
            local_port = parts[0].strip()
            if not local_port or not local_port[0].isdigit():
                continue

            # The rest is after the |
            rest = parts[1].strip() if len(parts) > 1 else ""

            # Split the rest into fields (ChassisId, PortId, PortDescr, SysName)
            fields = rest.split()

            if len(fields) < 2:
                continue

            # Extract remote_device (SysName - last field) and remote_port (PortId)
            remote_device = fields[-1]  # SysName is always last
            remote_port = ""

            # Skip if no valid remote device name
            if not remote_device or remote_device in ['-', '']:
                continue

            # Skip VLAN interface names in PortId field
            # VLANs appear as: vlan1, vlan200, bridge.201, trunk/..., etc.
            if len(fields) >= 2:
                port_id = fields[1] if len(fields) >= 2 else fields[0]
                # Skip if PortId is a VLAN interface
                port_id_lower = port_id.lower()
                if any(vlan_pattern in port_id_lower for vlan_pattern in
                       ['vlan', 'bridge', 'trunk/', 'bond', 'lag']):
                    continue
                remote_port = port_id

            # Create unique key for this physical connection
            connection_key = (local_port, remote_device)

            # Skip if we've already seen this physical connection
            if connection_key in seen_connections:
                continue

            seen_connections.add(connection_key)

            neighbors.append(LLDPNeighbor(
                local_device=hostname,
                local_port=local_port,
                remote_device=remote_device,
                remote_port=remote_port,
                remote_description=None
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
        # Note: enable mode is now handled within execute_shell_command()
        test_commands = {
            'linux': 'uname -a',
            'mikrotik': '/system identity print',
            'arista': 'show version',
            'aruba': 'show version',
            'ruijie': 'show version',
            'proxmox': 'uname -a'
        }

        command = test_commands.get(device.device_type, 'echo test')
        self.logger.debug(f"Executing test command on {device.hostname}: {command}")

        # Use shell-based execution for devices that need interactive mode
        if device.device_type in ['aruba', 'arista', 'ruijie']:
            self.logger.debug(f"Using shell-based execution for {device.device_type} device")
            stdout, stderr, exit_code = ssh.execute_shell_command(command, enable_mode=True)
        else:
            self.logger.debug(f"Using exec_command for {device.device_type} device")
            stdout, stderr, exit_code = ssh.execute_command(command)

        ssh.close()

        self.logger.debug(f"Command exit code: {exit_code}")
        self.logger.debug(f"Output length: {len(stdout)} chars, Error length: {len(stderr)} chars")

        if exit_code == 0:
            self.logger.info(f"✓ {device.hostname} - Connection successful")
            self.logger.debug(f"Output: {stdout[:200]}")  # Show first 200 chars
            return True
        else:
            self.logger.error(f"✗ {device.hostname} - Command execution failed")
            self.logger.error(f"Stdout: {stdout[:500]}")  # Show stdout even on failure
            self.logger.error(f"Stderr: {stderr[:500]}")
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
        # Note: enable mode is now handled within execute_shell_command()
        lldp_commands = {
            'linux': 'sudo lldpctl',
            'mikrotik': '/ip neighbor print detail without-paging where identity!=""',
            'arista': 'show lldp neighbors detail',
            'aruba': 'show lldp info remote-device',
            'ruijie': 'show lldp neighbors detail',
            'proxmox': 'sudo lldpctl'
        }

        command = lldp_commands.get(device.device_type)
        if not command:
            self.logger.error(f"Unknown device type: {device.device_type}")
            ssh.close()
            return []

        self.logger.debug(f"Executing LLDP command on {device.hostname}: {command}")

        # For interactive devices, also get speed command to run both in same shell session
        speed_command = None
        if device.device_type in ['aruba', 'arista', 'ruijie']:
            speed_commands_map = {
                'aruba': 'show interfaces brief',
                'arista': 'show interfaces status',
                'ruijie': 'show interfaces status'
            }
            speed_command = speed_commands_map.get(device.device_type)

        # Use shell-based execution for devices that need interactive mode
        if device.device_type in ['aruba', 'arista', 'ruijie']:
            self.logger.debug(f"Using shell-based execution for {device.device_type} device")
            if speed_command:
                # Execute both LLDP and speed commands in same shell session
                self.logger.debug(f"Executing LLDP and speed commands in same session")
                results = ssh.execute_shell_commands([command, speed_command], enable_mode=True)
                stdout, stderr, exit_code = results[0]  # LLDP output
                speed_stdout, speed_stderr, speed_exit_code = results[1] if len(results) > 1 else ("", "", 1)
            else:
                stdout, stderr, exit_code = ssh.execute_shell_command(command, enable_mode=True)
                speed_stdout = ""
        else:
            # Use regular exec_command for Linux, MikroTik, Proxmox
            self.logger.debug(f"Using exec_command for {device.device_type} device")
            request_pty = False  # Don't use PTY for any device by default (only sudo needs it)
            stdout, stderr, exit_code = ssh.execute_command(command, request_pty=request_pty)
            speed_stdout = ""

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
        self.logger.debug(f"  First 500 chars of output: {stdout[:500]}")

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

        self.logger.debug(f"  Parsed {len(neighbors)} LLDP neighbors from {device.hostname}")

        # Get port speeds for local ports (excluding virtual/VLAN interfaces)
        if neighbors:
            # Filter out virtual interfaces before speed detection
            local_ports = list(set([n.local_port for n in neighbors if self._is_physical_interface(n.local_port)]))
            self.logger.debug(f"Detecting speeds for physical ports only: {local_ports}")

            # Log filtered virtual interfaces
            virtual_ports = list(set([n.local_port for n in neighbors if not self._is_physical_interface(n.local_port)]))
            if virtual_ports:
                self.logger.debug(f"Skipping speed detection for virtual interfaces: {virtual_ports}")

            # For interactive devices (Aruba/Arista/Ruijie), use the pre-collected speed output
            if device.device_type in ['aruba', 'arista', 'ruijie']:
                if speed_stdout and speed_command:
                    self.logger.debug(f"Parsing speed data from same shell session for {device.device_type}")
                    # Parse the speed output directly instead of executing new commands
                    speed_parsers = {
                        'aruba': PortSpeedDetector.parse_aruba_speeds,
                        'arista': PortSpeedDetector.parse_arista_speeds,
                        'ruijie': PortSpeedDetector.parse_ruijie_speeds
                    }

                    speed_parser = speed_parsers.get(device.device_type)
                    if speed_parser:
                        port_speeds = speed_parser(speed_stdout, local_ports)

                        # Log the speed detection results
                        device_type_names = {
                            'aruba': 'HP Aruba',
                            'arista': 'Arista',
                            'ruijie': 'Ruijie'
                        }
                        PortSpeedDetector._log_speed_detection(
                            device.hostname,
                            device_type_names.get(device.device_type, device.device_type),
                            speed_command,
                            speed_stdout,
                            local_ports,
                            port_speeds
                        )

                        # Assign speeds to neighbors
                        for neighbor in neighbors:
                            neighbor.local_port_speed = port_speeds.get(neighbor.local_port, "Unknown")
                            self.logger.debug(f"{neighbor.local_port} speed: {neighbor.local_port_speed}")
                else:
                    self.logger.warning(f"No speed data collected for {device.device_type}")
                    for neighbor in neighbors:
                        neighbor.local_port_speed = "Unknown"
            else:
                # For non-interactive devices, use existing speed detection methods
                speed_detectors = {
                    'linux': PortSpeedDetector.get_port_speeds_linux,
                    'mikrotik': PortSpeedDetector.get_port_speeds_mikrotik,
                    'proxmox': PortSpeedDetector.get_port_speeds_proxmox,
                    'aruba': PortSpeedDetector.get_port_speeds_aruba,
                    'arista': PortSpeedDetector.get_port_speeds_arista,
                    'ruijie': PortSpeedDetector.get_port_speeds_ruijie
                }

                speed_detector = speed_detectors.get(device.device_type)
                if speed_detector:
                    port_speeds = speed_detector(ssh, local_ports)

                    # Assign speeds to neighbors
                    for neighbor in neighbors:
                        neighbor.local_port_speed = port_speeds.get(neighbor.local_port, "Unknown")
                        self.logger.debug(f"{neighbor.local_port} speed: {neighbor.local_port_speed}")

        ssh.close()
        self.logger.info(f"✓ {device.hostname} - Found {len(neighbors)} LLDP neighbors")
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
            self.logger.debug(f"Filtered {filtered_count} virtual interface connections")

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
        # Use MultiGraph to support multiple edges between same devices
        edge_labels = {}
        for neighbor in self.neighbors:
            # Create edge
            G.add_edge(neighbor.local_device, neighbor.remote_device)

            # Store port information for edge labels (aggregate multiple links)
            edge_key = (neighbor.local_device, neighbor.remote_device)
            if edge_key not in edge_labels:
                edge_labels[edge_key] = []
            edge_labels[edge_key].append(f"{neighbor.local_port}↕{neighbor.remote_port}")

        # Format edge labels to show all links
        formatted_edge_labels = {}
        for edge_key, ports in edge_labels.items():
            formatted_edge_labels[edge_key] = "\n".join(ports)

        # Calculate figure size based on number of nodes (minimum 20x15, scales up)
        num_nodes = len(G.nodes())
        fig_width = max(20, num_nodes * 2)
        fig_height = max(15, num_nodes * 1.5)

        # Create visualization
        plt.figure(figsize=(fig_width, fig_height))

        # Use spring layout with more spacing (k controls distance between nodes)
        # Higher k = more spread out, more iterations = better layout
        k_value = 3 / (num_nodes ** 0.5) if num_nodes > 1 else 2  # Adaptive spacing
        pos = nx.spring_layout(G, k=k_value, iterations=100, seed=42, scale=2)

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

        # Scale visual elements based on figure size
        node_size = min(5000, max(2000, 100000 / num_nodes))  # Larger nodes for fewer devices
        font_size_nodes = min(14, max(8, 120 / (num_nodes ** 0.5)))
        font_size_edges = min(10, max(6, 80 / (num_nodes ** 0.5)))
        edge_width = min(3, max(1.5, 40 / num_nodes))

        # Draw nodes
        nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                              node_size=node_size, alpha=0.9,
                              edgecolors='black', linewidths=2)

        # Draw edges
        nx.draw_networkx_edges(G, pos, width=edge_width, alpha=0.6, edge_color='#7f8c8d')

        # Draw labels
        nx.draw_networkx_labels(G, pos, font_size=font_size_nodes, font_weight='bold')

        # Draw edge labels (port information) - using formatted labels
        nx.draw_networkx_edge_labels(G, pos, formatted_edge_labels, font_size=font_size_edges,
                                     bbox=dict(boxstyle='round,pad=0.3',
                                             facecolor='white', alpha=0.8))

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
        from collections import defaultdict
        import math

        if not self.neighbors:
            self.logger.error("No topology data to visualize")
            return

        # Gather device statistics
        device_type_counts = defaultdict(int)
        for device in self.devices:
            device_type_counts[device.device_type] += 1

        # Build device info for tooltips (configured devices have full info)
        device_info = {}
        for device in self.devices:
            device_info[device.hostname] = {
                'type': device.device_type,
                'ip': device.ip_address
            }

        # Add discovered devices with minimal info
        for neighbor in self.neighbors:
            for device_name in [neighbor.local_device, neighbor.remote_device]:
                if device_name not in device_info:
                    device_info[device_name] = {
                        'type': 'discovered',
                        'ip': 'Not configured'
                    }

        # Build connection list with speeds - include ALL physical links
        connections = []
        for neighbor in self.neighbors:
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

        self.logger.debug(f"HTML: Including {len(connections)} connections in visualization")

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

        .port-label-box {{
            fill: rgba(15, 23, 42, 0.9);
            stroke: rgba(148, 163, 184, 0.3);
            stroke-width: 1;
            rx: 4;
            ry: 4;
        }}

        .port-label-text {{
            fill: #e2e8f0;
            font-size: 10px;
            font-family: 'Courier New', monospace;
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
            <div class="topology-container">'''

        # Collect all unique devices (configured + discovered via LLDP) BEFORE creating SVG
        all_device_names = set()
        for device in self.devices:
            all_device_names.add(device.hostname)
        for neighbor in self.neighbors:
            all_device_names.add(neighbor.local_device)
            all_device_names.add(neighbor.remote_device)

        all_devices_sorted = sorted(all_device_names)
        num_devices = len(all_devices_sorted)

        self.logger.debug(f"HTML: Displaying {num_devices} devices ({len(self.devices)} configured, {num_devices - len(self.devices)} discovered)")

        # Adaptive circular layout for nodes - scales with device count
        # Base size that scales with number of devices
        base_size = max(600, num_devices * 40)  # Larger canvas for more devices
        center_x, center_y = base_size, base_size * 0.8
        radius = min(base_size * 0.7, num_devices * 30)  # Radius grows with device count

        # Calculate SVG size dynamically based on device count
        svg_width = base_size * 2
        svg_height = int(base_size * 1.6)

        html_content += f'''
                <svg width="{svg_width}" height="{svg_height}" viewBox="0 0 {svg_width} {svg_height}">
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

        # Calculate device positions
        device_positions = {}

        for i, device_name in enumerate(all_devices_sorted):
            angle = (2 * 3.14159 * i) / num_devices - (3.14159 / 2)  # Start from top
            x = center_x + radius * cos(angle)
            y = center_y + radius * sin(angle)
            device_positions[device_name] = (x, y)

        # Group connections by device pair to handle multiple links
        connection_groups = defaultdict(list)
        for conn in connections:
            if conn['local_device'] in device_positions and conn['remote_device'] in device_positions:
                # Create a sorted pair key to group bidirectional links
                pair = tuple(sorted([conn['local_device'], conn['remote_device']]))
                connection_groups[pair].append(conn)

        # Draw links with grouped label boxes
        for pair, conns in connection_groups.items():
            num_links = len(conns)

            # Get the base positions for this pair
            device1, device2 = pair
            x1, y1 = device_positions[device1]
            x2, y2 = device_positions[device2]

            # Calculate line properties
            dx = x2 - x1
            dy = y2 - y1
            length = math.sqrt(dx*dx + dy*dy)

            # Calculate midpoint for label box
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2

            # Draw each link line
            for idx, conn in enumerate(conns):
                speed_class = conn['speed_class']

                # Offset multiple links perpendicular to the line
                if num_links > 1:
                    # Calculate perpendicular offset
                    offset_amount = ((idx - (num_links - 1) / 2) * 15)  # 15px spacing
                    perp_x = -dy / length * offset_amount
                    perp_y = dx / length * offset_amount

                    line_x1 = x1 + perp_x
                    line_y1 = y1 + perp_y
                    line_x2 = x2 + perp_x
                    line_y2 = y2 + perp_y
                else:
                    line_x1, line_y1 = x1, y1
                    line_x2, line_y2 = x2, y2

                html_content += f'''                        <line class="link {speed_class}" x1="{line_x1}" y1="{line_y1}" x2="{line_x2}" y2="{line_y2}"/>
'''

            # Create a grouped label box at midpoint
            # Calculate box dimensions based on number of connections
            line_height = 14
            padding = 4
            box_height = num_links * line_height + 2 * padding
            box_width = 120  # Fixed width for consistent sizing

            # Position box perpendicular to line to avoid overlapping
            perp_offset = 20
            perp_x = -dy / length * perp_offset
            perp_y = dx / length * perp_offset

            box_x = mid_x + perp_x - box_width / 2
            box_y = mid_y + perp_y - box_height / 2

            # Draw label box background
            html_content += f'''                        <rect class="port-label-box" x="{box_x}" y="{box_y}" width="{box_width}" height="{box_height}"/>
'''

            # Add stacked labels for each connection
            for idx, conn in enumerate(conns):
                text_y = box_y + padding + (idx + 0.7) * line_height

                # Determine which device is local vs remote based on original connection
                if conn['local_device'] == device1:
                    local_port = conn['local_port']
                    remote_port = conn['remote_port']
                    local_speed = conn['local_speed']
                    remote_speed = conn['remote_speed']
                else:
                    # Swap if reversed
                    local_port = conn['remote_port']
                    remote_port = conn['local_port']
                    local_speed = conn['remote_speed']
                    remote_speed = conn['local_speed']

                speed_label_local = f" [{local_speed}]" if local_speed else ""
                speed_label_remote = f" [{remote_speed}]" if remote_speed else ""

                label_text = f"{local_port}{speed_label_local} ↔ {remote_port}{speed_label_remote}"

                html_content += f'''                        <text class="port-label-text" x="{mid_x + perp_x}" y="{text_y}">{label_text}</text>
'''

        html_content += '''                    </g>

                    <g id="nodes">
'''

        # Draw nodes - all discovered devices
        # Build device type lookup for coloring
        device_type_lookup = {device.hostname: device.device_type for device in self.devices}

        for device_name in all_devices_sorted:
            x, y = device_positions[device_name]
            # Get device type from config, or default to 'unknown' for discovered devices
            device_type = device_type_lookup.get(device_name, 'unknown')
            color = device_colors.get(device_type, '#95a5a6')

            html_content += f'''                        <g class="node" data-device="{device_name}">
                            <circle cx="{x}" cy="{y}" r="40" fill="{color}" filter="url(#glow)"/>
                            <text x="{x}" y="{y + 5}">{device_name[:12]}</text>
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

    def visualize_d3_interactive(self, output_file: str = 'network_topology_d3.html'):
        """Generate clean, modern interactive D3.js force-directed graph visualization"""

        # Collect unique devices and create node list
        device_set = set()
        for neighbor in self.neighbors:
            device_set.add(neighbor.local_device)
            device_set.add(neighbor.remote_device)

        # Prepare connection data - deduplicate bidirectional links
        connection_map = {}
        for neighbor in self.neighbors:
            # Create sorted key to ensure bidirectional deduplication
            devices = tuple(sorted([neighbor.local_device, neighbor.remote_device]))
            key = f"{devices[0]}-{devices[1]}"

            # Keep the connection with the best speed information
            if key not in connection_map:
                connection_map[key] = {
                    'source': neighbor.local_device,
                    'target': neighbor.remote_device,
                    'source_port': neighbor.local_port,
                    'target_port': neighbor.remote_port,
                    'speed': neighbor.local_port_speed or 'Unknown',
                    'label': f"{neighbor.local_port} ↔ {neighbor.remote_port}"
                }
            else:
                # Update if this connection has better speed info
                existing_speed = connection_map[key]['speed']
                new_speed = neighbor.local_port_speed or 'Unknown'
                if existing_speed == 'Unknown' and new_speed != 'Unknown':
                    connection_map[key]['speed'] = new_speed

        connections = list(connection_map.values())

        self.logger.info(f"Generating D3 visualization with {len(device_set)} devices and {len(connections)} connections")

        # Prepare node data for JSON serialization
        nodes_data = [{'id': d, 'label': d} for d in sorted(device_set)]

        # Generate clean HTML with embedded D3.js visualization
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
        }}

        .container {{
            max-width: 1600px;
            margin: 0 auto;
        }}

        h1 {{
            text-align: center;
            margin-bottom: 30px;
            font-size: 2em;
            color: #60a5fa;
            text-shadow: 0 0 20px rgba(96, 165, 250, 0.5);
        }}

        .stats {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 20px 30px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            border: 1px solid #334155;
        }}

        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #60a5fa;
        }}

        .stat-label {{
            font-size: 0.9em;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        #graph {{
            width: 100%;
            height: 700px;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-radius: 12px;
            border: 2px solid #334155;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
            margin-bottom: 20px;
        }}

        .controls {{
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .btn {{
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}

        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.4);
        }}

        .legend {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #334155;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}

        .legend h3 {{
            margin-bottom: 15px;
            color: #60a5fa;
        }}

        .legend-section {{
            margin-bottom: 15px;
        }}

        .legend-item {{
            display: inline-flex;
            align-items: center;
            margin-right: 20px;
            margin-bottom: 8px;
        }}

        .legend-line {{
            width: 40px;
            height: 3px;
            margin-right: 8px;
            border-radius: 2px;
        }}

        .legend-node {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
            margin-right: 8px;
        }}

        .tooltip {{
            position: absolute;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid #475569;
            padding: 12px 16px;
            border-radius: 8px;
            pointer-events: none;
            display: none;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            font-size: 13px;
            line-height: 1.6;
        }}

        .tooltip strong {{
            color: #60a5fa;
        }}

        .link {{
            stroke-opacity: 0.6;
        }}

        .link:hover {{
            stroke-opacity: 1;
            stroke-width: 4 !important;
        }}

        .node {{
            cursor: pointer;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
        }}

        .node:hover {{
            filter: drop-shadow(0 4px 8px rgba(96, 165, 250, 0.6));
        }}

        .node-label {{
            font-size: 11px;
            font-weight: 600;
            fill: white;
            text-anchor: middle;
            pointer-events: none;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Network Topology</h1>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="deviceCount">0</div>
                <div class="stat-label">Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="linkCount">0</div>
                <div class="stat-label">Links</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="speedAvg">—</div>
                <div class="stat-label">Avg Speed</div>
            </div>
        </div>

        <div class="controls">
            <button class="btn" onclick="resetLayout()">🔄 Reset Layout</button>
            <button class="btn" onclick="zoomIn()">🔍 Zoom In</button>
            <button class="btn" onclick="zoomOut()">🔍 Zoom Out</button>
            <button class="btn" onclick="fitView()">⤢ Fit View</button>
        </div>

        <div id="graph"></div>

        <div class="legend">
            <h3>Legend</h3>
            <div class="legend-section">
                <strong>Link Speeds:</strong><br>
                <div style="margin-top: 10px;">
                    <div class="legend-item">
                        <div class="legend-line" style="background: #ef4444;"></div>
                        <span>Unknown / Down</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-line" style="background: #f59e0b;"></div>
                        <span>100M</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-line" style="background: #3b82f6;"></div>
                        <span>1G</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-line" style="background: #10b981;"></div>
                        <span>10G</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-line" style="background: #8b5cf6;"></div>
                        <span>40G+</span>
                    </div>
                </div>
            </div>
            <div class="legend-section" style="margin-top: 15px;">
                <strong>Device Types:</strong><br>
                <div style="margin-top: 10px;">
                    <div class="legend-item">
                        <div class="legend-node" style="background: #3b82f6;"></div>
                        <span>Switches (Arista/Aruba)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-node" style="background: #10b981;"></div>
                        <span>MikroTik</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-node" style="background: #f59e0b;"></div>
                        <span>Servers (Proxmox/Linux)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-node" style="background: #64748b;"></div>
                        <span>Other Devices</span>
                    </div>
                </div>
            </div>
            <p style="margin-top: 15px; color: #94a3b8; font-size: 0.9em;">
                💡 <strong>Tip:</strong> Drag nodes to reposition • Scroll to zoom • Hover for details
            </p>
        </div>
    </div>

    <div class="tooltip" id="tooltip"></div>

    <script>
        // Network data
        const networkData = {{
            nodes: {json.dumps(nodes_data)},
            links: {json.dumps(connections)}
        }};

        console.log('Network data:', networkData);

        // Helper functions
        function getDeviceColor(name) {{
            const n = name.toLowerCase();
            if (n.includes('arista') || n.includes('aruba') || n.includes('2930') || n.includes('2520')) return '#3b82f6';
            if (n.includes('mikrotik') || n.includes('rb') || n.includes('crs')) return '#10b981';
            if (n.includes('proxmox') || n.includes('linux') || n.includes('nas')) return '#f59e0b';
            return '#64748b';
        }}

        function getLinkColor(speed) {{
            if (!speed || speed === 'Unknown' || speed === 'Down') return '#ef4444';
            const s = speed.toLowerCase();
            if (s.includes('100m')) return '#f59e0b';
            if (s.includes('1g') || s.includes('1000')) return '#3b82f6';
            if (s.includes('10g') || s.includes('10000')) return '#10b981';
            if (s.includes('40g') || s.includes('100g')) return '#8b5cf6';
            return '#ef4444';
        }}

        function getLinkWidth(speed) {{
            if (!speed || speed === 'Unknown' || speed === 'Down') return 2;
            const s = speed.toLowerCase();
            if (s.includes('100m')) return 2;
            if (s.includes('1g')) return 3;
            if (s.includes('10g')) return 4;
            if (s.includes('40g') || s.includes('100g')) return 5;
            return 2;
        }}

        // Update statistics
        document.getElementById('deviceCount').textContent = networkData.nodes.length;
        document.getElementById('linkCount').textContent = networkData.links.length;

        // Calculate average speed
        const speeds = networkData.links.map(l => l.speed).filter(s => s && s !== 'Unknown' && s !== 'Down');
        if (speeds.length > 0) {{
            const hasHighSpeed = speeds.some(s => s.includes('10G') || s.includes('40G'));
            document.getElementById('speedAvg').textContent = hasHighSpeed ? '10G+' : '1G';
        }}

        // Setup D3 visualization
        const container = document.getElementById('graph');
        const width = container.clientWidth;
        const height = container.clientHeight;

        const svg = d3.select('#graph')
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        const g = svg.append('g');

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {{
                g.attr('transform', event.transform);
            }});

        svg.call(zoom);

        // Force simulation
        const simulation = d3.forceSimulation(networkData.nodes)
            .force('link', d3.forceLink(networkData.links)
                .id(d => d.id)
                .distance(200))
            .force('charge', d3.forceManyBody().strength(-800))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50));

        // Create links
        const link = g.append('g')
            .selectAll('line')
            .data(networkData.links)
            .join('line')
            .attr('class', 'link')
            .attr('stroke', d => getLinkColor(d.speed))
            .attr('stroke-width', d => getLinkWidth(d.speed))
            .on('mouseover', showLinkTooltip)
            .on('mouseout', hideTooltip);

        // Create nodes
        const node = g.append('g')
            .selectAll('g')
            .data(networkData.nodes)
            .join('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', dragStart)
                .on('drag', dragging)
                .on('end', dragEnd));

        node.append('rect')
            .attr('width', 90)
            .attr('height', 32)
            .attr('x', -45)
            .attr('y', -16)
            .attr('rx', 6)
            .attr('fill', d => getDeviceColor(d.id))
            .attr('stroke', '#475569')
            .attr('stroke-width', 2);

        node.append('text')
            .attr('class', 'node-label')
            .attr('dy', 4)
            .text(d => d.label.length > 12 ? d.label.substring(0, 10) + '...' : d.label)
            .on('mouseover', showNodeTooltip)
            .on('mouseout', hideTooltip);

        // Tooltip functions
        function showLinkTooltip(event, d) {{
            const tooltip = d3.select('#tooltip');
            tooltip.style('display', 'block')
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px')
                .html(`
                    <strong>Connection</strong><br>
                    ${{d.source.id}} : <strong>${{d.source_port}}</strong><br>
                    ${{d.target.id}} : <strong>${{d.target_port}}</strong><br>
                    Speed: <strong style="color: ${{getLinkColor(d.speed)}};">${{d.speed}}</strong>
                `);
        }}

        function showNodeTooltip(event, d) {{
            const connections = networkData.links.filter(l =>
                l.source.id === d.id || l.target.id === d.id
            );
            const tooltip = d3.select('#tooltip');
            tooltip.style('display', 'block')
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px')
                .html(`
                    <strong>${{d.label}}</strong><br>
                    Type: ${{getDeviceType(d.label)}}<br>
                    Connections: <strong>${{connections.length}}</strong>
                `);
        }}

        function hideTooltip() {{
            d3.select('#tooltip').style('display', 'none');
        }}

        function getDeviceType(name) {{
            const n = name.toLowerCase();
            if (n.includes('arista')) return 'Arista Switch';
            if (n.includes('aruba') || n.includes('2930') || n.includes('2520')) return 'HP Aruba Switch';
            if (n.includes('mikrotik') || n.includes('rb') || n.includes('crs')) return 'MikroTik Device';
            if (n.includes('proxmox')) return 'Proxmox Host';
            if (n.includes('linux') || n.includes('nas')) return 'Linux Server';
            return 'Network Device';
        }}

        // Simulation tick
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});

        // Drag functions
        function dragStart(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragging(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragEnd(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}

        // Control functions
        function resetLayout() {{
            networkData.nodes.forEach(d => {{
                d.fx = null;
                d.fy = null;
            }});
            simulation.alpha(1).restart();
        }}

        function zoomIn() {{
            svg.transition().call(zoom.scaleBy, 1.5);
        }}

        function zoomOut() {{
            svg.transition().call(zoom.scaleBy, 0.67);
        }}

        function fitView() {{
            svg.transition().call(zoom.transform, d3.zoomIdentity);
        }}
    </script>
</body>
</html>'''

        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"✓ D3 visualization saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to write visualization: {e}")


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
                "enable_password": "your_enable_password_here",
                "port": 22
            },
            {
                "hostname": "aruba-switch-01",
                "ip_address": "192.168.1.30",
                "device_type": "aruba",
                "username": "admin",
                "password": "your_password_here",
                "enable_password": "your_enable_password_here",
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

  # Discover and visualize network topology (creates PNG, HTML, and D3 by default)
  %(prog)s devices.json

  # Discover with custom output files
  %(prog)s devices.json --output topology.json --graph network.png --d3 interactive.html

  # Skip D3.js visualization, only create PNG and static HTML
  %(prog)s devices.json --no-d3

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
    parser.add_argument('--d3', default='network_topology_d3.html',
                       help='Generate D3.js interactive force-directed graph (default: network_topology_d3.html, use --no-d3 to disable)')
    parser.add_argument('--no-d3', action='store_true',
                       help='Skip generating D3.js visualization')
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
        # Find specific device - try exact match first, then normalized match
        device = next((d for d in discovery.devices if d.hostname == args.test), None)

        # If no exact match, try normalized matching
        if not device:
            normalized_test = discovery._normalize_hostname(args.test)
            for d in discovery.devices:
                normalized_device = discovery._normalize_hostname(d.hostname)
                if normalized_test == normalized_device or normalized_test in normalized_device or normalized_device in normalized_test:
                    device = d
                    print(f"Matched '{args.test}' to configured device '{d.hostname}'")
                    break

        if not device:
            print(f"Error: Device '{args.test}' not found in configuration")
            print(f"Available devices: {', '.join([d.hostname for d in discovery.devices])}")
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

    # Generate D3.js interactive visualization by default (unless --no-d3 is specified)
    if not args.no_d3 and args.d3:
        discovery.visualize_d3_interactive(args.d3)

    return 0


if __name__ == '__main__':
    sys.exit(main())
