#!/usr/bin/env bash
#
# Setup script for LLDP Network Discovery Tool
# This script sets up the Python environment and installs required packages
#

set -e  # Exit on error

echo "=============================================="
echo "LLDP Network Discovery - Environment Setup"
echo "=============================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed."
    echo "Please install Python 3.8 or higher:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  RHEL/CentOS:   sudo yum install python3 python3-pip"
    echo "  macOS:         brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✓ Python $PYTHON_VERSION found"
echo ""

# Check if we're in a virtual environment
echo "[2/5] Checking virtual environment..."
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✓ Already in virtual environment: $VIRTUAL_ENV"
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
    echo ""
    echo "To activate the virtual environment, run:"
    echo "  source venv/bin/activate"
    echo ""
    read -p "Activate now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        source venv/bin/activate
        echo "✓ Virtual environment activated"
    else
        echo "Please activate it manually before running the script"
        exit 0
    fi
fi
echo ""

# Upgrade pip
echo "[3/5] Upgrading pip..."
python3 -m pip install --upgrade pip --quiet
echo "✓ pip upgraded"
echo ""

# Install required Python packages
echo "[4/5] Installing required Python packages..."
echo "  - netmiko (SSH connections to network devices)"
echo "  - graphviz (network diagram generation)"
pip install netmiko graphviz --quiet
echo "✓ Python packages installed"
echo ""

# Check for system Graphviz
echo "[5/5] Checking system Graphviz installation..."
if command -v dot &> /dev/null; then
    GRAPHVIZ_VERSION=$(dot -V 2>&1 | head -1)
    echo "✓ Graphviz found: $GRAPHVIZ_VERSION"
else
    echo "⚠ WARNING: Graphviz system package not found"
    echo ""
    echo "For network diagram generation, install Graphviz:"
    echo "  Ubuntu/Debian: sudo apt install graphviz"
    echo "  RHEL/CentOS:   sudo yum install graphviz"
    echo "  macOS:         brew install graphviz"
    echo ""
    echo "The script will still work but won't generate PNG/SVG diagrams"
fi
echo ""

# Check for lldpd on Linux hosts
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Optional: Checking for lldpd (for Linux hosts)..."
    if command -v lldpctl &> /dev/null || command -v lldpcli &> /dev/null; then
        echo "✓ lldpd found"
    else
        echo "⚠ lldpd not found (only needed if scanning Linux hosts)"
        echo "  To install: sudo apt install lldpd  (Ubuntu/Debian)"
        echo "              sudo yum install lldpd  (RHEL/CentOS)"
    fi
    echo ""
fi

# Create example configuration
echo "Creating example configuration file..."
if [ ! -f devices.json ]; then
    cat > devices.json.example << 'EOF'
[
    {
        "ip": "192.168.1.1",
        "type": "cisco_ios",
        "comment": "Core switch"
    },
    {
        "ip": "192.168.1.2",
        "type": "cisco_ios",
        "username": "netadmin",
        "comment": "Distribution switch with custom credentials"
    },
    {
        "ip": "192.168.1.3",
        "type": "mikrotik_routeros",
        "comment": "Edge router"
    },
    {
        "ip": "192.168.1.10",
        "type": "linux",
        "username": "root",
        "comment": "Proxmox host"
    }
]
EOF
    echo "✓ Created devices.json.example"
    echo ""
    echo "Copy devices.json.example to devices.json and edit with your devices"
else
    echo "✓ devices.json already exists"
fi
echo ""

echo "=============================================="
echo "✓ Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Edit devices.json with your network devices"
echo "  2. Run the script: python3 Lldpdiscovery.py"
echo ""
echo "For help and documentation, see:"
echo "  - README.md"
echo "  - Index.html (GitHub guide)"
echo ""
