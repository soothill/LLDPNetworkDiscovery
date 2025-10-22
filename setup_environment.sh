#!/bin/bash

################################################################################
# LLDP Network Discovery - Python Environment Setup Script
################################################################################
# This script sets up the Python environment and installs all required
# dependencies for the LLDP Network Topology Report Generator
#
# Features:
# - Automatic detection of Linux distribution
# - Python 3 installation verification
# - Virtual environment creation
# - Required Python package installation
# - Optional system package installation (Graphviz)
#
# Usage:
#   bash setup_environment.sh
#   OR
#   chmod +x setup_environment.sh && ./setup_environment.sh
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print header
print_header() {
    echo "=============================================================================="
    echo "  LLDP Network Discovery - Environment Setup"
    echo "=============================================================================="
    echo
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi

    print_info "Detected distribution: $DISTRO"
}

# Check if Python 3 is installed
check_python() {
    print_info "Checking for Python 3..."

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
        PYTHON_CMD="python3"
        PIP_CMD="pip3"
        return 0
    else
        print_error "Python 3 is not installed!"
        return 1
    fi
}

# Install Python 3 if not present
install_python() {
    print_warning "Python 3 is not installed. Attempting to install..."

    case $DISTRO in
        ubuntu|debian)
            print_info "Installing Python 3 on Debian/Ubuntu..."
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        rhel|centos|fedora)
            print_info "Installing Python 3 on RHEL/CentOS/Fedora..."
            sudo yum install -y python3 python3-pip
            ;;
        *)
            print_error "Unsupported distribution. Please install Python 3 manually."
            exit 1
            ;;
    esac

    if check_python; then
        print_success "Python 3 installed successfully!"
    else
        print_error "Failed to install Python 3"
        exit 1
    fi
}

# Check if pip is installed
check_pip() {
    print_info "Checking for pip..."

    if command -v $PIP_CMD &> /dev/null; then
        print_success "pip found"
        return 0
    else
        print_warning "pip not found, installing..."
        return 1
    fi
}

# Install pip if not present
install_pip() {
    case $DISTRO in
        ubuntu|debian)
            sudo apt-get install -y python3-pip
            ;;
        rhel|centos|fedora)
            sudo yum install -y python3-pip
            ;;
        *)
            print_info "Installing pip using get-pip.py..."
            curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
            python3 get-pip.py
            rm get-pip.py
            ;;
    esac
}

# Create virtual environment
create_venv() {
    print_info "Creating Python virtual environment..."

    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists at ./venv"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf venv
        else
            print_info "Using existing virtual environment"
            return 0
        fi
    fi

    $PYTHON_CMD -m venv venv

    if [ -d "venv" ]; then
        print_success "Virtual environment created at ./venv"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
}

# Activate virtual environment
activate_venv() {
    print_info "Activating virtual environment..."
    source venv/bin/activate
    print_success "Virtual environment activated"
}

# Upgrade pip in virtual environment
upgrade_pip() {
    print_info "Upgrading pip..."
    python -m pip install --upgrade pip
    print_success "pip upgraded"
}

# Install Python dependencies
install_python_deps() {
    print_info "Installing required Python packages..."

    # Install from requirements.txt if it exists
    if [ -f "requirements.txt" ]; then
        print_info "Installing from requirements.txt..."
        pip install -r requirements.txt
    else
        # Install packages directly
        print_info "Installing netmiko..."
        pip install netmiko

        print_info "Installing graphviz (Python library)..."
        pip install graphviz
    fi

    print_success "Python packages installed successfully!"
}

# Install system dependencies (Graphviz)
install_system_deps() {
    echo
    print_info "Optional: Install Graphviz system package for diagram generation"
    read -p "Do you want to install Graphviz system package? (Y/n): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        print_info "Installing Graphviz system package..."

        case $DISTRO in
            ubuntu|debian)
                sudo apt-get install -y graphviz
                ;;
            rhel|centos|fedora)
                sudo yum install -y graphviz
                ;;
            *)
                print_warning "Please install Graphviz manually for your distribution"
                print_info "Debian/Ubuntu: sudo apt-get install graphviz"
                print_info "RHEL/CentOS: sudo yum install graphviz"
                print_info "macOS: brew install graphviz"
                return 1
                ;;
        esac

        if command -v dot &> /dev/null; then
            print_success "Graphviz installed successfully!"
        else
            print_warning "Graphviz installation may have failed"
        fi
    else
        print_info "Skipping Graphviz installation"
        print_warning "Note: Network diagram generation will not be available without Graphviz"
    fi
}

# Display installed packages
show_installed_packages() {
    echo
    print_info "Installed Python packages:"
    pip list | grep -E "netmiko|graphviz"
    echo
}

# Print usage instructions
print_usage() {
    echo
    echo "=============================================================================="
    echo "  Setup Complete!"
    echo "=============================================================================="
    echo
    print_success "Python environment is ready!"
    echo
    echo "To use the LLDP Network Discovery tool:"
    echo
    echo "1. Activate the virtual environment:"
    echo "   ${GREEN}source venv/bin/activate${NC}"
    echo
    echo "2. Run the LLDP discovery script:"
    echo "   ${GREEN}python Lldpdiscovery.py${NC}"
    echo
    echo "3. When finished, deactivate the virtual environment:"
    echo "   ${GREEN}deactivate${NC}"
    echo
    echo "Required Network Device Setup:"
    echo "  - Linux devices: Install lldpd package and start service"
    echo "    Debian/Ubuntu: apt-get install lldpd && systemctl enable --now lldpd"
    echo "    RHEL/CentOS: yum install lldpd && systemctl enable --now lldpd"
    echo
    echo "  - Cisco devices: LLDP is typically enabled by default"
    echo "  - MikroTik: Enable LLDP in interface settings"
    echo
    echo "For more information, see the documentation in Lldpdiscovery.py"
    echo "=============================================================================="
    echo
}

# Main setup function
main() {
    print_header

    # Detect distribution
    detect_distro
    echo

    # Check and install Python if needed
    if ! check_python; then
        install_python
    fi
    echo

    # Check and install pip if needed
    if ! check_pip; then
        install_pip
    fi
    echo

    # Create virtual environment
    create_venv
    echo

    # Activate virtual environment
    activate_venv
    echo

    # Upgrade pip
    upgrade_pip
    echo

    # Install Python dependencies
    install_python_deps
    echo

    # Install system dependencies (optional)
    install_system_deps

    # Show installed packages
    show_installed_packages

    # Print usage instructions
    print_usage

    print_success "Setup completed successfully!"
}

# Run main function
main
