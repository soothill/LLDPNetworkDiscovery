#!/bin/bash
#
# LLDP Network Discovery Tool - Setup Script
# Installs Python dependencies and system requirements
#
# Copyright (c) 2025 Darren Soothill
# All rights reserved.
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please do not run this script as root"
    exit 1
fi

print_header "LLDP Network Discovery Tool Setup"

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ "$(uname)" == "Darwin" ]; then
        OS="macos"
    else
        OS="unknown"
    fi

    print_info "Detected OS: $OS"
}

# Check Python version
check_python() {
    print_info "Checking Python installation..."

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

        print_success "Python $PYTHON_VERSION found"

        if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
            print_error "Python 3.7 or higher is required"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
}

# Check pip
check_pip() {
    print_info "Checking pip installation..."

    if command -v pip3 &> /dev/null; then
        PIP_VERSION=$(pip3 --version | cut -d' ' -f2)
        print_success "pip $PIP_VERSION found"
    else
        print_warning "pip3 not found, attempting to install..."

        case $OS in
            ubuntu|debian)
                sudo apt-get update
                sudo apt-get install -y python3-pip
                ;;
            rhel|centos|fedora)
                sudo yum install -y python3-pip
                ;;
            macos)
                print_info "Installing pip via get-pip.py..."
                curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
                python3 get-pip.py --user
                rm get-pip.py
                ;;
            *)
                print_error "Please install pip3 manually"
                exit 1
                ;;
        esac

        print_success "pip3 installed"
    fi
}

# Install system dependencies
install_system_deps() {
    print_header "Installing System Dependencies"

    case $OS in
        ubuntu|debian)
            print_info "Installing system packages for Debian/Ubuntu..."
            sudo apt-get update
            sudo apt-get install -y \
                python3-dev \
                python3-pip \
                python3-venv \
                build-essential \
                libffi-dev \
                libssl-dev \
                openssh-client
            print_success "System packages installed"
            ;;

        rhel|centos|fedora)
            print_info "Installing system packages for RHEL/CentOS/Fedora..."
            sudo yum install -y \
                python3-devel \
                python3-pip \
                gcc \
                libffi-devel \
                openssl-devel \
                openssh-clients
            print_success "System packages installed"
            ;;

        macos)
            print_info "Checking Homebrew..."
            if ! command -v brew &> /dev/null; then
                print_warning "Homebrew not found. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi

            print_info "Installing system packages for macOS..."
            brew install python3 || true
            print_success "System packages installed"
            ;;

        *)
            print_warning "Unknown OS. Skipping system package installation."
            print_info "Please ensure python3, pip3, and OpenSSH client are installed."
            ;;
    esac
}

# Create virtual environment
create_venv() {
    print_header "Setting Up Python Virtual Environment"

    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf venv
        else
            print_info "Using existing virtual environment"
            return
        fi
    fi

    print_info "Creating virtual environment..."
    python3 -m venv venv
    print_success "Virtual environment created"
}

# Install Python dependencies
install_python_deps() {
    print_header "Installing Python Dependencies"

    print_info "Activating virtual environment..."
    source venv/bin/activate

    print_info "Upgrading pip..."
    pip install --upgrade pip

    print_info "Installing Python packages from requirements.txt..."
    pip install -r requirements.txt

    print_success "Python dependencies installed"

    # List installed packages
    print_info "Installed packages:"
    pip list | grep -E "(paramiko|networkx|matplotlib)"
}

# Create sample configuration
create_sample_config() {
    print_header "Configuration Setup"

    if [ -f "devices.json" ]; then
        print_warning "devices.json already exists"
        read -p "Do you want to create a new sample config? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            mv devices.json devices.json.backup
            print_info "Existing config backed up to devices.json.backup"
            python3 lldp_discovery.py --create-config
            print_success "New sample configuration created"
        fi
    else
        python3 lldp_discovery.py --create-config
        print_success "Sample configuration created: devices.json"
    fi
}

# Make script executable
make_executable() {
    print_info "Making lldp_discovery.py executable..."
    chmod +x lldp_discovery.py
    print_success "Script is now executable"
}

# Print usage instructions
print_usage() {
    print_header "Setup Complete!"

    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo ""
    echo "1. Activate the virtual environment:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo "2. Edit the configuration file with your device details:"
    echo -e "   ${YELLOW}nano devices.json${NC}"
    echo "   or"
    echo -e "   ${YELLOW}vim devices.json${NC}"
    echo ""
    echo "3. Test connectivity to your devices:"
    echo -e "   ${YELLOW}python lldp_discovery.py --test-all devices.json${NC}"
    echo ""
    echo "4. Run the discovery:"
    echo -e "   ${YELLOW}python lldp_discovery.py devices.json${NC}"
    echo ""
    echo "5. For more options:"
    echo -e "   ${YELLOW}python lldp_discovery.py --help${NC}"
    echo ""
    echo -e "${BLUE}Documentation:${NC} See README.md for detailed usage instructions"
    echo ""
}

# Run setup in order
detect_os
check_python
check_pip
install_system_deps
create_venv
install_python_deps
make_executable
create_sample_config
print_usage

exit 0
