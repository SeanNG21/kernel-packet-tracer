#!/bin/bash

# NFT Tracer Production Installation Script
# Installs the application as a systemd service

set -e

INSTALL_DIR="/opt/nft-tracer-app"
SERVICE_FILE="nft-tracer.service"

echo "=========================================="
echo "  NFT Tracer Production Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "ERROR: Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS $VER"
echo ""

# Install system dependencies
echo "Installing system dependencies..."
case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y \
            python3 \
            python3-pip \
            bpfcc-tools \
            python3-bpfcc \
            linux-headers-$(uname -r) \
            nodejs \
            npm
        ;;
    fedora|rhel|centos)
        dnf install -y \
            python3 \
            python3-pip \
            bcc-tools \
            python3-bcc \
            kernel-devel \
            nodejs \
            npm
        ;;
    *)
        echo "WARNING: Unsupported OS. Please install dependencies manually."
        ;;
esac

echo "✓ System dependencies installed"
echo ""

# Create installation directory
echo "Creating installation directory..."
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR/
echo "✓ Files copied to $INSTALL_DIR"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
cd $INSTALL_DIR/backend
pip3 install -r requirements.txt
echo "✓ Python dependencies installed"
echo ""

# Build frontend
echo "Building frontend..."
cd $INSTALL_DIR/frontend
npm install
npm run build
echo "✓ Frontend built"
echo ""

# Create output directory
mkdir -p $INSTALL_DIR/output
chmod 755 $INSTALL_DIR/output

# Install systemd service
echo "Installing systemd service..."
cp $INSTALL_DIR/$SERVICE_FILE /etc/systemd/system/
systemctl daemon-reload
systemctl enable nft-tracer.service
echo "✓ Service installed"
echo ""

# Start service
echo "Starting service..."
systemctl start nft-tracer.service
sleep 2

# Check status
if systemctl is-active --quiet nft-tracer.service; then
    echo "✓ Service started successfully"
else
    echo "ERROR: Service failed to start"
    echo "Check logs with: journalctl -u nft-tracer.service -f"
    exit 1
fi

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Service status:"
systemctl status nft-tracer.service --no-pager -l
echo ""
echo "Useful commands:"
echo "  Start:   systemctl start nft-tracer"
echo "  Stop:    systemctl stop nft-tracer"
echo "  Restart: systemctl restart nft-tracer"
echo "  Status:  systemctl status nft-tracer"
echo "  Logs:    journalctl -u nft-tracer -f"
echo ""
echo "API available at: http://localhost:5000/api"
echo ""
echo "To serve the frontend, you can use nginx:"
echo "  sudo apt-get install nginx"
echo "  Configure nginx to serve: $INSTALL_DIR/frontend/build"
echo ""
