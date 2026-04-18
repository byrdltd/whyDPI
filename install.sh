#!/bin/bash

# whyDPI Installation Script
# For educational and research purposes only

set -e

echo "=============================================="
echo "whyDPI Installation Script"
echo "Educational DPI Bypass Tool"
echo "=============================================="
echo ""
echo "⚠️  For educational and research purposes only"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./install.sh"
    exit 1
fi

# Detect package manager
if command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -S --noconfirm"
elif command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y"
else
    echo "❌ Unsupported package manager. Please install dependencies manually."
    exit 1
fi

echo "📦 Detected package manager: $PKG_MANAGER"
echo ""

# Set pip flags for Arch-based distros (PEP 668 externally-managed-environment)
if [ "$PKG_MANAGER" = "pacman" ]; then
    PIP_FLAGS="--break-system-packages"
    echo "ℹ️  Using --break-system-packages for Arch Linux"
else
    PIP_FLAGS=""
fi
echo ""

# Install system dependencies
echo "📥 Installing system dependencies..."

if [ "$PKG_MANAGER" = "pacman" ]; then
    # Arch Linux: Check if iptables OR iptables-nft is already installed.
    if pacman -Qi iptables &>/dev/null || pacman -Qi iptables-nft &>/dev/null; then
        echo "ℹ️  iptables already installed, skipping..."
        $INSTALL_CMD python python-pip
    else
        echo "ℹ️  Installing iptables-nft (modern nftables backend)..."
        $INSTALL_CMD python python-pip iptables-nft
    fi
elif [ "$PKG_MANAGER" = "apt" ]; then
    $INSTALL_CMD python3 python3-pip iptables
elif [ "$PKG_MANAGER" = "dnf" ]; then
    $INSTALL_CMD python3 python3-pip iptables
fi

echo "✅ System dependencies installed"
echo ""

# Install Python dependencies
echo "📥 Installing Python dependencies..."
pip3 install $PIP_FLAGS -r requirements.txt

echo "✅ Python dependencies installed"
echo ""

# Install whyDPI
echo "📥 Installing whyDPI..."
pip3 install $PIP_FLAGS -e .

echo "✅ whyDPI installed"
echo ""

# Install systemd service (optional)
read -p "Do you want to install systemd service for auto-start at boot? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📦 Installing systemd service..."
    cp whydpi.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable whydpi
    echo "✅ Systemd service installed and enabled at boot"
    echo ""

    read -p "Start whyDPI now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl start whydpi
        sleep 2
        if systemctl is-active --quiet whydpi; then
            echo "✅ whyDPI is running"
        else
            echo "❌ Failed to start whyDPI. Check: sudo journalctl -u whydpi -n 20"
        fi
    else
        echo "ℹ️  To start manually: sudo systemctl start whydpi"
    fi
else
    echo "ℹ️  Skipped systemd service installation"
    echo "ℹ️  You'll need to run 'sudo whydpi start' manually after each reboot"
fi

echo ""
echo "=============================================="
echo "✅ Installation Complete!"
echo "=============================================="
echo ""
echo "Usage:"
echo "  sudo whydpi start --configure-dns"
echo "  sudo whydpi stop"
echo "  sudo whydpi probe example.org example.net"
echo "  sudo whydpi cache list"
echo "  sudo whydpi dns-configure"
echo "  sudo whydpi dns-restore"
echo ""
echo "⚠️  Remember: For educational and research purposes only!"
echo ""
