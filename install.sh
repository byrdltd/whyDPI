#!/bin/bash

# whyDPI Installation Script
# For educational and research purposes only

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

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

# Install system dependencies (engine + tray stack — mirrors AUR/deb/rpm packaging)
echo "📥 Installing system dependencies..."

if [ "$PKG_MANAGER" = "pacman" ]; then
    # Arch: iptables may already be present; tray needs tk + AppIndicator for KDE/GNOME.
    PKGS=(python python-pip tk libnotify libayatana-appindicator python-gobject)
    if pacman -Qi iptables &>/dev/null || pacman -Qi iptables-nft &>/dev/null; then
        echo "ℹ️  iptables already installed, skipping..."
    else
        echo "ℹ️  Installing iptables-nft (modern nftables backend)..."
        PKGS+=(iptables-nft)
    fi
    $INSTALL_CMD "${PKGS[@]}"
elif [ "$PKG_MANAGER" = "apt" ]; then
    $INSTALL_CMD python3 python3-pip iptables python3-tk libnotify-bin \
        libayatana-appindicator3-1 gir1.2-ayatanaappindicator3-0.1 python3-gi
elif [ "$PKG_MANAGER" = "dnf" ]; then
    $INSTALL_CMD python3 python3-pip iptables python3-tkinter libnotify \
        libayatana-appindicator-gtk3 python3-gobject
fi

echo "✅ System dependencies installed"
echo ""

# Install Python dependencies
echo "📥 Installing Python dependencies..."
pip3 install $PIP_FLAGS -r requirements.txt

echo "✅ Python dependencies installed"
echo ""

# Install whyDPI (CLI + tray extras — same surface as AUR optdepends / deb Recommends)
echo "📥 Installing whyDPI..."
pip3 install $PIP_FLAGS -e ".[tray]"

echo "✅ whyDPI installed"
echo ""

# Tray desktop integration (application menu, login autostart, hicolor icons)
echo "📥 Installing tray desktop integration..."
install -Dm644 packaging/desktop/whydpi-tray.desktop \
    /usr/share/applications/whydpi-tray.desktop
install -Dm644 packaging/desktop/whydpi-tray.desktop \
    /etc/xdg/autostart/whydpi-tray.desktop
for sz in 16 32 48 64 128 256 512; do
    install -Dm644 "assets/icon-${sz}.png" \
        "/usr/share/icons/hicolor/${sz}x${sz}/apps/whydpi.png"
done
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f /usr/share/icons/hicolor &>/dev/null || true
fi
echo "✅ Tray desktop integration installed (autostart at login)"
echo ""

# Dev installs often leave ~/.local/bin symlinks into a repo .venv that shadow
# the system entry points and break the tray on Wayland (xorg backend crash).
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -n "$USER_HOME" ]; then
        for bin in whydpi whydpi-tray; do
            link="$USER_HOME/.local/bin/$bin"
            if [ -L "$link" ] && readlink "$link" | grep -qE '/\.venv/'; then
                rm -f "$link"
                echo "ℹ️  Removed stale venv symlink: $link"
            fi
        done
    fi
fi

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

# Offer to start the tray in the installer's desktop session (autostart only
# applies on the next login; this avoids "service is up but no icon" confusion).
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    echo ""
    read -p "Launch whyDPI tray in ${SUDO_USER}'s desktop session now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        TRAY_DISPLAY=$(sudo -u "$SUDO_USER" printenv DISPLAY 2>/dev/null || true)
        TRAY_DBUS=$(sudo -u "$SUDO_USER" printenv DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true)
        TRAY_ENV=(DISPLAY="${TRAY_DISPLAY:-:0}")
        if [ -n "$TRAY_DBUS" ]; then
            TRAY_ENV+=(DBUS_SESSION_BUS_ADDRESS="$TRAY_DBUS")
        fi
        TRAY_BIN="/usr/bin/whydpi-tray"
        if command -v runuser &>/dev/null; then
            runuser -u "$SUDO_USER" -- env "${TRAY_ENV[@]}" "$TRAY_BIN" &
        else
            sudo -u "$SUDO_USER" env "${TRAY_ENV[@]}" "$TRAY_BIN" &
        fi
        echo "✅ whyDPI tray launched (check the system tray / status notifier area)"
    else
        echo "ℹ️  Tray will autostart at your next login, or run: whydpi-tray"
    fi
fi

echo ""
echo "=============================================="
echo "✅ Installation Complete!"
echo "=============================================="
echo ""
echo "Usage:"
echo "  sudo whydpi start --configure-dns"
echo "  sudo whydpi stop"
echo "  whydpi-tray                    # system tray icon (also autostarts at login)"
echo "  sudo whydpi probe example.org example.net"
echo "  sudo whydpi cache list"
echo "  sudo whydpi dns-configure"
echo "  sudo whydpi dns-restore"
echo ""
echo "⚠️  Remember: For educational and research purposes only!"
echo ""
