# whyDPI

**Educational DPI Bypass Tool for Research Purposes**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

---

## ⚠️ DISCLAIMER / YASAL UYARI

### English

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

This tool is provided for educational purposes and network security research only. Users are solely responsible for compliance with all applicable laws and regulations in their jurisdiction.

- ⚠️ Bypassing network restrictions may violate terms of service or local laws
- ⚠️ The developers and contributors assume **NO LIABILITY** for any misuse
- ⚠️ Use at your own risk and responsibility
- ⚠️ This tool is provided "AS IS" without warranty of any kind

**By using this software, you acknowledge that you have read this disclaimer and agree to use it responsibly and legally.**

### Türkçe

**SADECE EĞİTİM VE ARAŞTIRMA AMAÇLIDIR**

Bu araç sadece eğitim amaçlı ve ağ güvenliği araştırması için sağlanmaktadır. Kullanıcılar bulundukları yargı bölgesindeki tüm geçerli yasa ve düzenlemelere uymaktan **tamamen sorumludur**.

- ⚠️ Ağ kısıtlamalarını aşmak hizmet şartlarını veya yerel yasaları ihlal edebilir
- ⚠️ Geliştiriciler ve katkıda bulunanlar kötüye kullanımdan **SORUMLU DEĞİLDİR**
- ⚠️ Kullanım riski ve sorumluluğu **size aittir**
- ⚠️ Bu araç "OLDUĞU GİBİ" herhangi bir garanti olmaksızın sağlanmaktadır

**Bu yazılımı kullanarak, bu uyarıyı okuduğunuzu ve sorumlu ve yasal bir şekilde kullanmayı kabul ettiğinizi onaylamış olursunuz.**

---

## What is whyDPI?

whyDPI is a minimal, educational tool for understanding Deep Packet Inspection (DPI) bypass techniques used by network security researchers and privacy advocates.

### How it works

whyDPI uses **Random Garbage Fake Packet Injection** - a simple yet effective technique against DPI systems.

1. **DNS Bypass**: Configures Yandex DNS (77.88.8.8) to avoid DNS hijacking
2. **Packet Interception**: Intercepts outgoing HTTPS/HTTP packets via Linux NFQUEUE
3. **Random Garbage Injection**: Generates 500 bytes of random data and sends with TTL=3
4. **Real Packet Release**: Releases the full real packet normally

```
[Browser] → [iptables NFQUEUE] → [whyDPI]
                                    ├─ Inject random garbage (500 bytes, TTL=3, SAME SEQ)
                                    └─ Release real packet (SAME SEQ)
              ↓
         [DPI sees garbage first, gets confused]
              ↓
         [Garbage expires after 3 hops]
              ↓
         [Real packet passes through confused DPI]
              ↓
         [Server sees both, ignores garbage, accepts real]
```

**Why this works:**
- Every packet contains unique random data (`os.urandom()` - cryptographically secure)
- DPI cannot build signatures (all packets different)
- DPI sees garbage first → pattern matching fails → confusion
- Server receives both but ignores garbage (duplicate SEQ number)
- Simple, effective, 100% independent implementation

### Key Features

- ✅ **Pure Python**: 100% Python implementation, zero binary dependencies
- ✅ **Minimal**: Clean, well-structured code (~600 lines)
- ✅ **Transparent**: No proxy configuration needed
- ✅ **Educational**: Well-commented code for learning
- ✅ **Robust DNS**: Auto-configures DNS bypass (masks systemd-resolved, configures NetworkManager)
- ✅ **Configurable**: Adjust TTL, ports, queue number
- ✅ **Systemd**: Optional daemon mode

---

## Installation

### Prerequisites

- **Linux** (tested on Arch/CachyOS, should work on Debian/Ubuntu/Fedora)
- **Python 3.8+**
- **Root access** (required for iptables and raw sockets)

### Quick Install

```bash
git clone https://github.com/byrdltd/whyDPI.git
cd whyDPI
sudo ./install.sh
```

**During installation:**
- When asked "install systemd service?", choose **Yes (y)** to enable auto-start at boot
- When asked "Start whyDPI now?", choose **Yes (y)** to start immediately
- ✅ whyDPI will automatically start on every reboot

### Manual Install

```bash
# Install system dependencies
# Arch/CachyOS:
sudo pacman -S python python-pip libnetfilter_queue iptables

# Debian/Ubuntu:
sudo apt install python3 python3-pip libnetfilter-queue1 iptables

# Fedora:
sudo dnf install python3 python3-pip libnetfilter_queue iptables

# Install Python dependencies
pip3 install -r requirements.txt

# Install whyDPI
pip3 install -e .
```

---

## Usage

### Basic Usage

```bash
# Start whyDPI with automatic DNS configuration
sudo whydpi start --configure-dns

# Start whyDPI (without DNS configuration)
sudo whydpi start

# Stop whyDPI
sudo whydpi stop
```

### Advanced Usage

```bash
# Custom TTL (default: 3)
sudo whydpi start --ttl 5

# Custom ports (default: 80, 443)
sudo whydpi start --ports 80 443 8080

# Custom NFQUEUE number (default: 200)
sudo whydpi start --queue 100

# Verbose logging
sudo whydpi start -v
```

### DNS Management

```bash
# Configure Yandex DNS
sudo whydpi dns-configure

# Restore original DNS
sudo whydpi dns-restore
```

### Systemd Service (Auto-Start at Boot)

**If you installed via `install.sh` and chose "Yes" for systemd service:**
- ✅ whyDPI is **automatically enabled at boot**
- ✅ whyDPI will start on every reboot
- ✅ No manual intervention needed

**Manual Installation (if skipped during install.sh):**

```bash
# Copy service file
sudo cp whydpi.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable at boot (IMPORTANT!)
sudo systemctl enable whydpi

# Start now
sudo systemctl start whydpi
```

**Service Management:**

```bash
# Check status
sudo systemctl status whydpi

# View logs
sudo journalctl -u whydpi -f

# Restart
sudo systemctl restart whydpi

# Disable auto-start at boot
sudo systemctl disable whydpi

# Stop service
sudo systemctl stop whydpi
```

---

## Testing

Test with websites that may be subject to DPI inspection in your region:

```bash
# Start whyDPI
sudo whydpi start --configure-dns

# Test in browser
# - https://discord.com
# - Other sites as appropriate for your research
```

**Note:** Test responsibly and only on networks you own or have permission to test.

---

## How It Works (Technical)

### 1. DNS Bypass

ISPs may hijack DNS queries and return fake IPs for blocked sites.

**Solution:** Use alternative DNS (Yandex 77.88.8.8) to get real IPs.

whyDPI automatically:
- Stops and masks `systemd-resolved` (prevents auto-restart)
- Removes symlinks and creates immutable `/etc/resolv.conf`
- Configures NetworkManager connections with Yandex DNS
- Makes DNS configuration persistent across reboots

```
User → Yandex DNS (77.88.8.8) → Real IP
     ✓ Bypasses ISP DNS hijacking
     ✓ Prevents systemd-resolved override
     ✓ Survives NetworkManager changes
```

### 2. DPI Bypass - Random Garbage Injection

ISPs use Deep Packet Inspection to analyze HTTPS traffic (SNI in TLS handshake).

**Solution:** Inject random garbage packets with TTL=3 to confuse DPI:

```
1. Browser sends: [Real TLS ClientHello with SNI: discord.com]
2. whyDPI captures it via NFQUEUE
3. whyDPI generates: 500 bytes of random garbage (os.urandom - cryptographically secure)
4. whyDPI injects: Garbage packet with TTL=3, SAME SEQ as real packet
5. whyDPI releases: Full REAL packet (also with SAME SEQ)
6. DPI sees: Random garbage first → pattern matching fails → confused state
7. Garbage packet: Dies after 3 hops (never reaches server)
8. Real packet: Passes through confused DPI → connection succeeds
9. Server: Sees both packets with duplicate SEQ → ignores garbage → accepts real
```

**Why Random Garbage Injection works:**
- Every packet contains unique random data (DPI can't build signatures)
- Simple and effective against most DPI systems
- Low overhead - only 500 bytes per connection
- Exploits DPI's limited state tracking capabilities
- 100% independent implementation using Python's os.urandom()

### 3. iptables NFQUEUE

```
                 ┌──────────────┐
                 │   Browser    │
                 └──────┬───────┘
                        │ HTTPS (443)
                        ▼
                 ┌──────────────┐
                 │  iptables    │
                 │   POSTROUTING│
                 └──────┬───────┘
                        │ NFQUEUE
                        ▼
                 ┌──────────────┐
                 │    whyDPI    │ ← Injects fake packet
                 └──────┬───────┘
                        │ Real + Fake packets
                        ▼
                 ┌──────────────┐
                 │   Network    │
                 └──────────────┘
```

---

## Parameters Explained

```bash
whydpi start --queue 200 --ttl 3 --ports 80 443
```

- `--queue 200` - NFQUEUE number (must match iptables rule)
- `--ttl 3` - TTL of fake packet (dies after 3 hops)
- `--ports 80 443` - Ports to intercept (HTTP, HTTPS)

**Why TTL=3?**
- Too low (1-2): May not reach ISP's DPI
- Too high (>5): May reach destination server, causing issues
- **TTL=3**: Perfect balance - reaches DPI but not server

---

## Project Structure

```
whyDPI/
├── whydpi/
│   ├── __init__.py        # Package initialization
│   ├── __main__.py        # CLI entry point
│   ├── config.py          # Configuration and fake packets
│   ├── dns_config.py      # DNS configuration helper
│   ├── nfqueue_handler.py # Packet interception logic
│   └── packet_injector.py # Fake packet injection
├── install.sh             # Installation script
├── setup.py               # Python package setup
├── requirements.txt       # Python dependencies
├── whydpi.service         # Systemd service file
├── LICENSE                # MIT License + disclaimers
└── README.md              # This file
```

---

## Troubleshooting

### "Permission denied" errors

Make sure you're running as root:
```bash
sudo whydpi start
```

### DNS not working after restore

```bash
sudo chattr -i /etc/resolv.conf
sudo systemctl restart NetworkManager  # or systemd-resolved
```

### whyDPI not starting

```bash
# Check logs
sudo whydpi start -v

# Check if ports are correct
sudo iptables -t mangle -L POSTROUTING -v -n

# Check if nfqueue is working
lsmod | grep nfnetlink
```

### Still can't access blocked sites

1. **Verify DNS is configured**:
   ```bash
   cat /etc/resolv.conf  # Should show: nameserver 77.88.8.8
   getent ahosts discord.com  # Should show real Cloudflare IPs (162.159.x.x), NOT ISP fake IPs
   ```

2. **Check systemd-resolved status**:
   ```bash
   systemctl status systemd-resolved  # Should be: inactive (dead), masked
   ```

3. **Clear browser DNS cache**: Restart browser or use incognito mode

4. **Try different TTL values**: `sudo whydpi start --ttl 2` or `--ttl 5`

5. Some ISPs use multiple DPI systems - whyDPI may not work in all cases

---

## Uninstall

```bash
# Stop service
sudo systemctl stop whydpi
sudo systemctl disable whydpi

# Remove systemd service
sudo rm /etc/systemd/system/whydpi.service
sudo systemctl daemon-reload

# Restore DNS
sudo whydpi dns-restore

# Uninstall Python package
pip3 uninstall whydpi

# Remove iptables rules
sudo whydpi stop
```

---

## Contributing

Contributions are welcome! This is an educational project, so:

- ✅ Bug fixes and improvements
- ✅ Documentation improvements
- ✅ Additional bypass techniques (with research references)
- ✅ Support for more platforms

**Note:** All contributions must maintain the educational nature and include appropriate disclaimers.

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

This software is provided "AS IS" without warranty of any kind.

---

## FAQ

**Q: Will this slow down my internet?**
A: No significant impact. whyDPI only processes first few packets of each connection.

**Q: Does this work on other distros?**
A: Yes, works on any Linux with iptables/systemd. Adjust package manager commands as needed.

**Q: Can I use this with VPN/Tor?**
A: whyDPI is not a VPN. It can be used alongside VPN for additional privacy, but it's designed for direct connections.

**Q: What if my ISP updates their DPI?**
A: DPI systems evolve. You may need to adjust parameters (TTL, etc.) or try different techniques.

**Q: Is this legal?**
A: This tool is for educational research. Users must comply with local laws. We assume no liability for misuse.

---

**Last Updated:** October 19, 2025
**Version:** 0.1.0
**Status:** Alpha - Educational Release

---

