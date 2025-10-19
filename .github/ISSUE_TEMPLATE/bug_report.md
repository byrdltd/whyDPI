---
name: Bug Report
about: Report a bug or unexpected behavior in whyDPI
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

<!-- A clear and concise description of what the bug is -->

## Steps to Reproduce

1.
2.
3.
4.

## Expected Behavior

<!-- What you expected to happen -->

## Actual Behavior

<!-- What actually happened -->

## Environment

**Operating System:**
<!-- e.g., Arch Linux, Ubuntu 22.04, Fedora 39 -->

**Kernel Version:**
```bash
uname -r
# Output:
```

**Python Version:**
```bash
python3 --version
# Output:
```

**whyDPI Version:**
```bash
whydpi --version
# Output:
```

**Installation Method:**
- [ ] install.sh script
- [ ] pip install
- [ ] Manual installation
- [ ] Other (please specify):

## System Configuration

**iptables rules:**
```bash
sudo iptables -t mangle -L -v -n
# Output (paste here):
```

**DNS Configuration:**
```bash
cat /etc/resolv.conf
# Output (paste here):
```

**NetworkManager Status:**
```bash
systemctl status NetworkManager
# Output (paste here, if applicable):
```

## Error Messages / Logs

<!-- Paste any error messages or relevant log output -->

```
# Error messages here
```

**Verbose Mode Output (if available):**
```bash
sudo whydpi start --verbose
# Output (paste here):
```

## Additional Context

<!-- Any other information that might be relevant -->

- Are you behind a corporate firewall or VPN?
- Did this work before? If so, what changed?
- Are you using any other network manipulation tools?
- Have you tested in a VM or isolated environment?

## Troubleshooting Already Attempted

- [ ] Verified I'm running as root/sudo
- [ ] Checked iptables rules with `sudo iptables -t mangle -L -v -n`
- [ ] Verified DNS configuration with `cat /etc/resolv.conf`
- [ ] Tried stopping and restarting whyDPI
- [ ] Tested with default parameters (no custom TTL, ports, etc.)
- [ ] Checked the [README troubleshooting section](https://github.com/byrdltd/whyDPI#troubleshooting)
- [ ] Searched existing issues for similar problems

## Security Note

**⚠️ If this is a security vulnerability, please DO NOT open a public issue.**

Instead, report it privately via [GitHub Security Advisories](https://github.com/byrdltd/whyDPI/security/advisories/new).

See our [Security Policy](https://github.com/byrdltd/whyDPI/blob/main/SECURITY.md) for details.
