# Security Policy

## Disclaimer

**whyDPI** is an educational and research tool designed to demonstrate DPI bypass techniques. This project:

- Requires root privileges for packet manipulation
- Modifies system network configuration (DNS, iptables, NetworkManager)
- Manipulates network traffic at the packet level
- Is intended for educational, research, and personal network freedom purposes only

**Use responsibly and in compliance with local laws and regulations.**

## Reporting Security Issues

If you discover a security vulnerability in whyDPI, please report it via:

### **[GitHub Security Advisories](https://github.com/byrdltd/whyDPI/security/advisories/new)**

This allows us to discuss and fix the issue privately before public disclosure.

**Please DO NOT open public issues for security vulnerabilities.**

## What Qualifies as a Security Issue

### ✅ **In Scope - Please Report:**

- **Code vulnerabilities**
  - Injection attacks (command injection, code execution)
  - Buffer overflows or memory corruption
  - Path traversal or file system access issues
  - Unvalidated input handling

- **Privilege escalation**
  - Unintended privilege escalation beyond necessary root access
  - Insecure temporary file handling
  - Race conditions in privilege checks

- **Packet manipulation bugs**
  - Incorrect packet crafting leading to network instability
  - Unintended packet injection beyond DPI bypass functionality
  - Memory leaks or crashes in packet handling

- **Configuration vulnerabilities**
  - DNS configuration errors breaking internet connectivity
  - iptables rules persisting incorrectly
  - Inability to restore original system state
  - Insecure file permissions

- **Dependency vulnerabilities**
  - Known CVEs in NetfilterQueue or scapy
  - Insecure dependency usage patterns

- **Information disclosure**
  - Unintended logging of sensitive data
  - Packet payload exposure beyond necessary processing

### ❌ **Out of Scope - Not Security Issues:**

- **By design functionality**
  - "Tool requires root access" - This is required for packet manipulation
  - "Tool bypasses DPI/firewalls" - This is the intended purpose
  - "Modifies system configuration" - This is necessary for operation
  - "Uses third-party DNS" - This is user-configurable behavior

- **Legal/Compliance issues**
  - ISP terms of service violations
  - Local law compliance
  - Network policy violations
  - Ethical concerns about bypassing restrictions

- **Misuse scenarios**
  - User modifications for malicious purposes
  - Deployment in unauthorized environments
  - Integration into offensive security tools

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Responsible Disclosure Guidelines

We ask that you:

1. **Allow reasonable time** for a fix before public disclosure (we aim for 90 days)
2. **Provide sufficient detail** to reproduce the issue:
   - Affected component (DNS config, packet injection, iptables, etc.)
   - Steps to reproduce
   - Expected vs. actual behavior
   - Potential impact (system stability, data exposure, etc.)
   - Proof of concept (if available)

3. **Do not publicly disclose** until we've released a fix
4. **Do not exploit** the vulnerability beyond proof of concept testing

## Security Best Practices for Users

When using whyDPI:

- ✅ Review source code before granting root access
- ✅ Test in a virtual machine or isolated environment first
- ✅ Keep dependencies updated (Dependabot alerts enabled)
- ✅ Use `--stop` to cleanly restore system configuration
- ✅ Monitor system logs for unexpected behavior
- ✅ Verify iptables rules with `sudo iptables -t mangle -L -v -n`
- ✅ Check DNS configuration with `resolvectl status` or `cat /etc/resolv.conf`

## Development Security

### For Contributors

When contributing to whyDPI:

- Never introduce additional privilege requirements beyond existing root access
- Validate all user input (ports, TTL values, queue numbers)
- Avoid hardcoding credentials or sensitive data
- Test DNS restoration thoroughly (`--stop` functionality)
- Ensure iptables rules are properly cleaned up
- Pin dependency versions for reproducible builds
- Document security implications of new features

### Code Review Focus Areas

Pull requests will be reviewed for:

- Input validation and sanitization
- Proper error handling (especially in packet processing)
- Safe system command execution (no shell injection)
- Secure file operations (permissions, race conditions)
- Memory safety in packet handling
- Proper cleanup of system modifications

## Acknowledgments

We appreciate responsible disclosure and will credit security researchers (with their permission) who report valid security issues.

## Contact

For security concerns, use [GitHub Security Advisories](https://github.com/byrdltd/whyDPI/security/advisories/new).

For general questions, use [GitHub Issues](https://github.com/byrdltd/whyDPI/issues).

---

**Last Updated:** 2025-10-19
