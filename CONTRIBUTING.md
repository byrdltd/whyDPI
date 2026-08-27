# Contributing to whyDPI

Thank you for your interest in contributing to whyDPI! This document provides guidelines for contributing to this educational DPI bypass tool.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep our community approachable and respectable.

## Safe, responsible contributions

whyDPI is **educational research software**.  To keep the repository
usable in public and safe for downstream packagers:

- **Do not** embed real-world blocked-site names, pornography brands,
  gambling operators or other sensational domains in code, tests,
  fixtures, logs or commit messages — use `example.com`,
  `192.0.2.0/24` (TEST-NET-1), or clearly fake labels.
- **Do not** commit credentials, API tokens, personal machine paths or
  packet captures that could identify users.
- **Do not** submit changes whose primary purpose is to help evade a
  specific law, workplace policy or parental-control product you do not
  administer — technical improvements that happen to help generic DPI
  research are fine; “unblock X in country Y” drive-by PRs are not.
- **Do** read [`DISCLAIMER.md`](DISCLAIMER.md) before shipping UX that
  weakens the acceptable-use story (e.g. hiding the first-run dialog).

Documentation and UI copy stay in **English** so the project remains
globally legible.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include as many details as possible:

**Use the bug report template** which includes:
- A clear and descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Your environment (OS, Python version, kernel version)
- Relevant logs and error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a detailed description of the proposed functionality
- Explain why this enhancement would be useful
- Include examples of how the feature would be used

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead, please follow our [Security Policy](SECURITY.md) and report via [GitHub Security Advisories](https://github.com/byrdltd/whyDPI/security/advisories/new).

### Pull Requests

We actively welcome your pull requests! Here's how to contribute code:

1. **Fork the repository** and create your branch from `main`
2. **Follow the development setup** instructions below
3. **Make your changes** following our coding standards
4. **Test your changes** thoroughly
5. **Update documentation** if needed
6. **Commit your changes** with clear commit messages
7. **Push to your fork** and submit a pull request

#### Pull Request Guidelines

- Fill in the pull request template
- Keep changes focused - one feature/fix per PR
- Write clear, descriptive commit messages
- Run `pytest` for logic changes (`pip install -e ".[dev]"` first)
- Ensure your code passes linting checks
- Update the README.md if you change functionality
- Reference related issues in your PR description

## Development Setup

### Prerequisites

- Linux system (Arch, Debian/Ubuntu, Fedora, or similar) and/or Windows
  for platform-specific work
- Python 3.10 or higher
- Root/sudo access (for testing packet manipulation)
- Git

### Setting Up Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/whyDPI.git
cd whyDPI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in editable mode + dev tools (pytest)
pip install -e ".[dev]"
```

Optional — git hooks for whitespace / YAML sanity (once per clone):

```bash
pip install pre-commit
pre-commit install
```

### System Dependencies

Install system packages required for NetfilterQueue:

**Arch Linux / CachyOS:**
```bash
sudo pacman -S libnetfilter_queue iptables python-pip gcc
```

**Debian / Ubuntu:**
```bash
sudo apt update
sudo apt install libnetfilter-queue-dev iptables python3-pip build-essential
```

**Fedora:**
```bash
sudo dnf install libnetfilter_queue-devel iptables python3-pip gcc
```

### Testing Your Changes

1. **Unit tests (no root, no network)** — from a venv:
   ```bash
   pip install -e ".[dev]"
   pytest
   ```

Since whyDPI requires root privileges and manipulates network traffic, **live** testing requires care:

1. **Test in a VM or isolated environment** first
2. **Verify iptables rules** are created correctly:
   ```bash
   sudo iptables -t mangle -L -v -n
   ```
3. **Test DNS configuration** changes:
   ```bash
   cat /etc/resolv.conf
   resolvectl status  # on systemd systems
   ```
4. **Verify cleanup** works properly:
   ```bash
   sudo whydpi --stop
   # Check that iptables rules are removed
   # Check that DNS is restored
   ```
5. **Test different scenarios**:
   - Fresh installation
   - Starting/stopping multiple times
   - Different parameter combinations (--ttl, --ports, etc.)
   - Systemd service functionality

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://peps.python.org/pep-0008/) with some specific guidelines:

- **Line length**: Maximum 100 characters (not 79)
- **Indentation**: 4 spaces (no tabs)
- **Imports**: Organize as: standard library, third-party, local imports
- **Docstrings**: Use triple quotes for all public functions/classes
- **Comments**: Explain *why*, not *what* (code should be self-explanatory)

### Code Organization

- Keep functions focused and single-purpose
- Maximum function length: ~50 lines (prefer smaller)
- Use descriptive variable names (no single letters except loop counters)
- Avoid global variables when possible
- Handle errors gracefully with try/except

### Documentation

- Add docstrings to all public functions and classes
- Include Args, Returns, Raises sections in docstrings
- Update README.md for user-facing changes
- Add inline comments for complex logic

### Example Function Documentation

```python
def inject_fake_packet(packet, ttl=3, payload_size=500):
    """
    Inject a random garbage packet to confuse DPI systems.

    Args:
        packet (scapy.Packet): Original packet to duplicate
        ttl (int): Time-to-live for fake packet (default: 3)
        payload_size (int): Size of random payload in bytes (default: 500)

    Returns:
        bool: True if injection succeeded, False otherwise

    Raises:
        ValueError: If ttl or payload_size are invalid
    """
    # Implementation...
```

### Commit Messages

Write clear commit messages following this format:

```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem this commit solves and why you chose
this particular solution.

- Bullet points are fine
- Use present tense: "Add feature" not "Added feature"
- Reference issues: Fixes #123, Closes #456
```

**Good commit messages:**
- `Fix DNS restoration on Fedora systems`
- `Add support for custom DNS servers via --dns flag`
- `Improve error handling in packet injection`

**Bad commit messages:**
- `fix bug`
- `update code`
- `changes`

## Project structure (current)

```
whyDPI/
├── whydpi/                 # Python package (CLI, engine, platforms, net, ui)
│   ├── cli.py              # ``whydpi`` subcommands
│   ├── core/               # strategy cache, discovery, engine
│   ├── net/                # TLS, DoH, transparent proxy (Linux)
│   ├── platforms/        # linux.py / windows.py engine wiring
│   ├── system/             # netfilter, resolver, windivert, dns_redirect_windows
│   └── ui/                 # tray, autostart, consent, status window
├── packaging/              # AUR, Debian, Fedora, Windows (Inno, PyInstaller)
├── tests/                  # pytest unit tests (no root / no live network)
├── pyproject.toml          # version, optional extras, pytest config
├── DISCLAIMER.md           # acceptable-use — read before UX changes
├── README.md
├── LICENSE
├── SECURITY.md
└── CONTRIBUTING.md         # this file
```

### Key entry points

- **`whydpi/core/engine.py`** — dispatches to `platforms.linux` or `platforms.windows`
- **`whydpi/net/proxy.py`** — transparent TLS proxy (Linux only)
- **`whydpi/system/windivert.py`** — WinDivert TLS shaping (Windows)
- **`whydpi/system/dns_redirect_windows.py`** — packet-layer DNS → DoH (Windows)

## Areas Needing Contributions

We especially welcome contributions in these areas:

### High Priority
- [x] Basic pytest coverage (`tests/` — strategy, cache, consent paths)
- [ ] Unit tests for packet parsing edge cases
- [ ] Integration tests for full DPI bypass workflow (VM / lab only)
- [ ] CI/CD workflow improvements
- [ ] Type hints throughout codebase
- [ ] Input validation improvements

### Medium Priority
- [ ] Support for additional Linux distributions
- [ ] Configuration file support (YAML/TOML)
- [ ] More DPI bypass techniques
- [ ] Performance optimizations
- [ ] Better logging and debugging options
- [ ] IPv6 support

### Documentation
- [ ] Video tutorials
- [ ] Architecture documentation (see also `docs/` locally — may be gitignored)
- [ ] Troubleshooting guide expansion
- [ ] Usage examples directory

### Nice to Have
- [ ] GUI or TUI interface
- [ ] Automatic DPI detection
- [ ] Statistics and monitoring
- [ ] Custom packet patterns
- [ ] Alternative DNS providers

## Questions?

If you have questions about contributing:

1. Check existing [issues](https://github.com/byrdltd/whyDPI/issues)
2. Open a new issue with the "question" label
3. Be specific and provide context

## Recognition

Contributors will be recognized in:
- GitHub contributors list (automatic)
- Release notes (for significant contributions)
- AUTHORS file (planned)

## License

By contributing to whyDPI, you agree that your contributions will be licensed under the MIT License. See [LICENSE](LICENSE) for details.

All contributions must be your original work or properly attributed. By submitting a contribution, you certify that:

- You created the contribution entirely yourself
- You have the right to submit it under the MIT License
- You understand this is an educational project with specific ethical guidelines

## Educational Purpose

Remember that whyDPI is an **educational and research tool**. When contributing:

- Maintain the educational focus in code comments
- Explain *how* and *why* DPI bypass techniques work
- Keep ethical considerations in mind
- Include appropriate warnings for powerful features
- Prioritize transparency and understanding over obscurity

---

Thank you for contributing to whyDPI! Your efforts help advance network security education and research.
