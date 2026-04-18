# Fedora RPM spec for whydpi.
#
# Build with:  rpmbuild -bb packaging/fedora/whydpi.spec
# (see packaging/fedora/build-rpm.sh for a self-contained wrapper)

%global pypi_name whydpi

Name:           %{pypi_name}
Version:        0.2.2
Release:        1%{?dist}
Summary:        Adaptive, per-SNI DPI bypass with TLS fragmentation

License:        MIT
URL:            https://github.com/byrdltd/whyDPI
Source0:        https://github.com/byrdltd/whyDPI/archive/v%{version}.tar.gz#/%{pypi_name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-build
BuildRequires:  python3-installer
BuildRequires:  python3-wheel
BuildRequires:  systemd-rpm-macros

Requires:       python3 >= 3.10
Requires:       iptables

%description
whyDPI is a transparent TLS proxy and DNS forwarder for research
environments.  It ships zero hard-coded hostnames: what works for a
given destination is discovered at runtime, cached per-SNI, and refined
when conditions change.

Key features:
  * Runtime TLS fragmentation strategy discovery
  * Per-SNI strategy cache on tmpfs (wiped on shutdown)
  * Atomic netfilter (iptables/ip6tables) rules, IPv4 + IPv6
  * DNS-over-HTTPS stub resolver

For educational and research purposes only.

%prep
%autosetup -n whyDPI-%{version}

%build
%py3_build_wheel

%install
%py3_install_wheel %{pypi_name}-%{version}-*.whl
install -D -m 644 whydpi.service %{buildroot}%{_unitdir}/whydpi.service

%post
%systemd_post whydpi.service

%preun
%systemd_preun whydpi.service

%postun
%systemd_postun_with_restart whydpi.service

%files
%license LICENSE
%doc README.md
%{_bindir}/whydpi
%{_bindir}/whydpi-tray
%{python3_sitelib}/whydpi/
%{python3_sitelib}/whydpi-%{version}.dist-info/
%{_unitdir}/whydpi.service

%changelog
* Sat Apr 18 2026 byrdltd <byrdltd@users.noreply.github.com> - 0.2.2-1
- Cross-platform tray (pystray) with polkit-escalated service control.
- Windows port: WinDivert-based packet fragmenter + netsh DNS manager,
  shipped as native .exe plus Scoop manifest.
- Linux behaviour is byte-identical; no configuration migration.

* Sat Apr 18 2026 byrdltd <byrdltd@users.noreply.github.com> - 0.2.1-1
- Release-tag bump only; no code changes from 0.2.0.

* Sat Apr 18 2026 byrdltd <byrdltd@users.noreply.github.com> - 0.2.0-1
- Initial Fedora packaging.
- Full rewrite: adaptive per-SNI TLS fragmentation discovery; DoH stub
  resolver; atomic netfilter rules; IPv4 + IPv6 support; tmpfs-backed
  strategy cache wiped on shutdown for privacy.
