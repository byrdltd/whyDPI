# Fedora RPM spec for whydpi.
#
# Build with:  rpmbuild -bb packaging/fedora/whydpi.spec
# (see packaging/fedora/build-rpm.sh for a self-contained wrapper)

%global pypi_name whydpi

Name:           %{pypi_name}
Version:        0.2.3
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

# Tray UX is optional but strongly encouraged — without these, the
# whydpi-tray command prints a friendly "install these extras" hint
# and exits, but nothing breaks for headless/server installs.
Recommends:     python3-pystray
Recommends:     python3-pillow
Recommends:     libnotify

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

# Desktop entry + XDG autostart (see PKGBUILD comment for the rationale
# behind installing the same file into two locations).
install -D -m 644 packaging/desktop/whydpi-tray.desktop \
  %{buildroot}%{_datadir}/applications/whydpi-tray.desktop
install -D -m 644 packaging/desktop/whydpi-tray.desktop \
  %{buildroot}%{_sysconfdir}/xdg/autostart/whydpi-tray.desktop

# Hicolor icons so the DE can resolve Icon=whydpi at any panel size.
for sz in 16 32 48 64 128 256 512; do
  install -D -m 644 assets/logo-${sz}.png \
    %{buildroot}%{_datadir}/icons/hicolor/${sz}x${sz}/apps/whydpi.png
done

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
%{_datadir}/applications/whydpi-tray.desktop
%config(noreplace) %{_sysconfdir}/xdg/autostart/whydpi-tray.desktop
%{_datadir}/icons/hicolor/*/apps/whydpi.png

%changelog
* Sat Apr 18 2026 byrdltd <byrdltd@users.noreply.github.com> - 0.2.3-1
- Windows installer fixes: shellexec flag for UAC-elevated post-install
  launch (fixes CreateProcess error 740), and whydpi.ui.tray / whydpi.cli
  are now correctly bundled into the PyInstaller onefile exes.
- Linux: ship an XDG autostart entry so the tray appears on login
  without manual setup; install hicolor icons (16-512px); tray now
  fires a libnotify toast at startup and on every service state
  transition so the "is whyDPI actually running?" question is visible
  on the desktop instead of hidden in a panel indicator.

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
