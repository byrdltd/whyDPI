# Fedora RPM spec for whydpi.
#
# Build with:  rpmbuild -bb packaging/fedora/whydpi.spec
# (see packaging/fedora/build-rpm.sh for a self-contained wrapper)

%global pypi_name whydpi

Name:           %{pypi_name}
Version:        1.3.1
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
Recommends:     python3-tkinter
Recommends:     libnotify
Recommends:     zenity

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

# Application-menu launcher only.  Login autostart is an opt-in from
# the tray ("Launch whyDPI on login"), matching Linux convention:
# install finishes, the user clicks.
install -D -m 644 packaging/desktop/whydpi-tray.desktop \
  %{buildroot}%{_datadir}/applications/whydpi-tray.desktop
install -D -m 755 packaging/linux/first-run-launch.sh \
  %{buildroot}%{_prefix}/lib/whydpi/first-run-launch.sh

# Hicolor icons so the DE can resolve Icon=whydpi at any panel size.
for sz in 16 32 48 64 128 256 512; do
  install -D -m 644 assets/icon-${sz}.png \
    %{buildroot}%{_datadir}/icons/hicolor/${sz}x${sz}/apps/whydpi.png
done

%pre
# Scriptlet is from the new RPM; on-disk first-run-launch.sh may still
# be the previous version, so pkill is inlined.
if [ "$1" -ge 2 ]; then
  pkill -f '/usr/bin/whydpi-tray' >/dev/null 2>&1 || :
  pkill -f 'python.*-m whydpi.ui.tray' >/dev/null 2>&1 || :
fi

%post
%systemd_post whydpi.service
if [ -x /usr/lib/whydpi/first-run-launch.sh ]; then
  if [ "$1" -ge 2 ]; then
    /usr/lib/whydpi/first-run-launch.sh --restart >/dev/null 2>&1 || :
  else
    /usr/lib/whydpi/first-run-launch.sh >/dev/null 2>&1 || :
  fi
fi

%preun
%systemd_preun whydpi.service
if [ "$1" = 0 ]; then
  pkill -f '/usr/bin/whydpi-tray' >/dev/null 2>&1 || :
  pkill -f 'python.*-m whydpi.ui.tray' >/dev/null 2>&1 || :
fi

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
%{_prefix}/lib/whydpi/first-run-launch.sh
%{_datadir}/icons/hicolor/*/apps/whydpi.png

%changelog
* Wed Sep 23 2026 byrdltd <byrdltd@users.noreply.github.com> - 1.3.1-1
- Packaging refresh; no functional change since 1.3.0.

* Thu Aug 27 2026 byrdltd <byrdltd@users.noreply.github.com> - 1.3.0-1
- Adaptive per-SNI TLS fragmentation with parallel strategy discovery.
- DoH stub resolver, IPv4/IPv6 transparent proxy, CDN IP-range rotation.
- Encrypted-ClientHello neutralisation and multi-record ClientHello reassembly.
- Cross-platform system tray and Windows WinDivert decoy fallback.
