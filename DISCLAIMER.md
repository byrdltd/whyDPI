# whyDPI — Disclaimer and Acceptable-Use Statement

> **In plain language:** whyDPI is a research and education project.  Before
> you run it, please read this page.  You — not the authors, not the
> packagers, not the mirrors — are responsible for how and where you use
> it.

This project exists so that network engineers, security researchers and
curious users can observe and measure how consumer-ISP **Deep Packet
Inspection** (DPI) systems react to carefully shaped TLS handshakes.
It has no built-in list of "blocked sites" or "countries to bypass":
its behaviour is driven entirely by the destinations the operator
(*you*) chooses to send through it.

That neutrality is powerful, and easy to misuse.  The sections below
spell out what we do and do not endorse, what the technical limits
are, and the commitments you implicitly make by running the software.

---

## 1. Scope of the project

whyDPI is **educational tooling** in the same spirit as Wireshark,
Scapy, nmap, Burp Suite or GoodbyeDPI.  It is intended for:

* Studying how DPI middleboxes classify TLS flows.
* Reproducing published research on TLS record fragmentation, SNI
  handling and active network censorship.
* Operating **your own** endpoint against **your own** network, on
  lab / research equipment, or on a production link *for which you
  hold explicit written authority to deviate from default filtering*.
* Teaching courses on applied networking, TLS internals and
  censorship circumvention techniques.

whyDPI is **not** intended for, and the authors do not condone using
it to:

* Circumvent filters specifically designed to protect minors
  (school-network filters, family-safety controls, regulator-mandated
  age-verification gateways).
* Evade the terms of a corporate acceptable-use policy, BYOD agreement
  or managed-device MDM profile that you have accepted.
* Enable access to content whose distribution is unlawful *in your
  jurisdiction regardless of the transport layer* — including, but not
  limited to, child sexual abuse material, non-consensual intimate
  imagery, content produced through human trafficking, material
  protected by legitimate copyright that you do not hold a licence
  to, or material covered by an applicable court order.
* Interfere with emergency services, industrial-control traffic,
  hospital networks, aviation/maritime communications or other
  critical infrastructure.
* Mount denial-of-service, traffic amplification or surveillance
  attacks against third parties.

## 2. Legal responsibility is yours

Running whyDPI modifies how your operating system resolves DNS, routes
packets and negotiates TLS.  In many jurisdictions the act of doing so
is perfectly legal; in others it may conflict with:

* The subscriber agreement with your Internet service provider.
* Specific court orders or regulatory injunctions that oblige the ISP
  to filter certain destinations.
* Workplace or educational-institution network policies.
* Data-protection rules when you operate the DoH stub on behalf of
  other users whose queries you then log or proxy.

You are the operator and therefore the legally responsible party.
The authors, maintainers, distributors and packagers of whyDPI make
no warranty of fitness, do not certify the tool for any particular
purpose, and accept no liability for any loss, damage, fine or
criminal consequence arising from its use.  See `LICENSE` for the
full MIT warranty disclaimer.

## 3. Privacy and telemetry

whyDPI **does not** contain:

* Any telemetry, analytics, crash reporter or phone-home beacon.
* Any hard-coded upstream that reports usage metadata.
* Any auto-update channel that silently fetches new payloads.

It **does** write, by default:

* A single file `strategies.json` under the cache directory
  (`/run/whydpi/` on Linux packaged installs, `~/.cache/whydpi/` on
  pip installs, `%LOCALAPPDATA%\whyDPI\` on Windows), recording which
  fragmentation recipe worked for which SNI.  The file contains
  hostnames you actively connected to — treat it as sensitive.
* Diagnostic output to the standard logging facility of your OS
  (`journalctl -u whydpi` on Linux, Windows Event Viewer on Windows).
* Temporary per-connection state held in memory only for the lifetime
  of the connection.

On Linux the cache directory is placed on a tmpfs when the systemd
unit is used, so a reboot wipes the on-disk strategy history.  The
tray's *Quit* action asks systemd to stop the service, which on the
packaged install causes the tmpfs to be released.  Pip installs do
not get this automatic wipe — operators should clear
`~/.cache/whydpi/` manually if they need browse-history privacy.

## 4. Security posture

whyDPI operates with elevated privileges by design:

* Linux: the systemd unit runs as a dedicated unprivileged user with
  a narrow set of capabilities (`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`)
  plus a Netfilter/NFT mark that redirects the relevant flows.
* Windows: the tray and CLI binaries carry a `requireAdministrator`
  UAC manifest because the WinDivert kernel driver and
  `DnsFlushResolverCache` APIs refuse to operate from non-elevated
  processes.

Running elevated code expands your attack surface.  Only install
whyDPI from the official channels listed in `README.md`.  If you
distribute your own build, please preserve the `LICENSE`, `NOTICE`
and this `DISCLAIMER.md` in the resulting artefacts.

## 5. Export and sanctions

Cryptographic software may be subject to export controls.  whyDPI
itself contains no cryptographic primitives it implements from
scratch — it uses the system's TLS library (OpenSSL on Linux,
Schannel/bcrypt via `ssl.SSLContext` on Windows).  Nevertheless, the
use, redistribution or transport of this software across a national
border may be constrained by the laws of your country, of the
country you are transporting it to, or of the country you hold
citizenship in.  Check before you ship.

## 6. How to comply

By running whyDPI you acknowledge that:

1. You have read this disclaimer and understand that its purpose is
   research and education.
2. You hold the legal standing (ownership, written authorisation,
   safe-harbour defence under your local academic-research statute,
   etc.) to operate the tool on the network segments you point it
   at.
3. You will not use the tool to reach content that is unlawful
   regardless of the underlying transport, nor to interfere with
   services whose filtering exists to protect minors or public
   safety.
4. You indemnify the authors, maintainers, packagers and
   distributors of whyDPI against any claim arising from your
   deployment decisions.

If you cannot in good faith commit to points 1–4, please stop
using the tool and uninstall it: `systemctl stop whydpi &&
pacman -R whydpi` (Linux) or the Inno Setup uninstaller under
*Apps & features* (Windows).

---

*Questions or concerns about this disclaimer?  Open an issue at
<https://github.com/byrdltd/whyDPI/issues> — in English so the whole
community can follow.*
