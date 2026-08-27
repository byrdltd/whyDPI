# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""User-visible copy, keyed for locale lookup.

Keys are stable identifiers (``section.element.qualifier``).  Add a key
to **every** catalog in the same change.  Brand name ``whyDPI`` stays
untranslated.
"""

from __future__ import annotations

DEFAULT_LANG = "en"
SUPPORTED = ("de", "en", "es", "fr", "ru", "tr")

EN: dict[str, str] = {
    # Tray menu
    "tray.menu.start": "Start whyDPI",
    "tray.menu.stop": "Stop whyDPI",
    "tray.menu.status": "Show status…",
    "tray.menu.cache": "Open cache folder",
    "tray.menu.autostart": "Launch whyDPI on login",
    "tray.menu.about": "About whyDPI v{version}",
    "tray.menu.disclaimer": "Acceptable use & disclaimer",
    "tray.menu.quit": "Quit",
    "tray.menu.update.check": "Check for updates",
    "tray.menu.update.install": "Install whyDPI v{version}…",
    "tray.title.running": "whyDPI v{version} — protecting",
    "tray.title.idle": "whyDPI v{version} — ready",
    # Toasts
    "tray.notify.protecting.title": "whyDPI is protecting this connection",
    "tray.notify.protecting.body": "Adaptive TLS fragmentation is on.",
    "tray.notify.ready.title": "whyDPI is ready",
    "tray.notify.ready.body": "Protection is off. Click the tray icon to start.",
    "tray.notify.stopped.title": "whyDPI protection is off",
    "tray.notify.stopped.body": "DNS has been restored to your original settings.",
    "tray.notify.autostart.on.title": "whyDPI will start when you sign in",
    "tray.notify.autostart.on.body": "The tray and protection resume at next login.",
    "tray.notify.autostart.off.title": "whyDPI will not start at sign-in",
    "tray.notify.autostart.off.body": "This takes effect the next time you sign in.",
    "tray.notify.autostart.fail.title": "Could not change sign-in setting",
    "tray.notify.autostart.fail.body": "See the whyDPI log for details.",
    "tray.notify.update.available.title": "whyDPI {version} is available",
    "tray.notify.update.available.body": "Open the tray menu and choose Install to update.",
    "tray.notify.update.uptodate.title": "whyDPI is up to date",
    "tray.notify.update.uptodate.body": "You are running v{version}.",
    "tray.notify.update.checkfail.title": "Could not check for updates",
    "tray.notify.update.installing.title": "Updating whyDPI…",
    "tray.notify.update.installing.body": "Installing {version}",
    "tray.notify.update.fail.title": "Update failed",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI is already running in the tray (near the clock). "
        "Right-click the shield icon to open the menu."
    ),
    "tray.dialog.update.title": "whyDPI update",
    "tray.dialog.update.body": (
        "whyDPI {version} is available.\n\n"
        "Download it from GitHub Releases and install now?"
    ),
    "tray.error.missing_deps": (
        "whyDPI tray needs optional extras:\n"
        "  pip install 'whydpi[tray]'\n"
        "or on Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nunderlying import error: {error}"
    ),
    "tray.error.not_admin": (
        "whyDPI on Windows must run as Administrator so that:\n"
        "  • WinDivert can load its kernel driver,\n"
        "  • DNS hijacking can open a WinDivert handle,\n"
        "  • the resolver cache can be flushed.\n"
        "\n"
        "Right-click the whyDPI shortcut and choose Run as administrator.\n"
        "The installer already requests elevation on a normal double-click."
    ),
    "tray.error.service_missing": (
        "The whyDPI service ({service}) is not installed.\n"
        "Install the whydpi package first, then open the tray again."
    ),
    # Consent
    "consent.title": "whyDPI — acceptable use",
    "consent.heading": "Read before you continue",
    "consent.summary": (
        "whyDPI is educational and research software.\n"
        "\n"
        "You choose every destination it touches. You are legally responsible "
        "for your use. Do not use it to bypass parental controls, policies you "
        "agreed to, court orders, or to access unlawful content.\n"
        "\n"
        "By accepting, you acknowledge DISCLAIMER.md in full. If you do not "
        "agree, choose Quit."
    ),
    "consent.full_label": "Full text:",
    "consent.checkbox": "I have read and accept",
    "consent.continue": "Continue",
    "consent.quit": "Quit",
    "consent.accept": "I have read and accept",
    "consent.open_full": "Open full disclaimer",
    # Status window
    "status.title": "whyDPI — learned strategies",
    "status.intro": (
        "Per-SNI strategies learned at runtime. "
        "Sensitive — only hostnames your traffic used appear here."
    ),
    "status.cache_file": "Cache file: {path}",
    "status.col.host": "SNI / host",
    "status.col.strategy": "Strategy",
    "status.col.ok": "Successes",
    "status.col.fail": "Failures",
    "status.col.last_ok": "Last success",
    "status.col.last_fail": "Last failure kind",
    "status.empty": "No entries yet",
    "status.close": "Close",
    "status.footer": "whyDPI v{version}",
    # Desktop entries
    "desktop.name": "whyDPI",
    "desktop.generic": "DPI bypass controller",
    "desktop.comment": "Start, stop and monitor whyDPI from the system tray",
    "desktop.autostart_comment": "Adaptive DPI bypass — system tray",
    # CLI (user-facing only)
    "cli.description": (
        "Educational DPI bypass — transparent TLS fragmentation and DoH. "
        "Set WHYDPI_TRACE=1 to log intercepted packets (Windows diagnostic)."
    ),
    "cli.epilog": (
        "Tray: set WHYDPI_SKIP_DISCLAIMER=1 only in CI/automation to skip "
        "the first-run dialog (not for personal machines)."
    ),
    "cli.help.config": "path to config.toml (default: ~/.config/whydpi/config.toml)",
    "cli.help.start": "start whyDPI",
    "cli.help.stop": "stop whyDPI and restore DNS",
    "cli.help.dns_configure": "pin /etc/resolv.conf to the stub resolver",
    "cli.help.dns_restore": "restore the original /etc/resolv.conf",
    "cli.help.probe": "probe hosts and report the winning strategy",
    "cli.help.cache": "inspect or prune the strategy cache",
    "cli.help.configure_dns": "pin /etc/resolv.conf at startup",
    "cli.help.probe_targets": "hosts for an optional pre-flight probe",
    "cli.help.dns_mode": "override dns.mode for this run",
    "cli.help.targets": "host[:port] targets to probe",
    "cli.help.verbose": "verbose logging",
    "cli.help.cache_list": "list cached hosts",
    "cli.help.cache_clear": "clear the entire cache",
    "cli.help.cache_forget": "forget specific hosts",
    "cli.help.cache_forget_hosts": "hosts to forget",
    "cli.error.root": "whyDPI must run as root (sudo)",
    "cli.cache.empty": "(cache empty)",
    "cli.cache.cleared": "cache cleared",
    "consent.error.no_tk": (
        "whyDPI needs Tk for the first-run dialog. "
        "Install the Tk bindings (for example: sudo pacman -S tk) "
        "or set WHYDPI_SKIP_DISCLAIMER=1 only for automation."
    ),
    "update.error.no_asset": "This release has no Windows installer.",
    "update.error.no_scoop": "scoop was not found on PATH.",
    "update.error.no_sha": "SHA256SUMS.txt has no entry for {name}.",
    "update.error.hash": "Installer hash mismatch (expected {expected}, got {actual}).",
}

TR: dict[str, str] = {
    "tray.menu.start": "whyDPI’yi başlat",
    "tray.menu.stop": "whyDPI’yi durdur",
    "tray.menu.status": "Durumu göster…",
    "tray.menu.cache": "Önbellek klasörünü aç",
    "tray.menu.autostart": "Oturum açılınca whyDPI’yi başlat",
    "tray.menu.about": "whyDPI v{version} hakkında",
    "tray.menu.disclaimer": "Kabul edilebilir kullanım ve feragatname",
    "tray.menu.quit": "Çıkış",
    "tray.menu.update.check": "Güncellemeleri denetle",
    "tray.menu.update.install": "whyDPI v{version} kur…",
    "tray.title.running": "whyDPI v{version} — koruyor",
    "tray.title.idle": "whyDPI v{version} — hazır",
    "tray.notify.protecting.title": "whyDPI bu bağlantıyı koruyor",
    "tray.notify.protecting.body": "Uyarlanabilir TLS parçalama açık.",
    "tray.notify.ready.title": "whyDPI hazır",
    "tray.notify.ready.body": "Koruma kapalı. Başlatmak için tepsi simgesine tıklayın.",
    "tray.notify.stopped.title": "whyDPI koruması kapalı",
    "tray.notify.stopped.body": "DNS özgün ayarlarına döndü.",
    "tray.notify.autostart.on.title": "whyDPI oturum açılışında başlayacak",
    "tray.notify.autostart.on.body": "Tepsi ve koruma bir sonraki oturumda devam eder.",
    "tray.notify.autostart.off.title": "whyDPI oturum açılışında başlamayacak",
    "tray.notify.autostart.off.body": "Değişiklik bir sonraki oturumda geçerli olur.",
    "tray.notify.autostart.fail.title": "Oturum açılışı ayarı değiştirilemedi",
    "tray.notify.autostart.fail.body": "Ayrıntılar için whyDPI günlüğüne bakın.",
    "tray.notify.update.available.title": "whyDPI {version} kullanıma hazır",
    "tray.notify.update.available.body": "Güncellemek için tepsi menüsünden Kur’u seçin.",
    "tray.notify.update.uptodate.title": "whyDPI güncel",
    "tray.notify.update.uptodate.body": "Çalışan sürüm v{version}.",
    "tray.notify.update.checkfail.title": "Güncelleme denetimi başarısız",
    "tray.notify.update.installing.title": "whyDPI güncelleniyor…",
    "tray.notify.update.installing.body": "{version} kuruluyor",
    "tray.notify.update.fail.title": "Güncelleme başarısız",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI zaten tepside çalışıyor (saatin yanındaki kalkan simgesi). "
        "Menü için simgeye sağ tıklayın."
    ),
    "tray.dialog.update.title": "whyDPI güncellemesi",
    "tray.dialog.update.body": (
        "whyDPI {version} kullanıma hazır.\n\n"
        "GitHub Sürümleri’nden indirilip şimdi kurulsun mu?"
    ),
    "tray.error.missing_deps": (
        "whyDPI tepsi simgesi ek bileşenler ister:\n"
        "  pip install 'whydpi[tray]'\n"
        "Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nimport hatası: {error}"
    ),
    "tray.error.not_admin": (
        "Windows’ta whyDPI Yönetici olarak çalışmalıdır:\n"
        "  • WinDivert çekirdek sürücüsünü yüklemek,\n"
        "  • DNS yönlendirmesi için WinDivert tutamacı açmak,\n"
        "  • çözümleyici önbelleğini temizlemek.\n"
        "\n"
        "Kısayola sağ tıklayıp Yönetici olarak çalıştır’ı seçin.\n"
        "Kurulum programı normal çift tıklamada yükseltme ister."
    ),
    "tray.error.service_missing": (
        "whyDPI hizmeti ({service}) kurulu değil.\n"
        "Önce whydpi paketini kurun, ardından tepsiyi yeniden açın."
    ),
    "consent.title": "whyDPI — kabul edilebilir kullanım",
    "consent.heading": "Devam etmeden önce okuyun",
    "consent.summary": (
        "whyDPI eğitim ve araştırma yazılımıdır.\n"
        "\n"
        "Dokunduğu her hedefi siz seçersiniz. Kullanımdan hukuken siz "
        "sorunlusunuz. Ebeveyn denetimini, kabul ettiğiniz kurum politikalarını, "
        "mahkeme kararlarını aşmak veya yasa dışı içeriğe erişmek için "
        "kullanmayın.\n"
        "\n"
        "Kabul ederek DISCLAIMER.md metninin tamamını onaylamış olursunuz. "
        "Katılmıyorsanız Çıkış’ı seçin."
    ),
    "consent.full_label": "Tam metin:",
    "consent.checkbox": "Okudum ve kabul ediyorum",
    "consent.continue": "Devam",
    "consent.quit": "Çıkış",
    "consent.accept": "Okudum ve kabul ediyorum",
    "consent.open_full": "Feragatnamenin tamamını aç",
    "status.title": "whyDPI — öğrenilen stratejiler",
    "status.intro": (
        "Çalışma anında öğrenilen SNI stratejileri. "
        "Hassas — yalnızca sizin trafiğinizin kullandığı adlar görünür."
    ),
    "status.cache_file": "Önbellek dosyası: {path}",
    "status.col.host": "SNI / sunucu",
    "status.col.strategy": "Strateji",
    "status.col.ok": "Başarı",
    "status.col.fail": "Hata",
    "status.col.last_ok": "Son başarı",
    "status.col.last_fail": "Son hata türü",
    "status.empty": "Henüz kayıt yok",
    "status.close": "Kapat",
    "status.footer": "whyDPI v{version}",
    "desktop.name": "whyDPI",
    "desktop.generic": "DPI aşım denetimi",
    "desktop.comment": "whyDPI hizmetini sistem tepsisinden başlatın, durdurun ve izleyin",
    "desktop.autostart_comment": "Uyarlanabilir DPI aşımı — sistem tepsisi",
    "cli.description": (
        "Eğitim amaçlı DPI aşımı — şeffaf TLS parçalama ve DoH. "
        "Paket günlüğü için WHYDPI_TRACE=1 (Windows tanı)."
    ),
    "cli.epilog": (
        "Tepsi: WHYDPI_SKIP_DISCLAIMER=1 yalnızca CI/otomasyon içindir; "
        "kişisel makinede onay penceresini atlamak için kullanmayın."
    ),
    "cli.help.config": "config.toml yolu (varsayılan: ~/.config/whydpi/config.toml)",
    "cli.help.start": "whyDPI’yi başlat",
    "cli.help.stop": "whyDPI’yi durdur ve DNS’i geri yükle",
    "cli.help.dns_configure": "/etc/resolv.conf dosyasını stub çözümleyiciye sabitle",
    "cli.help.dns_restore": "özgün /etc/resolv.conf dosyasını geri yükle",
    "cli.help.probe": "sunucuları yokla, kazanan stratejiyi bildir",
    "cli.help.cache": "strateji önbelleğine bak veya temizle",
    "cli.help.configure_dns": "başlangıçta /etc/resolv.conf dosyasını sabitle",
    "cli.help.probe_targets": "isteğe bağlı ön yoklama için sunucular",
    "cli.help.dns_mode": "bu çalışma için dns.mode değerini geçersiz kıl",
    "cli.help.targets": "yoklanacak hedef host[:port]",
    "cli.help.verbose": "ayrıntılı günlük",
    "cli.help.cache_list": "önbellekteki sunucuları listele",
    "cli.help.cache_clear": "önbelleğin tamamını temizle",
    "cli.help.cache_forget": "belirli sunucuları unut",
    "cli.help.cache_forget_hosts": "unutulacak sunucular",
    "cli.error.root": "whyDPI root olarak çalışmalıdır (sudo)",
    "cli.cache.empty": "(önbellek boş)",
    "cli.cache.cleared": "önbellek temizlendi",
    "consent.error.no_tk": (
        "whyDPI ilk çalışma penceresi için Tk ister. "
        "Tk bağlarını kurun (örnek: sudo pacman -S tk) "
        "veya WHYDPI_SKIP_DISCLAIMER=1 yalnızca otomasyon için kullanın."
    ),
    "update.error.no_asset": "Bu sürümde Windows kurulum dosyası yok.",
    "update.error.no_scoop": "PATH üzerinde scoop bulunamadı.",
    "update.error.no_sha": "SHA256SUMS.txt içinde {name} yok.",
    "update.error.hash": "Kurulum dosyası özeti uyuşmuyor (beklenen {expected}, alınan {actual}).",
}

DE: dict[str, str] = {
    "tray.menu.start": "whyDPI starten",
    "tray.menu.stop": "whyDPI beenden",
    "tray.menu.status": "Status anzeigen…",
    "tray.menu.cache": "Cache-Ordner öffnen",
    "tray.menu.autostart": "whyDPI bei der Anmeldung starten",
    "tray.menu.about": "Über whyDPI v{version}",
    "tray.menu.disclaimer": "Zulässige Nutzung und Haftungsausschluss",
    "tray.menu.quit": "Beenden",
    "tray.menu.update.check": "Nach Updates suchen",
    "tray.menu.update.install": "whyDPI v{version} installieren…",
    "tray.title.running": "whyDPI v{version} — Schutz aktiv",
    "tray.title.idle": "whyDPI v{version} — bereit",
    "tray.notify.protecting.title": "whyDPI schützt diese Verbindung",
    "tray.notify.protecting.body": "Adaptive TLS-Fragmentierung ist aktiv.",
    "tray.notify.ready.title": "whyDPI ist bereit",
    "tray.notify.ready.body": "Schutz ist aus. Klicken Sie auf das Symbol im Infobereich, um zu starten.",
    "tray.notify.stopped.title": "whyDPI-Schutz ist aus",
    "tray.notify.stopped.body": "DNS wurde auf Ihre ursprünglichen Einstellungen zurückgesetzt.",
    "tray.notify.autostart.on.title": "whyDPI startet bei der Anmeldung",
    "tray.notify.autostart.on.body": "Infobereich und Schutz werden bei der nächsten Anmeldung fortgesetzt.",
    "tray.notify.autostart.off.title": "whyDPI startet nicht bei der Anmeldung",
    "tray.notify.autostart.off.body": "Die Änderung gilt ab der nächsten Anmeldung.",
    "tray.notify.autostart.fail.title": "Anmeldeoption konnte nicht geändert werden",
    "tray.notify.autostart.fail.body": "Details stehen im whyDPI-Protokoll.",
    "tray.notify.update.available.title": "whyDPI {version} ist verfügbar",
    "tray.notify.update.available.body": "Öffnen Sie das Menü im Infobereich und wählen Sie Installieren.",
    "tray.notify.update.uptodate.title": "whyDPI ist aktuell",
    "tray.notify.update.uptodate.body": "Sie verwenden v{version}.",
    "tray.notify.update.checkfail.title": "Updateprüfung fehlgeschlagen",
    "tray.notify.update.installing.title": "whyDPI wird aktualisiert…",
    "tray.notify.update.installing.body": "{version} wird installiert",
    "tray.notify.update.fail.title": "Update fehlgeschlagen",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI läuft bereits im Infobereich (neben der Uhr). "
        "Klicken Sie mit der rechten Maustaste auf das Schildsymbol, um das Menü zu öffnen."
    ),
    "tray.dialog.update.title": "whyDPI-Update",
    "tray.dialog.update.body": (
        "whyDPI {version} ist verfügbar.\n\n"
        "Jetzt von GitHub Releases herunterladen und installieren?"
    ),
    "tray.error.missing_deps": (
        "Das whyDPI-Infobereichssymbol benötigt optionale Pakete:\n"
        "  pip install 'whydpi[tray]'\n"
        "oder unter Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nImportfehler: {error}"
    ),
    "tray.error.not_admin": (
        "Unter Windows muss whyDPI als Administrator ausgeführt werden, damit:\n"
        "  • WinDivert den Kernel-Treiber laden kann,\n"
        "  • DNS-Umleitung ein WinDivert-Handle öffnen kann,\n"
        "  • der Resolver-Cache geleert werden kann.\n"
        "\n"
        "Klicken Sie mit der rechten Maustaste auf die whyDPI-Verknüpfung und wählen Sie "
        "Als Administrator ausführen.\n"
        "Das Setup fordert bei einem normalen Doppelklick bereits die Erhöhung an."
    ),
    "tray.error.service_missing": (
        "Der whyDPI-Dienst ({service}) ist nicht installiert.\n"
        "Installieren Sie zuerst das whydpi-Paket und öffnen Sie den Infobereich erneut."
    ),
    "consent.title": "whyDPI — zulässige Nutzung",
    "consent.heading": "Bitte vor dem Fortfahren lesen",
    "consent.summary": (
        "whyDPI ist Software für Bildung und Forschung.\n"
        "\n"
        "Sie wählen jedes Ziel, das berührt wird. Für die Nutzung sind Sie "
        "rechtlich verantwortlich. Verwenden Sie das Programm nicht, um "
        "Jugendschutz, vereinbarte Richtlinien, Gerichtsbeschlüsse zu umgehen "
        "oder auf rechtswidrige Inhalte zuzugreifen.\n"
        "\n"
        "Mit der Annahme bestätigen Sie DISCLAIMER.md vollständig. "
        "Wenn Sie nicht einverstanden sind, wählen Sie Beenden."
    ),
    "consent.full_label": "Vollständiger Text:",
    "consent.checkbox": "Ich habe gelesen und stimme zu",
    "consent.continue": "Weiter",
    "consent.quit": "Beenden",
    "consent.accept": "Ich habe gelesen und stimme zu",
    "consent.open_full": "Vollständigen Haftungsausschluss öffnen",
    "status.title": "whyDPI — gelernte Strategien",
    "status.intro": (
        "Zur Laufzeit gelernte SNI-Strategien. "
        "Vertraulich — hier erscheinen nur Hostnamen, die Ihr Datenverkehr verwendet hat."
    ),
    "status.cache_file": "Cache-Datei: {path}",
    "status.col.host": "SNI / Host",
    "status.col.strategy": "Strategie",
    "status.col.ok": "Erfolge",
    "status.col.fail": "Fehler",
    "status.col.last_ok": "Letzter Erfolg",
    "status.col.last_fail": "Letzte Fehlerart",
    "status.empty": "Noch keine Einträge",
    "status.close": "Schließen",
    "status.footer": "whyDPI v{version}",
    "desktop.name": "whyDPI",
    "desktop.generic": "Steuerung zur DPI-Umgehung",
    "desktop.comment": "whyDPI aus dem Infobereich starten, beenden und überwachen",
    "desktop.autostart_comment": "Adaptive DPI-Umgehung — Infobereich",
    "cli.description": (
        "DPI-Umgehung zu Bildungszwecken — transparente TLS-Fragmentierung und DoH. "
        "WHYDPI_TRACE=1 protokolliert abgefangene Pakete (Windows-Diagnose)."
    ),
    "cli.epilog": (
        "Infobereich: WHYDPI_SKIP_DISCLAIMER=1 nur in CI/Automatisierung, "
        "um den Erststart-Dialog zu überspringen (nicht auf persönlichen Rechnern)."
    ),
    "cli.help.config": "Pfad zu config.toml (Standard: ~/.config/whydpi/config.toml)",
    "cli.help.start": "whyDPI starten",
    "cli.help.stop": "whyDPI beenden und DNS wiederherstellen",
    "cli.help.dns_configure": "/etc/resolv.conf auf den Stub-Resolver festlegen",
    "cli.help.dns_restore": "ursprüngliche /etc/resolv.conf wiederherstellen",
    "cli.help.probe": "Hosts prüfen und die gewinnende Strategie ausgeben",
    "cli.help.cache": "Strategie-Cache anzeigen oder bereinigen",
    "cli.help.configure_dns": "/etc/resolv.conf beim Start festlegen",
    "cli.help.probe_targets": "Hosts für eine optionale Vorabprüfung",
    "cli.help.dns_mode": "dns.mode für diesen Lauf überschreiben",
    "cli.help.targets": "zu prüfende Ziele host[:port]",
    "cli.help.verbose": "ausführliches Protokoll",
    "cli.help.cache_list": "zwischengespeicherte Hosts auflisten",
    "cli.help.cache_clear": "gesamten Cache leeren",
    "cli.help.cache_forget": "bestimmte Hosts vergessen",
    "cli.help.cache_forget_hosts": "zu vergessende Hosts",
    "cli.error.root": "whyDPI muss als root laufen (sudo)",
    "cli.cache.empty": "(Cache leer)",
    "cli.cache.cleared": "Cache geleert",
    "consent.error.no_tk": (
        "whyDPI benötigt Tk für den Erststart-Dialog. "
        "Installieren Sie die Tk-Bindungen (zum Beispiel: sudo pacman -S tk) "
        "oder setzen Sie WHYDPI_SKIP_DISCLAIMER=1 nur für Automatisierung."
    ),
    "update.error.no_asset": "Diese Version enthält kein Windows-Installationsprogramm.",
    "update.error.no_scoop": "scoop wurde im PATH nicht gefunden.",
    "update.error.no_sha": "SHA256SUMS.txt enthält keinen Eintrag für {name}.",
    "update.error.hash": "Hash des Installers stimmt nicht (erwartet {expected}, erhalten {actual}).",
}

ES: dict[str, str] = {
    "tray.menu.start": "Iniciar whyDPI",
    "tray.menu.stop": "Detener whyDPI",
    "tray.menu.status": "Mostrar estado…",
    "tray.menu.cache": "Abrir carpeta de caché",
    "tray.menu.autostart": "Iniciar whyDPI al iniciar sesión",
    "tray.menu.about": "Acerca de whyDPI v{version}",
    "tray.menu.disclaimer": "Uso aceptable y descargo de responsabilidad",
    "tray.menu.quit": "Salir",
    "tray.menu.update.check": "Buscar actualizaciones",
    "tray.menu.update.install": "Instalar whyDPI v{version}…",
    "tray.title.running": "whyDPI v{version} — protegiendo",
    "tray.title.idle": "whyDPI v{version} — listo",
    "tray.notify.protecting.title": "whyDPI está protegiendo esta conexión",
    "tray.notify.protecting.body": "La fragmentación TLS adaptativa está activa.",
    "tray.notify.ready.title": "whyDPI está listo",
    "tray.notify.ready.body": "La protección está desactivada. Haga clic en el icono de la bandeja para iniciar.",
    "tray.notify.stopped.title": "La protección de whyDPI está desactivada",
    "tray.notify.stopped.body": "DNS se ha restaurado a su configuración original.",
    "tray.notify.autostart.on.title": "whyDPI se iniciará al iniciar sesión",
    "tray.notify.autostart.on.body": "La bandeja y la protección se reanudan en el próximo inicio de sesión.",
    "tray.notify.autostart.off.title": "whyDPI no se iniciará al iniciar sesión",
    "tray.notify.autostart.off.body": "El cambio se aplica la próxima vez que inicie sesión.",
    "tray.notify.autostart.fail.title": "No se pudo cambiar el inicio de sesión",
    "tray.notify.autostart.fail.body": "Consulte el registro de whyDPI para más detalles.",
    "tray.notify.update.available.title": "whyDPI {version} está disponible",
    "tray.notify.update.available.body": "Abra el menú de la bandeja y elija Instalar para actualizar.",
    "tray.notify.update.uptodate.title": "whyDPI está actualizado",
    "tray.notify.update.uptodate.body": "Está ejecutando v{version}.",
    "tray.notify.update.checkfail.title": "No se pudo buscar actualizaciones",
    "tray.notify.update.installing.title": "Actualizando whyDPI…",
    "tray.notify.update.installing.body": "Instalando {version}",
    "tray.notify.update.fail.title": "Error al actualizar",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI ya se está ejecutando en la bandeja (junto al reloj). "
        "Haga clic derecho en el icono del escudo para abrir el menú."
    ),
    "tray.dialog.update.title": "Actualización de whyDPI",
    "tray.dialog.update.body": (
        "whyDPI {version} está disponible.\n\n"
        "¿Descargarlo desde GitHub Releases e instalarlo ahora?"
    ),
    "tray.error.missing_deps": (
        "La bandeja de whyDPI necesita extras opcionales:\n"
        "  pip install 'whydpi[tray]'\n"
        "o en Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nerror de importación: {error}"
    ),
    "tray.error.not_admin": (
        "En Windows, whyDPI debe ejecutarse como administrador para:\n"
        "  • cargar el controlador de kernel de WinDivert,\n"
        "  • abrir un identificador WinDivert para la redirección DNS,\n"
        "  • vaciar la caché del resolvedor.\n"
        "\n"
        "Haga clic derecho en el acceso directo de whyDPI y elija Ejecutar como administrador.\n"
        "El instalador ya solicita elevación con un doble clic normal."
    ),
    "tray.error.service_missing": (
        "El servicio whyDPI ({service}) no está instalado.\n"
        "Instale primero el paquete whydpi y vuelva a abrir la bandeja."
    ),
    "consent.title": "whyDPI — uso aceptable",
    "consent.heading": "Lea esto antes de continuar",
    "consent.summary": (
        "whyDPI es software educativo y de investigación.\n"
        "\n"
        "Usted elige cada destino al que accede. Es legalmente responsable "
        "de su uso. No lo utilice para eludir controles parentales, políticas "
        "que haya aceptado, órdenes judiciales ni para acceder a contenido ilícito.\n"
        "\n"
        "Al aceptar, reconoce DISCLAIMER.md en su totalidad. Si no está "
        "de acuerdo, elija Salir."
    ),
    "consent.full_label": "Texto completo:",
    "consent.checkbox": "He leído y acepto",
    "consent.continue": "Continuar",
    "consent.quit": "Salir",
    "consent.accept": "He leído y acepto",
    "consent.open_full": "Abrir el descargo completo",
    "status.title": "whyDPI — estrategias aprendidas",
    "status.intro": (
        "Estrategias por SNI aprendidas en tiempo de ejecución. "
        "Información sensible: solo aparecen los nombres que usó su tráfico."
    ),
    "status.cache_file": "Archivo de caché: {path}",
    "status.col.host": "SNI / host",
    "status.col.strategy": "Estrategia",
    "status.col.ok": "Aciertos",
    "status.col.fail": "Fallos",
    "status.col.last_ok": "Último acierto",
    "status.col.last_fail": "Último tipo de fallo",
    "status.empty": "Aún no hay entradas",
    "status.close": "Cerrar",
    "status.footer": "whyDPI v{version}",
    "desktop.name": "whyDPI",
    "desktop.generic": "Control de omisión de DPI",
    "desktop.comment": "Inicie, detenga y supervise whyDPI desde la bandeja del sistema",
    "desktop.autostart_comment": "Omisión DPI adaptativa — bandeja del sistema",
    "cli.description": (
        "Omisión DPI educativa — fragmentación TLS transparente y DoH. "
        "WHYDPI_TRACE=1 registra paquetes interceptados (diagnóstico en Windows)."
    ),
    "cli.epilog": (
        "Bandeja: WHYDPI_SKIP_DISCLAIMER=1 solo en CI/automatización para omitir "
        "el diálogo del primer inicio (no en equipos personales)."
    ),
    "cli.help.config": "ruta a config.toml (predeterminada: ~/.config/whydpi/config.toml)",
    "cli.help.start": "iniciar whyDPI",
    "cli.help.stop": "detener whyDPI y restaurar DNS",
    "cli.help.dns_configure": "fijar /etc/resolv.conf al resolvedor stub",
    "cli.help.dns_restore": "restaurar el /etc/resolv.conf original",
    "cli.help.probe": "sondear hosts e informar la estrategia ganadora",
    "cli.help.cache": "inspeccionar o limpiar la caché de estrategias",
    "cli.help.configure_dns": "fijar /etc/resolv.conf al iniciar",
    "cli.help.probe_targets": "hosts para un sondeo previo opcional",
    "cli.help.dns_mode": "reemplazar dns.mode en esta ejecución",
    "cli.help.targets": "destinos host[:port] a sondear",
    "cli.help.verbose": "registro detallado",
    "cli.help.cache_list": "listar hosts en caché",
    "cli.help.cache_clear": "vaciar toda la caché",
    "cli.help.cache_forget": "olvidar hosts concretos",
    "cli.help.cache_forget_hosts": "hosts que olvidar",
    "cli.error.root": "whyDPI debe ejecutarse como root (sudo)",
    "cli.cache.empty": "(caché vacía)",
    "cli.cache.cleared": "caché vaciada",
    "consent.error.no_tk": (
        "whyDPI necesita Tk para el diálogo del primer inicio. "
        "Instale los enlaces de Tk (por ejemplo: sudo pacman -S tk) "
        "o use WHYDPI_SKIP_DISCLAIMER=1 solo para automatización."
    ),
    "update.error.no_asset": "Esta versión no incluye instalador de Windows.",
    "update.error.no_scoop": "no se encontró scoop en PATH.",
    "update.error.no_sha": "SHA256SUMS.txt no tiene una entrada para {name}.",
    "update.error.hash": "El hash del instalador no coincide (se esperaba {expected}, se obtuvo {actual}).",
}

FR: dict[str, str] = {
    "tray.menu.start": "Démarrer whyDPI",
    "tray.menu.stop": "Arrêter whyDPI",
    "tray.menu.status": "Afficher l’état…",
    "tray.menu.cache": "Ouvrir le dossier du cache",
    "tray.menu.autostart": "Lancer whyDPI à la connexion",
    "tray.menu.about": "À propos de whyDPI v{version}",
    "tray.menu.disclaimer": "Usage acceptable et clause de non-responsabilité",
    "tray.menu.quit": "Quitter",
    "tray.menu.update.check": "Rechercher des mises à jour",
    "tray.menu.update.install": "Installer whyDPI v{version}…",
    "tray.title.running": "whyDPI v{version} — protection active",
    "tray.title.idle": "whyDPI v{version} — prêt",
    "tray.notify.protecting.title": "whyDPI protège cette connexion",
    "tray.notify.protecting.body": "La fragmentation TLS adaptative est activée.",
    "tray.notify.ready.title": "whyDPI est prêt",
    "tray.notify.ready.body": "La protection est désactivée. Cliquez sur l’icône de la zone de notification pour démarrer.",
    "tray.notify.stopped.title": "Protection whyDPI désactivée",
    "tray.notify.stopped.body": "Le DNS a été rétabli selon vos paramètres d’origine.",
    "tray.notify.autostart.on.title": "whyDPI démarrera à l’ouverture de session",
    "tray.notify.autostart.on.body": "La zone de notification et la protection reprendront à la prochaine connexion.",
    "tray.notify.autostart.off.title": "whyDPI ne démarrera pas à l’ouverture de session",
    "tray.notify.autostart.off.body": "La modification prendra effet à la prochaine connexion.",
    "tray.notify.autostart.fail.title": "Impossible de modifier le démarrage de session",
    "tray.notify.autostart.fail.body": "Consultez le journal whyDPI pour plus de détails.",
    "tray.notify.update.available.title": "whyDPI {version} est disponible",
    "tray.notify.update.available.body": "Ouvrez le menu de la zone de notification et choisissez Installer.",
    "tray.notify.update.uptodate.title": "whyDPI est à jour",
    "tray.notify.update.uptodate.body": "Vous utilisez la v{version}.",
    "tray.notify.update.checkfail.title": "Échec de la recherche de mises à jour",
    "tray.notify.update.installing.title": "Mise à jour de whyDPI…",
    "tray.notify.update.installing.body": "Installation de {version}",
    "tray.notify.update.fail.title": "Échec de la mise à jour",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI est déjà en cours d’exécution dans la zone de notification (près de l’horloge). "
        "Cliquez avec le bouton droit sur l’icône du bouclier pour ouvrir le menu."
    ),
    "tray.dialog.update.title": "Mise à jour whyDPI",
    "tray.dialog.update.body": (
        "whyDPI {version} est disponible.\n\n"
        "Le télécharger depuis GitHub Releases et l’installer maintenant ?"
    ),
    "tray.error.missing_deps": (
        "L’icône whyDPI nécessite des extras optionnels :\n"
        "  pip install 'whydpi[tray]'\n"
        "ou sous Arch Linux :\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nerreur d’import : {error}"
    ),
    "tray.error.not_admin": (
        "Sous Windows, whyDPI doit s’exécuter en tant qu’administrateur afin de :\n"
        "  • charger le pilote noyau WinDivert,\n"
        "  • ouvrir un handle WinDivert pour la redirection DNS,\n"
        "  • vider le cache du résolveur.\n"
        "\n"
        "Cliquez avec le bouton droit sur le raccourci whyDPI et choisissez Exécuter en tant qu’administrateur.\n"
        "Le programme d’installation demande déjà l’élévation lors d’un double-clic normal."
    ),
    "tray.error.service_missing": (
        "Le service whyDPI ({service}) n’est pas installé.\n"
        "Installez d’abord le paquet whydpi, puis rouvrez la zone de notification."
    ),
    "consent.title": "whyDPI — usage acceptable",
    "consent.heading": "À lire avant de continuer",
    "consent.summary": (
        "whyDPI est un logiciel éducatif et de recherche.\n"
        "\n"
        "Vous choisissez chaque destination qu’il touche. Vous êtes juridiquement "
        "responsable de son usage. Ne l’utilisez pas pour contourner un contrôle "
        "parental, des politiques que vous avez acceptées, une décision de justice, "
        "ni pour accéder à un contenu illicite.\n"
        "\n"
        "En acceptant, vous reconnaissez DISCLAIMER.md dans son intégralité. "
        "Si vous n’êtes pas d’accord, choisissez Quitter."
    ),
    "consent.full_label": "Texte intégral :",
    "consent.checkbox": "J’ai lu et j’accepte",
    "consent.continue": "Continuer",
    "consent.quit": "Quitter",
    "consent.accept": "J’ai lu et j’accepte",
    "consent.open_full": "Ouvrir la clause complète",
    "status.title": "whyDPI — stratégies apprises",
    "status.intro": (
        "Stratégies SNI apprises à l’exécution. "
        "Données sensibles — seuls les noms d’hôte utilisés par votre trafic apparaissent ici."
    ),
    "status.cache_file": "Fichier de cache : {path}",
    "status.col.host": "SNI / hôte",
    "status.col.strategy": "Stratégie",
    "status.col.ok": "Réussites",
    "status.col.fail": "Échecs",
    "status.col.last_ok": "Dernière réussite",
    "status.col.last_fail": "Dernier type d’échec",
    "status.empty": "Aucune entrée pour le moment",
    "status.close": "Fermer",
    "status.footer": "whyDPI v{version}",
    "desktop.name": "whyDPI",
    "desktop.generic": "Contrôle de contournement DPI",
    "desktop.comment": "Démarrer, arrêter et surveiller whyDPI depuis la zone de notification",
    "desktop.autostart_comment": "Contournement DPI adaptatif — zone de notification",
    "cli.description": (
        "Contournement DPI éducatif — fragmentation TLS transparente et DoH. "
        "WHYDPI_TRACE=1 consigne les paquets interceptés (diagnostic Windows)."
    ),
    "cli.epilog": (
        "Zone de notification : WHYDPI_SKIP_DISCLAIMER=1 uniquement en CI/automatisation "
        "pour ignorer le dialogue du premier lancement (pas sur une machine personnelle)."
    ),
    "cli.help.config": "chemin vers config.toml (défaut : ~/.config/whydpi/config.toml)",
    "cli.help.start": "démarrer whyDPI",
    "cli.help.stop": "arrêter whyDPI et restaurer le DNS",
    "cli.help.dns_configure": "épingler /etc/resolv.conf sur le résolveur stub",
    "cli.help.dns_restore": "restaurer le /etc/resolv.conf d’origine",
    "cli.help.probe": "sonder les hôtes et indiquer la stratégie gagnante",
    "cli.help.cache": "consulter ou nettoyer le cache de stratégies",
    "cli.help.configure_dns": "épingler /etc/resolv.conf au démarrage",
    "cli.help.probe_targets": "hôtes pour un sondage préalable facultatif",
    "cli.help.dns_mode": "remplacer dns.mode pour cette exécution",
    "cli.help.targets": "cibles host[:port] à sonder",
    "cli.help.verbose": "journalisation détaillée",
    "cli.help.cache_list": "lister les hôtes en cache",
    "cli.help.cache_clear": "vider tout le cache",
    "cli.help.cache_forget": "oublier des hôtes précis",
    "cli.help.cache_forget_hosts": "hôtes à oublier",
    "cli.error.root": "whyDPI doit s’exécuter en root (sudo)",
    "cli.cache.empty": "(cache vide)",
    "cli.cache.cleared": "cache vidé",
    "consent.error.no_tk": (
        "whyDPI a besoin de Tk pour le dialogue du premier lancement. "
        "Installez les liaisons Tk (par exemple : sudo pacman -S tk) "
        "ou définissez WHYDPI_SKIP_DISCLAIMER=1 uniquement pour l’automatisation."
    ),
    "update.error.no_asset": "Cette version n’inclut pas d’installateur Windows.",
    "update.error.no_scoop": "scoop est introuvable dans le PATH.",
    "update.error.no_sha": "SHA256SUMS.txt ne contient pas d’entrée pour {name}.",
    "update.error.hash": "Le hachage de l’installateur ne correspond pas (attendu {expected}, obtenu {actual}).",
}

RU: dict[str, str] = {
    "tray.menu.start": "Запустить whyDPI",
    "tray.menu.stop": "Остановить whyDPI",
    "tray.menu.status": "Показать состояние…",
    "tray.menu.cache": "Открыть папку кэша",
    "tray.menu.autostart": "Запускать whyDPI при входе",
    "tray.menu.about": "О whyDPI v{version}",
    "tray.menu.disclaimer": "Допустимое использование и отказ от ответственности",
    "tray.menu.quit": "Выход",
    "tray.menu.update.check": "Проверить обновления",
    "tray.menu.update.install": "Установить whyDPI v{version}…",
    "tray.title.running": "whyDPI v{version} — защита включена",
    "tray.title.idle": "whyDPI v{version} — готов",
    "tray.notify.protecting.title": "whyDPI защищает это соединение",
    "tray.notify.protecting.body": "Адаптивная фрагментация TLS включена.",
    "tray.notify.ready.title": "whyDPI готов",
    "tray.notify.ready.body": "Защита выключена. Нажмите значок в области уведомлений, чтобы запустить.",
    "tray.notify.stopped.title": "Защита whyDPI выключена",
    "tray.notify.stopped.body": "DNS возвращён к исходным настройкам.",
    "tray.notify.autostart.on.title": "whyDPI будет запускаться при входе",
    "tray.notify.autostart.on.body": "Область уведомлений и защита возобновятся при следующем входе.",
    "tray.notify.autostart.off.title": "whyDPI не будет запускаться при входе",
    "tray.notify.autostart.off.body": "Изменение вступит в силу при следующем входе.",
    "tray.notify.autostart.fail.title": "Не удалось изменить автозапуск",
    "tray.notify.autostart.fail.body": "Подробности см. в журнале whyDPI.",
    "tray.notify.update.available.title": "Доступен whyDPI {version}",
    "tray.notify.update.available.body": "Откройте меню в области уведомлений и выберите Установить.",
    "tray.notify.update.uptodate.title": "whyDPI обновлён",
    "tray.notify.update.uptodate.body": "Запущена версия v{version}.",
    "tray.notify.update.checkfail.title": "Не удалось проверить обновления",
    "tray.notify.update.installing.title": "Обновление whyDPI…",
    "tray.notify.update.installing.body": "Установка {version}",
    "tray.notify.update.fail.title": "Ошибка обновления",
    "tray.notify.already.title": "whyDPI",
    "tray.notify.already.body": (
        "whyDPI уже работает в области уведомлений (рядом с часами). "
        "Щёлкните правой кнопкой по значку щита, чтобы открыть меню."
    ),
    "tray.dialog.update.title": "Обновление whyDPI",
    "tray.dialog.update.body": (
        "Доступен whyDPI {version}.\n\n"
        "Скачать из GitHub Releases и установить сейчас?"
    ),
    "tray.error.missing_deps": (
        "Значку whyDPI нужны дополнительные пакеты:\n"
        "  pip install 'whydpi[tray]'\n"
        "или в Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        "\nошибка импорта: {error}"
    ),
    "tray.error.not_admin": (
        "В Windows whyDPI должен запускаться от имени администратора, чтобы:\n"
        "  • загрузить драйвер ядра WinDivert,\n"
        "  • открыть дескриптор WinDivert для перенаправления DNS,\n"
        "  • очистить кэш распознавателя.\n"
        "\n"
        "Щёлкните правой кнопкой ярлык whyDPI и выберите Запуск от имени администратора.\n"
        "Установщик уже запрашивает повышение прав при обычном двойном щелчке."
    ),
    "tray.error.service_missing": (
        "Служба whyDPI ({service}) не установлена.\n"
        "Сначала установите пакет whydpi, затем снова откройте область уведомлений."
    ),
    "consent.title": "whyDPI — допустимое использование",
    "consent.heading": "Прочтите перед продолжением",
    "consent.summary": (
        "whyDPI — программное обеспечение для обучения и исследований.\n"
        "\n"
        "Каждое назначение выбираете вы. Вы несёте юридическую ответственность "
        "за использование. Не применяйте программу для обхода родительского "
        "контроля, принятых вами политик, судебных решений или доступа "
        "к противоправному содержимому.\n"
        "\n"
        "Принимая условия, вы подтверждаете DISCLAIMER.md полностью. "
        "Если вы не согласны, выберите Выход."
    ),
    "consent.full_label": "Полный текст:",
    "consent.checkbox": "Я прочитал(а) и принимаю",
    "consent.continue": "Продолжить",
    "consent.quit": "Выход",
    "consent.accept": "Я прочитал(а) и принимаю",
    "consent.open_full": "Открыть полный отказ от ответственности",
    "status.title": "whyDPI — изученные стратегии",
    "status.intro": (
        "SNI-стратегии, изученные во время работы. "
        "Конфиденциально — здесь только имена, которые использовал ваш трафик."
    ),
    "status.cache_file": "Файл кэша: {path}",
    "status.col.host": "SNI / узел",
    "status.col.strategy": "Стратегия",
    "status.col.ok": "Успехи",
    "status.col.fail": "Сбои",
    "status.col.last_ok": "Последний успех",
    "status.col.last_fail": "Последний тип сбоя",
    "status.empty": "Пока нет записей",
    "status.close": "Закрыть",
    "status.footer": "whyDPI v{version}",
    "desktop.name": "whyDPI",
    "desktop.generic": "Управление обходом DPI",
    "desktop.comment": "Запуск, остановка и контроль whyDPI из области уведомлений",
    "desktop.autostart_comment": "Адаптивный обход DPI — область уведомлений",
    "cli.description": (
        "Образовательный обход DPI — прозрачная фрагментация TLS и DoH. "
        "WHYDPI_TRACE=1 записывает перехваченные пакеты (диагностика Windows)."
    ),
    "cli.epilog": (
        "Область уведомлений: WHYDPI_SKIP_DISCLAIMER=1 только для CI/автоматизации, "
        "чтобы пропустить диалог первого запуска (не на личных машинах)."
    ),
    "cli.help.config": "путь к config.toml (по умолчанию: ~/.config/whydpi/config.toml)",
    "cli.help.start": "запустить whyDPI",
    "cli.help.stop": "остановить whyDPI и восстановить DNS",
    "cli.help.dns_configure": "зафиксировать /etc/resolv.conf на stub-распознаватель",
    "cli.help.dns_restore": "восстановить исходный /etc/resolv.conf",
    "cli.help.probe": "проверить узлы и сообщить победившую стратегию",
    "cli.help.cache": "просмотреть или очистить кэш стратегий",
    "cli.help.configure_dns": "зафиксировать /etc/resolv.conf при запуске",
    "cli.help.probe_targets": "узлы для необязательной предварительной проверки",
    "cli.help.dns_mode": "переопределить dns.mode для этого запуска",
    "cli.help.targets": "цели host[:port] для проверки",
    "cli.help.verbose": "подробный журнал",
    "cli.help.cache_list": "показать узлы в кэше",
    "cli.help.cache_clear": "очистить весь кэш",
    "cli.help.cache_forget": "забыть указанные узлы",
    "cli.help.cache_forget_hosts": "узлы, которые нужно забыть",
    "cli.error.root": "whyDPI должен запускаться от root (sudo)",
    "cli.cache.empty": "(кэш пуст)",
    "cli.cache.cleared": "кэш очищен",
    "consent.error.no_tk": (
        "whyDPI нужен Tk для диалога первого запуска. "
        "Установите привязки Tk (например: sudo pacman -S tk) "
        "или задайте WHYDPI_SKIP_DISCLAIMER=1 только для автоматизации."
    ),
    "update.error.no_asset": "В этом выпуске нет установщика Windows.",
    "update.error.no_scoop": "scoop не найден в PATH.",
    "update.error.no_sha": "В SHA256SUMS.txt нет записи для {name}.",
    "update.error.hash": "Хэш установщика не совпадает (ожидалось {expected}, получено {actual}).",
}

CATALOGS: dict[str, dict[str, str]] = {
    "en": EN,
    "tr": TR,
    "de": DE,
    "es": ES,
    "fr": FR,
    "ru": RU,
}
