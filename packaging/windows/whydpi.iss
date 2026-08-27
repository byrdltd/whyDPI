; whyDPI — Inno Setup 6 installer script
; SPDX-License-Identifier: MIT
;
; Produces a single whydpi-<version>-setup.exe that installs
; whydpi-tray.exe and whydpi.exe into %ProgramFiles%\whyDPI\ plus the
; usual Start-menu + optional Desktop / Autostart entries.
;
; The build system (GitHub Actions or a local PowerShell run) sets
; WHYDPI_VERSION in the environment before invoking ISCC; ISPP reads
; it to stamp {#MyAppVersion} everywhere it is needed.

#define MyAppName       "whyDPI"
#define MyAppPublisher  "whyDPI Contributors"
#define MyAppURL        "https://github.com/byrdltd/whyDPI"
#define MyAppVersion    GetEnv("WHYDPI_VERSION")
#if MyAppVersion == ""
  #define MyAppVersion "0.0.0"
#endif
#define MyExeTray       "whydpi-tray.exe"
#define MyExeCli        "whydpi.exe"

[Setup]
AppId={{A9A4E9B2-6A2F-4C73-8B14-7A50A6B6F1E2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=dist
OutputBaseFilename=whydpi-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
SetupIconFile=..\..\assets\favicon.ico
UninstallDisplayIcon={app}\{#MyExeTray}
LicenseFile=..\..\LICENSE
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.AutostartTask=Start whyDPI automatically when I sign in to Windows
english.AdditionalBehaviour=Additional behaviour
english.LaunchWhyDPI=Launch whyDPI
english.RegisterAutostart=Registering autostart task...
turkish.AutostartTask=Windows oturumu açılınca whyDPI’yi otomatik başlat
turkish.AdditionalBehaviour=Ek davranış
turkish.LaunchWhyDPI=whyDPI’yi başlat
turkish.RegisterAutostart=Oturum açılışı görevi kaydediliyor...
german.AutostartTask=whyDPI automatisch starten, wenn ich mich bei Windows anmelde
german.AdditionalBehaviour=Weiteres Verhalten
german.LaunchWhyDPI=whyDPI starten
german.RegisterAutostart=Autostart-Aufgabe wird registriert...
spanish.AutostartTask=Iniciar whyDPI automáticamente al iniciar sesión en Windows
spanish.AdditionalBehaviour=Comportamiento adicional
spanish.LaunchWhyDPI=Iniciar whyDPI
spanish.RegisterAutostart=Registrando la tarea de inicio...
french.AutostartTask=Démarrer whyDPI automatiquement à l’ouverture de session Windows
french.AdditionalBehaviour=Comportement supplémentaire
french.LaunchWhyDPI=Lancer whyDPI
french.RegisterAutostart=Enregistrement de la tâche de démarrage...
russian.AutostartTask=Запускать whyDPI автоматически при входе в Windows
russian.AdditionalBehaviour=Дополнительное поведение
russian.LaunchWhyDPI=Запустить whyDPI
russian.RegisterAutostart=Регистрация задачи автозапуска...

[Tasks]
Name: "desktopicon";  Description: "{cm:CreateDesktopIcon}";   GroupDescription: "{cm:AdditionalIcons}"
; "autostart" registers a per-user Task Scheduler entry named
; "whyDPI Tray" that launches the tray at every logon with the
; user's already-granted admin token, so the WinDivert driver
; loads silently without a per-login UAC prompt.  The task runs
; as the logged-in user (NOT as SYSTEM); a SYSTEM-scoped service
; would need its own WinDivert handle management and the user's
; network-profile context, which buys us nothing here.  The tray
; menu's "Launch on login" toggle writes / deletes the same task,
; so the two paths stay in sync.  Off by default — we'd rather the
; user opt in after confirming the app works on their network.
Name: "autostart";    Description: "{cm:AutostartTask}"; GroupDescription: "{cm:AdditionalBehaviour}"; Flags: unchecked

[Files]
; ``--onedir`` PyInstaller layouts: each exe sits next to its own
; ``_internal\`` runtime folder.  The tray dir becomes ``{app}``
; itself (so ``whydpi-tray.exe`` lives at ``{app}\whydpi-tray.exe``);
; the CLI dir lives under ``{app}\cli\`` to keep the two
; ``_internal\`` trees from colliding.
Source: "build\dist\whydpi-tray\*";       DestDir: "{app}";      Flags: ignoreversion recursesubdirs createallsubdirs restartreplace uninsrestartdelete
Source: "build\dist-cli\whydpi\*";        DestDir: "{app}\cli";  Flags: ignoreversion recursesubdirs createallsubdirs restartreplace uninsrestartdelete
Source: "..\..\LICENSE";                  DestDir: "{app}";      Flags: ignoreversion
Source: "..\..\README.md";                DestDir: "{app}";      Flags: ignoreversion
Source: "..\..\assets\favicon.ico";       DestDir: "{app}";      Flags: ignoreversion
Source: "..\..\assets\icon-256.png";      DestDir: "{app}";      Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";            Filename: "{app}\{#MyExeTray}";    IconFilename: "{app}\favicon.ico"
Name: "{group}\{#MyAppName} (CLI)";      Filename: "{app}\cli\{#MyExeCli}"; IconFilename: "{app}\favicon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}";  Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}";    Filename: "{app}\{#MyExeTray}";    IconFilename: "{app}\favicon.ico"; Tasks: desktopicon

[Run]
; Create an elevated scheduled task that launches the tray at login.
; Using schtasks avoids the HKLM\...\Run caveats (Run keys cannot
; request elevation, resulting in a blocked UAC popup on every login).
Filename: "schtasks.exe"; Parameters: "/Create /F /SC ONLOGON /RL HIGHEST /TN ""whyDPI Tray"" /TR ""\""{app}\{#MyExeTray}\"""""; Flags: runhidden; Tasks: autostart; StatusMsg: "{cm:RegisterAutostart}"

; Offer to launch the tray immediately on "Finish".  We must use
; shellexec here: the tray exe ships with a requireAdministrator UAC
; manifest and plain CreateProcess refuses to start such binaries
; with ERROR_ELEVATION_REQUIRED (740) even from an elevated installer.
; ShellExecuteEx respects the UAC manifest and reuses the installer's
; elevated token, so no extra prompt is shown.
Filename: "{app}\{#MyExeTray}"; Description: "{cm:LaunchWhyDPI}"; Flags: shellexec nowait postinstall skipifsilent

[UninstallRun]
; Remove the autostart task (ignore failure — user may have deleted it manually).
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""whyDPI Tray"""; Flags: runhidden; RunOnceId: "DeleteAutostartTask"

; Kill the tray first so WinDivert handles drop, then unload the driver.
; ``waituntilterminated`` is required: without it the uninstaller starts
; deleting ``WinDivert64.sys`` while the kernel still has the driver
; image mapped (DeleteFile code 5 / access denied).  ``whydpi stop`` is
; a no-op on Windows (no persisted DNS/netfilter); the process exit is
; the cleanup.  Stop every WinDivert service name we have seen in the wild.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#MyExeTray} /T"; Flags: runhidden waituntilterminated; RunOnceId: "KillTrayOnUninstall"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#MyExeCli} /T"; Flags: runhidden waituntilterminated; RunOnceId: "KillCliOnUninstall"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; Flags: runhidden waituntilterminated; RunOnceId: "StopWinDivertOnUninstall"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert14"; Flags: runhidden waituntilterminated; RunOnceId: "StopWinDivert14OnUninstall"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert1.4"; Flags: runhidden waituntilterminated; RunOnceId: "StopWinDivert14AltOnUninstall"

[Code]
{ WinDivert keeps WinDivert64.sys mapped after the tray exits.  Inno's
  Restart Manager closes user-mode processes but cannot unload a
  kernel driver, so a reinstall/upgrade then fails with DeleteFile
  code 5 (access denied) on that .sys.  Stop the processes, then the
  driver service, before any file copy or delete. }

procedure KillWhyDpiProcesses;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyExeTray} /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyExeCli} /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure UnloadWinDivert;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert14', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert1.4', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopWhyDpiAndDriver;
begin
  KillWhyDpiProcesses;
  UnloadWinDivert;
  Sleep(2000);
  UnloadWinDivert;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopWhyDpiAndDriver;
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopWhyDpiAndDriver;
  Result := True;
end;
