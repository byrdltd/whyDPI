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
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";  Description: "{cm:CreateDesktopIcon}";   GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart";    Description: "Start whyDPI with Windows (runs as SYSTEM via Task Scheduler)"; GroupDescription: "Additional behaviour"; Flags: unchecked

[Files]
Source: "build\dist\{#MyExeTray}"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\dist\{#MyExeCli}";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE";           DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md";         DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\assets\favicon.ico";DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\assets\logo-256.png";DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";            Filename: "{app}\{#MyExeTray}"; IconFilename: "{app}\favicon.ico"
Name: "{group}\{#MyAppName} (CLI)";      Filename: "{app}\{#MyExeCli}";  IconFilename: "{app}\favicon.ico"
Name: "{group}\Uninstall {#MyAppName}";  Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}";    Filename: "{app}\{#MyExeTray}"; IconFilename: "{app}\favicon.ico"; Tasks: desktopicon

[Run]
; Create an elevated scheduled task that launches the tray at login.
; Using schtasks avoids the HKLM\...\Run caveats (Run keys cannot
; request elevation, resulting in a blocked UAC popup on every login).
Filename: "schtasks.exe"; Parameters: "/Create /F /SC ONLOGON /RL HIGHEST /TN ""whyDPI Tray"" /TR ""\""{app}\{#MyExeTray}\"""""; Flags: runhidden; Tasks: autostart; StatusMsg: "Registering autostart task..."

; Offer to launch the tray immediately on "Finish".
Filename: "{app}\{#MyExeTray}"; Description: "Launch whyDPI"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the autostart task (ignore failure — user may have deleted it manually).
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""whyDPI Tray"""; Flags: runhidden

; Restore DNS in case the user uninstalls while the tray is running.
Filename: "{app}\{#MyExeCli}"; Parameters: "stop"; Flags: runhidden
