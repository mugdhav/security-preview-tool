; Inno Setup script for the portable-exe install route.
;
;   1. build the one-file exe:   python scripts/build_desktop.py portable
;   2. compile this script:      iscc resources/installer/security-preview.iss
;                                (Inno Setup 6: https://jrsoftware.org/isdl.php)
;
; Output: dist/security-preview-setup-<version>.exe  -- an installer with
; Start-Menu + optional desktop shortcut, an optional folder right-click verb,
; and a clean uninstaller. The signed Briefcase .msi is the primary Windows
; artifact; this is the no-MSI alternative.

#define AppName "security-preview"
#define AppVersion "0.1.0"
#define AppPublisher "security-preview contributors"
#define AppExe "security-preview.exe"

[Setup]
AppId={{CE694A2C-655F-4B61-911A-34D7698D75CB}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=..\..\dist
OutputBaseFilename=security-preview-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
; Per-user install by default -> no UAC prompt, HKCU registry.
PrivilegesRequiredOverridesAllowed=dialog

[Files]
Source: "..\..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\DESKTOP.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "contextmenu"; Description: "Add ""Scan with {#AppName}"" to the folder right-click menu"; GroupDescription: "Integration:"

[Registry]
; Folder right-click (on a folder) and background right-click (inside a folder).
Root: HKA; Subkey: "Software\Classes\Directory\shell\SecurityPreview"; \
  ValueType: string; ValueName: ""; ValueData: "Scan with {#AppName}"; \
  Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SecurityPreview"; \
  ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; \
  Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SecurityPreview\command"; \
  ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" --scan ""%V"""; \
  Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\SecurityPreview"; \
  ValueType: string; ValueName: ""; ValueData: "Scan with {#AppName}"; \
  Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\SecurityPreview"; \
  ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; \
  Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\SecurityPreview\command"; \
  ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" --scan ""%V"""; \
  Flags: uninsdeletekey; Tasks: contextmenu

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
