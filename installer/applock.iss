#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef AppArch
  #define AppArch "x64"
#endif
#ifndef BinDir
  #define BinDir "..\target\release"
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
AppId={{8D6E4A21-5F3B-4E1C-9D82-7A1B3C4D5E6F}
AppName=AppLock
AppVersion={#AppVersion}
AppPublisher=AppLock
DefaultDirName={autopf}\AppLock
DefaultGroupName=AppLock
LicenseFile=license.rtf
PrivilegesRequired=admin
#if AppArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
OutputDir={#OutDir}
OutputBaseFilename=applock-{#AppVersion}-{#AppArch}-setup
UninstallDisplayName=AppLock

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#BinDir}\applock-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\applock-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\applock-lockui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\applock-manager.exe"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\AppLock"

[Icons]
Name: "{autoprograms}\AppLock\AppLock Manager"; Filename: "{app}\applock-manager.exe"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AppLockAgent"; ValueData: """{app}\applock-agent.exe"""; Flags: uninsdeletevalue

[Run]
; Restrict %ProgramData%\AppLock to SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) only.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\AppLock"" /inheritance:r /grant:r ""*S-1-5-18:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"""; Flags: runhidden waituntilterminated
; Replace any existing service cleanly, configure SCM recovery and non-admin stop protection, and start.
Filename: "{sys}\sc.exe"; Parameters: "stop AppLockService"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete AppLockService"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "create AppLockService binPath= ""\""{app}\applock-service.exe\"""" start= auto obj= LocalSystem DisplayName= ""AppLock Service"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure AppLockService reset= 86400 actions= restart/2000/restart/5000/restart/10000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "sdset AppLockService D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start AppLockService"; Flags: runhidden waituntilterminated
Filename: "{app}\applock-agent.exe"; Description: "Start AppLock protection now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM applock-agent.exe"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "stop AppLockService"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete AppLockService"; Flags: runhidden waituntilterminated
