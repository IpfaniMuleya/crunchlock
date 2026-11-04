; Inno Setup script for the Crunchlock Windows installer.
; Built in CI by:  iscc /DAppVersion=1.2.3 /DDistDir=..\..\dist /DIconFile=..\..\build\icons\crunchlock.ico packaging\windows\crunchlock.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef DistDir
  #define DistDir "..\..\dist"
#endif
#ifndef IconFile
  #define IconFile "..\..\build\icons\crunchlock.ico"
#endif

[Setup]
AppId={{6A3C2E55-0C8B-4C38-9F2B-6D2B3C1F7A11}
AppName=Crunchlock
AppVersion={#AppVersion}
AppPublisher=Crunchlock
DefaultDirName={autopf}\Crunchlock
DefaultGroupName=Crunchlock
DisableProgramGroupPage=yes
; Installs for the current user without admin rights; admins may choose all users.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ChangesAssociations=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#DistDir}
OutputBaseFilename=Crunchlock-Setup-{#AppVersion}
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\CrunchlockGUI.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "contextmenu"; Description: "Add ""Lock with Crunchlock"" to the right-click menu"; GroupDescription: "Explorer integration:"
Name: "association"; Description: "Open .clk files with Crunchlock (double-click to unlock)"; GroupDescription: "Explorer integration:"

[Files]
Source: "{#DistDir}\CrunchlockGUI.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\crunchlock.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Crunchlock"; Filename: "{app}\CrunchlockGUI.exe"
Name: "{autodesktop}\Crunchlock"; Filename: "{app}\CrunchlockGUI.exe"; Tasks: desktopicon

[Registry]
; .clk files open in Crunchlock
Root: HKA; Subkey: "Software\Classes\.clk"; ValueType: string; ValueName: ""; ValueData: "Crunchlock.LockedFile"; Flags: uninsdeletevalue; Tasks: association
Root: HKA; Subkey: "Software\Classes\Crunchlock.LockedFile"; ValueType: string; ValueName: ""; ValueData: "Crunchlock locked file"; Flags: uninsdeletekey; Tasks: association
Root: HKA; Subkey: "Software\Classes\Crunchlock.LockedFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: """{app}\CrunchlockGUI.exe"",0"; Tasks: association
Root: HKA; Subkey: "Software\Classes\Crunchlock.LockedFile\shell\open"; ValueType: string; ValueName: ""; ValueData: "Unlock with Crunchlock"; Tasks: association
Root: HKA; Subkey: "Software\Classes\Crunchlock.LockedFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CrunchlockGUI.exe"" ""%1"""; Tasks: association
; Right-click "Lock with Crunchlock" on any file or folder
Root: HKA; Subkey: "Software\Classes\*\shell\Crunchlock"; ValueType: string; ValueName: ""; ValueData: "Lock with Crunchlock"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\Crunchlock"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\CrunchlockGUI.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\Crunchlock\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CrunchlockGUI.exe"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\Crunchlock"; ValueType: string; ValueName: ""; ValueData: "Lock with Crunchlock"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\Crunchlock"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\CrunchlockGUI.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\Crunchlock\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CrunchlockGUI.exe"" ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\CrunchlockGUI.exe"; Description: "Start Crunchlock now"; Flags: nowait postinstall skipifsilent
