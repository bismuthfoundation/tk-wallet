[Setup]
AppName=Bismuth Wallet
AppVersion=0.9.4
DefaultDirName={pf}\Bismuth Wallet
DefaultGroupName=Bismuth Wallet
UninstallDisplayIcon={app}\wallet.exe
Compression=lzma2
SolidCompression=yes
OutputBaseFilename=Bismuth_wallet
SetupIconFile=graphics\icon.ico
DisableDirPage=no

WizardImageFile=graphics\left.bmp
WizardSmallImageFile=graphics\mini.bmp

[Files]
Source: "Dist\*" ; DestDir: "{app}"; Flags: recursesubdirs;

[Icons]
Name: "{group}\Wallet"; Filename: "{app}\wallet.exe"
Name: "{group}\Uninstall Bismuth Wallet"; Filename: "{uninstallexe}"

[Registry]
; keys for 32-bit systems
Root: HKCU32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\wallet.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64
Root: HKLM32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\wallet.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64

; keys for 64-bit systems
Root: HKCU64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\wallet.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\wallet.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64

[Run]
Filename: "{app}\wallet.exe"; Description: "Bismuth Wallet"; Flags: shellexec postinstall skipifsilent
