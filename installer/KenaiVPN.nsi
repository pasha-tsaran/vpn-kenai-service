Unicode true
RequestExecutionLevel admin
ManifestDPIAware true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef STAGE_ROOT
  !error "STAGE_ROOT is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif
!ifndef APP_VERSION
  !define APP_VERSION "0.1.0"
!endif
!ifndef FILE_VERSION
  !define FILE_VERSION "0.1.0.0"
!endif

!define APP_NAME "Kenai VPN"
!define COMPANY_NAME "Kenai VPN"
!define SERVICE_NAME "KenaiVpnService"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\KenaiVPN"

Name "${APP_NAME}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\Kenai VPN"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "Kenai VPN"
SetCompressor /SOLID lzma
SetCompressorDictSize 64
ShowInstDetails show
ShowUninstDetails show
AutoCloseWindow false
AllowRootDirInstall false

VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=1049 "ProductName" "${APP_NAME}"
VIAddVersionKey /LANG=1049 "CompanyName" "${COMPANY_NAME}"
VIAddVersionKey /LANG=1049 "FileDescription" "Kenai VPN Installer"
VIAddVersionKey /LANG=1049 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1049 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1049 "LegalCopyright" "Copyright (C) 2026 Kenai VPN"

!define MUI_ABORTWARNING
!define MUI_ICON "${STAGE_ROOT}\app_icon.ico"
!define MUI_UNICON "${STAGE_ROOT}\app_icon.ico"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

Var ServiceResult
Var ServiceOutput
Var ServiceWasInstalled
Var ServiceWasCreated
Var ServiceAction
Var ServiceBinaryPath

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "Kenai VPN поддерживает только 64-битную Windows."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "Kenai VPN требует Windows 10 или новее."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function RequireServiceSuccess
  Pop $ServiceResult
  Pop $ServiceOutput
  ${If} $ServiceResult != 0
    DetailPrint "$ServiceAction failed with code $ServiceResult"
    DetailPrint "$ServiceOutput"
    MessageBox MB_ICONSTOP "Не удалось выполнить этап '$ServiceAction' при настройке системной службы Kenai VPN. Код: $ServiceResult"
    Abort
  ${EndIf}
FunctionEnd

; Register the service through the Windows Service API. Passing a quoted image
; path through sc.exe/nsExec is ambiguous when $INSTDIR contains spaces and can
; make sc.exe return ERROR_INVALID_COMMAND_LINE (1639).
Function ConfigureServiceRegistration
  StrCpy $ServiceBinaryPath '"$INSTDIR\service\KenaiVpnService.exe"'
  System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 0x0003) p.r0'
  ${If} $0 == 0
    System::Call 'kernel32::GetLastError() i.r2'
    MessageBox MB_ICONSTOP "Не удалось открыть диспетчер системных служб. Код: $2"
    Abort
  ${EndIf}

  ${If} $ServiceWasInstalled == "1"
    System::Call 'advapi32::OpenServiceW(p r0, w "${SERVICE_NAME}", i 0x0002) p.r1'
    ${If} $1 == 0
      System::Call 'kernel32::GetLastError() i.r2'
      System::Call 'advapi32::CloseServiceHandle(p r0)'
      MessageBox MB_ICONSTOP "Не удалось открыть системную службу Kenai VPN. Код: $2"
      Abort
    ${EndIf}
    System::Call 'advapi32::ChangeServiceConfigW(p r1, i 0xffffffff, i 2, i 1, w "$ServiceBinaryPath", p 0, p 0, p 0, p 0, p 0, w "Kenai VPN Service") i.r2'
  ${Else}
    System::Call 'advapi32::CreateServiceW(p r0, w "${SERVICE_NAME}", w "Kenai VPN Service", i 0x000f01ff, i 0x10, i 2, i 1, w "$ServiceBinaryPath", p 0, p 0, p 0, p 0, p 0) p.r1'
    ${If} $1 != 0
      StrCpy $ServiceWasCreated "1"
      StrCpy $2 "1"
    ${Else}
      StrCpy $2 "0"
    ${EndIf}
  ${EndIf}

  ${If} $2 == 0
    System::Call 'kernel32::GetLastError() i.r3'
    ${If} $1 != 0
      System::Call 'advapi32::CloseServiceHandle(p r1)'
    ${EndIf}
    System::Call 'advapi32::CloseServiceHandle(p r0)'
    MessageBox MB_ICONSTOP "Не удалось зарегистрировать системную службу Kenai VPN. Код: $3"
    Abort
  ${EndIf}
  System::Call 'advapi32::CloseServiceHandle(p r1)'
  System::Call 'advapi32::CloseServiceHandle(p r0)'
FunctionEnd

Function .onInstFailed
  ${If} $ServiceWasCreated == "1"
    nsExec::ExecToStack '"$SYSDIR\sc.exe" stop "${SERVICE_NAME}"'
    Pop $ServiceResult
    Pop $ServiceOutput
    nsExec::ExecToStack '"$SYSDIR\sc.exe" delete "${SERVICE_NAME}"'
    Pop $ServiceResult
    Pop $ServiceOutput
  ${EndIf}
FunctionEnd

Section "Kenai VPN" SEC_MAIN
  SectionIn RO
  SetShellVarContext all
  SetRegView 64

  StrCpy $ServiceWasInstalled "0"
  StrCpy $ServiceWasCreated "0"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query "${SERVICE_NAME}"'
  Pop $ServiceResult
  Pop $ServiceOutput
  ${If} $ServiceResult == 0
    StrCpy $ServiceWasInstalled "1"
    nsExec::ExecToStack '"$SYSDIR\net.exe" stop "${SERVICE_NAME}" /y'
    Pop $ServiceResult
    Pop $ServiceOutput
    Sleep 500
  ${EndIf}

  ; Replace the complete application payload only after the service stopped.
  RMDir /r "$INSTDIR\app"
  RMDir /r "$INSTDIR\service"
  RMDir /r "$INSTDIR\licenses"
  SetOutPath "$INSTDIR\app"
  File /r "${STAGE_ROOT}\app\*"
  SetOutPath "$INSTDIR\service"
  File /r "${STAGE_ROOT}\service\*"
  SetOutPath "$INSTDIR\licenses"
  File /r "${STAGE_ROOT}\licenses\*"

  ; SYSTEM and Administrators can update; interactive users receive read/execute only.
  StrCpy $ServiceAction "защита файлов приложения"
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"'
  Call RequireServiceSuccess

  Call ConfigureServiceRegistration

  StrCpy $ServiceAction "описание службы"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" description "${SERVICE_NAME}" "Privileged tunnel service for Kenai VPN"'
  Call RequireServiceSuccess
  StrCpy $ServiceAction "изоляция службы"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" sidtype "${SERVICE_NAME}" unrestricted'
  Call RequireServiceSuccess
  StrCpy $ServiceAction "политика восстановления службы"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" failure "${SERVICE_NAME}" reset= 86400 actions= restart/5000/restart/15000'
  Call RequireServiceSuccess
  StrCpy $ServiceAction "запуск службы"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" start "${SERVICE_NAME}"'
  Call RequireServiceSuccess

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${COMPANY_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\app\KenaiVPN.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  ; Repair is performed by rerunning this idempotent setup package.
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\Kenai VPN"
  CreateShortcut "$SMPROGRAMS\Kenai VPN\Kenai VPN.lnk" "$INSTDIR\app\KenaiVPN.exe"
  CreateShortcut "$SMPROGRAMS\Kenai VPN\Удалить Kenai VPN.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64

  nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /IM "KenaiVPN.exe" /T /F'
  Pop $ServiceResult
  Pop $ServiceOutput
  nsExec::ExecToStack '"$SYSDIR\net.exe" stop "${SERVICE_NAME}" /y'
  Pop $ServiceResult
  Pop $ServiceOutput
  Sleep 3000

  ; Fixed recovery cleanup for tunnel services that could survive a prior crash.
  nsExec::ExecToStack '"$SYSDIR\sc.exe" stop "WireGuardTunnel$$Kenai"'
  Pop $ServiceResult
  Pop $ServiceOutput
  nsExec::ExecToStack '"$SYSDIR\sc.exe" delete "WireGuardTunnel$$Kenai"'
  Pop $ServiceResult
  Pop $ServiceOutput
  nsExec::ExecToStack '"$SYSDIR\sc.exe" stop "AmneziaWGTunnel$$KenaiAwg"'
  Pop $ServiceResult
  Pop $ServiceOutput
  nsExec::ExecToStack '"$SYSDIR\sc.exe" delete "AmneziaWGTunnel$$KenaiAwg"'
  Pop $ServiceResult
  Pop $ServiceOutput
  nsExec::ExecToStack '"$SYSDIR\sc.exe" delete "${SERVICE_NAME}"'
  Pop $ServiceResult
  Pop $ServiceOutput
  Sleep 1500

  SetShellVarContext all
  RMDir /r "$APPDATA\KenaiVPN"
  SetShellVarContext current
  RMDir /r "$LOCALAPPDATA\Kenai VPN"
  RMDir /r "$APPDATA\Kenai VPN"
  System::Call 'advapi32::CredDeleteW(w "key_kenai_vpn_desktop_VGhpcyBpcyB0aGUgcHJlZml4IGZv_", i 1, i 0) i.r0'

  SetShellVarContext all
  Delete "$SMPROGRAMS\Kenai VPN\Kenai VPN.lnk"
  Delete "$SMPROGRAMS\Kenai VPN\Удалить Kenai VPN.lnk"
  RMDir "$SMPROGRAMS\Kenai VPN"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  RMDir /r "$INSTDIR"
SectionEnd
