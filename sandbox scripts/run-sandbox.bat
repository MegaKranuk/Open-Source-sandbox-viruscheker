@echo off
chcp 65001 >nul
title Automated Malware Analysis Pipeline

set "RBI_DOWNLOADS_PATH=%~1"
if not defined RBI_DOWNLOADS_PATH set "RBI_DOWNLOADS_PATH=%USERPROFILE%\Downloads"
set "RBI_ELEVATION_VBS=%temp%\rbi-elevate-%random%.vbs"

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo [!] Requesting administrative privileges...
    >"%RBI_ELEVATION_VBS%" echo Set UAC = CreateObject^("Shell.Application"^)
    >>"%RBI_ELEVATION_VBS%" echo UAC.ShellExecute "powershell.exe", "-NoExit -NoProfile -ExecutionPolicy Bypass -File ""%~dp0start-rbi.ps1"" -DownloadsPath ""%RBI_DOWNLOADS_PATH%""", "%~dp0", "runas", 1
    cscript //nologo "%RBI_ELEVATION_VBS%"
    del "%RBI_ELEVATION_VBS%" >nul 2>&1
    exit /B
)

echo [*] Starting EDR Harness (start-rbi.ps1)...
powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-rbi.ps1" -DownloadsPath "%RBI_DOWNLOADS_PATH%"

pause
