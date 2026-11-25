@echo off
setlocal
set "LOG=C:\Telemetry\runner-bootstrap.log"
>>"%LOG%" echo [BOOTSTRAP] Started at %DATE% %TIME%.

rem
if exist "C:\Sample\edr-week1\guest-edr-week1.ps1" (
    >>"%LOG%" echo [BOOTSTRAP] Installing Week 1 EDR telemetry ^(Sysmon + AppLocker audit^).
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\Sample\edr-week1\guest-edr-week1.ps1" -Install >>"%LOG%" 2>&1
) else (
    >>"%LOG%" echo [BOOTSTRAP] Week 1 EDR agent not found; continuing without it.
)

rem
if exist "C:\Sample\edr-week1\guest-killswitch.ps1" (
    >>"%LOG%" echo [BOOTSTRAP] Starting kill-switch in background.
    start "RBI-KillSwitch" /min powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\Sample\edr-week1\guest-killswitch.ps1"
) else (
    >>"%LOG%" echo [BOOTSTRAP] Kill-switch script not found; continuing without it.
)

rem 
if not exist "C:\Sample\sandbox-runner.ps1" (
    >>"%LOG%" echo [BOOTSTRAP] ERROR: C:\Sample\sandbox-runner.ps1 is missing.
    exit /b 2
)

set "RUNNER_ARGS="
if /I "%~1"=="-AllowOnlineRuntimeInstall" set "RUNNER_ARGS=-AllowOnlineRuntimeInstall"

>>"%LOG%" echo [BOOTSTRAP] Runner file found. Starting Windows PowerShell.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\Sample\sandbox-runner.ps1" %RUNNER_ARGS% >>"%LOG%" 2>&1
set "RUNNER_EXIT_CODE=%ERRORLEVEL%"
>>"%LOG%" echo [BOOTSTRAP] Runner exited with code %RUNNER_EXIT_CODE% at %DATE% %TIME%.

rem
if exist "C:\Sample\edr-week1\guest-edr-week1.ps1" (
    >>"%LOG%" echo [BOOTSTRAP] Exporting Week 1 EDR telemetry.
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\Sample\edr-week1\guest-edr-week1.ps1" -Export >>"%LOG%" 2>&1
    >>"%LOG%" echo [BOOTSTRAP] Week 1 EDR export step finished at %DATE% %TIME%.
)
exit /b %RUNNER_EXIT_CODE%
