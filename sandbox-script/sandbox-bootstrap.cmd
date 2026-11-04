@echo off
setlocal
set "LOG=C:\Telemetry\runner-bootstrap.log"
>>"%LOG%" echo [BOOTSTRAP] Started at %DATE% %TIME%.

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
exit /b %RUNNER_EXIT_CODE%
