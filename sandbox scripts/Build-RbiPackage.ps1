param(
    [Parameter(Mandatory)][string]$ScriptsDir,
    [string]$OutDir = "$env:USERPROFILE\Desktop\RBI-package",
    [string]$BaselineCsv = 'C:\Quarantine_Zone\Baseline\baseline.csv'
)

$ErrorActionPreference = 'Stop'
$edr = Join-Path $ScriptsDir 'edr-week1'

$required = @(
    @{ Src = (Join-Path $ScriptsDir 'start-rbi.ps1');             Dst = 'start-rbi.ps1' }
    @{ Src = (Join-Path $ScriptsDir 'sandbox-runner.ps1');        Dst = 'sandbox-runner.ps1' }
    @{ Src = (Join-Path $ScriptsDir 'sandbox-bootstrap.cmd');     Dst = 'sandbox-bootstrap.cmd' }
    @{ Src = (Join-Path $ScriptsDir 'sandbox.wsb');               Dst = 'sandbox.wsb' }
    @{ Src = (Join-Path $edr 'EdrWeek1Report.ps1');               Dst = 'edr-week1\EdrWeek1Report.ps1' }
    @{ Src = (Join-Path $edr 'RbiHashCache.ps1');                 Dst = 'edr-week1\RbiHashCache.ps1' }
    @{ Src = (Join-Path $edr 'RbiStaticAnalysis.ps1');            Dst = 'edr-week1\RbiStaticAnalysis.ps1' }
    @{ Src = (Join-Path $edr 'guest-edr-week1.ps1');              Dst = 'edr-week1\guest-edr-week1.ps1' }
    @{ Src = (Join-Path $edr 'guest-killswitch.ps1');             Dst = 'edr-week1\guest-killswitch.ps1' }
    @{ Src = (Join-Path $edr 'sysmonconfig-week1.xml');           Dst = 'edr-week1\sysmonconfig-week1.xml' }
    @{ Src = (Join-Path $edr 'applocker-audit-week1.xml');        Dst = 'edr-week1\applocker-audit-week1.xml' }
    @{ Src = $BaselineCsv;                                        Dst = '__baseline__' }
)

$optional = @(
    @{ Src = (Join-Path $ScriptsDir 'run-sandbox.bat');           Dst = 'run-sandbox.bat' }
    @{ Src = (Join-Path $ScriptsDir 'Compare-RbiCopies.ps1');     Dst = 'Compare-RbiCopies.ps1' }
    @{ Src = (Join-Path $edr 'Install-EdrWeek1Tools.ps1');        Dst = 'edr-week1\Install-EdrWeek1Tools.ps1' }
    @{ Src = (Join-Path $edr 'Collect-GuestBaseline.ps1');        Dst = 'edr-week1\Collect-GuestBaseline.ps1' }
)

$missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_.Src) } | ForEach-Object { $_.Src })
if ($missing.Count -gt 0) {
    Write-Host 'FAIL: required files are missing, package not built:' -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" }
    return
}
$skippedOpt = @($optional | Where-Object { -not (Test-Path -LiteralPath $_.Src) } | ForEach-Object { $_.Src })
if ($skippedOpt.Count -gt 0) {
    Write-Host 'Optional files not found (skipped):' -ForegroundColor Yellow
    $skippedOpt | ForEach-Object { Write-Host "  $_" }
}

if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir 'edr-week1') | Out-Null

foreach ($item in ($required + $optional)) {
    if (-not (Test-Path -LiteralPath $item.Src)) { continue }
    if ($item.Dst -eq '__baseline__') { continue }
    Copy-Item -LiteralPath $item.Src -Destination (Join-Path $OutDir $item.Dst)
}

$stage = Join-Path $env:TEMP 'rbi-baseline-stage'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -LiteralPath $BaselineCsv -Destination (Join-Path $stage 'baseline.csv')
Compress-Archive -LiteralPath (Join-Path $stage 'baseline.csv') -DestinationPath (Join-Path $OutDir 'baseline.zip') -Force
Remove-Item $stage -Recurse -Force

$rows = Get-ChildItem -LiteralPath $OutDir -Recurse -File | Where-Object { $_.Name -ne 'manifest.csv' } | ForEach-Object {
    [pscustomobject]@{
        Path   = $_.FullName.Substring($OutDir.Length).TrimStart('\')
        Size   = $_.Length
        Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
}
$rows | Export-Csv -LiteralPath (Join-Path $OutDir 'manifest.csv') -NoTypeInformation -Encoding ASCII

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Host ("OK: {0} files in {1}" -f $rows.Count, $OutDir) -ForegroundColor Green
Write-Host ("Baseline was built on: Windows 10 Enterprise 24H2, build 26100, UBR 9974. This machine: {0} {1} UBR {2}" -f $cv.ProductName, $cv.CurrentBuild, $cv.UBR)
Write-Host 'Copy the whole folder (with manifest.csv) to the target machine.'
