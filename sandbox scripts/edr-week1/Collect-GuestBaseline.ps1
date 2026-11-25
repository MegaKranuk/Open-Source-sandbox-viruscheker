param(
    [string[]]$Roots = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\Microsoft.NET"),
    [string[]]$Extensions = @('.exe', '.dll'),
    [string]$OutDir = 'C:\Telemetry\baseline',
    [switch]$WithSignature
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv    = Join-Path $OutDir "baseline-v5-$stamp.csv"
$header = Join-Path $OutDir "baseline-v5-$stamp.header.txt"

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hdr = @(
    "script=Collect-GuestBaseline v5",
    "Recurse=true",
    "utc=$((Get-Date).ToUniversalTime().ToString('o'))",
    "ProductName=$($cv.ProductName)",
    "DisplayVersion=$($cv.DisplayVersion)",
    "CurrentBuild=$($cv.CurrentBuild)",
    "UBR=$($cv.UBR)",
    "OSVersion=$([Environment]::OSVersion.VersionString)",
    "Roots=$($Roots -join ';')",
    "Extensions=$($Extensions -join ';')",
    "WithSignature=$([bool]$WithSignature)"
)
Set-Content -LiteralPath $header -Value $hdr -Encoding ASCII

$files = @()
foreach ($r in $Roots) {
    if (Test-Path -LiteralPath $r) {
        $files += Get-ChildItem -LiteralPath $r -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $Extensions -contains $_.Extension.ToLower() }
    }
}
$files = @($files | Sort-Object FullName)

function Test-IsPE {
    param([string]$Path)
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $b = New-Object byte[] 2
            $n = $fs.Read($b, 0, 2)
            return ($n -eq 2 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Q { param($v) return '"' + ([string]$v).Replace('"', '""') + '"' }

$sw = New-Object System.IO.StreamWriter($csv, $false, [Text.Encoding]::ASCII)
$sw.WriteLine('Path,Size,Sha256,IsPE,SignatureStatus,Signer,FileVersion,ProductVersion')
$total = $files.Count
$n = 0; $pe = 0; $err = 0
foreach ($f in $files) {
    $n++
    if (($n % 200) -eq 0) { Write-Host ("progress {0}/{1}" -f $n, $total) }
    $hash = ''
    try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = 'HASH-ERROR'; $err++ }
    $isPe = Test-IsPE $f.FullName
    if ($isPe) { $pe++ }
    $sigStatus = 'skipped'; $signer = ''
    if ($WithSignature) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
            $sigStatus = [string]$sig.Status
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        } catch { $sigStatus = 'SIG-ERROR' }
    }
    $fv = ''; $pv = ''
    try { $fv = [string]$f.VersionInfo.FileVersion; $pv = [string]$f.VersionInfo.ProductVersion } catch {}
    $sw.WriteLine(((Q $f.FullName), (Q $f.Length), (Q $hash), (Q $isPe), (Q $sigStatus), (Q $signer), (Q $fv), (Q $pv)) -join ',')
}
$sw.Close()

Write-Host ("files={0} pe={1} hasherrors={2} signature={3}" -f $total, $pe, $err, [bool]$WithSignature)
Write-Host "csv:    $csv"
Write-Host "header: $header"
