param([string]$Dest = 'C:\RBI_EdrTools')
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$tmp = Join-Path $env:TEMP ('rbi-edr-week1-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$zip = Join-Path $tmp 'Sysmon.zip'
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $tmp 'Sysmon') -Force
$exe = Get-ChildItem -LiteralPath (Join-Path $tmp 'Sysmon') -Filter 'Sysmon64.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) { Copy-Item -LiteralPath $exe.FullName -Destination $Dest -Force } else { Write-Warning 'Sysmon64.exe was not found inside Sysmon.zip.' }

Get-ChildItem -LiteralPath $Dest -Filter *.exe | ForEach-Object {
    $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName
    [pscustomobject]@{ File = $_.Name; SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; Signature = $sig.Status; Signer = $sig.SignerCertificate.Subject }
} | Format-Table -AutoSize
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Done. Check Sysmon's version against sysmonconfig-week1.xml's schemaversion with 'Sysmon64.exe -v' / '-s'."
