function Get-HashCacheRoot {
    $base = if ($QuarantineFolder) { $QuarantineFolder } else { 'C:\Quarantine_Zone' }
    return (Join-Path $base 'HashCache')
}

function Get-HashCachePath {
    param([Parameter(Mandatory)][string]$Sha256)
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Not a SHA-256 value: $Sha256" }
    $h = $Sha256.ToLower()
    $levels = $h.ToCharArray()[0..7] | ForEach-Object { [string]$_ }
    return (Join-Path (Join-Path (Get-HashCacheRoot) ($levels -join '\')) "$h.json")
}

function Get-CachedVerdict {
    param([Parameter(Mandatory)][string]$Sha256)
    try { $p = Get-HashCachePath $Sha256 } catch { return $null }
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return $null }
}

function Set-CachedVerdict {
    param(
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][ValidateSet('CLEAN', 'MALICIOUS')][string]$Verdict,
        [Parameter(Mandatory)][string]$Source
    )
    $h = $Sha256.ToLower()
    $p = Get-HashCachePath $h
    New-Item -ItemType Directory -Force -Path (Split-Path $p) | Out-Null
    $tmp = "$p.tmp"
    [ordered]@{ sha256 = $h; verdict = $Verdict; source = $Source; utc = (Get-Date).ToUniversalTime().ToString('o') } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $p -Force
}

function Add-BaselineMapping {
    param([Parameter(Mandatory)][System.Xml.XmlDocument]$Document)
    try {
        $bHost = 'C:\Quarantine_Zone\Baseline'
        New-Item -ItemType Directory -Force -Path $bHost | Out-Null
        $folders = $Document.SelectSingleNode('/Configuration/MappedFolders')
        if (-not $folders) { return }
        if ($Document.SelectSingleNode("/Configuration/MappedFolders/MappedFolder[SandboxFolder='C:\Baseline']")) { return }
        $mf = $Document.CreateElement('MappedFolder')
        foreach ($pair in @(@('HostFolder', $bHost), @('SandboxFolder', 'C:\Baseline'), @('ReadOnly', 'true'))) {
            $n = $Document.CreateElement($pair[0])
            $n.InnerText = $pair[1]
            [void]$mf.AppendChild($n)
        }
        [void]$folders.AppendChild($mf)
    } catch {
        Write-Host "[!] Baseline mapping was not added: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Add-HashCacheMapping {
    param([Parameter(Mandatory)][System.Xml.XmlDocument]$Document)
    Add-BaselineMapping -Document $Document
    try {
        $root = Get-HashCacheRoot
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        $folders = $Document.SelectSingleNode('/Configuration/MappedFolders')
        if (-not $folders) { return }
        if ($Document.SelectSingleNode("/Configuration/MappedFolders/MappedFolder[SandboxFolder='C:\HashCache']")) { return }
        $mf = $Document.CreateElement('MappedFolder')
        foreach ($pair in @(@('HostFolder', $root), @('SandboxFolder', 'C:\HashCache'), @('ReadOnly', 'true'))) {
            $n = $Document.CreateElement($pair[0])
            $n.InnerText = $pair[1]
            [void]$mf.AppendChild($n)
        }
        [void]$folders.AppendChild($mf)
    } catch {
        Write-Host "[!] Hash cache mapping was not added: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Write-HashCacheVerdict {
    param([string]$Sha256, [string]$RunStatus, [string]$ReportFile)
    try {
        if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            Add-Content -Path $ReportFile -Value "[HASHCACHE] No SHA-256 of the staged sample was available; nothing cached."
            return
        }
        $verdict = $null
        if ($RunStatus -eq 'VIRUS') { $verdict = 'MALICIOUS' }
        elseif ($RunStatus -eq 'NO DETECTION') { $verdict = 'CLEAN' }
        if (-not $verdict) {
            Add-Content -Path $ReportFile -Value "[HASHCACHE] Verdict $RunStatus is not cached (only VIRUS and NO DETECTION are)."
            return
        }
        $existing = Get-CachedVerdict $Sha256
        if ($existing -and [string]$existing.verdict -eq 'MALICIOUS' -and $verdict -eq 'CLEAN') {
            Add-Content -Path $ReportFile -Value "[HASHCACHE] Existing MALICIOUS entry kept; not downgraded to CLEAN: $($Sha256.ToLower())"
            return
        }
        Set-CachedVerdict -Sha256 $Sha256 -Verdict $verdict -Source 'start-rbi'
        Add-Content -Path $ReportFile -Value "[HASHCACHE] Saved $verdict for $($Sha256.ToLower())"
    } catch {
        Add-Content -Path $ReportFile -Value "[HASHCACHE] Could not save the verdict: $($_.Exception.Message)"
    }
}
