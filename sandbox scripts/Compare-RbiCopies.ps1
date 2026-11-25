param(
    [string[]]$Roots = @('C:\Tools', 'C:\Quarantine_Zone', "$env:USERPROFILE\Desktop"),
    [string]$Out = "$env:USERPROFILE\Desktop\RBI-inventory\copies.txt"
)

$Known = @{
    'cc375610041172440037630d79c88df6972df18ccda51d66c6eccd2931526ae5' = 'CURRENT  guest-edr-week1.ps1'
    '852610ee553226e85f40ca0c16b76ca4565884c9c902286987409095abe8e0d5' = 'CURRENT  sysmonconfig-week1.xml (schema 4.91)'
    '018c717a1566cf52b2bfb9579295c3bb13700d6031a1ee4f42443592153d7d60' = 'CURRENT  sandbox-bootstrap.cmd (install + killswitch)'
    '4d30d18b1fb21018ab5f2ad7c6e08791a95e2a0d6e64cac7e8449becbf1426da' = 'CURRENT? sandbox-runner.ps1 (99272, has fsutil patch)'
    '14a9ad56a4886834b4e3a10895b398f08a28741b5dc54cdd1333f0620e045acb' = 'CURRENT  applocker-audit-week1.xml'
    '1af2bc9aa873b1fdd24269a258f7c5cebc32fec91f25a39b3d90602103807dd6' = 'CURRENT  Install-EdrWeek1Tools.ps1'
    '18a3885523a98f1087dad1520f0e141eaf6eb39ce2bc36abf2aab384e4dc9934' = 'CURRENT  guest-killswitch.ps1 (scope: baseline + other-system)'
    '505c23b094dc6c70f7666ce7469cdebe77b58b4d94d07fdf18c948bf89f7fe4e' = 'CURRENT  RbiHashCache.ps1'
    'f99a23707cd42c275cd0c917df2f7783f2f055dc904a23c0470d914c2ae2debe' = 'CURRENT  EdrWeek1Report.ps1 (patched: copies killswitch)'
    '0b5705c58a34d77a6dec5ef19a9da9cedc47d1aa0d0331b7dd9c616b33f48a37' = 'BASE     EdrWeek1Report.ps1 (4461, not yet patched)'
    'a56ae7fd164c5b1d4f2cd2a11e761a34f77b0dcd1f2b1208bc8f895f8be567d2' = 'OLD      sysmonconfig-week1.xml (schema 4.90, wrong for Sysmon 15.22)'
    'ade20178995808e66f3abd19a3d8181dec685906efc893ccacb0adf0615b60ea' = 'OLD      sandbox-runner.ps1 (98757, no fsutil patch)'
    '1f9ef58c9e71c4a89e8f3c13254ad5ca5a28d40b8f03a673b6809e4473c4f2c4' = 'OLD      sandbox-bootstrap.cmd (1651, no killswitch)'
    '0b550cd49b2e66a4ac96f8be1ab51a63ff06c632701b9f88fd2e935897bd085a' = 'OLD      sandbox-bootstrap.cmd (1421, runner check BEFORE install)'
    '59f2847e88ae008f71926306d55f1f2239cb62e45d75fe9aa77f830447590ed7' = 'OLD      EdrWeek1Report.ps1 (4478, breaks staging from edr-week1 folder)'
}

$rx = '^(guest-edr-week1|guest-killswitch|sysmonconfig-week1|applocker-audit-week1|sandbox-bootstrap|sandbox-runner|sandbox\.wsb|EdrWeek1Report|RbiHashCache|Install-EdrWeek1Tools|start-rbi|manual-week1)'

$rows = foreach ($r in $Roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $rx -and $_.FullName -notmatch 'RBI_WritableVolume|\\HashCache\\' } |
        ForEach-Object {
            $h = ''
            try { $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch {}
            $label = 'UNKNOWN'
            if ($h -and $Known.ContainsKey($h)) { $label = $Known[$h] }
            [pscustomobject]@{
                Status   = $label
                Size     = $_.Length
                Modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                Path     = $_.FullName
            }
        }
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$text = ($rows | Sort-Object Path | Format-Table -AutoSize -Wrap | Out-String -Width 400)
$old = @($rows | Where-Object { $_.Status -like 'OLD*' })
$summary = "Files found: $(@($rows).Count). OLD copies: $($old.Count). UNKNOWN: $(@($rows | Where-Object { $_.Status -eq 'UNKNOWN' }).Count)."
Set-Content -LiteralPath $Out -Value ($text + "`r`n" + $summary) -Encoding UTF8
Write-Host $text
Write-Host $summary
Write-Host "Saved: $Out"
