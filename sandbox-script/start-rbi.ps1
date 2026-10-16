$QuarantineFolder = "C:\Quarantine_Zone"
$WsbFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox.wsb"

if (-Not (Test-Path $WsbFile)) {
    Write-Host "ERROR: File sandbox.wsb not found!" -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit
}

while ($true) {
    Write-Host "Cleaning infected Quarantine Zone..." -ForegroundColor Magenta
    $cleared = $false
    
    for ($try = 0; $try -lt 10; $try++) {
        if (-Not (Test-Path $QuarantineFolder)) {
            $cleared = $true
            break
        }
        
        cmd.exe /c "icacls C:\Quarantine_Zone /reset /t /c /q" 2>$null
        cmd.exe /c "attrib -h -s -r /s /d C:\Quarantine_Zone\*.*" 2>$null
        
        Get-ChildItem -Path $QuarantineFolder -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path $QuarantineFolder -Force -Recurse -ErrorAction SilentlyContinue
        cmd.exe /c "rmdir /s /q C:\Quarantine_Zone" 2>$null
        
        if (-Not (Test-Path $QuarantineFolder) -or (Get-ChildItem -Path $QuarantineFolder -Force -ErrorAction SilentlyContinue).Count -eq 0) {
            $cleared = $true
            break
        }
        
        Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
    }

    if (-Not (Test-Path $QuarantineFolder)) {
        New-Item -ItemType Directory -Force -Path $QuarantineFolder | Out-Null
    }
    New-Item -ItemType Directory -Force -Path "$QuarantineFolder\Downloads" | Out-Null
    New-Item -ItemType Directory -Force -Path "$QuarantineFolder\Desktop" | Out-Null

    Write-Host "Starting Isolated Environment..." -ForegroundColor Cyan
    Start-Process -FilePath $WsbFile

    Write-Host "Waiting for Sandbox to initialize..." -ForegroundColor Yellow
    $isRunning = $false
    for ($i = 0; $i -lt 40; $i++) {
        $procs = Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" }
        if ($procs.Count -gt 0) {
            $isRunning = $true
            break
        }
        Start-Sleep -Seconds 1
    }

    if (-Not $isRunning) {
        Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" } | Stop-Process -Force
        Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
        continue
    }

    Write-Host "Sandbox active. Behavioral monitoring is running..." -ForegroundColor Green

    while ($true) {
        Start-Sleep -Seconds 1
        
        if (Test-Path $QuarantineFolder) {
            $files = @(Get-ChildItem -Path $QuarantineFolder -Recurse -File -ErrorAction SilentlyContinue)
            if ($files.Count -gt 0) {

                $sampleFiles = $files | Select-Object -First 100
                
                $ransomArtifacts = $sampleFiles | Where-Object { 
                    $_.Name -match "(read|decrypt|recover|restore|lock|crypto|ransom|help)" -or 
                    $_.Extension -match "\.(lock|encrypted|crypto|wnry|wncry|fun|pay|demons|locked|crypted)"
                }

                $recentTime = (Get-Date).AddSeconds(-3)
                $rapidChanges = $sampleFiles | Where-Object { $_.LastWriteTime -ge $recentTime -or $_.CreationTime -ge $recentTime }

                if ($ransomArtifacts.Count -gt 0) {
                    Write-Host "ATTACK DETECTED! Cryptor signature found." -ForegroundColor Red
                    Write-Host "Waiting 35 seconds to demonstrate the cryptor attack..." -ForegroundColor Yellow
                    
                    Start-Sleep -Seconds 35
                    
                    Write-Host "Terminating Sandbox automatically..." -ForegroundColor Magenta
                    Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" } | Stop-Process -Force
                    Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
                    break 
                }
                elseif ($rapidChanges.Count -ge 15) {
                    Write-Host "ATTACK DETECTED! Bomber / Mass file creation found." -ForegroundColor Red
                    Write-Host "Waiting 70 seconds to demonstrate the bomber attack..." -ForegroundColor Yellow
                    
                    Start-Sleep -Seconds 70
                    
                    Write-Host "Terminating Sandbox automatically..." -ForegroundColor Magenta
                    Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" } | Stop-Process -Force
                    Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
                    break 
                }
            }
        }

        $activeProcs = Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" }
        if ($activeProcs.Count -eq 0) {
            Start-Sleep -Seconds 2
            $verifyProcs = Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" }
            if ($verifyProcs.Count -eq 0) {
                Write-Host "Sandbox closed by user." -ForegroundColor Yellow
                Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
                break 
            }
        }
    }

    $timeout = 0
    while (Get-Process -Name "*Sandbox*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "vmmem" }) {
        Start-Sleep -Seconds 1
        $timeout++
        if ($timeout -gt 5) { 
            Get-Process -Name "vmwp" -ErrorAction SilentlyContinue | Stop-Process -Force
            break 
        }
    }
    
    Start-Sleep -Seconds 3
}