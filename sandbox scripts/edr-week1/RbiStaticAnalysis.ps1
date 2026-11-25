$script:RbiApiGroups = [ordered]@{
    'process injection' = @('CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'NtUnmapViewOfSection', 'SetThreadContext', 'QueueUserAPC', 'NtWriteVirtualMemory', 'RtlCreateUserThread', 'NtCreateThreadEx')
    'network download'  = @('URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetReadFile', 'WinHttpOpen', 'WinHttpConnect', 'HttpSendRequestA', 'HttpSendRequestW')
    'sockets'           = @('WSAStartup', 'socket', 'connect', 'send', 'recv', 'getaddrinfo', 'gethostbyname')
    'persistence'       = @('RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW', 'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW')
    'anti-debug'        = @('IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA')
    'crypto'            = @('CryptEncrypt', 'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptGenKey', 'BCryptEncrypt', 'CryptDeriveKey')
    'process launch'    = @('CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW', 'WinExec')
    'token/privileges'  = @('OpenProcessToken', 'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'CredEnumerateA', 'CredEnumerateW')
    'dynamic loading'   = @('LoadLibraryA', 'LoadLibraryW', 'GetProcAddress')
    'keylogging'        = @('SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyboardState')
}

$script:RbiKeywords = @('powershell', 'cmd.exe /c', 'wscript.shell', 'vssadmin', 'bcdedit', 'schtasks', 'mimikatz',
    'DownloadString', 'FromBase64String', 'Invoke-Expression', 'CurrentVersion\Run', 'virtualbox', 'vmware', 'sandboxie', 'wireshark', 'procmon')

function Read-RbiBytes {
    param($Stream, [long]$Offset, [int]$Count)
    if ($Offset -lt 0 -or $Offset -ge $Stream.Length -or $Count -le 0) { return ,(New-Object byte[] 0) }
    $n = [int][Math]::Min([long]$Count, $Stream.Length - $Offset)
    $buf = New-Object byte[] $n
    [void]$Stream.Seek($Offset, [IO.SeekOrigin]::Begin)
    $read = 0
    while ($read -lt $n) {
        $r = $Stream.Read($buf, $read, $n - $read)
        if ($r -le 0) { break }
        $read += $r
    }
    if ($read -le 0) { return ,(New-Object byte[] 0) }
    if ($read -lt $n) { [Array]::Resize([ref]$buf, $read) }
    return ,$buf
}

function Read-RbiAscii {
    param($Stream, [long]$Offset, [int]$Max)
    if ($Offset -lt 0) { return '' }
    $b = Read-RbiBytes $Stream $Offset $Max
    $end = [Array]::IndexOf($b, [byte]0)
    if ($end -lt 0) { $end = $b.Length }
    if ($end -le 0) { return '' }
    $s = [Text.Encoding]::ASCII.GetString($b, 0, $end)
    if ($s -notmatch '^[A-Za-z0-9_@?$.\-]+$') { return '' }
    return $s
}

function Get-RbiEntropy {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return 0.0 }
    $c = New-Object 'int[]' 256
    foreach ($b in $Bytes) { $c[$b]++ }
    $e = 0.0
    $n = [double]$Bytes.Length
    foreach ($v in $c) {
        if ($v -gt 0) { $p = $v / $n; $e -= $p * [Math]::Log($p, 2) }
    }
    return [Math]::Round($e, 2)
}

function ConvertTo-RbiOffset {
    param([long]$Rva, $Sections)
    foreach ($s in $Sections) {
        $span = [Math]::Max([long]$s.VSize, [long]$s.RawSize)
        if ($Rva -ge [long]$s.VA -and $Rva -lt ([long]$s.VA + $span)) { return ([long]$s.RawPtr + ($Rva - [long]$s.VA)) }
    }
    return -1
}

function Get-RbiImports {
    param($Stream, $Sections, [bool]$Is64, [long]$ImpRva)
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $dlls = New-Object System.Collections.Generic.List[string]
    $descOff = ConvertTo-RbiOffset $ImpRva $Sections
    if ($ImpRva -le 0 -or $descOff -lt 0) { return @{ Dlls = $dlls; Names = $names } }
    $step = 4
    if ($Is64) { $step = 8 }
    for ($d = 0; $d -lt 200; $d++) {
        $b = Read-RbiBytes $Stream ($descOff + 20 * $d) 20
        if ($b.Length -lt 20) { break }
        $oft = [long][BitConverter]::ToUInt32($b, 0)
        $nameRva = [long][BitConverter]::ToUInt32($b, 12)
        $ft = [long][BitConverter]::ToUInt32($b, 16)
        if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
        $dll = Read-RbiAscii $Stream (ConvertTo-RbiOffset $nameRva $Sections) 64
        if ($dll) { $dlls.Add($dll) }
        $thunkRva = $ft
        if ($oft -ne 0) { $thunkRva = $oft }
        $tOff = ConvertTo-RbiOffset $thunkRva $Sections
        if ($tOff -lt 0) { continue }
        for ($t = 0; $t -lt 1500; $t++) {
            if ($names.Count -ge 4000) { break }
            $e = Read-RbiBytes $Stream ($tOff + $step * $t) $step
            if ($e.Length -lt $step) { break }
            $lo = [long][BitConverter]::ToUInt32($e, 0)
            $hi = 0
            if ($Is64) { $hi = [long][BitConverter]::ToUInt32($e, 4) }
            if ($lo -eq 0 -and $hi -eq 0) { break }
            if (($e[$step - 1] -band 0x80) -ne 0) { continue }
            $nOff = ConvertTo-RbiOffset $lo $Sections
            if ($nOff -lt 0) { continue }
            $fn = Read-RbiAscii $Stream ($nOff + 2) 80
            if ($fn) { [void]$names.Add($fn) }
        }
    }
    return @{ Dlls = $dlls; Names = $names }
}

function Add-RbiPeLines {
    param($Stream, [byte[]]$H, [int]$PeOff, $Lines, [string]$FilePath)
    $ind = 0
    $machine = [BitConverter]::ToUInt16($H, $PeOff + 4)
    $numSec = [int][BitConverter]::ToUInt16($H, $PeOff + 6)
    $ts = [BitConverter]::ToUInt32($H, $PeOff + 8)
    $optSize = [int][BitConverter]::ToUInt16($H, $PeOff + 20)
    $chars = [int][BitConverter]::ToUInt16($H, $PeOff + 22)
    $opt = $PeOff + 24
    if (($opt + 240) -gt $H.Length) { $Lines.Add('[STATIC] PE header is truncated or unusual; deeper checks skipped.'); return }
    $magic = [int][BitConverter]::ToUInt16($H, $opt)
    $is64 = ($magic -eq 0x20B)
    $dirBase = $opt + 96
    if ($is64) { $dirBase = $opt + 112 }
    $subsys = [int][BitConverter]::ToUInt16($H, $opt + 68)

    $mach = 'unknown (0x{0:X})' -f $machine
    if ($machine -eq 0x14C) { $mach = 'x86' } elseif ($machine -eq 0x8664) { $mach = 'x64' } elseif ($machine -eq 0xAA64) { $mach = 'ARM64' }
    $kind = 'EXE'
    if (($chars -band 0x2000) -ne 0) { $kind = 'DLL' }
    $clrRva = [long][BitConverter]::ToUInt32($H, $dirBase + 14 * 8)
    $dotnet = ''
    if ($clrRva -ne 0) { $dotnet = ', .NET managed' }
    $sub = 'other'
    if ($subsys -eq 2) { $sub = 'GUI' } elseif ($subsys -eq 3) { $sub = 'console' }
    $Lines.Add("[STATIC] PE: $kind, $mach, $sub$dotnet")

    $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01', [DateTimeKind]::Utc)
    $compiled = $epoch.AddSeconds([double]$ts)
    $note = ''
    if ($ts -eq 0) { $note = ' (zero: stripped or reproducible build)' }
    elseif ($compiled -gt (Get-Date).ToUniversalTime().AddDays(1)) { $note = ' (in the future: timestamp likely forged)'; $ind++ }
    $Lines.Add("[STATIC] Compile timestamp (UTC): $($compiled.ToString('yyyy-MM-dd HH:mm'))$note")

    if ($numSec -gt 96) { $Lines.Add("[STATIC] Unusual section count: $numSec (capped at 96)"); $numSec = 96; $ind++ }
    $secOff = $opt + $optSize
    $sections = @()
    for ($i = 0; $i -lt $numSec; $i++) {
        $o = $secOff + 40 * $i
        if (($o + 40) -gt $H.Length) { break }
        $nm = ([Text.Encoding]::ASCII.GetString($H, $o, 8)).TrimEnd([char]0) -replace '[^\x20-\x7E]', '?'
        $sections += [pscustomobject]@{
            Name    = $nm
            VSize   = [long][BitConverter]::ToUInt32($H, $o + 8)
            VA      = [long][BitConverter]::ToUInt32($H, $o + 12)
            RawSize = [long][BitConverter]::ToUInt32($H, $o + 16)
            RawPtr  = [long][BitConverter]::ToUInt32($H, $o + 20)
            Chars   = [long][BitConverter]::ToUInt32($H, $o + 36)
        }
    }
    $packerNames = @('UPX0', 'UPX1', '.aspack', '.adata', '.themida', '.vmp0', '.vmp1', '.petite', '.nsp0', '.MPRESS1')
    foreach ($s in $sections) {
        $ent = 0.0
        if ($s.RawSize -gt 0) {
            $sample = Read-RbiBytes $Stream $s.RawPtr ([int][Math]::Min($s.RawSize, 262144))
            $ent = Get-RbiEntropy $sample
        }
        $flags = @()
        if (($s.Chars -band 0x20000000L) -ne 0 -and ($s.Chars -band 0x80000000L) -ne 0) { $flags += 'W+X'; $ind++ }
        if ($ent -ge 7.2) { $flags += 'high entropy'; $ind++ }
        if ($packerNames -contains $s.Name) { $flags += 'packer section name'; $ind++ }
        $f = ''
        if ($flags.Count -gt 0) { $f = '  <-- ' + ($flags -join ', ') }
        $Lines.Add(("[STATIC] Section {0,-9} raw={1,9} entropy={2}{3}" -f $s.Name, $s.RawSize, $ent, $f))
    }

    $impRva = [long][BitConverter]::ToUInt32($H, $dirBase + 8)
    $imp = Get-RbiImports $Stream $sections $is64 $impRva
    $Lines.Add("[STATIC] Imports: $($imp.Dlls.Count) DLLs, $($imp.Names.Count) named functions")
    if ($imp.Names.Count -gt 0 -and $imp.Names.Count -le 10 -and $imp.Names.Contains('GetProcAddress')) {
        $Lines.Add('[STATIC] Very few imports plus GetProcAddress: typical of packed or loader-style files.')
        $ind++
    }
    foreach ($g in $script:RbiApiGroups.Keys) {
        $hit = @($script:RbiApiGroups[$g] | Where-Object { $imp.Names.Contains($_) })
        if ($hit.Count -gt 0) {
            $Lines.Add("[STATIC] API group '$g': " + (($hit | Select-Object -First 6) -join ', '))
            if ($g -eq 'process injection' -or $g -eq 'keylogging') { $ind++ }
        }
    }

    $secDirSize = [long][BitConverter]::ToUInt32($H, $dirBase + 36)
    $embedded = ($secDirSize -gt 0)
    $validStatus = ''
    $subj = ''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
        $st = [string]$sig.Status
        if ($st -eq 'Valid' -or $st -eq 'NotTrusted' -or $st -eq 'HashMismatch') {
            $validStatus = $st
            if ($sig.SignerCertificate) { $subj = $sig.SignerCertificate.Subject }
        }
    } catch {}
    if ($embedded) { $Lines.Add('[STATIC] Embedded Authenticode signature: present') }
    else { $Lines.Add('[STATIC] Embedded Authenticode signature: none') }
    if ($validStatus) {
        $how = ''
        if (-not $embedded -and $validStatus -eq 'Valid') { $how = ' (via Windows catalog)' }
        $Lines.Add("[STATIC] Authenticode validation: $validStatus$how; signer: $subj")
        if ($validStatus -eq 'HashMismatch') { $ind++ }
    }
    if (-not $embedded -and $validStatus -ne 'Valid') { $Lines.Add('[STATIC] No valid signature found'); $ind++ }

    $Lines.Add("[STATIC] PE indicators noted so far: $ind")
}

function Add-RbiMagicLines {
    param($Stream, [byte[]]$H, $Lines, [string]$FilePath)
    $kind = 'unknown or plain data'
    if ($H.Length -ge 4 -and $H[0] -eq 0x50 -and $H[1] -eq 0x4B -and $H[2] -eq 3 -and $H[3] -eq 4) { $kind = 'ZIP-based (zip, docx, xlsx, jar, apk...)' }
    elseif ($H.Length -ge 4 -and $H[0] -eq 0xD0 -and $H[1] -eq 0xCF -and $H[2] -eq 0x11 -and $H[3] -eq 0xE0) { $kind = 'OLE2 (legacy Office; may hold macros)' }
    elseif ($H.Length -ge 4 -and $H[0] -eq 0x25 -and $H[1] -eq 0x50 -and $H[2] -eq 0x44 -and $H[3] -eq 0x46) { $kind = 'PDF' }
    elseif ($H.Length -ge 4 -and $H[0] -eq 0x52 -and $H[1] -eq 0x61 -and $H[2] -eq 0x72 -and $H[3] -eq 0x21) { $kind = 'RAR archive' }
    elseif ($H.Length -ge 4 -and $H[0] -eq 0x37 -and $H[1] -eq 0x7A -and $H[2] -eq 0xBC -and $H[3] -eq 0xAF) { $kind = '7-Zip archive' }
    elseif ($H.Length -ge 4 -and $H[0] -eq 0x7F -and $H[1] -eq 0x45 -and $H[2] -eq 0x4C -and $H[3] -eq 0x46) { $kind = 'ELF (Linux executable)' }
    elseif ($H.Length -ge 8 -and $H[0] -eq 0x4C -and $H[1] -eq 0 -and $H[2] -eq 0 -and $H[3] -eq 0 -and $H[4] -eq 1 -and $H[5] -eq 0x14) { $kind = 'Windows shortcut (.lnk)' }
    elseif ($H.Length -gt 0) {
        $probe = [Math]::Min($H.Length, 4096)
        $odd = 0
        for ($i = 0; $i -lt $probe; $i++) { if (($H[$i] -lt 9) -or ($H[$i] -gt 126)) { $odd++ } }
        if (($odd / [double]$probe) -lt 0.02) { $kind = 'text or script' }
    }
    if ($H.Length -eq 0) { $kind = 'empty file' }
    $Lines.Add("[STATIC] Not a PE file. Detected type: $kind")

    if ($kind -like 'ZIP-based*') {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            $zip = [IO.Compression.ZipFile]::OpenRead($FilePath)
            try {
                $names = @($zip.Entries | ForEach-Object { $_.FullName })
                $Lines.Add("[STATIC] ZIP entries: $($names.Count)")
                foreach ($n in ($names | Select-Object -First 10)) { $Lines.Add('[STATIC]   ' + ($n -replace '[^\x20-\x7E]', '?')) }
                $risky = @($names | Where-Object { $_ -match '\.(exe|dll|scr|js|jse|vbs|vbe|lnk|bat|cmd|ps1|hta|jar|iso|img)$' })
                if ($risky.Count -gt 0) { $Lines.Add("[STATIC] Executable-type entries inside archive: $($risky.Count)") }
                if (@($names | Where-Object { $_ -match 'vbaProject\.bin$' }).Count -gt 0) { $Lines.Add('[STATIC] Office macro container (vbaProject.bin) present') }
            } finally { $zip.Dispose() }
        } catch { $Lines.Add("[STATIC] ZIP listing failed: $($_.Exception.Message)") }
    }
}

function Add-RbiStringLines {
    param($Stream, $Lines)
    $bytes = Read-RbiBytes $Stream 0 8388608
    if ($bytes.Length -eq 0) { return }
    $ascii = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    $uni = [Text.Encoding]::Unicode.GetString($bytes)
    $urlRx = 'https?://[A-Za-z0-9\-._~:/?#@!$&()*+,;=%]{4,120}'
    $ipRx = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    $urls = [System.Collections.Generic.HashSet[string]]::new()
    $ips = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($text in @($ascii, $uni)) {
        foreach ($m in [regex]::Matches($text, $urlRx)) { [void]$urls.Add($m.Value) }
        foreach ($m in [regex]::Matches($text, $ipRx)) { if (-not $m.Value.StartsWith('0.') -and $m.Value -notmatch '^\d+\.\d+\.0\.0$') { [void]$ips.Add($m.Value) } }
    }
    $Lines.Add("[STATIC] Strings scanned in first $($bytes.Length) bytes. URLs: $($urls.Count), IPv4-like: $($ips.Count) (IPv4-like can be version numbers)")
    foreach ($u in ($urls | Select-Object -First 8)) { $Lines.Add('[STATIC]   URL ' + $u) }
    foreach ($i in ($ips | Select-Object -First 8)) { $Lines.Add('[STATIC]   IP  ' + $i) }
    $found = @()
    foreach ($k in $script:RbiKeywords) {
        if ($ascii.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $uni.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $found += $k }
    }
    if ($found.Count -gt 0) { $Lines.Add('[STATIC] Keywords present: ' + ($found -join ', ')) }
}

function Get-RbiStaticLines {
    param([Parameter(Mandatory)][string]$FilePath)
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('[STATIC DEEP] Structure, imports and strings (file is read, never executed)')
    $fs = $null
    try {
        $fs = [IO.File]::Open($FilePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $h = Read-RbiBytes $fs 0 65536
        $isPe = $false
        $peOff = 0
        if ($h.Length -ge 64 -and $h[0] -eq 0x4D -and $h[1] -eq 0x5A) {
            $peOff = [int][BitConverter]::ToInt32($h, 0x3C)
            if ($peOff -gt 0 -and ($peOff + 24) -lt $h.Length -and $h[$peOff] -eq 0x50 -and $h[$peOff + 1] -eq 0x45 -and $h[$peOff + 2] -eq 0 -and $h[$peOff + 3] -eq 0) { $isPe = $true }
        }
        if ($isPe) { Add-RbiPeLines -Stream $fs -H $h -PeOff $peOff -Lines $L -FilePath $FilePath }
        else { Add-RbiMagicLines -Stream $fs -H $h -Lines $L -FilePath $FilePath }
        Add-RbiStringLines -Stream $fs -Lines $L
    } catch {
        $L.Add("[STATIC] Static module error: $($_.Exception.Message)")
    } finally {
        if ($fs) { $fs.Dispose() }
    }
    $L.Add('[STATIC LIMIT] Informational only: these lines do not change the verdict. Indicators are common in legitimate software too.')
    return $L.ToArray()
}
