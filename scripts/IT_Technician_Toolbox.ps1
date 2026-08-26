# ==============================================================
#  IT Technician Toolbox - PowerShell Edition (v1.3)
# ==============================================================

# --- Ensure script runs as administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Read-CompuTekInput {
    param([Parameter(Mandatory)][string]$Prompt)
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine("__COMPUTEK_PROMPT__:$Prompt")
        [Console]::Out.Flush()
        return [Console]::In.ReadLine()
    }
    return Read-Host $Prompt
}

function Get-ToolboxRecoveryProtectors {
    param([Parameter(Mandatory)]$BitLockerVolume)
    return @($BitLockerVolume.KeyProtector | Where-Object {
        $_.KeyProtectorType -eq 'RecoveryPassword' -and
        ([string]$_.RecoveryPassword) -match '^\d{6}(?:-\d{6}){7}$'
    })
}

function Save-ToolboxRecoveryPasswords {
    param(
        [Parameter(Mandatory)]$BitLockerVolume,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Timestamp
    )

    $mountPoint = [string]$BitLockerVolume.MountPoint
    $protectors = @(Get-ToolboxRecoveryProtectors -BitLockerVolume $BitLockerVolume)
    if ($protectors.Count -eq 0) { throw "No complete 48-digit recovery password is available for $mountPoint." }

    $keyFile = Join-Path $Directory ("BitLockerRecovery_{0}_{1}_{2}.txt" -f $env:COMPUTERNAME,$mountPoint.TrimEnd(':'),$Timestamp)
    $content = @(
        'BITLOCKER RECOVERY INFORMATION - CONFIDENTIAL',
        'Anyone with this recovery password may be able to unlock the drive.',
        'Secure or remove this file from the service USB after the job.',
        '',
        "Computer: $env:COMPUTERNAME",
        "Mount point: $mountPoint",
        "Saved (UTC): $([DateTime]::UtcNow.ToString('o'))",
        ''
    )
    foreach ($protector in $protectors) {
        $content += "Recovery key ID: $([string]$protector.KeyProtectorId)"
        $content += "Recovery password: $([string]$protector.RecoveryPassword)"
        $content += ''
    }
    $content | Set-Content -LiteralPath $keyFile -Encoding UTF8 -Force
    $flushStream = [IO.File]::Open($keyFile,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try { $flushStream.Flush($true) } finally { $flushStream.Dispose() }

    $savedText = Get-Content -LiteralPath $keyFile -Raw -ErrorAction Stop
    foreach ($protector in $protectors) {
        if ($savedText.IndexOf([string]$protector.RecoveryPassword,[StringComparison]::Ordinal) -lt 0 -or
            $savedText.IndexOf([string]$protector.KeyProtectorId,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "The recovery-password file for $mountPoint failed its read-back check."
        }
    }
    return [pscustomobject]@{
        FilePath = $keyFile
        Sha256 = (Get-FileHash -LiteralPath $keyFile -Algorithm SHA256 -ErrorAction Stop).Hash
        ProtectorCount = $protectors.Count
    }
}

# --- USB session and console setup ---
$toolRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) { $env:COMPUTEK_SCANNER_PORTABLE_ROOT } else { $PSScriptRoot }
$toolboxTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$toolboxSessionRoot = Join-Path $toolRoot ("CompuTekData\{0}\TechnicianToolbox\{1}" -f $env:COMPUTERNAME,$toolboxTimestamp)
New-Item -Path $toolboxSessionRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
$logFile = Join-Path $toolboxSessionRoot 'Toolbox.log'

try { $host.UI.RawUI.WindowTitle = "IT Technician Toolbox" } catch {}
if ($env:COMPUTEK_SCANNER_APP -ne '1') { Clear-Host }
Write-Host "`n=== IT TECHNICIAN TOOLBOX ===" -ForegroundColor Cyan
Write-Host "Case folder: $toolboxSessionRoot" -ForegroundColor Cyan
Write-Host 'Toolbox logs and CHKDSK reports will be saved on this service USB.' -ForegroundColor Cyan

# --- Logging Function ---
function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
}

function Invoke-ToolboxChkdsk {
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]:$')][string]$Target,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$ApproveWindowsPrompt
    )

    if ($ApproveWindowsPrompt) {
        'Y' | & chkdsk.exe $Target @Arguments 2>&1 |
            Tee-Object -FilePath $OutputPath -Append |
            ForEach-Object { Write-Host ([string]$_) }
    } else {
        & chkdsk.exe $Target @Arguments 2>&1 |
            Tee-Object -FilePath $OutputPath -Append |
            ForEach-Object { Write-Host ([string]$_) }
    }
    return $LASTEXITCODE
}

# --- Menu Loop ---
$exitToolbox = $false
$rebootStarted = $false
do {
    Write-Host "`n[1] System Information"
    Write-Host "[2] Network Information"
    Write-Host "[3] Flush DNS / Renew IP"
    Write-Host "[4] Test Internet Connection"
    Write-Host "[5] Clear Temp Files"
    Write-Host "[6] Run SFC (System File Checker)"
    Write-Host "[7] Run CHKDSK (Check Disk)"
    Write-Host "[8] Run DISM (Repair Windows Image)"
    Write-Host "[9] Open Task Manager"
    Write-Host "[10] Clear Print Queue"
    Write-Host "[11] Enable BitLocker Encryption"
    Write-Host "[0] Reboot System"
    Write-Host "[X] Exit Toolbox"
    $choice = Read-CompuTekInput "Choose an option"
    $normalizedChoice = ([string]$choice).Trim().ToUpperInvariant()

    try {
    switch ($normalizedChoice) {
        "1" {
            Write-Host "`n--- SYSTEM INFORMATION ---" -ForegroundColor Yellow
            systeminfo
            Log "Displayed system information"
        }
        "2" {
            Write-Host "`n--- NETWORK INFORMATION ---" -ForegroundColor Yellow
            ipconfig /all
            Log "Displayed network information"
        }
        "3" {
            Write-Host "`nFlushing DNS..." -ForegroundColor Yellow
            ipconfig /flushdns
            Write-Host "Releasing IP..."
            ipconfig /release
            Write-Host "Renewing IP..."
            Write-Host 'Windows may take several minutes while each network adapter waits for DHCP. The toolbox will return to the menu when Windows finishes.' -ForegroundColor Cyan
            ipconfig /renew
            $renewExitCode = $LASTEXITCODE
            if ($renewExitCode -eq 0) {
                Write-Host 'DNS flush and IP renewal completed. Returning to the toolbox menu.' -ForegroundColor Green
            } else {
                Write-Host "IP renewal finished with exit code $renewExitCode. Review the network information before continuing." -ForegroundColor Yellow
            }
            Log "Flushed DNS and renewed IP; ipconfig /renew exit code $renewExitCode"
        }
        "4" {
            Write-Host "`nTesting internet connection..." -ForegroundColor Yellow
            ping 8.8.8.8
            ping www.google.com
            Log "Tested internet connection"
        }
        "5" {
            $confirm = Read-CompuTekInput "Are you sure you want to clear temp files? (Y/N)"
            if ($confirm -match "^[Yy]$") {
                Write-Host "`nClearing temporary files..." -ForegroundColor Yellow
                Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Temp files cleared." -ForegroundColor Green
                Log "Cleared temp files"
            } else {
                Write-Host "Canceled clearing temp files." -ForegroundColor DarkGray
            }
        }
        "6" {
            Write-Host "`nRunning System File Checker..." -ForegroundColor Yellow
            sfc /scannow
            Log "Ran SFC scan"
        }
        "7" {
            Write-Host "`n--- AVAILABLE DRIVES ---" -ForegroundColor Yellow
            $drives = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object {
                $_.DriveLetter -and $_.FileSystem
            } | Sort-Object DriveLetter)
            for ($i = 0; $i -lt $drives.Count; $i++) {
                $d = $drives[$i]
                Write-Host "[$($i + 1)] $($d.DriveLetter):\  $($d.FileSystem)  $($d.FileSystemLabel)" -ForegroundColor Cyan
            }
            Write-Host "[0] Cancel" -ForegroundColor DarkGray
            $selection = Read-CompuTekInput "Select a drive number"
            if ($selection -ne '0' -and $selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $drives.Count) {
                $drive = $drives[[int]$selection - 1]
                $target = "$($drive.DriveLetter):"
                $scanArguments = if ([string]$drive.FileSystem -eq 'NTFS') { @('/scan') } else { @() }
                $scanLog = Join-Path $toolboxSessionRoot ("CHKDSK_{0}_ReadOnly_{1}.txt" -f $drive.DriveLetter,(Get-Date -Format 'yyyyMMdd_HHmmss'))

                Write-Host "`nRunning CHKDSK in read-only scan mode on $target..." -ForegroundColor Yellow
                Write-Host 'No repair switch is being used. Windows will inspect the file system without an automatic /F or /R.' -ForegroundColor Cyan
                $scanExitCode = Invoke-ToolboxChkdsk -Target $target -Arguments $scanArguments -OutputPath $scanLog
                Log "Read-only CHKDSK on $target returned exit code $scanExitCode; report $scanLog"

                if ($scanExitCode -eq 0) {
                    Write-Host "[OK] $target passed the read-only CHKDSK scan. No repair was started." -ForegroundColor Green
                    Write-Host "Report: $scanLog" -ForegroundColor DarkGray
                } else {
                    Write-Host "[REVIEW] CHKDSK returned exit code $scanExitCode. Review the report before approving a repair." -ForegroundColor Yellow
                    Write-Host 'Choose F for logical file-system repair. Choose R only when bad sectors or physical-media problems are suspected; /R can take many hours.' -ForegroundColor Yellow
                    $repairChoice = Read-CompuTekInput 'Type F for CHKDSK /F, R for CHKDSK /R, or SKIP'
                    if ($repairChoice -match '^[FfRr]$') {
                        $repairSwitch = if ($repairChoice -match '^[Rr]$') { '/r' } else { '/f' }
                        $requiredText = "RUN CHKDSK $($repairSwitch.ToUpper()) $target"
                        Write-Host "Close files and programs using $target. Windows may dismount the volume or schedule the repair for restart." -ForegroundColor Yellow
                        $repairApproval = Read-CompuTekInput "Type $requiredText to approve this repair, or type CANCEL"
                        if ($repairApproval -ceq $requiredText) {
                            $repairLog = Join-Path $toolboxSessionRoot ("CHKDSK_{0}_{1}_{2}.txt" -f $drive.DriveLetter,$repairSwitch.TrimStart('/').ToUpper(),(Get-Date -Format 'yyyyMMdd_HHmmss'))
                            Write-Host "Running CHKDSK $repairSwitch on $target after technician approval..." -ForegroundColor Yellow
                            $repairExitCode = Invoke-ToolboxChkdsk -Target $target -Arguments @($repairSwitch) -OutputPath $repairLog -ApproveWindowsPrompt
                            Log "Technician-approved CHKDSK $repairSwitch on $target returned exit code $repairExitCode; report $repairLog"
                            Write-Host "Repair command finished with exit code $repairExitCode. Report: $repairLog" -ForegroundColor Cyan
                            if ($target -ieq $env:SystemDrive) {
                                Write-Host 'If Windows scheduled this repair, restart the computer when the technician is ready. This toolbox will not reboot automatically.' -ForegroundColor Yellow
                            } else {
                                $verifyLog = Join-Path $toolboxSessionRoot ("CHKDSK_{0}_Verify_{1}.txt" -f $drive.DriveLetter,(Get-Date -Format 'yyyyMMdd_HHmmss'))
                                Write-Host 'Running a final read-only verification scan...' -ForegroundColor Cyan
                                $verifyExitCode = Invoke-ToolboxChkdsk -Target $target -Arguments $scanArguments -OutputPath $verifyLog
                                Log "Post-repair CHKDSK verification on $target returned exit code $verifyExitCode; report $verifyLog"
                                Write-Host "Verification exit code: $verifyExitCode. Report: $verifyLog" -ForegroundColor $(if($verifyExitCode -eq 0){'Green'}else{'Yellow'})
                            }
                        } else {
                            Write-Host 'Exact repair approval was not provided. No repair was started.' -ForegroundColor DarkGray
                        }
                    } else {
                        Write-Host 'Repair skipped. No /F or /R command was started.' -ForegroundColor DarkGray
                    }
                }
            } else {
                Write-Host "Canceled CHKDSK." -ForegroundColor DarkGray
            }
        }
        "8" {
            Write-Host "`nRunning DISM Health Restore..." -ForegroundColor Yellow
            DISM /Online /Cleanup-Image /RestoreHealth
            Log "Ran DISM RestoreHealth"
        }
        "9" {
            Start-Process taskmgr
            Log "Opened Task Manager"
        }
        "10" {
            Write-Host "`nClearing print queue..." -ForegroundColor Yellow
            $queueCleared = $false
            $spoolerRestarted = $false
            try {
                Stop-Service -Name Spooler -Force -ErrorAction Stop
                $printDir = "$env:SystemRoot\System32\spool\PRINTERS"
                if (Test-Path $printDir) {
                    Get-ChildItem -LiteralPath $printDir -Force -ErrorAction Stop | Remove-Item -Force -Recurse -ErrorAction Stop
                }
                $queueCleared = $true
            } catch {
                Write-Host "Failed to clear print queue: $_" -ForegroundColor Red
                Log "Error clearing print queue: $_"
            } finally {
                try {
                    Start-Service -Name Spooler -ErrorAction Stop
                    $spoolerRestarted = $true
                } catch {
                    Write-Host "Print Spooler could not be restarted: $_" -ForegroundColor Red
                    Log "Error restarting Print Spooler: $_"
                }
            }
            if ($queueCleared -and $spoolerRestarted) {
                Write-Host "Print queue cleared and Print Spooler restarted successfully." -ForegroundColor Green
                Log "Cleared print queue and restarted Print Spooler successfully"
            }
        }
        "11" {
            Write-Host "`n=== ENABLE BITLOCKER ENCRYPTION (USED SPACE ONLY) ===" -ForegroundColor Cyan
            Write-Host 'Recovery passwords must be verified on the service USB before encryption is enabled.' -ForegroundColor Yellow

            try {
                Import-Module BitLocker -ErrorAction Stop | Out-Null
                Set-Service -Name 'BDESVC' -StartupType Manual -ErrorAction Stop
                Start-Service -Name 'BDESVC' -ErrorAction SilentlyContinue

                foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker','HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE')) {
                    if (Test-Path -LiteralPath $path) {
                        foreach ($name in @('PreventDeviceEncryption','PreventAutoEncryption','DisableAutoEncryption')) {
                            if ((Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue).$name -eq 1) {
                                Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
                            }
                        }
                    }
                }

                $toolRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) { $env:COMPUTEK_SCANNER_PORTABLE_ROOT } else { $PSScriptRoot }
                $scriptDrive = (Get-Item -LiteralPath $toolRoot -ErrorAction Stop).PSDrive.Name
                $eligibleDrives = @()
                foreach ($storageVolume in @(Get-Volume -ErrorAction Stop | Where-Object {
                    $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne $scriptDrive
                } | Sort-Object DriveLetter)) {
                    $letter = "$($storageVolume.DriveLetter):"
                    try {
                        $bitLockerVolume = Get-BitLockerVolume -MountPoint $letter -ErrorAction Stop
                        if ([string]$bitLockerVolume.VolumeStatus -eq 'FullyDecrypted' -and [int]$bitLockerVolume.EncryptionPercentage -eq 0) {
                            $eligibleDrives += [pscustomobject]@{ Storage = $storageVolume; BitLocker = $bitLockerVolume }
                        } else {
                            Write-Host "$letter is $($bitLockerVolume.VolumeStatus) and is not eligible for a new enable request." -ForegroundColor DarkGray
                        }
                    } catch {
                        Write-Host "Could not safely inspect $letter; it will not be offered." -ForegroundColor Red
                    }
                }

                if ($eligibleDrives.Count -eq 0) {
                    Write-Host 'No fully decrypted fixed drives are available for encryption.' -ForegroundColor Green
                    break
                }

                Write-Host "`nAvailable drives for BitLocker:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $eligibleDrives.Count; $i++) {
                    $item = $eligibleDrives[$i]
                    Write-Host "[$($i + 1)] $($item.Storage.DriveLetter):  $($item.Storage.FileSystemLabel)" -ForegroundColor Cyan
                }
                Write-Host '[A] Encrypt All Listed Drives' -ForegroundColor Yellow
                Write-Host '[0] Cancel' -ForegroundColor DarkGray

                $choiceBL = Read-CompuTekInput 'Select a drive number (or A for all)'
                $targets = @()
                if ($choiceBL.ToUpper() -eq 'A') {
                    $targets = @($eligibleDrives)
                } elseif ($choiceBL -match '^\d+$' -and [int]$choiceBL -ge 1 -and [int]$choiceBL -le $eligibleDrives.Count) {
                    $targets = @($eligibleDrives[[int]$choiceBL - 1])
                } else {
                    Write-Host 'Canceled BitLocker encryption.' -ForegroundColor DarkGray
                    break
                }

                $approval = Read-CompuTekInput 'Type ENABLE BITLOCKER to verify recovery passwords and begin encryption, or type CANCEL'
                if ($approval -ne 'ENABLE BITLOCKER') {
                    Write-Host 'Canceled BitLocker encryption.' -ForegroundColor DarkGray
                    break
                }

                $keyDirectory = Join-Path $toolRoot ("BitLockerKeys\{0}" -f $env:COMPUTERNAME)
                New-Item -Path $keyDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
                $keyTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

                foreach ($target in $targets) {
                    $letter = "$($target.Storage.DriveLetter):"
                    Write-Host "`nPreparing BitLocker on $letter..." -ForegroundColor Yellow
                    try {
                        $current = Get-BitLockerVolume -MountPoint $letter -ErrorAction Stop
                        if ([string]$current.VolumeType -eq 'OperatingSystem') {
                            $tpm = Get-Tpm -ErrorAction Stop
                            if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
                                throw 'The TPM is not present and ready; the operating-system drive was not encrypted.'
                            }
                        }

                        if (@(Get-ToolboxRecoveryProtectors -BitLockerVolume $current).Count -eq 0) {
                            Add-BitLockerKeyProtector -MountPoint $letter -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                            $current = Get-BitLockerVolume -MountPoint $letter -ErrorAction Stop
                        }

                        $backup = Save-ToolboxRecoveryPasswords -BitLockerVolume $current -Directory $keyDirectory -Timestamp $keyTimestamp
                        Write-Host "[VERIFIED] Recovery password saved and read back: $($backup.FilePath)" -ForegroundColor Green
                        Write-Host "           SHA-256: $($backup.Sha256)" -ForegroundColor DarkGray

                        if ([string]$current.VolumeType -eq 'OperatingSystem') {
                            Enable-BitLocker -MountPoint $letter -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector -ErrorAction Stop | Out-Null
                        } else {
                            Enable-BitLocker -MountPoint $letter -EncryptionMethod XtsAes128 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                        }

                        $afterEnable = Get-BitLockerVolume -MountPoint $letter -ErrorAction Stop
                        $backup = Save-ToolboxRecoveryPasswords -BitLockerVolume $afterEnable -Directory $keyDirectory -Timestamp $keyTimestamp
                        Write-Host "[STARTED] $letter state: $($afterEnable.VolumeStatus), $($afterEnable.EncryptionPercentage)% encrypted." -ForegroundColor Green
                        if ([string]$afterEnable.VolumeType -eq 'OperatingSystem' -and [string]$afterEnable.VolumeStatus -eq 'EncryptionInProgress') {
                            Write-Host 'The OS-drive hardware check may require a reboot before encryption continues.' -ForegroundColor Yellow
                        }
                        Log "BitLocker requested on $letter; recovery file $($backup.FilePath); status $($afterEnable.VolumeStatus)"
                    } catch {
                        Write-Host "[FAILED] BitLocker was not safely enabled on ${letter}: $($_.Exception.Message)" -ForegroundColor Red
                        Log "BitLocker enable failed on ${letter}: $($_.Exception.Message)"
                    }
                }

                Write-Host "`nBitLocker requests complete. Encryption is not reported complete until VolumeStatus is FullyEncrypted." -ForegroundColor Cyan
            } catch {
                Write-Host "BitLocker workflow could not start safely: $($_.Exception.Message)" -ForegroundColor Red
                Log "BitLocker workflow failed: $($_.Exception.Message)"
            }
        }
        "0" {
            $confirmReboot = Read-CompuTekInput "Are you sure you want to reboot now? (Y/N)"
            if ($confirmReboot -match "^[Yy]$") {
                Write-Host "`nRebooting system..." -ForegroundColor Yellow
                Log "System reboot initiated"
                Restart-Computer -Force -ErrorAction Stop
                $rebootStarted = $true
            } else {
                Write-Host "Reboot canceled." -ForegroundColor DarkGray
            }
        }
        "X" {
            Write-Host "`nExiting IT Technician Toolbox..." -ForegroundColor Cyan
            Log "Exited Toolbox"
            $exitToolbox = $true
            break
        }
        default {
            Write-Host "Invalid selection. Try again." -ForegroundColor Red
        }
    }
    } catch {
        Write-Host "The selected toolbox action could not finish: $($_.Exception.Message)" -ForegroundColor Red
        Log "Toolbox option $normalizedChoice failed: $($_.Exception.Message)"
        Write-Host 'Returning to the toolbox menu.' -ForegroundColor Yellow
    }

    if (-not $exitToolbox -and -not $rebootStarted) {
        Write-Host "`nPress Enter to continue..." -ForegroundColor DarkGray
        [void](Read-CompuTekInput 'Press Enter to continue')
        if ($env:COMPUTEK_SCANNER_APP -ne '1') { Clear-Host }
        Write-Host "=== IT TECHNICIAN TOOLBOX ===`n" -ForegroundColor Cyan
    }

} while (-not $exitToolbox -and -not $rebootStarted)

Write-Host "`nGoodbye!" -ForegroundColor Cyan
Start-Sleep 1
exit
