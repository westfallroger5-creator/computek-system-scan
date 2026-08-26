# ==============================================================
#  PRE-CLONE SYSTEM PREPARATION TOOL - v5.0 (CompuTek Edition)
# ==============================================================

$ErrorActionPreference = 'Stop'

# --- Elevate when the script is run directly. The EXE is already elevated. ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
 ).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host 'Requesting administrator rights...' -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 1
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

function Write-CompuTekStage {
    param([Parameter(Mandatory)][string]$Message)
    [Console]::Out.WriteLine("SCAN STAGE: $Message")
    [Console]::Out.Flush()
}

function Get-CompuTekRecoveryProtectors {
    param([Parameter(Mandatory)]$BitLockerVolume)
    return @($BitLockerVolume.KeyProtector | Where-Object {
        $_.KeyProtectorType -eq 'RecoveryPassword' -and
        ([string]$_.RecoveryPassword) -match '^\d{6}(?:-\d{6}){7}$'
    })
}

function Save-CompuTekRecoveryPasswords {
    param(
        [Parameter(Mandatory)]$BitLockerVolume,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$Timestamp
    )

    $mountPoint = [string]$BitLockerVolume.MountPoint
    $protectors = @(Get-CompuTekRecoveryProtectors -BitLockerVolume $BitLockerVolume)
    if ($protectors.Count -eq 0) {
        throw "No complete 48-digit recovery password is available for $mountPoint."
    }

    $driveLabel = $mountPoint.TrimEnd(':').Replace('\\','_').Replace('/','_')
    $destination = Join-Path $DestinationDirectory ("BitLockerRecovery_{0}_{1}_{2}.txt" -f $ComputerName,$driveLabel,$Timestamp)
    $lines = @(
        'BITLOCKER RECOVERY INFORMATION - CONFIDENTIAL',
        'Anyone with this recovery password may be able to unlock the drive.',
        'Store this file securely and remove it from the service USB after the job.',
        '',
        "Computer: $ComputerName",
        "Mount point: $mountPoint",
        "Saved (UTC): $([DateTime]::UtcNow.ToString('o'))",
        ''
    )
    foreach ($protector in $protectors) {
        $lines += "Recovery key ID: $([string]$protector.KeyProtectorId)"
        $lines += "Recovery password: $([string]$protector.RecoveryPassword)"
        $lines += ''
    }

    $lines | Set-Content -LiteralPath $destination -Encoding UTF8 -Force

    # Ask Windows to flush the closed key file through the storage stack before
    # the read-back check. Failure is treated as a blocker, not a warning.
    $flushStream = [IO.File]::Open($destination,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try { $flushStream.Flush($true) } finally { $flushStream.Dispose() }

    # Read the file back from the destination before allowing decryption.
    $savedText = Get-Content -LiteralPath $destination -Raw -ErrorAction Stop
    foreach ($protector in $protectors) {
        $password = [string]$protector.RecoveryPassword
        $keyId = [string]$protector.KeyProtectorId
        if ($savedText.IndexOf($password,[StringComparison]::Ordinal) -lt 0 -or
            $savedText.IndexOf($keyId,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "Recovery information for $mountPoint did not pass the USB read-back check."
        }
    }
    $passwordsInFile = @([regex]::Matches($savedText,'\b\d{6}(?:-\d{6}){7}\b'))
    if ($passwordsInFile.Count -lt $protectors.Count) {
        throw "Recovery password verification failed for $mountPoint."
    }

    $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256 -ErrorAction Stop).Hash
    return [pscustomobject]@{
        MountPoint = $mountPoint
        FilePath = $destination
        Sha256 = $hash
        ProtectorCount = $protectors.Count
        Verified = $true
    }
}

function Wait-CompuTekDecryption {
    param(
        [Parameter(Mandatory)][string]$MountPoint,
        [int]$TimeoutHours = 48,
        [int]$PollSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddHours($TimeoutHours)
    $consecutiveQueryFailures = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
            $consecutiveQueryFailures = 0
            $state = [string]$volume.VolumeStatus
            $percentage = [int]$volume.EncryptionPercentage
            Write-CompuTekStage ("Decrypting {0}: {1}% remains encrypted ({2})" -f $MountPoint,$percentage,$state)
            Write-Host ("{0} - {1}% remains encrypted ({2})" -f $MountPoint,$percentage,$state) -ForegroundColor Yellow

            if ($state -eq 'FullyDecrypted' -and $percentage -eq 0) {
                return [pscustomobject]@{ Success = $true; State = $state; EncryptionPercentage = $percentage; Message = 'Fully decrypted' }
            }
        }
        catch {
            $consecutiveQueryFailures++
            Write-Host "[WARN] Could not read decryption status for $MountPoint ($consecutiveQueryFailures of 5): $($_.Exception.Message)" -ForegroundColor Yellow
            if ($consecutiveQueryFailures -ge 5) {
                return [pscustomobject]@{ Success = $false; State = 'QueryFailed'; EncryptionPercentage = $null; Message = 'BitLocker status failed five times in a row' }
            }
        }
        Start-Sleep -Seconds $PollSeconds
    }

    return [pscustomobject]@{ Success = $false; State = 'TimedOut'; EncryptionPercentage = $null; Message = "Decryption did not finish within $TimeoutHours hours" }
}

function Set-CompuTekPreCloneEncryptionPolicy {
    param([Parameter(Mandatory)][string]$BackupPath)

    $settings = @(
        [pscustomobject]@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'; Name = 'PreventDeviceEncryption'; Value = 1 },
        [pscustomobject]@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'; Name = 'PreventAutoEncryption'; Value = 1 },
        [pscustomobject]@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE'; Name = 'DisableAutoEncryption'; Value = 1 }
    )

    $original = foreach ($setting in $settings) {
        $existing = $null
        $present = $false
        if (Test-Path -LiteralPath $setting.Path) {
            $properties = Get-ItemProperty -LiteralPath $setting.Path -ErrorAction SilentlyContinue
            if ($properties -and $null -ne $properties.PSObject.Properties[$setting.Name]) {
                $present = $true
                $existing = $properties.$($setting.Name)
            }
        }
        [pscustomobject]@{ Path = $setting.Path; Name = $setting.Name; WasPresent = $present; PreviousValue = $existing }
    }
    $original | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $BackupPath -Encoding UTF8 -Force

    foreach ($setting in $settings) {
        if (-not (Test-Path -LiteralPath $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -PropertyType DWord -Value $setting.Value -Force | Out-Null
    }
}

function Get-CompuTekPortableMediaInfo {
    param([Parameter(Mandatory)][string]$RootPath)

    $rootItem = Get-Item -LiteralPath $RootPath -ErrorAction Stop
    $driveLetter = [string]$rootItem.PSDrive.Name
    if ($driveLetter -notmatch '^[A-Za-z]$') {
        throw 'The program is not running from a drive-letter-based service USB.'
    }
    $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
    $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop | Select-Object -First 1
    if (-not $partition -or $null -eq $partition.DiskNumber) {
        throw "The physical disk for service media $driveLetter`: could not be identified."
    }
    $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
    $driveType = [string]$volume.DriveType
    $busType = [string]$disk.BusType
    $isExternalServiceMedia = ($driveType -eq 'Removable' -or $busType -in @('USB','SD','MMC'))
    if (-not $isExternalServiceMedia) {
        throw "Pre-Clone must be launched from removable service media. $driveLetter`: is $driveType on a $busType disk."
    }
    return [pscustomobject]@{
        DriveLetter = $driveLetter.ToUpperInvariant()
        DiskNumber = [int]$partition.DiskNumber
        DriveType = $driveType
        BusType = $busType
        FriendlyName = [string]$disk.FriendlyName
    }
}

$portableRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) {
    $env:COMPUTEK_SCANNER_PORTABLE_ROOT
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if ([string]::IsNullOrWhiteSpace($portableRoot)) { $portableRoot = [string](Get-Location) }
$portableRoot = [IO.Path]::GetFullPath($portableRoot)
$computer = if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'UNKNOWN-COMPUTER' } else { $env:COMPUTERNAME }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$caseDirectory = Join-Path $portableRoot ("BitLockerKeys\{0}\PreClone_{1}" -f $computer,$timestamp)
$exitCode = 4

$portableMedia = $null
try {
    $portableMedia = Get-CompuTekPortableMediaInfo -RootPath $portableRoot
}
catch {
    Write-Host "[BLOCKED] Service USB safety check failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Run CompuTekScanner.exe directly from the service USB. Pre-Clone will not exclude an unverified internal disk.' -ForegroundColor Yellow
    exit $exitCode
}

try {
    New-Item -Path $caseDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "[BLOCKED] Cannot create the Pre-Clone output folder at $caseDirectory." -ForegroundColor Red
    Write-Host 'Connect a writable service USB, run the program from that USB, and try again.' -ForegroundColor Yellow
    exit $exitCode
}

Write-Host '==== PRE-CLONE SYSTEM PREPARATION ====' -ForegroundColor Cyan
Write-Host 'Workflow: verify recovery-key backup, fully decrypt, then check disks.' -ForegroundColor Cyan
Write-Host "Case folder: $caseDirectory" -ForegroundColor Green
Write-Host ("Service media: {0}: on physical disk {1} ({2}, {3})" -f $portableMedia.DriveLetter,$portableMedia.DiskNumber,$portableMedia.BusType,$portableMedia.FriendlyName) -ForegroundColor Cyan
Write-Host 'Recovery-key files are confidential. Secure or remove them from the service USB after the job.' -ForegroundColor Yellow

$fixedVolumes = @()
$storageMappingSucceeded = $true
try {
    $fixedVolumes = @(Get-Volume -ErrorAction Stop | Where-Object {
        $_.DriveLetter -and $_.DriveType -eq 'Fixed'
    } | Sort-Object DriveLetter)
}
catch {
    $storageMappingSucceeded = $false
    Write-Host "[BLOCKED] Fixed-drive inventory failed: $($_.Exception.Message)" -ForegroundColor Red
}

$portableDrive = $portableMedia.DriveLetter
$targetVolumes = @()
foreach ($volume in $fixedVolumes) {
    try {
        $partition = Get-Partition -DriveLetter $volume.DriveLetter -ErrorAction Stop | Select-Object -First 1
        if (-not $partition -or $null -eq $partition.DiskNumber) { throw 'No physical disk number was returned.' }
        if ([int]$partition.DiskNumber -eq [int]$portableMedia.DiskNumber) {
            Write-Host ("[INFO] Excluding service-media volume {0}: on physical disk {1}." -f $volume.DriveLetter,$portableMedia.DiskNumber) -ForegroundColor DarkGray
            continue
        }
        $targetVolumes += $volume
    }
    catch {
        $storageMappingSucceeded = $false
        Write-Host ("[BLOCKED] Could not map volume {0}: to a physical disk: {1}" -f $volume.DriveLetter,$_.Exception.Message) -ForegroundColor Red
    }
}
$bitLockerResults = @()
$keyBackups = @()
$diskResults = @()
$inspectionSucceeded = $storageMappingSucceeded -and $targetVolumes.Count -gt 0
$decryptionApproved = $false

Write-CompuTekStage 'Inspecting BitLocker status on fixed drives'
try {
    Import-Module BitLocker -ErrorAction Stop | Out-Null
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw 'The BitLocker PowerShell commands are not available on this Windows installation.'
    }
}
catch {
    $inspectionSucceeded = $false
    Write-Host "[BLOCKED] BitLocker cannot be inspected safely: $($_.Exception.Message)" -ForegroundColor Red
}

$bitLockerVolumes = @()
if ($inspectionSucceeded) {
    foreach ($volume in $targetVolumes) {
        $mountPoint = "$($volume.DriveLetter):"
        try {
            $bitLockerVolumes += Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
        }
        catch {
            $inspectionSucceeded = $false
            $bitLockerResults += [pscustomobject]@{ MountPoint = $mountPoint; InitialState = 'QueryFailed'; FinalState = 'Unknown'; Ready = $false; Message = $_.Exception.Message }
            Write-Host "[BLOCKED] Could not inspect BitLocker on ${mountPoint}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

$encryptedVolumes = @($bitLockerVolumes | Where-Object {
    ([string]$_.VolumeStatus) -ne 'FullyDecrypted' -or [int]$_.EncryptionPercentage -gt 0
})

if ($encryptedVolumes.Count -gt 0) {
    Write-Host ''
    Write-Host 'Encrypted or decrypting volumes detected:' -ForegroundColor Yellow
    foreach ($volume in $encryptedVolumes) {
        Write-Host (" - {0}: {1}, {2}% encrypted" -f $volume.MountPoint,$volume.VolumeStatus,$volume.EncryptionPercentage) -ForegroundColor Yellow
    }
    $response = Read-CompuTekInput 'Type PREPARE FOR CLONE to verify recovery keys and fully decrypt these drives, or type CANCEL'
    $decryptionApproved = $response -eq 'PREPARE FOR CLONE'
    if (-not $decryptionApproved) {
        Write-Host '[STOPPED] Technician did not approve decryption. The computer is NOT READY for Acronis cloning.' -ForegroundColor Yellow
    }
} elseif ($inspectionSucceeded) {
    Write-Host '[OK] All inspected fixed drives are already fully decrypted.' -ForegroundColor Green
}

if ($decryptionApproved) {
    foreach ($initialVolume in $encryptedVolumes) {
        $mountPoint = [string]$initialVolume.MountPoint
        $initialState = [string]$initialVolume.VolumeStatus
        $mountDrive = $mountPoint.TrimEnd(':')
        $resultMessage = $null
        $finalState = 'Unknown'
        $ready = $false

        try {
            if ($portableDrive -and $mountDrive -eq $portableDrive) {
                throw "The recovery key cannot be stored on the same drive being decrypted ($mountPoint)."
            }

            Write-CompuTekStage "Verifying the BitLocker recovery password for $mountPoint"
            $current = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
            $protectors = @(Get-CompuTekRecoveryProtectors -BitLockerVolume $current)
            if ($protectors.Count -eq 0) {
                Write-Host "[INFO] No 48-digit recovery password exists on $mountPoint; adding one before decryption." -ForegroundColor Cyan
                Add-BitLockerKeyProtector -MountPoint $mountPoint -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                $current = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
            }

            $backup = Save-CompuTekRecoveryPasswords -BitLockerVolume $current -DestinationDirectory $caseDirectory -ComputerName $computer -Timestamp $timestamp
            $keyBackups += $backup
            Write-Host "[VERIFIED] Complete recovery information for $mountPoint was saved and read back successfully." -ForegroundColor Green
            Write-Host "           File: $($backup.FilePath)" -ForegroundColor Green
            Write-Host "           SHA-256: $($backup.Sha256)" -ForegroundColor DarkGray

            Write-CompuTekStage "Starting BitLocker decryption on $mountPoint"
            if ($current.AutoUnlockEnabled -eq $true) {
                Write-Host "[INFO] Disabling BitLocker auto-unlock on $mountPoint before decryption." -ForegroundColor Cyan
                Disable-BitLockerAutoUnlock -MountPoint $mountPoint -ErrorAction Stop | Out-Null
            }
            Disable-BitLocker -MountPoint $mountPoint -ErrorAction Stop | Out-Null
            Write-Host "[STARTED] BitLocker decryption on $mountPoint." -ForegroundColor Cyan

            $waitResult = Wait-CompuTekDecryption -MountPoint $mountPoint
            $finalState = [string]$waitResult.State
            $ready = [bool]$waitResult.Success
            $resultMessage = [string]$waitResult.Message
            if ($ready) {
                Write-Host "[OK] $mountPoint is fully decrypted." -ForegroundColor Green
            } else {
                Write-Host "[NOT READY] $mountPoint decryption did not complete: $resultMessage" -ForegroundColor Red
            }
        }
        catch {
            $resultMessage = $_.Exception.Message
            Write-Host "[BLOCKED] $mountPoint was not prepared: $resultMessage" -ForegroundColor Red
        }

        $bitLockerResults += [pscustomobject]@{
            MountPoint = $mountPoint
            InitialState = $initialState
            FinalState = $finalState
            RecoveryBackupVerified = @($keyBackups | Where-Object {$_.MountPoint -eq $mountPoint -and $_.Verified}).Count -gt 0
            Ready = $ready
            Message = $resultMessage
        }
    }
}

foreach ($volume in @($bitLockerVolumes | Where-Object {
    ([string]$_.VolumeStatus) -eq 'FullyDecrypted' -and [int]$_.EncryptionPercentage -eq 0
})) {
    if (@($bitLockerResults | Where-Object {$_.MountPoint -eq $volume.MountPoint}).Count -eq 0) {
        $bitLockerResults += [pscustomobject]@{
            MountPoint = [string]$volume.MountPoint
            InitialState = 'FullyDecrypted'
            FinalState = 'FullyDecrypted'
            RecoveryBackupVerified = $null
            Ready = $true
            Message = 'No decryption was required'
        }
    }
}

$bitLockerPreparationReady = $inspectionSucceeded -and
    $bitLockerResults.Count -eq $targetVolumes.Count -and
    @($bitLockerResults | Where-Object {-not $_.Ready}).Count -eq 0
$encryptionPolicyReady = $false
if ($bitLockerPreparationReady) {
    Write-CompuTekStage 'Preventing automatic re-encryption during cloning'
    try {
        $policyBackup = Join-Path $caseDirectory 'PreClonePolicyBackup.json'
        Set-CompuTekPreCloneEncryptionPolicy -BackupPath $policyBackup
        Write-Host '[OK] Automatic device-encryption prevention is active for the clone workflow.' -ForegroundColor Green
        Write-Host "     Original policy values: $policyBackup" -ForegroundColor DarkGray
        Write-Host '     The BitLocker service was left available; Final System Check removes these temporary flags.' -ForegroundColor Cyan
        $encryptionPolicyReady = $true
    }
    catch {
        Write-Host "[NOT READY] Could not set temporary encryption-prevention policy: $($_.Exception.Message)" -ForegroundColor Red
        $inspectionSucceeded = $false
    }
}

Write-CompuTekStage 'Checking Secure Boot status'
$secureBootStatus = 'Unknown'
try {
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        $secureBootStatus = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' }
        Write-Host "[INFO] Secure Boot: $secureBootStatus" -ForegroundColor Cyan
    } else {
        $secureBootStatus = 'NotSupported'
        Write-Host '[INFO] Secure Boot status is not supported on this system.' -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "[WARN] Secure Boot status could not be read: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-CompuTekStage 'Running non-destructive CHKDSK scans'
foreach ($volume in $targetVolumes) {
    $mountPoint = "$($volume.DriveLetter):"
    $fileSystem = [string]$volume.FileSystem
    $checkArguments = if ($fileSystem -eq 'NTFS') { @($mountPoint,'/scan') } else { @($mountPoint) }
    $logPath = Join-Path $caseDirectory ("CHKDSK_{0}.txt" -f $volume.DriveLetter)
    Write-Host "[INFO] Checking $mountPoint ($fileSystem). This can take several minutes..." -ForegroundColor Cyan
    try {
        $checkOutput = @(& chkdsk.exe @checkArguments 2>&1)
        $checkExitCode = $LASTEXITCODE
        $checkOutput | Set-Content -LiteralPath $logPath -Encoding UTF8 -Force
        $diskReady = $checkExitCode -eq 0
        $meaning = switch ($checkExitCode) {
            0 { 'No file-system errors were found' }
            1 { 'Errors were found and fixed; review and run Pre-Clone again to verify' }
            2 { 'Cleanup was performed or could not be performed without repair options' }
            3 { 'The disk could not be checked or errors remain unfixed' }
            default { "CHKDSK returned unexpected exit code $checkExitCode" }
        }
        $diskResults += [pscustomobject]@{ MountPoint = $mountPoint; FileSystem = $fileSystem; ExitCode = $checkExitCode; Ready = $diskReady; Message = $meaning; LogPath = $logPath }
        if ($diskReady) {
            Write-Host "[OK] $mountPoint passed CHKDSK. Log: $logPath" -ForegroundColor Green
        } else {
            Write-Host "[NOT READY] $mountPoint did not pass CHKDSK: $meaning" -ForegroundColor Red
            Write-Host "            Review $logPath and repair the disk before cloning." -ForegroundColor Yellow
        }
    }
    catch {
        $diskResults += [pscustomobject]@{ MountPoint = $mountPoint; FileSystem = $fileSystem; ExitCode = $null; Ready = $false; Message = $_.Exception.Message; LogPath = $logPath }
        Write-Host "[NOT READY] CHKDSK could not complete on ${mountPoint}: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$bitLockerReady = $bitLockerPreparationReady -and $encryptionPolicyReady
$disksReady = $diskResults.Count -eq $targetVolumes.Count -and
    @($diskResults | Where-Object {-not $_.Ready}).Count -eq 0
$acronisReady = $targetVolumes.Count -gt 0 -and $bitLockerReady -and $disksReady

$summary = [pscustomobject]@{
    SchemaVersion = 1
    ComputerName = $computer
    CompletedUtc = [DateTime]::UtcNow.ToString('o')
    PortableRoot = $portableRoot
    PortableMedia = $portableMedia
    SecureBoot = $secureBootStatus
    BitLockerInspectionSucceeded = $inspectionSucceeded
    AcronisReady = $acronisReady
    BitLocker = @($bitLockerResults)
    RecoveryBackups = @($keyBackups)
    DiskChecks = @($diskResults)
}
$summaryJsonPath = Join-Path $caseDirectory 'PreCloneSummary.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryJsonPath -Encoding UTF8 -Force
$summaryTextPath = Join-Path $caseDirectory 'PreCloneSummary.txt'
@(
    'COMPUTEK PRE-CLONE SUMMARY',
    "Computer: $computer",
    "Acronis ready: $(if ($acronisReady) {'YES'} else {'NO'})",
    "BitLocker ready: $(if ($bitLockerReady) {'YES'} else {'NO'})",
    "Disk checks passed: $(if ($disksReady) {'YES'} else {'NO'})",
    "Secure Boot: $secureBootStatus",
    "Case folder: $caseDirectory",
    '',
    'Acronis ready means every inspected fixed drive is fully decrypted and CHKDSK returned no errors.',
    'Recovery-password files are confidential and must be secured or removed from the service USB after the job.'
) | Set-Content -LiteralPath $summaryTextPath -Encoding UTF8 -Force

Write-Host ''
Write-Host '==== PRE-CLONE RESULT ====' -ForegroundColor Cyan
if ($acronisReady) {
    Write-Host 'READY FOR ACRONIS CLONE: YES' -ForegroundColor Green
    Write-Host 'All fixed target drives are fully decrypted and passed CHKDSK.' -ForegroundColor Green
    $exitCode = 0
} else {
    Write-Host 'READY FOR ACRONIS CLONE: NO' -ForegroundColor Red
    Write-Host 'Do not start the clone until the failed or incomplete items above are corrected and this check passes.' -ForegroundColor Yellow
}
Write-Host "Summary: $summaryTextPath" -ForegroundColor Cyan
Write-Host "Case folder: $caseDirectory" -ForegroundColor Cyan

if ($env:COMPUTEK_SCANNER_APP -ne '1') {
    Write-Host 'Press Enter to close this window...' -ForegroundColor Cyan
    [void][System.Console]::ReadLine()
}
exit $exitCode
