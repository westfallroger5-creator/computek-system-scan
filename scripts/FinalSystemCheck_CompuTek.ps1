# =====================================================
#  FINAL SYSTEM READINESS CHECK - COMPU-TEK
# =====================================================
try { $Host.UI.RawUI.WindowTitle = "Final System Readiness Check - Compu-TEK" } catch {}

function Read-CompuTekInput {
    param([Parameter(Mandatory)][string]$Prompt)
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine("__COMPUTEK_PROMPT__:$Prompt")
        [Console]::Out.Flush()
        return [Console]::In.ReadLine()
    }
    return Read-Host $Prompt
}

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "      FINAL SYSTEM READINESS CHECK - COMPU-TEK" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

$BitLockerSkipped = $false
$SpeakerTestFailed = $false
$HibernationFailed = $false
$RestorePointFailed = $false

# --- 1. Windows Edition & Activation ---
$edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
Write-Host "[INFO] Windows Edition: $edition" -ForegroundColor Cyan

try {
    $l = Get-CimInstance SoftwareLicensingProduct |
         Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
    if ($l) {
        Write-Host "[OK] Windows is activated." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Windows not activated!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to determine activation status." -ForegroundColor Yellow
}

# --- 1b. Disable and verify Hibernation ---
try {
    Write-Host "`n[INFO] Disabling hibernation as part of the standard final-store workflow..." -ForegroundColor Cyan
    & powercfg.exe /hibernate off | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "powercfg returned exit code $LASTEXITCODE"
    }

    $powerSettings = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -ErrorAction Stop
    if ($null -ne $powerSettings.PSObject.Properties['HibernateEnabled'] -and
        [int]$powerSettings.HibernateEnabled -eq 0) {
        Write-Host "[OK] Hibernation is disabled." -ForegroundColor Green
    } else {
        $HibernationFailed = $true
        Write-Host "[WARN] Hibernation could not be verified as disabled." -ForegroundColor Yellow
    }
} catch {
    $HibernationFailed = $true
    Write-Host "[WARN] Unable to disable or verify hibernation: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 2. BitLocker (skip for Home/Core editions) ---
if ($edition -match 'Home' -or $edition -match 'Core' -or $edition -match 'SingleLanguage') {
    Write-Host "[INFO] BitLocker check skipped: Windows Home/Core edition detected." -ForegroundColor Cyan
    $BitLockerSkipped = $true
}
else {
    try {
        Write-Host "`n[INFO] Checking and repairing BitLocker configuration..." -ForegroundColor Cyan

        # --- Step 1: Remove prevention flags that could block encryption ---
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker",
            "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
        )

        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                foreach ($name in @("PreventDeviceEncryption", "PreventAutoEncryption", "DisableAutoEncryption")) {
                    $val = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
                    if ($val -eq 1) {
                        Write-Host "[FIX] Removing BitLocker restriction flag: $name" -ForegroundColor Yellow
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Write-Host "[OK] BitLocker policy flags verified." -ForegroundColor Green

        # Older Pre-Clone versions disabled BDESVC. Repair that state so the
        # final computer can manage BitLocker normally again.
        $bitLockerService = Get-CimInstance Win32_Service -Filter "Name='BDESVC'" -ErrorAction SilentlyContinue
        if ($bitLockerService -and $bitLockerService.StartMode -eq 'Disabled') {
            Write-Host "[FIX] Restoring the BitLocker service to Manual startup." -ForegroundColor Yellow
            Set-Service -Name 'BDESVC' -StartupType Manual -ErrorAction Stop
        }

        # --- Step 2: Check BitLocker status per drive ---
        $oldPref = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module BitLocker -ErrorAction SilentlyContinue | Out-Null
        $WarningPreference = $oldPref

        $vols = Get-BitLockerVolume -ErrorAction Stop
        if ($vols) {
            foreach ($v in $vols) {
                $label = (Get-Volume -DriveLetter $v.MountPoint.TrimEnd(':') -ErrorAction SilentlyContinue).FileSystemLabel
                if ($label -match 'Ventoy' -or $label -match 'VTOYEFI' -or
                    $v.MountPoint -match 'Ventoy' -or $v.MountPoint -match 'VTOYEFI') { continue }

                $status = $v.EncryptionPercentage
                $state  = $v.VolumeStatus
                $prot   = $v.ProtectionStatus

                if ($state -match "FullyEncrypted" -or $state -match "UsedSpaceOnlyEncrypted" -or $status -eq 100) {
                    Write-Host "[OK] BitLocker active on drive $($v.MountPoint) ($state, $status%)" -ForegroundColor Green
                }
                elseif ($prot -eq 'Off' -or $state -match "FullyDecrypted") {
                    Write-Host "[WARN] BitLocker off on drive $($v.MountPoint)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "[INFO] BitLocker unknown state on $($v.MountPoint) ($state)" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "[INFO] No BitLocker volumes found." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "[WARN] Unable to query BitLocker status or clear flags." -ForegroundColor Yellow
    }
}

# --- 3. Active Virus Protection ---
try {
    $defender = $null
    $otherAV  = $null

    try { $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}

    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue

    if ($defender -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
        Write-Host "[OK] Microsoft Defender active and protecting." -ForegroundColor Green
    }
    elseif ($avProducts -and ($avProducts.productState -ne $null)) {
        $names = ($avProducts.displayName | Sort-Object -Unique) -join ", "
        Write-Host "[INFO] Third-party AV detected: $names (Defender off)" -ForegroundColor Cyan
    }
    else {
        Write-Host "[WARN] No active antivirus protection detected!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to verify antivirus protection." -ForegroundColor Yellow
}

# --- 4. Splashtop Streamer ---
try {
    $svc = Get-Service -Name "SplashtopRemoteService" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "[OK] Splashtop Streamer running." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Splashtop Streamer not detected or not running!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Unable to check Splashtop service." -ForegroundColor Yellow
}

# --- 5. Windows Updates ---
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
    $count    = $result.Updates.Count
    if ($count -gt 0) {
        Write-Host "[WARN] Pending Windows Updates: $count" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Windows is up to date." -ForegroundColor Green
    }
} catch {
    if ($_.Exception.HResult -eq -2145124318) {
        Write-Host "[INFO] Updates managed by WSUS or policy." -ForegroundColor Cyan
    } else {
        Write-Host "[INFO] Windows Update check skipped due to restriction." -ForegroundColor Cyan
    }
}

# --- 6. Device Manager ---
try {
    $e = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' }
    if ($null -ne $e -and $e.Count -gt 0) {
        foreach ($i in $e) {
            Write-Host "[WARN] Device Issue: $($i.FriendlyName) ($($i.InstanceId))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] No device issues found." -ForegroundColor Green
    }
} catch {
    Write-Host "[WARN] Unable to query Device Manager." -ForegroundColor Yellow
}

# --- 7. System Restore Point (Hardened for field use) ---
try {
    Write-Host "`n[INFO] Enabling System Protection and creating the required restore point..." -ForegroundColor Cyan

    # Detect system drive
    $sysDrive = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).SystemDrive
    if (-not $sysDrive) { 
        Write-Host "[WARN] Unable to detect system drive for restore point." -ForegroundColor Yellow
        throw "No system drive" 
    }

    # Enable-ComputerRestore is safe to call when protection is already enabled
    # and avoids parsing localized vssadmin text.
    try {
        $restoreDrive = $sysDrive.TrimEnd('\') + '\'
        Enable-ComputerRestore -Drive $restoreDrive -ErrorAction Stop
        Write-Host "[OK] System Protection is enabled on $restoreDrive." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not enable System Protection. It may be disabled by policy on this machine." -ForegroundColor Yellow
        Write-Host "[INFO] Skipping restore point creation." -ForegroundColor DarkGray
        $RestorePointFailed = $true
        throw "ProtectionOff"
    }
    # Attempt to create restore point
    try {
        $dateLabel = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
        $restoreDescription = "Compu-TEK Readiness Check - $dateLabel"
        Write-Host "[INFO] Creating System Restore Point..." -ForegroundColor Cyan

        # Windows normally skips a new point when another was made during the
        # last 24 hours. Temporarily allow this required final-store point, then
        # restore the customer's original frequency setting.
        $restoreRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $frequencyName = 'SystemRestorePointCreationFrequency'
        if (-not (Test-Path -LiteralPath $restoreRegistryPath)) {
            New-Item -Path $restoreRegistryPath -Force | Out-Null
        }
        $restoreProperties = Get-ItemProperty -LiteralPath $restoreRegistryPath -ErrorAction Stop
        $frequencyWasPresent = $null -ne $restoreProperties.PSObject.Properties[$frequencyName]
        $originalFrequency = if ($frequencyWasPresent) { $restoreProperties.$frequencyName } else { $null }

        try {
            New-ItemProperty -LiteralPath $restoreRegistryPath -Name $frequencyName -PropertyType DWord -Value 0 -Force | Out-Null
            Checkpoint-Computer -Description $restoreDescription -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        }
        finally {
            if ($frequencyWasPresent) {
                New-ItemProperty -LiteralPath $restoreRegistryPath -Name $frequencyName -PropertyType DWord -Value $originalFrequency -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $restoreRegistryPath -Name $frequencyName -ErrorAction SilentlyContinue
            }
        }

        $createdPoint = @(Get-ComputerRestorePoint -ErrorAction Stop | Where-Object {
            $_.Description -eq $restoreDescription
        } | Select-Object -First 1)
        if ($createdPoint.Count -eq 0) {
            throw 'Windows did not return the newly requested restore point.'
        }

        Write-Host "[OK] Restore Point created successfully." -ForegroundColor Green
    }
    catch {
        $RestorePointFailed = $true
        Write-Host "[WARN] Restore point could NOT be created. (Likely VSS or policy issue)" -ForegroundColor Yellow
    }
} catch {
    # This catches all failures, but *never* ends the script
    $RestorePointFailed = $true
    Write-Host "[INFO] System Restore section skipped due to environment restrictions." -ForegroundColor DarkGray
}

# --- 8. Audio Device / Speaker Check ---
try {
    Write-Host ""
    Write-Host "---------------------------------------------------"
    Write-Host "[8/8] Checking audio output devices..." -ForegroundColor Cyan

    $audioDevices = Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue
    $activeAudio  = $audioDevices | Where-Object { $_.Status -eq "OK" }

    if (-not $activeAudio) {
        Write-Host "[WARN] No active audio output device detected!" -ForegroundColor Yellow
        $SpeakerTestFailed = $true
    }
    else {
        $device = $activeAudio | Select-Object -First 1
        $driver = $device.DriverProviderName
        $name   = $device.Name

        Write-Host ("[OK] Active audio device detected: " + $name) -ForegroundColor Green

        if ($driver -match "Microsoft") {
            Write-Host "[WARN] Generic Microsoft audio driver in use -- verify correct sound driver installed." -ForegroundColor Yellow
        } else {
            Write-Host ("[INFO] Audio driver provider: " + $driver) -ForegroundColor Cyan
        }

        try {
            $code = @"
using System;
using System.Runtime.InteropServices;

[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    void RegisterControlChangeNotify(IntPtr pNotify);
    void UnregisterControlChangeNotify(IntPtr pNotify);
    void GetChannelCount(out uint pnChannelCount);
    void SetMasterVolumeLevel(float fLevelDB, Guid pguidEventContext);
    void SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext);
    void GetMasterVolumeLevel(out float pfLevelDB);
    void GetMasterVolumeLevelScalar(out float pfLevel);
    void SetChannelVolumeLevel(uint nChannel, float fLevelDB, Guid pguidEventContext);
    void SetChannelVolumeLevelScalar(uint nChannel, float fLevel, Guid pguidEventContext);
    void GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
    void GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
    void SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext);
    void GetMute(out bool pbMute);
    void GetVolumeStepInfo(out uint pnStep, out uint pnStepCount);
    void VolumeStepUp(Guid pguidEventContext);
    void VolumeStepDown(Guid pguidEventContext);
    void QueryHardwareSupport(out uint pdwHardwareSupportMask);
    void GetVolumeRange(out float pflVolumeMindB, out float pflVolumeMaxdB, out float pflVolumeIncrementdB);
}

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    void NotImpl1();
    void GetDefaultAudioEndpoint(uint dataFlow, uint role, out IMMDevice ppDevice);
}

[Guid("D666063F-1587-4E43-81F1-B948E807363F"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    void Activate(ref Guid id, uint clsCtx, IntPtr pActivationParams, out IAudioEndpointVolume aev);
}

[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
class MMDeviceEnumeratorComObject {}

public class VolumeControl {
    public static void SetVolumeToHalf() {
        var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
        IMMDevice device;
        enumerator.GetDefaultAudioEndpoint(0, 1, out device);
        Guid IID_IAudioEndpointVolume = typeof(IAudioEndpointVolume).GUID;
        IAudioEndpointVolume volume;
        device.Activate(ref IID_IAudioEndpointVolume, 23, IntPtr.Zero, out volume);
        volume.SetMute(false, Guid.Empty);
        volume.SetMasterVolumeLevelScalar(0.5f, Guid.Empty);
    }
}
"@
            Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
            [VolumeControl]::SetVolumeToHalf()
            Write-Host "[INFO] Speaker volume set to 50% and unmuted." -ForegroundColor Cyan
        } catch {
            Write-Host "[INFO] Unable to modify speaker volume (non-fatal)." -ForegroundColor DarkGray
        }

        try {
            Write-Host "[INFO] Playing Compu-Tek test melody..." -ForegroundColor Cyan

            function Play-Note {
                param ([int]$freq, [int]$dur)
                if ($dur -lt 150) { $dur = 150 }
                Start-Sleep -Milliseconds 30
                [console]::Beep($freq, $dur)
                Start-Sleep -Milliseconds ($dur + 150)
            }

            $notes = @{
                "G" = 392; "A" = 440; "B" = 494;
                "C" = 522; "D" = 588; "E" = 658
            }

            $melody = @(
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("G",200),@("G",200),@("G",200),
                @("C",600),@("E",200),
                @("C",200),@("C",200),
                @("B",200),@("B",200),
                @("A",200),@("A",200),
                @("G",600)
            )

            foreach ($note in $melody) {
                try {
                    $freq = $notes[$note[0]]
                    $dur  = $note[1]
                    Play-Note -freq $freq -dur $dur
                } catch {
                    Start-Sleep -Milliseconds 300
                }
            }

            Write-Host "[INFO] Speaker test melody finished." -ForegroundColor Cyan
            $heardResponse = Read-CompuTekInput 'Did you clearly hear the speaker test? (Y/N)'
            if ($heardResponse -match '^[Yy]$') {
                Write-Host "[OK] Technician confirmed audible speaker output." -ForegroundColor Green
            } else {
                Write-Host "[WARN] Technician did not confirm audible speaker output." -ForegroundColor Yellow
                $SpeakerTestFailed = $true
            }
        } catch {
            Write-Host "[WARN] Speaker test failed during melody playback." -ForegroundColor Yellow
            $SpeakerTestFailed = $true
        }
    }

    $disabled = $audioDevices | Where-Object { $_.Status -ne "OK" }
    if ($disabled) {
        foreach ($d in $disabled) {
            Write-Host ("[WARN] Disabled or problem audio device: " + $d.Name) -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[WARN] Unable to query audio devices." -ForegroundColor Yellow
    $SpeakerTestFailed = $true
}

# --- Summary ---
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "All checks complete. Review results above." -ForegroundColor Cyan
if ($BitLockerSkipped) {
    Write-Host "[INFO] BitLocker test skipped automatically due to Home/Core edition." -ForegroundColor DarkGray
}
if ($SpeakerTestFailed) {
    Write-Host "[WARN] Speaker readiness failed -- audible output was not confirmed." -ForegroundColor Yellow
}
if ($HibernationFailed) {
    Write-Host "[WARN] Required final action failed: hibernation is not confirmed off." -ForegroundColor Yellow
}
if ($RestorePointFailed) {
    Write-Host "[WARN] Required final action failed: a restore point was not confirmed." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
if ($env:COMPUTEK_SCANNER_APP -eq '1') {
    Write-Host "Final System Check complete." -ForegroundColor Green
} else {
    Write-Host "Press Enter to close this window..." -ForegroundColor Cyan
    [void][System.Console]::ReadLine()
}
exit



