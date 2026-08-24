<#
 RemoteAccessScanAndRemove.ps1

 Evidence-first remote-access scanner and interactive remediation tool.
 - Uses a shared, updateable JSON catalog instead of a hard-coded product list.
 - Inspects all loaded-user uninstall records, AppX packages, services, processes,
   autoruns, scheduled tasks, startup folders, active connections, and targeted files.
 - Inspects file metadata and Authenticode status so a renamed executable can still match.
 - Flags unknown services/persistence/processes in user-writable locations.
 - Never removes anything during scanning. Every remediation requires typed confirmation.
 - Uses the vendor uninstaller first. It does not delete services before uninstalling.
 - Unknown or portable artifacts can be stopped, disabled, and quarantined after a
   separate confirmation; service definitions are retained as evidence.
#>

[CmdletBinding()]
param(
    [switch]$DeepScan,
    [ValidateRange(1,365)][int]$LookbackDays = 30,
    [switch]$ScanOnly,
    [switch]$IncludeHashes
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $argumentList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-LookbackDays',[string]$LookbackDays)
    if ($DeepScan) { $argumentList += '-DeepScan' }
    if ($ScanOnly) { $argumentList += '-ScanOnly' }
    if ($IncludeHashes) { $argumentList += '-IncludeHashes' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentList -Verb RunAs
    exit
}

$modulePath = Join-Path $PSScriptRoot 'CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $PSScriptRoot 'RemoteAccessSignatures.json'
Import-Module $modulePath -Force -ErrorAction Stop
$catalog = Get-CompuTekCatalog -Path $catalogPath

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$caseRoot = Join-Path $env:ProgramData "CompuTek\RemoteScanner\Cases\$($env:COMPUTERNAME)_$timestamp"
$quarantineRoot = Join-Path $env:ProgramData "CompuTek\RemoteScanner\Quarantine\$($env:COMPUTERNAME)_$timestamp"
New-Item -Path $caseRoot -ItemType Directory -Force | Out-Null
$remediationLog = Join-Path $caseRoot 'Remediation.log'

function Write-RemediationLog {
    param([string]$Message, [string]$Color = 'Gray')
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
    $line | Out-File -LiteralPath $remediationLog -Append -Encoding UTF8
    Write-Host $Message -ForegroundColor $Color
}

function Show-Finding {
    param($Finding, [string]$Indent = '    ')
    $location = if ($Finding.Path) { $Finding.Path } elseif ($Finding.RegistryPath) { $Finding.RegistryPath } else { $Finding.DisplayName }
    Write-Host ("{0}[{1}/{2}] {3}: {4}" -f $Indent,$Finding.Confidence,$Finding.ArtifactType,$Finding.Evidence,$location) -ForegroundColor $(if($Finding.Confidence -eq 'High'){'Red'}elseif($Finding.Confidence -eq 'Medium'){'Yellow'}else{'DarkYellow'})
    if ($Finding.OriginalFilename -and $Finding.Path -and ([IO.Path]::GetFileName($Finding.Path) -ine $Finding.OriginalFilename)) {
        Write-Host ("{0}Renamed file evidence: on disk '{1}', original name '{2}'" -f $Indent,[IO.Path]::GetFileName($Finding.Path),$Finding.OriginalFilename) -ForegroundColor Red
    }
    if ($Finding.ConnectionCount -gt 0) {
        Write-Host ("{0}Active endpoints: {1}" -f $Indent,(@($Finding.RemoteEndpoints) -join ', ')) -ForegroundColor Yellow
    }
}

function New-RemovalCandidates {
    param($Findings)
    $candidates = @()
    $index = 0
    foreach ($group in @($Findings | Where-Object {$_.ProductId -ne 'unknown'} | Group-Object ProductId | Sort-Object {$_.Group[0].ProductName})) {
        $index++
        $candidates += [pscustomobject]@{
            Index = $index
            Id = [string]$group.Name
            Name = [string]$group.Group[0].ProductName
            Category = [string]$group.Group[0].Category
            Findings = @($group.Group)
            IsUnknown = $false
        }
    }
    $unknownNumber = 0
    foreach ($finding in @($Findings | Where-Object {$_.ProductId -eq 'unknown'})) {
        $index++
        $unknownNumber++
        $candidates += [pscustomobject]@{
            Index = $index
            Id = "unknown-$unknownNumber"
            Name = "Unknown suspicious artifact: $($finding.Name)"
            Category = 'unknown'
            Findings = @($finding)
            IsUnknown = $true
        }
    }
    return @($candidates)
}

function Backup-CandidateEvidence {
    param($Candidate)
    $safeId = $Candidate.Id -replace '[^a-zA-Z0-9._-]','_'
    $path = Join-Path $caseRoot ("BeforeRemoval_{0}.json" -f $safeId)
    $Candidate | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Disable-NativeRemoteFeature {
    param($Candidate)
    switch ($Candidate.Id) {
        'quick-assist' {
            $packages = @($Candidate.Findings | Where-Object {$_.PackageFullName} | Select-Object -ExpandProperty PackageFullName -Unique)
            if (-not $packages) {
                $packages = @(Get-AppxPackage -AllUsers -Name '*QuickAssist*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PackageFullName)
            }
            foreach ($package in $packages) {
                Write-RemediationLog "Removing Quick Assist AppX package: $package" 'Yellow'
                $command = Get-Command Remove-AppxPackage -ErrorAction Stop
                if ($command.Parameters.ContainsKey('AllUsers')) {
                    Remove-AppxPackage -Package $package -AllUsers -ErrorAction Stop
                } else {
                    Remove-AppxPackage -Package $package -ErrorAction Stop
                }
            }
        }
        'windows-rdp' {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Type DWord -Value 1 -ErrorAction Stop
            if (Get-Command Disable-NetFirewallRule -ErrorAction SilentlyContinue) {
                Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayGroup -match 'Remote Desktop'} | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            }
            Write-RemediationLog 'Windows Remote Desktop was disabled.' 'Green'
        }
        'windows-remote-assistance' {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
            Set-ItemProperty $path -Name fAllowToGetHelp -Type DWord -Value 0 -ErrorAction Stop
            Set-ItemProperty $path -Name fAllowFullControl -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Write-RemediationLog 'Windows Remote Assistance was disabled.' 'Green'
        }
        'windows-winrm' {
            Stop-Service WinRM -Force -ErrorAction SilentlyContinue
            Set-Service WinRM -StartupType Disabled -ErrorAction Stop
            Write-RemediationLog 'Windows Remote Management was stopped and disabled. Existing listener configuration was retained for evidence.' 'Green'
        }
        'openssh-server' {
            Stop-Service sshd -Force -ErrorAction SilentlyContinue
            Set-Service sshd -StartupType Disabled -ErrorAction Stop
            Write-RemediationLog 'OpenSSH Server was stopped and disabled. The Windows capability was not removed.' 'Green'
        }
        default { throw "No native-feature remediation is defined for $($Candidate.Id)." }
    }
}

function Invoke-OfficialUninstall {
    param($Candidate)
    $entries = @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'InstalledProgram' -and ($_.QuietUninstallString -or $_.UninstallString)} | Sort-Object RegistryPath -Unique)
    $attempted = $false
    $allSucceeded = $true
    foreach ($entry in $entries) {
        $attempted = $true
        $command = if ($entry.QuietUninstallString) { $entry.QuietUninstallString } else { $entry.UninstallString }
        Write-RemediationLog "Running registered uninstaller for $($entry.DisplayName): $command" 'Yellow'
        try {
            $result = Invoke-CompuTekUninstallCommand -Command $command
            Write-RemediationLog ("Uninstaller exit code: {0}" -f $result.ExitCode) $(if($result.Success){'Green'}else{'Red'})
            if (-not $result.Success) { $allSucceeded = $false }
            if ($result.RebootRequired) { Write-RemediationLog 'The uninstaller reported that a reboot is required.' 'Yellow' }
        } catch {
            $allSucceeded = $false
            Write-RemediationLog "Uninstaller failed: $($_.Exception.Message)" 'Red'
        }
    }
    return [pscustomobject]@{Attempted=$attempted;Success=($attempted -and $allSucceeded)}
}

function Invoke-PortableNeutralization {
    param($Candidate)
    $confirmation = Read-Host "Type NEUTRALIZE $($Candidate.Id) to stop/disable its persistence and quarantine user-writable files"
    if ($confirmation -cne "NEUTRALIZE $($Candidate.Id)") {
        Write-RemediationLog "Neutralization skipped for $($Candidate.Id)." 'DarkGray'
        return $false
    }

    $destination = Join-Path $quarantineRoot ($Candidate.Id -replace '[^a-zA-Z0-9._-]','_')
    New-Item -Path $destination -ItemType Directory -Force | Out-Null

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Process' -and $_.ProcessId} | Sort-Object ProcessId -Unique)) {
        try {
            Stop-Process -Id $finding.ProcessId -Force -ErrorAction Stop
            Write-RemediationLog "Stopped process $($finding.Name) (PID $($finding.ProcessId))." 'Green'
        } catch { Write-RemediationLog "Could not stop PID $($finding.ProcessId): $($_.Exception.Message)" 'Red' }
    }

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Service'} | Sort-Object Name -Unique)) {
        try {
            Stop-Service -Name $finding.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $finding.Name -StartupType Disabled -ErrorAction Stop
            Write-RemediationLog "Stopped and disabled service $($finding.Name). The service definition was retained as evidence." 'Green'
        } catch { Write-RemediationLog "Could not disable service $($finding.Name): $($_.Exception.Message)" 'Red' }
    }

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'RunKey' -and $_.RegistryPath -and $_.RegistryValueName})) {
        try {
            Remove-ItemProperty -Path $finding.RegistryPath -Name $finding.RegistryValueName -ErrorAction Stop
            Write-RemediationLog "Removed autorun value $($finding.RegistryPath) -> $($finding.RegistryValueName)." 'Green'
        } catch { Write-RemediationLog "Could not remove autorun $($finding.RegistryValueName): $($_.Exception.Message)" 'Red' }
    }

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'ScheduledTask'} | Sort-Object DisplayName -Unique)) {
        try {
            $taskName = $finding.Name
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-RemediationLog "Disabled scheduled task $taskName. The task definition was retained as evidence." 'Green'
        } catch { Write-RemediationLog "Could not disable scheduled task $($finding.Name): $($_.Exception.Message)" 'Red' }
    }

    $paths = @($Candidate.Findings | Where-Object {$_.Path} | Select-Object -ExpandProperty Path -Unique)
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if (-not (Test-CompuTekUserWritablePath $path)) {
            Write-RemediationLog "Did not quarantine non-user-writable path automatically: $path" 'Yellow'
            continue
        }
        try {
            $hash = Get-CompuTekFileEvidence -Path $path -IncludeHash
            $metadataPath = Join-Path $destination (([IO.Path]::GetFileName($path)) + '.evidence.json')
            $hash | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
            $target = Join-Path $destination ([IO.Path]::GetFileName($path))
            if (Test-Path -LiteralPath $target) { $target = Join-Path $destination (([guid]::NewGuid().ToString('N')) + '_' + [IO.Path]::GetFileName($path)) }
            Move-Item -LiteralPath $path -Destination $target -Force -ErrorAction Stop
            Write-RemediationLog "Quarantined $path -> $target" 'Green'
        } catch { Write-RemediationLog "Could not quarantine ${path}: $($_.Exception.Message)" 'Red' }
    }
    return $true
}

Clear-Host
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  CompuTek Remote-Access Scanner and Remediation Tool' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "Catalog: $($catalog.catalogVersion) ($(@($catalog.products).Count) product families)" -ForegroundColor DarkGray
Write-Host "Case folder: $caseRoot" -ForegroundColor DarkGray
if ($DeepScan) { Write-Host 'Deep scan is enabled. This can take a long time.' -ForegroundColor Yellow }
Write-Host 'Scanning. No changes are made during this phase...' -ForegroundColor Cyan

try {
    $scan = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays $LookbackDays -DeepScan:$DeepScan -IncludeHashes:$IncludeHashes
} catch {
    Write-Host "Scanner could not start: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 2
}

$reportPaths = Export-CompuTekScanReport -Scan $scan -Directory $caseRoot -BaseName 'BeforeRemediation'
Write-Host "`n==================== SCAN STATUS ====================" -ForegroundColor Cyan
Write-Host "Artifacts inspected: $($scan.Stats.ArtifactsInspected)"
Write-Host "Known remote products/features: $($scan.Stats.KnownProducts + $scan.Stats.NativeFeatures)"
Write-Host "Suspicious unknown artifacts: $($scan.Stats.SuspiciousUnknown)"
if ($scan.IsComplete) {
    Write-Host 'Scan status: COMPLETE' -ForegroundColor Green
} else {
    Write-Host 'Scan status: INCOMPLETE - do not treat an empty result as clean.' -ForegroundColor Red
    foreach ($errorMessage in $scan.Errors) { Write-Host "  - $errorMessage" -ForegroundColor Yellow }
}

$candidates = New-RemovalCandidates -Findings $scan.Findings
if ($candidates.Count -eq 0) {
    Write-Host "`nNo cataloged remote-access software or suspicious remote-capable artifacts were found." -ForegroundColor $(if($scan.IsComplete){'Green'}else{'Yellow'})
    Write-Host "JSON report: $($reportPaths.Json)" -ForegroundColor DarkGray
    Write-Host "CSV report:  $($reportPaths.Csv)" -ForegroundColor DarkGray
    Read-Host 'Press Enter to close'
    exit 0
}

Write-Host "`n===================== FINDINGS ======================" -ForegroundColor Cyan
foreach ($candidate in $candidates) {
    $highest = if ($candidate.Findings.Confidence -contains 'High') {'High'} elseif ($candidate.Findings.Confidence -contains 'Medium') {'Medium'} else {'Low'}
    Write-Host ("{0,2}. [{1}] {2} ({3} evidence item(s))" -f $candidate.Index,$highest,$candidate.Name,$candidate.Findings.Count) -ForegroundColor $(if($highest -eq 'High'){'Red'}elseif($highest -eq 'Medium'){'Yellow'}else{'DarkYellow'})
    foreach ($finding in $candidate.Findings) { Show-Finding $finding }
}

Write-Host "`nReports were saved before any remediation:" -ForegroundColor Cyan
Write-Host "  $($reportPaths.Json)" -ForegroundColor DarkGray
Write-Host "  $($reportPaths.Csv)" -ForegroundColor DarkGray
Write-Host 'A finding is not proof of malicious use. Verify company-approved support tools before removal.' -ForegroundColor Yellow

if ($ScanOnly) {
    Read-Host 'Scan-only mode complete. Press Enter to close'
    exit 0
}

$selection = Read-Host "Enter finding numbers to remediate (example: 1,3), A for all, or Q to quit"
if ($selection -match '^[Qq]$') { exit 0 }
if ($selection -match '^[Aa]$') {
    $selectedIndexes = @($candidates.Index)
} else {
    $selectedIndexes = @($selection -split '[,; ]+' | Where-Object {$_ -match '^\d+$'} | ForEach-Object {[int]$_} | Sort-Object -Unique)
}
$selected = @($candidates | Where-Object {$selectedIndexes -contains $_.Index})
if (-not $selected) {
    Write-Host 'No valid selections were provided. Nothing was changed.' -ForegroundColor Yellow
    Read-Host 'Press Enter to close'
    exit 1
}

foreach ($candidate in $selected) {
    Write-Host "`n---------------- $($candidate.Name) ----------------" -ForegroundColor Magenta
    foreach ($finding in $candidate.Findings) { Show-Finding $finding }
    $confirmation = Read-Host "Type REMOVE $($candidate.Id) to authorize remediation of this item"
    if ($confirmation -cne "REMOVE $($candidate.Id)") {
        Write-RemediationLog "Removal skipped for $($candidate.Id)." 'DarkGray'
        continue
    }

    $backup = Backup-CandidateEvidence $candidate
    Write-RemediationLog "Evidence backup created: $backup" 'Cyan'
    try {
        if ($candidate.Category -eq 'native-feature') {
            Disable-NativeRemoteFeature $candidate
            continue
        }

        $uninstallResult = Invoke-OfficialUninstall $candidate
        if (-not $uninstallResult.Attempted) {
            Write-RemediationLog 'No registered vendor uninstaller was found.' 'Yellow'
            [void](Invoke-PortableNeutralization $candidate)
        } elseif (-not $uninstallResult.Success) {
            Write-RemediationLog 'The registered uninstaller did not report success. Optional neutralization is available.' 'Yellow'
            [void](Invoke-PortableNeutralization $candidate)
        }
    } catch {
        Write-RemediationLog "Remediation failed for $($candidate.Id): $($_.Exception.Message)" 'Red'
    }
}

Write-Host "`nRe-scanning to verify the result..." -ForegroundColor Cyan
try {
    $verification = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays $LookbackDays -DeepScan:$DeepScan -IncludeHashes:$IncludeHashes
    $verificationPaths = Export-CompuTekScanReport -Scan $verification -Directory $caseRoot -BaseName 'AfterRemediation'
    $remainingSelected = @($verification.Findings | Where-Object {$selected.Id -contains $_.ProductId -or ($_.ProductId -eq 'unknown' -and $selected.IsUnknown)})
    if ($remainingSelected.Count -gt 0) {
        Write-Host "Verification found $($remainingSelected.Count) remaining evidence item(s). Review the after-remediation report; do not assume removal is complete." -ForegroundColor Red
    } else {
        Write-Host 'No selected product identifiers remained in the verification scan.' -ForegroundColor Green
    }
    if (-not $verification.IsComplete) { Write-Host 'Verification scan was incomplete. Review its collector errors.' -ForegroundColor Red }
    Write-Host "After-remediation JSON: $($verificationPaths.Json)" -ForegroundColor DarkGray
    Write-Host "After-remediation CSV:  $($verificationPaths.Csv)" -ForegroundColor DarkGray
} catch {
    Write-RemediationLog "Verification scan failed: $($_.Exception.Message)" 'Red'
}

Write-Host "Remediation log: $remediationLog" -ForegroundColor DarkGray
Write-Host 'Reboot if requested by an uninstaller, then run this scanner again.' -ForegroundColor Yellow
Read-Host 'Press Enter to close'
exit 0
