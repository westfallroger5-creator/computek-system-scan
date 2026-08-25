<#
 RemoteAccessScanAndRemove.ps1

 Evidence-first remote-access scanner and interactive remediation tool.
 - Uses a shared, updateable JSON catalog instead of a hard-coded product list.
 - Inspects all loaded-user uninstall records, AppX packages, services, processes,
   autoruns, scheduled tasks, startup folders, active connections, and targeted files.
 - Inspects file metadata and Authenticode status so a renamed executable can still match.
 - Flags unknown services/persistence/processes in user-writable locations.
 - Never removes anything during scanning. A technician must classify every detected
   installation as KEEP or REMOVE before the remediation phase can start.
 - Separates different installation locations for the same product so an approved
   company agent can be kept while a hidden copy of that product is removed.
 - Preserves logs, configuration, registry records, and hashes before removal.
 - Uses the vendor uninstaller first, then removes residual processes, services,
   tasks, autoruns, AppX packages, registration records, and executable artifacts.
 - Quarantines residual files instead of permanently erasing the evidence and
   performs a verification scan that is tied to each approved removal scope.
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

function Protect-CompuTekEvidenceDirectory {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
            $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,$propagation,$allow)
            [void]$acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        Write-Host "WARNING: Could not restrict evidence folder permissions: $Path ($($_.Exception.Message))" -ForegroundColor Red
        return $false
    }
}

$caseFolderProtected = Protect-CompuTekEvidenceDirectory -Path $caseRoot

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

function Get-FindingScopePath {
    param($Finding)

    if ($Finding.Category -eq 'native-feature') { return $null }
    if ($Finding.ArtifactType -eq 'AppxPackage') { return [string]$Finding.Path }

    $path = if ($Finding.InstallLocation) { [string]$Finding.InstallLocation } else { [string]$Finding.Path }
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"')).TrimEnd('\')

    if (-not $Finding.InstallLocation -or $Finding.ArtifactType -ne 'InstalledProgram') {
        try {
            if ((Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue) -or [IO.Path]::GetExtension($path)) {
                $parent = Split-Path -Parent $path
                if ($parent) { $path = $parent }
            }
        } catch {}
    }

    try { return [IO.Path]::GetFullPath($path).TrimEnd('\') } catch { return $path }
}

function New-RemovalCandidates {
    param($Findings)

    $installAnchors = @{}
    foreach ($finding in @($Findings | Where-Object {$_.ArtifactType -eq 'InstalledProgram' -and $_.ProductId -ne 'unknown'})) {
        $anchor = Get-FindingScopePath $finding
        if (-not $anchor) { continue }
        if (-not $installAnchors.ContainsKey($finding.ProductId)) { $installAnchors[$finding.ProductId] = New-Object System.Collections.Generic.List[string] }
        if (-not $installAnchors[$finding.ProductId].Contains($anchor)) { $installAnchors[$finding.ProductId].Add($anchor) }
    }

    $scopeGroups = @{}
    foreach ($finding in @($Findings)) {
        $scopePath = Get-FindingScopePath $finding
        if ($scopePath -and $installAnchors.ContainsKey($finding.ProductId)) {
            $scopeLower = $scopePath.TrimEnd('\').ToLowerInvariant()
            $matchingAnchor = @($installAnchors[$finding.ProductId] | Where-Object {
                $anchorLower = ([string]$_).TrimEnd('\').ToLowerInvariant()
                $scopeLower -eq $anchorLower -or $scopeLower.StartsWith($anchorLower + '\')
            } | Sort-Object Length -Descending | Select-Object -First 1)
            if ($matchingAnchor) { $scopePath = [string]$matchingAnchor[0] }
        }
        $scopeKey = if ($finding.Category -eq 'native-feature') {
            "native:$($finding.ProductId)"
        } elseif ($finding.ArtifactType -eq 'AppxPackage' -and $finding.PackageFullName) {
            "appx:$($finding.PackageFullName)"
        } elseif ($scopePath) {
            "path:$($scopePath.ToLowerInvariant())"
        } else {
            "artifact:$($finding.ArtifactType):$($finding.Name):$($finding.RegistryPath)".ToLowerInvariant()
        }
        $key = "$($finding.ProductId)|$scopeKey"
        if (-not $scopeGroups.ContainsKey($key)) {
            $scopeGroups[$key] = [ordered]@{
                ProductId = [string]$finding.ProductId
                ProductName = [string]$finding.ProductName
                Category = [string]$finding.Category
                ScopeKey = $scopeKey
                ScopePath = $scopePath
                Findings = New-Object System.Collections.Generic.List[object]
            }
        }
        $scopeGroups[$key].Findings.Add($finding)
    }

    $candidates = @()
    $productCounts = @{}
    $index = 0
    foreach ($entry in @($scopeGroups.Values | Sort-Object ProductName,ScopeKey)) {
        $index++
        $baseId = if ($entry.ProductId -eq 'unknown') { 'unknown' } else { $entry.ProductId }
        if (-not $productCounts.ContainsKey($baseId)) { $productCounts[$baseId] = 0 }
        $productCounts[$baseId]++
        $id = '{0}-{1}' -f $baseId,$productCounts[$baseId]
        $name = if ($entry.ProductId -eq 'unknown') {
            "Unknown suspicious artifact: $($entry.Findings[0].Name)"
        } else {
            $entry.ProductName
        }
        $candidates += [pscustomobject]@{
            Index = $index
            Id = $id
            ProductId = $entry.ProductId
            Name = [string]$name
            Category = $entry.Category
            ScopeKey = $entry.ScopeKey
            ScopePath = $entry.ScopePath
            Findings = @($entry.Findings | ForEach-Object {$_})
            IsUnknown = ($entry.ProductId -eq 'unknown')
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

function ConvertTo-NativeRegistryPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $native = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::','' -replace '^Registry::',''
    $native = $native -replace '^HKLM:\\','HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\','HKEY_CURRENT_USER\' -replace '^HKU:\\','HKEY_USERS\'
    if ($native -match '^HKEY_(LOCAL_MACHINE|CURRENT_USER|USERS)\\') { return $native }
    return $null
}

function Export-RegistryEvidence {
    param([string]$RegistryPath, [string]$Destination)
    $native = ConvertTo-NativeRegistryPath $RegistryPath
    if (-not $native) { return $false }
    try {
        & reg.exe export $native $Destination /y 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Destination -PathType Leaf))
    } catch { return $false }
}

function Preserve-CandidateOperationalData {
    param($Candidate)

    $safeId = $Candidate.Id -replace '[^a-zA-Z0-9._-]','_'
    $destination = Join-Path $caseRoot "PreservedRemoteToolData\$safeId"
    New-Item -Path $destination -ItemType Directory -Force | Out-Null
    $Candidate | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'CandidateEvidence.json') -Encoding UTF8

    $registryPaths = New-Object System.Collections.Generic.List[string]
    foreach ($finding in @($Candidate.Findings)) {
        if ($finding.RegistryPath -and -not $registryPaths.Contains([string]$finding.RegistryPath)) {
            $registryPaths.Add([string]$finding.RegistryPath)
        }
        if ($finding.ArtifactType -eq 'Service' -and $finding.Name) {
            $servicePath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($finding.Name)"
            if (-not $registryPaths.Contains($servicePath)) { $registryPaths.Add($servicePath) }
        }
    }
    $registryIndex = 0
    foreach ($registryPath in $registryPaths) {
        $registryIndex++
        $regFile = Join-Path $destination ('Registry_{0:000}.reg' -f $registryIndex)
        if (Export-RegistryEvidence -RegistryPath $registryPath -Destination $regFile) {
            Write-RemediationLog "Preserved registry evidence: $registryPath" 'DarkGray'
        } else {
            Write-RemediationLog "Registry evidence could not be exported: $registryPath" 'Yellow'
        }
    }

    $sourceDirectories = New-Object System.Collections.Generic.List[string]
    foreach ($finding in @($Candidate.Findings)) {
        foreach ($candidatePath in @($finding.InstallLocation,$finding.Path)) {
            if ([string]::IsNullOrWhiteSpace([string]$candidatePath)) { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables(([string]$candidatePath).Trim('"')).TrimEnd('\')
            $directory = if (Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue) { $expanded } else { Split-Path -Parent $expanded }
            $isBroadUserFolder = ([string]$directory).ToLowerInvariant() -match '\\users\\[^\\]+\\(desktop|downloads)$'
            if ($directory -and -not $isBroadUserFolder -and -not (Test-ProtectedRemediationPath -Path $directory -Directory) -and (Test-Path -LiteralPath $directory -PathType Container -ErrorAction SilentlyContinue) -and -not $sourceDirectories.Contains($directory)) {
                $sourceDirectories.Add($directory)
            }
        }
    }
    if ($Candidate.ProductId -eq 'openssh-server') {
        $sshData = Join-Path $env:ProgramData 'ssh'
        if (Test-Path -LiteralPath $sshData -PathType Container -ErrorAction SilentlyContinue) { $sourceDirectories.Add($sshData) }
        foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
            $sshProfile = Join-Path $profile.FullName '.ssh'
            if (Test-Path -LiteralPath $sshProfile -PathType Container -ErrorAction SilentlyContinue) { $sourceDirectories.Add($sshProfile) }
        }
    }

    $manifest = @()
    $copiedCount = 0
    [int64]$copiedBytes = 0
    $namePattern = '(?i)(screenconnect|connectwise|remote|support|session|audit|history|server|client|agent|ssh|authorized_keys)'
    foreach ($directory in $sourceDirectories) {
        if ($copiedCount -ge 500 -or $copiedBytes -ge 524288000) { break }
        $enumerationErrors = @()
        foreach ($file in Get-ChildItem -LiteralPath $directory -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable +enumerationErrors) {
            if ($copiedCount -ge 500 -or $copiedBytes -ge 524288000) { break }
            if ($file.Length -gt 52428800) { continue }
            if ($file.Extension -notmatch '^\.(log|config|ini|yaml|yml|xml|json|txt|db|sqlite|sqlite3)$' -and $file.Name -notmatch $namePattern) { continue }
            try {
                $copyName = '{0:0000}_{1}' -f ($copiedCount + 1),($file.Name -replace '[^a-zA-Z0-9._-]','_')
                $copyPath = Join-Path $destination $copyName
                Copy-Item -LiteralPath $file.FullName -Destination $copyPath -Force -ErrorAction Stop
                $hash = $null
                try { $hash = (Get-FileHash -LiteralPath $copyPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
                $manifest += [pscustomobject]@{
                    SourcePath = $file.FullName
                    EvidenceCopy = $copyPath
                    Length = $file.Length
                    LastWriteTimeUtc = $file.LastWriteTimeUtc
                    SHA256 = $hash
                }
                $copiedCount++
                $copiedBytes += $file.Length
            } catch {
                Write-RemediationLog "Could not preserve operational file $($file.FullName): $($_.Exception.Message)" 'Yellow'
            }
        }
    }
    $manifest | Export-Csv -LiteralPath (Join-Path $destination 'PreservedFilesManifest.csv') -NoTypeInformation -Encoding UTF8
    Write-RemediationLog "Preserved $copiedCount remote-tool log/configuration file(s) for $($Candidate.Id)." 'Cyan'
    return $destination
}

function Remove-NativeRemoteFeature {
    param($Candidate)
    switch ($Candidate.ProductId) {
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
            if (Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
                foreach ($provisioned in @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match 'QuickAssist'})) {
                    Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction Stop | Out-Null
                    Write-RemediationLog "Removed provisioned Quick Assist package: $($provisioned.PackageName)" 'Green'
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
            if (Get-Command Disable-NetFirewallRule -ErrorAction SilentlyContinue) {
                Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayGroup -match 'Remote Assistance'} | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            }
            Write-RemediationLog 'Windows Remote Assistance was disabled.' 'Green'
        }
        'windows-winrm' {
            Stop-Service WinRM -Force -ErrorAction SilentlyContinue
            Set-Service WinRM -StartupType Disabled -ErrorAction Stop
            if (Test-Path 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue) {
                Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Get-Command Disable-NetFirewallRule -ErrorAction SilentlyContinue) {
                Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayGroup -match 'Windows Remote Management'} | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            }
            Write-RemediationLog 'Windows Remote Management was stopped and disabled; listeners were removed.' 'Green'
        }
        'openssh-server' {
            Stop-Service sshd -Force -ErrorAction SilentlyContinue
            Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
            if (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue) {
                foreach ($capability in @(Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed'})) {
                    Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
                    Write-RemediationLog "Removed Windows capability $($capability.Name)." 'Green'
                }
            }
            $sshData = Join-Path $env:ProgramData 'ssh'
            if (Test-Path -LiteralPath $sshData -ErrorAction SilentlyContinue) {
                [void](Move-ToCandidateQuarantine -Candidate $Candidate -Path $sshData -Kind 'OpenSSH server configuration')
            }
            foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
                foreach ($keyName in @('authorized_keys','administrators_authorized_keys')) {
                    $keyPath = Join-Path (Join-Path $profile.FullName '.ssh') $keyName
                    if (Test-Path -LiteralPath $keyPath -PathType Leaf -ErrorAction SilentlyContinue) {
                        [void](Move-ToCandidateQuarantine -Candidate $Candidate -Path $keyPath -Kind 'OpenSSH authorization file')
                    }
                }
            }
        }
        default { throw "No native-feature remediation is defined for $($Candidate.ProductId)." }
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

function Remove-CandidateAppxPackages {
    param($Candidate)
    if (-not (Get-Command Remove-AppxPackage -ErrorAction SilentlyContinue)) { return }

    foreach ($package in @($Candidate.Findings | Where-Object {$_.PackageFullName} | Select-Object -ExpandProperty PackageFullName -Unique)) {
        try {
            $command = Get-Command Remove-AppxPackage -ErrorAction Stop
            if ($command.Parameters.ContainsKey('AllUsers')) {
                Remove-AppxPackage -Package $package -AllUsers -ErrorAction Stop
            } else {
                Remove-AppxPackage -Package $package -ErrorAction Stop
            }
            Write-RemediationLog "Removed AppX package: $package" 'Green'
        } catch { Write-RemediationLog "Could not remove AppX package ${package}: $($_.Exception.Message)" 'Red' }
    }

    if (Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        $packageNames = @($Candidate.Findings | Where-Object {$_.PackageName} | Select-Object -ExpandProperty PackageName -Unique)
        foreach ($package in @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$packageNames -contains $_.DisplayName})) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
                Write-RemediationLog "Removed provisioned AppX package: $($package.PackageName)" 'Green'
            } catch { Write-RemediationLog "Could not remove provisioned package $($package.PackageName): $($_.Exception.Message)" 'Red' }
        }
    }
}

function Stop-CandidateProcesses {
    param($Candidate)
    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Process' -and $_.ProcessId} | Sort-Object ProcessId -Unique)) {
        try {
            $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($finding.ProcessId)" -ErrorAction SilentlyContinue
            if (-not $current) { continue }
            $currentPath = if ($current.ExecutablePath) { $current.ExecutablePath } else { Get-CompuTekExecutablePath $current.CommandLine }
            if ($finding.Path -and $currentPath -and $currentPath -ine $finding.Path) {
                Write-RemediationLog "Skipped PID $($finding.ProcessId) because the process path changed after the scan." 'Yellow'
                continue
            }
            Stop-Process -Id $finding.ProcessId -Force -ErrorAction Stop
            Write-RemediationLog "Stopped process $($finding.Name) (PID $($finding.ProcessId))." 'Green'
        } catch { Write-RemediationLog "Could not stop PID $($finding.ProcessId): $($_.Exception.Message)" 'Red' }
    }
}

function Remove-CandidateServices {
    param($Candidate)
    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Service' -and $_.Name} | Sort-Object Name -Unique)) {
        try {
            $service = Get-Service -Name $finding.Name -ErrorAction SilentlyContinue
            if (-not $service) { continue }
            Stop-Service -Name $finding.Name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $finding.Name 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe returned exit code $LASTEXITCODE" }
            Write-RemediationLog "Removed service definition $($finding.Name)." 'Green'
        } catch { Write-RemediationLog "Could not remove service $($finding.Name): $($_.Exception.Message)" 'Red' }
    }
}

function Remove-CandidatePersistence {
    param($Candidate)

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'RunKey' -and $_.RegistryPath -and $_.RegistryValueName})) {
        try {
            if (Get-ItemProperty -Path $finding.RegistryPath -Name $finding.RegistryValueName -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $finding.RegistryPath -Name $finding.RegistryValueName -ErrorAction Stop
                Write-RemediationLog "Removed autorun value $($finding.RegistryPath) -> $($finding.RegistryValueName)." 'Green'
            }
        } catch { Write-RemediationLog "Could not remove autorun $($finding.RegistryValueName): $($_.Exception.Message)" 'Red' }
    }

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'ScheduledTask'} | Sort-Object DisplayName -Unique)) {
        try {
            if (-not (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue)) { throw 'Scheduled task cmdlets are unavailable' }
            $taskPath = if ($finding.TaskPath) { $finding.TaskPath } else { '\' }
            $task = Get-ScheduledTask -TaskName $finding.Name -TaskPath $taskPath -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $finding.Name -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
                Write-RemediationLog "Removed scheduled task $taskPath$($finding.Name)." 'Green'
            }
        } catch { Write-RemediationLog "Could not remove scheduled task $($finding.DisplayName): $($_.Exception.Message)" 'Red' }
    }
}

function Test-ProtectedRemediationPath {
    param([string]$Path, [switch]$Directory)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    try { $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path.Trim('"'))).TrimEnd('\') } catch { return $true }
    $lower = $full.ToLowerInvariant()
    $protectedExact = @(
        $env:SystemDrive,
        $env:SystemRoot,
        (Join-Path $env:SystemRoot 'System32'),
        (Join-Path $env:SystemRoot 'SysWOW64'),
        $env:ProgramData,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        (Join-Path $env:SystemDrive 'Users')
    ) | Where-Object {$_} | ForEach-Object {([string]$_).TrimEnd('\').ToLowerInvariant()}
    if ($protectedExact -contains $lower) { return $true }
    if ($lower.StartsWith(([string]$caseRoot).ToLowerInvariant()) -or $lower.StartsWith(([string]$quarantineRoot).ToLowerInvariant())) { return $true }
    if ($lower.StartsWith(([string]$env:SystemRoot).TrimEnd('\').ToLowerInvariant() + '\') -and -not $lower.StartsWith((Join-Path $env:SystemRoot 'Temp').ToLowerInvariant() + '\')) { return $true }
    if ($Directory -and $lower -match '\\users\\[^\\]+\\appdata\\(local|locallow|roaming)$') { return $true }
    return $false
}

function Move-ToCandidateQuarantine {
    param($Candidate, [string]$Path, [string]$Kind)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    $isDirectory = Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue
    if (Test-ProtectedRemediationPath -Path $Path -Directory:$isDirectory) {
        Write-RemediationLog "Protected path was not moved automatically: $Path" 'Red'
        return $false
    }
    if ($Candidate.IsUnknown -and ($isDirectory -or -not (Test-CompuTekUserWritablePath $Path))) {
        Write-RemediationLog "Unknown artifact outside a user-writable file path was not moved automatically: $Path" 'Red'
        return $false
    }

    $destination = Join-Path $quarantineRoot ($Candidate.Id -replace '[^a-zA-Z0-9._-]','_')
    New-Item -Path $destination -ItemType Directory -Force | Out-Null
    if (-not (Protect-CompuTekEvidenceDirectory -Path $destination)) {
        Write-RemediationLog "Quarantine folder permissions could not be secured. The file was left in place: $Path" 'Red'
        return $false
    }
    try {
        $metadata = if ($isDirectory) {
            [pscustomobject]@{Path=$Path;Type='Directory';CapturedAtUtc=(Get-Date).ToUniversalTime()}
        } else {
            Get-CompuTekFileEvidence -Path $Path -IncludeHash
        }
        $metadataPath = Join-Path $destination (([guid]::NewGuid().ToString('N')) + '.evidence.json')
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
        $leaf = Split-Path -Leaf $Path
        if (-not $leaf) { $leaf = 'artifact' }
        $target = Join-Path $destination $leaf
        if (Test-Path -LiteralPath $target) { $target = Join-Path $destination (([guid]::NewGuid().ToString('N')) + '_' + $leaf) }
        Move-Item -LiteralPath $Path -Destination $target -Force -ErrorAction Stop
        Write-RemediationLog "Quarantined $Kind $Path -> $target" 'Green'
        return $true
    } catch {
        Write-RemediationLog "Could not quarantine ${Path}: $($_.Exception.Message)" 'Red'
        return $false
    }
}

function Remove-CandidateResidualFiles {
    param($Candidate)
    $directories = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[string]

    foreach ($finding in @($Candidate.Findings)) {
        if ($finding.ArtifactType -eq 'InstalledProgram' -and $finding.InstallLocation -and (Test-Path -LiteralPath $finding.InstallLocation -PathType Container -ErrorAction SilentlyContinue)) {
            if (-not $directories.Contains([string]$finding.InstallLocation)) { $directories.Add([string]$finding.InstallLocation) }
        }
        foreach ($path in @($finding.SourcePath,$finding.Path)) {
            if ([string]::IsNullOrWhiteSpace([string]$path)) { continue }
            if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue) {
                if (-not $files.Contains([string]$path)) { $files.Add([string]$path) }
            } elseif ($finding.ArtifactType -eq 'InstalledProgram' -and (Test-Path -LiteralPath $path -PathType Container -ErrorAction SilentlyContinue)) {
                if (-not $directories.Contains([string]$path)) { $directories.Add([string]$path) }
            }
        }
    }

    foreach ($directory in @($directories | Sort-Object Length -Descending)) {
        [void](Move-ToCandidateQuarantine -Candidate $Candidate -Path $directory -Kind 'installation directory')
    }
    foreach ($file in @($files | Sort-Object -Unique)) {
        [void](Move-ToCandidateQuarantine -Candidate $Candidate -Path $file -Kind 'residual file')
    }
}

function Remove-CandidateRegistration {
    param($Candidate)
    foreach ($registryPath in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'InstalledProgram' -and $_.RegistryPath} | Select-Object -ExpandProperty RegistryPath -Unique)) {
        try {
            if (Test-Path -Path $registryPath -ErrorAction SilentlyContinue) {
                Remove-Item -Path $registryPath -Recurse -Force -ErrorAction Stop
                Write-RemediationLog "Removed leftover uninstall registration: $registryPath" 'Green'
            }
        } catch { Write-RemediationLog "Could not remove leftover registration ${registryPath}: $($_.Exception.Message)" 'Red' }
    }
}

function Invoke-FullCandidateRemoval {
    param($Candidate)

    $backup = Backup-CandidateEvidence $Candidate
    Write-RemediationLog "Evidence backup created: $backup" 'Cyan'
    $preserved = Preserve-CandidateOperationalData $Candidate
    Write-RemediationLog "Operational logs/configuration preserved under: $preserved" 'Cyan'

    if ($Candidate.Category -eq 'native-feature') {
        Remove-NativeRemoteFeature $Candidate
        return
    }

    $uninstallResult = Invoke-OfficialUninstall $Candidate
    if (-not $uninstallResult.Attempted) {
        Write-RemediationLog 'No registered vendor uninstaller was found; continuing with exact residual removal.' 'Yellow'
    } elseif (-not $uninstallResult.Success) {
        Write-RemediationLog 'The registered uninstaller did not report success; continuing with exact residual removal.' 'Yellow'
    }

    Stop-CandidateProcesses $Candidate
    Remove-CandidateServices $Candidate
    Remove-CandidatePersistence $Candidate
    Remove-CandidateAppxPackages $Candidate
    Remove-CandidateResidualFiles $Candidate
    Remove-CandidateRegistration $Candidate
}

function Test-FindingBelongsToCandidate {
    param($Finding, $Candidate)
    if ($Finding.ProductId -ne $Candidate.ProductId) { return $false }
    if ($Candidate.Category -eq 'native-feature') { return $true }
    if ($Candidate.ScopeKey -like 'appx:*') { return ("appx:$($Finding.PackageFullName)" -ieq $Candidate.ScopeKey) }

    $scopePath = Get-FindingScopePath $Finding
    if ($scopePath -and $Candidate.ScopePath -and $scopePath -ieq $Candidate.ScopePath) { return $true }
    foreach ($original in @($Candidate.Findings)) {
        if ($original.ArtifactType -eq $Finding.ArtifactType -and $original.Name -and $original.Name -ieq $Finding.Name) { return $true }
    }
    return $false
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
    Write-Host ("    Review ID: {0} | Installation scope: {1}" -f $candidate.Id,$(if($candidate.ScopePath){$candidate.ScopePath}else{$candidate.ScopeKey})) -ForegroundColor Cyan
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

if (-not $caseFolderProtected) {
    Write-Host 'Removal is blocked because the evidence folder could not be restricted to SYSTEM and Administrators.' -ForegroundColor Red
    Write-Host 'Nothing was changed. Correct the folder-permission problem and run the scanner again.' -ForegroundColor Yellow
    Read-Host 'Press Enter to close'
    exit 3
}

$technicianName = ''
while ([string]::IsNullOrWhiteSpace($technicianName)) {
    $technicianName = Read-Host 'Technician name or initials (required; Q quits without changes)'
    if ($technicianName -match '^[Qq]$') { exit 0 }
}
$caseReference = Read-Host 'Ticket/case reference (optional)'
$decisionPath = Join-Path $caseRoot 'TechnicianDecisions.json'
$decisions = @()
$decisionById = @{}

Write-Host "`nEvery installation must be verified. KEEP and REMOVE decisions are recorded before any changes occur." -ForegroundColor Cyan
foreach ($candidate in $candidates) {
    Write-Host "`n---------------- $($candidate.Name) ----------------" -ForegroundColor Magenta
    Write-Host ("Review ID: {0}`nInstallation scope: {1}" -f $candidate.Id,$(if($candidate.ScopePath){$candidate.ScopePath}else{$candidate.ScopeKey})) -ForegroundColor Cyan
    foreach ($finding in $candidate.Findings) { Show-Finding $finding }

    $decision = $null
    while (-not $decision) {
        $answer = Read-Host "Type KEEP $($candidate.Id), REMOVE $($candidate.Id), or Q to abort"
        if ($answer -match '^[Qq]$') {
            Write-Host 'Technician review aborted. Nothing was changed.' -ForegroundColor Yellow
            exit 0
        }
        if ($answer -ieq "KEEP $($candidate.Id)") { $decision = 'KeepApproved' }
        elseif ($answer -ieq "REMOVE $($candidate.Id)") { $decision = 'Remove' }
        else { Write-Host 'The entry did not match this review ID. Try again.' -ForegroundColor Yellow }
    }

    $record = [pscustomobject][ordered]@{
        CandidateId = $candidate.Id
        ProductId = $candidate.ProductId
        ProductName = $candidate.Name
        InstallationScope = if ($candidate.ScopePath) { $candidate.ScopePath } else { $candidate.ScopeKey }
        Decision = $decision
        Technician = $technicianName
        WindowsAccount = "$env:USERDOMAIN\$env:USERNAME"
        TicketOrCase = $caseReference
        DecidedAtUtc = (Get-Date).ToUniversalTime()
        RemovalOutcome = if ($decision -eq 'KeepApproved') { 'KeptByTechnician' } else { 'AwaitingFinalConfirmation' }
    }
    $decisions += $record
    $decisionById[$candidate.Id] = $decision
}

$decisionDocument = [pscustomobject][ordered]@{
    SchemaVersion = 1
    ComputerName = $env:COMPUTERNAME
    CaseFolder = $caseRoot
    Technician = $technicianName
    WindowsAccount = "$env:USERDOMAIN\$env:USERNAME"
    TicketOrCase = $caseReference
    RecordedAtUtc = (Get-Date).ToUniversalTime()
    Decisions = $decisions
}
$decisionDocument | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $decisionPath -Encoding UTF8
Write-Host "`n================ TECHNICIAN DECISIONS ================" -ForegroundColor Cyan
foreach ($record in $decisions) {
    Write-Host ("{0,-16} {1,-14} {2}" -f $record.Decision,$record.CandidateId,$record.InstallationScope) -ForegroundColor $(if($record.Decision -eq 'Remove'){'Yellow'}else{'Green'})
}
Write-Host "Decision record: $decisionPath" -ForegroundColor DarkGray

$selected = @($candidates | Where-Object {$decisionById[$_.Id] -eq 'Remove'})
if ($selected.Count -eq 0) {
    Write-Host 'All detected installations were approved to keep. Nothing was changed.' -ForegroundColor Green
    Read-Host 'Press Enter to close'
    exit 0
}

Write-Host "`n$($selected.Count) installation(s) are authorized for full removal." -ForegroundColor Yellow
Write-Host 'Logs and configuration will be preserved first. Then uninstallers, services, tasks, autoruns, packages, registrations, and residual files will be removed or quarantined.' -ForegroundColor Yellow
$finalConfirmation = Read-Host 'Type APPLY REMOVALS to begin, or anything else to quit without changes'
if ($finalConfirmation -cne 'APPLY REMOVALS') {
    Write-Host 'Final confirmation was not provided. Nothing was changed.' -ForegroundColor Yellow
    exit 0
}

foreach ($candidate in $selected) {
    Write-Host "`nRemoving $($candidate.Name) from scope $($candidate.ScopePath)..." -ForegroundColor Magenta
    $decisionRecord = @($decisions | Where-Object {$_.CandidateId -eq $candidate.Id})[0]
    $decisionRecord.RemovalOutcome = 'RemovalAttempted'
    try {
        Invoke-FullCandidateRemoval $candidate
    } catch {
        $decisionRecord.RemovalOutcome = 'RemovalError'
        Write-RemediationLog "Remediation failed for $($candidate.Id): $($_.Exception.Message)" 'Red'
    }
}

Write-Host "`nRe-scanning to verify the result..." -ForegroundColor Cyan
try {
    $verification = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays $LookbackDays -DeepScan:$DeepScan -IncludeHashes:$IncludeHashes
    $verificationPaths = Export-CompuTekScanReport -Scan $verification -Directory $caseRoot -BaseName 'AfterRemediation'
    $verificationSummary = @()
    foreach ($candidate in $selected) {
        $remaining = @($verification.Findings | Where-Object {Test-FindingBelongsToCandidate -Finding $_ -Candidate $candidate})
        $status = if (-not $verification.IsComplete) {
            'NotVerified-ScanIncomplete'
        } elseif ($remaining.Count -gt 0) {
            'RemovalIncomplete'
        } else {
            'RemovalVerified'
        }
        $decisionRecord = @($decisions | Where-Object {$_.CandidateId -eq $candidate.Id})[0]
        $decisionRecord.RemovalOutcome = $status
        $verificationSummary += [pscustomobject]@{
            CandidateId = $candidate.Id
            ProductName = $candidate.Name
            InstallationScope = if ($candidate.ScopePath) { $candidate.ScopePath } else { $candidate.ScopeKey }
            Status = $status
            RemainingFindings = $remaining.Count
        }
        Write-Host ("{0}: {1} ({2} remaining finding(s))" -f $candidate.Id,$status,$remaining.Count) -ForegroundColor $(if($status -eq 'RemovalVerified'){'Green'}else{'Red'})
    }
    $verificationSummary | Export-Csv -LiteralPath (Join-Path $caseRoot 'RemovalVerification.csv') -NoTypeInformation -Encoding UTF8
    $verificationSummary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $caseRoot 'RemovalVerification.json') -Encoding UTF8
    if (-not $verification.IsComplete) { Write-Host 'Verification scan was incomplete. No removal is marked verified; review its collector errors.' -ForegroundColor Red }
    Write-Host "After-remediation JSON: $($verificationPaths.Json)" -ForegroundColor DarkGray
    Write-Host "After-remediation CSV:  $($verificationPaths.Csv)" -ForegroundColor DarkGray
} catch {
    foreach ($record in @($decisions | Where-Object {$_.Decision -eq 'Remove'})) { $record.RemovalOutcome = 'NotVerified-ScanFailed' }
    Write-RemediationLog "Verification scan failed: $($_.Exception.Message)" 'Red'
}

$decisionDocument.RecordedAtUtc = (Get-Date).ToUniversalTime()
$decisionDocument | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $decisionPath -Encoding UTF8

Write-Host "Remediation log: $remediationLog" -ForegroundColor DarkGray
Write-Host 'Reboot if requested by an uninstaller, then run this scanner again.' -ForegroundColor Yellow
Read-Host 'Press Enter to close'
exit 0
