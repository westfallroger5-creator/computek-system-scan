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
    [ValidateRange(1,365)][int]$LookbackDays = 7,
    [switch]$IncludeHashes
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-CompuTekInput {
    param([Parameter(Mandatory)][string]$Prompt)
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine("__COMPUTEK_PROMPT__:$Prompt")
        [Console]::Out.Flush()
        return [Console]::In.ReadLine()
    }
    return Read-Host $Prompt
}

function Complete-CompuTekRun {
    param(
        [string]$Message = 'Complete',
        [ConsoleColor]$Color = [ConsoleColor]::Green
    )
    Write-Host $Message -ForegroundColor $Color
    if ($env:COMPUTEK_SCANNER_APP -ne '1') { [void](Read-Host 'Press Enter to close') }
}

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $argumentList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-LookbackDays',[string]$LookbackDays)
    if ($DeepScan) { $argumentList += '-DeepScan' }
    if ($IncludeHashes) { $argumentList += '-IncludeHashes' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentList -Verb RunAs
    exit
}

$modulePath = Join-Path $PSScriptRoot 'CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $PSScriptRoot 'RemoteAccessSignatures.json'
Import-Module $modulePath -Force -ErrorAction Stop
$catalog = Get-CompuTekCatalog -Path $catalogPath

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$portableRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) { $env:COMPUTEK_SCANNER_PORTABLE_ROOT } else { $PSScriptRoot }
$portableDataRoot = Join-Path $portableRoot ("CompuTekData\{0}" -f $env:COMPUTERNAME)
$caseRoot = Join-Path $portableDataRoot "RemoteScanner\Cases\$timestamp"
$quarantineRoot = Join-Path $portableDataRoot "RemoteScanner\Quarantine\$timestamp"
New-Item -Path $caseRoot -ItemType Directory -Force | Out-Null
$remediationLog = Join-Path $caseRoot 'Remediation.log'
$script:EvidenceStorageSecurity = 'PortableFolder-NormalPermissions'

function Initialize-CompuTekEvidenceDirectory {
    param([Parameter(Mandatory)][string]$Path)

    # Evidence stays under the service USB/application folder with the drive's normal
    # inherited permissions. Older releases replaced the folder ACL with SYSTEM and
    # Administrators only, which made routine cleanup require elevation.
    try {
        $driveLetter = (Get-Item -LiteralPath $Path -ErrorAction Stop).PSDrive.Name
        $fileSystem = (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue).FileSystem
        if ($fileSystem) { $script:EvidenceStorageSecurity = "PortableMedia-$fileSystem-NormalPermissions" }
    } catch {}
    return $true
}

Initialize-CompuTekEvidenceDirectory -Path $caseRoot | Out-Null

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
    $safeFileName = Get-CompuTekSafeFileName $Finding.Path
    if ($Finding.OriginalFilename -and $safeFileName -and ($safeFileName -ine $Finding.OriginalFilename)) {
        Write-Host ("{0}Renamed file evidence: on disk '{1}', original name '{2}'" -f $Indent,$safeFileName,$Finding.OriginalFilename) -ForegroundColor Red
    }
    if ($Finding.ConnectionCount -gt 0) {
        Write-Host ("{0}Active endpoints: {1}" -f $Indent,(@($Finding.RemoteEndpoints) -join ', ')) -ForegroundColor Yellow
    }
}

function Get-CandidateLocationLabel {
    param($Candidate)
    if ($Candidate.IsManagedSuite) {
        return ("{0} related installation location(s), consolidated as one managed suite" -f @($Candidate.Locations).Count)
    }
    if ($Candidate.GroupByVersion) {
        return ("{0} related location(s), grouped for this version" -f @($Candidate.Locations).Count)
    }
    if ($Candidate.ScopePath) { return [string]$Candidate.ScopePath }
    return [string]$Candidate.ScopeKey
}

function Show-CandidateSummary {
    param($Candidate, [switch]$Detailed)

    $typeCounts = @($Candidate.Findings | Group-Object ArtifactType | Sort-Object Name)
    $typeText = @($typeCounts | ForEach-Object {"$($_.Count) $($_.Name)"}) -join ', '
    $runningServices = @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Service' -and $_.ServiceState -eq 'Running'}).Count
    $runningProcesses = @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Process'}).Count
    $endpoints = @($Candidate.Findings | ForEach-Object {@($_.RemoteEndpoints)} | Where-Object {$_} | Sort-Object -Unique)
    $renamed = @($Candidate.Findings | Where-Object {
        $safeFileName = Get-CompuTekSafeFileName $_.Path
        $_.OriginalFilename -and $_.Path -and
        $safeFileName -and ($safeFileName -ine $_.OriginalFilename) -and
        (Test-CompuTekUserWritablePath $_.Path)
    })

    Write-Host ("    Location: {0}" -f (Get-CandidateLocationLabel $Candidate)) -ForegroundColor Cyan
    if ($Candidate.DetectedVersion) {
        Write-Host ("    Detected version{0}: {1}" -f $(if($Candidate.IsManagedSuite){'s'}else{''}),$Candidate.DetectedVersion) -ForegroundColor Cyan
    } else {
        Write-Host '    Detected version: unavailable; kept separate by location for safety' -ForegroundColor DarkYellow
    }
    Write-Host ("    Evidence: {0}" -f $typeText) -ForegroundColor Gray
    if ($runningServices -gt 0 -or $runningProcesses -gt 0) {
        Write-Host ("    Active now: {0} running service(s), {1} process(es)" -f $runningServices,$runningProcesses) -ForegroundColor Yellow
    }
    if ($endpoints.Count -gt 0) {
        Write-Host ("    Remote endpoint(s): {0}" -f ($endpoints -join ', ')) -ForegroundColor Yellow
    }
    if ($renamed.Count -gt 0) {
        Write-Host ("    WARNING: {0} renamed-file indicator(s) require review." -f $renamed.Count) -ForegroundColor Red
    }
    if ($Candidate.IsManagedSuite) {
        Write-Host '    CompuTek ownership verified: the Syncro shop identity matches the approved hash in the USB signature catalog.' -ForegroundColor Green
        if (@($Candidate.ProductIds) -contains 'splashtop') {
            Write-Host '    Splashtop ownership verified: Syncro is enabled for it and both products contain the same RMM deployment code. The code is never displayed or saved.' -ForegroundColor Green
            Write-Host '    Store Splashtop packages and nonmatching installations remain separate numbered findings.' -ForegroundColor Green
        }
    }
    $installerFiles = @(Get-CandidateInstallerFiles $Candidate)
    if ($installerFiles.Count -gt 0) {
        Write-Host ("    Installer/portable file(s): {0}. Type OPEN {1} to show the downloaded file in File Explorer." -f $installerFiles.Count,$Candidate.Index) -ForegroundColor Cyan
    }

    if ($Candidate.GroupByVersion -and @($Candidate.Locations).Count -gt 1) {
        foreach ($location in @($Candidate.Locations | Select-Object -First 4)) {
            Write-Host ("      - {0}" -f $location) -ForegroundColor DarkGray
        }
        if (@($Candidate.Locations).Count -gt 4) {
            Write-Host ("      ...and {0} more related location(s); the full list is saved in the report." -f (@($Candidate.Locations).Count - 4)) -ForegroundColor DarkGray
        }
    }

    if ($Detailed) {
        $priority = @{InstalledProgram=1;Service=2;NativeFeature=3;AppxPackage=4;StartApp=5;RunKey=6;ScheduledTask=7;StartupFile=8;Process=9;File=10}
        $examples = @($Candidate.Findings | Sort-Object @{Expression={if($priority.ContainsKey($_.ArtifactType)){$priority[$_.ArtifactType]}else{99}}},Path,Name | Select-Object -First 6)
        Write-Host '    Key items:' -ForegroundColor Gray
        foreach ($finding in $examples) {
            $location = if ($finding.Path) {$finding.Path} elseif ($finding.RegistryPath) {$finding.RegistryPath} else {$finding.DisplayName}
            Write-Host ("      [{0}] {1}" -f $finding.ArtifactType,$location) -ForegroundColor Gray
        }
        if ($Candidate.Findings.Count -gt $examples.Count) {
            Write-Host ("      ...{0} additional supporting item(s) are saved in JSON/CSV." -f ($Candidate.Findings.Count - $examples.Count)) -ForegroundColor DarkGray
        }
    }
}

function Get-CandidateInstallerFiles {
    param($Candidate)

    $installerFiles = New-Object System.Collections.Generic.List[string]
    $installedRoots = @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData) | Where-Object {$_} | ForEach-Object {
        ([IO.Path]::GetFullPath([string]$_)).TrimEnd('\')
    }
    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'File'})) {
        foreach ($value in @($finding.Path,$finding.SourcePath)) {
            $path = [Environment]::ExpandEnvironmentVariables(([string]$value).Trim().Trim('"'))
            if (-not $path) { continue }
            try {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
                $path = [IO.Path]::GetFullPath($path)
            } catch { continue }
            if ([IO.Path]::GetExtension($path) -notmatch '(?i)^\.(exe|msi|msix|msixbundle|appx|appxbundle|zip)$') { continue }
            $insideInstalledRoot = @($installedRoots | Where-Object {
                $path.StartsWith(([string]$_).TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)
            }).Count -gt 0
            if ($insideInstalledRoot) { continue }
            if (-not $installerFiles.Contains($path)) { $installerFiles.Add($path) }
        }
    }
    return @($installerFiles | Sort-Object @{Expression={if($_ -match '(?i)\\downloads\\'){0}elseif($_ -match '(?i)\\desktop\\'){1}elseif($_ -match '(?i)\\temp\\'){2}else{3}}},@{Expression={$_}})
}

function Open-CandidateInstallerFiles {
    param($Candidate)

    $installerFiles = @(Get-CandidateInstallerFiles $Candidate)
    if ($installerFiles.Count -eq 0) {
        Write-Host "No downloaded installer or portable remote-tool file was found for agent $($Candidate.Index). Installed-component paths remain in the saved JSON report." -ForegroundColor Yellow
        return
    }
    $openedDirectories = @{}
    foreach ($installerFile in $installerFiles) {
        $directory = Split-Path -Parent $installerFile
        $directoryKey = $directory.ToLowerInvariant()
        if ($openedDirectories.ContainsKey($directoryKey)) { continue }
        $openedDirectories[$directoryKey] = $true
        try {
            Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $installerFile) -ErrorAction Stop
            Write-Host "Opened downloaded installer/portable file: $installerFile" -ForegroundColor Green
        } catch {
            Write-Host "Could not show ${installerFile}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Get-FindingScopePath {
    param($Finding)

    if ($Finding.Category -eq 'native-feature') { return $null }
    if ($Finding.ArtifactType -eq 'AppxPackage') { return [string]$Finding.Path }

    if ($Finding.ArtifactType -eq 'InstalledProgram' -and -not $Finding.InstallLocation) {
        $registeredPath = [Environment]::ExpandEnvironmentVariables(([string]$Finding.Path).Trim('"'))
        if ($registeredPath -match '(?i)^(?:msiexec(?:\.exe)?|rundll32(?:\.exe)?)$') {
            # MSI uninstall records can expose only the Windows host executable.
            # Resolving that relative name against the staged engine created a fake
            # location under ProgramData and must never become a removal scope.
            return $null
        }
    }

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

function Test-FindingIsWindowsHostProcess {
    param($Finding)
    if ($Finding.ArtifactType -ne 'Process' -or -not $Finding.Path) { return $false }
    $expanded = [Environment]::ExpandEnvironmentVariables(([string]$Finding.Path).Trim('"'))
    $windowsRoot = ([IO.Path]::GetFullPath($env:SystemRoot)).TrimEnd('\') + '\'
    $insideWindows = $false
    try { $insideWindows = ([IO.Path]::GetFullPath($expanded)).StartsWith($windowsRoot,[StringComparison]::OrdinalIgnoreCase) } catch {}
    if (-not $insideWindows) { return $false }
    $fileName = Get-CompuTekSafeFileName $expanded
    return (
        $fileName -match '(?i)^(rundll32|msiexec|cmd|powershell|pwsh|wscript|cscript)\.exe$' -and
        ($Finding.SignatureStatus -eq 'Valid' -or "$($Finding.CompanyName) $($Finding.Signer)" -match '(?i)\bMicrosoft(?: Corporation)?\b')
    )
}

function Test-FindingIsPassiveSupportEvidence {
    param($Finding)
    if ($Finding.ArtifactType -eq 'StartApp') { return $true }
    if ($Finding.ArtifactType -eq 'File') {
        $extension = if ($Finding.Path) { [IO.Path]::GetExtension([string]$Finding.Path) } else { '' }
        if ($extension -match '(?i)^\.(lnk|url)$') { return $true }
    }
    return (Test-FindingIsWindowsHostProcess $Finding)
}

function Get-FindingDetectedVersion {
    param($Finding)
    if (Test-FindingIsPassiveSupportEvidence $Finding) { return $null }
    foreach ($propertyName in @('DisplayVersion','FileVersion')) {
        $property = $Finding.PSObject.Properties[$propertyName]
        if (-not $property) { continue }
        $version = ([string]$property.Value).Trim()
        if ($version) { return $version }
    }
    return $null
}

function Get-CompuTekManagedIdentityStatus {
    param($Catalog)

    $approvedHashes = @()
    $managedProperty = $Catalog.PSObject.Properties['managedIdentities']
    if ($managedProperty -and $managedProperty.Value) {
        $syncroProperty = $managedProperty.Value.PSObject.Properties['syncro']
        if ($syncroProperty -and $syncroProperty.Value) {
            $hashProperty = $syncroProperty.Value.PSObject.Properties['shopSubdomainSha256']
            if ($hashProperty) { $approvedHashes = @($hashProperty.Value | ForEach-Object {([string]$_).Trim().ToUpperInvariant()} | Where-Object {$_ -match '^[A-F0-9]{64}$'}) }
        }
    }

    $syncroApproved = $false
    $syncroSplashtopEnabled = $false
    $syncroSplashtopRmmCode = $null
    foreach ($syncroRegistryPath in @('HKLM:\SOFTWARE\WOW6432Node\RepairTech\Syncro','HKLM:\SOFTWARE\RepairTech\Syncro')) {
        try {
            $syncroValues = Get-ItemProperty -LiteralPath $syncroRegistryPath -ErrorAction Stop
            $subdomain = ([string]$syncroValues.shop_subdomain).Trim().ToLowerInvariant()
            if ($subdomain -and $approvedHashes.Count -gt 0) {
                $sha = [Security.Cryptography.SHA256]::Create()
                try { $actualHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($subdomain)))).Replace('-','') } finally { $sha.Dispose() }
                if ($approvedHashes -contains $actualHash) { $syncroApproved = $true }
            }
            $splashtopStateText = ([string]$syncroValues.SplashtopState).Trim()
            if ($splashtopStateText) {
                try {
                    $splashtopState = $splashtopStateText | ConvertFrom-Json -ErrorAction Stop
                    $enabledProperty = $splashtopState.PSObject.Properties['Enabled']
                    $rmmCodeProperty = $splashtopState.PSObject.Properties['RmmCode']
                    $syncroSplashtopEnabled = ($enabledProperty -and [bool]$enabledProperty.Value)
                    if ($rmmCodeProperty) { $syncroSplashtopRmmCode = ([string]$rmmCodeProperty.Value).Trim() }
                } catch {
                    # A damaged or legacy state value cannot prove ownership. Never
                    # display or save the raw value because it may contain credentials.
                    $syncroSplashtopEnabled = $false
                    $syncroSplashtopRmmCode = $null
                }
            }
            break
        } catch {}
    }

    $deploymentCodeMatches = $false
    foreach ($splashtopRegistryPath in @('HKLM:\SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server','HKLM:\SOFTWARE\Splashtop Inc.\Splashtop Remote Server')) {
        try {
            $splashtopValues = Get-ItemProperty -LiteralPath $splashtopRegistryPath -ErrorAction Stop
            $registeredRmmCode = ([string]$splashtopValues.RmmCode).Trim()
            if ($syncroSplashtopRmmCode -and $registeredRmmCode -and $syncroSplashtopRmmCode -ceq $registeredRmmCode) {
                $deploymentCodeMatches = $true
                break
            }
        } catch {}
    }

    $splashtopLinked = ($syncroApproved -and $syncroSplashtopEnabled -and $deploymentCodeMatches)
    return [pscustomobject]@{
        SyncroApproved = $syncroApproved
        SplashtopLinked = $splashtopLinked
        MatchMethod = if ($splashtopLinked) {
            'Approved Syncro shop identity + exact Splashtop RMM deployment-code match'
        } elseif ($syncroApproved) {
            'Approved Syncro shop identity; no exact Splashtop deployment-code match'
        } else {
            'No approved Syncro shop identity match'
        }
    }
}

function Test-PathWithinVersionAnchor {
    param([string]$Path, [string]$Anchor)
    if (-not $Path -or -not $Anchor) { return $false }
    $pathLower = $Path.TrimEnd('\').ToLowerInvariant()
    $anchorLower = $Anchor.TrimEnd('\').ToLowerInvariant()
    return ($pathLower -eq $anchorLower -or $pathLower.StartsWith($anchorLower + '\'))
}

function New-RemovalCandidates {
    param(
        $Findings,
        $ManagedIdentityStatus = (Get-CompuTekManagedIdentityStatus -Catalog $catalog)
    )

    $suiteProducts = @{}
    $managedSuiteDefinitions = @{}
    foreach ($product in @($catalog.products)) {
        $groupProperty = $product.PSObject.Properties['groupProductComponents']
        if ($groupProperty -and [bool]$groupProperty.Value) { $suiteProducts[[string]$product.id] = $true }

        $managedSuiteProperty = $product.PSObject.Properties['managedSuiteId']
        if (-not $managedSuiteProperty -or [string]::IsNullOrWhiteSpace([string]$managedSuiteProperty.Value)) { continue }
        $managedSuiteId = [string]$managedSuiteProperty.Value
        if (-not $managedSuiteDefinitions.ContainsKey($managedSuiteId)) {
            $managedSuiteDefinitions[$managedSuiteId] = [ordered]@{
                Id = $managedSuiteId
                Name = [string]$product.managedSuiteName
                ProductIds = New-Object System.Collections.Generic.List[string]
                PrimaryProductIds = New-Object System.Collections.Generic.List[string]
            }
        }
        if (-not $managedSuiteDefinitions[$managedSuiteId].ProductIds.Contains([string]$product.id)) {
            $managedSuiteDefinitions[$managedSuiteId].ProductIds.Add([string]$product.id)
        }
        $primaryProperty = $product.PSObject.Properties['managedSuitePrimary']
        if ($primaryProperty -and [bool]$primaryProperty.Value -and -not $managedSuiteDefinitions[$managedSuiteId].PrimaryProductIds.Contains([string]$product.id)) {
            $managedSuiteDefinitions[$managedSuiteId].PrimaryProductIds.Add([string]$product.id)
        }
    }

    # Group every known product by its exact detected version. Supporting artifacts
    # without version metadata join only when there is one unambiguous product version
    # or their path belongs to a versioned installation. Ambiguous items stay separate.
    $versionDataByProduct = @{}
    foreach ($finding in @($Findings | Where-Object {$_.ProductId -ne 'unknown'})) {
        if (Test-FindingIsWindowsHostProcess $finding) {
            $finding | Add-Member -NotePropertyName SupportingOnly -NotePropertyValue $true -Force
        }
        $version = Get-FindingDetectedVersion $finding
        if (-not $version) { continue }
        $productId = [string]$finding.ProductId
        if (-not $versionDataByProduct.ContainsKey($productId)) {
            $versionDataByProduct[$productId] = [ordered]@{
                Versions = New-Object System.Collections.Generic.List[string]
                InstallVersions = New-Object System.Collections.Generic.List[string]
                InstallAnchors = New-Object System.Collections.Generic.List[object]
            }
        }
        if (-not $versionDataByProduct[$productId].Versions.Contains($version)) {
            $versionDataByProduct[$productId].Versions.Add($version)
        }
        if ($finding.ArtifactType -eq 'InstalledProgram') {
            if (-not $versionDataByProduct[$productId].InstallVersions.Contains($version)) {
                $versionDataByProduct[$productId].InstallVersions.Add($version)
            }
            $anchor = Get-FindingScopePath $finding
            if ($anchor) {
                $versionDataByProduct[$productId].InstallAnchors.Add([pscustomobject]@{Path=$anchor;Version=$version})
            }
        }
    }

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
        $isSupportingOnly = [bool]$finding.PSObject.Properties['SupportingOnly'] -and [bool]$finding.SupportingOnly
        $evidenceLocation = if ($isSupportingOnly) { $null } else { $scopePath }
        $resolvedVersion = $null
        $productVersionData = if ($versionDataByProduct.ContainsKey([string]$finding.ProductId)) { $versionDataByProduct[[string]$finding.ProductId] } else { $null }
        if ($scopePath -and $productVersionData) {
            $matchingVersionAnchor = @($productVersionData.InstallAnchors | Where-Object {
                Test-PathWithinVersionAnchor -Path $scopePath -Anchor $_.Path
            } | Sort-Object @{Expression={$_.Path.Length};Descending=$true} | Select-Object -First 1)
            if ($matchingVersionAnchor) { $resolvedVersion = [string]($matchingVersionAnchor[0].Version) }
        }
        $isSuiteProduct = $suiteProducts.ContainsKey([string]$finding.ProductId)
        $installedProductVersions = @()
        if ($productVersionData) { $installedProductVersions = @($productVersionData.InstallVersions.ToArray()) }
        if (-not $resolvedVersion -and $isSuiteProduct -and $productVersionData -and $installedProductVersions.Count -eq 1) {
            # Syncro and Splashtop install multiple helper services/programs whose file
            # build numbers differ from the registered suite version. Treat those as
            # components of the one installed suite instead of separate agents.
            $resolvedVersion = [string]($installedProductVersions[0])
        }
        if (-not $resolvedVersion) { $resolvedVersion = Get-FindingDetectedVersion $finding }
        if (-not $resolvedVersion -and $productVersionData) {
            $fallbackVersions = @()
            if ($installedProductVersions.Count -gt 0) {
                $fallbackVersions = @($installedProductVersions)
            } else {
                $fallbackVersions = @($productVersionData.Versions.ToArray())
            }
            if ($fallbackVersions.Count -eq 1) { $resolvedVersion = [string]($fallbackVersions[0]) }
        }
        $groupByVersion = ($finding.ProductId -ne 'unknown' -and -not [string]::IsNullOrWhiteSpace($resolvedVersion))
        $groupAsPassiveProduct = (
            $finding.ProductId -ne 'unknown' -and
            -not $groupByVersion -and
            (Test-FindingIsPassiveSupportEvidence $finding) -and
            -not $productVersionData
        )

        if (-not $groupByVersion -and $scopePath -and $installAnchors.ContainsKey($finding.ProductId)) {
            $scopeLower = $scopePath.TrimEnd('\').ToLowerInvariant()
            $matchingAnchor = @($installAnchors[$finding.ProductId] | Where-Object {
                $anchorLower = ([string]$_).TrimEnd('\').ToLowerInvariant()
                $scopeLower -eq $anchorLower -or $scopeLower.StartsWith($anchorLower + '\')
            } | Sort-Object Length -Descending | Select-Object -First 1)
            if ($matchingAnchor) { $scopePath = [string]($matchingAnchor[0]) }
        }
        $scopeKey = if ($groupByVersion) {
            "product-version:$($finding.ProductId):$($resolvedVersion.ToLowerInvariant())"
        } elseif ($groupAsPassiveProduct) {
            "product-passive:$($finding.ProductId)"
        } elseif ($finding.Category -eq 'native-feature') {
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
                ScopePath = if ($groupByVersion -or $groupAsPassiveProduct) { $null } else { $scopePath }
                GroupByVersion = $groupByVersion
                DetectedVersion = $resolvedVersion
                Locations = New-Object System.Collections.Generic.List[string]
                Findings = New-Object System.Collections.Generic.List[object]
            }
        }
        if ($evidenceLocation -and -not $scopeGroups[$key].Locations.Contains([string]$evidenceLocation)) {
            $scopeGroups[$key].Locations.Add([string]$evidenceLocation)
        }
        $scopeGroups[$key].Findings.Add($finding)
    }

    $entries = @($scopeGroups.Values)
    foreach ($definition in @($managedSuiteDefinitions.Values)) {
        if (-not $ManagedIdentityStatus.SyncroApproved) { continue }
        $suiteEntries = @($entries | Where-Object {
            if ($definition.ProductIds -notcontains [string]$_.ProductId) { return $false }
            if ([string]$_.ProductId -eq 'splashtop') {
                if (-not $ManagedIdentityStatus.SplashtopLinked) { return $false }
                if (@($_.Findings | Where-Object {$_.ArtifactType -in @('AppxPackage','StartApp')}).Count -gt 0) { return $false }
            }
            $suspiciousUserWritableEvidence = @($_.Findings | Where-Object {
                if (-not $_.Path -or -not (Test-CompuTekUserWritablePath $_.Path)) { return $false }
                $isPassiveDownloadedFile = (
                    $_.ArtifactType -eq 'File' -and
                    [IO.Path]::GetExtension([string]$_.Path) -match '(?i)^\.(exe|msi|msix|msixbundle|appx|appxbundle|zip)$' -and
                    [string]$_.Path -match '(?i)\\(downloads|desktop|temp)\\'
                )
                return (-not $isPassiveDownloadedFile)
            })
            return ($suspiciousUserWritableEvidence.Count -eq 0)
        })
        $hasPrimary = @($suiteEntries | Where-Object {$definition.PrimaryProductIds -contains [string]$_.ProductId}).Count -gt 0
        if (-not $hasPrimary) { continue }

        $managedFindings = New-Object System.Collections.Generic.List[object]
        $managedLocations = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $suiteEntries) {
            foreach ($finding in $entry.Findings.ToArray()) { $managedFindings.Add($finding) }
            foreach ($location in $entry.Locations.ToArray()) {
                if ($location -and -not $managedLocations.Contains([string]$location)) { $managedLocations.Add([string]$location) }
            }
        }
        $primaryVersions = @($suiteEntries | Where-Object {
            $definition.PrimaryProductIds -contains [string]$_.ProductId -and $_.DetectedVersion
        } | ForEach-Object {[string]$_.DetectedVersion} | Sort-Object -Unique)
        $primaryProductId = [string]($definition.PrimaryProductIds[0])
        $includedProductIds = @($suiteEntries | ForEach-Object {[string]$_.ProductId} | Sort-Object -Unique)
        $includesSplashtop = ($includedProductIds -contains 'splashtop')
        $mergedEntry = [ordered]@{
            ProductId = $primaryProductId
            ProductIds = [string[]]$includedProductIds
            ProductName = if ($includesSplashtop -and $definition.Name) {[string]$definition.Name} else {'CompuTek SyncroMSP Agent (ownership verified)'}
            Category = 'rmm'
            ScopeKey = "managed-suite:$($definition.Id)"
            ScopePath = $null
            GroupByVersion = $false
            DetectedVersion = ($primaryVersions -join ', ')
            Locations = $managedLocations
            Findings = $managedFindings
            IsManagedSuite = $true
            ManagedSuiteId = [string]$definition.Id
            ManagedIdentityMatch = [string]$ManagedIdentityStatus.MatchMethod
        }
        $mergedEntryKeys = @{}
        foreach ($entry in $suiteEntries) { $mergedEntryKeys["$($entry.ProductId)|$($entry.ScopeKey)"] = $true }
        $entries = @($entries | Where-Object {-not $mergedEntryKeys.ContainsKey("$($_.ProductId)|$($_.ScopeKey)")})
        $entries += $mergedEntry
    }

    $candidates = @()
    $productCounts = @{}
    $index = 0
    foreach ($entry in @($entries | Sort-Object ProductName,ScopeKey)) {
        $index++
        $baseId = if ($entry.IsManagedSuite) { "managed-$($entry.ManagedSuiteId)" } elseif ($entry.ProductId -eq 'unknown') { 'unknown' } else { $entry.ProductId }
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
            ProductIds = if ($entry.ProductIds) {@($entry.ProductIds)} else {@([string]$entry.ProductId)}
            Name = [string]$name
            Category = $entry.Category
            ScopeKey = $entry.ScopeKey
            ScopePath = $entry.ScopePath
            GroupByVersion = [bool]$entry.GroupByVersion
            DetectedVersion = [string]$entry.DetectedVersion
            Locations = @($entry.Locations | Sort-Object)
            Findings = @($entry.Findings | ForEach-Object {$_})
            IsUnknown = ($entry.ProductId -eq 'unknown')
            IsManagedSuite = [bool]$entry.IsManagedSuite
            ManagedSuiteId = [string]$entry.ManagedSuiteId
            ManagedIdentityMatch = [string]$entry.ManagedIdentityMatch
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
        if ($finding.PSObject.Properties['SupportingOnly'] -and [bool]$finding.SupportingOnly) { continue }
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
        foreach ($file in Get-CompuTekCandidateFilesSafe -Root $directory -MaxDepth 8) {
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
    param($Candidate, [string]$AttemptLabel = 'initial attempt')
    $entries = @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'InstalledProgram' -and ($_.QuietUninstallString -or $_.UninstallString)} | Sort-Object RegistryPath -Unique)
    $attempted = $false
    $allSucceeded = $true
    foreach ($entry in $entries) {
        $attempted = $true
        $command = if ($entry.QuietUninstallString) { $entry.QuietUninstallString } else { $entry.UninstallString }
        Write-RemediationLog "Running registered uninstaller for $($entry.DisplayName) ($AttemptLabel): $command" 'Yellow'
        try {
            $result = Invoke-CompuTekUninstallCommand -Command $command
            if ($result.TimedOut) {
                Write-RemediationLog ("Uninstaller did not finish within {0} seconds and was stopped so the offline cleanup could continue." -f $result.TimeoutSeconds) 'Red'
            } else {
                Write-RemediationLog ("Uninstaller exit code: {0}" -f $result.ExitCode) $(if($result.Success){'Green'}else{'Red'})
            }
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
    $attempted = $false
    $allSucceeded = $true
    if (-not (Get-Command Remove-AppxPackage -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{Attempted=$false;Success=$false}
    }

    foreach ($package in @($Candidate.Findings | Where-Object {$_.PackageFullName} | Select-Object -ExpandProperty PackageFullName -Unique)) {
        $attempted = $true
        try {
            $command = Get-Command Remove-AppxPackage -ErrorAction Stop
            if ($command.Parameters.ContainsKey('AllUsers')) {
                Remove-AppxPackage -Package $package -AllUsers -ErrorAction Stop
            } else {
                Remove-AppxPackage -Package $package -ErrorAction Stop
            }
            Write-RemediationLog "Removed AppX package: $package" 'Green'
        } catch {
            $allSucceeded = $false
            Write-RemediationLog "Could not remove AppX package ${package}: $($_.Exception.Message)" 'Red'
        }
    }

    if (Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        $packageNames = @($Candidate.Findings | Where-Object {$_.PackageName} | Select-Object -ExpandProperty PackageName -Unique)
        foreach ($package in @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$packageNames -contains $_.DisplayName})) {
            $attempted = $true
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
                Write-RemediationLog "Removed provisioned AppX package: $($package.PackageName)" 'Green'
            } catch {
                $allSucceeded = $false
                Write-RemediationLog "Could not remove provisioned package $($package.PackageName): $($_.Exception.Message)" 'Red'
            }
        }
    }
    return [pscustomobject]@{Attempted=$attempted;Success=($attempted -and $allSucceeded)}
}

function Stop-CandidateProcesses {
    param($Candidate)
    $candidatePaths = @($Candidate.Findings | Where-Object {
        $_.Path -and ([string]$_.Path) -match '(?i)\.(exe|com)$' -and
        -not ($_.PSObject.Properties['SupportingOnly'] -and [bool]$_.SupportingOnly)
    } | ForEach-Object {[Environment]::ExpandEnvironmentVariables(([string]$_.Path).Trim('"'))} | Sort-Object -Unique)
    $stoppedProcessIds = New-Object System.Collections.Generic.List[int]
    foreach ($finding in @($Candidate.Findings | Where-Object {
        $_.ArtifactType -eq 'Process' -and $_.ProcessId -and
        -not ($_.PSObject.Properties['SupportingOnly'] -and [bool]$_.SupportingOnly)
    } | Sort-Object ProcessId -Unique)) {
        try {
            $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($finding.ProcessId)" -ErrorAction SilentlyContinue
            if (-not $current) { continue }
            $currentPath = if ($current.ExecutablePath) { $current.ExecutablePath } else { Get-CompuTekExecutablePath $current.CommandLine }
            if ($finding.Path -and $currentPath -and $currentPath -ine $finding.Path) {
                Write-RemediationLog "Skipped PID $($finding.ProcessId) because the process path changed after the scan." 'Yellow'
                continue
            }
            Stop-Process -Id $finding.ProcessId -Force -ErrorAction Stop
            $stoppedProcessIds.Add([int]$finding.ProcessId)
            Write-RemediationLog "Stopped process $($finding.Name) (PID $($finding.ProcessId))." 'Green'
        } catch { Write-RemediationLog "Could not stop PID $($finding.ProcessId): $($_.Exception.Message)" 'Red' }
    }

    # A protecting service may restart a process with a new PID after the scan. Stop
    # only processes whose current executable path exactly matches version-group evidence.
    if ($candidatePaths.Count -gt 0) {
        foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            if ($stoppedProcessIds.Contains([int]$process.ProcessId)) { continue }
            $currentPath = if ($process.ExecutablePath) { [string]$process.ExecutablePath } else { Get-CompuTekExecutablePath $process.CommandLine }
            if (-not $currentPath -or @($candidatePaths | Where-Object {$_ -ieq $currentPath}).Count -eq 0) { continue }
            try {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                Write-RemediationLog "Stopped restarted/related process $($process.Name) (PID $($process.ProcessId))." 'Green'
            } catch { Write-RemediationLog "Could not stop related PID $($process.ProcessId): $($_.Exception.Message)" 'Red' }
        }
    }
}

function Remove-CandidateStoreProducts {
    param(
        $Candidate,
        [switch]$RegisteredUninstallSucceeded,
        [switch]$AppxRemovalSucceeded,
        [switch]$AllowProductWideFallback
    )

    $storeEvidence = @($Candidate.Findings | Where-Object {$_.ArtifactType -in @('AppxPackage','StartApp')})
    if ($storeEvidence.Count -eq 0) { return }
    if ($RegisteredUninstallSucceeded) {
        Write-RemediationLog 'The registered vendor uninstaller succeeded; the verification scan will confirm that its Store registration was removed.' 'Green'
        return
    }
    if ($AppxRemovalSucceeded) {
        Write-RemediationLog 'Windows package removal succeeded; the verification scan will confirm that every Store registration was removed.' 'Green'
        return
    }
    if (-not $AllowProductWideFallback) {
        Write-RemediationLog 'Exact Store-ID fallback was skipped because another version of this product was approved to keep. Verification will report any remaining selected package for manual removal.' 'Yellow'
        return
    }
    $storeProductIds = @($storeEvidence | ForEach-Object {@($_.StoreProductIds)} | Where-Object {$_} | Sort-Object -Unique)
    if ($storeProductIds.Count -eq 0) { return }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-RemediationLog ("Windows Package Manager is unavailable. Store product ID(s) require manual removal if still present: {0}" -f ($storeProductIds -join ', ')) 'Red'
        return
    }

    foreach ($storeProductId in $storeProductIds) {
        Write-RemediationLog "Running exact Microsoft Store uninstall for product ID $storeProductId." 'Yellow'
        try {
            $arguments = @('uninstall','--id',[string]$storeProductId,'--exact','--source','msstore','--silent','--accept-source-agreements','--disable-interactivity')
            $process = Start-Process -FilePath $winget.Source -ArgumentList $arguments -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-RemediationLog "Microsoft Store uninstall completed for product ID $storeProductId." 'Green'
            } else {
                Write-RemediationLog "Microsoft Store uninstall returned exit code $($process.ExitCode) for product ID $storeProductId; verification will determine whether it remains." 'Red'
            }
        } catch {
            Write-RemediationLog "Microsoft Store uninstall failed for product ID ${storeProductId}: $($_.Exception.Message)" 'Red'
        }
    }
}

function Stop-CandidateServices {
    param($Candidate)
    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Service' -and $_.Name} | Sort-Object Name -Unique)) {
        try {
            $service = Get-Service -Name $finding.Name -ErrorAction SilentlyContinue
            if (-not $service) { continue }
            Set-Service -Name $finding.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $finding.Name -Force -ErrorAction Stop
            $service = Get-Service -Name $finding.Name -ErrorAction SilentlyContinue
            if ($service) { $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20)) }
            Write-RemediationLog "Stopped and disabled blocking service $($finding.Name)." 'Green'
        } catch { Write-RemediationLog "Could not stop blocking service $($finding.Name): $($_.Exception.Message)" 'Red' }
    }
}

function Remove-CandidateServices {
    param($Candidate)
    Stop-CandidateServices $Candidate
    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'Service' -and $_.Name} | Sort-Object Name -Unique)) {
        try {
            $service = Get-Service -Name $finding.Name -ErrorAction SilentlyContinue
            if (-not $service) { continue }
            & sc.exe delete $finding.Name 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe returned exit code $LASTEXITCODE" }
            Write-RemediationLog "Removed service definition $($finding.Name)." 'Green'
        } catch { Write-RemediationLog "Could not remove service $($finding.Name): $($_.Exception.Message)" 'Red' }
    }
}

function Remove-CandidateStartupItems {
    param($Candidate)

    foreach ($finding in @($Candidate.Findings | Where-Object {$_.ArtifactType -eq 'StartupFile' -and $_.SourcePath} | Sort-Object SourcePath -Unique)) {
        $startupPath = [string]$finding.SourcePath
        if (-not (Test-Path -LiteralPath $startupPath -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
        if (Move-ToCandidateQuarantine -Candidate $Candidate -Path $startupPath -Kind 'startup-folder reinstall item' -AllowExactStartupItem) {
            Write-RemediationLog "Removed startup-folder item before uninstall verification: $startupPath" 'Green'
        } else {
            Write-RemediationLog "Startup-folder item could not be removed: $startupPath" 'Red'
        }
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
        (Join-Path $env:ProgramData 'Microsoft'),
        $env:ProgramFiles,
        (Join-Path $env:ProgramFiles 'Common Files'),
        ${env:ProgramFiles(x86)},
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Common Files' }),
        (Join-Path $env:SystemDrive 'Users')
    ) | Where-Object {$_} | ForEach-Object {([string]$_).TrimEnd('\').ToLowerInvariant()}
    if ($protectedExact -contains $lower) { return $true }
    if ($lower.StartsWith(([string]$caseRoot).ToLowerInvariant()) -or $lower.StartsWith(([string]$quarantineRoot).ToLowerInvariant())) { return $true }
    if ($lower.StartsWith(([string]$env:SystemRoot).TrimEnd('\').ToLowerInvariant() + '\') -and -not $lower.StartsWith((Join-Path $env:SystemRoot 'Temp').ToLowerInvariant() + '\')) { return $true }
    $protectedTrees = @(
        (Join-Path $env:ProgramData 'Microsoft'),
        (Join-Path $env:ProgramFiles 'Common Files'),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Common Files' })
    ) | Where-Object {$_} | ForEach-Object {([string]$_).TrimEnd('\').ToLowerInvariant() + '\'}
    if (@($protectedTrees | Where-Object {$lower.StartsWith($_)}).Count -gt 0) { return $true }
    if ($Directory -and $lower -match '\\users\\[^\\]+$') { return $true }
    if ($Directory -and $lower -match '\\users\\[^\\]+\\appdata\\(local|locallow|roaming)$') { return $true }
    if ($Directory -and $lower -match '\\users\\[^\\]+\\(desktop|documents|downloads|pictures|music|videos|onedrive)$') { return $true }
    return $false
}

function Move-ToCandidateQuarantine {
    param($Candidate, [string]$Path, [string]$Kind, [switch]$AllowExactStartupItem)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    $isDirectory = Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue
    if (Test-ProtectedRemediationPath -Path $Path -Directory:$isDirectory) {
        Write-RemediationLog "Protected path was not moved automatically: $Path" 'Red'
        return $false
    }
    try {
        $pathItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($pathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-RemediationLog "Linked or redirected path was not moved automatically: $Path" 'Red'
            return $false
        }
    } catch {
        Write-RemediationLog "Path could not be safety-checked and was not moved automatically: $Path" 'Red'
        return $false
    }
    if ($Candidate.IsUnknown -and -not $AllowExactStartupItem -and ($isDirectory -or -not (Test-CompuTekUserWritablePath $Path))) {
        Write-RemediationLog "Unknown artifact outside a user-writable file path was not moved automatically: $Path" 'Red'
        return $false
    }

    $destination = Join-Path $quarantineRoot ($Candidate.Id -replace '[^a-zA-Z0-9._-]','_')
    New-Item -Path $destination -ItemType Directory -Force | Out-Null
    Initialize-CompuTekEvidenceDirectory -Path $destination | Out-Null
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
        if ($finding.PSObject.Properties['SupportingOnly'] -and [bool]$finding.SupportingOnly) { continue }
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
    param($Candidate, [switch]$AllowProductWideStoreFallback)

    $backup = Backup-CandidateEvidence $Candidate
    Write-RemediationLog "Evidence backup created: $backup" 'Cyan'
    $preserved = Preserve-CandidateOperationalData $Candidate
    Write-RemediationLog "Operational logs/configuration preserved under: $preserved" 'Cyan'

    if ($Candidate.Category -eq 'native-feature') {
        Remove-NativeRemoteFeature $Candidate
        return
    }

    # Prevent a selected agent from being relaunched or reinstalled at sign-in
    # while its registered vendor uninstaller is running.
    Remove-CandidateStartupItems $Candidate

    $uninstallResult = Invoke-OfficialUninstall $Candidate
    if (-not $uninstallResult.Attempted) {
        Write-RemediationLog 'No registered vendor uninstaller was found; continuing with exact residual removal.' 'Yellow'
    } elseif (-not $uninstallResult.Success) {
        Write-RemediationLog 'The registered uninstaller failed. Stopping related services/processes, then retrying it once.' 'Yellow'
        Stop-CandidateServices $Candidate
        Stop-CandidateProcesses $Candidate
        $retryResult = Invoke-OfficialUninstall -Candidate $Candidate -AttemptLabel 'retry after blockers were stopped'
        if ($retryResult.Success) { $uninstallResult = $retryResult }
        if (-not $retryResult.Success) {
            Write-RemediationLog 'The registered uninstaller retry also failed; continuing with exact residual removal and verification.' 'Red'
        }
    }

    Stop-CandidateProcesses $Candidate
    Remove-CandidateServices $Candidate
    Remove-CandidatePersistence $Candidate
    $appxResult = Remove-CandidateAppxPackages $Candidate
    Remove-CandidateStoreProducts -Candidate $Candidate -RegisteredUninstallSucceeded:$uninstallResult.Success -AppxRemovalSucceeded:$appxResult.Success -AllowProductWideFallback:$AllowProductWideStoreFallback
    Remove-CandidateResidualFiles $Candidate
    Remove-CandidateRegistration $Candidate
}

function Test-FindingBelongsToCandidate {
    param($Finding, $Candidate)
    if (@($Candidate.ProductIds) -notcontains [string]$Finding.ProductId) { return $false }
    if ($Candidate.IsManagedSuite) { return $true }
    $storeArtifactTypes = @('AppxPackage','StartApp')
    $candidateHasStoreEvidence = @($Candidate.Findings | Where-Object {$_.ArtifactType -in $storeArtifactTypes}).Count -gt 0
    if ($candidateHasStoreEvidence -and $Finding.ArtifactType -in $storeArtifactTypes) {
        # Windows can expose the same Store installation through AppX during one
        # scan and only through its Start registration during the next. Treat the
        # cross-view evidence as remaining software. A versioned AppX finding can
        # still distinguish a separately kept version; an unversioned Start entry
        # is deliberately conservative so removal is never falsely marked verified.
        $findingStoreVersion = Get-FindingDetectedVersion $Finding
        if ($Candidate.GroupByVersion -and $findingStoreVersion) {
            return ($findingStoreVersion -ieq $Candidate.DetectedVersion)
        }
        return $true
    }
    if ($Candidate.GroupByVersion) {
        $findingVersion = Get-FindingDetectedVersion $Finding
        if ($findingVersion) {
            if ($findingVersion -ieq $Candidate.DetectedVersion) { return $true }
            foreach ($original in @($Candidate.Findings)) {
                $sameIdentity = ($original.ArtifactType -eq $Finding.ArtifactType -and $original.Name -and $original.Name -ieq $Finding.Name)
                if ($sameIdentity -and $original.Path -and $Finding.Path) { $sameIdentity = ($original.Path -ieq $Finding.Path) }
                if (-not $sameIdentity) { continue }
                $originalVersion = Get-FindingDetectedVersion $original
                if ($originalVersion -and $originalVersion -ieq $findingVersion) { return $true }
            }
            return $false
        }
        $findingScope = Get-FindingScopePath $Finding
        if ($findingScope -and @($Candidate.Locations | Where-Object {$_ -and $_ -ieq $findingScope}).Count -gt 0) { return $true }
        foreach ($original in @($Candidate.Findings)) {
            if ($original.ArtifactType -eq $Finding.ArtifactType -and $original.Name -and $original.Name -ieq $Finding.Name) { return $true }
        }
        return $false
    }
    if ($Candidate.Category -eq 'native-feature') { return $true }
    if ($Candidate.ScopeKey -like 'appx:*') { return ("appx:$($Finding.PackageFullName)" -ieq $Candidate.ScopeKey) }

    $scopePath = Get-FindingScopePath $Finding
    if ($scopePath -and $Candidate.ScopePath -and $scopePath -ieq $Candidate.ScopePath) { return $true }
    foreach ($original in @($Candidate.Findings)) {
        if ($original.ArtifactType -eq $Finding.ArtifactType -and $original.Name -and $original.Name -ieq $Finding.Name) { return $true }
    }
    return $false
}

function Test-CandidateHasKeptProductPeer {
    param($Candidate, $AllCandidates, $DecisionById)
    foreach ($otherCandidate in @($AllCandidates)) {
        if ($DecisionById[$otherCandidate.Id] -ne 'KeepApproved') { continue }
        $sharedProduct = @($otherCandidate.ProductIds | Where-Object {
            @($Candidate.ProductIds) -contains [string]$_
        }).Count -gt 0
        if ($sharedProduct) { return $true }
    }
    return $false
}

function ConvertTo-CompuTekCandidateSelection {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateRange(1,10000)][int]$Maximum,
        [Parameter(Mandatory)][ValidateSet('KEEP','REMOVE','OPEN')][string]$ExpectedAction
    )

    $value = ([string]$Text).Trim()
    $actionMatch = [regex]::Match($value,'(?i)^(KEEP|REMOVE|OPEN)\b\s*(.*)$')
    if ($actionMatch.Success) {
        if ($actionMatch.Groups[1].Value.ToUpperInvariant() -ne $ExpectedAction) {
            throw "This answer must start with $ExpectedAction."
        }
        $value = $actionMatch.Groups[2].Value.Trim()
    }
    if ($value -match '^NONE$') { return @() }
    if ($value -match '^ALL$') { return @(1..$Maximum) }
    if (-not $value) { throw "Enter $ExpectedAction followed by numbers, $ExpectedAction ALL, or $ExpectedAction NONE." }

    $numbers = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($part in @($value -split ',')) {
        $item = $part.Trim()
        if ($item -match '^(\d+)$') {
            $start = [int]$Matches[1]
            $end = $start
        } elseif ($item -match '^(\d+)\s*-\s*(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            if ($end -lt $start) { throw "Range '$item' must go from a lower number to a higher number." }
        } else {
            throw "'$item' is not a valid number or range. Example: $ExpectedAction 2,4-7"
        }
        if ($start -lt 1 -or $end -gt $Maximum) { throw "'$item' is outside the available agent numbers 1-$Maximum." }
        foreach ($number in $start..$end) { [void]$numbers.Add($number) }
    }
    return @($numbers | Sort-Object)
}

if ($env:COMPUTEK_SCANNER_APP -ne '1') { Clear-Host }
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  CompuTek Remote-Access Scanner and Remediation Tool' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "Catalog: $($catalog.catalogVersion) ($(@($catalog.products).Count) product families)" -ForegroundColor DarkGray
Write-Host "Case folder: $caseRoot" -ForegroundColor Cyan
Write-Host 'Findings, decisions, evidence, and quarantine data will be saved on this service USB.' -ForegroundColor Cyan
if ($DeepScan) {
    Write-Host 'Full fixed-drive scan is enabled. This can take a long time.' -ForegroundColor Yellow
} else {
    Write-Host 'Scan mode: bounded high-risk folders. Select Full fixed-drive scan to inspect beyond the targeted depth.' -ForegroundColor Yellow
}
Write-Host 'Scanning. No changes are made during this phase...' -ForegroundColor Cyan

try {
    $scan = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays $LookbackDays -DeepScan:$DeepScan -IncludeHashes:$IncludeHashes
} catch {
    Write-Host "Scanner could not start: $($_.Exception.Message)" -ForegroundColor Red
    Complete-CompuTekRun 'Scanner stopped before collection completed.' Red
    exit 2
}

$reportPaths = Export-CompuTekScanReport -Scan $scan -Directory $caseRoot -BaseName 'BeforeRemediation'
Write-Host "`n==================== SCAN STATUS ====================" -ForegroundColor Cyan
Write-Host "Artifacts inspected: $($scan.Stats.ArtifactsInspected)"
Write-Host "Known remote product families: $($scan.Stats.KnownProducts)"
Write-Host "Suspicious unknown artifacts: $($scan.Stats.SuspiciousUnknown)"
Write-Host "Startup-folder items inspected: $($scan.Stats.StartupItems)"
if ($scan.Stats.StartupReinstallRisks -gt 0) {
    Write-Host "Startup-folder reinstall/download risks: $($scan.Stats.StartupReinstallRisks)" -ForegroundColor Red
}
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
    Write-Host "Startup inventory: $($reportPaths.StartupCsv)" -ForegroundColor DarkGray
    if ($scan.IsComplete) {
        Complete-CompuTekRun 'Scan complete.'
        exit 0
    }
    Complete-CompuTekRun 'Scan incomplete — technician attention is required.'
    exit 3
}

Write-Host "`n===================== FINDINGS ======================" -ForegroundColor Cyan
foreach ($candidate in $candidates) {
    $highest = if ($candidate.Findings.Confidence -contains 'High') {'High'} elseif ($candidate.Findings.Confidence -contains 'Medium') {'Medium'} else {'Low'}
    $displayClass = if ($candidate.IsManagedSuite) {'Managed'} elseif ($candidate.IsUnknown) {$highest} else {'Known'}
    Write-Host ("{0,2}. [{1}] {2}" -f $candidate.Index,$displayClass,$candidate.Name) -ForegroundColor $(if($candidate.IsManagedSuite){'Green'}elseif($candidate.IsUnknown -and $highest -eq 'High'){'Red'}elseif($candidate.IsUnknown){'Yellow'}else{'Cyan'})
    Show-CandidateSummary $candidate
}

Write-Host "`nReports were saved before any remediation:" -ForegroundColor Cyan
Write-Host "  $($reportPaths.Json)" -ForegroundColor DarkGray
Write-Host "  $($reportPaths.Csv)" -ForegroundColor DarkGray
Write-Host "  Startup items: $($reportPaths.StartupCsv)" -ForegroundColor DarkGray
Write-Host 'A finding is not proof of malicious use. Verify company-approved support tools before removal.' -ForegroundColor Yellow

$technicianName = ''
while ([string]::IsNullOrWhiteSpace($technicianName)) {
    $technicianName = Read-CompuTekInput 'Technician name or initials (required; Q quits without changes)'
    if ($technicianName -match '^[Qq]$') { exit 0 }
}
$caseReference = Read-CompuTekInput 'Ticket/case reference (optional)'
$decisionPath = Join-Path $caseRoot 'TechnicianDecisions.json'
$decisions = @()
$decisionById = @{}

Write-Host "`nClassify the numbered agents in two batches. Every number must be placed in KEEP or REMOVE before continuing." -ForegroundColor Cyan
Write-Host 'Examples: KEEP 1,3-5    KEEP NONE    REMOVE 2,6-8    REMOVE ALL    OPEN 1' -ForegroundColor Gray
Write-Host 'At either decision prompt, type OPEN followed by agent numbers to show detected installer/portable files in Downloads, Desktop, Temp, or another non-installed location. The prompt will then repeat.' -ForegroundColor Green
$keepNumbers = @()
$removeNumbers = @()
while ($true) {
    try {
        $keepAnswer = Read-CompuTekInput 'Which agent numbers should be kept? Type KEEP numbers, KEEP NONE, OPEN numbers, or Q to abort'
        if ($keepAnswer -match '^[Qq]$') { Write-Host 'Technician review aborted. Nothing was changed.' -ForegroundColor Yellow; exit 0 }
        if ($keepAnswer -match '(?i)^\s*OPEN\b') {
            $openNumbers = @(ConvertTo-CompuTekCandidateSelection -Text $keepAnswer -Maximum $candidates.Count -ExpectedAction OPEN)
            foreach ($number in $openNumbers) { Open-CandidateInstallerFiles $candidates[$number - 1] }
            continue
        }
        $keepNumbers = @(ConvertTo-CompuTekCandidateSelection -Text $keepAnswer -Maximum $candidates.Count -ExpectedAction KEEP)

        while ($true) {
            $removeAnswer = Read-CompuTekInput 'Which agent numbers should be removed? Type REMOVE numbers, REMOVE ALL, REMOVE NONE, OPEN numbers, or Q to abort'
            if ($removeAnswer -match '^[Qq]$') { Write-Host 'Technician review aborted. Nothing was changed.' -ForegroundColor Yellow; exit 0 }
            if ($removeAnswer -match '(?i)^\s*OPEN\b') {
                $openNumbers = @(ConvertTo-CompuTekCandidateSelection -Text $removeAnswer -Maximum $candidates.Count -ExpectedAction OPEN)
                foreach ($number in $openNumbers) { Open-CandidateInstallerFiles $candidates[$number - 1] }
                continue
            }
            $removeNumbers = @(ConvertTo-CompuTekCandidateSelection -Text $removeAnswer -Maximum $candidates.Count -ExpectedAction REMOVE)
            break
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host 'Re-enter both KEEP and REMOVE selections.' -ForegroundColor Yellow
        continue
    }

    $overlap = @($keepNumbers | Where-Object {$removeNumbers -contains $_})
    $classified = @($keepNumbers + $removeNumbers | Sort-Object -Unique)
    $unclassified = @(1..$candidates.Count | Where-Object {$classified -notcontains $_})
    if ($overlap.Count -gt 0) {
        Write-Host ("The same number cannot be kept and removed: {0}" -f ($overlap -join ', ')) -ForegroundColor Red
        continue
    }
    if ($unclassified.Count -gt 0) {
        Write-Host ("Every agent must be classified. Missing: {0}" -f ($unclassified -join ', ')) -ForegroundColor Yellow
        continue
    }

    Write-Host "`n================ PROPOSED DECISIONS ================" -ForegroundColor Cyan
    foreach ($candidate in $candidates) {
        $choice = if ($keepNumbers -contains $candidate.Index) {'KEEP'} else {'REMOVE'}
        $versionLabel = if ($candidate.DetectedVersion) { "version $($candidate.DetectedVersion)" } else { 'version unavailable' }
        Write-Host ("{0,2}. [{1,-6}] {2} - {3}" -f $candidate.Index,$choice,$candidate.Name,$versionLabel) -ForegroundColor $(if($choice -eq 'KEEP'){'Green'}else{'Yellow'})
    }
    $confirmationPrompt = if ($removeNumbers.Count -gt 0) {
        'Type YES to approve these decisions and remove the selected agents, R to re-enter them, or Q to abort'
    } else {
        'Type YES to approve keeping all selected agents, R to re-enter them, or Q to abort'
    }
    $decisionConfirmation = Read-CompuTekInput $confirmationPrompt
    if ($decisionConfirmation -match '^[Qq]$') { Write-Host 'Technician review aborted. Nothing was changed.' -ForegroundColor Yellow; exit 0 }
    if ($decisionConfirmation -ieq 'YES') { break }
    Write-Host 'Selections were not confirmed. Re-enter both lists.' -ForegroundColor Yellow
}

foreach ($candidate in $candidates) {
    $decision = if ($keepNumbers -contains $candidate.Index) { 'KeepApproved' } else { 'Remove' }
    $record = [pscustomobject][ordered]@{
        CandidateNumber = $candidate.Index
        CandidateId = $candidate.Id
        ProductId = $candidate.ProductId
        ProductIds = @($candidate.ProductIds)
        ProductName = $candidate.Name
        IsManagedSuite = [bool]$candidate.IsManagedSuite
        DetectedVersion = $candidate.DetectedVersion
        InstallationScope = Get-CandidateLocationLabel $candidate
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
    SchemaVersion = 3
    ComputerName = $env:COMPUTERNAME
    CaseFolder = $caseRoot
    Technician = $technicianName
    WindowsAccount = "$env:USERDOMAIN\$env:USERNAME"
    TicketOrCase = $caseReference
    RecordedAtUtc = (Get-Date).ToUniversalTime()
    EvidenceStorageSecurity = $script:EvidenceStorageSecurity
    Decisions = $decisions
}
$decisionDocument | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $decisionPath -Encoding UTF8
Write-Host "`n================ TECHNICIAN DECISIONS ================" -ForegroundColor Cyan
foreach ($record in $decisions) {
    Write-Host ("{0,2}. {1,-16} {2,-14} {3}" -f $record.CandidateNumber,$record.Decision,$record.CandidateId,$record.InstallationScope) -ForegroundColor $(if($record.Decision -eq 'Remove'){'Yellow'}else{'Green'})
}
Write-Host "Decision record: $decisionPath" -ForegroundColor DarkGray

$selected = @($candidates | Where-Object {$decisionById[$_.Id] -eq 'Remove'})
if ($selected.Count -eq 0) {
    Write-Host 'All detected installations were approved to keep. Nothing was changed.' -ForegroundColor Green
    if ($scan.IsComplete) {
        Complete-CompuTekRun 'Technician review complete. No removals were selected.'
        exit 0
    }
    Complete-CompuTekRun 'Technician review complete, but the scan was incomplete — attention is required.'
    exit 3
}

Write-Host "`n$($selected.Count) installation(s) are authorized for full removal." -ForegroundColor Yellow
Write-Host 'Logs and configuration will be preserved first. Then uninstallers, services, tasks, autoruns, packages, registrations, and residual files will be removed or quarantined.' -ForegroundColor Yellow
Write-Host 'The technician confirmed these removals with YES. Starting the approved work now.' -ForegroundColor Cyan

foreach ($candidate in $selected) {
    Write-Host "`nRemoving $($candidate.Name) from $(Get-CandidateLocationLabel $candidate)..." -ForegroundColor Magenta
    $decisionRecord = @($decisions | Where-Object {$_.CandidateId -eq $candidate.Id})[0]
    $decisionRecord.RemovalOutcome = 'RemovalAttempted'
    try {
        $sameProductKept = Test-CandidateHasKeptProductPeer -Candidate $candidate -AllCandidates $candidates -DecisionById $decisionById
        Invoke-FullCandidateRemoval -Candidate $candidate -AllowProductWideStoreFallback:(-not $sameProductKept)
    } catch {
        $decisionRecord.RemovalOutcome = 'RemovalError'
        Write-RemediationLog "Remediation failed for $($candidate.Id): $($_.Exception.Message)" 'Red'
    }
}

Write-Host "`nRe-scanning to verify the result..." -ForegroundColor Cyan
$manualRemovalItems = @()
$attentionRequired = $false
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
        if ($status -ne 'RemovalVerified') { $attentionRequired = $true }
        $remainingLocations = @($remaining | ForEach-Object {
            if ($_.ArtifactType -eq 'StartupFile' -and $_.SourcePath) { [string]$_.SourcePath }
            elseif ($_.Path) { [string]$_.Path }
            elseif ($_.InstallLocation) { [string]$_.InstallLocation }
            elseif ($_.SourcePath) { [string]$_.SourcePath }
            elseif ($_.RegistryPath) { [string]$_.RegistryPath }
        } | Where-Object {$_} | Sort-Object -Unique)
        $remainingServices = @($remaining | Where-Object {$_.ArtifactType -eq 'Service' -and $_.Name} | Select-Object -ExpandProperty Name -Unique)
        $remainingStartupItems = @($remaining | Where-Object {$_.ArtifactType -eq 'StartupFile' -and $_.SourcePath} | Select-Object -ExpandProperty SourcePath -Unique)
        $verificationSummary += [pscustomobject]@{
            CandidateId = $candidate.Id
            ProductName = $candidate.Name
            DetectedVersion = $candidate.DetectedVersion
            InstallationScope = Get-CandidateLocationLabel $candidate
            Status = $status
            RemainingFindings = $remaining.Count
            RemainingStartupItems = $remainingStartupItems.Count
            RemainingLocations = $remainingLocations -join '; '
        }
        Write-Host ("{0}: {1} ({2} remaining finding(s))" -f $candidate.Id,$status,$remaining.Count) -ForegroundColor $(if($status -eq 'RemovalVerified'){'Green'}else{'Red'})
        if ($status -ne 'RemovalVerified') {
            $manualRemovalItems += [pscustomobject][ordered]@{
                CandidateId = $candidate.Id
                ProductName = $candidate.Name
                DetectedVersion = $candidate.DetectedVersion
                Locations = $remainingLocations
                Services = $remainingServices
                StartupItems = $remainingStartupItems
                RemainingFindings = $remaining.Count
                Status = $status
            }
        }
    }
    $verificationSummary | Export-Csv -LiteralPath (Join-Path $caseRoot 'RemovalVerification.csv') -NoTypeInformation -Encoding UTF8
    $verificationSummary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $caseRoot 'RemovalVerification.json') -Encoding UTF8
    if (-not $verification.IsComplete) { Write-Host 'Verification scan was incomplete. No removal is marked verified; review its collector errors.' -ForegroundColor Red }
    Write-Host "After-remediation JSON: $($verificationPaths.Json)" -ForegroundColor DarkGray
    Write-Host "After-remediation CSV:  $($verificationPaths.Csv)" -ForegroundColor DarkGray
    Write-Host "After-remediation startup inventory: $($verificationPaths.StartupCsv)" -ForegroundColor DarkGray
    if ($verification.Stats.StartupReinstallRisks -gt 0) {
        Write-Host "$($verification.Stats.StartupReinstallRisks) startup-folder item(s) can still download or reinstall software. Review the startup inventory before rebooting." -ForegroundColor Red
    } else {
        Write-Host 'No startup-folder download/reinstall commands remain flagged.' -ForegroundColor Green
    }
} catch {
    foreach ($record in @($decisions | Where-Object {$_.Decision -eq 'Remove'})) { $record.RemovalOutcome = 'NotVerified-ScanFailed' }
    $attentionRequired = $true
    foreach ($candidate in $selected) {
        $manualRemovalItems += [pscustomobject][ordered]@{
            CandidateId = $candidate.Id
            ProductName = $candidate.Name
            DetectedVersion = $candidate.DetectedVersion
            Locations = @()
            Services = @()
            StartupItems = @()
            RemainingFindings = $null
            Status = 'NotVerified-ScanFailed'
        }
    }
    Write-RemediationLog "Verification scan failed: $($_.Exception.Message)" 'Red'
}

$manualRemovalJson = Join-Path $caseRoot 'ManualRemovalRequired.json'
$manualRemovalText = Join-Path $caseRoot 'ManualRemovalRequired.txt'
if ($manualRemovalItems.Count -gt 0) {
    $manualRemovalItems | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manualRemovalJson -Encoding UTF8
    $manualLines = @(
        'COMPUTEK TECHNICIAN FOLLOW-UP REQUIRED',
        '',
        'One or more approved removals could not be conclusively verified.',
        'Reboot and run the scanner again first. Only entries marked RemovalIncomplete with listed locations may require manual or Safe Mode removal.',
        'If status is NotVerified-ScanIncomplete or NotVerified-ScanFailed, do not manually delete files based on this report; repair the scan problem and verify again.',
        'Do not remove another approved version or an unlisted system location.',
        ''
    )
    foreach ($item in $manualRemovalItems) {
        $manualLines += ("{0} - version {1} - review ID {2} - status {3}" -f $item.ProductName,$(if($item.DetectedVersion){$item.DetectedVersion}else{'unavailable'}),$item.CandidateId,$item.Status)
        foreach ($location in @($item.Locations)) { $manualLines += ("  Location: {0}" -f $location) }
        foreach ($service in @($item.Services)) { $manualLines += ("  Service: {0}" -f $service) }
        foreach ($startupItem in @($item.StartupItems)) { $manualLines += ("  Startup item: {0}" -f $startupItem) }
        $manualLines += ''
    }
    $manualLines | Set-Content -LiteralPath $manualRemovalText -Encoding UTF8

    Write-Host "`n================ TECHNICIAN ACTION REQUIRED ================" -ForegroundColor Red
    Write-Host 'One or more removals were incomplete or could not be verified. Reboot and scan again before any manual file removal.' -ForegroundColor Red
    foreach ($item in $manualRemovalItems) {
        Write-Host ("{0} version {1}:" -f $item.ProductName,$(if($item.DetectedVersion){$item.DetectedVersion}else{'unavailable'})) -ForegroundColor Yellow
        foreach ($location in @($item.Locations | Select-Object -First 10)) { Write-Host ("    {0}" -f $location) -ForegroundColor Yellow }
        if (@($item.Locations).Count -gt 10) { Write-Host '    Additional locations are saved in the manual-removal report.' -ForegroundColor Yellow }
    }
    Write-Host "Manual-removal report: $manualRemovalText" -ForegroundColor Cyan
} else {
    @('No verified manual-removal actions are currently required.') | Set-Content -LiteralPath $manualRemovalText -Encoding UTF8
}

$decisionDocument.RecordedAtUtc = (Get-Date).ToUniversalTime()
$decisionDocument | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $decisionPath -Encoding UTF8

Write-Host "Remediation log: $remediationLog" -ForegroundColor DarkGray
Write-Host 'Reboot if requested by an uninstaller, then run this scanner again.' -ForegroundColor Yellow
Complete-CompuTekRun 'Remediation workflow complete.'
exit $(if($attentionRequired){3}else{0})
