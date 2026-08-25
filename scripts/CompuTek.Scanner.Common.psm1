Set-StrictMode -Version 2.0

$script:DefaultCatalogPath = Join-Path $PSScriptRoot 'RemoteAccessSignatures.json'
$script:CollectorWarnings = New-Object System.Collections.Generic.List[string]

function Write-CompuTekScanStage {
    param([Parameter(Mandatory)][string]$Message)

    $line = "SCAN STAGE: $Message"
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine($line)
        [Console]::Out.Flush()
    } else {
        Write-Host $line -ForegroundColor Cyan
    }
}

function Add-CompuTekCollectorWarning {
    param([string]$Message)
    if ($Message -and -not $script:CollectorWarnings.Contains($Message)) {
        $script:CollectorWarnings.Add($Message)
    }
}

function Get-CompuTekCandidateFilesSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$Extensions = @(),
        [int]$MaxDepth = -1
    )

    try {
        $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-CompuTekCollectorWarning "Skipped reparse-point scan root '$Root' to prevent a traversal loop."
            return
        }
    } catch {
        Add-CompuTekCollectorWarning "File scan root could not be opened: $Root ($($_.Exception.Message))"
        return
    }

    $extensionSet = @{}
    foreach ($extension in $Extensions) {
        if ($extension) { $extensionSet[$extension.ToLowerInvariant()] = $true }
    }

    $pending = New-Object 'System.Collections.Generic.Queue[object]'
    $pending.Enqueue([pscustomobject]@{Path=$Root;Depth=0})
    $visitedDirectories = @{}
    $filesInspected = 0
    $candidateFiles = 0
    $readErrors = 0

    while ($pending.Count -gt 0) {
        $entry = $pending.Dequeue()
        try { $directoryKey = [IO.Path]::GetFullPath([string]$entry.Path).TrimEnd('\').ToLowerInvariant() } catch { $directoryKey = ([string]$entry.Path).ToLowerInvariant() }
        if ($visitedDirectories.ContainsKey($directoryKey)) { continue }
        $visitedDirectories[$directoryKey] = $true

        $directoryErrors = @()
        $children = @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction SilentlyContinue -ErrorVariable +directoryErrors)
        $readErrors += @($directoryErrors).Count
        foreach ($child in $children) {
            if ($child.PSIsContainer) {
                if ($MaxDepth -ge 0 -and [int]$entry.Depth -ge $MaxDepth) { continue }
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $pending.Enqueue([pscustomobject]@{Path=$child.FullName;Depth=([int]$entry.Depth + 1)})
                continue
            }

            $filesInspected++
            if (($filesInspected % 2500) -eq 0) {
                Write-CompuTekScanStage -Message ("Inspected {0:N0} files under {1}" -f $filesInspected,$Root)
            }
            if ($extensionSet.Count -eq 0 -or $extensionSet.ContainsKey($child.Extension.ToLowerInvariant())) {
                $candidateFiles++
                Write-Output $child
            }
        }
    }

    if ($readErrors -gt 0) {
        Add-CompuTekCollectorWarning "Some folders under '$Root' could not be read ($readErrors access/read errors)."
    }
    Write-CompuTekScanStage -Message ("Finished {0} - inspected {1:N0} files, {2:N0} relevant file types" -f $Root,$filesInspected,$candidateFiles)
}

function ConvertTo-CompuTekArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Get-CompuTekPropertyValue {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-CompuTekCatalog {
    [CmdletBinding()]
    param([string]$Path = $script:DefaultCatalogPath)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Remote-access catalog not found: $Path"
    }

    try {
        $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Remote-access catalog is invalid JSON: $($_.Exception.Message)"
    }

    if ($catalog.schemaVersion -ne 1 -or -not $catalog.products) {
        throw "Remote-access catalog schema is unsupported or contains no products."
    }

    $ids = @{}
    foreach ($product in @($catalog.products)) {
        if (-not $product.id -or -not $product.name) {
            throw "Every catalog product must have an id and name."
        }
        $id = ([string]$product.id).ToLowerInvariant()
        if ($ids.ContainsKey($id)) { throw "Duplicate catalog product id: $id" }
        $ids[$id] = $true
    }

    return $catalog
}

function Get-CompuTekExecutablePath {
    [CmdletBinding()]
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $text = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $text = $text -replace '^\\\?\\', ''

    if ($text -match '^\s*"([^"]+\.(?:exe|com|dll))"') { return $Matches[1] }
    if ($text -match '^\s*(.+?\.(?:exe|com|dll))(?=\s|$)') { return $Matches[1].Trim('"') }
    if ($text -match '^\s*([^\s]+)') { return $Matches[1].Trim('"') }
    return $null
}

function Test-CompuTekUserWritablePath {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path).ToLowerInvariant()
    return (
        $p -match '\\users\\[^\\]+\\appdata\\' -or
        $p -match '\\users\\[^\\]+\\downloads\\' -or
        $p -match '\\users\\[^\\]+\\desktop\\' -or
        $p -match '\\windows\\temp\\' -or
        $p -match '\\temp\\' -or
        $p -match '\\public\\downloads\\'
    )
}

function Test-CompuTekProgramDataPath {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ([Environment]::ExpandEnvironmentVariables($Path).ToLowerInvariant() -match '\\programdata\\')
}

function Get-CompuTekFileEvidence {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Path,
        [switch]$IncludeHash
    )

    $result = [ordered]@{
        FileName          = $null
        Path              = $Path
        ProductName       = $null
        FileDescription   = $null
        CompanyName       = $null
        OriginalFilename  = $null
        FileVersion       = $null
        Signer            = $null
        SignatureStatus   = 'Unknown'
        Length            = $null
        CreationTimeUtc   = $null
        LastWriteTimeUtc  = $null
        SHA256            = $null
        InspectionError   = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]$result }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    $result.Path = $expanded
    $result.FileName = [IO.Path]::GetFileName($expanded)

    if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
        $result.InspectionError = 'File not found or not accessible'
        return [pscustomobject]$result
    }

    try {
        $item = Get-Item -LiteralPath $expanded -Force -ErrorAction Stop
        $result.Length = $item.Length
        $result.CreationTimeUtc = $item.CreationTimeUtc
        $result.LastWriteTimeUtc = $item.LastWriteTimeUtc

        if ($item.Extension -match '^\.(exe|dll|com|msi)$') {
            try {
                $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($expanded)
                $result.ProductName = $version.ProductName
                $result.FileDescription = $version.FileDescription
                $result.CompanyName = $version.CompanyName
                $result.OriginalFilename = $version.OriginalFilename
                $result.FileVersion = $version.FileVersion
            } catch {}

            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction Stop
                $result.SignatureStatus = [string]$signature.Status
                if ($signature.SignerCertificate) {
                    $result.Signer = [string]$signature.SignerCertificate.Subject
                }
            } catch {
                $result.SignatureStatus = 'InspectionFailed'
            }
        }

        if ($IncludeHash -and $item.Length -le 2147483648) {
            try { $result.SHA256 = (Get-FileHash -LiteralPath $expanded -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        }
    } catch {
        $result.InspectionError = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Find-CompuTekProductMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)]$Evidence
    )

    $name = ([string]$Evidence.Name).ToLowerInvariant()
    $displayName = ([string]$Evidence.DisplayName).ToLowerInvariant()
    $path = ([string]$Evidence.Path).ToLowerInvariant()
    $commandLine = ([string]$Evidence.CommandLine).ToLowerInvariant()
    $productName = ([string]$Evidence.ProductName).ToLowerInvariant()
    $description = ([string]$Evidence.FileDescription).ToLowerInvariant()
    $original = ([string]$Evidence.OriginalFilename).ToLowerInvariant()
    $packageName = ([string]$Evidence.PackageName).ToLowerInvariant()
    $fileName = if ($Evidence.FileName) { ([string]$Evidence.FileName).ToLowerInvariant() } elseif ($path) { [IO.Path]::GetFileName($path).ToLowerInvariant() } else { '' }
    $artifactType = [string]$Evidence.ArtifactType
    $textFields = @($name, $displayName, $path, $commandLine, $productName, $description, $packageName)
    $matches = @()

    foreach ($product in @($Catalog.products)) {
        $reasons = New-Object System.Collections.Generic.List[string]

        foreach ($exe in (ConvertTo-CompuTekArray $product.executables)) {
            if ($fileName -and $fileName -eq ([string]$exe).ToLowerInvariant()) {
                $reasons.Add("executable:$exe")
            }
        }
        foreach ($orig in (ConvertTo-CompuTekArray $product.originalFilenames)) {
            if ($original -and $original -eq ([string]$orig).ToLowerInvariant()) {
                $reasons.Add("original-filename:$orig")
            }
        }
        foreach ($alias in (ConvertTo-CompuTekArray $product.aliases)) {
            $needle = ([string]$alias).ToLowerInvariant()
            if (-not $needle) { continue }
            foreach ($field in $textFields) {
                if ($field -and $field.Contains($needle)) {
                    $reasons.Add("product-text:$alias")
                    break
                }
            }
        }
        if ($artifactType -eq 'Service') {
            foreach ($pattern in (ConvertTo-CompuTekArray $product.servicePatterns)) {
                if ($Evidence.Name -like $pattern -or $Evidence.DisplayName -like $pattern) {
                    $reasons.Add("service:$pattern")
                }
            }
        }
        if ($artifactType -eq 'AppxPackage') {
            foreach ($pattern in (ConvertTo-CompuTekArray $product.packagePatterns)) {
                if ($Evidence.PackageName -like $pattern -or $Evidence.DisplayName -like $pattern) {
                    $reasons.Add("package:$pattern")
                }
            }
        }
        foreach ($pattern in (ConvertTo-CompuTekArray $product.pathPatterns)) {
            if ($Evidence.Path -and $Evidence.Path -like $pattern) {
                $reasons.Add("path:$pattern")
            }
        }

        if ($reasons.Count -gt 0) {
            $uniqueReasons = @($reasons | Sort-Object -Unique)
            $matches += [pscustomobject]@{
                Product = $product
                Reasons = $uniqueReasons
                Strength = if ($uniqueReasons.Count -ge 2 -or ($uniqueReasons -match '^(original-filename|service|package|executable):')) { 'High' } else { 'Medium' }
            }
        }
    }

    return @($matches)
}

function New-CompuTekArtifact {
    param([hashtable]$Values)
    $defaults = [ordered]@{
        ArtifactType       = $null
        Source             = $null
        Name               = $null
        DisplayName        = $null
        Path               = $null
        CommandLine        = $null
        ProductName        = $null
        FileDescription    = $null
        CompanyName        = $null
        OriginalFilename   = $null
        FileName           = $null
        Signer             = $null
        SignatureStatus    = 'Unknown'
        FileVersion        = $null
        Length             = $null
        CreationTimeUtc    = $null
        LastWriteTimeUtc   = $null
        SHA256             = $null
        Publisher          = $null
        RegistryPath       = $null
        RegistryValueName  = $null
        UninstallString    = $null
        QuietUninstallString = $null
        InstallLocation    = $null
        PackageName        = $null
        PackageFullName    = $null
        TaskPath           = $null
        SourcePath         = $null
        ProcessId          = $null
        ServiceState       = $null
        ServiceStartMode   = $null
        ServiceStartName   = $null
        ConnectionCount    = 0
        RemoteEndpoints    = @()
        HeuristicReason    = $null
        HeuristicConfidence = $null
        RemediationKind    = 'ReviewOnly'
    }
    foreach ($key in $Values.Keys) { $defaults[$key] = $Values[$key] }
    return [pscustomobject]$defaults
}

function Add-CompuTekFileFields {
    param($Artifact, $FileEvidence)
    foreach ($property in 'Path','ProductName','FileDescription','CompanyName','OriginalFilename','FileName','Signer','SignatureStatus','FileVersion','Length','CreationTimeUtc','LastWriteTimeUtc','SHA256') {
        if ($FileEvidence.$property -ne $null -and $FileEvidence.$property -ne '') {
            $Artifact.$property = $FileEvidence.$property
        }
    }
    return $Artifact
}

function Get-CompuTekRegistryRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $roots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $roots.Add('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    try {
        foreach ($hive in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sid = $hive.PSChildName
            if ($sid -match '^S-1-5-21-' -and $sid -notmatch '_Classes$') {
                $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
            }
        }
    } catch { Add-CompuTekCollectorWarning "Loaded user hives could not be enumerated for uninstall entries: $($_.Exception.Message)" }
    return @($roots | Sort-Object -Unique)
}

function Get-CompuTekUninstallArtifacts {
    [CmdletBinding()]
    param()

    $items = @()
    foreach ($root in Get-CompuTekRegistryRoots) {
        try {
            if (-not (Test-Path $root -ErrorAction Stop)) { continue }
            foreach ($key in Get-ChildItem $root -ErrorAction Stop) {
                $p = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                $displayName = Get-CompuTekPropertyValue $p 'DisplayName'
                $installLocation = Get-CompuTekPropertyValue $p 'InstallLocation'
                $displayIcon = Get-CompuTekPropertyValue $p 'DisplayIcon'
                $publisher = Get-CompuTekPropertyValue $p 'Publisher'
                $uninstallString = Get-CompuTekPropertyValue $p 'UninstallString'
                $quietUninstallString = Get-CompuTekPropertyValue $p 'QuietUninstallString'
                if (-not $p -or (-not $displayName -and -not $installLocation)) { continue }
                $candidatePath = $installLocation
                if (-not $candidatePath -and $displayIcon) {
                    $candidatePath = ([string]$displayIcon -replace ',\s*-?\d+$','').Trim('"')
                }
                if (-not $candidatePath) {
                    $candidatePath = Get-CompuTekExecutablePath $uninstallString
                }
                $artifact = New-CompuTekArtifact @{
                    ArtifactType = 'InstalledProgram'; Source = 'UninstallRegistry'; Name = $displayName
                    DisplayName = $displayName; Path = $candidatePath; Publisher = $publisher
                    RegistryPath = $key.PSPath; UninstallString = $uninstallString
                    QuietUninstallString = $quietUninstallString; InstallLocation = $installLocation
                    RemediationKind = 'Uninstall'
                }
                if ($candidatePath -and (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
                    $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $candidatePath)
                }
                $items += $artifact
            }
        } catch {
            Add-CompuTekCollectorWarning "Uninstall registry root could not be read ($root): $($_.Exception.Message)"
        }
    }
    return @($items)
}

function Get-CompuTekAppxArtifacts {
    [CmdletBinding()]
    param()
    if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) { return @() }
    $items = @()
    foreach ($pkg in Get-AppxPackage -AllUsers -ErrorAction Stop) {
        $items += New-CompuTekArtifact @{
            ArtifactType = 'AppxPackage'; Source = 'Appx'; Name = $pkg.Name; DisplayName = $pkg.Name
            Path = $pkg.InstallLocation; Publisher = $pkg.Publisher; PackageName = $pkg.Name
            PackageFullName = $pkg.PackageFullName; RemediationKind = 'RemoveAppx'
        }
    }
    return @($items)
}

function Get-CompuTekTcpProcessMap {
    [CmdletBinding()]
    param()
    $map = @{}
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return $map }
    foreach ($connection in Get-NetTCPConnection -State Established -ErrorAction Stop) {
        if (-not $connection.OwningProcess) { continue }
        if ($connection.RemoteAddress -in @('127.0.0.1','::1','0.0.0.0','::')) { continue }
        $key = [string]$connection.OwningProcess
        if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
        $map[$key].Add("$($connection.RemoteAddress):$($connection.RemotePort)")
    }
    return $map
}

function Get-CompuTekProcessArtifacts {
    [CmdletBinding()]
    param([hashtable]$ConnectionMap = @{})
    $items = @()
    $processes = Get-CimInstance Win32_Process -ErrorAction Stop
    foreach ($process in $processes) {
        $path = $process.ExecutablePath
        if (-not $path) { $path = Get-CompuTekExecutablePath $process.CommandLine }
        $pidKey = [string]$process.ProcessId
        $endpoints = if ($ConnectionMap.ContainsKey($pidKey)) { @($ConnectionMap[$pidKey]) } else { @() }
        $artifact = New-CompuTekArtifact @{
            ArtifactType = 'Process'; Source = 'RunningProcesses'; Name = $process.Name
            DisplayName = $process.Name; Path = $path; CommandLine = $process.CommandLine
            ProcessId = $process.ProcessId; ConnectionCount = $endpoints.Count
            RemoteEndpoints = $endpoints; RemediationKind = 'StopProcess'
        }
        if ($path) { $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $path) }
        $items += $artifact
    }
    return @($items)
}

function Get-CompuTekServiceArtifacts {
    [CmdletBinding()]
    param()
    $items = @()
    foreach ($service in Get-CimInstance Win32_Service -ErrorAction Stop) {
        $path = Get-CompuTekExecutablePath $service.PathName
        $artifact = New-CompuTekArtifact @{
            ArtifactType = 'Service'; Source = 'WindowsServices'; Name = $service.Name
            DisplayName = $service.DisplayName; Path = $path; CommandLine = $service.PathName
            ServiceState = $service.State; ServiceStartMode = $service.StartMode
            ServiceStartName = $service.StartName; RemediationKind = 'DisableService'
        }
        if ($path) { $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $path) }
        $items += $artifact
    }
    return @($items)
}

function Get-CompuTekRunKeyRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )) { $roots.Add($root) }
    try {
        foreach ($hive in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sid = $hive.PSChildName
            if ($sid -match '^S-1-5-21-' -and $sid -notmatch '_Classes$') {
                $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            }
        }
    } catch { Add-CompuTekCollectorWarning "Loaded user hives could not be enumerated for Run/RunOnce entries: $($_.Exception.Message)" }
    return @($roots | Sort-Object -Unique)
}

function Get-CompuTekPersistenceArtifacts {
    [CmdletBinding()]
    param()
    $items = @()

    foreach ($root in Get-CompuTekRunKeyRoots) {
        try {
            if (-not (Test-Path $root -ErrorAction Stop)) { continue }
            $props = Get-ItemProperty $root -ErrorAction Stop
            foreach ($property in $props.PSObject.Properties) {
                if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                $command = [string]$property.Value
                $path = Get-CompuTekExecutablePath $command
                $artifact = New-CompuTekArtifact @{
                    ArtifactType = 'RunKey'; Source = 'RegistryAutorun'; Name = $property.Name
                    DisplayName = $property.Name; Path = $path; CommandLine = $command
                    RegistryPath = $root; RegistryValueName = $property.Name; RemediationKind = 'RemoveAutorun'
                }
                if ($path) { $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $path) }
                $items += $artifact
            }
        } catch {
            Add-CompuTekCollectorWarning "Autorun registry root could not be read ($root): $($_.Exception.Message)"
        }
    }

    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
                foreach ($action in @($task.Actions)) {
                    $execute = Get-CompuTekPropertyValue $action 'Execute'
                    $arguments = Get-CompuTekPropertyValue $action 'Arguments'
                    $command = (([string]$execute) + ' ' + ([string]$arguments)).Trim()
                    $path = Get-CompuTekExecutablePath $command
                    $artifact = New-CompuTekArtifact @{
                        ArtifactType = 'ScheduledTask'; Source = 'TaskScheduler'; Name = $task.TaskName
                        DisplayName = ($task.TaskPath + $task.TaskName); Path = $path; CommandLine = $command
                        TaskPath = $task.TaskPath
                        RemediationKind = 'DisableScheduledTask'
                    }
                    if ($path) { $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $path) }
                    $items += $artifact
                }
            }
        } catch {
            Add-CompuTekCollectorWarning "Scheduled tasks could not be fully enumerated: $($_.Exception.Message)"
        }
    } else {
        Add-CompuTekCollectorWarning 'Scheduled task cmdlets are unavailable.'
    }

    $startupFolders = New-Object System.Collections.Generic.List[string]
    $startupFolders.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))
    $profileErrors = @()
    foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable +profileErrors) {
        $startupFolders.Add((Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
    }
    if ($profileErrors.Count -gt 0) { Add-CompuTekCollectorWarning "Some user profiles could not be enumerated for Startup folders ($($profileErrors.Count) errors)." }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch {}
    foreach ($folder in @($startupFolders | Sort-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $folder -ErrorAction Stop)) { continue }
            foreach ($file in Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction Stop) {
                $target = $file.FullName
                $command = $file.FullName
                if ($shell -and $file.Extension -ieq '.lnk') {
                    try {
                        $shortcut = $shell.CreateShortcut($file.FullName)
                        $target = $shortcut.TargetPath
                        $command = ($shortcut.TargetPath + ' ' + $shortcut.Arguments).Trim()
                    } catch {}
                }
                $artifact = New-CompuTekArtifact @{
                    ArtifactType = 'StartupFile'; Source = 'StartupFolder'; Name = $file.Name
                    DisplayName = $file.Name; Path = $target; CommandLine = $command
                    SourcePath = $file.FullName
                    LastWriteTimeUtc = $file.LastWriteTimeUtc; RemediationKind = 'QuarantineFile'
                }
                if ($target -and (Test-Path -LiteralPath $target -PathType Leaf)) {
                    $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $target)
                }
                $items += $artifact
            }
        } catch {
            Add-CompuTekCollectorWarning "Startup folder could not be read ($folder): $($_.Exception.Message)"
        }
    }
    return @($items)
}

function Get-CompuTekTargetedFileArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [int]$LookbackDays = 30,
        [switch]$DeepScan
    )

    $cutoff = (Get-Date).ToUniversalTime().AddDays(-1 * [Math]::Abs($LookbackDays))
    $roots = New-Object System.Collections.Generic.List[string]
    if ($DeepScan) {
        foreach ($volume in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue) {
            if ($volume.DeviceID) { $roots.Add(($volume.DeviceID + '\')) }
        }
    } else {
        $profileErrors = @()
        foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable +profileErrors) {
            if (($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            foreach ($relative in @('AppData\Local','AppData\Roaming','Downloads','Desktop')) {
                $candidate = Join-Path $profile.FullName $relative
                if (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue) { $roots.Add($candidate) }
            }
        }
        if ($profileErrors.Count -gt 0) { Add-CompuTekCollectorWarning "Some user profiles could not be enumerated for the targeted file scan ($($profileErrors.Count) errors)." }
        foreach ($candidate in @($env:ProgramData, (Join-Path $env:SystemRoot 'Temp'))) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) { $roots.Add($candidate) }
        }
    }

    $extensions = @('.exe','.com','.dll','.msi','.msix','.appx','.lnk','.bat','.cmd','.ps1','.vbs','.js','.zip','.rar','.7z')
    $excludedPrefixes = @(
        (Join-Path $env:ProgramData 'CompuTek\RemoteScanner\Quarantine'),
        (Join-Path $env:ProgramData 'CompuTek\RemoteScanner\Cases'),
        (Join-Path $env:ProgramData 'CompuTek\PostScam\Cases')
    ) | ForEach-Object { ([string]$_).TrimEnd('\').ToLowerInvariant() + '\' }
    $items = @()
    $seen = @{}
    $maxDepth = if ($DeepScan) { -1 } else { 5 }
    foreach ($root in @($roots | Sort-Object -Unique)) {
        Write-CompuTekScanStage -Message ("Inspecting files under {0} ({1})" -f $root,$(if($DeepScan){'full depth'}else{'targeted depth'}))
        foreach ($file in Get-CompuTekCandidateFilesSafe -Root $root -Extensions $extensions -MaxDepth $maxDepth) {
            $lowerPath = $file.FullName.ToLowerInvariant()
            $excluded = $false
            foreach ($prefix in $excludedPrefixes) {
                if ($lowerPath.StartsWith($prefix)) { $excluded = $true; break }
            }
            if ($excluded) { continue }
            $key = $file.FullName.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $artifact = New-CompuTekArtifact @{
                ArtifactType = 'File'; Source = if ($DeepScan) { 'DeepFileScan' } else { 'TargetedFileScan' }
                Name = $file.Name; DisplayName = $file.Name; FileName = $file.Name; Path = $file.FullName
                Length = $file.Length; CreationTimeUtc = $file.CreationTimeUtc; LastWriteTimeUtc = $file.LastWriteTimeUtc
                RemediationKind = 'QuarantineFile'
            }
            $fastMatches = @(Find-CompuTekProductMatch -Catalog $Catalog -Evidence $artifact)
            $recentExecutable = ($file.Extension -match '^\.(exe|com|dll|msi)$' -and $file.LastWriteTimeUtc -ge $cutoff)
            if ($fastMatches.Count -eq 0 -and -not $recentExecutable) { continue }

            if ($file.Extension -match '^\.(exe|com|dll|msi)$') {
                $artifact = Add-CompuTekFileFields $artifact (Get-CompuTekFileEvidence $file.FullName)
            }
            $matches = @(Find-CompuTekProductMatch -Catalog $Catalog -Evidence $artifact)
            if ($matches.Count -gt 0) {
                $items += $artifact
                continue
            }

            if ($recentExecutable -and (Test-CompuTekUserWritablePath $file.FullName) -and $artifact.SignatureStatus -notin @('Valid','Unknown')) {
                $artifact.HeuristicReason = 'Recent unsigned or invalidly signed executable in a user-writable location'
                $artifact.HeuristicConfidence = 'Low'
                $items += $artifact
            }
        }
    }
    return @($items)
}

function Get-CompuTekNativeFeatureArtifacts {
    [CmdletBinding()]
    param()
    $items = @()

    try {
        $terminal = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        if ($terminal.fDenyTSConnections -eq 0) {
            $items += New-CompuTekArtifact @{
                ArtifactType = 'NativeFeature'; Source = 'WindowsConfiguration'; Name = 'Windows Remote Desktop'
                DisplayName = 'Windows Remote Desktop is enabled'; ProductName = 'Windows Remote Desktop (RDP)'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                HeuristicReason = 'fDenyTSConnections=0'; RemediationKind = 'DisableNativeFeature'
            }
        }
    } catch {}
    try {
        $assistance = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction Stop
        if ($assistance.fAllowToGetHelp -eq 1 -or $assistance.fAllowFullControl -eq 1) {
            $items += New-CompuTekArtifact @{
                ArtifactType = 'NativeFeature'; Source = 'WindowsConfiguration'; Name = 'Windows Remote Assistance'
                DisplayName = 'Windows Remote Assistance is enabled'; ProductName = 'Windows Remote Assistance'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
                HeuristicReason = 'Remote Assistance policy permits connections'; RemediationKind = 'DisableNativeFeature'
            }
        }
    } catch {}
    try {
        $winrm = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        if ($winrm -and $winrm.State -eq 'Running') {
            $items += New-CompuTekArtifact @{
                ArtifactType = 'NativeFeature'; Source = 'WindowsConfiguration'; Name = 'Windows Remote Management'
                DisplayName = 'Windows Remote Management service is running'; ProductName = 'Windows Remote Management (WinRM)'
                ServiceState = $winrm.State; ServiceStartMode = $winrm.StartMode; RemediationKind = 'DisableNativeFeature'
            }
        }
    } catch {}
    return @($items)
}

function ConvertTo-CompuTekFinding {
    param($Artifact, $Match, [string]$Disposition, [string]$Confidence, [string]$EvidenceText)
    $product = if ($Match) { $Match.Product } else { $null }
    return [pscustomobject][ordered]@{
        ProductId            = if ($product) { $product.id } else { 'unknown' }
        ProductName          = if ($product) { $product.name } else { 'Unknown suspicious remote-capable artifact' }
        Category             = if ($product) { $product.category } else { 'unknown' }
        Confidence           = $Confidence
        Disposition          = $Disposition
        Evidence             = $EvidenceText
        ArtifactType         = $Artifact.ArtifactType
        Source               = $Artifact.Source
        Name                 = $Artifact.Name
        DisplayName          = $Artifact.DisplayName
        Path                 = $Artifact.Path
        CommandLine          = $Artifact.CommandLine
        ProductMetadata      = $Artifact.ProductName
        FileDescription      = $Artifact.FileDescription
        CompanyName          = $Artifact.CompanyName
        OriginalFilename     = $Artifact.OriginalFilename
        Signer               = $Artifact.Signer
        SignatureStatus      = $Artifact.SignatureStatus
        FileVersion          = $Artifact.FileVersion
        SHA256               = $Artifact.SHA256
        Publisher            = $Artifact.Publisher
        RegistryPath         = $Artifact.RegistryPath
        RegistryValueName    = $Artifact.RegistryValueName
        UninstallString      = $Artifact.UninstallString
        QuietUninstallString = $Artifact.QuietUninstallString
        InstallLocation      = $Artifact.InstallLocation
        PackageName          = $Artifact.PackageName
        PackageFullName      = $Artifact.PackageFullName
        TaskPath             = $Artifact.TaskPath
        SourcePath           = $Artifact.SourcePath
        ProcessId            = $Artifact.ProcessId
        ServiceState         = $Artifact.ServiceState
        ServiceStartMode     = $Artifact.ServiceStartMode
        ConnectionCount      = $Artifact.ConnectionCount
        RemoteEndpoints      = @($Artifact.RemoteEndpoints)
        CreationTimeUtc      = $Artifact.CreationTimeUtc
        LastWriteTimeUtc     = $Artifact.LastWriteTimeUtc
        RemediationKind      = $Artifact.RemediationKind
    }
}

function Invoke-CompuTekRemoteAccessScan {
    [CmdletBinding()]
    param(
        [string]$CatalogPath = $script:DefaultCatalogPath,
        [int]$LookbackDays = 30,
        [switch]$DeepScan,
        [switch]$IncludeHashes
    )

    $started = (Get-Date).ToUniversalTime()
    $script:CollectorWarnings.Clear()
    $errors = New-Object System.Collections.Generic.List[string]
    $findings = New-Object System.Collections.Generic.List[object]
    $artifacts = New-Object System.Collections.Generic.List[object]
    Write-CompuTekScanStage -Message 'Step 1 of 10 - validating the remote-software catalog'
    $catalog = Get-CompuTekCatalog -Path $CatalogPath

    $connectionMap = @{}
    Write-CompuTekScanStage -Message 'Step 2 of 10 - mapping active network connections'
    try { $connectionMap = Get-CompuTekTcpProcessMap } catch { $errors.Add("TCP connection inventory failed: $($_.Exception.Message)") }

    $collectorNumber = 2
    foreach ($collector in @(
        @{Name='uninstall registry'; Run={ Get-CompuTekUninstallArtifacts }},
        @{Name='AppX packages'; Run={ Get-CompuTekAppxArtifacts }},
        @{Name='services'; Run={ Get-CompuTekServiceArtifacts }},
        @{Name='processes'; Run={ Get-CompuTekProcessArtifacts -ConnectionMap $connectionMap }},
        @{Name='persistence'; Run={ Get-CompuTekPersistenceArtifacts }},
        @{Name='native remote features'; Run={ Get-CompuTekNativeFeatureArtifacts }},
        @{Name='targeted files'; Run={ Get-CompuTekTargetedFileArtifacts -Catalog $catalog -LookbackDays $LookbackDays -DeepScan:$DeepScan }}
    )) {
        $collectorNumber++
        Write-CompuTekScanStage -Message ("Step {0} of 10 - collecting {1}" -f $collectorNumber,$collector.Name)
        try {
            foreach ($artifact in & $collector.Run) { if ($artifact) { $artifacts.Add($artifact) } }
        } catch {
            $errors.Add("$($collector.Name) inventory failed: $($_.Exception.Message)")
        }
    }
    foreach ($warning in @($script:CollectorWarnings)) {
        if (-not $errors.Contains($warning)) { $errors.Add($warning) }
    }

    Write-CompuTekScanStage -Message ("Step 10 of 10 - analyzing {0} collected artifacts" -f $artifacts.Count)
    $dedupe = @{}
    foreach ($artifact in $artifacts) {
        if ($IncludeHashes -and $artifact.Path -and -not $artifact.SHA256 -and (Test-Path -LiteralPath $artifact.Path -PathType Leaf)) {
            $withHash = Get-CompuTekFileEvidence -Path $artifact.Path -IncludeHash
            if ($withHash.SHA256) { $artifact.SHA256 = $withHash.SHA256 }
        }

        $matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $artifact)
        foreach ($match in $matches) {
            if ($match.Product.id -eq 'windows-rdp' -and $artifact.ArtifactType -eq 'Service') { continue }
            if ($match.Product.id -eq 'windows-winrm' -and $artifact.ArtifactType -eq 'Service' -and $artifact.ServiceState -ne 'Running') { continue }

            $disposition = if ($match.Product.category -eq 'native-feature') { 'RemoteFeatureEnabledOrInstalled' } else { 'KnownRemoteAccessSoftware' }
            $evidenceText = (@($match.Reasons) -join '; ')
            $finding = ConvertTo-CompuTekFinding $artifact $match $disposition $match.Strength $evidenceText
            $key = ("{0}|{1}|{2}|{3}" -f $finding.ProductId,$finding.ArtifactType,$finding.Name,$finding.Path).ToLowerInvariant()
            if (-not $dedupe.ContainsKey($key)) { $dedupe[$key] = $true; $findings.Add($finding) }
        }

        if ($matches.Count -gt 0) { continue }
        $reason = $null
        $confidence = $null
        if ($artifact.ArtifactType -eq 'Service' -and (Test-CompuTekUserWritablePath $artifact.Path)) {
            $reason = 'Service executable is in a user-writable AppData, Downloads, Desktop, or Temp location'
            $confidence = 'High'
        } elseif ($artifact.ArtifactType -eq 'Service' -and (Test-CompuTekProgramDataPath $artifact.Path) -and $artifact.SignatureStatus -notin @('Valid','Unknown')) {
            $reason = 'Unsigned or invalidly signed service executable is under ProgramData'
            $confidence = 'Medium'
        } elseif ($artifact.ArtifactType -in @('RunKey','ScheduledTask','StartupFile') -and (Test-CompuTekUserWritablePath $artifact.Path)) {
            $reason = 'Persistence launches an executable from a user-writable location'
            $confidence = 'Medium'
        } elseif ($artifact.ArtifactType -eq 'Process' -and (Test-CompuTekUserWritablePath $artifact.Path) -and $artifact.ConnectionCount -gt 0) {
            $reason = 'Running executable in a user-writable location has active network connections'
            $confidence = 'Medium'
        } elseif ($artifact.HeuristicReason) {
            $reason = $artifact.HeuristicReason
            $confidence = $artifact.HeuristicConfidence
        }

        if ($reason) {
            $finding = ConvertTo-CompuTekFinding $artifact $null 'SuspiciousUnknown' $confidence $reason
            $key = ("unknown|{0}|{1}|{2}" -f $finding.ArtifactType,$finding.Name,$finding.Path).ToLowerInvariant()
            if (-not $dedupe.ContainsKey($key)) { $dedupe[$key] = $true; $findings.Add($finding) }
        }
    }

    $completed = (Get-Date).ToUniversalTime()
    $errorArray = $errors.ToArray()
    $findingArray = $findings.ToArray()
    return [pscustomobject][ordered]@{
        SchemaVersion = 1
        CatalogVersion = $catalog.catalogVersion
        ComputerName = $env:COMPUTERNAME
        StartedAtUtc = $started
        CompletedAtUtc = $completed
        DeepScan = [bool]$DeepScan
        LookbackDays = $LookbackDays
        IsComplete = ($errors.Count -eq 0)
        Errors = $errorArray
        Findings = $findingArray
        Stats = [pscustomobject]@{
            ArtifactsInspected = $artifacts.Count
            Findings = $findings.Count
            KnownProducts = @($findingArray | Where-Object {$_.Disposition -eq 'KnownRemoteAccessSoftware'} | Select-Object -ExpandProperty ProductId -Unique).Count
            NativeFeatures = @($findingArray | Where-Object {$_.Disposition -eq 'RemoteFeatureEnabledOrInstalled'} | Select-Object -ExpandProperty ProductId -Unique).Count
            SuspiciousUnknown = @($findingArray | Where-Object {$_.Disposition -eq 'SuspiciousUnknown'}).Count
            CollectorErrors = $errors.Count
        }
    }
}

function Export-CompuTekScanReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Scan,
        [Parameter(Mandatory)][string]$Directory,
        [string]$BaseName = 'RemoteAccessScan'
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $jsonPath = Join-Path $Directory ($BaseName + '.json')
    $csvPath = Join-Path $Directory ($BaseName + '.csv')
    $Scan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    @($Scan.Findings) | Select-Object ProductId,ProductName,Category,Confidence,Disposition,Evidence,ArtifactType,Source,Name,Path,SourcePath,TaskPath,CommandLine,OriginalFilename,CompanyName,Signer,SignatureStatus,RegistryPath,PackageFullName,ServiceState,ServiceStartMode,ConnectionCount,@{Name='RemoteEndpoints';Expression={@($_.RemoteEndpoints) -join ';'}} | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    return [pscustomobject]@{Json=$jsonPath;Csv=$csvPath}
}

function Split-CompuTekUninstallCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)
    $expanded = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($expanded -match '(?i)msiexec(?:\.exe)?\s+.*?({[0-9a-f-]{36}})') {
        return [pscustomobject]@{FilePath='msiexec.exe';Arguments=@('/x',$Matches[1],'/qn','/norestart');Kind='MSI'}
    }
    if ($expanded -match '^\s*"([^"]+\.exe)"\s*(.*)$') {
        return [pscustomobject]@{FilePath=$Matches[1];Arguments=@($Matches[2]);Kind='EXE'}
    }
    if ($expanded -match '^\s*(.+?\.exe)\s*(.*)$') {
        return [pscustomobject]@{FilePath=$Matches[1].Trim();Arguments=@($Matches[2]);Kind='EXE'}
    }
    $parts = $expanded -split '\s+',2
    return [pscustomobject]@{FilePath=$parts[0];Arguments=if($parts.Count -gt 1){@($parts[1])}else{@()};Kind='EXE'}
}

function Invoke-CompuTekUninstallCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)
    $parsed = Split-CompuTekUninstallCommand -Command $Command
    $filePath = $parsed.FilePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        $resolved = Get-Command $filePath -ErrorAction SilentlyContinue
        if ($resolved) { $filePath = $resolved.Source } else { throw "Uninstaller executable was not found: $($parsed.FilePath)" }
    }
    $arguments = @($parsed.Arguments | Where-Object { $_ -ne $null -and $_ -ne '' })
    $process = Start-Process -FilePath $filePath -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
    return [pscustomobject]@{
        FilePath = $filePath
        Arguments = $arguments
        ExitCode = $process.ExitCode
        Success = ($process.ExitCode -in @(0,1605,1614,1641,3010))
        RebootRequired = ($process.ExitCode -in @(1641,3010))
    }
}

Export-ModuleMember -Function @(
    'Get-CompuTekCatalog',
    'Get-CompuTekExecutablePath',
    'Test-CompuTekUserWritablePath',
    'Get-CompuTekFileEvidence',
    'Get-CompuTekCandidateFilesSafe',
    'Find-CompuTekProductMatch',
    'Get-CompuTekUninstallArtifacts',
    'Get-CompuTekProcessArtifacts',
    'Get-CompuTekServiceArtifacts',
    'Get-CompuTekPersistenceArtifacts',
    'Get-CompuTekTcpProcessMap',
    'Invoke-CompuTekRemoteAccessScan',
    'Export-CompuTekScanReport',
    'Split-CompuTekUninstallCommand',
    'Invoke-CompuTekUninstallCommand'
)
