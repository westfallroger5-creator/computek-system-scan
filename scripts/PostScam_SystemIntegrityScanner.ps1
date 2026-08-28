<#
 PostScam_SystemIntegrityScanner.ps1

 Read-only post-scam evidence collection for Windows workstations.
 This script does not claim to prove which files were stolen. It gathers the local
 evidence Windows still has: remote-access artifacts, persistence, remote sessions,
 account changes, suspicious execution, Defender changes, active connections,
 possible transfer/staging artifacts, recent-file links, and file-access audit events.

 No services, files, tasks, accounts, firewall rules, or registry values are changed.
#>

[CmdletBinding()]
param(
    [ValidateRange(1,365)][int]$LookbackDays = 7,
    [switch]$DeepScan,
    [switch]$IncludeFileHashes,
    [switch]$ExtendedForensics
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
    param([string]$Message = 'Complete')
    Write-Host $Message -ForegroundColor Green
    if ($env:COMPUTEK_SCANNER_APP -ne '1') { [void](Read-Host 'Press Enter to close') }
}

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-LookbackDays',[string]$LookbackDays)
    if ($DeepScan) { $arguments += '-DeepScan' }
    if ($IncludeFileHashes) { $arguments += '-IncludeFileHashes' }
    if ($ExtendedForensics) { $arguments += '-ExtendedForensics' }
    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
    exit
}

$modulePath = Join-Path $PSScriptRoot 'CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $PSScriptRoot 'RemoteAccessSignatures.json'
Import-Module $modulePath -Force -ErrorAction Stop
$catalog = Get-CompuTekCatalog -Path $catalogPath

$started = Get-Date
$cutoff = $started.AddDays(-1 * [Math]::Abs($LookbackDays))
$timestamp = $started.ToString('yyyyMMdd_HHmmss')
$portableRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) { $env:COMPUTEK_SCANNER_PORTABLE_ROOT } else { $PSScriptRoot }
$caseRoot = Join-Path $portableRoot ("CompuTekData\{0}\PostScam\Cases\{1}" -f $env:COMPUTERNAME,$timestamp)
New-Item -Path $caseRoot -ItemType Directory -Force | Out-Null

$script:Evidence = New-Object System.Collections.Generic.List[object]
$script:Supplemental = New-Object System.Collections.Generic.List[object]
$script:Gaps = New-Object System.Collections.Generic.List[string]
$script:TextLog = Join-Path $caseRoot 'PostScam_Audit.log'
$script:ActionableCategories = @(
    'RemoteAccess','PersistenceEvent','SecurityEvent','RemoteSession','SuspiciousExecution',
    'SecurityControl','SysmonEvidence','Persistence','WmiPersistence','RegistryBackdoor',
    'RemoteAccessKey','NetworkConnection','FirewallBackdoor','NetworkConfiguration',
    'BrowserExtension','ExecutionArtifact'
)

$remoteTerms = @($catalog.products | ForEach-Object { @($_.aliases) + @($_.executables) } | Where-Object {$_} | ForEach-Object {[regex]::Escape([string]$_)} | Sort-Object -Unique)
$remoteRegex = if ($remoteTerms.Count -gt 0) { '(?i)(' + ($remoteTerms -join '|') + ')' } else { '(?!)' }
$suspiciousCommandRegex = '(?i)(downloadstring|invoke-expression|\biex\b|frombase64string|encodedcommand|invoke-webrequest|\bcurl(?:\.exe)?\b|\bwget\b|bitsadmin|certutil|mshta|regsvr32|rundll32|comsvcs|installutil|wmic|psexec|procdump|mimikatz|nanodump|secretsdump|browserpassview|webbrowserpassview|rclone|megacmd|megasync|winscp|pscp|compress-archive|7z(?:\.exe)?|rar(?:\.exe)?|tar(?:\.exe)?)'
$script:PostScamUserWritableTextRegex = '(?i)\\users\\[^\\]+\\(?:appdata|downloads|desktop)\\|\\windows\\temp\\'
$script:PostScamTrustedMicrosoftPathRegex = '(?i)[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\microsoft\\(?:(?:teams\\(?:current\\teams|update))|(?:onedrive\\(?:(?:\d+(?:\.\d+)+\\)?(?:onedrive|onedrivelauncher|onedrivestandaloneupdater|filecoauth)))|(?:windowsapps\\ms-teams))\.exe'

function Test-CompuTekPostScamUserWritableRisk {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -notmatch $script:PostScamUserWritableTextRegex) { return $false }

    $untrustedText = [string]$Text
    foreach ($match in [regex]::Matches($Text,$script:PostScamTrustedMicrosoftPathRegex)) {
        $candidatePath = [string]$match.Value
        if (Test-CompuTekTrustedMicrosoftApplication -Path $candidatePath) {
            $untrustedText = $untrustedText.Replace($candidatePath,'<trusted-microsoft-application>')
        }
    }
    return ($untrustedText -match $script:PostScamUserWritableTextRegex)
}

function Test-CompuTekPostScamPersistenceText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return (
        $Text -match $remoteRegex -or
        $Text -match $suspiciousCommandRegex -or
        (Test-CompuTekPostScamUserWritableRisk $Text)
    )
}

function Write-Audit {
    param([string]$Message, [string]$Color = 'Gray')
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
    $line | Out-File -LiteralPath $script:TextLog -Append -Encoding UTF8
    Write-Host $Message -ForegroundColor $Color
}

function Add-Gap {
    param([string]$Message)
    if (-not $script:Gaps.Contains($Message)) { $script:Gaps.Add($Message) }
    $line = '[{0}] COLLECTION GAP: {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
    $line | Out-File -LiteralPath $script:TextLog -Append -Encoding UTF8
}

function Add-Evidence {
    param(
        [string]$Category,
        [ValidateSet('High','Medium','Review','Informational')][string]$Severity = 'Review',
        [string]$Name,
        [string]$Details,
        [Nullable[datetime]]$TimeCreated,
        [string]$Path,
        [string]$User,
        [string]$Source,
        [Nullable[int]]$EventId,
        $Data
    )
    $record = [pscustomobject][ordered]@{
        Category = $Category
        Severity = $Severity
        TimeCreatedUtc = if ($TimeCreated) { $TimeCreated.ToUniversalTime() } else { $null }
        Name = $Name
        Details = $Details
        Path = $Path
        User = $User
        Source = $Source
        EventId = $EventId
        Data = $Data
    }
    $isActionable = ($Severity -in @('High','Medium') -and $Category -in $script:ActionableCategories)
    if ($isActionable) { $script:Evidence.Add($record) } else { $script:Supplemental.Add($record) }
}

function Get-TruncatedText {
    param([AllowNull()][string]$Text, [int]$Maximum = 5000)
    if ($null -eq $Text) { return '' }
    $clean = $Text -replace "`0",''
    if ($clean.Length -gt $Maximum) { return $clean.Substring(0,$Maximum) + '...[truncated]' }
    return $clean
}

function Protect-CommandText {
    param([string]$Text)
    $redacted = $Text -replace '(?i)((?:password|passwd|token|api[_-]?key|authorization|secret)\s*[:=]\s*)[^\s;]+','$1<redacted>'
    $redacted = $redacted -replace '(?i)([?&](?:password|token|key|auth|authorization|session|code|secret)=)[^&\s]+','$1<redacted>'
    return Get-TruncatedText $redacted 3000
}

function Get-EventDataMap {
    param($Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            $name = [string]$node.Name
            if (-not $name) { $name = "Data$($map.Count)" }
            $map[$name] = [string]$node.'#text'
        }
    } catch {}
    return $map
}

function Get-EventMessage {
    param($Event)
    try { return Get-TruncatedText ([string]$Event.Message) 5000 } catch { return "Event record ID $($Event.RecordId); message resource unavailable" }
}

function Get-RecentEvents {
    param([string]$LogName, [int[]]$Ids, [int]$Maximum = 2000)
    try {
        return @(Get-WinEvent -FilterHashtable @{LogName=$LogName;StartTime=$cutoff;Id=$Ids} -MaxEvents $Maximum -ErrorAction Stop)
    } catch {
        Add-Gap "Event log '$LogName' could not be queried for IDs $($Ids -join ','): $($_.Exception.Message)"
        return @()
    }
}

function Add-WindowsEventEvidence {
    param($Event, [string]$Category, [string]$Severity, [string]$Name, $Data)
    Add-Evidence -Category $Category -Severity $Severity -Name $Name -Details (Get-EventMessage $Event) -TimeCreated $Event.TimeCreated -Source $Event.LogName -EventId $Event.Id -Data $Data
}

function Get-RecentFileCandidates {
    param([string[]]$Extensions, [switch]$OnlyTempAndAppData)
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
        if (($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $relativePaths = if ($OnlyTempAndAppData) { @('AppData\Local\Temp','AppData\Roaming') } else { @('Desktop','Documents','Downloads','OneDrive','AppData\Local\Temp') }
        foreach ($relative in $relativePaths) {
            $candidate = Join-Path $profile.FullName $relative
            if (Test-Path -LiteralPath $candidate) { $roots.Add($candidate) }
        }
    }
    if (Test-Path (Join-Path $env:SystemRoot 'Temp')) { $roots.Add((Join-Path $env:SystemRoot 'Temp')) }
    $seen = @{}
    $maxDepth = if ($DeepScan) { -1 } else { 5 }
    foreach ($root in @($roots | Sort-Object -Unique)) {
        foreach ($file in Get-CompuTekCandidateFilesSafe -Root $root -Extensions $Extensions -MaxDepth $maxDepth) {
            if ($file.LastWriteTime -lt $cutoff -and $file.CreationTime -lt $cutoff) { continue }
            if ($seen.ContainsKey($file.FullName)) { continue }
            $seen[$file.FullName] = $true
            Write-Output $file
        }
    }
}

Clear-Host
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host '  CompuTek Post-Scam System Integrity and Evidence Scanner' -ForegroundColor Cyan
Write-Host '================================================================' -ForegroundColor Cyan
Write-Audit "Computer: $env:COMPUTERNAME"
Write-Audit "Lookback: $LookbackDays days (since $($cutoff.ToString('u')))"
Write-Audit "Catalog: $($catalog.catalogVersion) ($(@($catalog.products).Count) product families)"
Write-Audit "Case folder: $caseRoot"
Write-Audit 'This is a read-only collection. A missing audit trail does not prove an action did not occur.' 'Yellow'

# ------------------ REMOTE ACCESS INVENTORY ------------------
Write-Audit "`n[1/12] Remote-access software, processes, services, persistence, and files" 'Cyan'
try {
    $remoteScan = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays $LookbackDays -DeepScan:$DeepScan -IncludeHashes:$IncludeFileHashes
    $remoteReports = Export-CompuTekScanReport -Scan $remoteScan -Directory $caseRoot -BaseName 'RemoteAccessInventory'
    foreach ($finding in @($remoteScan.Findings)) {
        $isUserWritable = $finding.Path -and (Test-CompuTekUserWritablePath $finding.Path)
        $isTrustedMicrosoftApp = Test-CompuTekTrustedMicrosoftApplication -Path $finding.Path -CompanyName $finding.CompanyName -Signer $finding.Signer -SignatureStatus $finding.SignatureStatus -ArtifactType $finding.ArtifactType -Name $finding.Name -CommandLine $finding.CommandLine
        $isPersistence = $finding.ArtifactType -in @('Service','RunKey','ScheduledTask','StartupFile','NativeFeature')
        $isActionableRemote = (
            ($finding.ProductId -eq 'unknown' -and -not $isTrustedMicrosoftApp -and $finding.Confidence -in @('High','Medium')) -or
            $finding.Category -eq 'native-feature' -or
            ($finding.ProductId -ne 'unknown' -and $isUserWritable -and ($isPersistence -or $finding.ConnectionCount -gt 0))
        )
        $severity = if ($isActionableRemote -and $finding.Confidence -eq 'High') {'High'} elseif ($isActionableRemote) {'Medium'} else {'Informational'}
        Add-Evidence -Category 'RemoteAccess' -Severity $severity -Name $finding.ProductName -Details ("{0}; {1}; artifact={2}; original={3}; signer={4}; signature={5}" -f $finding.Disposition,$finding.Evidence,$finding.ArtifactType,$finding.OriginalFilename,$finding.Signer,$finding.SignatureStatus) -Path $finding.Path -Source $finding.Source -Data $finding
    }

    if ($ExtendedForensics) {
        # Optional deep evidence inventory. This is deliberately excluded from the
        # concise actionable list because legitimate support products can have
        # hundreds of configuration and log files.
        $configurationDirectories = @{}
        foreach ($finding in @($remoteScan.Findings | Where-Object {$_.ProductId -ne 'unknown' -and $_.Path})) {
            $directory = if (Test-Path -LiteralPath $finding.Path -PathType Container -ErrorAction SilentlyContinue) { $finding.Path } else { Split-Path -Parent $finding.Path }
            if (-not $directory -or -not (Test-Path -LiteralPath $directory -PathType Container -ErrorAction SilentlyContinue)) { continue }
            $configurationDirectories[$directory.TrimEnd('\').ToLowerInvariant()] = [pscustomobject]@{Path=$directory;ProductId=$finding.ProductId;ProductName=$finding.ProductName}
        }
        foreach ($entry in $configurationDirectories.Values) {
            foreach ($file in @(Get-CompuTekCandidateFilesSafe -Root $entry.Path -Extensions @('.config','.conf','.ini','.xml','.json','.log','.txt','.db') -MaxDepth 4 | Select-Object -First 100)) {
                $fileEvidence = Get-CompuTekFileEvidence -Path $file.FullName -IncludeHash:$IncludeFileHashes
                Add-Evidence -Category 'RemoteAccessConfiguration' -Severity 'Informational' -Name "$($entry.ProductName) configuration/log artifact" -Details ("size={0}; modified={1:u}; SHA256={2}" -f $file.Length,$file.LastWriteTime,$fileEvidence.SHA256) -TimeCreated $file.LastWriteTime -Path $file.FullName -Source 'Remote product directory' -Data @{ProductId=$entry.ProductId;SHA256=$fileEvidence.SHA256}
            }
        }
    }

    try {
        $servicesRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        foreach ($key in Get-ChildItem $servicesRoot -ErrorAction Stop | Where-Object {$_.PSChildName -like 'ScreenConnect Client*'}) {
            $values = Get-ItemProperty $key.PSPath -ErrorAction Stop
            $details = Protect-CommandText (Get-TruncatedText ($values | Select-Object DisplayName,ImagePath,ObjectName,Start,Description | Out-String) 4000)
            $serviceExecutable = Get-CompuTekExecutablePath ([string]$values.ImagePath)
            $severity = if ($serviceExecutable -and (Test-CompuTekUserWritablePath $serviceExecutable)) {'High'} else {'Informational'}
            Add-Evidence -Category $(if($severity -eq 'High'){'RemoteAccess'}else{'RemoteAccessConfiguration'}) -Severity $severity -Name "ScreenConnect service registry: $($key.PSChildName)" -Details $details -Path $serviceExecutable -Source 'Registry' -Data $null
        }
    } catch { Add-Gap "ScreenConnect service registry details could not be collected: $($_.Exception.Message)" }

    foreach ($errorMessage in @($remoteScan.Errors)) { Add-Gap "Remote-access collector: $errorMessage" }
    foreach ($warningMessage in @($remoteScan.Warnings)) { Add-Gap "Remote-access collector note: $warningMessage" }
    $actionableRemoteCount = @($script:Evidence | Where-Object {$_.Category -eq 'RemoteAccess'}).Count
    Write-Audit "Remote-access inventory saved. Actionable persistence/hidden-access findings: $actionableRemoteCount" $(if($actionableRemoteCount){'Yellow'}else{'Green'})
} catch {
    Add-Gap "Remote-access scan failed: $($_.Exception.Message)"
}

# ------------------ WINDOWS EVENT LOGS ------------------
Write-Audit "`n[2/12] Service, task, account, logon, and audit-log events" 'Cyan'
foreach ($event in Get-RecentEvents -LogName 'System' -Ids @(7040,7045) -Maximum 2000) {
    $data = Get-EventDataMap $event
    $eventText = (Get-EventMessage $event) + ' ' + (($data.Values | ForEach-Object {[string]$_}) -join ' ')
    $suspiciousPersistence = Test-CompuTekPostScamPersistenceText $eventText
    if ($suspiciousPersistence -or $event.Id -eq 7045) {
        $severity = if ($suspiciousPersistence) {'High'} else {'Review'}
        Add-WindowsEventEvidence $event 'PersistenceEvent' $severity "System event $($event.Id): service installed or suspiciously changed" $data
    }
}

$securityIds = @(1102,4624,4648,4672,4688,4697,4698,4720,4722,4728,4732,4756)
foreach ($event in Get-RecentEvents -LogName 'Security' -Ids $securityIds -Maximum 5000) {
    $data = Get-EventDataMap $event
    $include = $false
    $severity = 'Medium'
    $name = "Security event $($event.Id)"
    $eventText = (Get-EventMessage $event) + ' ' + (($data.Values | ForEach-Object {[string]$_}) -join ' ')
    switch ($event.Id) {
        1102 { $include=$true; $severity='High'; $name='Windows audit log was cleared' }
        4624 {
            $logonType = [string]$data['LogonType']
            $include = ($logonType -eq '10')
            $severity = 'High'
            $name = 'Successful Remote Desktop logon'
        }
        4648 {
            $processName = [string]$data['ProcessName']
            $include = ($processName -match $remoteRegex -or $processName -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $processName))
            $name='Explicit credentials used by a suspicious process'; $severity='Medium'
        }
        4672 { $include=$false }
        4688 {
            $command = ([string]$data['CommandLine']) + ' ' + ([string]$data['NewProcessName'])
            $include = ($command -match $remoteRegex -or $command -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $command))
            $severity = 'High'; $name='Suspicious process creation'
        }
        4697 {
            $include=$true; $name='Service installed through Security auditing'
            $severity=if(Test-CompuTekPostScamPersistenceText $eventText){'High'}else{'Review'}
        }
        4698 {
            $include=$true; $name='Scheduled task created'
            $severity=if(Test-CompuTekPostScamPersistenceText $eventText){'High'}else{'Review'}
        }
        4720 { $include=$true; $name='Local/domain user account created'; $severity='High' }
        4722 { $include=$true; $name='User account enabled'; $severity='Medium' }
        4728 { $include=$true; $name='Member added to a global security group'; $severity='High' }
        4732 { $include=$true; $name='Member added to a local security group'; $severity='High' }
        4756 { $include=$true; $name='Member added to a universal security group'; $severity='High' }
    }
    if ($include) { Add-WindowsEventEvidence $event 'SecurityEvent' $severity $name $data }
}

if ($ExtendedForensics) {
    # Optional lead collection. File-object auditing can produce thousands of normal
    # records and does not prove that data left the computer.
    foreach ($event in Get-RecentEvents -LogName 'Security' -Ids @(4663) -Maximum 1000) {
        $data = Get-EventDataMap $event
        $objectName = [string]$data['ObjectName']
        if ($objectName -match '(?i)\\users\\[^\\]+\\(desktop|documents|onedrive|downloads)\\') {
            Add-Evidence -Category 'PossibleDataAccess' -Severity 'Review' -Name 'Audited access to a user file' -Details 'Windows recorded access to this object. This is not proof the file was viewed or exfiltrated.' -TimeCreated $event.TimeCreated -Path $objectName -User ([string]$data['SubjectUserName']) -Source 'Security' -EventId 4663 -Data $data
        }
    }
}

foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Ids @(106,140,141) -Maximum 1500) {
    $message = Get-EventMessage $event
    if (Test-CompuTekPostScamPersistenceText $message) {
        Add-WindowsEventEvidence $event 'PersistenceEvent' 'Medium' "Suspicious Task Scheduler event $($event.Id)" (Get-EventDataMap $event)
    }
}

# ------------------ REMOTE SESSION EVIDENCE ------------------
Write-Audit "`n[3/12] Remote Desktop, Quick Assist, and WinRM session evidence" 'Cyan'
foreach ($spec in @(
    @{Log='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';Ids=@(1149);Name='RDP authentication succeeded';Severity='High'},
    @{Log='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';Ids=@(21,22,24,25);Name='RDP session activity';Severity='High'},
    @{Log='Microsoft-Windows-WinRM/Operational';Ids=@(6,91,142,169);Name='WinRM activity';Severity='Medium'}
)) {
    foreach ($event in Get-RecentEvents -LogName $spec.Log -Ids $spec.Ids -Maximum 1500) {
        Add-WindowsEventEvidence $event 'RemoteSession' $spec.Severity $spec.Name (Get-EventDataMap $event)
    }
}

try {
    $quickAssistLogs = @(Get-WinEvent -ListLog '*QuickAssist*' -ErrorAction SilentlyContinue | Where-Object {$_.IsEnabled})
    if ($quickAssistLogs.Count -eq 0) { Add-Gap 'No enabled Quick Assist event log was available.' }
    foreach ($logInfo in $quickAssistLogs) {
        try {
            foreach ($event in Get-WinEvent -FilterHashtable @{LogName=$logInfo.LogName;StartTime=$cutoff} -MaxEvents 1000 -ErrorAction Stop) {
                Add-WindowsEventEvidence $event 'RemoteSession' 'High' 'Quick Assist event' (Get-EventDataMap $event)
            }
        } catch { Add-Gap "Quick Assist log '$($logInfo.LogName)' could not be read: $($_.Exception.Message)" }
    }
} catch { Add-Gap "Quick Assist log discovery failed: $($_.Exception.Message)" }

try {
    $currentSessions = (& quser.exe 2>&1 | Out-String).Trim()
    if ($currentSessions) {
        $currentSessions | Set-Content -LiteralPath (Join-Path $caseRoot 'CurrentSessions.txt') -Encoding UTF8
        Add-Evidence -Category 'RemoteSession' -Severity 'Review' -Name 'Current interactive sessions' -Details (Get-TruncatedText $currentSessions 3000) -Source 'quser.exe'
    }
} catch { Add-Gap "Current session enumeration failed: $($_.Exception.Message)" }

# ------------------ POWERSHELL, DEFENDER, AND SYSMON ------------------
Write-Audit "`n[4/12] Suspicious command execution and security-control changes" 'Cyan'
foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4103,4104) -Maximum 3000) {
    $message = Get-EventMessage $event
    if ($message -match $remoteRegex -or $message -match $suspiciousCommandRegex) {
        Add-Evidence -Category 'SuspiciousExecution' -Severity 'High' -Name "PowerShell event $($event.Id)" -Details (Protect-CommandText $message) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data (Get-EventDataMap $event)
    }
}
foreach ($event in Get-RecentEvents -LogName 'Windows PowerShell' -Ids @(400,403,600,800) -Maximum 2000) {
    $message = Get-EventMessage $event
    if ($message -match $remoteRegex -or $message -match $suspiciousCommandRegex) {
        Add-Evidence -Category 'SuspiciousExecution' -Severity 'High' -Name "Classic PowerShell event $($event.Id)" -Details (Protect-CommandText $message) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data (Get-EventDataMap $event)
    }
}
foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids @(1116,1117,5001,5007,5013) -Maximum 2000) {
    $message = Get-EventMessage $event
    $include = ($event.Id -in @(1116,1117,5001,5013) -or ($event.Id -eq 5007 -and $message -match '(?i)(exclusion|disable|realtime|behavior|script.?scanning|cloud|tamper)'))
    if ($include) {
        $severity = if ($event.Id -in @(5001,5013)) {'High'} else {'Medium'}
        Add-WindowsEventEvidence $event 'SecurityControl' $severity "Microsoft Defender event $($event.Id)" (Get-EventDataMap $event)
    }
}

try {
    $mp = Get-MpPreference -ErrorAction Stop
    foreach ($pair in @(
        @{Name='ExclusionPath';Value=@($mp.ExclusionPath)},
        @{Name='ExclusionProcess';Value=@($mp.ExclusionProcess)},
        @{Name='ExclusionExtension';Value=@($mp.ExclusionExtension)},
        @{Name='ExclusionIpAddress';Value=@($mp.ExclusionIpAddress)}
    )) {
        foreach ($value in @($pair.Value | Where-Object {$_})) {
            Add-Evidence -Category 'SecurityControl' -Severity 'High' -Name "Defender $($pair.Name)" -Details ([string]$value) -Source 'Get-MpPreference'
        }
    }
    foreach ($property in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning','DisableArchiveScanning') {
        if ($mp.$property -eq $true) {
            Add-Evidence -Category 'SecurityControl' -Severity 'High' -Name "Defender protection disabled: $property" -Details "$property=True" -Source 'Get-MpPreference'
        }
    }
} catch { Add-Gap "Microsoft Defender preferences could not be collected: $($_.Exception.Message)" }

try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if ($sysmonLog.IsEnabled) {
        foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids @(1,3,11,12,13,22,23,26) -Maximum 4000) {
            $message = Get-EventMessage $event
            if (Test-CompuTekPostScamPersistenceText $message) {
                Add-Evidence -Category 'SysmonEvidence' -Severity 'Medium' -Name "Sysmon event $($event.Id)" -Details (Protect-CommandText $message) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data (Get-EventDataMap $event)
            }
        }
    }
} catch { Add-Gap 'Sysmon was not installed, enabled, or readable. Historical process/network/file telemetry is therefore limited.' }

# ------------------ PERSISTENCE AND BACKDOOR CONFIGURATION ------------------
Write-Audit "`n[5/12] Autoruns, scheduled tasks, WMI subscriptions, and registry backdoors" 'Cyan'
try {
    foreach ($artifact in Get-CompuTekPersistenceArtifacts) {
        $matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $artifact)
        $isTrustedMicrosoftApp = Test-CompuTekTrustedMicrosoftApplication -Path $artifact.Path -CompanyName $artifact.CompanyName -Signer $artifact.Signer -SignatureStatus $artifact.SignatureStatus -ArtifactType $artifact.ArtifactType -Name $artifact.Name -CommandLine $artifact.CommandLine
        $isSuspicious = ($matches.Count -gt 0 -or $artifact.CommandLine -match $suspiciousCommandRegex -or ((Test-CompuTekUserWritablePath $artifact.Path) -and -not $isTrustedMicrosoftApp))
        if ($isSuspicious) {
            $matchedNames = @($matches | ForEach-Object {$_.Product.name}) -join ', '
            Add-Evidence -Category 'Persistence' -Severity $(if($matches.Count -gt 0){'High'}else{'Medium'}) -Name "$($artifact.ArtifactType): $($artifact.DisplayName)" -Details ("command={0}; matched={1}; original={2}; signer={3}" -f (Protect-CommandText $artifact.CommandLine),$matchedNames,$artifact.OriginalFilename,$artifact.Signer) -Path $artifact.Path -Source $artifact.Source -Data $artifact
        }
    }
} catch { Add-Gap "Persistence inventory failed: $($_.Exception.Message)" }

foreach ($className in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') {
    try {
        foreach ($item in Get-CimInstance -Namespace 'root/subscription' -ClassName $className -ErrorAction Stop) {
            $serialized = Get-TruncatedText ($item | Select-Object * | Out-String) 5000
            Add-Evidence -Category 'WmiPersistence' -Severity 'High' -Name "Permanent WMI subscription: $className" -Details (Protect-CommandText $serialized) -Source 'root/subscription' -Data $null
        }
    } catch { Add-Gap "WMI persistence class '$className' could not be queried: $($_.Exception.Message)" }
}

try {
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $winlogon = Get-ItemProperty $winlogonPath -ErrorAction Stop
    if ([string]$winlogon.Shell -and $winlogon.Shell -ine 'explorer.exe') {
        Add-Evidence -Category 'RegistryBackdoor' -Severity 'High' -Name 'Non-default Winlogon Shell' -Details ([string]$winlogon.Shell) -Path $winlogonPath -Source 'Registry'
    }
    if ([string]$winlogon.Userinit -and $winlogon.Userinit -notmatch '(?i)userinit\.exe,?\s*$') {
        Add-Evidence -Category 'RegistryBackdoor' -Severity 'High' -Name 'Non-default Winlogon Userinit' -Details ([string]$winlogon.Userinit) -Path $winlogonPath -Source 'Registry'
    }
} catch { Add-Gap "Winlogon registry values could not be read: $($_.Exception.Message)" }

foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
)) {
    try {
        foreach ($key in Get-ChildItem $root -ErrorAction Stop) {
            $debugger = (Get-ItemProperty $key.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($debugger) { Add-Evidence -Category 'RegistryBackdoor' -Severity 'High' -Name "IFEO Debugger: $($key.PSChildName)" -Details (Protect-CommandText ([string]$debugger)) -Path $key.PSPath -Source 'Registry' }
        }
    } catch { Add-Gap "IFEO registry path could not be scanned: $root" }
}

try {
    $appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $appInit = Get-ItemProperty $appInitPath -ErrorAction Stop
    if ($appInit.LoadAppInit_DLLs -eq 1 -or $appInit.AppInit_DLLs) {
        Add-Evidence -Category 'RegistryBackdoor' -Severity 'High' -Name 'AppInit DLL injection configured' -Details ("Load={0}; DLLs={1}" -f $appInit.LoadAppInit_DLLs,$appInit.AppInit_DLLs) -Path $appInitPath -Source 'Registry'
    }
} catch { Add-Gap "AppInit registry configuration could not be read: $($_.Exception.Message)" }

try {
    $silentRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path $silentRoot) {
        foreach ($key in Get-ChildItem $silentRoot -ErrorAction Stop) {
            $monitor = (Get-ItemProperty $key.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
            if ($monitor) { Add-Evidence -Category 'RegistryBackdoor' -Severity 'High' -Name "SilentProcessExit monitor: $($key.PSChildName)" -Details (Protect-CommandText ([string]$monitor)) -Path $key.PSPath -Source 'Registry' }
        }
    }
} catch { Add-Gap "SilentProcessExit configuration could not be scanned: $($_.Exception.Message)" }

# ------------------ USERS, ADMINS, KEYS, AND PROFILES ------------------
Write-Audit "`n[6/12] Local accounts, administrators, SSH keys, and PowerShell profiles" 'Cyan'
try {
    $localUsers = @(Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,UserMayChangePassword,PrincipalSource,SID)
    $localUsers | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $caseRoot 'LocalUsers.json') -Encoding UTF8
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    foreach ($member in Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop) {
        Add-Evidence -Category 'PrivilegedAccount' -Severity 'Review' -Name 'Local Administrators member' -Details ("{0}; type={1}; source={2}" -f $member.Name,$member.ObjectClass,$member.PrincipalSource) -User $member.Name -Source 'LocalAccounts' -Data $member
    }
} catch { Add-Gap "Local users or Administrators membership could not be collected: $($_.Exception.Message)" }

foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
    foreach ($authorizedKeys in @(
        (Join-Path $profile.FullName '.ssh\authorized_keys'),
        (Join-Path $profile.FullName '.ssh\authorized_keys2')
    )) {
        if (Test-Path -LiteralPath $authorizedKeys -PathType Leaf) {
            $fileEvidence = Get-CompuTekFileEvidence -Path $authorizedKeys -IncludeHash
            $lineCount = @(Get-Content -LiteralPath $authorizedKeys -ErrorAction SilentlyContinue | Where-Object {$_ -and $_ -notmatch '^\s*#'}).Count
            Add-Evidence -Category 'RemoteAccessKey' -Severity 'High' -Name 'OpenSSH authorized keys present' -Details ("key entries={0}; SHA256={1}" -f $lineCount,$fileEvidence.SHA256) -Path $authorizedKeys -Source 'FileSystem' -Data $fileEvidence
        }
    }

    foreach ($history in @(
        (Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
        (Join-Path $profile.FullName 'AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt')
    )) {
        if (-not (Test-Path -LiteralPath $history -PathType Leaf)) { continue }
        try {
            $lineNumber = 0
            foreach ($line in Get-Content -LiteralPath $history -ErrorAction Stop) {
                $lineNumber++
                if ($line -match $remoteRegex -or $line -match $suspiciousCommandRegex) {
                    Add-Evidence -Category 'SuspiciousExecution' -Severity 'High' -Name 'Suspicious PowerShell history command' -Details ("line {0}: {1}" -f $lineNumber,(Protect-CommandText $line)) -Path $history -User $profile.Name -Source 'PSReadLine'
                }
            }
        } catch { Add-Gap "PowerShell history could not be read: $history" }
    }

    foreach ($profileFolder in @((Join-Path $profile.FullName 'Documents\WindowsPowerShell'),(Join-Path $profile.FullName 'Documents\PowerShell'))) {
        if (-not (Test-Path -LiteralPath $profileFolder)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $profileFolder -Filter '*profile*.ps1' -File -Force -ErrorAction SilentlyContinue) {
            $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($file.LastWriteTime -ge $cutoff -or $content -match $remoteRegex -or $content -match $suspiciousCommandRegex) {
                $fileEvidence = Get-CompuTekFileEvidence -Path $file.FullName -IncludeHash
                $suspiciousProfile = ($content -match $remoteRegex -or $content -match $suspiciousCommandRegex)
                Add-Evidence -Category 'Persistence' -Severity $(if($suspiciousProfile){'High'}else{'Review'}) -Name 'PowerShell profile script' -Details ("modified={0:u}; SHA256={1}; suspicious-content={2}" -f $file.LastWriteTime,$fileEvidence.SHA256,$suspiciousProfile) -Path $file.FullName -User $profile.Name -Source 'FileSystem' -Data $fileEvidence
            }
        }
    }
}

# ------------------ NETWORK, BITS, FIREWALL, PROXY, AND HOSTS ------------------
Write-Audit "`n[7/12] Active connections, transfer jobs, firewall rules, proxy, DNS, and hosts" 'Cyan'
try {
    $processMap = @{}
    foreach ($process in Get-CimInstance Win32_Process -ErrorAction Stop) { $processMap[[string]$process.ProcessId] = $process }
    $connections = @()
    foreach ($connection in Get-NetTCPConnection -State Established -ErrorAction Stop) {
        if ($connection.RemoteAddress -in @('127.0.0.1','::1','0.0.0.0','::')) { continue }
        $process = $processMap[[string]$connection.OwningProcess]
        $path = if ($process) {$process.ExecutablePath}else{$null}
        $fileEvidence = if ($path) {Get-CompuTekFileEvidence -Path $path}else{$null}
        $row = [pscustomobject]@{
            TimeCollectedUtc=(Get-Date).ToUniversalTime();LocalAddress=$connection.LocalAddress;LocalPort=$connection.LocalPort
            RemoteAddress=$connection.RemoteAddress;RemotePort=$connection.RemotePort;State=$connection.State
            ProcessId=$connection.OwningProcess;ProcessName=if($process){$process.Name}else{$null};Path=$path
            CommandLine=if($process){Protect-CommandText $process.CommandLine}else{$null};Signer=if($fileEvidence){$fileEvidence.Signer}else{$null}
            SignatureStatus=if($fileEvidence){$fileEvidence.SignatureStatus}else{$null}
        }
        $connections += $row
        $isTrustedMicrosoftApp = if ($fileEvidence) { Test-CompuTekTrustedMicrosoftApplication -Path $path -CompanyName $fileEvidence.CompanyName -Signer $fileEvidence.Signer -SignatureStatus $fileEvidence.SignatureStatus } else { $false }
        if (($path -and (Test-CompuTekUserWritablePath $path) -and -not $isTrustedMicrosoftApp) -or $row.CommandLine -match $remoteRegex -or $row.CommandLine -match $suspiciousCommandRegex) {
            Add-Evidence -Category 'NetworkConnection' -Severity 'High' -Name 'Suspicious process has an active connection' -Details ("{0}:{1}; PID={2}; command={3}" -f $connection.RemoteAddress,$connection.RemotePort,$connection.OwningProcess,$row.CommandLine) -Path $path -Source 'Get-NetTCPConnection' -Data $row
        }
    }
    $connections | Export-Csv -LiteralPath (Join-Path $caseRoot 'ActiveTcpConnections.csv') -NoTypeInformation -Encoding UTF8
} catch { Add-Gap "Active TCP connections could not be collected: $($_.Exception.Message)" }

try {
    $bits = @(Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object DisplayName,Description,JobState,OwnerAccount,CreationTime,ModificationTime,TransferType,BytesTotal,BytesTransferred,FileList)
    $bits | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $caseRoot 'BitsJobs.json') -Encoding UTF8
    foreach ($job in $bits) {
        Add-Evidence -Category 'DataTransfer' -Severity 'Medium' -Name "BITS job: $($job.DisplayName)" -Details (Get-TruncatedText ($job | Out-String) 4000) -TimeCreated $job.CreationTime -User $job.OwnerAccount -Source 'BITS' -Data $job
    }
} catch { Add-Gap "BITS jobs could not be collected: $($_.Exception.Message)" }

try {
    foreach ($rule in Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop) {
        $program = $null
        try { $program = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop).Program } catch {}
        $isTrustedMicrosoftApp = if ($program) { Test-CompuTekTrustedMicrosoftApplication -Path $program } else { $false }
        if ($rule.DisplayName -match $remoteRegex -or ($program -and (Test-CompuTekUserWritablePath $program) -and -not $isTrustedMicrosoftApp)) {
            Add-Evidence -Category 'FirewallBackdoor' -Severity 'High' -Name $rule.DisplayName -Details ("action={0}; profile={1}; program={2}" -f $rule.Action,$rule.Profile,$program) -Path $program -Source 'Windows Firewall' -Data $rule
        }
    }
} catch { Add-Gap "Firewall rules could not be fully inspected: $($_.Exception.Message)" }

try {
    $dns = @(Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Name,Data,Type,Status,TimeToLive)
    $dns | Export-Csv -LiteralPath (Join-Path $caseRoot 'DnsClientCache.csv') -NoTypeInformation -Encoding UTF8
} catch { Add-Gap "DNS client cache could not be collected: $($_.Exception.Message)" }

try {
    $winHttpProxy = (& netsh winhttp show proxy | Out-String).Trim()
    $userProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue | Select-Object ProxyEnable,ProxyServer,AutoConfigURL
    [pscustomobject]@{WinHttp=$winHttpProxy;CurrentUser=$userProxy} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $caseRoot 'ProxyConfiguration.json') -Encoding UTF8
    if ($userProxy.ProxyEnable -eq 1 -or $userProxy.AutoConfigURL) {
        Add-Evidence -Category 'NetworkConfiguration' -Severity 'Medium' -Name 'User proxy configuration is enabled' -Details ("server={0}; PAC={1}" -f $userProxy.ProxyServer,$userProxy.AutoConfigURL) -Source 'Registry'
    }
} catch { Add-Gap "Proxy configuration could not be collected: $($_.Exception.Message)" }

try {
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $customHosts = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop | Where-Object {$_ -match '\S' -and $_ -notmatch '^\s*#'})
    if ($customHosts.Count -gt 0) {
        Add-Evidence -Category 'NetworkConfiguration' -Severity 'Medium' -Name 'Custom hosts-file entries' -Details (Get-TruncatedText ($customHosts -join "`n") 4000) -Path $hostsPath -Source 'FileSystem'
    }
} catch { Add-Gap "Hosts file could not be read: $($_.Exception.Message)" }

# ------------------ OPTIONAL EXTENDED DATA-ACCESS LEADS ------------------
if ($ExtendedForensics) {
Write-Audit "`n[8/12] Extended data-staging and recent-file leads" 'Cyan'
try {
    foreach ($file in Get-RecentFileCandidates -Extensions @('.zip','.7z','.rar','.tar','.gz','.tgz')) {
        if ($file.Length -lt 102400) { continue }
        $fileEvidence = Get-CompuTekFileEvidence -Path $file.FullName -IncludeHash:$IncludeFileHashes
        Add-Evidence -Category 'PossibleDataStaging' -Severity 'Medium' -Name 'Recently created or modified archive' -Details ("size={0}; created={1:u}; modified={2:u}; SHA256={3}. This is not proof of exfiltration." -f $file.Length,$file.CreationTime,$file.LastWriteTime,$fileEvidence.SHA256) -TimeCreated $file.LastWriteTime -Path $file.FullName -Source 'FileSystem' -Data $fileEvidence
    }
} catch { Add-Gap "Recent archive scan failed: $($_.Exception.Message)" }

try {
    foreach ($file in Get-RecentFileCandidates -Extensions @('.doc','.docx','.xls','.xlsx','.xlsm','.csv','.pdf','.txt','.pst','.ost','.kdbx') -OnlyTempAndAppData) {
        if ($file.Length -eq 0) { continue }
        Add-Evidence -Category 'PossibleDataStaging' -Severity 'Review' -Name 'Sensitive-document type recently present in Temp/AppData' -Details ("size={0}; created={1:u}; modified={2:u}. Review whether this is an expected application cache or a staged copy." -f $file.Length,$file.CreationTime,$file.LastWriteTime) -TimeCreated $file.LastWriteTime -Path $file.FullName -Source 'FileSystem'
    }
} catch { Add-Gap "Temp/AppData document-staging scan failed: $($_.Exception.Message)" }

try {
    $shell = New-Object -ComObject WScript.Shell
    foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
        $recent = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
        if (-not (Test-Path -LiteralPath $recent)) { continue }
        foreach ($link in Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -ge $cutoff}) {
            try {
                $shortcut = $shell.CreateShortcut($link.FullName)
                if ($shortcut.TargetPath -match '(?i)\\users\\[^\\]+\\(desktop|documents|onedrive|downloads)\\') {
                    Add-Evidence -Category 'PossibleDataAccess' -Severity 'Review' -Name 'Recent-file shortcut' -Details 'This indicates recent shell interaction with the target, not who opened it or whether it was copied.' -TimeCreated $link.LastWriteTime -Path $shortcut.TargetPath -User $profile.Name -Source 'Windows Recent Items' -Data @{Shortcut=$link.FullName;Arguments=$shortcut.Arguments}
                }
            } catch {}
        }
    }
} catch { Add-Gap "Recent-file shortcuts could not be inspected: $($_.Exception.Message)" }
}

# Prefetch matching remains in the focused scan because execution of remote-control,
# credential-dumping, or transfer tools can be an actionable harm indicator.
try {
    $prefetchPath = Join-Path $env:SystemRoot 'Prefetch'
    $prefetch = @(Get-ChildItem -LiteralPath $prefetchPath -Filter '*.pf' -File -Force -ErrorAction Stop | Where-Object {$_.LastWriteTime -ge $cutoff} | Select-Object Name,Length,CreationTimeUtc,LastWriteTimeUtc)
    $prefetch | Export-Csv -LiteralPath (Join-Path $caseRoot 'RecentPrefetch.csv') -NoTypeInformation -Encoding UTF8
    foreach ($item in $prefetch) {
        if ($item.Name -match $remoteRegex -or $item.Name -match '(?i)(RCLONE|MEGA|WINSCP|PSCP|CURL|BITSADMIN|7Z|RAR|PROCDUMP|PSEXEC)') {
            Add-Evidence -Category 'ExecutionArtifact' -Severity 'Medium' -Name "Prefetch: $($item.Name)" -Details ("last run evidence timestamp={0:u}" -f $item.LastWriteTimeUtc) -TimeCreated $item.LastWriteTimeUtc -Path (Join-Path $prefetchPath $item.Name) -Source 'Prefetch' -Data $item
        }
    }
} catch { Add-Gap "Prefetch could not be collected (it may be disabled): $($_.Exception.Message)" }

# ------------------ BROWSER EXTENSIONS ------------------
Write-Audit "`n[9/12] Browser extensions with remote or high-risk permissions" 'Cyan'
$highRiskPermissions = @('nativeMessaging','desktopCapture','tabCapture','proxy','debugger','management')
foreach ($profile in Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue) {
    foreach ($browserRoot in @(
        (Join-Path $profile.FullName 'AppData\Local\Google\Chrome\User Data'),
        (Join-Path $profile.FullName 'AppData\Local\Microsoft\Edge\User Data'),
        (Join-Path $profile.FullName 'AppData\Local\BraveSoftware\Brave-Browser\User Data')
    )) {
        if (-not (Test-Path -LiteralPath $browserRoot)) { continue }
        foreach ($manifestFile in Get-CompuTekCandidateFilesSafe -Root $browserRoot -Extensions @('.json') -MaxDepth 6 | Where-Object {$_.Name -eq 'manifest.json' -and $_.FullName -match '\\Extensions\\'}) {
            try {
                $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                $permissions = @($manifest.permissions) + @($manifest.host_permissions)
                $risky = @($permissions | Where-Object {$highRiskPermissions -contains [string]$_})
                $text = ([string]$manifest.name) + ' ' + ([string]$manifest.description)
                if ($risky.Count -gt 0 -or $text -match $remoteRegex) {
                    $actionableExtension = ($text -match $remoteRegex -or ($risky.Count -gt 0 -and $manifestFile.LastWriteTime -ge $cutoff))
                    Add-Evidence -Category 'BrowserExtension' -Severity $(if($actionableExtension){'Medium'}else{'Review'}) -Name ([string]$manifest.name) -Details ("version={0}; high-risk permissions={1}; recently changed={2}" -f $manifest.version,($risky -join ','),[bool]($manifestFile.LastWriteTime -ge $cutoff)) -TimeCreated $manifestFile.LastWriteTime -Path $manifestFile.FullName -User $profile.Name -Source 'Chromium extension manifest' -Data @{Permissions=$permissions;Version=$manifest.version}
                }
            } catch {}
        }
    }
}

# ------------------ INSTALLED SOFTWARE AND RECENT FILES ------------------
Write-Audit "`n[10/12] Recently installed software" 'Cyan'
try {
    foreach ($entry in Get-CompuTekUninstallArtifacts) {
        $rawDate = $null
        try { $rawDate = (Get-ItemProperty $entry.RegistryPath -ErrorAction Stop).InstallDate } catch {}
        $installDate = $null
        if ($rawDate -and ([string]$rawDate) -match '^\d{8}$') {
            try { $installDate = [datetime]::ParseExact([string]$rawDate,'yyyyMMdd',$null) } catch {}
        }
        if ($installDate -and $installDate -ge $cutoff) {
            Add-Evidence -Category 'RecentInstall' -Severity 'Review' -Name $entry.DisplayName -Details ("publisher={0}; installed={1:d}; uninstall={2}" -f $entry.Publisher,$installDate,$entry.UninstallString) -TimeCreated $installDate -Path $entry.InstallLocation -Source 'UninstallRegistry' -Data $entry
        }
    }
} catch { Add-Gap "Recent-install inventory failed: $($_.Exception.Message)" }

# ------------------ COLLECTION INTEGRITY ------------------
Write-Audit "`n[11/12] Evidence and logging coverage" 'Cyan'
try {
    $auditPolicy = (& auditpol.exe /get /category:* 2>&1 | Out-String)
    $auditPolicy | Set-Content -LiteralPath (Join-Path $caseRoot 'AuditPolicy.txt') -Encoding UTF8
} catch { Add-Gap "Audit policy could not be exported: $($_.Exception.Message)" }

try {
    $eventLogState = @(Get-WinEvent -ListLog Security,System,'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ErrorAction SilentlyContinue | Select-Object LogName,IsEnabled,RecordCount,LastWriteTime,MaximumSizeInBytes,LogMode)
    $eventLogState | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $caseRoot 'EventLogState.json') -Encoding UTF8
} catch { Add-Gap "Event-log state could not be exported: $($_.Exception.Message)" }

# ------------------ EXPORT AND SUMMARY ------------------
Write-Audit "`n[12/12] Exporting evidence and summary" 'Cyan'
$evidenceJson = Join-Path $caseRoot 'Evidence.json'
$evidenceCsv = Join-Path $caseRoot 'Evidence.csv'
$supplementalJson = Join-Path $caseRoot 'SupplementalLeads.json'
$supplementalCsv = Join-Path $caseRoot 'SupplementalLeads.csv'
$actionableSummaryJson = Join-Path $caseRoot 'ActionableFindings.json'
$actionableSummaryText = Join-Path $caseRoot 'ActionableFindings.txt'
$gapsPath = Join-Path $caseRoot 'CollectionGaps.txt'
$summaryPath = Join-Path $caseRoot 'Summary.txt'

$evidenceRecords = [object[]]$script:Evidence.ToArray()
$supplementalRecords = [object[]]$script:Supplemental.ToArray()
$collectionGaps = [string[]]$script:Gaps.ToArray()

# Windows PowerShell 5.1 can throw "Argument types do not match" when @(...)
# directly materializes a generic List[T]. Convert each list to a normal array
# once before exporting so long-running collections always reach their summary.
ConvertTo-Json -InputObject $evidenceRecords -Depth 8 | Set-Content -LiteralPath $evidenceJson -Encoding UTF8
$evidenceRecords | Select-Object Category,Severity,TimeCreatedUtc,Name,Details,Path,User,Source,EventId | Export-Csv -LiteralPath $evidenceCsv -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject $supplementalRecords -Depth 8 | Set-Content -LiteralPath $supplementalJson -Encoding UTF8
$supplementalRecords | Select-Object Category,Severity,TimeCreatedUtc,Name,Details,Path,User,Source,EventId | Export-Csv -LiteralPath $supplementalCsv -NoTypeInformation -Encoding UTF8
$collectionGaps | Set-Content -LiteralPath $gapsPath -Encoding UTF8

$actionableGroups = @($evidenceRecords | Group-Object {
    '{0}|{1}|{2}' -f $_.Category,$_.Name,$_.Path
} | ForEach-Object {
    $items = @($_.Group)
    $sample = $items | Select-Object -First 1
    [pscustomobject][ordered]@{
        Severity = if ($items.Severity -contains 'High') {'High'} else {'Medium'}
        Category = $sample.Category
        Name = $sample.Name
        Occurrences = $items.Count
        LatestTimeUtc = @($items.TimeCreatedUtc | Where-Object {$_} | Sort-Object -Descending | Select-Object -First 1)[0]
        Path = $sample.Path
        Details = Get-TruncatedText ([string]$sample.Details) 700
        Sources = @($items.Source | Where-Object {$_} | Sort-Object -Unique) -join ', '
    }
} | Sort-Object @{Expression={if($_.Severity -eq 'High'){0}else{1}}},Category,Name,Path)
$actionableGroups | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $actionableSummaryJson -Encoding UTF8
$actionableTextLines = @('COMPUTEK ACTIONABLE POST-SCAM FINDINGS','')
if ($actionableGroups.Count -eq 0) {
    $actionableTextLines += 'No actionable persistence, hidden-access, or customer-harm indicators were identified by the focused scan.'
} else {
    foreach ($finding in $actionableGroups) {
        $actionableTextLines += ('[{0}] {1} - {2} (occurrences: {3})' -f $finding.Severity,$finding.Category,$finding.Name,$finding.Occurrences)
        if ($finding.Path) { $actionableTextLines += ('  Location: {0}' -f $finding.Path) }
        $actionableTextLines += ('  Details: {0}' -f $finding.Details)
        $actionableTextLines += ''
    }
}
$actionableTextLines | Set-Content -LiteralPath $actionableSummaryText -Encoding UTF8

$categoryCounts = @($evidenceRecords | Group-Object Category | Sort-Object Name)
$severityCounts = @($evidenceRecords | Group-Object Severity | Sort-Object Name)
$summaryLines = @(
    'COMPUTEK FOCUSED POST-SCAM SUMMARY',
    "Computer: $env:COMPUTERNAME",
    "Collected: $((Get-Date).ToString('u'))",
    "Lookback start: $($cutoff.ToString('u'))",
    "Actionable finding groups: $($actionableGroups.Count)",
    "Actionable evidence records: $($script:Evidence.Count)",
    "Supplemental leads saved (not flagged): $($script:Supplemental.Count)",
    "Collection gaps: $($script:Gaps.Count)",
    '',
    'Severity counts:'
) + @($severityCounts | ForEach-Object {"  $($_.Name): $($_.Count)"}) + @('', 'Category counts:') + @($categoryCounts | ForEach-Object {"  $($_.Name): $($_.Count)"}) + @(
    '',
    'INTERPRETATION LIMITS:',
    '- File access events show local audited access, not who viewed a file or whether it left the computer.',
    '- Recent Items and archive timestamps are leads for review, not proof of theft.',
    '- If Security, PowerShell, Sysmon, browser, firewall, DNS, router, or EDR logs were unavailable or cleared, exact attacker actions may be unknowable locally.',
    '- Preserve this case folder. Do not run cleanup before reviewing the evidence and resetting credentials from a known-clean device.'
)
$summaryLines | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host "`n=============== ACTIONABLE POST-SCAM FINDINGS ===============" -ForegroundColor Cyan
if ($actionableGroups.Count -eq 0) {
    Write-Host 'No actionable persistence, hidden-access, or customer-harm indicators were identified.' -ForegroundColor Green
} else {
    foreach ($finding in @($actionableGroups | Select-Object -First 12)) {
        $color = if ($finding.Severity -eq 'High') {'Red'} else {'Yellow'}
        Write-Host ("[{0}] {1}: {2} ({3} occurrence(s))" -f $finding.Severity,$finding.Category,$finding.Name,$finding.Occurrences) -ForegroundColor $color
        if ($finding.Path) { Write-Host ("    {0}" -f $finding.Path) -ForegroundColor Gray }
    }
    if ($actionableGroups.Count -gt 12) {
        Write-Host ("...{0} additional actionable finding group(s) are saved in ActionableFindings.txt." -f ($actionableGroups.Count - 12)) -ForegroundColor Yellow
    }
}
Write-Host ("Collection gaps: {0}" -f $script:Gaps.Count) -ForegroundColor $(if($script:Gaps.Count){'Yellow'}else{'Green'})
Write-Host "Case folder: $caseRoot" -ForegroundColor Cyan
Write-Host "Open this first: $actionableSummaryText" -ForegroundColor Cyan
Write-Host "Full actionable evidence: $evidenceJson" -ForegroundColor DarkGray
Write-Host "Supplemental leads (not flagged): $supplementalJson" -ForegroundColor DarkGray
Write-Host 'This report cannot prove that no other backdoor exists or identify every file that may have been viewed or copied.' -ForegroundColor Yellow
Write-Host 'If the scammer had administrator access, consider the machine untrusted until the evidence is reviewed and the remediation decision is made.' -ForegroundColor Yellow
Complete-CompuTekRun 'Post-scam evidence collection complete.'
exit 0
