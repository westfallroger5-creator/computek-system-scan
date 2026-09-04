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
    Assert-CompuTekNotCancelled
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine("__COMPUTEK_PROMPT__:$Prompt")
        [Console]::Out.Flush()
        $response = [Console]::In.ReadLine()
        Assert-CompuTekNotCancelled
        return $response
    }
    $response = Read-Host $Prompt
    Assert-CompuTekNotCancelled
    return $response
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

trap [OperationCanceledException] {
    Write-CompuTekResultReason -Message 'The technician canceled post-scam collection. The partial case data must not be treated as a complete or clean result.'
    Complete-CompuTekRun 'Post-scam collection canceled safely — partial evidence may have been saved.'
    exit 6
}

$started = Get-Date
$cutoff = $started.AddDays(-1 * [Math]::Abs($LookbackDays))
$timestamp = $started.ToString('yyyyMMdd_HHmmss')
$portableRoot = if ($env:COMPUTEK_SCANNER_PORTABLE_ROOT) { $env:COMPUTEK_SCANNER_PORTABLE_ROOT } else { $PSScriptRoot }
$caseRoot = Join-Path $portableRoot ("CompuTekData\{0}\PostScam\Cases\{1}" -f $env:COMPUTERNAME,$timestamp)
New-Item -Path $caseRoot -ItemType Directory -Force | Out-Null

$script:Evidence = New-Object System.Collections.Generic.List[object]
$script:Supplemental = New-Object System.Collections.Generic.List[object]
$script:Gaps = New-Object System.Collections.Generic.List[string]
$script:CoverageNotes = New-Object System.Collections.Generic.List[string]
$script:TextLog = Join-Path $caseRoot 'PostScam_Audit.log'
$script:ActionableCategories = @(
    'RemoteAccess','PersistenceEvent','SecurityEvent','RemoteSession','SuspiciousExecution',
    'SecurityControl','SysmonEvidence','Persistence','WmiPersistence','RegistryBackdoor',
    'RemoteAccessKey','NetworkConnection','FirewallBackdoor','NetworkConfiguration',
    'BrowserExtension','ExecutionArtifact'
)

$remoteTerms = @($catalog.products | ForEach-Object { @($_.aliases) + @($_.executables) } | Where-Object {$_} | ForEach-Object {[regex]::Escape([string]$_)} | Sort-Object -Unique)
$remoteRegex = if ($remoteTerms.Count -gt 0) { '(?i)(' + ($remoteTerms -join '|') + ')' } else { '(?!)' }
$suspiciousCommandRegex = '(?i)(downloadstring|invoke-expression|\biex\b|frombase64string|\bencodedcommand\b|invoke-webrequest|\bcurl(?:\.exe)?\b[^\r\n]{0,160}https?://|\bwget(?:\.exe)?\b[^\r\n]{0,160}https?://|\bbitsadmin(?:\.exe)?\b[^\r\n]{0,160}(?:/transfer|/addfile)|\bcertutil(?:\.exe)?\b[^\r\n]{0,160}(?:-urlcache|-decode)|\bmshta(?:\.exe)?\b[^\r\n]{0,160}(?:https?://|javascript:|vbscript:)|\bregsvr32(?:\.exe)?\b[^\r\n]{0,160}(?:/i:https?://|scrobj\.dll)|\brundll32(?:\.exe)?\b[^\r\n]{0,200}(?:javascript:|https?://|comsvcs[^\r\n]*minidump)|\bwmic(?:\.exe)?\b[^\r\n]{0,160}process\s+call\s+create|\bpsexec(?:\.exe)?\b|\bprocdump(?:\.exe)?\b|mimikatz|nanodump|secretsdump|browserpassview|webbrowserpassview|\brclone(?:\.exe)?\b|\bmegacmd(?:\.exe)?\b|\bmegasync(?:\.exe)?\b|\bwinscp(?:\.exe)?\b|\bpscp(?:\.exe)?\b|\bcompress-archive\b|(?<![a-z0-9])7z(?:\.exe)?\b|\brar(?:\.exe)?\b|\btar(?:\.exe)?\b)'
$script:PostScamUserWritableTextRegex = '(?i)\\users\\[^\\]+\\(?:appdata|downloads|desktop)\\|\\windows\\temp\\'
$script:PostScamTrustedApplicationPathRegex = '(?i)(?:[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\microsoft\\(?:(?:teams\\(?:current\\teams|update))|(?:onedrive\\(?:(?:\d+(?:\.\d+)+\\)?(?:onedrive|onedrivelauncher|onedrivestandaloneupdater|filecoauth)))|(?:windowsapps\\ms-teams))\.exe|[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\openai\\codex\\[^"\r\n]*?\\codex\.exe|[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\(?:microsoft\\)?powertoys\\[^"\r\n]*?\.exe|[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\mozilla firefox\\firefox\.exe)'
$script:TrustedChromiumExtensionIds = @('hehggadaopoacecdllhhajmbjkdcmajg')

function Test-CompuTekPostScamUserWritableRisk {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -notmatch $script:PostScamUserWritableTextRegex) { return $false }

    $untrustedText = [string]$Text
    foreach ($match in [regex]::Matches($Text,$script:PostScamTrustedApplicationPathRegex)) {
        $candidatePath = [string]$match.Value
        if (Test-CompuTekTrustedApplication -Path $candidatePath) {
            $untrustedText = $untrustedText.Replace($candidatePath,'<trusted-application>')
        }
    }
    return ($untrustedText -match $script:PostScamUserWritableTextRegex)
}

function Test-CompuTekPostScamPersistenceText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return (
        $Text -match $suspiciousCommandRegex -or
        (Test-CompuTekPostScamUserWritableRisk $Text)
    )
}

function Write-CompuTekResultReason {
    param([Parameter(Mandatory)][string]$Message)
    $singleLine = ($Message -replace '[\r\n]+',' ').Trim()
    if ($env:COMPUTEK_SCANNER_APP -eq '1') {
        [Console]::Out.WriteLine("__COMPUTEK_RESULT_REASON__:$singleLine")
        [Console]::Out.Flush()
    } else {
        Write-Host "ATTENTION REASON: $singleLine" -ForegroundColor Yellow
    }
}

function Get-CompuTekPowerShellCommandText {
    param($Event)
    $data = Get-EventDataMap $Event
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in 'ScriptBlockText','Payload') {
        if ($data.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$data[$key])) {
            $parts.Add([string]$data[$key])
        }
    }
    if ($parts.Count -gt 0) { return ($parts.ToArray() -join "`n") }

    $message = Get-EventMessage $Event
    if ($Event.Id -eq 800 -and $message -match '(?is)Pipeline execution details for command line:\s*(?<Command>.*?)\s*Context Information:') {
        return [string]$Matches.Command
    }
    return $message
}

function Test-CompuTekGeneratedPowerShellText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?i)(__cmdletization_|Cmdletization\.GeneratedTypes|\.EXTERNALHELP\s+[^\r\n]+\.cdxml|CompuTek\.Scanner\.Common|PostScam_SystemIntegrityScanner|COMPUTEK_SCANNER_APP)')
}

function Get-CompuTekDefenderFindingName {
    param([int]$EventId, [AllowNull()][string]$Message)
    if ($EventId -in @(1116,1117) -and $Message -match '(?im)^\s*Name:\s*(?<Threat>[^\r\n]+)') {
        return ('Microsoft Defender detection: {0}' -f $Matches.Threat.Trim())
    }
    return "Microsoft Defender event $EventId"
}

function Test-CompuTekDefenderConfigurationNoOp {
    param([AllowNull()][string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    $oldMatch = [regex]::Match($Message,'(?im)^\s*Old value:\s*(?<Setting>.+?)\s*=\s*(?<Value>\S+)\s*$')
    $newMatch = [regex]::Match($Message,'(?im)^\s*New value:\s*(?<Setting>.+?)\s*=\s*(?<Value>\S+)\s*$')
    if (-not $oldMatch.Success -or -not $newMatch.Success) { return $false }
    $oldSetting = @($oldMatch.Groups['Setting'].Value -split '\\')[-1].Trim()
    $newSetting = @($newMatch.Groups['Setting'].Value -split '\\')[-1].Trim()
    return ($oldSetting -ieq $newSetting -and $oldMatch.Groups['Value'].Value -ieq $newMatch.Groups['Value'].Value)
}

function Test-CompuTekTrustedScannerScriptPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $normalized = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).ToLowerInvariant()
    $trustedName = '(?:computek\.scanner\.common\.psm1|postscam_systemintegrityscanner\.ps1|remoteaccessscanandremove\.ps1|it_technician_toolbox\.ps1|finalsystemcheck_computek\.ps1|preclone\.ps1)'
    return (
        $normalized -match "\\programdata\\computek\\scannerapp\\engine\\[0-9.]+\\$trustedName$" -or
        $normalized -match "\\computek-system-scan-windows-app\\scripts\\$trustedName$"
    )
}

function Get-CompuTekPostScamDataValue {
    param([AllowNull()]$Data, [Parameter(Mandatory)][string[]]$Names)
    if ($null -eq $Data) { return $null }
    foreach ($name in $Names) {
        if ($Data -is [Collections.IDictionary]) {
            foreach ($key in @($Data.Keys)) {
                if ([string]$key -ieq $name) { return $Data[$key] }
            }
        } else {
            $property = $Data.PSObject.Properties | Where-Object {$_.Name -ieq $name} | Select-Object -First 1
            if ($property) { return $property.Value }
        }
    }
    return $null
}

function Get-CompuTekPostScamFirstDataValue {
    param([AllowNull()][object[]]$Items, [Parameter(Mandatory)][string[]]$Names)
    foreach ($item in @($Items)) {
        $value = Get-CompuTekPostScamDataValue -Data $item.Data -Names $Names
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) { return $value }
    }
    return $null
}

function Get-CompuTekPostScamDisplayResource {
    param([AllowNull()][string]$Resource)
    if ([string]::IsNullOrWhiteSpace($Resource)) { return 'not recorded' }
    $clean = $Resource.Trim()
    if ($clean -match '(?i)^CmdLine:_(?<Executable>[a-z]:\\.*?\.exe)(?<Arguments>\s+[^\{\r\n]{0,160})?') {
        $argumentText = if ($Matches.Arguments) {$Matches.Arguments.Trim()}else{''}
        return ('command line: {0}{1}' -f $Matches.Executable,$(if($argumentText){' ' + $argumentText}else{''}))
    }
    return Get-TruncatedText $clean 500
}

function Get-CompuTekPostScamReason {
    param([Parameter(Mandatory)][object[]]$Items)
    $records = @($Items)
    $sample = $records | Select-Object -First 1
    $count = $records.Count
    switch ($sample.Category) {
        'SecurityControl' {
            if ($sample.Name -match '^Microsoft Defender detection:') {
                $threat = [string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Threat Name','Name'))
                if (-not $threat) { $threat = $sample.Name -replace '^Microsoft Defender detection:\s*','' }
                $threatSeverity = [string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Severity Name','Severity'))
                $threatCategory = [string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Category Name','Category'))
                $threatId = [string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Threat ID','ID'))
                $resource = Get-CompuTekPostScamDisplayResource ([string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Path','Resources')))
                $action = [string](Get-CompuTekPostScamFirstDataValue -Items @($records | Where-Object {$_.EventId -eq 1117}) -Names @('Action Name','Action'))
                $additional = [string](Get-CompuTekPostScamFirstDataValue -Items @($records | Where-Object {$_.EventId -eq 1117}) -Names @('Additional Actions String','Additional Actions'))
                $errorCode = [string](Get-CompuTekPostScamFirstDataValue -Items @($records | Where-Object {$_.EventId -eq 1117}) -Names @('Error Code'))
                $errorDescription = [string](Get-CompuTekPostScamFirstDataValue -Items @($records | Where-Object {$_.EventId -eq 1117}) -Names @('Error Description','Error description'))
                $classification = (@($threatSeverity,$threatCategory) | Where-Object {$_}) -join ' '
                $remediation = if ($action) {
                    ' Defender recorded action: {0}; result: {1}{2}{3}.' -f $action,$(if($additional){$additional}else{'status not recorded'}),$(if($errorCode){'; error code ' + $errorCode}else{''}),$(if($errorDescription){' (' + $errorDescription.Trim() + ')'}else{''})
                } else { ' No completed remediation event was found in the collected records.' }
                return ('Defender recorded {0} related event(s) for {1}{2}. Threat ID: {3}. The affected resource was {4}.{5} It is included because antivirus detections remain high-priority evidence even when remediation succeeds.' -f $count,$(if($classification){$classification + ' '}else{''}),$threat,$threatId,$resource,$remediation)
            }
            return ('A Defender protection setting, exclusion, or malware-control event was recorded. It is included because weakened or changed antivirus protection can preserve attacker access. Evidence: {0}' -f (Get-TruncatedText ([string]$sample.Details) 500))
        }
        'FirewallBackdoor' {
            return ('Windows has {0} enabled inbound allow rule(s) for this program. The target is {1}, which is under a user-writable profile or temporary location. A program in that location can be replaced without changing the firewall rule, so an unexpected copy could retain inbound or remote-control access.' -f $count,$sample.Path)
        }
        'RemoteSession' {
            $allDetails = @($records.Details) -join "`n"
            $user = if ($allDetails -match '(?im)^User:\s*(?<User>[^\r\n]+)') {$Matches.User.Trim()}else{'not recorded'}
            $source = if ($allDetails -match '(?im)^Source Network Address:\s*(?<Source>[^\r\n]+)') {$Matches.Source.Trim()}else{'not recorded'}
            $sourceMeaning = if ($source -ieq 'LOCAL') {' LOCAL indicates local session activity and is not evidence of an outside network address by itself.'}else{''}
            return ('Windows recorded {0} Remote Desktop session event(s) during the lookback. User: {1}; source: {2}.{3} Session records are included so the technician can verify that the timing and account were expected.' -f $count,$user,$source,$sourceMeaning)
        }
        'SuspiciousExecution' {
            $scriptPath = [string](Get-CompuTekPostScamFirstDataValue -Items $records -Names @('Path'))
            return ('PowerShell logging recorded {0} script block or command event(s) matching a high-risk execution pattern such as an encoded command, downloader, credential tool, signed-binary proxy, or data-staging utility. Script path: {1}. The match requires command behavior; PowerShell starting or stopping is not enough.' -f $count,$(if($scriptPath){$scriptPath}else{'not recorded'}))
        }
        'ExecutionArtifact' {
            $latestExecution = @($records.TimeCreatedUtc | Where-Object {$_} | Sort-Object -Descending | Select-Object -First 1)[0]
            return ('Windows Prefetch indicates that {0} executed, most recently at {1}. Prefetch proves program execution, but does not identify who ran it or whether a remote connection occurred. It is included only when the executable matches a credential, transfer, or other high-risk utility.' -f $sample.Name,$latestExecution)
        }
        'Persistence' {
            return ('Windows startup persistence launches this item from a user-writable location or uses a high-risk command pattern. Location: {0}. It is included because it can restart access after sign-in or reboot.' -f $(if($sample.Path){$sample.Path}else{'see technical evidence'}))
        }
        'PersistenceEvent' { return ('Windows logged {0} recent service or scheduled-task change(s) containing a high-risk command or user-writable executable path. Ordinary Windows task updates and normal Program Files services are not enough to trigger this warning.' -f $count) }
        'WmiPersistence' { return ('A permanent WMI consumer or binding can run commands when a Windows event occurs, including after reboot. This item contains an executable/script consumer, a remote-tool indicator, or a user-writable/high-risk command. Default Windows SCM event-log subscriptions are excluded.') }
        'RegistryBackdoor' { return ('This registry value changes how Windows starts a shell/process or injects a monitor/DLL. These locations are uncommon in normal repair work and can launch code before or alongside the customer application.') }
        'RemoteAccessKey' { return ('An OpenSSH authorized-key file contains one or more login keys. Anyone holding a matching private key may be able to sign in without the customer password when SSH is enabled.') }
        'RemoteAccess' { return ('Remote-access software was found in a user-writable location with persistence or an active connection. Standard installed support software is kept in supplemental inventory; this warning is reserved for hidden or higher-risk placement.') }
        'NetworkConnection' { return ('A process running from a user-writable location, or using a high-risk command line, had an established external connection when the scan ran. Exact endpoint and process details are retained below.') }
        'NetworkConfiguration' { return ('A proxy, hosts-file entry, or similar network setting can redirect browsing or traffic. This setting is included so the technician can confirm it belongs to the customer or their network.') }
        'BrowserExtension' { return ('This recently changed browser extension requested remote-control or high-risk permissions such as native messaging, desktop/tab capture, proxy, debugger, or extension management. Exact known-safe extension IDs are kept as supplemental inventory.') }
        'SecurityEvent' { return ('Windows recorded an account, administrator-group, audit-log, service, scheduled-task, or Remote Desktop security event that can indicate new access. The event must be compared with the customer and technician timeline.') }
        default { return ('This item matched the focused {0} warning rules. Review the technical evidence and confirm whether its time, user, location, and behavior were expected.' -f (Get-CompuTekPostScamCategoryLabel $sample.Category)) }
    }
}

function Get-CompuTekPostScamReviewStep {
    param([Parameter(Mandatory)][object[]]$Items)
    $sample = @($Items) | Select-Object -First 1
    switch ($sample.Category) {
        'SecurityControl' {
            if ($sample.Name -match '^Microsoft Defender detection:') { return 'Open Windows Security > Protection history and match the threat name/ID. Confirm the action still shows remediated. If the affected resource begins CmdLine:, it is a command-line/content detection; it is not proof that the named EXE file was infected. Verify the named application is the expected signed installation; run a current Defender full scan if the activity was unexpected or remediation is not clearly successful.' }
            return 'Review Defender exclusions and protection settings. Remove an unexpected exclusion or re-enable protection only after confirming it is not required by approved security software.'
        }
        'FirewallBackdoor' { return 'Confirm the named program and folder belong to an approved remote-support product. If not, use the Remote-access scan for technician-approved removal, then verify the executable and its inbound firewall rules are gone.' }
        'RemoteSession' { return 'Compare the user, source address, and timestamps with the customer and technician schedule. A LOCAL source is local session activity; an unfamiliar external address or account needs investigation.' }
        'SuspiciousExecution' { return 'Expand Technical evidence and review the exact command and script path. Do not remove PowerShell itself. Investigate the downloaded file, account, or persistence mechanism that launched an unexpected command.' }
        'ExecutionArtifact' { return 'Identify the executable in the Remote-access inventory and ask whether it was intentionally used at the recorded time. Prefetch alone is not proof of malicious access.' }
        'Persistence' { return 'Confirm the Run key, task, service, or Startup item with the customer. Use the Remote-access scan when it belongs to unwanted support software; otherwise preserve evidence before disabling it.' }
        'PersistenceEvent' { return 'Review the service/task name, command, creator, and timestamp. Confirm it belongs to Windows or approved software before changing it.' }
        'WmiPersistence' { return 'Inspect the consumer command/script and its filter-to-consumer binding. Preserve the WMI details before removal; an unfamiliar executable or script requires technician investigation.' }
        'RegistryBackdoor' { return 'Compare the value with Windows defaults and preserve an export before changing it. Escalate unfamiliar IFEO, Winlogon, AppInit, or SilentProcessExit entries.' }
        'RemoteAccessKey' { return 'Ask whether SSH key access is intentionally configured. If not, preserve the key file and account details, remove the unauthorized key, and review SSH/service logs.' }
        'RemoteAccess' { return 'Use the separate Remote-access scan to identify the product/version and choose KEEP or REMOVE. Never delete it automatically based only on this report.' }
        'NetworkConnection' { return 'Verify the executable signature, parent application, remote endpoint, and whether the connection is expected. Preserve the evidence before stopping an unknown process.' }
        'NetworkConfiguration' { return 'Compare the proxy, PAC URL, DNS, or hosts entries with the customer/network configuration. Remove only settings confirmed to be unauthorized.' }
        'BrowserExtension' { return 'Check the extension ID, publisher, install source, permissions, and customer approval in the browser. Remove only an unapproved or unverifiable extension.' }
        'SecurityEvent' { return 'Match the event time and affected account/group/task/service to legitimate technician work. Reset credentials and investigate further when the customer cannot explain it.' }
        default { return 'Review the timestamp, source, location, and technical evidence with the customer before taking action.' }
    }
}

function ConvertTo-CompuTekHtmlText {
    param([AllowNull()]$Text)
    if ($null -eq $Text) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-CompuTekPostScamCategoryLabel {
    param([AllowNull()][string]$Category)
    switch ($Category) {
        'SecurityControl' { 'Security protection or malware detection' }
        'SecurityEvent' { 'Account or security event' }
        'RemoteSession' { 'Remote session activity' }
        'RemoteAccess' { 'Remote-access software requiring review' }
        'RemoteAccessKey' { 'Remote login key' }
        'PersistenceEvent' { 'Recent persistence change' }
        'Persistence' { 'Startup or scheduled persistence' }
        'WmiPersistence' { 'WMI persistence' }
        'RegistryBackdoor' { 'Registry backdoor' }
        'SuspiciousExecution' { 'Suspicious command execution' }
        'SysmonEvidence' { 'Endpoint activity evidence' }
        'NetworkConnection' { 'Suspicious active connection' }
        'FirewallBackdoor' { 'Suspicious firewall access' }
        'NetworkConfiguration' { 'Network configuration change' }
        'BrowserExtension' { 'Browser extension requiring review' }
        'ExecutionArtifact' { 'Program execution evidence' }
        default { if ($Category) {$Category}else{'Other evidence'} }
    }
}

function New-CompuTekPostScamHtmlReport {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [AllowNull()][object[]]$ActionableGroups,
        [AllowNull()][object[]]$SupplementalRecords,
        [AllowNull()][string[]]$CollectionGaps,
        [AllowNull()][string[]]$CoverageNotes,
        [Parameter(Mandatory)][datetime]$Cutoff,
        [Parameter(Mandatory)][string]$ComputerName
    )

    $groups = @($ActionableGroups)
    $supplemental = @($SupplementalRecords)
    $gaps = @($CollectionGaps)
    $coverage = @($CoverageNotes)
    $highCount = @($groups | Where-Object {$_.Severity -eq 'High'}).Count
    $mediumCount = @($groups | Where-Object {$_.Severity -eq 'Medium'}).Count
    $statusTitle = if ($groups.Count -gt 0) {'Technician review needed'} elseif ($gaps.Count -gt 0) {'Scan completed with collection failures'} else {'No focused warning indicators found'}
    $statusText = if ($groups.Count -gt 0) {
        'Review the grouped items below. A finding is evidence to verify, not automatic proof that a scammer caused it.'
    } elseif ($gaps.Count -gt 0) {
        'No focused warning indicators were found, but one or more required checks failed. Review the collection failures below before deciding the computer is ready.'
    } else {
        'The focused checks found no warning indicators. This does not prove that no access or data theft occurred.'
    }

    $html = New-Object Text.StringBuilder
    [void]$html.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$html.AppendLine('<title>CompuTek Post-Scam Review</title><style>body{margin:0;background:#f3f6fa;color:#172033;font:16px/1.5 "Segoe UI",Arial,sans-serif}.wrap{max-width:1050px;margin:0 auto;padding:28px}.top{background:#0c3f70;color:#fff;border-radius:14px;padding:24px 28px}.top h1{margin:0 0 6px;font-size:28px}.top p{margin:3px 0;color:#dbeafe}.status{margin:18px 0;padding:18px 20px;border-left:6px solid #d97706;background:#fff7ed;border-radius:10px}.status.clear{border-color:#15803d;background:#f0fdf4}.status h2{margin:0 0 4px;font-size:22px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}.card{background:#fff;border:1px solid #dbe3ee;border-radius:10px;padding:15px}.number{font-size:28px;font-weight:700}.muted{color:#5b6678}.section{background:#fff;border:1px solid #dbe3ee;border-radius:12px;padding:18px 20px;margin:16px 0}.section h2{margin:0 0 12px}.finding{border:1px solid #dbe3ee;border-radius:9px;margin:10px 0;background:#fbfdff}.finding summary{cursor:pointer;padding:13px 15px;font-weight:600}.finding .body{border-top:1px solid #e5eaf1;padding:12px 15px}.badge{display:inline-block;border-radius:999px;padding:2px 9px;margin-right:8px;font-size:13px}.high{background:#fee2e2;color:#991b1b}.medium{background:#fef3c7;color:#92400e}.label{font-weight:600}.reason,.check{white-space:pre-wrap;word-break:break-word;padding:12px;border-radius:7px}.reason{background:#eef6ff;border-left:4px solid #2563eb}.check{background:#f0fdf4;border-left:4px solid #15803d}.technical{margin-top:12px;border:1px solid #dbe3ee;border-radius:7px}.technical summary{padding:9px 11px;font-weight:600}.detail{white-space:pre-wrap;word-break:break-word;background:#f5f7fa;padding:10px;border-radius:0 0 7px 7px}.links a{display:inline-block;margin:4px 12px 4px 0}.gaps li{margin:5px 0}@media print{body{background:#fff}.wrap{max-width:none;padding:0}.finding{break-inside:avoid}}</style></head><body><main class="wrap">')
    [void]$html.AppendLine(('<header class="top"><h1>CompuTek Post-Scam Review</h1><p>Computer: {0}</p><p>Collected: {1} &nbsp; | &nbsp; Lookback starts: {2}</p></header>' -f (ConvertTo-CompuTekHtmlText $ComputerName),(ConvertTo-CompuTekHtmlText ((Get-Date).ToString('yyyy-MM-dd HH:mm'))),(ConvertTo-CompuTekHtmlText $Cutoff.ToString('yyyy-MM-dd HH:mm'))))
    [void]$html.AppendLine(('<section class="status{0}"><h2>{1}</h2><div>{2}</div></section>' -f $(if($groups.Count -eq 0 -and $gaps.Count -eq 0){' clear'}else{''}),(ConvertTo-CompuTekHtmlText $statusTitle),(ConvertTo-CompuTekHtmlText $statusText)))
    [void]$html.AppendLine(('<section class="cards"><div class="card"><div class="number">{0}</div><div>High-priority groups</div></div><div class="card"><div class="number">{1}</div><div>Review groups</div></div><div class="card"><div class="number">{2}</div><div>Supplemental leads saved</div></div><div class="card"><div class="number">{3}</div><div>Collection failures</div></div><div class="card"><div class="number">{4}</div><div>Coverage notes</div></div></section>' -f $highCount,$mediumCount,$supplemental.Count,$gaps.Count,$coverage.Count))
    [void]$html.AppendLine('<section class="section"><h2>What to do first</h2><ol><li>Review malware detections, disabled security controls, new accounts, remote login keys, and registry/WMI backdoors first.</li><li>Ask the customer or technician whether each remote session and remote-support tool was expected.</li><li>Use the separate Remote-access scan for technician-approved removal; this evidence scan never removes anything.</li><li>If compromise is confirmed, reset important passwords from a known-clean device and review email, banking, router, and account-provider logs.</li></ol></section>')

    [void]$html.AppendLine('<section class="section"><h2>Findings grouped for review</h2>')
    if ($groups.Count -eq 0) {
        [void]$html.AppendLine('<p>No focused warning groups were produced. Normal inventory and lower-confidence leads remain in the saved supporting files.</p>')
    } else {
        foreach ($categoryGroup in @($groups | Group-Object Category | Sort-Object Name)) {
            [void]$html.AppendLine(('<h3>{0} <span class="muted">({1})</span></h3>' -f (ConvertTo-CompuTekHtmlText (Get-CompuTekPostScamCategoryLabel $categoryGroup.Name)),$categoryGroup.Count))
            foreach ($finding in @($categoryGroup.Group | Sort-Object @{Expression={if($_.Severity -eq 'High'){0}else{1}}},Name,Path)) {
                $badgeClass = if ($finding.Severity -eq 'High') {'high'} else {'medium'}
                $latest = if ($finding.LatestTimeUtc) {[string]$finding.LatestTimeUtc}else{'Time unavailable'}
                [void]$html.AppendLine(('<details class="finding"{0}><summary><span class="badge {1}">{2}</span>{3} <span class="muted">({4} occurrence(s))</span></summary><div class="body"><div><span class="label">Latest:</span> {5}</div><div><span class="label">Source:</span> {6}</div>{7}<p class="label">Why it was included</p><div class="reason">{8}</div><p class="label">What the technician should check</p><div class="check">{9}</div><details class="technical"><summary>Technical evidence</summary><div class="detail">{10}</div></details></div></details>' -f $(if($finding.Severity -eq 'High'){' open'}else{''}),$badgeClass,(ConvertTo-CompuTekHtmlText $finding.Severity),(ConvertTo-CompuTekHtmlText $finding.Name),$finding.Occurrences,(ConvertTo-CompuTekHtmlText $latest),(ConvertTo-CompuTekHtmlText $finding.Sources),$(if($finding.Path){'<div><span class="label">Location:</span> ' + (ConvertTo-CompuTekHtmlText $finding.Path) + '</div>'}else{''}),(ConvertTo-CompuTekHtmlText $finding.WhyIncluded),(ConvertTo-CompuTekHtmlText $finding.WhatToCheck),(ConvertTo-CompuTekHtmlText $finding.TechnicalDetails)))
            }
        }
    }
    [void]$html.AppendLine('</section>')

    [void]$html.AppendLine('<section class="section links"><h2>Supporting files</h2><p>Normal inventory and low-confidence leads are intentionally kept out of the warning list.</p><a href="ActionableFindings.txt">Plain-text findings</a><a href="SupplementalLeads.csv">Supplemental leads</a><a href="CollectionGaps.txt">Collection failures</a><a href="CoverageNotes.txt">Coverage notes</a><a href="Summary.txt">Technical summary</a></section>')
    if ($gaps.Count -gt 0) {
        [void]$html.AppendLine('<section class="section gaps"><h2>Collection failures</h2><p>These required checks failed or returned incomplete results. Resolve them or account for the missing evidence before deciding the computer is ready.</p><ul>')
        foreach ($gap in $gaps) { [void]$html.AppendLine(('<li>{0}</li>' -f (ConvertTo-CompuTekHtmlText $gap))) }
        [void]$html.AppendLine('</ul></section>')
    }
    if ($coverage.Count -gt 0) {
        [void]$html.AppendLine('<section class="section gaps"><h2>Coverage notes</h2><p>These are optional telemetry limitations or non-blocking access notes. They do not mean the scan failed, but they describe evidence Windows did not have available for review.</p><ul>')
        foreach ($note in $coverage) { [void]$html.AppendLine(('<li>{0}</li>' -f (ConvertTo-CompuTekHtmlText $note))) }
        [void]$html.AppendLine('</ul></section>')
    }
    [void]$html.AppendLine('<section class="section"><h2>Important limits</h2><p>This local scan cannot prove that no backdoor exists, identify every file that may have been viewed or copied, or replace a full incident response. Preserve this case folder until the technician finishes review.</p></section></main></body></html>')
    $html.ToString() | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return $OutputPath
}

function Write-Audit {
    param([string]$Message, [string]$Color = 'Gray')
    Assert-CompuTekNotCancelled
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

function Add-CoverageNote {
    param([string]$Message)
    if (-not $script:CoverageNotes.Contains($Message)) { $script:CoverageNotes.Add($Message) }
    $line = '[{0}] COVERAGE NOTE: {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
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
    param([string]$LogName, [AllowNull()][int[]]$Ids, [int]$Maximum = 2000)
    try {
        $filter = @{LogName=$LogName;StartTime=$cutoff}
        if (@($Ids).Count -gt 0) { $filter.Id = $Ids }
        return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Maximum -ErrorAction Stop)
    } catch {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or [string]$_.Exception.Message -match '(?i)No events were found that match the specified selection criteria') {
            return @()
        }
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
        $isTrustedApplication = Test-CompuTekTrustedApplication -Path $finding.Path -CompanyName $finding.CompanyName -Signer $finding.Signer -SignatureStatus $finding.SignatureStatus -ArtifactType $finding.ArtifactType -Name $finding.Name -CommandLine $finding.CommandLine
        $isPersistence = $finding.ArtifactType -in @('Service','RunKey','ScheduledTask','StartupFile','NativeFeature')
        $isActionableRemote = (
            ($finding.ProductId -eq 'unknown' -and -not $isTrustedApplication -and $finding.Confidence -in @('High','Medium')) -or
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
    foreach ($warningMessage in @($remoteScan.Warnings)) { Add-CoverageNote "Remote-access collector note: $warningMessage" }
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
            $include = ($processName -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $processName))
            $name='Explicit credentials used by a suspicious process'; $severity='Medium'
        }
        4672 { $include=$false }
        4688 {
            $command = ([string]$data['CommandLine']) + ' ' + ([string]$data['NewProcessName'])
            $include = ($command -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $command))
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
        $message = Get-EventMessage $event
        $severity = if ($spec.Name -eq 'WinRM activity' -and $message -match '(?i)(\bfailed\b|\bfailure\b|\bdenied\b|\bcannot\b|\bcould not\b|error code:\s*(?!0\b)\d+)') {
            'Review'
        } elseif ($spec.Name -match '^RDP' -and $message -match '(?im)^Source Network Address:\s*LOCAL\s*$') {
            'Review'
        } else {
            $spec.Severity
        }
        Add-WindowsEventEvidence $event 'RemoteSession' $severity $spec.Name (Get-EventDataMap $event)
    }
}

try {
    $quickAssistLogs = @(Get-WinEvent -ListLog '*QuickAssist*' -ErrorAction SilentlyContinue | Where-Object {$_.IsEnabled})
    if ($quickAssistLogs.Count -eq 0) { Add-CoverageNote 'Quick Assist event logging was not available. This optional log might not exist until Quick Assist is installed or used, so no Quick Assist history could be reviewed.' }
    foreach ($logInfo in $quickAssistLogs) {
        foreach ($event in Get-RecentEvents -LogName $logInfo.LogName -Maximum 1000) {
            Add-WindowsEventEvidence $event 'RemoteSession' 'High' 'Quick Assist event' (Get-EventDataMap $event)
        }
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
    $eventData = Get-EventDataMap $event
    if ($event.ProcessId -eq $PID -or (Test-CompuTekTrustedScannerScriptPath ([string](Get-CompuTekPostScamDataValue -Data $eventData -Names @('Path'))))) { continue }
    $commandText = Get-CompuTekPowerShellCommandText $event
    if (-not (Test-CompuTekGeneratedPowerShellText $commandText) -and ($commandText -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $commandText))) {
        Add-Evidence -Category 'SuspiciousExecution' -Severity 'High' -Name "PowerShell event $($event.Id)" -Details (Protect-CommandText $commandText) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data $eventData
    }
}
foreach ($event in Get-RecentEvents -LogName 'Windows PowerShell' -Ids @(800) -Maximum 2000) {
    $eventData = Get-EventDataMap $event
    if ($event.ProcessId -eq $PID -or (Test-CompuTekTrustedScannerScriptPath ([string](Get-CompuTekPostScamDataValue -Data $eventData -Names @('Path'))))) { continue }
    $commandText = Get-CompuTekPowerShellCommandText $event
    if (-not (Test-CompuTekGeneratedPowerShellText $commandText) -and ($commandText -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $commandText))) {
        Add-Evidence -Category 'SuspiciousExecution' -Severity 'High' -Name 'Classic PowerShell command' -Details (Protect-CommandText $commandText) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data $eventData
    }
}
foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids @(1116,1117,5001,5007,5013) -Maximum 2000) {
    $message = Get-EventMessage $event
    if ($event.Id -eq 5007 -and (Test-CompuTekDefenderConfigurationNoOp $message)) {
        Add-Evidence -Category 'SecurityControl' -Severity 'Informational' -Name 'Defender configuration recorded with no effective value change' -Details $message -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data (Get-EventDataMap $event)
        continue
    }
    $include = ($event.Id -in @(1116,1117,5001,5013) -or ($event.Id -eq 5007 -and $message -match '(?i)(exclusion|disable|realtime|behavior|script.?scanning|cloud|tamper)'))
    if ($include) {
        $severity = if ($event.Id -in @(1116,1117,5001,5013)) {'High'} else {'Medium'}
        Add-WindowsEventEvidence $event 'SecurityControl' $severity (Get-CompuTekDefenderFindingName -EventId $event.Id -Message $message) (Get-EventDataMap $event)
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

$sysmonLog = $null
try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
} catch {
    if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*' -or [string]$_.Exception.Message -match '(?i)(not an event log|no event logs.*match|could not find.*log)') {
        Add-CoverageNote 'Sysmon is not installed. Sysmon is optional; the scan completed using Windows-native sources, but detailed historical process, network, and file telemetry was not available.'
    } else {
        Add-Gap "Sysmon log state could not be checked: $($_.Exception.Message)"
    }
}
if ($sysmonLog) {
    if ($sysmonLog.IsEnabled) {
        foreach ($event in Get-RecentEvents -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids @(1,3,11,12,13,22,23,26) -Maximum 4000) {
            $message = Get-EventMessage $event
            if (Test-CompuTekPostScamPersistenceText $message) {
                Add-Evidence -Category 'SysmonEvidence' -Severity 'Medium' -Name "Sysmon event $($event.Id)" -Details (Protect-CommandText $message) -TimeCreated $event.TimeCreated -Source $event.LogName -EventId $event.Id -Data (Get-EventDataMap $event)
            }
        }
    } else {
        Add-CoverageNote 'Sysmon is installed but its event log is disabled. Sysmon is optional; the scan completed using Windows-native sources, but detailed historical process, network, and file telemetry was not available.'
    }
}

# ------------------ PERSISTENCE AND BACKDOOR CONFIGURATION ------------------
Write-Audit "`n[5/12] Autoruns, scheduled tasks, WMI subscriptions, and registry backdoors" 'Cyan'
try {
    foreach ($artifact in Get-CompuTekPersistenceArtifacts) {
        $matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $artifact)
        $isTrustedApplication = Test-CompuTekTrustedApplication -Path $artifact.Path -CompanyName $artifact.CompanyName -Signer $artifact.Signer -SignatureStatus $artifact.SignatureStatus -ArtifactType $artifact.ArtifactType -Name $artifact.Name -CommandLine $artifact.CommandLine
        $isUserWritable = (Test-CompuTekUserWritablePath $artifact.Path)
        $hasSuspiciousBehavior = ($artifact.CommandLine -match $suspiciousCommandRegex)
        $isRemoteToolInUserProfile = ($matches.Count -gt 0 -and $isUserWritable)
        $isSuspicious = ($hasSuspiciousBehavior -or $isRemoteToolInUserProfile -or ($isUserWritable -and -not $isTrustedApplication))
        if ($isSuspicious) {
            $matchedNames = @($matches | ForEach-Object {$_.Product.name}) -join ', '
            Add-Evidence -Category 'Persistence' -Severity $(if($hasSuspiciousBehavior -or $isRemoteToolInUserProfile){'High'}else{'Medium'}) -Name "$($artifact.ArtifactType): $($artifact.DisplayName)" -Details ("command={0}; matched={1}; original={2}; signer={3}" -f (Protect-CommandText $artifact.CommandLine),$matchedNames,$artifact.OriginalFilename,$artifact.Signer) -Path $artifact.Path -Source $artifact.Source -Data $artifact
        }
    }
} catch { Add-Gap "Persistence inventory failed: $($_.Exception.Message)" }

foreach ($className in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') {
    try {
        foreach ($item in Get-CimInstance -Namespace 'root/subscription' -ClassName $className -ErrorAction Stop) {
            $serialized = Get-TruncatedText ($item | Select-Object * | Out-String) 5000
            $isDefaultScmSubscription = ($serialized -match '(?i)SCM Event Log Filter')
            $isExecutableConsumer = ($className -in @('CommandLineEventConsumer','ActiveScriptEventConsumer'))
            $isSuspiciousSubscription = (-not $isDefaultScmSubscription -and ($isExecutableConsumer -or (Test-CompuTekPostScamPersistenceText $serialized) -or $serialized -match $remoteRegex))
            Add-Evidence -Category 'WmiPersistence' -Severity $(if($isSuspiciousSubscription){'High'}else{'Review'}) -Name "Permanent WMI subscription: $className" -Details (Protect-CommandText $serialized) -Source 'root/subscription' -Data $null
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
                if ($line -match $suspiciousCommandRegex -or (Test-CompuTekPostScamUserWritableRisk $line)) {
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
    foreach ($connection in @(Get-CompuTekEstablishedTcpConnections)) {
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
        $isTrustedApplication = if ($fileEvidence) { Test-CompuTekTrustedApplication -Path $path -CompanyName $fileEvidence.CompanyName -Signer $fileEvidence.Signer -SignatureStatus $fileEvidence.SignatureStatus } else { $false }
        if (($path -and (Test-CompuTekUserWritablePath $path) -and -not $isTrustedApplication) -or $row.CommandLine -match $suspiciousCommandRegex) {
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
        $isTrustedApplication = if ($program) { Test-CompuTekTrustedApplication -Path $program } else { $false }
        $isUserWritableProgram = ($program -and (Test-CompuTekUserWritablePath $program) -and -not $isTrustedApplication)
        if ($isUserWritableProgram) {
            Add-Evidence -Category 'FirewallBackdoor' -Severity 'High' -Name $rule.DisplayName -Details ("action={0}; profile={1}; program={2}" -f $rule.Action,$rule.Profile,$program) -Path $program -Source 'Windows Firewall' -Data $rule
        } elseif ($rule.DisplayName -match $remoteRegex) {
            Add-Evidence -Category 'RemoteAccessConfiguration' -Severity 'Review' -Name $rule.DisplayName -Details ("Enabled inbound remote-support rule; action={0}; profile={1}; program={2}" -f $rule.Action,$rule.Profile,$program) -Path $program -Source 'Windows Firewall' -Data $rule
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
        if ($item.Name -match '(?i)(RCLONE|MEGA|WINSCP|PSCP|CURL|BITSADMIN|7Z|RAR|PROCDUMP|PSEXEC|MIMIKATZ|NANODUMP)') {
            Add-Evidence -Category 'ExecutionArtifact' -Severity 'Medium' -Name "Prefetch: $($item.Name)" -Details ("last run evidence timestamp={0:u}" -f $item.LastWriteTimeUtc) -TimeCreated $item.LastWriteTimeUtc -Path (Join-Path $prefetchPath $item.Name) -Source 'Prefetch' -Data $item
        } elseif ($item.Name -match $remoteRegex) {
            Add-Evidence -Category 'RemoteAccessExecution' -Severity 'Review' -Name "Remote-support prefetch: $($item.Name)" -Details ("Windows recorded execution at {0:u}. Prefetch does not show who used the program or whether a remote session occurred." -f $item.LastWriteTimeUtc) -TimeCreated $item.LastWriteTimeUtc -Path (Join-Path $prefetchPath $item.Name) -Source 'Prefetch' -Data $item
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
                $extensionId = if ($manifestFile.FullName -match '(?i)\\Extensions\\(?<Id>[a-p]{32})\\') {[string]$Matches.Id}else{''}
                $isTrustedExtension = ($script:TrustedChromiumExtensionIds -contains $extensionId)
                if ($risky.Count -gt 0 -or $text -match $remoteRegex) {
                    $actionableExtension = (-not $isTrustedExtension -and ($text -match $remoteRegex -or ($risky.Count -gt 0 -and $manifestFile.LastWriteTime -ge $cutoff)))
                    Add-Evidence -Category 'BrowserExtension' -Severity $(if($actionableExtension){'Medium'}else{'Review'}) -Name ([string]$manifest.name) -Details ("extension ID={0}; version={1}; high-risk permissions={2}; recently changed={3}; trusted ID={4}" -f $extensionId,$manifest.version,($risky -join ','),[bool]($manifestFile.LastWriteTime -ge $cutoff),$isTrustedExtension) -TimeCreated $manifestFile.LastWriteTime -Path $manifestFile.FullName -User $profile.Name -Source 'Chromium extension manifest' -Data @{ExtensionId=$extensionId;Permissions=$permissions;Version=$manifest.version}
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
$coverageNotesPath = Join-Path $caseRoot 'CoverageNotes.txt'
$summaryPath = Join-Path $caseRoot 'Summary.txt'
$htmlReportPath = Join-Path $caseRoot 'PostScamReport.html'

$evidenceRecords = [object[]]$script:Evidence.ToArray()
$supplementalRecords = [object[]]$script:Supplemental.ToArray()
$collectionGaps = [string[]]$script:Gaps.ToArray()
$coverageNotes = [string[]]$script:CoverageNotes.ToArray()

# Windows PowerShell 5.1 can throw "Argument types do not match" when @(...)
# directly materializes a generic List[T]. Convert each list to a normal array
# once before exporting so long-running collections always reach their summary.
ConvertTo-Json -InputObject $evidenceRecords -Depth 8 | Set-Content -LiteralPath $evidenceJson -Encoding UTF8
$evidenceRecords | Select-Object Category,Severity,TimeCreatedUtc,Name,Details,Path,User,Source,EventId | Export-Csv -LiteralPath $evidenceCsv -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject $supplementalRecords -Depth 8 | Set-Content -LiteralPath $supplementalJson -Encoding UTF8
$supplementalRecords | Select-Object Category,Severity,TimeCreatedUtc,Name,Details,Path,User,Source,EventId | Export-Csv -LiteralPath $supplementalCsv -NoTypeInformation -Encoding UTF8
$collectionGaps | Set-Content -LiteralPath $gapsPath -Encoding UTF8
$coverageNotes | Set-Content -LiteralPath $coverageNotesPath -Encoding UTF8

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
        WhyIncluded = Get-CompuTekPostScamReason -Items $items
        WhatToCheck = Get-CompuTekPostScamReviewStep -Items $items
        TechnicalDetails = Get-TruncatedText ([string]$sample.Details) 1800
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
        $actionableTextLines += ('  Why included: {0}' -f $finding.WhyIncluded)
        $actionableTextLines += ('  What to check: {0}' -f $finding.WhatToCheck)
        $actionableTextLines += ('  Technical evidence: {0}' -f $finding.TechnicalDetails)
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
    "Collection failures: $($script:Gaps.Count)",
    "Coverage notes (non-blocking): $($script:CoverageNotes.Count)",
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
[void](New-CompuTekPostScamHtmlReport -OutputPath $htmlReportPath -ActionableGroups $actionableGroups -SupplementalRecords $supplementalRecords -CollectionGaps $collectionGaps -CoverageNotes $coverageNotes -Cutoff $cutoff -ComputerName $env:COMPUTERNAME)

Write-Host "`n=============== ACTIONABLE POST-SCAM FINDINGS ===============" -ForegroundColor Cyan
if ($actionableGroups.Count -eq 0) {
    Write-Host 'No actionable persistence, hidden-access, or customer-harm indicators were identified.' -ForegroundColor Green
} else {
    foreach ($finding in @($actionableGroups | Select-Object -First 8)) {
        $color = if ($finding.Severity -eq 'High') {'Red'} else {'Yellow'}
        Write-Host ("[{0}] {1}: {2} ({3} occurrence(s))" -f $finding.Severity,(Get-CompuTekPostScamCategoryLabel $finding.Category),$finding.Name,$finding.Occurrences) -ForegroundColor $color
        if ($finding.Path) { Write-Host ("    {0}" -f $finding.Path) -ForegroundColor Gray }
    }
    if ($actionableGroups.Count -gt 8) {
        Write-Host ("...{0} additional finding group(s) are in the easy-to-read report." -f ($actionableGroups.Count - 8)) -ForegroundColor Yellow
    }
}
Write-Host ("Collection failures: {0}" -f $script:Gaps.Count) -ForegroundColor $(if($script:Gaps.Count){'Yellow'}else{'Green'})
Write-Host ("Coverage notes: {0}" -f $script:CoverageNotes.Count) -ForegroundColor DarkGray
Write-Host "Case folder: $caseRoot" -ForegroundColor Cyan
Write-Host "Easy-to-read report: $htmlReportPath" -ForegroundColor Cyan
Write-Host "Full actionable evidence: $evidenceJson" -ForegroundColor DarkGray
Write-Host "Supplemental leads (not flagged): $supplementalJson" -ForegroundColor DarkGray
Write-Host 'This report cannot prove that no other backdoor exists or identify every file that may have been viewed or copied.' -ForegroundColor Yellow
Write-Host 'If the scammer had administrator access, consider the machine untrusted until the evidence is reviewed and the remediation decision is made.' -ForegroundColor Yellow
if ($env:COMPUTEK_SCANNER_APP -eq '1') {
    # Ask the GUI to open the completed report. Starting a shell-associated HTML
    # file from the redirected, hidden PowerShell child is unreliable on some PCs.
    [Console]::Out.WriteLine("__COMPUTEK_OPEN_REPORT__:$htmlReportPath")
    [Console]::Out.Flush()
} else {
    try {
        Write-Host 'Opening the easy-to-read report in the default browser...' -ForegroundColor Cyan
        Start-Process -FilePath $htmlReportPath -ErrorAction Stop
    } catch {
        Write-Host "The report could not be opened automatically. Open this file: $htmlReportPath" -ForegroundColor Yellow
    }
}
if ($script:Gaps.Count -gt 0) {
    $gapSummary = @($script:Gaps | Select-Object -First 3) -join '; '
    Write-CompuTekResultReason -Message ("Post-scam evidence collection is incomplete because {0} required collector(s) failed: {1}. Review the HTML report and saved collection-failure details; do not treat the computer as clean." -f $script:Gaps.Count,$gapSummary)
    Complete-CompuTekRun 'Post-scam evidence collection complete — ATTENTION REQUIRED because collection was incomplete.'
    exit 7
}
Complete-CompuTekRun 'Post-scam evidence collection complete.'
exit 0
