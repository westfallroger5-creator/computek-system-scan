$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = 0
function Assert-AppTest {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "PASS: $Message" -ForegroundColor Green
    } else {
        $script:failures++
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

foreach ($relativePath in @(
    'scripts\RemoteAccessScanAndRemove.ps1',
    'scripts\PostScam_SystemIntegrityScanner.ps1',
    'scripts\CompuTek.Scanner.Common.psm1',
    'scripts\IT_Technician_Toolbox.ps1',
    'scripts\FinalSystemCheck_CompuTek.ps1',
    'scripts\PreClone.ps1',
    'build\Build-ScannerApp.ps1',
    'build\Sign-RemoteAccessCatalog.ps1',
    'tests\RealMachine.Integration.Tests.ps1'
)) {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot $relativePath),[ref]$tokens,[ref]$parseErrors)
    Assert-AppTest (@($parseErrors).Count -eq 0) "$relativePath parses in Windows PowerShell 5.1"
}

$remoteSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1') -Raw
$postScamSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\PostScam_SystemIntegrityScanner.ps1') -Raw
Assert-AppTest ($remoteSource -match '__COMPUTEK_PROMPT__:' -and $postScamSource -match '__COMPUTEK_PROMPT__:') 'Both scanner engines expose application-safe input prompts'
Assert-AppTest ($remoteSource -match 'COMPUTEK_SCANNER_APP' -and $remoteSource -match 'Read-CompuTekInput') 'The remote scanner remains interactive in both EXE and direct-script modes'
Assert-AppTest ($remoteSource -notmatch '\bScanOnly\b' -and $postScamSource -match "Complete-CompuTekRun 'Post-scam evidence collection complete\.'") 'Remote review is always offered and completed evidence collectors exit automatically'

$moduleSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1') -Raw
$mainFormSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\MainForm.cs') -Raw
$toolboxSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\IT_Technician_Toolbox.ps1') -Raw
$preCloneSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\PreClone.ps1') -Raw
$finalCheckSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\FinalSystemCheck_CompuTek.ps1') -Raw
$brandingSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\Branding.cs') -Raw
$embeddedEngineSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\EmbeddedEngine.cs') -Raw
$catalogValidatorSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\CatalogValidator.cs') -Raw
$engineHostSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\ScannerEngineHost.cs') -Raw
$buildSource = Get-Content -LiteralPath (Join-Path $repoRoot 'build\Build-ScannerApp.ps1') -Raw
$catalogSignerSource = Get-Content -LiteralPath (Join-Path $repoRoot 'build\Sign-RemoteAccessCatalog.ps1') -Raw
Assert-AppTest ($moduleSource -match 'SCAN STAGE:' -and $moduleSource -match 'Step 10 of 10' -and $moduleSource -match '\[Console\]::Out\.Flush\(\)') 'Remote scan publishes flushed, named progress stages to the EXE'
Assert-AppTest ($mainFormSource -match 'runningTimer' -and $mainFormSource -match 'elapsedText' -and $mainFormSource -notmatch 'Still working' -and $mainFormSource -notmatch 'writeHeartbeatToOutput') 'Elapsed time remains in the status bar without adding heartbeat lines to tool output'
Assert-AppTest ($mainFormSource -match 'lookbackDays\.Value = 7' -and $remoteSource -match '\$LookbackDays = 7' -and $postScamSource -match '\$LookbackDays = 7') 'Remote and post-scam scans default to a one-week lookback'
Assert-AppTest ($moduleSource -match 'Get-CompuTekCandidateFilesSafe' -and $moduleSource -match 'FileAttributes\]::ReparsePoint' -and $moduleSource -notmatch 'Get-ChildItem -LiteralPath \$root -Recurse') 'Default file discovery uses a junction-safe bounded traversal'
Assert-AppTest ($moduleSource -match '\$maxDepth = if \(\$DeepScan\) \{ -1 \} else \{ 5 \}') 'Full-depth file traversal is reserved for explicit Deep Scan mode'
Assert-AppTest ($postScamSource -match 'Get-CompuTekCandidateFilesSafe' -and $postScamSource -notmatch 'Get-ChildItem[^\r\n]+-Recurse') 'Post-scam file collection also uses the loop-safe traversal'
Assert-AppTest ($moduleSource -match '\[string\[\]\]\$endpoints = @\(\)' -and $moduleSource -match '\$file\.Name -ieq ''desktop\.ini''') 'Process endpoint counting and Startup-folder noise from the field report are corrected'
Assert-AppTest ($moduleSource -match 'Get-CompuTekSafeFileName' -and $moduleSource -match 'Path could not be inspected' -and $remoteSource -notmatch '\[IO\.Path\]::GetFileName') 'Malformed Startup URLs and registry paths remain evidence instead of terminating the scanner'
Assert-AppTest ($mainFormSource -match 'Technician tools' -and $mainFormSource -match 'StartTechnicianToolbox' -and $mainFormSource -match 'StartFinalSystemCheck' -and $mainFormSource -match 'StartPreClone') 'The Windows application restores the legacy technician tool entry points'
$finalTabIndex = $mainFormSource.IndexOf('toolTabs.TabPages.Add(finalCheckTab)')
$securityTabIndex = $mainFormSource.IndexOf('toolTabs.TabPages.Add(securityTab)')
Assert-AppTest ($finalTabIndex -ge 0 -and $securityTabIndex -gt $finalTabIndex -and $mainFormSource -match 'toolTabs\.SelectedTab = finalCheckTab' -and $mainFormSource -match 'AccessibleName = "Run Final System Check"') 'Final System Check is the accessible first page and default tab'
Assert-AppTest ($mainFormSource -match 'PictureBox brandLogo' -and $mainFormSource -match 'Branding\.CreateLogoImage' -and $brandingSource -match 'CompuTek\.Scanner\.Branding\.CompuTekLogo\.png') 'The application header loads the embedded CompuTek logo'
Assert-AppTest ($toolboxSource -match '__COMPUTEK_PROMPT__:' -and $preCloneSource -match '__COMPUTEK_PROMPT__:' -and $finalCheckSource -match '__COMPUTEK_PROMPT__:') 'Interactive technician tools use the EXE technician-response bridge'
Assert-AppTest ($toolboxSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $preCloneSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT') 'BitLocker recovery output is redirected to the portable USB folder'
Assert-AppTest ($remoteSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $remoteSource -match 'CompuTekData' -and $postScamSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $postScamSource -match 'CompuTekData') 'Remote and post-scam evidence is stored beside the EXE on the service USB'
Assert-AppTest ($postScamSource -match '\$script:Supplemental' -and $postScamSource -match 'ActionableFindings\.txt' -and $postScamSource -match '\[switch\]\$ExtendedForensics' -and $postScamSource -match 'Select-Object -First 8') 'Post-scam default output is consolidated to actionable findings while optional extended leads stay in USB reports'
Assert-AppTest ($postScamSource -match '\$script:Evidence\.ToArray\(\)' -and $postScamSource -match '\$script:Supplemental\.ToArray\(\)' -and $postScamSource -notmatch '@\(\$script:Evidence\)') 'Post-scam export materializes generic lists safely for Windows PowerShell 5.1'
Assert-AppTest ($postScamSource -match 'Test-CompuTekPostScamPersistenceText' -and $postScamSource -match "4697[\s\S]+?'Review'" -and $postScamSource -match '\$suspiciousProfile' -and $postScamSource -match '\$actionableExtension') 'Post-scam findings require suspicious service, task, profile, or recent extension evidence instead of flagging every normal change'
Assert-AppTest ($moduleSource -match 'MSTeams_8wekyb3d8bbwe' -and $moduleSource -match 'OneDriveLauncher' -and $moduleSource -match 'msteams:system-initiated' -and $postScamSource -match 'Test-CompuTekPostScamUserWritableRisk' -and $postScamSource -match '\$isTrustedApplication') 'Expected signed Teams, OneDrive, Codex, PowerToys, and Firefox applications are suppressed without trusting lookalikes'
Assert-AppTest ($postScamSource -match 'New-CompuTekPostScamHtmlReport' -and $postScamSource -match 'PostScamReport\.html' -and $postScamSource -match '__COMPUTEK_OPEN_REPORT__:' -and $mainFormSource -match 'CaptureAndOpenReport' -and $mainFormSource -match 'openReportButton' -and $mainFormSource -match 'UseShellExecute = true') 'Post-scam collection asks the GUI to open its self-contained HTML summary and provides an Open last report fallback'
Assert-AppTest ($postScamSource -match 'CoverageNotes\.txt' -and $postScamSource -match 'NoMatchingEventsFound' -and $postScamSource -match '\$remoteScan\.Warnings\)\) \{ Add-CoverageNote' -and $postScamSource -match 'Quick Assist event logging was not available') 'Expected missing events and optional telemetry limitations are separated from actual collection failures'
Assert-AppTest ($postScamSource -match 'Get-CompuTekPostScamReason' -and $postScamSource -match 'Get-CompuTekPostScamReviewStep' -and $postScamSource -match 'WhyIncluded' -and $postScamSource -match 'What the technician should check' -and $postScamSource -match 'Technical evidence') 'Every grouped warning includes a plain-language reason, technician check, and expandable technical evidence'
Assert-AppTest ($postScamSource -match "'Windows PowerShell' -Ids @\(800\)" -and $postScamSource -notmatch "'Windows PowerShell' -Ids @\(400,403,600,800\)" -and $postScamSource.Contains('\btar(?:\.exe)?\b')) 'Post-scam command review excludes PowerShell lifecycle noise and does not match tar inside started or restart'
Assert-AppTest ($postScamSource -match 'Test-CompuTekTrustedScannerScriptPath' -and $postScamSource -match '\$eventData' -and $postScamSource -match "RemoteAccessExecution' -Severity 'Review'" -and $postScamSource.Contains('Source Network Address:\s*LOCAL\s*$')) 'The scanner excludes its own script logging and keeps local RDP and ordinary remote-support Prefetch evidence supplemental'
Assert-AppTest ($postScamSource -match 'hehggadaopoacecdllhhajmbjkdcmajg' -and $postScamSource -match 'RemoteAccessConfiguration' -and $postScamSource -match 'SCM Event Log Filter') 'Official ChatGPT extension, ordinary remote-support firewall rules, and default WMI inventory stay out of the warning list'
Assert-AppTest ($remoteSource -match 'Get-FindingDetectedVersion' -and $remoteSource -match 'GroupByVersion' -and $moduleSource -match 'DisplayVersion') 'Remote findings are grouped by detected product version'
Assert-AppTest ($remoteSource -match 'ConvertTo-CompuTekCandidateSelection' -and $remoteSource -match 'KEEP 1,3-5' -and $remoteSource -match 'KEEP NONE' -and $remoteSource -match 'REMOVE 2,6-8' -and $remoteSource -match "decisionConfirmation -ieq 'YES'" -and $remoteSource -notmatch 'CONFIRM DECISIONS|APPLY REMOVALS') 'Numbered review items support KEEP NONE, batch ranges, and one simple YES confirmation'
Assert-AppTest ($moduleSource -match 'Approved Syncro identity' -and $moduleSource -match '\$syncroSplashtopRmmCode -ceq \$registeredRmmCode' -and $moduleSource -match '\$syncroSplashtopEnabled' -and $remoteSource -match 'Test-CompuTekManagedInstallationEntry' -and $remoteSource -match 'activeAnchors' -and $remoteSource -match "ArtifactType -in @\('AppxPackage','StartApp'\)" -and $remoteSource -match 'OPEN 1') 'Managed status requires an approved tenant plus an active, matching per-installation path and never absorbs Store packages'
Assert-AppTest ($remoteSource -match 'Split-CompuTekRemovalCandidates' -and $remoteSource -match 'PROTECTED COMPUTEK ACCESS' -and $remoteSource -match 'ProtectedCompuTekAccess\.json' -and $remoteSource -match 'cannot be selected or removed' -and $remoteSource -match 'KEEP ALL, then REMOVE NONE') 'Verified CompuTek access is outside the removal list and uncertain technicians receive a safe keep-and-escalate instruction'
Assert-AppTest ($remoteSource -match '\$DecisionById\[\$otherCandidate\.Id\].+ProtectedManagedAccess' -and $remoteSource -match 'Protected CompuTek managed access cannot be passed to the removal engine' -and $remoteSource -match 'AllCandidates \$allCandidates') 'Protected access also blocks direct removal and product-wide fallback during separate cleanup'
Assert-AppTest ($mainFormSource -notmatch 'APPLY REMOVALS' -and $mainFormSource -match 'removals require one final YES' -and $mainFormSource -match 'StringComparison\.OrdinalIgnoreCase') 'The GUI shows the current simple YES confirmation and recognizes attention results regardless of display-name capitalization'
Assert-AppTest ($moduleSource -match '\$actionableMatches' -and $moduleSource -match "category -ne 'native-feature'") 'Ordinary Windows-native remote features are excluded from removal candidates'
Assert-AppTest ($remoteSource -match 'retry after blockers were stopped' -and $remoteSource -match 'ManualRemovalRequired\.txt') 'Failed uninstallers get one blocker-stop retry and incomplete removal locations are saved for technicians'
Assert-AppTest ($moduleSource -match 'TimeoutSeconds = 90' -and $moduleSource -match '\$process\.WaitForExit\(\$TimeoutSeconds \* 1000\)' -and $moduleSource -match '\$arguments\.Count -gt 0' -and $remoteSource -match 'offline cleanup could continue') 'Offline or argument-free vendor uninstallers cannot freeze the scanner'
Assert-AppTest ($moduleSource -match 'Required file coverage under' -and $moduleSource -match 'Test-CompuTekKnownWindowsProtectedCoveragePath' -and $moduleSource -match 'Windows protected' -and $remoteSource -match 'REMEDIATION LOCKED: Required scan coverage is incomplete' -and $remoteSource.IndexOf('REMEDIATION LOCKED: Required scan coverage is incomplete') -lt $remoteSource.IndexOf('New-RemovalCandidates -Findings $scan.Findings')) 'Unexpected required remote-scan gaps fail closed while explicit Windows-protected namespaces remain visible limitations'
Assert-AppTest ($postScamSource -match 'exit 7' -and $postScamSource -match 'ATTENTION REQUIRED because collection was incomplete' -and $mainFormSource -match 'ExitCode == 7' -and $mainFormSource -match 'Post-scam collection needs attention') 'Post-scam collection has a distinct attention-required/incomplete result in the engine and GUI'
Assert-AppTest ($engineHostSource -match 'COMPUTEK_SCANNER_CANCEL_FILE' -and $engineHostSource -match 'RequestCancellation' -and $mainFormSource -match 'Cancel safely' -and $mainFormSource -match 'GetEngineTimeout' -and $preCloneSource -match 'OperationCanceledException') 'The EXE provides cooperative safe cancellation and workflow runtime limits'
Assert-AppTest ($toolboxSource -match 'Invoke-ToolboxProgressCommand' -and $toolboxSource -match 'ReadLineAsync' -and $toolboxSource -match '\$nativeProcess\.Kill\(\)' -and $toolboxSource -match "System32\\sfc\.exe" -and $toolboxSource -match "System32\\Dism\.exe") 'Toolbox SFC and DISM stream progress and honor cancellation while the native command is running'
Assert-AppTest ($toolboxSource -match 'Get-NetIPInterface -AddressFamily IPv4' -and $toolboxSource -match '\$adapter\.HardwareInterface' -and $toolboxSource -match '/renew.+\$adapterName' -and $toolboxSource -match '-TimeoutSeconds 45') 'DHCP refresh excludes virtual loopback adapters and time-limits each connected hardware adapter'
Assert-AppTest ($mainFormSource.IndexOf('inputPanel.Controls.Add(cancelButton)') -ge 0 -and $mainFormSource -notmatch 'statusPanel\.Controls\.Add\(cancelButton\)' -and $mainFormSource -match 'MinimumSize = new Size\(1000, 580\)') 'Cancel safely remains visible above the footer on smaller or display-scaled screens'
Assert-AppTest ($remoteSource -match 'SupportingOnly' -and $remoteSource -match 'Test-FindingIsWindowsHostProcess' -and $remoteSource -match 'product-passive:') 'Windows helper processes and passive shortcut evidence do not create duplicate removable agents'
Assert-AppTest ($remoteSource -match 'Test-FindingIsStandaloneInstallerEvidence' -and $remoteSource -match 'DOWNLOADED INSTALLER FILES \(NOT INSTALLED AGENTS\)' -and $remoteSource -match 'Installed Splashtop roles') 'Downloaded installers are separated from installed agents and protected Splashtop displays its actual installed roles'
Assert-AppTest ($remoteSource -match 'Linked or redirected path was not moved automatically' -and $remoteSource -match 'exit \$\(if\(\$attentionRequired\)\{3\}else\{0\}\)' -and $mainFormSource -match 'ExitCode == 3') 'Removal refuses redirected paths and reports incomplete verification as attention required in the GUI'
Assert-AppTest ($remoteSource -match '__COMPUTEK_RESULT_REASON__:' -and $mainFormSource -match 'resultReasonPrefix' -and $mainFormSource -match 'Remote-access scan needs attention' -and $mainFormSource -match 'Open Last Case Folder') 'The GUI explains why a remote scan needs attention instead of showing only exit code 3'
Assert-AppTest ($moduleSource -match 'Get-CompuTekStartupCommandInfo' -and $moduleSource -match 'StartupReinstallRisk' -and $moduleSource -match '\.StartupItems\.csv') 'All Startup folders are inventoried and reinstall-capable items are saved separately'
Assert-AppTest ($moduleSource -match '\$currentUserPackages\s*=\s*@\(Get-AppxPackage' -and $moduleSource -match 'Get-StartApps' -and $remoteSource -match 'Remove-CandidateStoreProducts' -and $remoteSource -match 'Test-CandidateHasKeptProductPeer') 'Store remote apps use redundant discovery, cross-view verification, and version-safe exact removal fallback'
Assert-AppTest ($remoteSource -match 'startup-folder reinstall item' -and $remoteSource -match 'RemainingStartupItems' -and $remoteSource -match 'After-remediation startup inventory') 'Selected Startup relaunch items are quarantined and must pass follow-up verification'
Assert-AppTest ($mainFormSource -match 'CreateSessionLog' -and $mainFormSource -match 'ApplicationSessions' -and $mainFormSource -match 'File\.AppendAllText' -and $mainFormSource -match 'USB session log could not be updated') 'Every application run saves its displayed output to a USB session log and visibly warns if USB writing stops'
Assert-AppTest ($moduleSource -match '\$portableDataRoot' -and $moduleSource -match 'Join-Path \$env:COMPUTEK_SCANNER_PORTABLE_ROOT ''CompuTekData''') 'File discovery excludes the scanner data it saved on the service USB'
Assert-AppTest ($mainFormSource -match 'ConfirmSensitiveTool' -and $mainFormSource -match 'MessageBoxDefaultButton\.Button2') 'Advanced technician workflows require a warning with safe default cancellation'
Assert-AppTest (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'Launch_CTSupport_Toolbox.bat')) -and -not (Test-Path -LiteralPath (Join-Path $repoRoot 'CTSupport_Toolbox.ps1'))) 'Obsolete BAT and PowerShell launchers are removed'

Assert-AppTest ($preCloneSource -match 'Get-BitLockerVolume' -and $preCloneSource -match 'Disable-BitLocker' -and $preCloneSource -notmatch 'manage-bde') 'Pre-Clone uses structured BitLocker commands instead of localized console-text parsing'
Assert-AppTest ($preCloneSource -match '\^\\d\{6\}\(\?:-\\d\{6\}\)\{7\}\$' -and $preCloneSource -match 'Get-Content -LiteralPath \$destination -Raw' -and $preCloneSource -match 'Get-FileHash') 'Pre-Clone validates, reads back, and hashes complete 48-digit recovery-password files'
$saveIndex = $preCloneSource.IndexOf('Save-CompuTekRecoveryPasswords -BitLockerVolume')
$decryptIndex = $preCloneSource.IndexOf('Disable-BitLocker -MountPoint')
Assert-AppTest ($saveIndex -ge 0 -and $decryptIndex -gt $saveIndex) 'Pre-Clone cannot start decryption before the recovery-password file passes verification'
Assert-AppTest ($preCloneSource -match 'READY FOR ACRONIS CLONE: YES' -and $preCloneSource -match '\$checkExitCode -eq 0' -and $preCloneSource -match '''FullyDecrypted'' -and \$percentage -eq 0') 'Acronis readiness requires complete decryption and successful CHKDSK exit codes'
Assert-AppTest ($preCloneSource -notmatch "Set-Service[^\r\n]+BDESVC[^\r\n]+Disabled" -and $preCloneSource -notmatch "Stop-Service[^\r\n]+BDESVC") 'Pre-Clone no longer disables the BitLocker service'
Assert-AppTest ($preCloneSource -match 'Disable-BitLockerAutoUnlock' -and $preCloneSource -match '\$current\.AutoUnlockEnabled') 'Pre-Clone handles auto-unlock data volumes before decryption'
Assert-AppTest ($preCloneSource -match 'Get-CompuTekPortableMediaInfo' -and $preCloneSource -match 'Get-Partition -DriveLetter' -and $preCloneSource -match '\$portableMedia\.DiskNumber' -and $preCloneSource -match 'Pre-Clone must be launched from removable service media') 'Pre-Clone proves the service USB physical disk and excludes every partition on it'
Assert-AppTest ($preCloneSource -match 'Get-CompuTekWindowsDisk' -and $preCloneSource -match 'Get-CompuTekFixedPartitionInventory -TargetDiskNumber \$windowsDisk\.DiskNumber' -and $preCloneSource -match 'IgnoredInternalDisks' -and $preCloneSource -match 'FixedDiskPartitions' -and $preCloneSource -match 'PartitionCoverageReady') 'Pre-Clone targets every partition on the Windows physical disk while other internal disks remain informational'
Assert-AppTest ($preCloneSource -match 'Get-CompuTekCloneStorageRisks' -and $preCloneSource -match 'Optane\|RAID\|VMD\|Rapid Storage' -and $preCloneSource -match 'Split boot layout' -and $preCloneSource -match 'StorageLayoutReady') 'Pre-Clone blocks readiness for RAID, Optane, RST, VMD, Storage Spaces, or split-boot layouts pending senior review'
Assert-AppTest ($preCloneSource -match 'Add-PartitionAccessPath' -and $preCloneSource -match 'Remove-PartitionAccessPath' -and $preCloneSource -match 'finally' -and $preCloneSource -match 'Invoke-CompuTekReadOnlyChkdsk' -and $preCloneSource -match 'not mounted or modified for online CHKDSK') 'Ordinary letterless data partitions use a temporary mount while hidden EFI/Recovery partitions remain protected'
Assert-AppTest ($preCloneSource -match '\$bitLockerPreparationReady' -and $preCloneSource -match '\$encryptionPolicyReady' -and $preCloneSource -notmatch '\$decryptionStartedAny') 'Pre-Clone prevents automatic re-encryption even when target drives were already decrypted'
Assert-AppTest ($finalCheckSource -match 'powercfg\.exe /hibernate off' -and $finalCheckSource -match 'Checkpoint-Computer' -and $finalCheckSource -match 'Does this PC have speakers or headphones' -and $finalCheckSource -match 'NO = replay' -and $finalCheckSource -match 'SpeakerTestSkipped' -and $finalCheckSource -match '\[Console\]::Beep' -and $finalCheckSource -notmatch 'SystemSounds') 'Final System Check keeps required actions, the Compu-Tek melody, the no-speaker skip, and replay after NO'
Assert-AppTest ($finalCheckSource -match '55c92734-d682-4d71-983e-d6ec3f16059f' -and $finalCheckSource -match 'LicenseIsAddon' -and $finalCheckSource -match "'NotActivated'" -and $finalCheckSource -notmatch 'Where-Object \{ \$_\.PartialProductKey -and \$_\.LicenseStatus -eq 1 \}') 'Final activation checks only the base Windows OS license instead of accepting Office or an add-on'
Assert-AppTest ($finalCheckSource -match 'Get-CompuTekSlmgrActivationStatus' -and $finalCheckSource -match "'//B'" -and $finalCheckSource -match "'//Nologo'" -and $finalCheckSource -match "'/xpr'" -and $finalCheckSource -match 'no restart is required' -and $finalCheckSource -match 'activationNeedsFallback') 'A failed or missing licensing query automatically uses the read-only Windows activation fallback without requiring a reboot'
Assert-AppTest ($finalCheckSource -match 'SYSTEM READY: ATTENTION REQUIRED' -and $finalCheckSource -match 'exit \$finalExitCode' -and $mainFormSource -match 'ExitCode == 5') 'Final System Check returns a visible attention result when a required readiness check fails'
Assert-AppTest ($finalCheckSource -match "Set-Service -Name 'BDESVC' -StartupType Manual") 'Final System Check repairs BitLocker service state left by older Pre-Clone versions'
Assert-AppTest ($finalCheckSource -match 'PreClonePolicyBackup\.json' -and $finalCheckSource -match 'PreClonePolicyRestored\.json' -and $finalCheckSource -match '\$setting\.WasPresent' -and $finalCheckSource -match '\$setting\.PreviousValue') 'Final System Check restores each saved pre-clone policy state once instead of blindly deleting or repeatedly replaying it'
Assert-AppTest ($finalCheckSource -notmatch 'vssadmin\s+list' -and $finalCheckSource -match 'SystemRestorePointCreationFrequency' -and $finalCheckSource -match 'Get-ComputerRestorePoint') 'Final restore-point creation is language-neutral, bypasses the 24-hour skip, and verifies the new point'
Assert-AppTest ($finalCheckSource -match 'Get-CompuTekAntivirusProductState' -and $finalCheckSource -match '-band 0xF000' -and $finalCheckSource -match 'AntivirusSignatureAge' -and $finalCheckSource -notmatch '\$avProducts\.productState -ne \$null') 'Final Check decodes enabled/current antivirus state instead of accepting any registered Security Center product'
Assert-AppTest ($finalCheckSource -match 'Get-CompuTekManagedIdentityStatus' -and $finalCheckSource -match 'Test-CompuTekPathWithinRoots' -and $finalCheckSource -match "SignatureStatus -eq 'Valid'" -and $finalCheckSource -match "serviceEvidence.CompanyName") 'Final Check verifies CompuTek Splashtop ownership, path, publisher signature, and running service'
Assert-AppTest ($toolboxSource -match 'Get-BitLockerVolume' -and $toolboxSource -match 'Enable-BitLocker' -and $toolboxSource -notmatch 'manage-bde') 'Toolbox BitLocker enablement uses structured PowerShell status instead of localized console text'
$toolboxSaveIndex = $toolboxSource.IndexOf('Save-ToolboxRecoveryPasswords -BitLockerVolume $current')
$toolboxEnableIndex = $toolboxSource.IndexOf('Enable-BitLocker -MountPoint')
Assert-AppTest ($toolboxSaveIndex -ge 0 -and $toolboxEnableIndex -gt $toolboxSaveIndex -and $toolboxSource -match 'Type ENABLE BITLOCKER') 'Toolbox verifies the recovery file and exact technician approval before enabling BitLocker'
Assert-AppTest ($toolboxSource -match 'Invoke-ToolboxChkdsk' -and $toolboxSource -match 'Running CHKDSK in read-only scan mode' -and $toolboxSource -match '\$scanExitCode -eq 0') 'Toolbox CHKDSK starts in read-only mode and stops when the volume passes'
$chkdskScanIndex = $toolboxSource.IndexOf("`$scanExitCode = Invoke-ToolboxChkdsk")
$chkdskRepairChoiceIndex = $toolboxSource.IndexOf("`$repairChoice = Read-CompuTekInput")
$chkdskRepairIndex = $toolboxSource.IndexOf("`$repairExitCode = Invoke-ToolboxChkdsk")
Assert-AppTest ($chkdskScanIndex -ge 0 -and $chkdskRepairChoiceIndex -gt $chkdskScanIndex -and $chkdskRepairIndex -gt $chkdskRepairChoiceIndex -and $toolboxSource -match 'RUN CHKDSK \$\(\$repairSwitch\.ToUpper\(\)\) \$target') 'CHKDSK /F or /R requires a technician choice and exact typed approval after the read-only scan'
Assert-AppTest ($toolboxSource -match 'This toolbox will not reboot automatically' -and $toolboxSource -match 'CHKDSK_\{0\}_ReadOnly') 'Toolbox preserves CHKDSK reports on USB and never automatically reboots after a repair request'
Assert-AppTest ($toolboxSource -match '\$exitToolbox = \$false' -and $toolboxSource -match '\$rebootStarted = \$false' -and $toolboxSource -match '} while \(-not \$exitToolbox -and -not \$rebootStarted\)') 'Every completed toolbox action returns to the menu except Exit and a successfully started reboot'
Assert-AppTest ($toolboxSource -match 'DHCP refresh finished with attention needed for:' -and $toolboxSource -match 'Returning to the toolbox menu\.' -and $toolboxSource -match 'no connected hardware adapter with DHCP enabled') 'DHCP refresh handles unavailable adapters and returns safely to the menu'
Assert-AppTest ($toolboxSource -match 'finally\s*\{[\s\S]+?Start-Service -Name Spooler -ErrorAction Stop' -and $toolboxSource -match 'Get-ChildItem -LiteralPath \$printDir') 'Clear Print Queue restarts the spooler even when queue deletion fails and reports deletion errors'
Assert-AppTest ($embeddedEngineSource -match 'PrepareProtectedDirectory\(compuTekRoot\)' -and $embeddedEngineSource -match 'PrepareProtectedDirectory\(engineRoot\)' -and $embeddedEngineSource -match 'RejectReparsePoint' -and $embeddedEngineSource -match 'File\.Delete\(destination\)' -and $embeddedEngineSource -match 'File\.Move\(temporary, destination\)' -and $embeddedEngineSource.IndexOf('File.Exists(portableCatalog)') -lt $embeddedEngineSource.IndexOf('File.Exists(managedCatalog)')) 'Engine staging protects the full ProgramData hierarchy, replaces unsafe inherited file ACLs, rejects reparse points, and prefers the USB catalog'
Assert-AppTest ($catalogValidatorSource -match 'ValidateSigned' -and $catalogValidatorSource -match 'RSASSA-PKCS1-v1_5-SHA256' -and $embeddedEngineSource -match 'CatalogPublicKeyResource' -and $embeddedEngineSource -match 'RemoteAccessSignatures\.json\.sig' -and $buildSource -match 'CatalogSigningCertificateThumbprint') 'External catalogs require a detached RSA signature verified by a public key embedded in the EXE'
Assert-AppTest ($catalogSignerSource -match 'GetRSAPrivateKey' -and $catalogSignerSource -match 'SignData' -and $catalogSignerSource -match 'VerifyData' -and $catalogSignerSource -match 'RSASSA-PKCS1-v1_5-SHA256' -and $catalogSignerSource -match 'duplicate product IDs' -and $catalogSignerSource -match 'UpdateChecksumManifest') 'A reviewed catalog can be signed, self-verified, and re-checksummed without rebuilding the EXE'
Assert-AppTest ($buildSource -match 'ProductionRelease' -and $buildSource -match 'TimestampServer' -and $buildSource -match 'TimeStamperCertificate' -and $buildSource -match 'A production release requires -CodeSigningCertificateThumbprint') 'Production builds require EXE signing and verify a trusted timestamp'

$activationTokens = $null
$activationErrors = $null
$activationAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\FinalSystemCheck_CompuTek.ps1'),[ref]$activationTokens,[ref]$activationErrors)
foreach ($functionName in @('Read-CompuTekYesNoChoice','Confirm-CompuTekSpeakerOutput','Get-CompuTekAntivirusProductState','Get-CompuTekLicenseStatusName','Get-CompuTekWindowsActivationStatus','Get-CompuTekSlmgrActivationStatus')) {
    $functionAst = @($activationAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true))[0]
    Invoke-Expression $functionAst.Extent.Text
}
$windowsApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f'
$officeLicensed = [pscustomobject]@{ApplicationID='0ff1ce15-a989-479d-af46-f275c6370663';PartialProductKey='OFFCE';LicenseIsAddon=$false;LicenseStatus=1;LicenseStatusReason=0;Name='Office Professional'}
$windowsNotification = [pscustomobject]@{ApplicationID=$windowsApplicationId;PartialProductKey='WIN10';LicenseIsAddon=$false;LicenseStatus=5;LicenseStatusReason=[uint32]3221549108;Name='Windows(R), Professional edition'}
$activationResult = Get-CompuTekWindowsActivationStatus -Products @($officeLicensed,$windowsNotification)
Assert-AppTest ($activationResult.State -eq 'NotActivated' -and $activationResult.Details -match 'Notification') 'An activated Office license cannot hide an unactivated Windows operating-system license'
$licensedWindowsAddon = [pscustomobject]@{ApplicationID=$windowsApplicationId;PartialProductKey='ADDON';LicenseIsAddon=$true;LicenseStatus=1;LicenseStatusReason=0;Name='Windows add-on license'}
$activationResult = Get-CompuTekWindowsActivationStatus -Products @($windowsNotification,$licensedWindowsAddon)
Assert-AppTest ($activationResult.State -eq 'NotActivated' -and $activationResult.Products.Count -eq 1) 'A licensed Windows add-on cannot hide an unactivated base Windows license'
$windowsLicensed = [pscustomobject]@{ApplicationID=$windowsApplicationId;PartialProductKey='WIN11';LicenseIsAddon=$false;LicenseStatus=1;LicenseStatusReason=0;Name='Windows(R), Professional edition'}
$activationResult = Get-CompuTekWindowsActivationStatus -Products @($officeLicensed,$windowsLicensed)
Assert-AppTest ($activationResult.State -eq 'Activated' -and $activationResult.LicensedProducts.Count -eq 1) 'A licensed base Windows operating-system record passes activation readiness'
$activationResult = Get-CompuTekWindowsActivationStatus -Products @()
Assert-AppTest ($activationResult.State -eq 'Unknown') 'Missing Windows licensing data requires technician attention instead of passing'
$activationFallback = Get-CompuTekSlmgrActivationStatus -OutputLines @('Windows(R), Professional edition:','The machine is permanently activated.')
Assert-AppTest ($activationFallback.State -eq 'Activated') 'The activation fallback recognizes a permanently activated Windows edition'
$activationFallback = Get-CompuTekSlmgrActivationStatus -OutputLines @('Windows(R), Professional edition:','Volume activation will expire 9/30/2026 1:00:00 PM')
Assert-AppTest ($activationFallback.State -eq 'Activated') 'The activation fallback recognizes a currently activated time-limited Windows license'
$activationFallback = Get-CompuTekSlmgrActivationStatus -OutputLines @('Windows is in Notification mode')
Assert-AppTest ($activationFallback.State -eq 'NotActivated') 'The activation fallback recognizes an explicit Windows notification-mode result'
$activationFallback = Get-CompuTekSlmgrActivationStatus -OutputLines @('The paging file is too small for this operation to complete')
Assert-AppTest ($activationFallback.State -eq 'Unknown') 'An unclear fallback result never becomes a false activation pass'

$activeCurrentAv = Get-CompuTekAntivirusProductState ([pscustomobject]@{displayName='Healthy AV';productState=397568})
$disabledCurrentAv = Get-CompuTekAntivirusProductState ([pscustomobject]@{displayName='Disabled AV';productState=393472})
$activeStaleAv = Get-CompuTekAntivirusProductState ([pscustomobject]@{displayName='Stale AV';productState=397584})
Assert-AppTest ($activeCurrentAv.Enabled -and $activeCurrentAv.SignaturesCurrent) 'Security Center state 0x061100 is decoded as enabled with current signatures'
Assert-AppTest (-not $disabledCurrentAv.Enabled -and $disabledCurrentAv.SignaturesCurrent) 'A registered but disabled antivirus product is not accepted as active'
Assert-AppTest ($activeStaleAv.Enabled -and -not $activeStaleAv.SignaturesCurrent) 'An enabled antivirus product with stale signatures does not pass readiness'

$audioSkipResult = & {
    function Read-CompuTekInput { param($Prompt); return 'NO' }
    Read-CompuTekYesNoChoice 'Audio required?'
}
Assert-AppTest (-not $audioSkipResult) 'The technician can mark audio not required for a PC without speakers'
$audioReplayResult = & {
    $responses = New-Object 'System.Collections.Generic.Queue[string]'
    $responses.Enqueue('NO')
    $responses.Enqueue('YES')
    $state = [pscustomobject]@{PlaybackCount=0}
    function Read-CompuTekInput { param($Prompt); return $responses.Dequeue() }
    function Invoke-CompuTekSpeakerPlayback { $state.PlaybackCount++ }
    $confirmed = Confirm-CompuTekSpeakerOutput
    [pscustomobject]@{Confirmed=$confirmed;PlaybackCount=$state.PlaybackCount}
}
Assert-AppTest ($audioReplayResult.Confirmed -and $audioReplayResult.PlaybackCount -eq 2) 'Answering NO replays the audio test instead of immediately failing readiness'
$audioFailResult = & {
    $state = [pscustomobject]@{PlaybackCount=0}
    function Read-CompuTekInput { param($Prompt); return 'FAIL' }
    function Invoke-CompuTekSpeakerPlayback { $state.PlaybackCount++ }
    $confirmed = Confirm-CompuTekSpeakerOutput
    [pscustomobject]@{Confirmed=$confirmed;PlaybackCount=$state.PlaybackCount}
}
Assert-AppTest (-not $audioFailResult.Confirmed -and $audioFailResult.PlaybackCount -eq 1) 'Only an explicit FAIL response marks a required audio test unsuccessful'

$preCloneTokens = $null
$preCloneErrors = $null
$preCloneAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\PreClone.ps1'),[ref]$preCloneTokens,[ref]$preCloneErrors)
$recoveryFunctions = @($preCloneAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-CompuTekRecoveryProtectors','Save-CompuTekRecoveryPasswords','Get-CompuTekWindowsDisk','Get-CompuTekCloneStorageRisks','Get-CompuTekFixedPartitionInventory','Invoke-CompuTekReadOnlyChkdsk')
},$true))
foreach ($functionAst in $recoveryFunctions) { Invoke-Expression $functionAst.Extent.Text }
$preCloneTestDirectory = Join-Path $repoRoot 'artifacts\PreCloneFunctionTests'
New-Item -Path $preCloneTestDirectory -ItemType Directory -Force | Out-Null
$syntheticPassword = '111111-222222-333333-444444-555555-666666-777777-888888'
$syntheticVolume = [pscustomobject]@{
    MountPoint = 'C:'
    KeyProtector = @([pscustomobject]@{
        KeyProtectorType = 'RecoveryPassword'
        KeyProtectorId = '{11111111-2222-3333-4444-555555555555}'
        RecoveryPassword = $syntheticPassword
    })
}
$syntheticBackup = Save-CompuTekRecoveryPasswords -BitLockerVolume $syntheticVolume -DestinationDirectory $preCloneTestDirectory -ComputerName 'TEST-PC' -Timestamp '20000101_000000'
$syntheticSavedText = Get-Content -LiteralPath $syntheticBackup.FilePath -Raw
Assert-AppTest ($syntheticBackup.Verified -and $syntheticSavedText -match [regex]::Escape($syntheticPassword) -and $syntheticBackup.Sha256 -match '^[A-F0-9]{64}$') 'Recovery-password writer preserves the complete password and verifies the saved file'
$partialRejected = $false
try {
    $partialVolume = [pscustomobject]@{ MountPoint = 'D:'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; KeyProtectorId = '{BAD}'; RecoveryPassword = '123456' }) }
    [void](Save-CompuTekRecoveryPasswords -BitLockerVolume $partialVolume -DestinationDirectory $preCloneTestDirectory -ComputerName 'TEST-PC' -Timestamp '20000101_000001')
} catch { $partialRejected = $true }
Assert-AppTest $partialRejected 'Recovery-password writer rejects partial or malformed keys'

$syntheticPartitionInventory = & {
    function Get-Disk { param($Number,$ErrorAction); [pscustomobject]@{Number=$Number;BusType='NVMe'} }
    function Get-Partition {
        param($DiskNumber,$ErrorAction)
        @(
            [pscustomobject]@{DiskNumber=0;PartitionNumber=1;AccessPaths=@('C:\');GptType='{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}';Type='Basic';Size=100GB},
            [pscustomobject]@{DiskNumber=0;PartitionNumber=2;AccessPaths=@('\\?\Volume{11111111-2222-3333-4444-555555555555}\');GptType='{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}';Type='Basic';Size=50GB},
            [pscustomobject]@{DiskNumber=0;PartitionNumber=3;AccessPaths=@();GptType='{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}';Type='Reserved';Size=16MB}
        )
    }
    function Get-Volume {
        param($Partition,$ErrorAction)
        if ($Partition.PartitionNumber -eq 1) { return [pscustomobject]@{DriveLetter='C';Path='\\?\Volume{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}\';FileSystem='NTFS'} }
        if ($Partition.PartitionNumber -eq 2) { return [pscustomobject]@{DriveLetter=$null;Path='\\?\Volume{11111111-2222-3333-4444-555555555555}\';FileSystem='NTFS'} }
        return $null
    }
    Get-CompuTekFixedPartitionInventory -TargetDiskNumber 0
}
Assert-AppTest ($syntheticPartitionInventory.Count -eq 3 -and @($syntheticPartitionInventory | Where-Object {$_.PartitionNumber -eq 2 -and $_.RequiresDiskCheck -and $_.MountPoint -match '^\\\\\?\\Volume'}).Count -eq 1) 'Pre-Clone includes a letterless NTFS partition on the Windows source disk'
Assert-AppTest (@($syntheticPartitionInventory | Where-Object {$_.PartitionNumber -eq 3 -and $_.CoverageReady -and -not $_.RequiresDiskCheck}).Count -eq 1) 'Pre-Clone accounts for a known reserved partition without pretending CHKDSK can inspect it'

$syntheticWindowsDisk = & {
    function Get-Partition { param($DriveLetter,$ErrorAction); [pscustomobject]@{DiskNumber=4} }
    function Get-Disk { param($Number,$ErrorAction); [pscustomobject]@{Number=$Number;FriendlyName='Synthetic NVMe';Model='Model X';BusType='NVMe';PartitionStyle='GPT';IsBoot=$true;IsSystem=$true;Size=500GB} }
    $savedSystemDrive = $env:SystemDrive
    try { $env:SystemDrive='C:'; Get-CompuTekWindowsDisk -ServiceDiskNumber 99 } finally { $env:SystemDrive=$savedSystemDrive }
}
Assert-AppTest ($syntheticWindowsDisk.DiskNumber -eq 4 -and $syntheticWindowsDisk.SystemDrive -eq 'C:') 'Pre-Clone resolves the clone source from the physical disk containing Windows'

$syntheticStorageRisks = & {
    function Get-CimInstance { param($ClassName,$ErrorAction); [pscustomobject]@{DeviceClass='SCSIAdapter';DeviceName='Intel Volume Management Device VMD';Manufacturer='Intel';DriverProviderName='Intel'} }
    function Get-StoragePool { param($ErrorAction); [pscustomobject]@{FriendlyName='Primordial';IsPrimordial=$true} }
    function Get-Partition { param($ErrorAction); [pscustomobject]@{DiskNumber=7;PartitionNumber=1;IsSystem=$true;IsBoot=$false} }
    Get-CompuTekCloneStorageRisks -WindowsDisk ([pscustomobject]@{DiskNumber=4;FriendlyName='RAID Array';Model='Optane';BusType='RAID'}) -ServiceDiskNumber 99
}
Assert-AppTest (@($syntheticStorageRisks | Where-Object {$_.Type -eq 'Storage layout'}).Count -eq 1 -and @($syntheticStorageRisks | Where-Object {$_.Type -eq 'Storage controller'}).Count -eq 1 -and @($syntheticStorageRisks | Where-Object {$_.Type -eq 'Split boot layout'}).Count -eq 1) 'RAID/Optane/VMD and boot files on another disk all block an ordinary one-disk clone'

$ordinaryStorageControllerRisks = @(& {
    function Get-CimInstance { param($ClassName,$ErrorAction); [pscustomobject]@{DeviceClass='SCSIAdapter';DeviceName='Microsoft Storage Spaces Controller';Manufacturer='Microsoft';DriverProviderName='Microsoft'} }
    function Get-StoragePool { param($ErrorAction); [pscustomobject]@{FriendlyName='Primordial';IsPrimordial=$true} }
    function Get-Partition { param($ErrorAction); @() }
    Get-CompuTekCloneStorageRisks -WindowsDisk ([pscustomobject]@{DiskNumber=0;FriendlyName='Normal NVMe';Model='Standalone SSD';BusType='NVMe'}) -ServiceDiskNumber 99
})
Assert-AppTest ($ordinaryStorageControllerRisks.Count -eq 0) 'The built-in Microsoft Storage Spaces Controller does not imply that Storage Spaces is active'

$activeStoragePoolRisks = @(& {
    function Get-CimInstance { param($ClassName,$ErrorAction); @() }
    function Get-StoragePool { param($ErrorAction); @([pscustomobject]@{FriendlyName='Primordial';IsPrimordial=$true},[pscustomobject]@{FriendlyName='Customer Pool';IsPrimordial=$false}) }
    function Get-Partition { param($ErrorAction); @() }
    Get-CompuTekCloneStorageRisks -WindowsDisk ([pscustomobject]@{DiskNumber=0;FriendlyName='Normal NVMe';Model='Standalone SSD';BusType='NVMe'}) -ServiceDiskNumber 99
})
Assert-AppTest (@($activeStoragePoolRisks | Where-Object {$_.Type -eq 'Storage Spaces' -and $_.Message -match 'Customer Pool'}).Count -eq 1) 'An actual non-primordial Storage Spaces pool blocks ordinary cloning for review'

$temporaryMountResult = & {
    $state = [pscustomobject]@{Added=0;Removed=0}
    function Test-Path { param($LiteralPath,$PathType,$ErrorAction); return $false }
    function New-Item { param($Path,$ItemType,[switch]$Force,$ErrorAction) }
    function Add-PartitionAccessPath { param($DiskNumber,$PartitionNumber,$AccessPath,$ErrorAction); $state.Added++ }
    function Remove-PartitionAccessPath { param($DiskNumber,$PartitionNumber,$AccessPath,$ErrorAction); $state.Removed++ }
    function Remove-Item { param($LiteralPath,[switch]$Force,$ErrorAction) }
    function Write-Host { param($Object,$ForegroundColor) }
    function chkdsk.exe { $global:LASTEXITCODE=0; 'synthetic clean disk' }
    $result = Invoke-CompuTekReadOnlyChkdsk -Volume ([pscustomobject]@{DiskNumber=4;PartitionNumber=1;DriveLetter='';MountPoint='\\?\Volume{TEST}\';FileSystem='FAT32'}) -CaseDirectory 'C:\SyntheticCase'
    [pscustomobject]@{Result=$result;State=$state}
}
Assert-AppTest ($temporaryMountResult.Result.ExitCode -eq 0 -and $temporaryMountResult.Result.TemporaryMountUsed -and $temporaryMountResult.State.Added -eq 1 -and $temporaryMountResult.State.Removed -eq 1) 'A letterless partition is mounted for CHKDSK and unmounted afterward'

$promptTokens = $null
$promptErrors = $null
$promptAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1'),[ref]$promptTokens,[ref]$promptErrors)
$promptFunction = @($promptAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-CompuTekInput'},$true))[0]
$probeScript = "function Assert-CompuTekNotCancelled {}`n" + $promptFunction.Extent.Text + "`n`$probeValue = Read-CompuTekInput 'Probe prompt'`nWrite-Output ('RESULT:' + `$probeValue)"
$encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeScript))
$probeInfo = New-Object Diagnostics.ProcessStartInfo
$probeInfo.FileName = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
$probeInfo.Arguments = "-NoLogo -NoProfile -EncodedCommand $encodedProbe"
$probeInfo.UseShellExecute = $false
$probeInfo.CreateNoWindow = $true
$probeInfo.RedirectStandardInput = $true
$probeInfo.RedirectStandardOutput = $true
$probeInfo.RedirectStandardError = $true
$probeInfo.EnvironmentVariables['COMPUTEK_SCANNER_APP'] = '1'
$probeProcess = New-Object Diagnostics.Process
$probeProcess.StartInfo = $probeInfo
[void]$probeProcess.Start()
$promptTask = $probeProcess.StandardOutput.ReadLineAsync()
$promptArrived = $promptTask.Wait(5000)
$promptLine = if ($promptArrived) {$promptTask.Result} else {$null}
$resultLine = $null
if ($promptArrived) {
    $probeProcess.StandardInput.WriteLine('technician-response')
    $probeProcess.StandardInput.Flush()
    $resultTask = $probeProcess.StandardOutput.ReadLineAsync()
    if ($resultTask.Wait(5000)) { $resultLine = $resultTask.Result }
}
$probeCompleted = $probeProcess.WaitForExit(5000)
if (-not $probeCompleted) { try {$probeProcess.Kill()} catch {} }
Assert-AppTest ($promptLine -eq '__COMPUTEK_PROMPT__:Probe prompt') 'EXE prompt protocol emits a complete line before waiting for technician input'
Assert-AppTest ($resultLine -eq 'RESULT:technician-response') 'EXE prompt protocol receives the technician response through redirected input'
$probeProcess.Dispose()

$manifest = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\app.manifest') -Raw
Assert-AppTest ($manifest -match 'requestedExecutionLevel level="requireAdministrator"') 'The Windows application requires administrator elevation'

$testOutput = Join-Path $repoRoot 'artifacts\ScannerAppTests'
$buildResult = & (Join-Path $repoRoot 'build\Build-ScannerApp.ps1') -OutputDirectory $testOutput
$exePath = Join-Path $testOutput 'CompuTekScanner.exe'
$catalogPath = Join-Path $testOutput 'RemoteAccessSignatures.json'
Assert-AppTest (Test-Path -LiteralPath $exePath -PathType Leaf) 'CompuTekScanner.exe builds successfully'
Assert-AppTest (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) 'An unsigned development build does not publish an external catalog that the EXE would reject'
Assert-AppTest ((Get-Item -LiteralPath $exePath).Length -gt 100000) 'Built EXE contains the embedded scanner engine'

$exeBytes = [IO.File]::ReadAllBytes($exePath)
$peOffset = [BitConverter]::ToInt32($exeBytes,0x3c)
$optionalHeader = $peOffset + 24
$optionalMagic = [BitConverter]::ToUInt16($exeBytes,$optionalHeader)
$subsystemOffset = if ($optionalMagic -eq 0x10b) {$optionalHeader + 68} else {$optionalHeader + 88}
$subsystem = [BitConverter]::ToUInt16($exeBytes,$subsystemOffset)
Assert-AppTest ($subsystem -eq 2) 'EXE uses the Windows GUI subsystem and does not open a separate console window'
$binaryText = [Text.Encoding]::UTF8.GetString($exeBytes)
Assert-AppTest ($binaryText -match 'requestedExecutionLevel level="requireAdministrator"') 'Administrator requirement is embedded in the built EXE manifest'

try {
    $assembly = [Reflection.Assembly]::LoadFile($exePath)
    $resources = @($assembly.GetManifestResourceNames())
    foreach ($resource in @(
        'CompuTek.Scanner.Branding.CompuTekLogo.png',
        'CompuTek.Scanner.Engine.RemoteAccessScanAndRemove.ps1',
        'CompuTek.Scanner.Engine.PostScam_SystemIntegrityScanner.ps1',
        'CompuTek.Scanner.Engine.IT_Technician_Toolbox.ps1',
        'CompuTek.Scanner.Engine.FinalSystemCheck_CompuTek.ps1',
        'CompuTek.Scanner.Engine.PreClone.ps1',
        'CompuTek.Scanner.Engine.CompuTek.Scanner.Common.psm1',
        'CompuTek.Scanner.Engine.RemoteAccessSignatures.json'
    )) {
        Assert-AppTest ($resources -contains $resource) "EXE embeds trusted engine resource $resource"
    }
    Assert-AppTest ($null -ne $assembly.GetType('CompuTek.Scanner.App.MainForm',$false)) 'EXE contains the technician GUI'
    Assert-AppTest ($assembly.GetName().Version.ToString() -eq '1.5.8.0') 'Built EXE reports version 1.5.8.0'
    $brandingType = $assembly.GetType('CompuTek.Scanner.App.Branding',$false)
    $createLogoMethod = if ($brandingType) {$brandingType.GetMethod('CreateLogoImage',[Reflection.BindingFlags]'Static,NonPublic')} else {$null}
    $embeddedLogo = if ($createLogoMethod) {$createLogoMethod.Invoke($null,@())} else {$null}
    try {
        Assert-AppTest ($null -ne $embeddedLogo -and $embeddedLogo.Width -eq 86 -and $embeddedLogo.Height -eq 57) 'Embedded CompuTek logo retains the approved 86x57 artwork'
    } finally {
        if ($embeddedLogo) {$embeddedLogo.Dispose()}
    }
    $associatedIcon = [Drawing.Icon]::ExtractAssociatedIcon($exePath)
    try {
        Assert-AppTest ($null -ne $associatedIcon) 'Built EXE publishes a Windows program icon derived from the CompuTek logo'
    } finally {
        if ($associatedIcon) {$associatedIcon.Dispose()}
    }
    $validatorType = $assembly.GetType('CompuTek.Scanner.App.CatalogValidator',$false)
    Assert-AppTest ($null -ne $validatorType) 'EXE contains catalog validation logic'
    if ($validatorType) {
        $validateMethod = $validatorType.GetMethod('Validate',[Reflection.BindingFlags]'Static,Public,NonPublic')
        $validateSignedMethod = $validatorType.GetMethod('ValidateSigned',[Reflection.BindingFlags]'Static,Public,NonPublic')
        $validCatalog = [IO.File]::ReadAllBytes((Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json'))
        $catalogInfo = $validateMethod.Invoke($null,@($validCatalog,'test catalog'))
        Assert-AppTest ($catalogInfo.ProductCount -ge 80) 'Compiled catalog validator accepts the embedded catalog structure'
        $duplicateJson = '{"schemaVersion":1,"catalogVersion":"test","products":[{"id":"duplicate","name":"One"},{"id":"duplicate","name":"Two"}]}'
        $duplicateRejected = $false
        try {
            [void]$validateMethod.Invoke($null,@([Text.Encoding]::UTF8.GetBytes($duplicateJson),'duplicate test'))
        } catch {
            $exception = $_.Exception
            while ($exception) {
                if ($exception -is [IO.InvalidDataException]) { $duplicateRejected = $true; break }
                $exception = $exception.InnerException
            }
        }
        Assert-AppTest $duplicateRejected 'Compiled catalog validator rejects duplicate product IDs'

        $testRsa = New-Object Security.Cryptography.RSACryptoServiceProvider 2048
        try {
            $publicKeyBytes = [Text.Encoding]::UTF8.GetBytes($testRsa.ToXmlString($false))
            $detachedSignature = $testRsa.SignData($validCatalog,'SHA256')
            $catalogHash = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create().ComputeHash($validCatalog))).Replace('-','')
            $signatureJson = [ordered]@{schemaVersion=1;algorithm='RSASSA-PKCS1-v1_5-SHA256';catalogSha256=$catalogHash;signature=[Convert]::ToBase64String($detachedSignature)} | ConvertTo-Json -Compress
            $signatureBytes = [Text.Encoding]::UTF8.GetBytes($signatureJson)
            $signedInfo = $validateSignedMethod.Invoke($null,@($validCatalog,$signatureBytes,$publicKeyBytes,'signed test catalog'))
            Assert-AppTest ($signedInfo.SignatureDescription -match 'verified') 'Compiled validator accepts a catalog signed by its trusted RSA public key'
            $tamperedCatalog = [byte[]]$validCatalog.Clone()
            $tamperedCatalog[$tamperedCatalog.Length - 2] = $tamperedCatalog[$tamperedCatalog.Length - 2] -bxor 1
            $tamperRejected = $false
            try { [void]$validateSignedMethod.Invoke($null,@($tamperedCatalog,$signatureBytes,$publicKeyBytes,'tampered test catalog')) } catch { $tamperRejected = $true }
            Assert-AppTest $tamperRejected 'Compiled validator rejects a changed catalog even when the old signature file is present'
        } finally { $testRsa.Dispose() }
    }

    $hostType = $assembly.GetType('CompuTek.Scanner.App.ScannerEngineHost',$false)
    $quoteMethod = $hostType.GetMethod('QuoteArgument',[Reflection.BindingFlags]'Static,NonPublic')
    $quotedPath = [string]$quoteMethod.Invoke($null,@('C:\Program Files\CompuTek Scanner\engine.ps1'))
    Assert-AppTest ($quotedPath.StartsWith('"') -and $quotedPath.EndsWith('"')) 'PowerShell paths containing spaces are safely quoted'
} catch {
    Assert-AppTest $false "Built EXE could not be inspected: $($_.Exception.Message)"
}

$hashFile = Join-Path $testOutput 'SHA256SUMS.txt'
Assert-AppTest (Test-Path -LiteralPath $hashFile -PathType Leaf) 'Build publishes SHA-256 checksums'

if ($failures -gt 0) {
    Write-Host "$failures scanner application test(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All scanner application tests passed.' -ForegroundColor Green
exit 0
