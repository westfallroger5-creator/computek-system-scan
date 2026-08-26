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
    'build\Build-ScannerApp.ps1'
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
Assert-AppTest ($moduleSource -match 'SCAN STAGE:' -and $moduleSource -match 'Step 10 of 10' -and $moduleSource -match '\[Console\]::Out\.Flush\(\)') 'Remote scan publishes flushed, named progress stages to the EXE'
Assert-AppTest ($mainFormSource -match 'runningTimer' -and $mainFormSource -match 'elapsedText' -and $mainFormSource -notmatch 'Still working' -and $mainFormSource -notmatch 'writeHeartbeatToOutput') 'Elapsed time remains in the status bar without adding heartbeat lines to tool output'
Assert-AppTest ($mainFormSource -match 'lookbackDays\.Value = 7' -and $remoteSource -match '\$LookbackDays = 7' -and $postScamSource -match '\$LookbackDays = 7') 'Remote and post-scam scans default to a one-week lookback'
Assert-AppTest ($moduleSource -match 'Get-CompuTekCandidateFilesSafe' -and $moduleSource -match 'FileAttributes\]::ReparsePoint' -and $moduleSource -notmatch 'Get-ChildItem -LiteralPath \$root -Recurse') 'Default file discovery uses a junction-safe bounded traversal'
Assert-AppTest ($moduleSource -match '\$maxDepth = if \(\$DeepScan\) \{ -1 \} else \{ 5 \}') 'Full-depth file traversal is reserved for explicit Deep Scan mode'
Assert-AppTest ($postScamSource -match 'Get-CompuTekCandidateFilesSafe' -and $postScamSource -notmatch 'Get-ChildItem[^\r\n]+-Recurse') 'Post-scam file collection also uses the loop-safe traversal'
Assert-AppTest ($moduleSource -match '\[string\[\]\]\$endpoints = @\(\)' -and $moduleSource -match '\$file\.Name -ieq ''desktop\.ini''') 'Process endpoint counting and Startup-folder noise from the field report are corrected'
Assert-AppTest ($mainFormSource -match 'Technician tools' -and $mainFormSource -match 'StartTechnicianToolbox' -and $mainFormSource -match 'StartFinalSystemCheck' -and $mainFormSource -match 'StartPreClone') 'The Windows application restores the legacy technician tool entry points'
$finalTabIndex = $mainFormSource.IndexOf('toolTabs.TabPages.Add(finalCheckTab)')
$securityTabIndex = $mainFormSource.IndexOf('toolTabs.TabPages.Add(securityTab)')
Assert-AppTest ($finalTabIndex -ge 0 -and $securityTabIndex -gt $finalTabIndex -and $mainFormSource -match 'toolTabs\.SelectedTab = finalCheckTab' -and $mainFormSource -match 'AccessibleName = "Run Final System Check"') 'Final System Check is the accessible first page and default tab'
Assert-AppTest ($mainFormSource -match 'PictureBox brandLogo' -and $mainFormSource -match 'Branding\.CreateLogoImage' -and $brandingSource -match 'CompuTek\.Scanner\.Branding\.CompuTekLogo\.png') 'The application header loads the embedded CompuTek logo'
Assert-AppTest ($toolboxSource -match '__COMPUTEK_PROMPT__:' -and $preCloneSource -match '__COMPUTEK_PROMPT__:' -and $finalCheckSource -match '__COMPUTEK_PROMPT__:') 'Interactive technician tools use the EXE technician-response bridge'
Assert-AppTest ($toolboxSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $preCloneSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT') 'BitLocker recovery output is redirected to the portable USB folder'
Assert-AppTest ($remoteSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $remoteSource -match 'CompuTekData' -and $postScamSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $postScamSource -match 'CompuTekData') 'Remote and post-scam evidence is stored beside the EXE on the service USB'
Assert-AppTest ($postScamSource -match '\$script:Supplemental' -and $postScamSource -match 'ActionableFindings\.txt' -and $postScamSource -match '\[switch\]\$ExtendedForensics' -and $postScamSource -match 'Select-Object -First 12') 'Post-scam default output is consolidated to actionable findings while optional extended leads stay in USB reports'
Assert-AppTest ($postScamSource -match '\$script:Evidence\.ToArray\(\)' -and $postScamSource -match '\$script:Supplemental\.ToArray\(\)' -and $postScamSource -notmatch '@\(\$script:Evidence\)') 'Post-scam export materializes generic lists safely for Windows PowerShell 5.1'
Assert-AppTest ($postScamSource -match 'Test-CompuTekPostScamPersistenceText' -and $postScamSource -match "4697[\s\S]+?'Review'" -and $postScamSource -match '\$suspiciousProfile' -and $postScamSource -match '\$actionableExtension') 'Post-scam findings require suspicious service, task, profile, or recent extension evidence instead of flagging every normal change'
Assert-AppTest ($remoteSource -match 'Get-FindingDetectedVersion' -and $remoteSource -match 'GroupByVersion' -and $moduleSource -match 'DisplayVersion') 'Remote findings are grouped by detected product version'
Assert-AppTest ($remoteSource -match 'ConvertTo-CompuTekCandidateSelection' -and $remoteSource -match 'KEEP 1,3-5' -and $remoteSource -match 'REMOVE 2,6-8' -and $remoteSource -match 'CONFIRM DECISIONS') 'Numbered agents support confirmed batch KEEP and REMOVE ranges'
Assert-AppTest ($remoteSource -match 'displayClass = if \(\$candidate\.IsManagedSuite\) \{''Managed''\}' -and $remoteSource -match 'OPEN 1' -and $remoteSource -match 'Open-CandidateInstallerFiles') 'Managed Syncro/Splashtop displays once without a warning label and supports showing downloaded installers'
Assert-AppTest ($moduleSource -match '\$actionableMatches' -and $moduleSource -match "category -ne 'native-feature'") 'Ordinary Windows-native remote features are excluded from removal candidates'
Assert-AppTest ($remoteSource -match 'retry after blockers were stopped' -and $remoteSource -match 'ManualRemovalRequired\.txt') 'Failed uninstallers get one blocker-stop retry and incomplete removal locations are saved for technicians'
Assert-AppTest ($remoteSource -match 'Linked or redirected path was not moved automatically' -and $remoteSource -match 'exit \$\(if\(\$attentionRequired\)\{3\}else\{0\}\)' -and $mainFormSource -match 'ExitCode == 3') 'Removal refuses redirected paths and reports incomplete verification as attention required in the GUI'
Assert-AppTest ($moduleSource -match 'Get-CompuTekStartupCommandInfo' -and $moduleSource -match 'StartupReinstallRisk' -and $moduleSource -match '\.StartupItems\.csv') 'All Startup folders are inventoried and reinstall-capable items are saved separately'
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
Assert-AppTest ($preCloneSource -match '\$bitLockerPreparationReady' -and $preCloneSource -match '\$encryptionPolicyReady' -and $preCloneSource -notmatch '\$decryptionStartedAny') 'Pre-Clone prevents automatic re-encryption even when target drives were already decrypted'
Assert-AppTest ($finalCheckSource -match 'powercfg\.exe /hibernate off' -and $finalCheckSource -match 'Checkpoint-Computer' -and $finalCheckSource -match 'Did you clearly hear the speaker test' -and $finalCheckSource -match 'SystemSounds') 'Final System Check keeps hibernation, restore-point, and default-audio technician verification actions'
Assert-AppTest ($finalCheckSource -match 'SYSTEM READY: ATTENTION REQUIRED' -and $finalCheckSource -match 'exit \$finalExitCode' -and $mainFormSource -match 'ExitCode == 5') 'Final System Check returns a visible attention result when a required readiness check fails'
Assert-AppTest ($finalCheckSource -match "Set-Service -Name 'BDESVC' -StartupType Manual") 'Final System Check repairs BitLocker service state left by older Pre-Clone versions'
Assert-AppTest ($finalCheckSource -match 'PreClonePolicyBackup\.json' -and $finalCheckSource -match 'PreClonePolicyRestored\.json' -and $finalCheckSource -match '\$setting\.WasPresent' -and $finalCheckSource -match '\$setting\.PreviousValue') 'Final System Check restores each saved pre-clone policy state once instead of blindly deleting or repeatedly replaying it'
Assert-AppTest ($finalCheckSource -notmatch 'vssadmin\s+list' -and $finalCheckSource -match 'SystemRestorePointCreationFrequency' -and $finalCheckSource -match 'Get-ComputerRestorePoint') 'Final restore-point creation is language-neutral, bypasses the 24-hour skip, and verifies the new point'
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
Assert-AppTest ($toolboxSource -match 'Windows may take several minutes while each network adapter waits for DHCP' -and $toolboxSource -match 'Returning to the toolbox menu\.' -and $toolboxSource -notmatch 'WaitForExit') 'Slow IP renewal remains uninterrupted and toolbox action errors return safely to the menu'
Assert-AppTest ($toolboxSource -match 'finally\s*\{[\s\S]+?Start-Service -Name Spooler -ErrorAction Stop' -and $toolboxSource -match 'Get-ChildItem -LiteralPath \$printDir') 'Clear Print Queue restarts the spooler even when queue deletion fails and reports deletion errors'
Assert-AppTest ($embeddedEngineSource -match 'PrepareProtectedDirectory\(compuTekRoot\)' -and $embeddedEngineSource -match 'PrepareProtectedDirectory\(engineRoot\)' -and $embeddedEngineSource -match 'RejectReparsePoint' -and $embeddedEngineSource -match 'File\.Delete\(destination\)' -and $embeddedEngineSource -match 'File\.Move\(temporary, destination\)' -and $embeddedEngineSource.IndexOf('File.Exists(portableCatalog)') -lt $embeddedEngineSource.IndexOf('File.Exists(managedCatalog)')) 'Engine staging protects the full ProgramData hierarchy, replaces unsafe inherited file ACLs, rejects reparse points, and prefers the USB catalog'

$preCloneTokens = $null
$preCloneErrors = $null
$preCloneAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\PreClone.ps1'),[ref]$preCloneTokens,[ref]$preCloneErrors)
$recoveryFunctions = @($preCloneAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-CompuTekRecoveryProtectors','Save-CompuTekRecoveryPasswords')
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

$promptTokens = $null
$promptErrors = $null
$promptAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1'),[ref]$promptTokens,[ref]$promptErrors)
$promptFunction = @($promptAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-CompuTekInput'},$true))[0]
$probeScript = $promptFunction.Extent.Text + "`n`$probeValue = Read-CompuTekInput 'Probe prompt'`nWrite-Output ('RESULT:' + `$probeValue)"
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
Assert-AppTest (Test-Path -LiteralPath $catalogPath -PathType Leaf) 'Updateable signature catalog is published beside the EXE'
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
    Assert-AppTest ($assembly.GetName().Version.ToString() -eq '1.4.6.0') 'Built EXE reports version 1.4.6.0'
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
        $validCatalog = [IO.File]::ReadAllBytes($catalogPath)
        $catalogInfo = $validateMethod.Invoke($null,@($validCatalog,'test catalog'))
        Assert-AppTest ($catalogInfo.ProductCount -ge 60) 'Compiled catalog validator accepts the published catalog'
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
