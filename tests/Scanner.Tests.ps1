$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json'
Import-Module $modulePath -Force

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
    'scripts\PostScam_SystemIntegrityScanner.ps1'
)) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot $relativePath),[ref]$tokens,[ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) "$relativePath parses in Windows PowerShell"
}
Assert-True (@($catalog.products).Count -ge 60) 'Catalog contains at least 60 remote-access/RMM product families'
Assert-True (@($catalog.products.id | Sort-Object -Unique).Count -eq @($catalog.products).Count) 'Catalog product IDs are unique'

$remediationSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1') -Raw
Assert-True ($remediationSource -match 'KEEP \$\(\$candidate\.Id\)' -and $remediationSource -match 'REMOVE \$\(\$candidate\.Id\)') 'Technician must explicitly keep or remove every installation scope'
Assert-True ($remediationSource -match "APPLY REMOVALS" -and $remediationSource -notmatch 'A for all') 'Bulk removal cannot start without a final typed confirmation'
Assert-True ($remediationSource -match 'PreservedRemoteToolData' -and $remediationSource -match 'TechnicianDecisions\.json') 'Operational evidence and technician decisions are preserved'
Assert-True ($remediationSource -match 'Protect-CompuTekEvidenceDirectory' -and $remediationSource -match 'S-1-5-32-544') 'Case and quarantine evidence is restricted to SYSTEM and Administrators'
Assert-True ($remediationSource -match 'sc\.exe delete' -and $remediationSource -match 'Unregister-ScheduledTask') 'Full removal deletes residual service and scheduled-task persistence'
Assert-True ($remediationSource -match 'RemovalVerified' -and $remediationSource -match 'NotVerified-ScanIncomplete') 'Removal is only verified after a complete follow-up scan'

$moduleSource = Get-Content -LiteralPath $modulePath -Raw
Assert-True ($moduleSource -match 'TaskPath\s*= \$task\.TaskPath' -and $moduleSource -match 'SourcePath = \$file\.FullName') 'Task and Startup-file source locations are retained for exact removal'

$remediationTokens = $null
$remediationErrors = $null
$remediationAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1'),[ref]$remediationTokens,[ref]$remediationErrors)
foreach ($functionName in @('Get-FindingScopePath','New-RemovalCandidates')) {
    $functionAst = @($remediationAst.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true))[0]
    Invoke-Expression $functionAst.Extent.Text
}
$legitimateInstall = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='InstalledProgram';Name='Company Support';Path='C:\Program Files\ScreenConnect';InstallLocation='C:\Program Files\ScreenConnect';RegistryPath='HKLM:\Software\Uninstall\CompanySupport';PackageFullName=$null}
$legitimateService = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Company';Path='C:\Program Files\ScreenConnect\Client\ScreenConnect.ClientService.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null}
$hiddenService = [pscustomobject]@{ProductId='screenconnect';ProductName='ScreenConnect / ConnectWise Control';Category='remote-support';ArtifactType='Service';Name='ScreenConnect Client Hidden';Path='C:\Users\Victim\AppData\Roaming\Adobe\AdobeReader.exe';InstallLocation=$null;RegistryPath=$null;PackageFullName=$null}
$scopes = @(New-RemovalCandidates @($legitimateInstall,$legitimateService,$hiddenService))
Assert-True ($scopes.Count -eq 2) 'Approved and hidden copies of the same product are presented as separate technician decisions'
Assert-True (@($scopes | Where-Object {$_.ScopePath -eq 'C:\Program Files\ScreenConnect'}).Findings.Count -eq 2) 'Subfolder services are grouped with their registered installation'
Assert-True (@($scopes | Where-Object {$_.ScopePath -eq 'C:\Users\Victim\AppData\Roaming\Adobe'}).Count -eq 1) 'Hidden AppData copy remains isolated from the approved installation'

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

$zohoBooks = New-TestEvidence @{
    ArtifactType='InstalledProgram';Name='Zoho Books';DisplayName='Zoho Books';Path='C:\Program Files\Zoho\Books\books.exe'
    Publisher='Zoho Corporation';ProductName='Zoho Books';FileName='books.exe'
}
$matches = @(Find-CompuTekProductMatch -Catalog $catalog -Evidence $zohoBooks)
Assert-True ($matches.Product.id -notcontains 'zoho-assist') 'Broad Zoho publisher does not misidentify another Zoho product as Zoho Assist'

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

if ($script:Failures -gt 0) {
    Write-Host "$script:Failures test(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All scanner tests passed.' -ForegroundColor Green
exit 0
