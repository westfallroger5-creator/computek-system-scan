[CmdletBinding()]
param(
    [Alias('ScannerExePath')]
    [string]$BuiltExePath,
    [switch]$RequireProductionSignature,
    [switch]$RequireCompuTekSplashtop,
    [switch]$SkipRemoteCoverageProbe,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$results = New-Object System.Collections.Generic.List[object]
$failures = 0

function Add-IntegrationResult {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    if (-not $Passed) { $script:failures++ }
    $script:results.Add([pscustomobject][ordered]@{Name=$Name;Passed=$Passed;Detail=$Detail})
    Write-Host ("{0}: {1} - {2}" -f $(if($Passed){'PASS'}else{'FAIL'}),$Name,$Detail) -ForegroundColor $(if($Passed){'Green'}else{'Red'})
}

$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-IntegrationResult 'Administrative context' $isAdministrator 'The production scanner and protected Windows inventories require elevation.'

try {
    $preClonePath = Join-Path $repoRoot 'scripts\PreClone.ps1'
    $preCloneTokens = $null
    $preCloneErrors = $null
    $preCloneAst = [System.Management.Automation.Language.Parser]::ParseFile($preClonePath,[ref]$preCloneTokens,[ref]$preCloneErrors)
    if ($preCloneErrors.Count -gt 0) { throw ($preCloneErrors | ForEach-Object {$_.Message} | Out-String) }
    $inventoryFunction = @($preCloneAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-CompuTekFixedPartitionInventory'
    },$true))[0]
    if (-not $inventoryFunction) { throw 'Get-CompuTekFixedPartitionInventory was not found.' }
    . ([scriptblock]::Create($inventoryFunction.Extent.Text))

    $windowsDriveLetter = ([string]$env:SystemDrive).TrimEnd(':')
    $windowsDiskNumber = [int](Get-Partition -DriveLetter $windowsDriveLetter -ErrorAction Stop | Select-Object -First 1).DiskNumber
    $expectedPartitions = @(Get-Partition -DiskNumber $windowsDiskNumber -ErrorAction Stop)
    $inventory = @(Get-CompuTekFixedPartitionInventory -TargetDiskNumber $windowsDiskNumber)
    $expectedKeys = @($expectedPartitions | ForEach-Object {'{0}/{1}' -f $_.DiskNumber,$_.PartitionNumber} | Sort-Object -Unique)
    $inventoryKeys = @($inventory | ForEach-Object {'{0}/{1}' -f $_.DiskNumber,$_.PartitionNumber} | Sort-Object -Unique)
    $missingKeys = @($expectedKeys | Where-Object {$_ -notin $inventoryKeys})
    $uncovered = @($inventory | Where-Object {-not $_.CoverageReady})
    $withoutDriveLetter = @($inventory | Where-Object {$_.RequiresDiskCheck -and -not $_.DriveLetter})
    $partitionPass = $expectedPartitions.Count -gt 0 -and $missingKeys.Count -eq 0 -and $uncovered.Count -eq 0
    Add-IntegrationResult 'Windows source-disk partition coverage' $partitionPass ("Pre-Clone source disk={0}; inventory={1}; source partitions={2}; missing={3}; unaccounted={4}; checkable without drive letter={5}" -f $windowsDiskNumber,$inventory.Count,$expectedPartitions.Count,$missingKeys.Count,$uncovered.Count,$withoutDriveLetter.Count)
} catch {
    Add-IntegrationResult 'Windows source-disk partition coverage' $false $_.Exception.Message
}

try {
    $finalCheckPath = Join-Path $repoRoot 'scripts\FinalSystemCheck_CompuTek.ps1'
    $finalCheckTokens = $null
    $finalCheckErrors = $null
    $finalCheckAst = [System.Management.Automation.Language.Parser]::ParseFile($finalCheckPath,[ref]$finalCheckTokens,[ref]$finalCheckErrors)
    if ($finalCheckErrors.Count -gt 0) { throw ($finalCheckErrors | ForEach-Object {$_.Message} | Out-String) }
    $antivirusFunction = @($finalCheckAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-CompuTekAntivirusProductState'
    },$true))[0]
    if (-not $antivirusFunction) { throw 'Get-CompuTekAntivirusProductState was not found.' }
    . ([scriptblock]::Create($antivirusFunction.Extent.Text))
    $securityProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    $decodedProducts = @($securityProducts | ForEach-Object {Get-CompuTekAntivirusProductState -Product $_})
    $activeProducts = @($decodedProducts | Where-Object {$_.Enabled -and $_.SignaturesCurrent})
    Add-IntegrationResult 'Antivirus state decoding' ($activeProducts.Count -gt 0) ("Windows Security Center reports {0} active product(s) with current signatures: {1}" -f $activeProducts.Count,(@($activeProducts.Name | Sort-Object -Unique) -join ', '))
} catch {
    Add-IntegrationResult 'Antivirus state decoding' $false $_.Exception.Message
}

$scannerModulePath = Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1'
$catalogPath = Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json'
try {
    Import-Module $scannerModulePath -Force -ErrorAction Stop
    $catalog = Get-CompuTekCatalog -Path $catalogPath
    Add-IntegrationResult 'Scanner module and catalog load' (@($catalog.products).Count -gt 0) ("catalog={0}; product families={1}" -f $catalog.catalogVersion,@($catalog.products).Count)
} catch {
    $catalog = $null
    Add-IntegrationResult 'Scanner module and catalog load' $false $_.Exception.Message
}

if (-not $SkipRemoteCoverageProbe -and $catalog) {
    try {
        Write-Host 'Running the actual read-only remote-access coverage probe. This may take several minutes...' -ForegroundColor Cyan
        $coverageScan = Invoke-CompuTekRemoteAccessScan -CatalogPath $catalogPath -LookbackDays 7
        $coveragePass = $coverageScan.IsComplete -and [int]$coverageScan.Stats.ArtifactsInspected -gt 0
        $coverageDetail = "complete={0}; artifacts={1}; findings={2}; errors={3}" -f $coverageScan.IsComplete,$coverageScan.Stats.ArtifactsInspected,@($coverageScan.Findings).Count,@($coverageScan.Errors).Count
        if (-not $coverageScan.IsComplete) { $coverageDetail += '; ' + (@($coverageScan.Errors) -join ' | ') }
        Add-IntegrationResult 'Required remote-access scan coverage' $coveragePass $coverageDetail
    } catch {
        Add-IntegrationResult 'Required remote-access scan coverage' $false $_.Exception.Message
    }
}

if ($RequireCompuTekSplashtop) {
    try {
        if (-not $catalog) { throw 'The scanner catalog did not load.' }
        $identity = Get-CompuTekManagedIdentityStatus -Catalog $catalog
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SplashtopRemoteService'" -ErrorAction Stop
        $servicePath = Get-CompuTekExecutablePath ([string]$service.PathName)
        $file = Get-CompuTekFileEvidence -Path $servicePath
        $verified = $identity.SplashtopLinked -and [string]$service.State -eq 'Running' -and
            (Test-CompuTekPathWithinRoots -Path $servicePath -Roots @($identity.SplashtopInstallRoots)) -and
            [string]$file.SignatureStatus -eq 'Valid' -and ("$($file.CompanyName) $($file.Signer)" -match '(?i)Splashtop')
        Add-IntegrationResult 'CompuTek Splashtop ownership' $verified ("running={0}; linked={1}; path={2}; signature={3}" -f ([string]$service.State -eq 'Running'),$identity.SplashtopLinked,$servicePath,$file.SignatureStatus)
    } catch {
        Add-IntegrationResult 'CompuTek Splashtop ownership' $false $_.Exception.Message
    }
}

if ($BuiltExePath) {
    try {
        $resolvedExe = [IO.Path]::GetFullPath($BuiltExePath)
        $signature = Get-AuthenticodeSignature -LiteralPath $resolvedExe -ErrorAction Stop
        $productionValid = $signature.Status -eq 'Valid' -and $signature.SignerCertificate -and $signature.TimeStamperCertificate
        $passed = if ($RequireProductionSignature) {[bool]$productionValid} else {Test-Path -LiteralPath $resolvedExe -PathType Leaf}
        Add-IntegrationResult 'EXE signature and timestamp' $passed ("status={0}; signer={1}; timestamp signer={2}" -f $signature.Status,$signature.SignerCertificate.Subject,$signature.TimeStamperCertificate.Subject)
    } catch {
        Add-IntegrationResult 'EXE signature and timestamp' $false $_.Exception.Message
    }
}

$document = [pscustomobject][ordered]@{
    SchemaVersion = 1
    ComputerName = $env:COMPUTERNAME
    CollectedUtc = [DateTime]::UtcNow.ToString('o')
    ReadOnly = $true
    Failures = $failures
    Results = @($results.ToArray())
}
if ($OutputPath) {
    $resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $resolvedOutput
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $document | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
    Write-Host "Integration result: $resolvedOutput" -ForegroundColor Cyan
}

if ($failures -gt 0) { exit 1 }
exit 0
