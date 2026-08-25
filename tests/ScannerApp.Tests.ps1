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

$moduleSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1') -Raw
$mainFormSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\CompuTek.Scanner.App\MainForm.cs') -Raw
Assert-AppTest ($moduleSource -match 'SCAN STAGE:' -and $moduleSource -match 'Step 10 of 10' -and $moduleSource -match '\[Console\]::Out\.Flush\(\)') 'Remote scan publishes flushed, named progress stages to the EXE'
Assert-AppTest ($mainFormSource -match 'runningTimer' -and $mainFormSource -match 'Still working' -and $mainFormSource -match 'elapsedText') 'The Windows application shows elapsed-time heartbeats during quiet collectors'

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
        'CompuTek.Scanner.Engine.RemoteAccessScanAndRemove.ps1',
        'CompuTek.Scanner.Engine.PostScam_SystemIntegrityScanner.ps1',
        'CompuTek.Scanner.Engine.CompuTek.Scanner.Common.psm1',
        'CompuTek.Scanner.Engine.RemoteAccessSignatures.json'
    )) {
        Assert-AppTest ($resources -contains $resource) "EXE embeds trusted engine resource $resource"
    }
    Assert-AppTest ($null -ne $assembly.GetType('CompuTek.Scanner.App.MainForm',$false)) 'EXE contains the technician GUI'
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
