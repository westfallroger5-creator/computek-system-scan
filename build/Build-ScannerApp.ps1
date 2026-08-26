[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$CodeSigningCertificateThumbprint
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot 'artifacts\CompuTekScanner'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

$compilerCandidates = @(
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$compiler = @($compilerCandidates | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1)
if (-not $compiler) { throw '.NET Framework 4.8 C# compiler was not found.' }
$compiler = [string]$compiler[0]

$sourceRoot = Join-Path $repoRoot 'src\CompuTek.Scanner.App'
$sourceFiles = @(
    'Program.cs',
    'MainForm.cs',
    'Branding.cs',
    'CatalogValidator.cs',
    'EmbeddedEngine.cs',
    'ScannerEngineHost.cs',
    'AssemblyInfo.cs'
) | ForEach-Object {Join-Path $sourceRoot $_}
foreach ($sourceFile in $sourceFiles) {
    if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) { throw "Application source file is missing: $sourceFile" }
}

$engineResources = [ordered]@{
    (Join-Path $repoRoot 'scripts\RemoteAccessScanAndRemove.ps1') = 'CompuTek.Scanner.Engine.RemoteAccessScanAndRemove.ps1'
    (Join-Path $repoRoot 'scripts\PostScam_SystemIntegrityScanner.ps1') = 'CompuTek.Scanner.Engine.PostScam_SystemIntegrityScanner.ps1'
    (Join-Path $repoRoot 'scripts\IT_Technician_Toolbox.ps1') = 'CompuTek.Scanner.Engine.IT_Technician_Toolbox.ps1'
    (Join-Path $repoRoot 'scripts\FinalSystemCheck_CompuTek.ps1') = 'CompuTek.Scanner.Engine.FinalSystemCheck_CompuTek.ps1'
    (Join-Path $repoRoot 'scripts\PreClone.ps1') = 'CompuTek.Scanner.Engine.PreClone.ps1'
    (Join-Path $repoRoot 'scripts\CompuTek.Scanner.Common.psm1') = 'CompuTek.Scanner.Engine.CompuTek.Scanner.Common.psm1'
    (Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json') = 'CompuTek.Scanner.Engine.RemoteAccessSignatures.json'
}
foreach ($resourcePath in $engineResources.Keys) {
    if (-not (Test-Path -LiteralPath $resourcePath -PathType Leaf)) { throw "Scanner engine resource is missing: $resourcePath" }
}

$logoBase64Path = Join-Path $sourceRoot 'CompuTekLogo.png.base64'
if (-not (Test-Path -LiteralPath $logoBase64Path -PathType Leaf)) { throw "CompuTek logo source is missing: $logoBase64Path" }
$systemTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$buildTempDirectory = Join-Path $systemTempRoot ('CompuTekScannerBuild-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $buildTempDirectory -ItemType Directory -Force | Out-Null

try {
    $logoBase64 = (Get-Content -LiteralPath $logoBase64Path -Raw -ErrorAction Stop) -replace '\s',''
    $logoBytes = [Convert]::FromBase64String($logoBase64)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $logoHash = ([BitConverter]::ToString($sha256.ComputeHash($logoBytes))).Replace('-','') } finally { $sha256.Dispose() }
    if ($logoHash -ne 'C8894EA95E7062A8E720471CFC53BBEDEB5A3E337CE00B1301619B9A741338A1') {
        throw "CompuTek logo failed its integrity check: $logoHash"
    }

    Add-Type -AssemblyName System.Drawing
    $logoPngPath = Join-Path $buildTempDirectory 'CompuTekLogo.png'
    $logoIconPngPath = Join-Path $buildTempDirectory 'CompuTekLogo.Icon.png'
    $logoIconPath = Join-Path $buildTempDirectory 'CompuTekLogo.ico'
    [IO.File]::WriteAllBytes($logoPngPath,$logoBytes)

    $sourceLogo = [Drawing.Image]::FromFile($logoPngPath)
    try {
        if ($sourceLogo.Width -ne 86 -or $sourceLogo.Height -ne 57) { throw 'CompuTek logo dimensions are not the approved 86x57 pixels.' }
        $iconCanvas = [Drawing.Bitmap]::new(128,128)
        try {
            $graphics = [Drawing.Graphics]::FromImage($iconCanvas)
            try {
                $graphics.Clear([Drawing.Color]::Transparent)
                $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
                $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
                $scale = [Math]::Min(116.0 / $sourceLogo.Width,116.0 / $sourceLogo.Height)
                $drawWidth = [int][Math]::Round($sourceLogo.Width * $scale)
                $drawHeight = [int][Math]::Round($sourceLogo.Height * $scale)
                $destination = [Drawing.Rectangle]::new([int]((128-$drawWidth)/2),[int]((128-$drawHeight)/2),$drawWidth,$drawHeight)
                $graphics.DrawImage($sourceLogo,$destination)
            } finally { $graphics.Dispose() }
            $iconCanvas.Save($logoIconPngPath,[Drawing.Imaging.ImageFormat]::Png)
        } finally { $iconCanvas.Dispose() }
    } finally { $sourceLogo.Dispose() }

    $iconPngBytes = [IO.File]::ReadAllBytes($logoIconPngPath)
    $iconHeader = New-Object byte[] 22
    [BitConverter]::GetBytes([UInt16]1).CopyTo($iconHeader,2)
    [BitConverter]::GetBytes([UInt16]1).CopyTo($iconHeader,4)
    $iconHeader[6] = 128
    $iconHeader[7] = 128
    [BitConverter]::GetBytes([UInt16]1).CopyTo($iconHeader,10)
    [BitConverter]::GetBytes([UInt16]32).CopyTo($iconHeader,12)
    [BitConverter]::GetBytes([UInt32]$iconPngBytes.Length).CopyTo($iconHeader,14)
    [BitConverter]::GetBytes([UInt32]22).CopyTo($iconHeader,18)
    $iconBytes = New-Object byte[] ($iconHeader.Length + $iconPngBytes.Length)
    [Array]::Copy($iconHeader,0,$iconBytes,0,$iconHeader.Length)
    [Array]::Copy($iconPngBytes,0,$iconBytes,$iconHeader.Length,$iconPngBytes.Length)
    [IO.File]::WriteAllBytes($logoIconPath,$iconBytes)
    $engineResources[$logoPngPath] = 'CompuTek.Scanner.Branding.CompuTekLogo.png'

$executable = Join-Path $OutputDirectory 'CompuTekScanner.exe'
$manifest = Join-Path $sourceRoot 'app.manifest'
$arguments = @(
    '/nologo',
    '/target:winexe',
    '/platform:anycpu',
    '/optimize+',
    '/checked+',
    '/warn:4',
    '/utf8output',
    "/out:$executable",
    "/win32manifest:$manifest",
    "/win32icon:$logoIconPath",
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Web.Extensions.dll'
)
foreach ($resourcePath in $engineResources.Keys) {
    $arguments += "/resource:$resourcePath,$($engineResources[$resourcePath])"
}
$arguments += $sourceFiles

Write-Host "Building CompuTekScanner.exe with $compiler" -ForegroundColor Cyan
& $compiler @arguments
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "C# compiler failed with exit code $LASTEXITCODE."
}

$catalogDestination = Join-Path $OutputDirectory 'RemoteAccessSignatures.json'
Copy-Item -LiteralPath (Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json') -Destination $catalogDestination -Force
$guideSource = Join-Path $repoRoot 'docs\ScannerApp.md'
if (Test-Path -LiteralPath $guideSource -PathType Leaf) {
    Copy-Item -LiteralPath $guideSource -Destination (Join-Path $OutputDirectory 'README.md') -Force
}

if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    $thumbprint = $CodeSigningCertificateThumbprint.Replace(' ','')
    $certificate = @(
        Get-ChildItem 'Cert:\CurrentUser\My','Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object {$_.Thumbprint -eq $thumbprint} |
            Select-Object -First 1
    )
    if (-not $certificate) { throw "Code-signing certificate was not found: $thumbprint" }
    $signature = Set-AuthenticodeSignature -LiteralPath $executable -Certificate $certificate[0] -HashAlgorithm SHA256 -ErrorAction Stop
    if ($signature.Status -ne 'Valid') { throw "EXE signing failed: $($signature.StatusMessage)" }
}

$hashLines = @($executable,$catalogDestination) | ForEach-Object {
    $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
    '{0} *{1}' -f $hash.Hash,(Split-Path -Leaf $_)
}
$hashLines | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ASCII

Write-Host "Built: $executable" -ForegroundColor Green
Write-Host "External signatures: $catalogDestination" -ForegroundColor Green
Write-Host 'The executable is unsigned unless -CodeSigningCertificateThumbprint was provided.' -ForegroundColor Yellow
return [pscustomobject]@{
    Executable = $executable
    Catalog = $catalogDestination
    OutputDirectory = $OutputDirectory
}
} finally {
    $resolvedBuildTemp = [IO.Path]::GetFullPath($buildTempDirectory)
    $allowedPrefix = $systemTempRoot + '\CompuTekScannerBuild-'
    if ($resolvedBuildTemp.StartsWith($allowedPrefix,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedBuildTemp)) {
        Remove-Item -LiteralPath $resolvedBuildTemp -Recurse -Force
    }
}
