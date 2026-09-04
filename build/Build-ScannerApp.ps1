[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$CodeSigningCertificateThumbprint,
    [string]$CatalogSigningCertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$ProductionRelease
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-CompuTekSigningCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Purpose)
    $normalized = $Thumbprint.Replace(' ','')
    $certificate = @(
        Get-ChildItem 'Cert:\CurrentUser\My','Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object {$_.Thumbprint -eq $normalized} |
            Select-Object -First 1
    )
    if (-not $certificate) { throw "$Purpose certificate was not found: $normalized" }
    if (-not $certificate[0].HasPrivateKey) { throw "$Purpose certificate has no accessible private key: $normalized" }
    return $certificate[0]
}

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
if ($ProductionRelease -and [string]::IsNullOrWhiteSpace($CodeSigningCertificateThumbprint)) {
    throw 'A production release requires -CodeSigningCertificateThumbprint.'
}
if ($ProductionRelease -and [string]::IsNullOrWhiteSpace($CatalogSigningCertificateThumbprint)) {
    $CatalogSigningCertificateThumbprint = $CodeSigningCertificateThumbprint
}
$codeSigningCertificate = if ($CodeSigningCertificateThumbprint) { Get-CompuTekSigningCertificate -Thumbprint $CodeSigningCertificateThumbprint -Purpose 'EXE code-signing' } else { $null }
$catalogSigningCertificate = if ($CatalogSigningCertificateThumbprint) { Get-CompuTekSigningCertificate -Thumbprint $CatalogSigningCertificateThumbprint -Purpose 'Catalog-signing' } else { $null }
$buildTempDirectory = Join-Path $systemTempRoot ('CompuTekScannerBuild-' + [Guid]::NewGuid().ToString('N'))
New-Item -Path $buildTempDirectory -ItemType Directory -Force | Out-Null

try {
    if ($catalogSigningCertificate) {
        $publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($catalogSigningCertificate)
        if (-not $publicRsa) { throw 'The catalog-signing certificate must contain an RSA public key.' }
        try { $publicKeyXml = $publicRsa.ToXmlString($false) } finally { $publicRsa.Dispose() }
        $catalogPublicKeyPath = Join-Path $buildTempDirectory 'CatalogPublicKey.xml'
        [IO.File]::WriteAllText($catalogPublicKeyPath,$publicKeyXml,(New-Object Text.UTF8Encoding($false)))
        $engineResources[$catalogPublicKeyPath] = 'CompuTek.Scanner.Trust.CatalogPublicKey.xml'
    }

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
$catalogSignatureDestination = $catalogDestination + '.sig'
foreach ($staleCatalogFile in @($catalogDestination,$catalogSignatureDestination)) {
    if (Test-Path -LiteralPath $staleCatalogFile -PathType Leaf) { Remove-Item -LiteralPath $staleCatalogFile -Force }
}
if ($catalogSigningCertificate) {
    Copy-Item -LiteralPath (Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json') -Destination $catalogDestination -Force
    $catalogBytes = [IO.File]::ReadAllBytes($catalogDestination)
    $catalogRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($catalogSigningCertificate)
    if (-not $catalogRsa) { throw 'The catalog-signing certificate must expose an RSA private key.' }
    try {
        $catalogSignature = $catalogRsa.SignData($catalogBytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } finally { $catalogRsa.Dispose() }
    $catalogHash = (Get-FileHash -LiteralPath $catalogDestination -Algorithm SHA256).Hash
    $signatureDocument = [ordered]@{
        schemaVersion = 1
        algorithm = 'RSASSA-PKCS1-v1_5-SHA256'
        catalogFile = 'RemoteAccessSignatures.json'
        catalogSha256 = $catalogHash
        signingCertificateThumbprint = $catalogSigningCertificate.Thumbprint
        signature = [Convert]::ToBase64String($catalogSignature)
    } | ConvertTo-Json
    [IO.File]::WriteAllText($catalogSignatureDestination,$signatureDocument,(New-Object Text.UTF8Encoding($false)))
}
$guideSource = Join-Path $repoRoot 'docs\ScannerApp.md'
if (Test-Path -LiteralPath $guideSource -PathType Leaf) {
    Copy-Item -LiteralPath $guideSource -Destination (Join-Path $OutputDirectory 'README.md') -Force
}

if ($codeSigningCertificate) {
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) { throw 'A timestamp server is required when signing the EXE.' }
    $signature = Set-AuthenticodeSignature -LiteralPath $executable -Certificate $codeSigningCertificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop
    if ($signature.Status -ne 'Valid') { throw "EXE signing failed: $($signature.StatusMessage)" }
    $verifiedSignature = Get-AuthenticodeSignature -LiteralPath $executable
    if ($verifiedSignature.Status -ne 'Valid' -or -not $verifiedSignature.SignerCertificate -or -not $verifiedSignature.TimeStamperCertificate) {
        throw 'The production EXE did not pass signer and timestamp verification after signing.'
    }
}

$publishedFiles = @($executable,$catalogDestination,$catalogSignatureDestination) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf}
$hashLines = $publishedFiles | ForEach-Object {
    $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
    '{0} *{1}' -f $hash.Hash,(Split-Path -Leaf $_)
}
$hashLines | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ASCII

Write-Host "Built: $executable" -ForegroundColor Green
if ($catalogSigningCertificate) {
    Write-Host "Signed external catalog: $catalogDestination" -ForegroundColor Green
    Write-Host "Detached catalog signature: $catalogSignatureDestination" -ForegroundColor Green
} else {
    Write-Host 'No external catalog was published because no catalog-signing certificate was provided; the development EXE uses its trusted embedded catalog.' -ForegroundColor Yellow
}
if (-not $codeSigningCertificate) { Write-Host 'Development build: the executable is unsigned.' -ForegroundColor Yellow }
return [pscustomobject]@{
    Executable = $executable
    Catalog = if (Test-Path -LiteralPath $catalogDestination) {$catalogDestination} else {$null}
    CatalogSignature = if (Test-Path -LiteralPath $catalogSignatureDestination) {$catalogSignatureDestination} else {$null}
    OutputDirectory = $OutputDirectory
}
} finally {
    $resolvedBuildTemp = [IO.Path]::GetFullPath($buildTempDirectory)
    $allowedPrefix = $systemTempRoot + '\CompuTekScannerBuild-'
    if ($resolvedBuildTemp.StartsWith($allowedPrefix,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedBuildTemp)) {
        Remove-Item -LiteralPath $resolvedBuildTemp -Recurse -Force
    }
}
