[CmdletBinding()]
param(
    [string]$CatalogPath,
    [Parameter(Mandatory)]
    [string]$CertificateThumbprint,
    [string]$SignaturePath,
    [switch]$UpdateChecksumManifest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CatalogPath)) {
    $CatalogPath = Join-Path $repoRoot 'scripts\RemoteAccessSignatures.json'
}
$CatalogPath = [IO.Path]::GetFullPath($CatalogPath)
if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) {
    throw "Catalog was not found: $CatalogPath"
}
if ((Get-Item -LiteralPath $CatalogPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "A linked or redirected catalog will not be signed: $CatalogPath"
}
if ([string]::IsNullOrWhiteSpace($SignaturePath)) { $SignaturePath = $CatalogPath + '.sig' }
$SignaturePath = [IO.Path]::GetFullPath($SignaturePath)
if (Test-Path -LiteralPath $SignaturePath) {
    if ((Get-Item -LiteralPath $SignaturePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "A linked or redirected signature path will not be overwritten: $SignaturePath"
    }
}

$catalogBytes = [IO.File]::ReadAllBytes($CatalogPath)
if ($catalogBytes.Length -eq 0 -or $catalogBytes.Length -gt 10MB) {
    throw 'The catalog must contain between 1 byte and 10 MB of JSON data.'
}
$catalog = [Text.Encoding]::UTF8.GetString($catalogBytes) | ConvertFrom-Json -ErrorAction Stop
if ([int]$catalog.schemaVersion -ne 1 -or [string]::IsNullOrWhiteSpace([string]$catalog.catalogVersion)) {
    throw 'The catalog schemaVersion or catalogVersion is invalid.'
}
$products = @($catalog.products)
if ($products.Count -eq 0) { throw 'The catalog contains no product signatures.' }
$productIds = @($products | ForEach-Object {[string]$_.id})
if (@($productIds | Where-Object {[string]::IsNullOrWhiteSpace($_)}).Count -gt 0) {
    throw 'Every product signature must have an ID.'
}
if (@($productIds | Group-Object | Where-Object {$_.Count -gt 1}).Count -gt 0) {
    throw 'The catalog contains duplicate product IDs.'
}

$normalizedThumbprint = $CertificateThumbprint.Replace(' ','')
$certificate = @(Get-ChildItem 'Cert:\CurrentUser\My','Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
    Where-Object {$_.Thumbprint -eq $normalizedThumbprint} |
    Select-Object -First 1)[0]
if (-not $certificate) { throw "Catalog-signing certificate was not found: $normalizedThumbprint" }
if (-not $certificate.HasPrivateKey) { throw 'The catalog-signing certificate has no accessible private key.' }
$now = Get-Date
if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) { throw 'The catalog-signing certificate is not currently valid.' }

$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
if (-not $rsa) { throw 'The catalog-signing certificate must expose an RSA private key.' }
try {
    $signatureBytes = $rsa.SignData(
        $catalogBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
} finally {
    $rsa.Dispose()
}

$publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
if (-not $publicRsa) { throw 'The catalog-signing certificate has no RSA public key.' }
try {
    $verified = $publicRsa.VerifyData(
        $catalogBytes,
        $signatureBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
} finally {
    $publicRsa.Dispose()
}
if (-not $verified) { throw 'The generated catalog signature failed immediate verification.' }

$catalogHash = (Get-FileHash -LiteralPath $CatalogPath -Algorithm SHA256).Hash
$signatureDocument = [ordered]@{
    schemaVersion = 1
    algorithm = 'RSASSA-PKCS1-v1_5-SHA256'
    catalogFile = (Split-Path -Leaf $CatalogPath)
    catalogSha256 = $catalogHash
    signingCertificateThumbprint = $certificate.Thumbprint
    signingCertificateSubject = $certificate.Subject
    signedUtc = [DateTime]::UtcNow.ToString('o')
    signature = [Convert]::ToBase64String($signatureBytes)
} | ConvertTo-Json

$signatureParent = Split-Path -Parent $SignaturePath
if (-not (Test-Path -LiteralPath $signatureParent -PathType Container)) {
    New-Item -Path $signatureParent -ItemType Directory -Force | Out-Null
}
[IO.File]::WriteAllText($SignaturePath,$signatureDocument,(New-Object Text.UTF8Encoding($false)))

$checksumPath = $null
if ($UpdateChecksumManifest) {
    $checksumPath = Join-Path $signatureParent 'SHA256SUMS.txt'
    $packageFiles = New-Object System.Collections.Generic.List[string]
    $packageExe = Join-Path $signatureParent 'CompuTekScanner.exe'
    if (Test-Path -LiteralPath $packageExe -PathType Leaf) { $packageFiles.Add($packageExe) }
    $packageFiles.Add($CatalogPath)
    $packageFiles.Add($SignaturePath)
    $hashLines = @($packageFiles.ToArray() | Select-Object -Unique | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        '{0} *{1}' -f $hash.Hash,(Split-Path -Leaf $_)
    })
    $hashLines | Set-Content -LiteralPath $checksumPath -Encoding ASCII
}

Write-Host "Signed catalog: $CatalogPath" -ForegroundColor Green
Write-Host "Detached signature: $SignaturePath" -ForegroundColor Green
Write-Host "Catalog version: $($catalog.catalogVersion)" -ForegroundColor Cyan
Write-Host "Certificate thumbprint: $($certificate.Thumbprint)" -ForegroundColor Cyan
if ($checksumPath) { Write-Host "Updated checksums: $checksumPath" -ForegroundColor Cyan }

return [pscustomobject]@{
    CatalogPath = $CatalogPath
    SignaturePath = $SignaturePath
    CatalogVersion = [string]$catalog.catalogVersion
    CatalogSha256 = $catalogHash
    CertificateThumbprint = $certificate.Thumbprint
    ChecksumPath = $checksumPath
}
