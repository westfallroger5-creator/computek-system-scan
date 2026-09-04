# CompuTek internal catalog-signing certificate

This public metadata identifies the internal key currently trusted by CompuTek Scanner builds. It is not secret.

- Subject: `CN=CompuTek Internal Remote-Access Catalog Signing`
- Thumbprint: `189585B486CA28390D5128AC4FB81C691D76F3EB`
- Algorithm: RSA 3072 / SHA-256
- Validity: September 4, 2026 through September 4, 2036
- Private-key location: `Cert:\CurrentUser\My` on the authorized CompuTek build computer
- Intended use: detached signatures for `RemoteAccessSignatures.json` only

The private key is exportable only in encrypted form. It must never be committed to Git, copied into a release ZIP, or stored on a technician USB. Create an encrypted PFX backup with a strong password and store the PFX and password separately in company-controlled secure storage. Losing this private key requires rebuilding the EXE with a new embedded public key; compromise requires replacing the key and every affected package.

Build an unsigned internal EXE that trusts this key and publishes a signed external catalog:

```powershell
.\build\Build-ScannerApp.ps1 `
  -CatalogSigningCertificateThumbprint '189585B486CA28390D5128AC4FB81C691D76F3EB'
```

Sign a reviewed catalog update without rebuilding the EXE:

```powershell
.\build\Sign-RemoteAccessCatalog.ps1 `
  -CatalogPath '<release folder>\RemoteAccessSignatures.json' `
  -CertificateThumbprint '189585B486CA28390D5128AC4FB81C691D76F3EB' `
  -UpdateChecksumManifest
```

Copy both `RemoteAccessSignatures.json` and `RemoteAccessSignatures.json.sig` to the technician USB. The EXE remains unsigned until an organization code-signing certificate is supplied, but it will cryptographically reject catalog changes not signed by this internal key.
