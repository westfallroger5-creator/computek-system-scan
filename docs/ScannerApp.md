# CompuTek Scanner Windows application

`CompuTekScanner.exe` is the technician-facing Windows application for remote-access review/removal, post-scam evidence collection, and the legacy CompuTek technician utilities. It requests administrator rights when opened; technicians no longer need to start a BAT file or manually open PowerShell.

## Files to keep together

- `CompuTekScanner.exe` — the application and embedded, versioned scanner engine.
- `RemoteAccessSignatures.json` — the updateable remote-software catalog.
- `SHA256SUMS.txt` — checksums for verifying the published EXE and catalog.

The EXE contains known-good copies of both scanners, the technician tools, and the shared scanner module. It stages those protected components under `%ProgramData%\CompuTek\ScannerApp\Engine` whenever it runs. The JSON catalog remains outside the EXE and can be replaced without rebuilding the program.

## Technician workflow

1. Double-click `CompuTekScanner.exe` and approve the Windows administrator prompt.
2. Confirm the signature version shown in the upper-right corner.
3. Choose the lookback period and optional full fixed-drive scan/file hashes. The normal scan uses a junction-safe, bounded search of high-risk user and shared-data folders. Full fixed-drive mode searches every fixed drive and can take considerably longer.
4. Leave **Remote scan only** checked for reporting without removal, or clear it to enter technician-reviewed removal mode.
5. Leave the application open while it reports the current collection stage and elapsed time. Large AppData or ProgramData folders can take several minutes; a visible **Still working** heartbeat confirms the scan has not frozen.
6. For removal mode, classify each detected installation with the exact `KEEP <review-id>` or `REMOVE <review-id>` response shown by the application. This happens separately for different installation locations, including two copies of the same product.
7. Review the decision summary and type `APPLY REMOVALS` only when the selections are correct.
8. Use **Open last case folder** after completion to review the evidence, decisions, remediation log, and verification report.

The post-scam collector is read-only. It gathers local evidence and collection gaps but cannot prove that no data was taken or that no custom/fileless backdoor exists.

## Technician tools

The **Technician tools** tab restores the original entry points:

- **IT Technician Toolbox** — system and network information, DNS/IP repair, internet testing, temporary-file cleanup, SFC, CHKDSK, DISM, Task Manager, print-queue cleanup, BitLocker, and reboot.
- **Final System Check** — the original readiness workflow, including its hibernation, restore-point, BitLocker, and audio actions.
- **Pre-Clone Preparation** — the original advanced BitLocker decryption/key-backup, Secure Boot, disk-check, and reboot workflow.

These tools are launched individually. The old **Run ALL scripts** choice is intentionally not present because it could start multiple disk, encryption, cleanup, and reboot operations together. The application displays a warning before each legacy workflow, and the embedded scripts retain their action-specific prompts. BitLocker recovery information is written beneath the USB/application folder rather than the protected staging directory.

## Updating remote-software signatures

Replace `RemoteAccessSignatures.json` beside the EXE, then select **Reload signatures**. The application validates the schema, catalog version, product entries, and duplicate IDs before it will run.

For centrally managed computers, place the catalog at `%ProgramData%\CompuTek\ScannerApp\RemoteAccessSignatures.json`. That managed catalog has priority over the portable file beside the EXE. A malformed priority catalog blocks scanning instead of silently falling back to older signatures.

## Building

From Windows PowerShell 5.1 at the repository root:

```powershell
.\build\Build-ScannerApp.ps1
```

The application is built under `artifacts\CompuTekScanner` with the .NET Framework 4.8 compiler included in supported Windows installations. No developer SDK or third-party package is required.

For a production release, sign the EXE with an organization code-signing certificate:

```powershell
.\build\Build-ScannerApp.ps1 -CodeSigningCertificateThumbprint '<certificate thumbprint>'
```

Do not distribute an unsigned production build as trusted CompuTek software.
