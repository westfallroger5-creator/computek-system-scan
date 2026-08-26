# CompuTek Scanner Windows application

`CompuTekScanner.exe` is the technician-facing Windows application for remote-access review/removal, post-scam evidence collection, and CompuTek technician utilities. It requests administrator rights when opened; the obsolete BAT and PowerShell launchers are no longer used.

The CompuTek logo is embedded in the application header and program icon. The USB does not need a separate logo file.

## Files to keep together

- `CompuTekScanner.exe` — the application and embedded, versioned scanner engine.
- `RemoteAccessSignatures.json` — the updateable remote-software catalog.
- `SHA256SUMS.txt` — checksums for verifying the published EXE and catalog.

The EXE contains known-good copies of both scanners, the technician tools, and the shared scanner module. It stages those protected components under `%ProgramData%\CompuTek\ScannerApp\Engine` whenever it runs. The JSON catalog remains outside the EXE and can be replaced without rebuilding the program.

Reports and quarantine data saved on the service USB use the drive's normal inherited permissions. The application does not apply an administrator-only lock, so old cases can be archived or deleted normally.

## Technician workflow

1. Double-click `CompuTekScanner.exe` and approve the Windows administrator prompt.
2. Confirm the signature version shown in the upper-right corner.
3. Choose the lookback period and optional full fixed-drive scan/file hashes. The normal scan uses a junction-safe, bounded search of high-risk user and shared-data folders. Full fixed-drive mode searches every fixed drive and can take considerably longer.
4. The remote scanner always displays its findings and offers technician-reviewed removal when findings exist. It never removes anything automatically. Findings are grouped by product and detected version: protecting copies of the same version are reviewed together, while different versions remain separate. Version-unknown items stay separated by location.
5. Leave the application open while the bottom status bar reports the current collection stage and elapsed time. The program does not add repetitive elapsed-time lines to the findings area.
6. Classify each detected product/version group with the exact `KEEP <review-id>` or `REMOVE <review-id>` response shown by the application.
7. Review the decision summary and type `APPLY REMOVALS` only when the selections are correct. Without that exact final phrase, nothing is removed.
8. For approved removals, the vendor uninstaller runs first. If it fails, the scanner stops/disables the matching services, terminates processes at exact matching executable paths, and retries once. If verification still finds that version, open `ManualRemovalRequired.txt` in the USB case folder for exact remaining locations; a technician can then reboot, rescan, or perform manual/Safe Mode removal.
9. Use **Open last case folder** after completion to review the USB evidence, decisions, remediation log, and verification report.

The post-scam collector is read-only and focused on actionable persistence, hidden access, security changes, suspicious execution, and possible customer harm. Repeated records are consolidated in `ActionableFindings.txt`; supplemental inventory is saved separately and not shown as a finding. It cannot prove that no data was taken or that no custom/fileless backdoor exists. A technician can run the script directly with `-ExtendedForensics` when broader data-access/staging leads are required.

All application sessions save a readable log beside the EXE under `CompuTekData/<COMPUTERNAME>/ApplicationSessions`. Remote-scan cases, post-scam evidence, Toolbox logs and CHKDSK reports are also stored under that computer's `CompuTekData` folder on the service USB. Pre-Clone recovery material remains under `BitLockerKeys/<COMPUTERNAME>`.

## Technician tools

The first/default **Final system check** page contains the store's most-used workflow and supports the `Alt+R` keyboard shortcut. The remaining tabs provide security scans and advanced technician tools:

- **IT Technician Toolbox** — system and network information, DNS/IP repair, internet testing, temporary-file cleanup, SFC, CHKDSK, DISM, Task Manager, print-queue cleanup, verified BitLocker enablement, and reboot. CHKDSK begins read-only; `/F` or `/R` is offered only after the scan reports a problem and requires an exact technician phrase. BitLocker also requires exact approval and a complete recovery-password file that passes a service-USB read-back check before encryption starts.
- **Final System Check** — the standard final-store workflow. It disables hibernation, checks activation, security, updates, devices and Splashtop, creates a restore point, un-mutes and sets speaker volume to 50%, plays the test melody, and asks the technician to confirm it was heard.
- **Pre-Clone Preparation** — the Acronis readiness gate. It verifies complete BitLocker recovery-password files on the service USB before decryption, waits for full decryption, and runs non-destructive CHKDSK scans.

These tools are launched individually; there is no **Run ALL scripts** action. The application explains each workflow before it starts, and the embedded scripts retain their action-specific prompts. BitLocker recovery information is written beneath the USB/application folder rather than the protected staging directory.

Pre-Clone displays **READY FOR ACRONIS CLONE: YES** only after every fixed target drive is fully decrypted and CHKDSK returns no errors. A cancelled prompt, missing or unverified recovery password, incomplete decryption, failed status query, or disk error produces **NOT READY**. Each run saves a readable summary, JSON details, CHKDSK logs, and hashes beneath `BitLockerKeys/<COMPUTERNAME>/PreClone_<timestamp>`.

BitLocker recovery passwords are confidential and can unlock customer data. Keep the service USB under technician control, never save a key onto the drive it unlocks, and secure or remove customer key files after the job is complete.

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
