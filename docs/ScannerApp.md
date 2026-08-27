# CompuTek Scanner Windows application

`CompuTekScanner.exe` is the technician-facing Windows application for remote-access review/removal, post-scam evidence collection, and CompuTek technician utilities. It requests administrator rights when opened; the obsolete BAT and PowerShell launchers are no longer used.

The CompuTek logo is embedded in the application header and program icon. The USB does not need a separate logo file.

## Files to keep together

- `CompuTekScanner.exe` — the application and embedded, versioned scanner engine.
- `RemoteAccessSignatures.json` — the updateable remote-software catalog.
- `SHA256SUMS.txt` — checksums for verifying the published EXE and catalog.

The EXE contains known-good copies of both scanners, the technician tools, and the shared scanner module. It stages those protected components under `%ProgramData%\CompuTek\ScannerApp\Engine` whenever it runs. The full staging hierarchy is restricted to Administrators and SYSTEM, linked/reparse-point staging paths are rejected, and staged files are recreated with the protected inherited permissions. The JSON catalog remains outside the EXE and can be replaced without rebuilding the program.

Reports and quarantine data saved on the service USB use the drive's normal inherited permissions. The application does not apply an administrator-only lock, so old cases can be archived or deleted normally.

## Technician workflow

1. Double-click `CompuTekScanner.exe` and approve the Windows administrator prompt.
2. Confirm the signature version shown in the upper-right corner.
3. The default lookback is 7 days. Change it when a case needs a wider period, and optionally select full fixed-drive scan/file hashes. The normal scan uses a junction-safe, bounded search of high-risk user and shared-data folders.
4. The remote scanner always displays its findings and offers technician-reviewed removal when findings exist. It never removes anything automatically. Store software is checked through combined all-user packages, current-user packages, and current-user Start registrations so TeamViewer Remote and Team Remote Desktop are not dependent on one Windows inventory. It also inventories the all-users Startup folder and every user profile's Startup folder, resolves shortcuts and scripts, and flags commands that could redownload or reinstall an agent at sign-in. Ordinary entries that do not match remote software or suspicious persistence remain in the saved USB inventory without cluttering the review list. When Syncro is present, the CompuTek Syncro agent and bundled Splashtop components display once as a green **Managed** suite; standalone Splashtop and separate ScreenConnect versions remain independently reviewable.
5. Leave the application open while the bottom status bar reports the current collection stage and elapsed time. The program does not add repetitive elapsed-time lines to the findings area.
6. Classify numbered agents in batches, for example `KEEP 1,3-5`, `KEEP NONE`, `REMOVE 2,6-8`, or `REMOVE ALL`. Type `OPEN 1` or `OPEN 2,4-5` at either decision prompt to show detected downloaded installers or portable remote-tool files in File Explorer. `OPEN` does not open installed Program Files folders. Every number must appear in exactly one KEEP or REMOVE list.
7. Review the proposed decision summary. Type `YES` to approve the displayed decisions, `R` to re-enter the lists, or `Q` to stop without changes. This is the only removal confirmation.
8. After every approved removal batch, wait for the automatic verification scan. A removal is complete only when it reports `RemovalVerified`; otherwise follow the saved technician-action report. Store verification follows the selected product across AppX and Start-menu inventory views so Windows cannot produce a false success by changing how it reports the same installation.
9. For approved removals, the scanner first quarantines an exact matching Startup-folder relaunch item, then runs the vendor uninstaller. If it fails, the scanner stops/disables the matching services, terminates processes at exact matching executable paths, and retries once. Store packages use Windows package removal first and can fall back to their exact Store ID when needed; this product-wide fallback is disabled if another version was approved to keep. Broad shared/system/profile folders and linked or redirected paths are never moved automatically. A complete before/after Startup inventory is saved as JSON and CSV. If verification still finds that version or cannot complete, the application shows **ATTENTION REQUIRED** and `ManualRemovalRequired.txt` explains whether exact remaining locations need technician work or the scan must simply be repaired and rerun.
10. Use **Open last case folder** after completion to review the USB evidence, Startup inventories, decisions, remediation log, and verification report.

Built-in Windows remote features are not offered for removal merely because they are installed or enabled. The post-scam collector is read-only and reports relevant remote-session events or suspicious persistence when evidence of actual use exists. It remains focused on actionable persistence, hidden access, security changes, suspicious execution, and possible customer harm.

All application sessions save a readable log beside the EXE under `CompuTekData/<COMPUTERNAME>/ApplicationSessions`. Remote-scan cases, post-scam evidence, Toolbox logs and CHKDSK reports are also stored under that computer's `CompuTekData` folder on the service USB. Pre-Clone recovery material remains under `BitLockerKeys/<COMPUTERNAME>`.

## Technician tools

The first/default **Final system check** page contains the store's most-used workflow and supports the `Alt+R` keyboard shortcut. The remaining tabs provide security scans and advanced technician tools:

- **IT Technician Toolbox** — system and network information, DNS/IP repair, internet testing, temporary-file cleanup, SFC, CHKDSK, DISM, Task Manager, print-queue cleanup, verified BitLocker enablement, and reboot. Every finished or failed action returns to the menu except Exit and a successfully started reboot. Print cleanup attempts to restart the Spooler even if queued-file deletion fails. DNS/IP repair warns that Windows DHCP renewal can take several minutes and lets it finish without a forced timeout. CHKDSK begins read-only; `/F` or `/R` is offered only after the scan reports a problem and requires an exact technician phrase. BitLocker also requires exact approval and a complete recovery-password file that passes a service-USB read-back check before encryption starts.
- **Final System Check** — the standard final-store workflow. It disables hibernation, checks activation, security, updates, devices and Splashtop, creates a restore point, un-mutes and sets speaker volume to 50%, plays Windows sounds through the default output, and asks the technician to confirm they were heard. It ends with **SYSTEM READY: YES** or **ATTENTION REQUIRED**.
- **Pre-Clone Preparation** — the Acronis readiness gate. It first proves that the program is running from removable service media and excludes every volume on that USB physical disk. It verifies complete BitLocker recovery-password files before decryption, waits for full decryption, applies temporary anti-re-encryption policy even for already-decrypted targets, and runs non-destructive CHKDSK scans. Final System Check restores the policy values saved before Pre-Clone.

These tools are launched individually; there is no **Run ALL scripts** action. The application explains each workflow before it starts, and the embedded scripts retain their action-specific prompts. BitLocker recovery information is written beneath the USB/application folder rather than the protected staging directory.

Pre-Clone displays **READY FOR ACRONIS CLONE: YES** only after removable-service-media identification succeeds, every internal fixed target drive is fully decrypted, temporary automatic-re-encryption prevention is active, and CHKDSK returns no errors. An internal-drive launch, ambiguous physical-disk mapping, cancelled prompt, missing or unverified recovery password, incomplete decryption, failed status query, or disk error produces **NOT READY**. Each run saves a readable summary, JSON details, CHKDSK logs, and hashes beneath `BitLockerKeys/<COMPUTERNAME>/PreClone_<timestamp>`.

BitLocker recovery passwords are confidential and can unlock customer data. Keep the service USB under technician control, never save a key onto the drive it unlocks, and secure or remove customer key files after the job is complete.

## Updating remote-software signatures

Replace `RemoteAccessSignatures.json` beside the EXE, then select **Reload signatures**. The application validates the schema, catalog version, product entries, and duplicate IDs before it will run. The portable catalog beside the EXE has first priority so a service USB carries its reviewed signature set from computer to computer.

For centrally managed computers that do not carry a catalog beside the EXE, place the catalog at `%ProgramData%\CompuTek\ScannerApp\RemoteAccessSignatures.json`. A malformed selected catalog blocks scanning instead of silently falling back to older signatures.

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
