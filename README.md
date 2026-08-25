# CompuTek Scanner and Technician Toolbox

CompuTek's portable Windows program for remote-access review/removal, post-scam evidence collection, and common technician workflows. It can run directly from a USB drive and requests administrator rights when opened.

## Windows application (preferred)

`CompuTekScanner.exe` provides one technician-facing Windows interface for the remote-access scanner, post-scam collector, IT Technician Toolbox, Final System Check, and Pre-Clone Preparation. It embeds the trusted scripts, displays live output and technician questions in one window, and removes the BAT-to-PowerShell launch requirement.

The remote-software catalog remains an external `RemoteAccessSignatures.json` file, so signatures can be updated without rebuilding the EXE. See [docs/ScannerApp.md](docs/ScannerApp.md) for technician use, signature updates, build instructions, and code-signing guidance.

Build and test it on Windows with:

```powershell
.\tests\ScannerApp.Tests.ps1
```

## Legacy BAT/PowerShell launcher

The original `Launch_CTSupport_Toolbox.bat` and `CTSupport_Toolbox.ps1` remain available for compatibility. New USB deployments should use `CompuTekScanner.exe`. The Windows program launches each technician workflow individually and does not expose the legacy **Run ALL scripts** action, which could start cleanup, encryption, disk-repair, and reboot workflows together.

> All tools request administrative rights up front so they can read system state, create logs, and make changes when needed.

## Included tools

### FinalSystemCheck_CompuTek.ps1
End-of-job readiness checklist:
- Reports Windows edition and activation status, disables hibernation, and confirms BitLocker policy flags are not blocking encryption.
- Checks antivirus posture (Defender or third-party), Splashtop service health, pending Windows Updates, and Device Manager errors.
- Attempts to enable System Protection and create a restore point when allowed by policy.
- Verifies audio devices, un-mutes/sets volume to 50%, and plays a short melody to confirm speaker output.

### IT_Technician_Toolbox.ps1
Quick access maintenance menu with logging to `%TEMP%\toolbox_log.txt`:
- System and network information, DNS flush + IP renew, internet connectivity tests.
- Temp file cleanup, SFC, CHKDSK (drive picker), DISM restore health, Task Manager launch, and print queue reset.
- BitLocker “used space only” enablement workflow that stores recovery keys under `BitLockerKeys/<COMPUTERNAME>` next to the script.

### PreClone.ps1
Pre-imaging helper focused on BitLocker and disk health:
- Detects encrypted volumes, exports recovery info, decrypts if approved, and monitors progress.
- Optionally blocks automatic re-encryption and disables the BitLocker service when decryption occurred.
- Checks Secure Boot state, runs CHKDSK (smart mode), and summarizes actions, including key save location.

### PostScam_SystemIntegrityScanner.ps1
Read-only post-scam evidence collection with a configurable 30-day default lookback:
- Runs the shared remote-access inventory, including every user profile's AppData, and preserves the results as JSON and CSV.
- Collects service/task/account changes, RDP, Quick Assist and WinRM events, suspicious PowerShell and process activity, Defender changes, WMI subscriptions, registry backdoors, local administrators, SSH keys, active connections, BITS jobs, firewall/proxy/DNS/hosts state, browser extensions, Prefetch, recent archives, possible Temp/AppData staging, and Recent Items links.
- Uses Security event 4663 when file-object auditing was enabled to identify possible file access. It clearly distinguishes evidence of access or staging from proof of exfiltration.
- Records every unavailable log or collector as a collection gap; an incomplete collection is never reported as clean.
- Writes a timestamped case folder under `%ProgramData%\CompuTek\PostScam\Cases` and does not change system state.

### RemoteAccessScanAndRemove.ps1
Evidence-first detection and interactive remediation of remote-access software:
- Uses `RemoteAccessSignatures.json`, currently covering 60+ remote-support, RMM, VNC, and built-in Windows remote-access families. The catalog can be updated without changing either scanner.
- Inspects machine and loaded-user uninstall entries, all-user AppX packages, services, running processes, active connections, Run keys, scheduled tasks, all-user startup folders, every profile's AppData/Desktop/Downloads, ProgramData, and Windows Temp.
- Checks original PE filename, product metadata, company metadata, Authenticode status, service-name patterns, package names, and paths. This detects variable ScreenConnect service names and can identify renamed tools such as an AppData copy named `AdobeReader.exe` whose original filename is `ScreenConnect.ClientService.exe`.
- Separately flags unknown services or persistence in user-writable paths and network-connected processes running from those locations.
- Makes no changes while scanning. Before remediation it exports JSON/CSV evidence to `%ProgramData%\CompuTek\RemoteScanner\Cases`.
- Separates findings by installation location, even when two copies use the same product. A technician must classify every location with a typed `KEEP <review-id>` or `REMOVE <review-id>` decision, so the approved company support agent can remain while a hidden AppData copy is removed.
- Saves the technician identity, ticket/case reference, every keep/remove decision, and a final verification result in the case folder. No remediation begins until all findings are classified and the technician types `APPLY REMOVALS`.
- For each approved removal, preserves product logs, configuration, hashes, and registry evidence first; runs the registered vendor uninstaller; then removes residual processes, services, scheduled tasks, autoruns, AppX/provisioned packages, uninstall registrations, and executable artifacts. Residual files are moved to quarantine instead of being permanently erased.
- Rescans each removed installation scope. It reports `RemovalVerified` only when that scope is gone and the verification scan completed without collector errors; a kept copy of the same product does not cause a false removal failure.

### Shared scanner files

- `CompuTek.Scanner.Common.psm1` contains the evidence collectors, product matcher, report exporter, and safe uninstall-command parser used by both scanners.
- `RemoteAccessSignatures.json` is the data-only product catalog. Keep both files beside the two scanner scripts.
- `tests/Scanner.Tests.ps1` validates catalog integrity, hidden ScreenConnect detection, renamed-file detection, Quick Assist/RDP coverage, Zoho false-positive prevention, and uninstall parsing.

## Direct scanner options

The toolbox menu uses safe defaults. Technicians can also run either scanner directly:

```powershell
# Detection and reports only
powershell.exe -ExecutionPolicy Bypass -File .\scripts\RemoteAccessScanAndRemove.ps1 -ScanOnly

# Slower full fixed-drive scan, including file hashes for reported artifacts
powershell.exe -ExecutionPolicy Bypass -File .\scripts\RemoteAccessScanAndRemove.ps1 -DeepScan -IncludeHashes

# Post-scam evidence with a 60-day lookback
powershell.exe -ExecutionPolicy Bypass -File .\scripts\PostScam_SystemIntegrityScanner.ps1 -LookbackDays 60 -DeepScan -IncludeFileHashes

# Non-destructive synthetic tests
powershell.exe -ExecutionPolicy Bypass -File .\tests\Scanner.Tests.ps1
```

`-DeepScan` may take a long time. The standard scan already recursively covers every profile's AppData, Desktop, Downloads, ProgramData, and Windows Temp.

## Notes
- The launcher sorts scripts alphabetically; rename files to control menu order.
- All scripts run with `-ExecutionPolicy Bypass` to simplify use on locked-down machines.
- Keep the `scripts/` folder alongside the launcher so discovery and key-storage paths remain valid.
- Remote-access software is dual-use. Confirm whether a detected product is an approved company support tool before remediation.
- A post-scam scan cannot prove that no data was stolen or that no custom/fileless backdoor exists. Preserve the case folder and use router, firewall, identity-provider, banking, email, EDR, and other available logs when the incident warrants it.
