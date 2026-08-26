# CompuTek Scanner and Technician Toolbox

CompuTek's portable Windows program for remote-access review/removal, post-scam evidence collection, and common technician workflows. It can run directly from a USB drive and requests administrator rights when opened.

## Windows application (preferred)

`CompuTekScanner.exe` provides one technician-facing Windows interface for the remote-access scanner, post-scam collector, IT Technician Toolbox, Final System Check, and Pre-Clone Preparation. It embeds the trusted scripts, displays live output and technician questions in one window, and removes the BAT-to-PowerShell launch requirement.

The CompuTek logo is embedded into the EXE and appears in the application header and Windows program icon; no separate image file is required on the service USB.

The remote-software catalog remains an external `RemoteAccessSignatures.json` file, so signatures can be updated without rebuilding the EXE. See [docs/ScannerApp.md](docs/ScannerApp.md) for technician use, signature updates, build instructions, and code-signing guidance.

Build and test it on Windows with:

```powershell
.\tests\ScannerApp.Tests.ps1
```

> All tools request administrative rights up front so they can read system state, create logs, and make changes when needed.

## Included tools

### FinalSystemCheck_CompuTek.ps1
End-of-job readiness checklist:
- Appears on the first/default application page with a large keyboard-accessible button because it is the store's most-used workflow.
- Reports Windows edition and activation status, disables hibernation, and confirms BitLocker policy flags are not blocking encryption.
- Checks antivirus posture (Defender or third-party), Splashtop service health, pending Windows Updates, and Device Manager errors.
- Enables System Protection when needed and creates the required end-of-job restore point when Windows policy allows it.
- Verifies audio devices, un-mutes/sets volume to 50%, plays a short melody, and requires the technician to confirm that it was heard.

### IT_Technician_Toolbox.ps1
Quick access maintenance menu with logs saved beside the EXE under `CompuTekData/<COMPUTERNAME>/TechnicianToolbox` on the service USB:
- System and network information, DNS flush + IP renew, internet connectivity tests.
- Every completed or failed action returns to the toolbox menu. DNS/IP refresh explains that Windows DHCP renewal can take several minutes and is allowed to finish without a forced timeout.
- Temp file cleanup, SFC, CHKDSK (drive picker), DISM restore health, Task Manager launch, and print queue reset.
- CHKDSK always starts with a read-only scan. `/F` or `/R` is offered only after a nonzero scan result and requires an exact technician approval; the toolbox never reboots automatically.
- BitLocker “used space only” enablement workflow that requires typed technician approval, saves and reads back complete 48-digit recovery passwords under `BitLockerKeys/<COMPUTERNAME>` on the service USB before encryption, and uses TPM protection for the Windows drive.

### PreClone.ps1
Pre-imaging helper focused on BitLocker and disk health:
- Uses structured BitLocker information rather than language-dependent console text. If an encrypted volume lacks a 48-digit recovery-password protector, it adds one before decryption.
- Saves the full recovery password and protector ID under `BitLockerKeys/<COMPUTERNAME>` on the service USB, reads the file back, validates every password, and records a SHA-256 hash. Decryption is blocked if this verification fails or if the key would be stored on the drive being decrypted.
- Requires the technician to type `PREPARE FOR CLONE`, starts decryption, and reports progress until every target volume is fully decrypted. It applies temporary auto-encryption prevention without disabling the BitLocker service.
- Runs non-destructive CHKDSK scans, preserves each result, and reports **READY FOR ACRONIS CLONE: YES** only when BitLocker inspection, complete decryption, and all disk checks pass.

### PostScam_SystemIntegrityScanner.ps1
Read-only, focused post-scam integrity review with a configurable 7-day default lookback:
- Runs the shared remote-access inventory, including every user profile's AppData, and preserves the results as JSON and CSV.
- Flags actionable persistence, hidden access, security-control changes, suspicious execution, remote sessions, account changes, SSH keys, firewall/proxy/hosts changes, and other customer-harm indicators.
- Consolidates repeated evidence into a short `ActionableFindings.txt` report and shows at most 12 finding groups in the application. Normal inventory and low-confidence leads are saved separately instead of being flagged.
- Expensive data-access/staging leads are available only through the direct-script `-ExtendedForensics` option, keeping the normal store workflow focused and faster.
- Uses Security event 4663 when file-object auditing was enabled to identify possible file access. It clearly distinguishes evidence of access or staging from proof of exfiltration.
- Records every unavailable log or collector as a collection gap; an incomplete collection is never reported as clean.
- Writes a timestamped case folder beside the EXE under `CompuTekData/<COMPUTERNAME>/PostScam/Cases` on the service USB and does not change system state.
- Uses Windows PowerShell 5.1-safe evidence-array exports so large collections reliably reach the actionable summary files.

### RemoteAccessScanAndRemove.ps1
Evidence-first detection and interactive remediation of remote-access software:
- Uses `RemoteAccessSignatures.json`, currently covering 60+ remote-support, RMM, VNC, and built-in Windows remote-access families. The catalog can be updated without changing either scanner.
- Inspects machine and loaded-user uninstall entries, all-user AppX packages, services, running processes, active connections, Run keys, scheduled tasks, all-user startup folders, every profile's AppData/Desktop/Downloads, ProgramData, and Windows Temp.
- Checks original PE filename, product metadata, company metadata, Authenticode status, service-name patterns, package names, and paths. This detects variable ScreenConnect service names and can identify renamed tools such as an AppData copy named `AdobeReader.exe` whose original filename is `ScreenConnect.ClientService.exe`.
- Separately flags unknown services or persistence in user-writable paths and network-connected processes running from those locations.
- Makes no changes while scanning. It displays every finding and exports JSON/CSV evidence beside the EXE under `CompuTekData/<COMPUTERNAME>/RemoteScanner/Cases` on the service USB.
- A technician must classify every product/version group with a typed `KEEP <review-id>` or `REMOVE <review-id>` decision. Different detected versions remain independent, so an approved company version can be kept while an unwanted version is removed.
- Groups each known remote-software product by detected installed version. Syncro and Splashtop helper services/files follow their one registered suite version even when component build numbers differ; separate registered versions remain independent. ScreenConnect versions remain independently reviewable, and version-unknown items stay separated by location for safety.
- Built-in Windows Remote Desktop, Remote Assistance, Quick Assist, WinRM, and OpenSSH configuration are not removal findings by themselves. The Post-Scam scan reports relevant session/event evidence when actual use or suspicious persistence is observed.
- Does not treat an ordinary recent unsigned file in Temp/AppData as remote access by itself. Unknown services, persistence, and network-connected processes in user-writable locations remain flagged.
- Always offers technician-reviewed removal when findings exist. Numbered agents can be classified in batches such as `KEEP 1,3-5` and `REMOVE 2,6-8`; every number must be classified and the proposed list confirmed. No remediation begins until the technician also types `APPLY REMOVALS`.
- For each approved removal, preserves product logs, configuration, hashes, and registry evidence first; then runs the registered vendor uninstaller. If it fails, the scanner disables/stops only the matching version's services, stops exact related executable paths, and retries the uninstaller once before residual cleanup. Files that remain after verification are listed in `ManualRemovalRequired.txt` for technician or Safe Mode follow-up; the program does not force-delete them.
- Rescans each removed installation scope. It reports `RemovalVerified` only when that scope is gone and the verification scan completed without collector errors; a kept copy of the same product does not cause a false removal failure.

### Shared scanner files

- `CompuTek.Scanner.Common.psm1` contains the evidence collectors, product matcher, report exporter, and safe uninstall-command parser used by both scanners.
- `RemoteAccessSignatures.json` is the data-only product catalog. Keep both files beside the two scanner scripts.
- `tests/Scanner.Tests.ps1` validates catalog integrity, hidden ScreenConnect detection, renamed-file detection, Quick Assist/RDP coverage, Zoho false-positive prevention, and uninstall parsing.

## Direct scanner options

The toolbox menu uses safe defaults. Technicians can also run either scanner directly:

```powershell
# Slower full fixed-drive scan, including file hashes for reported artifacts
powershell.exe -ExecutionPolicy Bypass -File .\scripts\RemoteAccessScanAndRemove.ps1 -DeepScan -IncludeHashes

# Post-scam evidence with a 60-day lookback
powershell.exe -ExecutionPolicy Bypass -File .\scripts\PostScam_SystemIntegrityScanner.ps1 -LookbackDays 60 -DeepScan -IncludeFileHashes

# Non-destructive synthetic tests
powershell.exe -ExecutionPolicy Bypass -File .\tests\Scanner.Tests.ps1
```

`-DeepScan` may take a long time. The standard scan already recursively covers every profile's AppData, Desktop, Downloads, ProgramData, and Windows Temp.

## Notes
- USB deployments use `CompuTekScanner.exe`; the obsolete BAT and PowerShell launchers have been removed.
- The EXE contains the trusted workflow scripts. Keep `RemoteAccessSignatures.json` beside it so remote-software signatures can be updated without rebuilding.
- Every application session writes a readable log under `CompuTekData/<COMPUTERNAME>/ApplicationSessions` beside the EXE. Remote, post-scam, Toolbox, and Pre-Clone workflows also save their detailed reports in USB folders.
- Scan reports and quarantine folders retain the USB drive's normal inherited permissions, so technicians can archive or delete old cases without an administrator-only folder lock.
- BitLocker recovery-password files are confidential. Secure or remove them from the service USB after the clone job.
- Remote-access software is dual-use. Confirm whether a detected product is an approved company support tool before remediation.
- A post-scam scan cannot prove that no data was stolen or that no custom/fileless backdoor exists. Preserve the case folder and use router, firewall, identity-provider, banking, email, EDR, and other available logs when the incident warrants it.
