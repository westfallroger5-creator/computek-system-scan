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
- Reports Windows edition and validates the base Windows operating-system license specifically (not Office or licensed Windows add-ons), disables hibernation, and confirms BitLocker policy flags are not blocking encryption.
- Checks antivirus posture (Defender or third-party), Splashtop service health, pending Windows Updates, and Device Manager errors.
- Enables System Protection when needed and creates the required end-of-job restore point when Windows policy allows it.
- Asks whether the PC requires speaker output before running audio checks. A PC without speakers can be explicitly skipped without failing readiness. When required, it verifies audio devices, un-mutes/sets volume to 50%, and plays the Compu-Tek test melody through the default endpoint; `NO` replays the melody and only `FAIL` marks audio as needing attention. The melody uses generated tones instead of optional Windows theme sounds, which may be disabled.
- Ends with a clear **SYSTEM READY: YES** or **ATTENTION REQUIRED** result; failed required checks no longer appear as a successful green completion in the application.

### IT_Technician_Toolbox.ps1
Quick access maintenance menu with logs saved beside the EXE under `CompuTekData/<COMPUTERNAME>/TechnicianToolbox` on the service USB:
- System and network information, DNS flush + IP renew, internet connectivity tests.
- Every completed or failed action returns to the toolbox menu. DNS/IP refresh explains that Windows DHCP renewal can take several minutes and is allowed to finish without a forced timeout.
- Temp file cleanup, SFC, CHKDSK (drive picker), DISM restore health, Task Manager launch, and print queue reset.
- Print queue cleanup always attempts to restart the Print Spooler, including when a queued-file deletion fails.
- CHKDSK always starts with a read-only scan. `/F` or `/R` is offered only after a nonzero scan result and requires an exact technician approval; the toolbox never reboots automatically.
- BitLocker “used space only” enablement workflow that requires typed technician approval, saves and reads back complete 48-digit recovery passwords under `BitLockerKeys/<COMPUTERNAME>` on the service USB before encryption, and uses TPM protection for the Windows drive.

### PreClone.ps1
Pre-imaging helper focused on BitLocker and disk health:
- Uses structured BitLocker information rather than language-dependent console text. If an encrypted volume lacks a 48-digit recovery-password protector, it adds one before decryption.
- Saves the full recovery password and protector ID under `BitLockerKeys/<COMPUTERNAME>` on the service USB, reads the file back, validates every password, and records a SHA-256 hash. Decryption is blocked if this verification fails or if the key would be stored on the drive being decrypted.
- Requires verified removable USB/SD service media, resolves its physical disk number, and excludes every partition on that physical disk. Running Pre-Clone from an internal drive is blocked instead of silently excluding that customer drive.
- Requires the technician to type `PREPARE FOR CLONE`, starts decryption, and reports progress until every target volume is fully decrypted. It applies temporary auto-encryption prevention without disabling the BitLocker service.
- Applies the temporary prevention policy even when drives were already decrypted, saves the original policy state, and lets Final System Check restore those exact prior values.
- Runs non-destructive CHKDSK scans, preserves each result, and reports **READY FOR ACRONIS CLONE: YES** only when BitLocker inspection, complete decryption, and all disk checks pass.

### PostScam_SystemIntegrityScanner.ps1
Read-only, focused post-scam integrity review with a configurable 7-day default lookback:
- Runs the shared remote-access inventory, including every user profile's AppData, and preserves the results as JSON and CSV.
- Flags actionable persistence, hidden access, security-control changes, suspicious execution, remote sessions, account changes, SSH keys, firewall/proxy/hosts changes, and other customer-harm indicators.
- Consolidates repeated evidence into a short `ActionableFindings.txt` report and shows at most 12 finding groups in the application. Normal inventory and low-confidence leads are saved separately instead of being flagged.
- Treats ordinary recent service/task installs, benign recent PowerShell profiles, and older browser extensions with broad permissions as supplemental review data. They become actionable only when remote-tool, suspicious-command, user-writable-path, or recent high-risk evidence supports it.
- Recognizes legitimate per-user Teams and OneDrive components only when they are in Microsoft's expected folders and carry a valid Microsoft signature. Unsigned copies, renamed lookalikes, unexpected locations, and suspicious command lines remain actionable.
- Expensive data-access/staging leads are available only through the direct-script `-ExtendedForensics` option, keeping the normal store workflow focused and faster.
- Uses Security event 4663 when file-object auditing was enabled to identify possible file access. It clearly distinguishes evidence of access or staging from proof of exfiltration.
- Records every unavailable log or collector as a collection gap; an incomplete collection is never reported as clean.
- Writes a timestamped case folder beside the EXE under `CompuTekData/<COMPUTERNAME>/PostScam/Cases` on the service USB and does not change system state.
- Uses Windows PowerShell 5.1-safe evidence-array exports so large collections reliably reach the actionable summary files.

### RemoteAccessScanAndRemove.ps1
Evidence-first detection and interactive remediation of remote-access software:
- Uses `RemoteAccessSignatures.json`, currently covering 60+ remote-support, RMM, VNC, and built-in Windows remote-access families, including GoToAssist/GoTo Opener, TeamViewer Remote, the exact Team Remote Desktop Microsoft Store package, N-able Take Control, and the separate N-central/N-sight agent families. The catalog can be updated without changing either scanner.
- Inspects machine and loaded-user uninstall entries, all-user AppX packages, current-user AppX packages, current-user Start-app registrations, services, running processes, active connections, Run keys, scheduled tasks, the all-users Startup folder, every user profile's Startup/AppData/Desktop/Downloads folders, ProgramData, and Windows Temp. The three Store views are combined rather than used only as fallbacks, covering Store-delivered Win32 apps and per-user package registrations that may be absent from a successful all-user query. Any failed view is reported as a collection gap.
- Preserves malformed registry values and Startup URLs as reviewable evidence without passing them to unsafe filename parsing, so one unusual autorun entry cannot terminate the entire analysis with exit code 2.
- Resolves Startup-folder shortcuts, URLs, and scripts and flags an item that can download or reinstall software at sign-in, even when the visible target is a normal Windows program such as PowerShell. A complete before/after Startup inventory is saved as separate JSON and CSV evidence on the service USB; ordinary entries that do not match remote software or suspicious persistence stay out of the review list.
- Checks original PE filename, product metadata, company metadata, Authenticode status, service-name patterns, package names, and paths. This detects variable ScreenConnect service names and can identify renamed tools such as an AppData copy named `AdobeReader.exe` whose original filename is `ScreenConnect.ClientService.exe`.
- In explicit Deep Scan mode, reads executable metadata regardless of file age so an old, dormant renamed remote tool is not missed only because it falls outside the lookback period.
- Separately flags unknown services or persistence in user-writable paths and network-connected processes running from those locations.
- Makes no changes while scanning. It displays every finding and exports JSON/CSV evidence beside the EXE under `CompuTekData/<COMPUTERNAME>/RemoteScanner/Cases` on the service USB.
- A technician must classify every product/version group with a typed `KEEP <review-id>` or `REMOVE <review-id>` decision. Different detected versions remain independent, so an approved company version can be kept while an unwanted version is removed.
- Groups each known remote-software product by detected installed version. When the CompuTek Syncro primary agent is present, Syncro and its bundled Splashtop services/files are displayed once as a green **Managed** suite instead of separate warnings. Standalone Splashtop remains independently reviewable. ScreenConnect versions remain separate, and version-unknown items stay separated by location for safety.
- Built-in Windows Remote Desktop, Remote Assistance, Quick Assist, WinRM, and OpenSSH configuration are not removal findings by themselves. The Post-Scam scan reports relevant session/event evidence when actual use or suspicious persistence is observed.
- Does not treat an ordinary recent unsigned file in Temp/AppData as remote access by itself. Unknown services, persistence, and network-connected processes in user-writable locations remain flagged.
- Always offers technician-reviewed removal when findings exist. Numbered agents can be classified in batches such as `KEEP 1,3-5`, `KEEP NONE`, `REMOVE 2,6-8`, or `REMOVE ALL`; every number must be classified. Type `OPEN 1` (or a range) at either decision prompt to show the detected downloaded installer or portable remote-tool file in File Explorer; installed Program Files folders are not opened by this command. One final `YES` approves the displayed decisions and is the only confirmation that can begin the selected removals.
- For each approved removal, preserves product logs, configuration, hashes, and registry evidence first; quarantines its exact Startup-folder relaunch item; then runs the registered vendor uninstaller. If it fails, the scanner disables/stops only the matching version's services, stops exact related executable paths, and retries the uninstaller once before residual cleanup. Store packages first use Windows' supported AppX remover; if that fails or the app is visible only through Start registration, the exact cataloged Microsoft Store ID can be used with WinGet after technician approval. Product-wide Store fallback is blocked whenever another version of that product was approved to keep. Broad Windows/shared folders, whole user-profile folders, Downloads/Documents/Desktop folders, and redirected/reparse-point paths are never moved automatically. Files that remain after verification are listed in `ManualRemovalRequired.txt` for technician or Safe Mode follow-up; the program does not force-delete them.
- Rescans each removed installation scope, including Startup folders. It reports `RemovalVerified` only when that scope and its matching Startup relaunch items are gone and the verification scan completed without collector errors. Store verification follows the selected product across AppX and Start-registration views so a change in Windows inventory source cannot produce a false success; a clearly different version remains separate.
- A failed or incomplete verification produces a yellow **ATTENTION REQUIRED** application result and follow-up report. It never says manual removal is unnecessary when the verification itself could not complete.

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
- The EXE contains the trusted workflow scripts. Keep `RemoteAccessSignatures.json` beside it so remote-software signatures can be updated without rebuilding; the USB copy takes priority over a machine-level catalog.
- Every application session writes a readable log under `CompuTekData/<COMPUTERNAME>/ApplicationSessions` beside the EXE. Remote, post-scam, Toolbox, and Pre-Clone workflows also save their detailed reports in USB folders.
- Scan reports and quarantine folders retain the USB drive's normal inherited permissions, so technicians can archive or delete old cases without an administrator-only folder lock.
- BitLocker recovery-password files are confidential. Secure or remove them from the service USB after the clone job.
- Remote-access software is dual-use. Confirm whether a detected product is an approved company support tool before remediation.
- A post-scam scan cannot prove that no data was stolen or that no custom/fileless backdoor exists. Preserve the case folder and use router, firewall, identity-provider, banking, email, EDR, and other available logs when the incident warrants it.
