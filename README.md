# CompuTek Scanner and Technician Toolbox

CompuTek's portable Windows program for remote-access review/removal, post-scam evidence collection, and common technician workflows. It can run directly from a USB drive and requests administrator rights when opened.

## Windows application (preferred)

`CompuTekScanner.exe` provides one technician-facing Windows interface for the remote-access scanner, post-scam collector, IT Technician Toolbox, Final System Check, and Pre-Clone Preparation. It embeds the trusted scripts, displays live output and technician questions in one window, and removes the BAT-to-PowerShell launch requirement.

The CompuTek logo is embedded into the EXE and appears in the application header and Windows program icon; no separate image file is required on the service USB.

Production packages can carry a detached-signed `RemoteAccessSignatures.json` catalog, so reviewed signatures can be updated without rebuilding the EXE. The EXE verifies the adjacent `.sig` file with an embedded public key and fails closed if either file was changed. An embedded catalog remains the trusted fallback. See [docs/ScannerApp.md](docs/ScannerApp.md) for technician use, signed catalog updates, build instructions, and code-signing guidance.

The current internal technician build intentionally leaves the EXE unsigned while using a persistent CompuTek internal RSA key to sign the external catalog. This preserves catalog tamper protection and no-rebuild signature updates without purchasing a public Windows code-signing certificate.

Build and test it on Windows with:

```powershell
.\tests\ScannerApp.Tests.ps1
```

> All tools request administrative rights up front so they can read system state, create logs, and make changes when needed.

## Included tools

### FinalSystemCheck_CompuTek.ps1
End-of-job readiness checklist:
- Appears on the first/default application page with a large keyboard-accessible button because it is the store's most-used workflow.
- Reports Windows edition and validates the base Windows operating-system license specifically (not Office or licensed Windows add-ons). If the normal licensing inventory fails, it automatically uses Windows' read-only `slmgr.vbs /xpr` activation check without requiring a reboot. It also disables hibernation and confirms BitLocker policy flags are not blocking encryption.
- Requires an enabled antivirus with current signatures rather than accepting registration alone. Defender health is read from Defender status; third-party state is decoded from Windows Security Center.
- Accepts the CompuTek Splashtop service only when the exact running installation is linked to the approved Syncro tenant, resides under that approved installation root, and has a valid Splashtop publisher signature. It also checks pending Windows Updates and Device Manager errors.
- Enables System Protection when needed and creates the required end-of-job restore point when Windows policy allows it.
- Asks whether the PC requires speaker output before running audio checks. A PC without speakers can be explicitly skipped without failing readiness. When required, it verifies audio devices, un-mutes/sets volume to 50%, and plays the Compu-Tek test melody through the default endpoint; `NO` replays the melody and only `FAIL` marks audio as needing attention. The melody uses generated tones instead of optional Windows theme sounds, which may be disabled.
- Ends with a clear **SYSTEM READY: YES** or **ATTENTION REQUIRED** result; failed required checks no longer appear as a successful green completion in the application.

### IT_Technician_Toolbox.ps1
Quick access maintenance menu with logs saved beside the EXE under `CompuTekData/<COMPUTERNAME>/TechnicianToolbox` on the service USB:
- System and network information, DNS flush + IP renew, internet connectivity tests.
- Every completed or failed action returns to the toolbox menu. DNS/IP refresh targets only connected hardware adapters with DHCP enabled, excludes virtual loopback adapters such as Npcap, and time-limits each adapter individually.
- Temp file cleanup, live-progress SFC, CHKDSK (drive picker), live-progress DISM restore health, Task Manager launch, and print queue reset. SFC and DISM poll the application's cancellation request while running and clearly mark an interrupted result as incomplete.
- Print queue cleanup always attempts to restart the Print Spooler, including when a queued-file deletion fails.
- CHKDSK always starts with a read-only scan. `/F` or `/R` is offered only after a nonzero scan result and requires an exact technician approval; the toolbox never reboots automatically.
- BitLocker “used space only” enablement workflow that requires typed technician approval, saves and reads back complete 48-digit recovery passwords under `BitLockerKeys/<COMPUTERNAME>` on the service USB before encryption, and uses TPM protection for the Windows drive.

### PreClone.ps1
Pre-imaging helper focused on BitLocker and disk health:
- Uses structured BitLocker information rather than language-dependent console text. If an encrypted volume lacks a 48-digit recovery-password protector, it adds one before decryption.
- Saves the full recovery password and protector ID under `BitLockerKeys/<COMPUTERNAME>` on the service USB, reads the file back, validates every password, and records a SHA-256 hash. Decryption is blocked if this verification fails or if the key would be stored on the drive being decrypted.
- Requires verified removable USB/SD service media, resolves its physical disk number, and identifies the physical disk containing Windows as the sole clone source. It inventories every partition on that Windows disk. Hidden EFI/MSR/Recovery partitions are accounted for without changing their protected attributes; ordinary letterless data volumes receive a temporary private mount point that is always removed after read-only CHKDSK. Other internal disks are listed for the technician but do not block the system-drive clone because they can be moved physically.
- Blocks Acronis readiness for RAID, Intel Optane/RST/VMD, Storage Spaces, iSCSI/virtual storage, a split boot layout, or an incomplete controller check until a senior technician verifies the boot media has the required driver and the destination layout is supported.
- Requires the technician to type `PREPARE FOR CLONE`, starts decryption, and reports progress until every target volume is fully decrypted. It applies temporary auto-encryption prevention without disabling the BitLocker service.
- Applies the temporary prevention policy even when drives were already decrypted, saves the original policy state, and lets Final System Check restore those exact prior values.
- Runs non-destructive CHKDSK scans, preserves each result, and reports **READY FOR ACRONIS CLONE: YES** only when BitLocker inspection, complete decryption, and all disk checks pass.

### PostScam_SystemIntegrityScanner.ps1
Read-only, focused post-scam integrity review with a configurable 7-day default lookback:
- Runs the shared remote-access inventory, including every user profile's AppData, and preserves the results as JSON and CSV.
- Flags actionable persistence, hidden access, security-control changes, suspicious execution, remote sessions, account changes, SSH keys, firewall/proxy/hosts changes, and other customer-harm indicators.
- Consolidates repeated evidence into `ActionableFindings.txt` and a clean, offline `PostScamReport.html`. The HTML report groups items by technician priority, separates warning groups from supplemental inventory, actual collection failures, and non-blocking coverage notes, and is opened by the Windows application when the scan finishes. An **Open last report** button remains available if the browser was closed or Windows blocked the first attempt. The application shows at most eight groups so its live output remains readable.
- Explains each warning in three layers: a plain-language reason with the exact facts that triggered it, a recommended technician check, and expandable technical evidence. Defender incidents show threat ID/classification, the concise affected resource, recorded remediation action, result, and error status. A `CmdLine:` detection is explicitly distinguished from proof that the named EXE file was infected.
- Treats ordinary recent service/task installs, normal Windows `rundll32` tasks, PowerShell engine lifecycle events, standard remote-support firewall rules, default Windows WMI subscriptions, and older browser extensions with broad permissions as supplemental review data. A remote-product name by itself is not called a scam backdoor; hidden/user-profile persistence or suspicious behavior is required.
- Keeps the scanner's own protected PowerShell module activity, local-only RDP session events, and ordinary remote-support Prefetch execution in supplemental evidence instead of the warning list. An external RDP source, unknown remote account, hidden persistence, or credential/transfer utility still remains reviewable.
- Recognizes legitimate per-user Teams, OneDrive, Codex, PowerToys, and Firefox components only in their exact expected folders and with the expected valid publisher signature. The exact official ChatGPT Chromium extension ID is also retained as supplemental inventory. Unsigned copies, renamed lookalikes, unexpected locations, and suspicious command lines remain actionable.
- Uses complete command boundaries so an actual `tar.exe` staging command remains reviewable while ordinary words such as `started`, `restart`, and `startup` no longer create hundreds of false warnings.
- Expensive data-access/staging leads are available only through the direct-script `-ExtendedForensics` option, keeping the normal store workflow focused and faster.
- Uses Security event 4663 when file-object auditing was enabled to identify possible file access. It clearly distinguishes evidence of access or staging from proof of exfiltration.
- Records required log, unexpected folder, or collector read failures as collection gaps. Explicit Windows-owned protected namespaces that Windows intentionally denies are named as coverage limitations rather than making every healthy PC fail; an unreadable user-data, remote-agent, or unknown ProgramData location still fails closed. Missing matching events and unavailable optional Quick Assist or Sysmon telemetry remain clearly described limitations, but an incomplete required remote-access inventory produces the dedicated post-scam **ATTENTION REQUIRED / INCOMPLETE** result instead of a clean result.
- Writes a timestamped case folder beside the EXE under `CompuTekData/<COMPUTERNAME>/PostScam/Cases` on the service USB and does not change system state.
- Uses Windows PowerShell 5.1-safe evidence-array exports so large collections reliably reach the actionable summary files.

### RemoteAccessScanAndRemove.ps1
Evidence-first detection and interactive remediation of remote-access software:
- Uses `RemoteAccessSignatures.json`, currently covering 80 remote-support, RMM, VNC, and built-in Windows remote-access families, including GoToAssist/GoTo Opener, TeamViewer Remote, the exact Team Remote Desktop Microsoft Store package, Ninja Remote/NinjaOne, N-able Take Control, and the separate N-central/N-sight agent families. The catalog can be updated without changing either scanner.
- Inspects machine and loaded-user uninstall entries, all-user AppX packages, current-user AppX packages, current-user Start-app registrations, services, running processes, active connections, Run keys, scheduled tasks, the all-users Startup folder, every user profile's Startup/AppData/Desktop/Downloads folders, ProgramData, and Windows Temp. The three Store views are combined rather than used only as fallbacks, covering Store-delivered Win32 apps and per-user package registrations that may be absent from a successful all-user query. Any failed view is reported as a collection gap.
- Preserves malformed registry values and Startup URLs as reviewable evidence without passing them to unsafe filename parsing, so one unusual autorun entry cannot terminate the entire analysis with exit code 2.
- Resolves Startup-folder shortcuts, URLs, and scripts and flags an item that can download or reinstall software at sign-in, even when the visible target is a normal Windows program such as PowerShell. A complete before/after Startup inventory is saved as separate JSON and CSV evidence on the service USB; ordinary entries that do not match remote software or suspicious persistence stay out of the review list.
- Checks original PE filename, product metadata, company metadata, Authenticode status, service-name patterns, package names, and paths. This detects variable ScreenConnect service names and can identify renamed tools such as an AppData copy named `AdobeReader.exe` whose original filename is `ScreenConnect.ClientService.exe`.
- In explicit Deep Scan mode, reads executable metadata regardless of file age so an old, dormant renamed remote tool is not missed only because it falls outside the lookback period.
- Separately flags unknown services or persistence in user-writable paths and network-connected processes running from those locations.
- Makes no changes while scanning. It displays every finding and exports JSON/CSV evidence beside the EXE under `CompuTekData/<COMPUTERNAME>/RemoteScanner/Cases` on the service USB. If a required collector, scan root, user-data location, remote-agent folder, or unknown ProgramData location is unreadable, it fails closed before showing removal choices. Explicit Windows-owned protected namespaces are identified separately as limitations so standard Windows ACLs do not permanently lock remediation.
- A technician must classify every numbered review item with a typed `KEEP <review-id>` or `REMOVE <review-id>` decision. Different detected versions remain independent, so an unwanted copy can be removed without affecting a protected company installation.
- Groups each known remote-software product by its registered program or Microsoft Store package version. Services and processes belonging to that installation support one finding instead of appearing as extra agents merely because a component has another build number. Start registrations, shortcuts, and shared non-executable components do not create extra installed versions when core installation evidence exists. Downloaded setup packages appear in a separate **Downloaded Installer Files (Not Installed Agents)** section and are never removal choices; separately installed versions and running portable copies remain independently reviewable. Protected Splashtop also names its actual installed roles, such as Streamer and Splashtop for RMM. Syncro is shown in a separate green **Protected CompuTek Access** section only when that specific active installation is beneath an approved Syncro root and its shop identity matches the approved SHA-256 identity in the signed catalog. A specific active Splashtop installation joins it only when its process/service path is beneath an approved Splashtop root, Syncro marks Splashtop enabled, and Syncro's deployment code exactly matches Splashtop's registered RMM code. Approval is never applied globally to another copy with the same product name. Protected items receive no removal number and cannot be selected by `REMOVE` or `REMOVE ALL`. Identity codes are compared only in memory and never displayed or saved. Microsoft Store Splashtop packages and standalone or nonmatching installs remain independently reviewable and explicitly say that CompuTek ownership was not verified.
- Built-in Windows Remote Desktop, Remote Assistance, Quick Assist, WinRM, and OpenSSH configuration are not removal findings by themselves. The Post-Scam scan reports relevant session/event evidence when actual use or suspicious persistence is observed.
- Does not treat an ordinary recent unsigned file in Temp/AppData as remote access by itself. Unknown services, persistence, and network-connected processes in user-writable locations remain flagged.
- When a remote-access scan finishes with technician attention required, the app shows the specific remaining product/location or verification problem on screen and points to the saved case report.
- Always offers technician-reviewed removal when reviewable findings exist. Verified CompuTek access is displayed first but is automatically protected and excluded from all numbered choices. Numbered review items can be classified in batches such as `KEEP 1,3-5`, `KEEP NONE`, `REMOVE 2,6-8`, or `REMOVE ALL`; every review number must be classified. If ownership is uncertain, the safe path displayed on screen is `KEEP ALL`, then `REMOVE NONE`, followed by senior-technician review. The separate installer-file section accepts `OPEN FILES`; `OPEN 1` (or a range) at a decision prompt remains available for a reviewable portable remote-tool file. Installed Program Files folders are not opened by these commands. One final `YES` approves the displayed decisions and is the only confirmation that can begin the selected removals.
- For each approved removal, preserves product logs, configuration, hashes, and registry evidence first; quarantines its exact Startup-folder relaunch item; then runs the registered vendor uninstaller. A vendor uninstaller that waits on a browser, network page, or hidden prompt is stopped after 90 seconds so offline cleanup and verification can continue. Argument-free registered uninstallers are supported. If an uninstall fails, the scanner disables/stops only the matching version's services, stops exact related executable paths (never signed Windows host helpers), and retries once before residual cleanup. After the uninstaller finishes, executable installers and archives in Windows or user Temp folders are permanently deleted only when their catalog/file metadata ties them to the approved product; their path and SHA-256 evidence are saved first. If another version was kept, cleanup remains limited to the selected version or an exact original finding. Store packages first use Windows' supported AppX remover; if that fails or the app is visible only through Start registration, the exact cataloged Microsoft Store ID can be used with WinGet after technician approval. Product-wide Store fallback is blocked whenever another version of that product was approved to keep. Broad Windows/shared folders, whole user-profile folders, Downloads/Documents/Desktop folders, entire Temp roots, and redirected/reparse-point paths are never removed automatically. Locked files that remain after verification are listed in `ManualRemovalRequired.txt` for technician or Safe Mode follow-up.
- Waits briefly for a vendor's self-cleaning temporary uninstaller to exit, then rescans each removed installation scope, including Startup folders. It reports `RemovalVerified` only when that scope and its matching Startup relaunch items are gone and the verification scan completed without collector errors. Store verification follows the selected product across AppX and Start-registration views so a change in Windows inventory source cannot produce a false success; a clearly different version remains separate. Unexpected inaccessible locations or failed collectors make verification incomplete and prevent a false removal-success result; explicitly recognized Windows-protected namespaces remain named limitations.
- A failed or incomplete verification produces a yellow **ATTENTION REQUIRED** application result and follow-up report. It never says manual removal is unnecessary when the verification itself could not complete.

### Shared scanner files

- `CompuTek.Scanner.Common.psm1` contains the evidence collectors, product matcher, report exporter, and safe uninstall-command parser used by both scanners.
- `RemoteAccessSignatures.json` is the data-only product catalog. A production EXE accepts an external copy only with its matching detached `RemoteAccessSignatures.json.sig`; otherwise it uses its embedded catalog or blocks an invalid selected update.
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
- The EXE contains the trusted workflow scripts and fallback catalog. Keep a reviewed `RemoteAccessSignatures.json` and its matching `.sig` beside it to update signatures without rebuilding; the signed USB copy takes priority over a signed machine-level catalog.
- **Cancel safely** requests cancellation and canceled workflows return exit status 6. Toolbox SFC and DISM are interrupted promptly and must be rerun; removal, CHKDSK repair, and BitLocker operations are allowed to reach protected stopping points. No additional removal candidate is started after a cancellation request.
- Every application session writes a readable log under `CompuTekData/<COMPUTERNAME>/ApplicationSessions` beside the EXE. Remote, post-scam, Toolbox, and Pre-Clone workflows also save their detailed reports in USB folders.
- Scan reports and quarantine folders retain the USB drive's normal inherited permissions, so technicians can archive or delete old cases without an administrator-only folder lock.
- BitLocker recovery-password files are confidential. Secure or remove them from the service USB after the clone job.
- Remote-access software is dual-use. Confirm whether a detected product is an approved company support tool before remediation.
- A post-scam scan cannot prove that no data was stolen or that no custom/fileless backdoor exists. Preserve the case folder and use router, firewall, identity-provider, banking, email, EDR, and other available logs when the incident warrants it.
