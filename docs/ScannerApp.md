# CompuTek Scanner Windows application

`CompuTekScanner.exe` is the technician-facing Windows application for remote-access review/removal, post-scam evidence collection, and CompuTek technician utilities. It requests administrator rights when opened; the obsolete BAT and PowerShell launchers are no longer used.

The CompuTek logo is embedded in the application header and program icon. The USB does not need a separate logo file.

## Files to keep together

- `CompuTekScanner.exe` — the application and embedded, versioned scanner engine.
- `RemoteAccessSignatures.json` — the updateable remote-software catalog in a signed production package.
- `RemoteAccessSignatures.json.sig` — the detached catalog signature verified with the public key embedded in the EXE.
- `SHA256SUMS.txt` — checksums for verifying the published EXE and catalog.

The EXE contains known-good copies of both scanners, the technician tools, the shared scanner module, and a fallback signature catalog. It stages those protected components under `%ProgramData%\CompuTek\ScannerApp\Engine` whenever it runs. The full staging hierarchy is restricted to Administrators and SYSTEM, linked/reparse-point staging paths are rejected, and staged files are recreated with the protected inherited permissions. A reviewed external catalog can be replaced without rebuilding the program, but the EXE accepts it only when its detached RSA/SHA-256 signature verifies with the public key embedded at build time. A missing, altered, or mismatched `.sig` file blocks that external update instead of trusting it.

Reports and quarantine data saved on the service USB use the drive's normal inherited permissions. The application does not apply an administrator-only lock, so old cases can be archived or deleted normally.

## Technician workflow

1. Double-click `CompuTekScanner.exe` and approve the Windows administrator prompt.
2. Confirm the signature version shown in the upper-right corner.
3. The default lookback is 7 days. Change it when a case needs a wider period, and optionally select full fixed-drive scan/file hashes. The normal scan uses a junction-safe, bounded search of high-risk user and shared-data folders.
4. The remote scanner always displays its findings and offers technician-reviewed removal when reviewable findings exist. It never removes anything automatically. Store software is checked through combined all-user packages, current-user packages, and current-user Start registrations so TeamViewer Remote and Team Remote Desktop are not dependent on one Windows inventory. It also inventories the all-users Startup folder and every user profile's Startup folder, resolves shortcuts and scripts, and flags commands that could redownload or reinstall an agent at sign-in. A registered program or Store package anchors its services and processes into one finding even when a component carries a different build number. Start registrations, shortcuts, and shared non-executable components do not create duplicate installed versions when core evidence exists. Downloaded setup packages are shown separately as files rather than numbered installed-agent choices; separately installed versions and running portable copies stay reviewable. Ordinary entries that do not match remote software or suspicious persistence remain in the saved USB inventory without cluttering the review list. Syncro displays in a separate green **Protected CompuTek Access** section only when that exact active installation is under an approved root and its shop identity matches an approved SHA-256 hash in the signed catalog. A specific active Splashtop installation joins that protected item only when its service/process is under the approved root, Syncro marks it enabled, and Syncro's deployment code exactly matches Splashtop's registered RMM code. This approval is not global: another installed Splashtop copy remains a separate numbered choice. Protected items cannot be selected by `REMOVE` or `REMOVE ALL`; identity codes are compared only in memory and are never displayed or saved.
5. Leave the application open while the bottom status bar reports the current collection stage and elapsed time. The program does not add repetitive elapsed-time lines to the findings area.
6. Classify only the numbered review items in batches, for example `KEEP 1,3-5`, `KEEP NONE`, `REMOVE 2,6-8`, or `REMOVE ALL`. Protected CompuTek access cannot be selected. When uncertain, use the on-screen safe choice `KEEP ALL`, then `REMOVE NONE`, and ask a senior technician. Type `OPEN FILES` in the separate downloaded-installer section to show setup packages in File Explorer. `OPEN 1` or `OPEN 2,4-5` remains available for a numbered portable remote-tool finding. `OPEN` does not open installed Program Files folders. Every review number must appear in exactly one KEEP or REMOVE list.
7. Review the proposed decision summary. Type `YES` to approve the displayed decisions, `R` to re-enter the lists, or `Q` to stop without changes. This is the only removal confirmation.
8. After every approved removal batch, wait for the automatic cleanup and verification scan. The scanner first allows a short grace period for a vendor's temporary self-cleaning uninstaller to finish. It then permanently deletes executable installers and archives from Windows/user Temp folders only when catalog and file metadata tie them to the approved product, preserving path and SHA-256 evidence first. It never clears an entire Temp folder. If another product version was kept, cleanup remains tied to the selected version or an exact original finding. A removal is complete only when it reports `RemovalVerified`; locked temporary leftovers are included in the technician-action report. Store verification follows the selected product across AppX and Start-menu inventory views so Windows cannot produce a false success by changing how it reports the same installation.
9. For approved removals, the scanner first quarantines an exact matching Startup-folder relaunch item, then runs the vendor uninstaller. A vendor uninstaller that waits on a web page, network response, or hidden prompt is stopped after 90 seconds so an offline repair cannot freeze indefinitely. Registered uninstallers that take no arguments are supported. If uninstalling fails, the scanner stops/disables the matching services, terminates exact vendor executable paths (not signed Windows host helpers), and retries once. Store packages use Windows package removal first and can fall back to their exact Store ID when needed; this product-wide fallback is disabled if another version was approved to keep. Broad shared/system/profile folders and linked or redirected paths are never moved automatically. A complete before/after Startup inventory is saved as JSON and CSV. An unreadable required root, user-data location, remote-agent folder, unknown ProgramData location, or failed collector makes coverage incomplete and prevents removal choices or a false verification success. Explicit Windows-owned protected namespaces are named as limitations without making normal Windows ACLs permanently block remediation. If verification still finds that version or cannot complete, the application shows a plain-language **ATTENTION REQUIRED** dialog naming the remaining product and location or the collector problem. `ManualRemovalRequired.txt` retains the full detail and explains whether an exact location needs technician work or the scan must simply be repaired and rerun.
10. Use **Open last case folder** after completion to review the USB evidence, Startup inventories, decisions, remediation log, and verification report.

Built-in Windows remote features are not offered for removal merely because they are installed or enabled. The post-scam collector is read-only and reports relevant remote-session events or suspicious persistence when evidence of actual use exists. It remains focused on actionable persistence, hidden access, security changes, suspicious execution, and possible customer harm. When it finishes, it creates an offline `PostScamReport.html` in the USB case folder and asks the Windows application to open it in the default browser. The **Open last report** button can reopen it if the browser was closed or Windows blocked the first attempt; **Open last case folder** remains the fallback. That report groups repeated evidence, shows high-priority items before review items, and keeps normal inventory, standard remote-support firewall rules, local-only RDP events, ordinary remote-tool Prefetch, scanner-generated PowerShell events, and low-confidence leads in separate supporting files. Required collector and folder-read failures are kept separate from expected empty results and optional Quick Assist/Sysmon limitations. No established TCP connections is a successful empty inventory, and access-restricted Microsoft Feeds cache folders are Windows coverage notes rather than failures. Defender event 5007 records with identical old and new values are supporting information rather than actionable warnings. Any real collection gap returns the dedicated **ATTENTION REQUIRED / INCOMPLETE** status (exit 7), so a partial report cannot be mistaken for proof that the computer is clean. Every warning states why it triggered, what the technician should check, and provides expandable technical evidence. Defender explanations include the threat classification/ID, concise affected resource, remediation action, result, and error status; a command-line detection is not presented as proof that the named EXE file was infected.

All application sessions save a readable log beside the EXE under `CompuTekData/<COMPUTERNAME>/ApplicationSessions`. Remote-scan cases, post-scam evidence, Toolbox logs and CHKDSK reports are also stored under that computer's `CompuTekData` folder on the service USB. Pre-Clone recovery material remains under `BitLockerKeys/<COMPUTERNAME>`.

## Technician tools

The first/default **Final system check** page contains the store's most-used workflow and supports the `Alt+R` keyboard shortcut. The remaining tabs provide security scans and advanced technician tools:

The remote-access and post-scam scanners suppress the generic user-profile warning for signed OneDrive, Codex, PowerToys, and Firefox executables in their exact expected application folders. The Microsoft Store Teams startup alias is also recognized only when its Run value contains the exact Microsoft package-family path, executable name, and `msteams:system-initiated` URI. The official ChatGPT Chromium extension is recognized by its exact published extension ID. A lookalike name, unexpected folder, altered command line, wrong signer, or invalid signature is still reported.

Malformed autorun registry values and Startup URLs are retained in the saved inventory but are never passed directly to Windows filename parsing. An unusual persistence entry therefore remains available for technician review without stopping the complete scan.

- **IT Technician Toolbox** — system and network information, DNS/IP repair, internet testing, temporary-file cleanup, SFC, CHKDSK, DISM, Task Manager, print-queue cleanup, verified BitLocker enablement, and reboot. SFC and DISM display their native progress as it arrives and honor the application's cancellation request while running; an interrupted result is explicitly incomplete and must be run again. Every finished or failed action returns to the menu except Exit and a successfully started reboot. Print cleanup attempts to restart the Spooler even if queued-file deletion fails. DNS/IP repair renews only connected hardware adapters with DHCP enabled, skips virtual loopback adapters such as Npcap, and gives each adapter its own timeout so one bad interface cannot hold the toolbox. CHKDSK begins read-only; `/F` or `/R` is offered only after the scan reports a problem and requires an exact technician phrase. BitLocker also requires exact approval and a complete recovery-password file that passes a service-USB read-back check before encryption starts.
- **Final System Check** — the standard final-store workflow. It disables hibernation, validates the base Windows operating-system license rather than accepting another activated Microsoft product or add-on, requires antivirus to be enabled with current signatures, verifies the exact running CompuTek Splashtop installation's tenant link/path/publisher, checks updates and devices, and creates a restore point. Antivirus registration alone and an unrelated approved Splashtop elsewhere on the machine do not pass. If the normal structured licensing query fails, it automatically runs Windows' read-only `slmgr.vbs /xpr` fallback and accepts only a clear activated result; this does not require a reboot. It asks whether the PC requires speaker output; systems without speakers can skip audio without failing readiness. When audio is required, it un-mutes and sets volume to 50%, plays the Compu-Tek generated-tone melody through the default output, replays after `NO`, and requires explicit `FAIL` to mark audio as needing attention. It ends with **SYSTEM READY: YES** or **ATTENTION REQUIRED**.
- **Pre-Clone Preparation** — the Acronis readiness gate. It proves that the program is running from removable service media, identifies the physical disk containing Windows, and accounts for every partition on that source disk. Hidden EFI/MSR/Recovery partitions are included in the clone layout without changing their protected GPT attributes. An ordinary letterless data volume receives a temporary private mount point for read-only CHKDSK, removed in a guaranteed cleanup step. Other internal physical disks are listed but do not block a system-disk clone. RAID, Intel Optane/RST/VMD, Storage Spaces, virtual/iSCSI storage, split boot files, or incomplete storage-controller inspection block readiness for senior review. It verifies complete BitLocker recovery-password files before decryption, waits for full decryption, and applies temporary anti-re-encryption policy even for already-decrypted targets. Final System Check restores the policy values saved before Pre-Clone.

These tools are launched individually; there is no **Run ALL scripts** action. The application explains each workflow before it starts, and the embedded scripts retain their action-specific prompts. BitLocker recovery information is written beneath the USB/application folder rather than the protected staging directory.

Pre-Clone displays **READY FOR ACRONIS CLONE: YES** only after removable-service-media identification succeeds, every partition on the Windows source disk is accounted for, each BitLocker-capable source volume is fully decrypted, temporary automatic-re-encryption prevention is active, CHKDSK returns no errors, all temporary mount points were removed, and no storage-layout warning remains. An internal-drive launch, ambiguous physical-disk mapping, RAID/Optane/RST/VMD/Storage Spaces or split-boot warning, unknown source partition, cancelled prompt, missing or unverified recovery password, incomplete decryption, failed status query, or disk error produces **NOT READY**. Each run saves a readable summary, JSON details, CHKDSK logs, and hashes beneath `BitLockerKeys/<COMPUTERNAME>/PreClone_<timestamp>`.

BitLocker recovery passwords are confidential and can unlock customer data. Keep the service USB under technician control, never save a key onto the drive it unlocks, and secure or remove customer key files after the job is complete.

## Updating remote-software signatures

Do not copy an unsigned JSON update beside a production EXE. Create a reviewed `RemoteAccessSignatures.json`, sign its exact bytes with the catalog-signing RSA private key, and keep the generated `RemoteAccessSignatures.json.sig` beside it. Then select **Reload signatures**. The application verifies the detached RSA/SHA-256 signature with the catalog public key embedded in the EXE before validating the schema, catalog version, product entries, and duplicate IDs. The signed portable catalog beside the EXE has first priority so a service USB carries its reviewed signature set from computer to computer. Changing even one byte invalidates the signature.

The current internal catalog certificate and thumbprint are documented in [CatalogSigningCertificate.md](../build/CatalogSigningCertificate.md). After reviewing a catalog change, sign it without rebuilding the EXE:

```powershell
.\build\Sign-RemoteAccessCatalog.ps1 `
  -CatalogPath '<release folder>\RemoteAccessSignatures.json' `
  -CertificateThumbprint '189585B486CA28390D5128AC4FB81C691D76F3EB' `
  -UpdateChecksumManifest
```

The same external catalog contains approved managed-agent identities. `managedIdentities.syncro.shopSubdomainSha256` stores SHA-256 hashes of lowercase Syncro `shop_subdomain` values, not account passwords, API keys, or tokens. Updating that reviewed hash list changes which Syncro tenant can enter the green **Protected CompuTek Access** section without rebuilding the EXE. An absent or nonmatching identity remains a normal numbered RMM finding that the technician must classify.

For centrally managed computers that do not carry a catalog beside the EXE, place both signed files at `%ProgramData%\CompuTek\ScannerApp\RemoteAccessSignatures.json` and `%ProgramData%\CompuTek\ScannerApp\RemoteAccessSignatures.json.sig`. A missing signature, invalid signature, or malformed selected catalog blocks scanning instead of silently falling back to older signatures.

## Building

From Windows PowerShell 5.1 at the repository root:

```powershell
.\build\Build-ScannerApp.ps1
```

The application is built under `artifacts\CompuTekScanner` with the .NET Framework 4.8 compiler included in supported Windows installations. An ordinary development build is intentionally unsigned and uses only its embedded catalog; it does not publish an unsigned external catalog.

For the current internal-shop release, keep the EXE unsigned but embed the internal catalog verification key and publish the matching signed catalog:

```powershell
.\build\Build-ScannerApp.ps1 `
  -CatalogSigningCertificateThumbprint '189585B486CA28390D5128AC4FB81C691D76F3EB'
```

For a production release, provide an organization code-signing certificate with a private key. The build signs the external catalog, embeds its RSA verification key, signs the EXE, requests a trusted timestamp, and verifies both the signer and timestamp before succeeding. The same RSA certificate can perform both roles, or a separate RSA catalog-signing certificate can be supplied:

```powershell
.\build\Build-ScannerApp.ps1 `
  -ProductionRelease `
  -CodeSigningCertificateThumbprint '<code-signing certificate thumbprint>' `
  -CatalogSigningCertificateThumbprint '<RSA catalog-signing certificate thumbprint>' `
  -TimestampServer 'http://timestamp.digicert.com'
```

Run the unit/application suite and the read-only real-machine integration suite before distribution:

```powershell
.\tests\Scanner.Tests.ps1
.\tests\ScannerApp.Tests.ps1
.\tests\RealMachine.Integration.Tests.ps1 `
  -BuiltExePath .\artifacts\CompuTekScanner\CompuTekScanner.exe `
  -RequireProductionSignature
```

The last test must run elevated on representative Windows 10/11 hardware. It calls the actual fixed-partition inventory and read-only remote-coverage engine, checks Windows Security Center state, can verify CompuTek Splashtop with `-RequireCompuTekSplashtop`, and verifies the production EXE's Authenticode signature/timestamp without changing the PC. The coverage probe can take several minutes; `-SkipRemoteCoverageProbe` is intended only for troubleshooting the test harness, not for release approval. Do not distribute an unsigned production build as trusted CompuTek software.

## Cancellation and result statuses

**Cancel safely** writes a cancellation request and unblocks any technician-input wait. Toolbox SFC and DISM poll for that request, stop their command promptly, and mark the result incomplete so the technician knows it must be rerun. CHKDSK repair, BitLocker, and vendor-uninstall operations are allowed to reach their protected stopping points. No next removal candidate starts after cancellation is observed. Workflow runtime limits issue the same request.

- Exit 0: completed with no required attention.
- Exit 3: remote-access removal or verification needs technician attention, with the reason shown on screen.
- Exit 6: safely canceled at a workflow boundary.
- Exit 7: post-scam collection completed with required coverage gaps; the HTML report remains available but must not be treated as proof the PC is clean.
