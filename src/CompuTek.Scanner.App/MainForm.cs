using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CompuTek.Scanner.App
{
    internal sealed class MainForm : Form
    {
        private static readonly Color Navy = Color.FromArgb(20, 57, 82);
        private static readonly Color Blue = Color.FromArgb(29, 112, 184);
        private static readonly Color Green = Color.FromArgb(31, 126, 83);
        private static readonly Color LightBackground = Color.FromArgb(244, 247, 249);

        private readonly NumericUpDown lookbackDays = new NumericUpDown();
        private readonly CheckBox deepScan = new CheckBox();
        private readonly CheckBox includeHashes = new CheckBox();
        private readonly Button remoteButton = new Button();
        private readonly Button postScamButton = new Button();
        private readonly Button technicianToolboxButton = new Button();
        private readonly Button finalSystemCheckButton = new Button();
        private readonly Button preCloneButton = new Button();
        private readonly Button reloadButton = new Button();
        private readonly Button openCaseButton = new Button();
        private readonly Button openReportButton = new Button();
        private readonly PictureBox brandLogo = new PictureBox();
        private readonly RichTextBox output = new RichTextBox();
        private readonly Label catalogLabel = new Label();
        private readonly Label promptLabel = new Label();
        private readonly TextBox responseText = new TextBox();
        private readonly Button sendButton = new Button();
        private readonly Label statusLabel = new Label();
        private readonly ProgressBar progress = new ProgressBar();
        private readonly Timer runningTimer = new Timer();

        private EngineLayout engineLayout;
        private ScannerEngineHost engineHost;
        private bool awaitingInput;
        private string lastCaseFolder;
        private string lastReportPath;
        private string runningDisplayName;
        private string currentStage;
        private DateTime engineStartedUtc;
        private string sessionLogPath;
        private string resultReason;

        public MainForm()
        {
            Text = "CompuTek Scanner";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(1160, 700);
            Size = new Size(1180, 820);
            BackColor = LightBackground;
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            AutoScaleMode = AutoScaleMode.Dpi;
            try { Icon = Branding.CreateWindowIcon(); } catch { }
            BuildInterface();
            runningTimer.Interval = 1000;
            runningTimer.Tick += UpdateRunningStatus;
            FormClosing += HandleFormClosing;
            Load += delegate { ReloadEngine(); };
        }

        private void BuildInterface()
        {
            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.ColumnCount = 1;
            layout.RowCount = 5;
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 92F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 190F));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 82F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 35F));
            Controls.Add(layout);

            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            header.Size = new Size(ClientSize.Width, 92);
            header.BackColor = Navy;

            brandLogo.BackColor = Color.Transparent;
            brandLogo.Location = new Point(18, 14);
            brandLogo.Size = new Size(96, 64);
            brandLogo.SizeMode = PictureBoxSizeMode.Zoom;
            brandLogo.TabStop = false;
            try { brandLogo.Image = Branding.CreateLogoImage(); } catch { }
            header.Controls.Add(brandLogo);

            Label title = new Label();
            title.Text = "CompuTek Scanner";
            title.ForeColor = Color.White;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold, GraphicsUnit.Point);
            title.AutoSize = true;
            title.Location = new Point(128, 12);
            header.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Security scanning, verified remediation, evidence collection, and technician utilities";
            subtitle.ForeColor = Color.FromArgb(215, 230, 240);
            subtitle.AutoSize = true;
            subtitle.Location = new Point(131, 56);
            header.Controls.Add(subtitle);

            catalogLabel.ForeColor = Color.White;
            catalogLabel.TextAlign = ContentAlignment.MiddleRight;
            catalogLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            catalogLabel.Location = new Point(730, 18);
            catalogLabel.Size = new Size(420, 52);
            catalogLabel.Text = "Loading signature catalog...";
            header.Controls.Add(catalogLabel);
            layout.Controls.Add(header, 0, 0);

            TabControl toolTabs = new TabControl();
            toolTabs.Dock = DockStyle.Fill;
            toolTabs.Padding = new Point(18, 5);

            TabPage finalCheckTab = new TabPage("Final system check");
            finalCheckTab.BackColor = LightBackground;
            TabPage securityTab = new TabPage("Security scans");
            securityTab.BackColor = LightBackground;
            TabPage technicianTab = new TabPage("Technician tools");
            technicianTab.BackColor = LightBackground;
            toolTabs.TabPages.Add(finalCheckTab);
            toolTabs.TabPages.Add(securityTab);
            toolTabs.TabPages.Add(technicianTab);
            toolTabs.SelectedTab = finalCheckTab;
            layout.Controls.Add(toolTabs, 0, 1);

            Panel finalCheckPanel = new Panel();
            finalCheckPanel.Dock = DockStyle.Fill;
            finalCheckPanel.BackColor = LightBackground;
            finalCheckPanel.Padding = new Padding(20, 14, 20, 10);

            finalSystemCheckButton.Text = "&Run Final System Check";
            finalSystemCheckButton.AccessibleName = "Run Final System Check";
            finalSystemCheckButton.AccessibleDescription = "Run the standard final-store readiness checklist.";
            finalSystemCheckButton.BackColor = Green;
            finalSystemCheckButton.ForeColor = Color.White;
            finalSystemCheckButton.FlatStyle = FlatStyle.Flat;
            finalSystemCheckButton.FlatAppearance.BorderSize = 0;
            finalSystemCheckButton.Font = new Font("Segoe UI Semibold", 13F, FontStyle.Bold);
            finalSystemCheckButton.Location = new Point(24, 22);
            finalSystemCheckButton.Size = new Size(360, 64);
            finalSystemCheckButton.Click += StartFinalSystemCheck;
            finalCheckPanel.Controls.Add(finalSystemCheckButton);

            Label finalCheckDescription = new Label();
            finalCheckDescription.Text = "Most-used store workflow: disable hibernation, verify activation, Windows security, updates and devices, create a restore point, and confirm working audio.";
            finalCheckDescription.Font = new Font("Segoe UI", 10.5F, FontStyle.Regular);
            finalCheckDescription.Location = new Point(414, 24);
            finalCheckDescription.Size = new Size(710, 62);
            finalCheckPanel.Controls.Add(finalCheckDescription);

            Label finalCheckShortcut = new Label();
            finalCheckShortcut.Text = "Start here when preparing a repaired computer to leave the store. Keyboard: Alt+R.";
            finalCheckShortcut.ForeColor = Color.FromArgb(60, 80, 92);
            finalCheckShortcut.Location = new Point(24, 110);
            finalCheckShortcut.Size = new Size(1050, 34);
            finalCheckPanel.Controls.Add(finalCheckShortcut);
            finalCheckTab.Controls.Add(finalCheckPanel);

            Panel commandPanel = new Panel();
            commandPanel.Dock = DockStyle.Fill;
            commandPanel.Size = new Size(ClientSize.Width, 156);
            commandPanel.Padding = new Padding(14, 10, 14, 8);
            commandPanel.BackColor = LightBackground;

            GroupBox options = new GroupBox();
            options.Text = "Scan options";
            options.Location = new Point(16, 10);
            options.Size = new Size(520, 132);
            options.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            Label daysLabel = new Label();
            daysLabel.Text = "Look back:";
            daysLabel.AutoSize = true;
            daysLabel.Location = new Point(18, 31);
            options.Controls.Add(daysLabel);

            lookbackDays.Minimum = 1;
            lookbackDays.Maximum = 365;
            lookbackDays.Value = 7;
            lookbackDays.Location = new Point(91, 27);
            lookbackDays.Width = 62;
            options.Controls.Add(lookbackDays);

            Label daysSuffix = new Label();
            daysSuffix.Text = "days";
            daysSuffix.AutoSize = true;
            daysSuffix.Location = new Point(159, 31);
            options.Controls.Add(daysSuffix);

            deepScan.Text = "Full fixed-drive scan (much slower)";
            deepScan.AutoSize = true;
            deepScan.Location = new Point(18, 64);
            options.Controls.Add(deepScan);

            includeHashes.Text = "Hash reported files";
            includeHashes.AutoSize = true;
            includeHashes.Location = new Point(270, 64);
            options.Controls.Add(includeHashes);

            Label removalReview = new Label();
            removalReview.Text = "Remote findings are always shown and offered for technician review. Nothing is removed automatically.";
            removalReview.ForeColor = Color.FromArgb(90, 65, 0);
            removalReview.Location = new Point(18, 94);
            removalReview.Size = new Size(480, 30);
            options.Controls.Add(removalReview);
            commandPanel.Controls.Add(options);

            remoteButton.Text = "Run remote-access scanner";
            remoteButton.BackColor = Blue;
            remoteButton.ForeColor = Color.White;
            remoteButton.FlatStyle = FlatStyle.Flat;
            remoteButton.FlatAppearance.BorderSize = 0;
            remoteButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            remoteButton.Size = new Size(250, 46);
            remoteButton.Location = new Point(558, 15);
            remoteButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            remoteButton.Click += StartRemoteScanner;
            commandPanel.Controls.Add(remoteButton);

            postScamButton.Text = "Collect post-scam evidence";
            postScamButton.BackColor = Green;
            postScamButton.ForeColor = Color.White;
            postScamButton.FlatStyle = FlatStyle.Flat;
            postScamButton.FlatAppearance.BorderSize = 0;
            postScamButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            postScamButton.Size = new Size(250, 46);
            postScamButton.Location = new Point(558, 76);
            postScamButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            postScamButton.Click += StartPostScamScanner;
            commandPanel.Controls.Add(postScamButton);

            reloadButton.Text = "Reload signatures";
            reloadButton.Size = new Size(150, 34);
            reloadButton.Location = new Point(828, 15);
            reloadButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            reloadButton.Click += delegate { ReloadEngine(); };
            commandPanel.Controls.Add(reloadButton);

            openCaseButton.Text = "Open last case folder";
            openCaseButton.Size = new Size(150, 34);
            openCaseButton.Location = new Point(828, 58);
            openCaseButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            openCaseButton.Enabled = false;
            openCaseButton.Click += OpenLastCaseFolder;
            commandPanel.Controls.Add(openCaseButton);

            openReportButton.Text = "Open last report";
            openReportButton.Size = new Size(160, 34);
            openReportButton.Location = new Point(988, 58);
            openReportButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            openReportButton.Enabled = false;
            openReportButton.Click += OpenLastReport;
            commandPanel.Controls.Add(openReportButton);

            Label safety = new Label();
            safety.Text = "Verified CompuTek access is protected. Reviewable removals require numbered KEEP/REMOVE choices and one final YES.";
            safety.ForeColor = Color.FromArgb(128, 74, 0);
            safety.Location = new Point(828, 96);
            safety.Size = new Size(320, 54);
            safety.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            commandPanel.Controls.Add(safety);
            securityTab.Controls.Add(commandPanel);

            Panel technicianPanel = new Panel();
            technicianPanel.Dock = DockStyle.Fill;
            technicianPanel.BackColor = LightBackground;
            technicianPanel.Padding = new Padding(16, 12, 16, 8);

            technicianToolboxButton.Text = "Open IT Technician Toolbox";
            technicianToolboxButton.BackColor = Blue;
            technicianToolboxButton.ForeColor = Color.White;
            technicianToolboxButton.FlatStyle = FlatStyle.Flat;
            technicianToolboxButton.FlatAppearance.BorderSize = 0;
            technicianToolboxButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            technicianToolboxButton.Location = new Point(18, 16);
            technicianToolboxButton.Size = new Size(330, 46);
            technicianToolboxButton.Click += StartTechnicianToolbox;
            technicianPanel.Controls.Add(technicianToolboxButton);

            Label toolboxDescription = new Label();
            toolboxDescription.Text = "System/network information, DNS/IP repair, internet test, temp cleanup, SFC, CHKDSK, DISM, Task Manager, print queue, BitLocker, and reboot.";
            toolboxDescription.Location = new Point(18, 68);
            toolboxDescription.Size = new Size(330, 55);
            technicianPanel.Controls.Add(toolboxDescription);

            preCloneButton.Text = "Run Pre-Clone Preparation";
            preCloneButton.BackColor = Color.FromArgb(180, 92, 28);
            preCloneButton.ForeColor = Color.White;
            preCloneButton.FlatStyle = FlatStyle.Flat;
            preCloneButton.FlatAppearance.BorderSize = 0;
            preCloneButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            preCloneButton.Location = new Point(370, 16);
            preCloneButton.Size = new Size(330, 46);
            preCloneButton.Click += StartPreClone;
            technicianPanel.Controls.Add(preCloneButton);

            Label preCloneDescription = new Label();
            preCloneDescription.Text = "Acronis gate: verify complete BitLocker recovery keys on the USB, fully decrypt fixed drives, then pass CHKDSK.";
            preCloneDescription.Location = new Point(370, 68);
            preCloneDescription.Size = new Size(330, 55);
            technicianPanel.Controls.Add(preCloneDescription);

            Label technicianWarning = new Label();
            technicianWarning.Text = "Pre-Clone and repair tools can change Windows or disks. The Final System Check intentionally performs the store's required finishing actions.";
            technicianWarning.ForeColor = Color.FromArgb(150, 60, 0);
            technicianWarning.Location = new Point(18, 135);
            technicianWarning.Size = new Size(1034, 36);
            technicianPanel.Controls.Add(technicianWarning);
            technicianTab.Controls.Add(technicianPanel);

            Panel statusPanel = new Panel();
            statusPanel.Dock = DockStyle.Fill;
            statusPanel.Size = new Size(ClientSize.Width, 35);
            statusPanel.BackColor = Color.White;
            statusPanel.Padding = new Padding(12, 7, 12, 5);
            statusLabel.Text = "Ready";
            statusLabel.Dock = DockStyle.Fill;
            statusPanel.Controls.Add(statusLabel);
            progress.Style = ProgressBarStyle.Marquee;
            progress.MarqueeAnimationSpeed = 25;
            progress.Visible = false;
            progress.Dock = DockStyle.Right;
            progress.Width = 210;
            statusPanel.Controls.Add(progress);
            layout.Controls.Add(statusPanel, 0, 4);

            Panel inputPanel = new Panel();
            inputPanel.Dock = DockStyle.Fill;
            inputPanel.Size = new Size(ClientSize.Width, 82);
            inputPanel.BackColor = Color.White;
            inputPanel.Padding = new Padding(14, 8, 14, 10);
            promptLabel.Text = "Technician response (enabled when the scanner asks a question)";
            promptLabel.Location = new Point(14, 8);
            promptLabel.Size = new Size(900, 20);
            inputPanel.Controls.Add(promptLabel);
            responseText.Location = new Point(14, 35);
            responseText.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            responseText.Width = 1018;
            responseText.BorderStyle = BorderStyle.FixedSingle;
            responseText.Enabled = false;
            responseText.KeyDown += HandleResponseKeyDown;
            inputPanel.Controls.Add(responseText);
            sendButton.Text = "Send";
            sendButton.Location = new Point(1043, 33);
            sendButton.Size = new Size(96, 30);
            sendButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            sendButton.Enabled = false;
            sendButton.Click += SendResponse;
            inputPanel.Controls.Add(sendButton);
            layout.Controls.Add(inputPanel, 0, 3);

            GroupBox outputGroup = new GroupBox();
            outputGroup.Text = "Live findings and tool output";
            outputGroup.Dock = DockStyle.Fill;
            outputGroup.Padding = new Padding(9);
            outputGroup.BackColor = LightBackground;
            output.BackColor = Color.FromArgb(18, 24, 28);
            output.ForeColor = Color.Gainsboro;
            output.Font = new Font("Consolas", 9.5F, FontStyle.Regular);
            output.ReadOnly = true;
            output.WordWrap = false;
            output.Dock = DockStyle.Fill;
            output.DetectUrls = false;
            outputGroup.Controls.Add(output);
            layout.Controls.Add(outputGroup, 0, 2);
        }

        private void ReloadEngine()
        {
            if (engineHost != null && engineHost.IsRunning) return;
            try
            {
                engineLayout = EmbeddedEngine.Prepare();
                catalogLabel.Text = String.Format(
                    "Signatures {0}  •  {1} product families\r\n{2}",
                    engineLayout.Catalog.Version,
                    engineLayout.Catalog.ProductCount,
                    engineLayout.Catalog.SourceDescription);
                statusLabel.Text = "Ready — signature catalog validated";
                SetActionControlsEnabled(true);
            }
            catch (Exception exception)
            {
                engineLayout = null;
                catalogLabel.Text = "Signature catalog error";
                statusLabel.Text = "Scanner unavailable: " + exception.Message;
                SetActionControlsEnabled(false);
                MessageBox.Show(
                    "The scanner cannot run until the signature catalog is corrected.\r\n\r\n" + exception.Message,
                    "Signature catalog error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void StartRemoteScanner(object sender, EventArgs args)
        {
            DialogResult result = MessageBox.Show(
                "The scanner will display every finding and save its reports beside this EXE on the service USB. Verified CompuTek access is protected and receives no removal number. It will then ask which numbered review items to KEEP and which to REMOVE.\r\n\r\nNothing is removed automatically. Every numbered review item must be classified, and removals require one final YES.\r\n\r\nContinue?",
                "Start remote-access review",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (result != DialogResult.Yes) return;

            List<string> arguments = CommonArguments();
            if (includeHashes.Checked) arguments.Add("-IncludeHashes");
            StartEngine("Remote-access scanner", engineLayout.RemoteScannerPath, arguments);
        }

        private void StartPostScamScanner(object sender, EventArgs args)
        {
            List<string> arguments = CommonArguments();
            if (includeHashes.Checked) arguments.Add("-IncludeFileHashes");
            StartEngine("Post-scam evidence collection", engineLayout.PostScamScannerPath, arguments);
        }

        private void StartTechnicianToolbox(object sender, EventArgs args)
        {
            if (!ConfirmSensitiveTool(
                "Open IT Technician Toolbox",
                "The toolbox includes repair actions that can clear temporary files or the print queue, renew network settings, run disk repair, enable BitLocker, or reboot Windows. Each applicable action still asks for confirmation.\r\n\r\nOpen the toolbox?")) return;
            StartEngine("IT Technician Toolbox", engineLayout.TechnicianToolboxPath, new List<string>());
        }

        private void StartFinalSystemCheck(object sender, EventArgs args)
        {
            if (!ConfirmSensitiveTool(
                "Run Final System Check",
                "This is CompuTek's standard final-store workflow. It disables hibernation, checks activation, security, updates, devices and Splashtop, creates a restore point, sets speaker volume to 50%, and asks the technician to confirm the audio test was heard.\r\n\r\nRun it when preparing this computer to leave the store?")) return;
            StartEngine("Final System Check", engineLayout.FinalSystemCheckPath, new List<string>());
        }

        private void StartPreClone(object sender, EventArgs args)
        {
            if (!ConfirmSensitiveTool(
                "Run Pre-Clone Preparation",
                "Pre-Clone is an Acronis readiness workflow. Before decryption, it must save the complete 48-digit BitLocker recovery password to this service USB and verify that file by reading it back. It then waits for full decryption and runs non-destructive CHKDSK scans.\r\n\r\nIt reports READY only when every required step passes. Continue only on the intended computer.")) return;
            StartEngine("Pre-Clone Preparation", engineLayout.PreClonePath, new List<string>());
        }

        private bool ConfirmSensitiveTool(string title, string message)
        {
            return MessageBox.Show(
                message,
                title,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        private List<string> CommonArguments()
        {
            List<string> arguments = new List<string>();
            arguments.Add("-LookbackDays");
            arguments.Add(Convert.ToInt32(lookbackDays.Value).ToString());
            if (deepScan.Checked) arguments.Add("-DeepScan");
            return arguments;
        }

        private void StartEngine(string displayName, string scriptPath, List<string> arguments)
        {
            if (engineLayout == null)
            {
                ReloadEngine();
                if (engineLayout == null) return;
            }

            try
            {
                string scriptFileName = Path.GetFileName(scriptPath);
                engineLayout = EmbeddedEngine.Prepare();
                string selectedScript = ResolveStagedScript(scriptFileName);
                sessionLogPath = null;
                sessionLogPath = CreateSessionLog(displayName);
                output.Clear();
                AppendOutput("Starting " + displayName + "...", Color.LightSkyBlue);
                AppendOutput("Engine: " + engineLayout.DirectoryPath, Color.DimGray);
                AppendOutput("Signatures: " + engineLayout.Catalog.Version + " (" + engineLayout.Catalog.SourceDescription + ")", Color.DimGray);
                AppendOutput("USB session log: " + sessionLogPath, Color.DimGray);
                lastCaseFolder = Path.GetDirectoryName(sessionLogPath);
                openCaseButton.Enabled = false;
                lastReportPath = null;
                openReportButton.Enabled = false;
                awaitingInput = false;
                resultReason = null;
                runningDisplayName = displayName;
                currentStage = "Starting scanner engine";
                engineStartedUtc = DateTime.UtcNow;
                SetRunningState(true, displayName + " is running");
                runningTimer.Start();

                engineHost = new ScannerEngineHost();
                engineHost.OutputReceived += HandleEngineOutput;
                engineHost.PromptReceived += HandleEnginePrompt;
                engineHost.Exited += HandleEngineExit;
                engineHost.Start(
                    EmbeddedEngine.GetPowerShellPath(),
                    selectedScript,
                    arguments,
                    engineLayout.DirectoryPath);
            }
            catch (Exception exception)
            {
                if (engineHost != null) engineHost.Dispose();
                engineHost = null;
                runningTimer.Stop();
                SetRunningState(false, "Could not start scanner");
                AppendOutput("ERROR: " + exception.Message, Color.Salmon);
                MessageBox.Show(exception.Message, "Scanner start error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private string ResolveStagedScript(string scriptFileName)
        {
            if (scriptFileName.Equals("RemoteAccessScanAndRemove.ps1", StringComparison.OrdinalIgnoreCase)) return engineLayout.RemoteScannerPath;
            if (scriptFileName.Equals("PostScam_SystemIntegrityScanner.ps1", StringComparison.OrdinalIgnoreCase)) return engineLayout.PostScamScannerPath;
            if (scriptFileName.Equals("IT_Technician_Toolbox.ps1", StringComparison.OrdinalIgnoreCase)) return engineLayout.TechnicianToolboxPath;
            if (scriptFileName.Equals("FinalSystemCheck_CompuTek.ps1", StringComparison.OrdinalIgnoreCase)) return engineLayout.FinalSystemCheckPath;
            if (scriptFileName.Equals("PreClone.ps1", StringComparison.OrdinalIgnoreCase)) return engineLayout.PreClonePath;
            throw new InvalidOperationException("Unknown embedded tool: " + scriptFileName);
        }

        private void HandleEngineOutput(object sender, EngineOutputEventArgs args)
        {
            if (IsDisposed) return;
            BeginInvoke((MethodInvoker)delegate
            {
                const string resultReasonPrefix = "__COMPUTEK_RESULT_REASON__:";
                const string openReportPrefix = "__COMPUTEK_OPEN_REPORT__:";
                if (args.Text.StartsWith(resultReasonPrefix, StringComparison.Ordinal))
                {
                    resultReason = args.Text.Substring(resultReasonPrefix.Length).Trim();
                    AppendOutput("ATTENTION REASON: " + resultReason, Color.Khaki);
                    return;
                }
                if (args.Text.StartsWith(openReportPrefix, StringComparison.Ordinal))
                {
                    CaptureAndOpenReport(args.Text.Substring(openReportPrefix.Length));
                    return;
                }
                if (args.Text.StartsWith("SCAN STAGE:", StringComparison.OrdinalIgnoreCase))
                    currentStage = args.Text.Substring("SCAN STAGE:".Length).Trim();
                CaptureCaseFolder(args.Text);
                AppendOutput(args.IsError ? "ERROR: " + args.Text : args.Text, args.IsError ? Color.Salmon : Color.Gainsboro);
            });
        }

        private void HandleEnginePrompt(object sender, EnginePromptEventArgs args)
        {
            if (IsDisposed) return;
            BeginInvoke((MethodInvoker)delegate
            {
                awaitingInput = true;
                promptLabel.Text = args.Prompt;
                responseText.Enabled = true;
                sendButton.Enabled = true;
                responseText.Clear();
                responseText.Focus();
                AppendOutput("QUESTION: " + args.Prompt, Color.Khaki);
            });
        }

        private void HandleEngineExit(object sender, EngineExitedEventArgs args)
        {
            if (IsDisposed) return;
            BeginInvoke((MethodInvoker)delegate
            {
                awaitingInput = false;
                responseText.Enabled = false;
                sendButton.Enabled = false;
                promptLabel.Text = "Technician response (enabled when the scanner asks a question)";
                if (engineHost != null) engineHost.Dispose();
                engineHost = null;
                runningTimer.Stop();
                string status;
                if (args.ExitCode == 0)
                    status = runningDisplayName + " completed";
                else if (args.ExitCode == 3 && String.Equals(runningDisplayName, "Remote-access scanner", StringComparison.OrdinalIgnoreCase))
                    status = runningDisplayName + " completed — ATTENTION REQUIRED";
                else if (args.ExitCode == 4 && String.Equals(runningDisplayName, "Pre-Clone Preparation", StringComparison.Ordinal))
                    status = runningDisplayName + " completed — NOT READY for Acronis";
                else if (args.ExitCode == 5 && String.Equals(runningDisplayName, "Final System Check", StringComparison.Ordinal))
                    status = runningDisplayName + " completed — ATTENTION REQUIRED";
                else
                    status = runningDisplayName + " stopped with exit code " + args.ExitCode;
                SetRunningState(false, status);
                AppendOutput(status + ".", args.ExitCode == 0 ? Color.LightGreen : (args.ExitCode == 3 || args.ExitCode == 4 || args.ExitCode == 5 ? Color.Khaki : Color.Salmon));
                openCaseButton.Enabled = !String.IsNullOrWhiteSpace(lastCaseFolder) && Directory.Exists(lastCaseFolder);
                openReportButton.Enabled = !String.IsNullOrWhiteSpace(lastReportPath) && File.Exists(lastReportPath);
                if (args.ExitCode == 3 && String.Equals(runningDisplayName, "Remote-access scanner", StringComparison.OrdinalIgnoreCase))
                {
                    string reason = String.IsNullOrWhiteSpace(resultReason)
                        ? "The scan finished, but it could not verify a clean result. Review the yellow messages and the saved case report."
                        : resultReason;
                    string savedReport = openCaseButton.Enabled
                        ? "\r\n\r\nUse Open Last Case Folder for the full report."
                        : String.Empty;
                    MessageBox.Show(
                        reason + savedReport,
                        "Remote-access scan needs attention",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }
            });
        }

        private void UpdateRunningStatus(object sender, EventArgs args)
        {
            if (engineHost == null || !engineHost.IsRunning)
                return;

            DateTime now = DateTime.UtcNow;
            TimeSpan elapsed = now - engineStartedUtc;
            string elapsedText = elapsed.TotalHours >= 1
                ? elapsed.ToString(@"h\:mm\:ss")
                : elapsed.ToString(@"m\:ss");
            statusLabel.Text = currentStage + " — elapsed " + elapsedText;
        }

        private void SendResponse(object sender, EventArgs args)
        {
            if (!awaitingInput || engineHost == null) return;
            try
            {
                engineHost.SendInput(responseText.Text);
                AppendOutput("[Technician response sent]", Color.DarkGray);
                awaitingInput = false;
                responseText.Clear();
                responseText.Enabled = false;
                sendButton.Enabled = false;
                promptLabel.Text = "Waiting for the scanner...";
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Could not send response", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void HandleResponseKeyDown(object sender, KeyEventArgs args)
        {
            if (args.KeyCode == Keys.Enter)
            {
                args.SuppressKeyPress = true;
                SendResponse(sender, EventArgs.Empty);
            }
        }

        private void CaptureCaseFolder(string line)
        {
            const string marker = "Case folder:";
            int index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return;
            string path = line.Substring(index + marker.Length).Trim().Trim('"');
            if (path.Length > 0) lastCaseFolder = path;
        }

        private void OpenLastCaseFolder(object sender, EventArgs args)
        {
            if (String.IsNullOrWhiteSpace(lastCaseFolder) || !Directory.Exists(lastCaseFolder)) return;
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "explorer.exe";
            startInfo.Arguments = "\"" + lastCaseFolder.Replace("\"", String.Empty) + "\"";
            startInfo.UseShellExecute = true;
            Process.Start(startInfo);
        }

        private void CaptureAndOpenReport(string reportedPath)
        {
            try
            {
                string reportPath = Path.GetFullPath((reportedPath ?? String.Empty).Trim().Trim('"'));
                if (!reportPath.EndsWith(".html", StringComparison.OrdinalIgnoreCase) || !File.Exists(reportPath))
                    throw new InvalidOperationException("The completed HTML report was not found.");

                if (!String.IsNullOrWhiteSpace(lastCaseFolder))
                {
                    string caseFolder = Path.GetFullPath(lastCaseFolder).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    string requiredPrefix = caseFolder + Path.DirectorySeparatorChar;
                    if (!reportPath.StartsWith(requiredPrefix, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("The report path is outside the saved case folder.");
                }

                lastReportPath = reportPath;
                openReportButton.Enabled = true;
                AppendOutput("Opening post-scam report: " + reportPath, Color.LightSkyBlue);
                OpenReport(reportPath);
            }
            catch (Exception exception)
            {
                AppendOutput("The report could not be opened automatically: " + exception.Message, Color.Khaki);
                if (!String.IsNullOrWhiteSpace(lastCaseFolder))
                    AppendOutput("Use Open last case folder to review the saved HTML report.", Color.Khaki);
                MessageBox.Show(
                    "The HTML report was saved, but Windows could not open it automatically.\r\n\r\n" +
                    exception.Message + "\r\n\r\nUse Open last case folder to open PostScamReport.html.",
                    "Post-scam report is ready",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }

        private void OpenLastReport(object sender, EventArgs args)
        {
            if (String.IsNullOrWhiteSpace(lastReportPath) || !File.Exists(lastReportPath)) return;
            try
            {
                OpenReport(lastReportPath);
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    exception.Message + "\r\n\r\nReport: " + lastReportPath,
                    "Could not open post-scam report",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }

        private static void OpenReport(string reportPath)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = reportPath;
            startInfo.UseShellExecute = true;
            Process.Start(startInfo);
        }

        private void SetRunningState(bool running, string status)
        {
            progress.Visible = running;
            statusLabel.Text = status;
            SetActionControlsEnabled(!running && engineLayout != null);
            reloadButton.Enabled = !running;
        }

        private void SetActionControlsEnabled(bool enabled)
        {
            remoteButton.Enabled = enabled;
            postScamButton.Enabled = enabled;
            technicianToolboxButton.Enabled = enabled;
            finalSystemCheckButton.Enabled = enabled;
            preCloneButton.Enabled = enabled;
            lookbackDays.Enabled = enabled;
            deepScan.Enabled = enabled;
            includeHashes.Enabled = enabled;
        }

        private static string CreateSessionLog(string displayName)
        {
            string directory = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "CompuTekData",
                Environment.MachineName,
                "ApplicationSessions");
            Directory.CreateDirectory(directory);
            string safeName = displayName;
            foreach (char invalid in Path.GetInvalidFileNameChars())
                safeName = safeName.Replace(invalid, '_');
            string path = Path.Combine(directory, DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + "_" + safeName.Replace(' ', '_') + ".log");
            File.WriteAllText(
                path,
                "CompuTek Scanner session\r\nComputer: " + Environment.MachineName +
                "\r\nTool: " + displayName +
                "\r\nStarted: " + DateTime.Now.ToString("o") + "\r\n\r\n",
                new UTF8Encoding(true));
            return path;
        }

        private void AppendOutput(string text, Color color)
        {
            string loggingWarning = null;
            if (!String.IsNullOrWhiteSpace(sessionLogPath))
            {
                try
                {
                    File.AppendAllText(sessionLogPath, text + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception exception)
                {
                    loggingWarning = "WARNING: The USB session log could not be updated. Check that the service USB is still connected and writable. " + exception.Message;
                    sessionLogPath = null;
                }
            }
            output.SelectionStart = output.TextLength;
            output.SelectionLength = 0;
            output.SelectionColor = color;
            output.AppendText(text + Environment.NewLine);
            output.SelectionColor = output.ForeColor;
            if (!String.IsNullOrWhiteSpace(loggingWarning))
            {
                output.SelectionStart = output.TextLength;
                output.SelectionColor = Color.Salmon;
                output.AppendText(loggingWarning + Environment.NewLine);
                output.SelectionColor = output.ForeColor;
            }
            output.ScrollToCaret();
        }

        private void HandleFormClosing(object sender, FormClosingEventArgs args)
        {
            if (engineHost != null && engineHost.IsRunning)
            {
                args.Cancel = true;
                MessageBox.Show(
                    "A scanner or technician tool is still running. Wait for it to finish before closing the application so work is not interrupted.",
                    "Tool still running",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }
    }
}
