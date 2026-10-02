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
        private readonly Button cancelButton = new Button();
        private readonly Label statusLabel = new Label();
        private readonly ProgressBar progress = new ProgressBar();
        private readonly Panel statusPanel = new Panel();
        private readonly Panel inputPanel = new Panel();
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
        private TimeSpan? engineTimeout;
        private bool timeoutCancellationRequested;

        public MainForm()
        {
            Text = "CompuTek Scanner";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(1000, 580);
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
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            Controls.Add(layout);

            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            header.BackColor = Navy;

            TableLayoutPanel headerLayout = new TableLayoutPanel();
            headerLayout.Dock = DockStyle.Fill;
            headerLayout.ColumnCount = 3;
            headerLayout.RowCount = 1;
            headerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 118F));
            headerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            headerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 410F));
            headerLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            header.Controls.Add(headerLayout);

            brandLogo.BackColor = Color.Transparent;
            brandLogo.Dock = DockStyle.Fill;
            brandLogo.Margin = new Padding(18, 13, 4, 13);
            brandLogo.SizeMode = PictureBoxSizeMode.Zoom;
            brandLogo.TabStop = false;
            try { brandLogo.Image = Branding.CreateLogoImage(); } catch { }
            headerLayout.Controls.Add(brandLogo, 0, 0);

            Panel headingPanel = new Panel();
            headingPanel.Dock = DockStyle.Fill;
            headingPanel.Margin = new Padding(4, 0, 8, 0);
            headerLayout.Controls.Add(headingPanel, 1, 0);

            Label title = new Label();
            title.Text = "CompuTek Scanner";
            title.ForeColor = Color.White;
            title.Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold, GraphicsUnit.Point);
            title.AutoSize = true;
            title.Location = new Point(6, 11);
            headingPanel.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Security scanning, verified remediation, evidence collection, and technician utilities";
            subtitle.ForeColor = Color.FromArgb(215, 230, 240);
            subtitle.AutoEllipsis = true;
            subtitle.Location = new Point(8, 56);
            subtitle.Size = new Size(610, 24);
            subtitle.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            headingPanel.Controls.Add(subtitle);

            catalogLabel.ForeColor = Color.White;
            catalogLabel.TextAlign = ContentAlignment.MiddleRight;
            catalogLabel.Dock = DockStyle.Fill;
            catalogLabel.Margin = new Padding(8, 10, 18, 10);
            catalogLabel.Text = "Loading signature catalog...";
            catalogLabel.AutoEllipsis = true;
            headerLayout.Controls.Add(catalogLabel, 2, 0);
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

            TableLayoutPanel finalCheckPanel = new TableLayoutPanel();
            finalCheckPanel.Dock = DockStyle.Fill;
            finalCheckPanel.BackColor = LightBackground;
            finalCheckPanel.Padding = new Padding(18, 14, 18, 10);
            finalCheckPanel.ColumnCount = 2;
            finalCheckPanel.RowCount = 2;
            finalCheckPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36F));
            finalCheckPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 64F));
            finalCheckPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            finalCheckPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));

            finalSystemCheckButton.Text = "&Run Final System Check";
            finalSystemCheckButton.AccessibleName = "Run Final System Check";
            finalSystemCheckButton.AccessibleDescription = "Run the standard final-store readiness checklist.";
            finalSystemCheckButton.BackColor = Green;
            finalSystemCheckButton.ForeColor = Color.White;
            finalSystemCheckButton.FlatStyle = FlatStyle.Flat;
            finalSystemCheckButton.FlatAppearance.BorderSize = 0;
            finalSystemCheckButton.Font = new Font("Segoe UI Semibold", 13F, FontStyle.Bold);
            finalSystemCheckButton.Dock = DockStyle.Fill;
            finalSystemCheckButton.Margin = new Padding(6, 8, 18, 12);
            finalSystemCheckButton.Click += StartFinalSystemCheck;
            finalCheckPanel.Controls.Add(finalSystemCheckButton, 0, 0);

            Label finalCheckDescription = new Label();
            finalCheckDescription.Text = "Most-used store workflow: disable hibernation, verify activation, Windows security, updates and devices, create a restore point, and confirm working audio.";
            finalCheckDescription.Font = new Font("Segoe UI", 10.5F, FontStyle.Regular);
            finalCheckDescription.Dock = DockStyle.Fill;
            finalCheckDescription.Margin = new Padding(10, 12, 8, 6);
            finalCheckDescription.TextAlign = ContentAlignment.MiddleLeft;
            finalCheckPanel.Controls.Add(finalCheckDescription, 1, 0);

            Label finalCheckShortcut = new Label();
            finalCheckShortcut.Text = "Start here when preparing a repaired computer to leave the store. Keyboard: Alt+R.";
            finalCheckShortcut.ForeColor = Color.FromArgb(60, 80, 92);
            finalCheckShortcut.Dock = DockStyle.Fill;
            finalCheckShortcut.Margin = new Padding(6, 4, 6, 0);
            finalCheckShortcut.TextAlign = ContentAlignment.MiddleLeft;
            finalCheckPanel.Controls.Add(finalCheckShortcut, 0, 1);
            finalCheckPanel.SetColumnSpan(finalCheckShortcut, 2);
            finalCheckTab.Controls.Add(finalCheckPanel);

            TableLayoutPanel commandPanel = new TableLayoutPanel();
            commandPanel.Dock = DockStyle.Fill;
            commandPanel.Padding = new Padding(14, 10, 14, 8);
            commandPanel.BackColor = LightBackground;
            commandPanel.ColumnCount = 3;
            commandPanel.RowCount = 1;
            commandPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46F));
            commandPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 27F));
            commandPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 27F));
            commandPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            GroupBox options = new GroupBox();
            options.Text = "Scan options";
            options.Dock = DockStyle.Fill;
            options.Margin = new Padding(2, 0, 12, 0);

            TableLayoutPanel optionsLayout = new TableLayoutPanel();
            optionsLayout.Dock = DockStyle.Fill;
            optionsLayout.Padding = new Padding(12, 6, 12, 4);
            optionsLayout.ColumnCount = 2;
            optionsLayout.RowCount = 3;
            optionsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52F));
            optionsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48F));
            optionsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            optionsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32F));
            optionsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            options.Controls.Add(optionsLayout);

            FlowLayoutPanel lookbackPanel = new FlowLayoutPanel();
            lookbackPanel.Dock = DockStyle.Fill;
            lookbackPanel.WrapContents = false;
            lookbackPanel.Margin = new Padding(0);

            Label daysLabel = new Label();
            daysLabel.Text = "Look back:";
            daysLabel.AutoSize = true;
            daysLabel.Margin = new Padding(0, 6, 6, 0);
            lookbackPanel.Controls.Add(daysLabel);

            lookbackDays.Minimum = 1;
            lookbackDays.Maximum = 365;
            lookbackDays.Value = 7;
            lookbackDays.Width = 62;
            lookbackDays.Margin = new Padding(0, 2, 6, 0);
            lookbackPanel.Controls.Add(lookbackDays);

            Label daysSuffix = new Label();
            daysSuffix.Text = "days";
            daysSuffix.AutoSize = true;
            daysSuffix.Margin = new Padding(0, 6, 0, 0);
            lookbackPanel.Controls.Add(daysSuffix);
            optionsLayout.Controls.Add(lookbackPanel, 0, 0);
            optionsLayout.SetColumnSpan(lookbackPanel, 2);

            deepScan.Text = "Full fixed-drive scan (much slower)";
            deepScan.AutoSize = true;
            deepScan.Dock = DockStyle.Fill;
            deepScan.Margin = new Padding(0, 3, 6, 0);
            optionsLayout.Controls.Add(deepScan, 0, 1);

            includeHashes.Text = "Hash reported files";
            includeHashes.AutoSize = true;
            includeHashes.Dock = DockStyle.Fill;
            includeHashes.Margin = new Padding(0, 3, 0, 0);
            optionsLayout.Controls.Add(includeHashes, 1, 1);

            Label removalReview = new Label();
            removalReview.Text = "Remote findings are always shown and offered for technician review. Nothing is removed automatically.";
            removalReview.ForeColor = Color.FromArgb(90, 65, 0);
            removalReview.Dock = DockStyle.Fill;
            removalReview.Margin = new Padding(0, 2, 0, 0);
            removalReview.AutoEllipsis = true;
            optionsLayout.Controls.Add(removalReview, 0, 2);
            optionsLayout.SetColumnSpan(removalReview, 2);
            commandPanel.Controls.Add(options, 0, 0);

            TableLayoutPanel scanActions = new TableLayoutPanel();
            scanActions.Dock = DockStyle.Fill;
            scanActions.Margin = new Padding(0, 0, 12, 0);
            scanActions.ColumnCount = 1;
            scanActions.RowCount = 3;
            scanActions.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            scanActions.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            scanActions.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));

            remoteButton.Text = "1. Review remote access";
            remoteButton.AccessibleDescription = "Find remote-support software, protect verified CompuTek access, and ask what to keep or remove.";
            remoteButton.BackColor = Blue;
            remoteButton.ForeColor = Color.White;
            remoteButton.FlatStyle = FlatStyle.Flat;
            remoteButton.FlatAppearance.BorderSize = 0;
            remoteButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            remoteButton.Dock = DockStyle.Fill;
            remoteButton.Margin = new Padding(0, 3, 0, 6);
            remoteButton.Click += StartRemoteScanner;
            scanActions.Controls.Add(remoteButton, 0, 0);

            postScamButton.Text = "2. Check for scammer changes";
            postScamButton.AccessibleDescription = "Collect focused evidence of persistence, security changes, remote sessions, and possible customer harm.";
            postScamButton.BackColor = Green;
            postScamButton.ForeColor = Color.White;
            postScamButton.FlatStyle = FlatStyle.Flat;
            postScamButton.FlatAppearance.BorderSize = 0;
            postScamButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            postScamButton.Dock = DockStyle.Fill;
            postScamButton.Margin = new Padding(0, 6, 0, 3);
            postScamButton.Click += StartPostScamScanner;
            scanActions.Controls.Add(postScamButton, 0, 1);

            Label scanOrderHint = new Label();
            scanOrderHint.Text = "Start with remote access, then run the post-scam check.";
            scanOrderHint.ForeColor = Color.FromArgb(60, 80, 92);
            scanOrderHint.Dock = DockStyle.Fill;
            scanOrderHint.TextAlign = ContentAlignment.MiddleCenter;
            scanActions.Controls.Add(scanOrderHint, 0, 2);
            commandPanel.Controls.Add(scanActions, 1, 0);

            TableLayoutPanel fileActions = new TableLayoutPanel();
            fileActions.Dock = DockStyle.Fill;
            fileActions.Margin = new Padding(0);
            fileActions.ColumnCount = 2;
            fileActions.RowCount = 3;
            fileActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            fileActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            fileActions.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));
            fileActions.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));
            fileActions.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            reloadButton.Text = "Reload signatures";
            reloadButton.Dock = DockStyle.Fill;
            reloadButton.Margin = new Padding(0, 0, 0, 5);
            reloadButton.Click += delegate { ReloadEngine(); };
            fileActions.Controls.Add(reloadButton, 0, 0);
            fileActions.SetColumnSpan(reloadButton, 2);

            openCaseButton.Text = "Open last case folder";
            openCaseButton.Dock = DockStyle.Fill;
            openCaseButton.Margin = new Padding(0, 0, 4, 4);
            openCaseButton.Enabled = false;
            openCaseButton.Click += OpenLastCaseFolder;
            fileActions.Controls.Add(openCaseButton, 0, 1);

            openReportButton.Text = "Open last report";
            openReportButton.Dock = DockStyle.Fill;
            openReportButton.Margin = new Padding(4, 0, 0, 4);
            openReportButton.Enabled = false;
            openReportButton.Click += OpenLastReport;
            fileActions.Controls.Add(openReportButton, 1, 1);

            Label safety = new Label();
            safety.Text = "Verified CompuTek access is protected. Reviewable removals require numbered KEEP/REMOVE choices and one final YES.";
            safety.ForeColor = Color.FromArgb(128, 74, 0);
            safety.Dock = DockStyle.Fill;
            safety.Margin = new Padding(0, 4, 0, 0);
            safety.TextAlign = ContentAlignment.MiddleLeft;
            safety.AutoEllipsis = true;
            fileActions.Controls.Add(safety, 0, 2);
            fileActions.SetColumnSpan(safety, 2);
            commandPanel.Controls.Add(fileActions, 2, 0);
            securityTab.Controls.Add(commandPanel);

            TableLayoutPanel technicianPanel = new TableLayoutPanel();
            technicianPanel.Dock = DockStyle.Fill;
            technicianPanel.BackColor = LightBackground;
            technicianPanel.Padding = new Padding(16, 12, 16, 8);
            technicianPanel.ColumnCount = 2;
            technicianPanel.RowCount = 3;
            technicianPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            technicianPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            technicianPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 58F));
            technicianPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            technicianPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));

            technicianToolboxButton.Text = "Open IT Technician Toolbox";
            technicianToolboxButton.BackColor = Blue;
            technicianToolboxButton.ForeColor = Color.White;
            technicianToolboxButton.FlatStyle = FlatStyle.Flat;
            technicianToolboxButton.FlatAppearance.BorderSize = 0;
            technicianToolboxButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            technicianToolboxButton.Dock = DockStyle.Fill;
            technicianToolboxButton.Margin = new Padding(2, 2, 10, 8);
            technicianToolboxButton.Click += StartTechnicianToolbox;
            technicianPanel.Controls.Add(technicianToolboxButton, 0, 0);

            Label toolboxDescription = new Label();
            toolboxDescription.Text = "System/network information, DNS/IP repair, internet test, temp cleanup, SFC, CHKDSK, DISM, Task Manager, print queue, BitLocker, and reboot.";
            toolboxDescription.Dock = DockStyle.Fill;
            toolboxDescription.Margin = new Padding(6, 2, 16, 2);
            technicianPanel.Controls.Add(toolboxDescription, 0, 1);

            preCloneButton.Text = "Run Pre-Clone Preparation";
            preCloneButton.BackColor = Color.FromArgb(180, 92, 28);
            preCloneButton.ForeColor = Color.White;
            preCloneButton.FlatStyle = FlatStyle.Flat;
            preCloneButton.FlatAppearance.BorderSize = 0;
            preCloneButton.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold);
            preCloneButton.Dock = DockStyle.Fill;
            preCloneButton.Margin = new Padding(10, 2, 2, 8);
            preCloneButton.Click += StartPreClone;
            technicianPanel.Controls.Add(preCloneButton, 1, 0);

            Label preCloneDescription = new Label();
            preCloneDescription.Text = "Acronis gate: verify complete BitLocker recovery keys on the USB, fully decrypt fixed drives, then pass CHKDSK.";
            preCloneDescription.Dock = DockStyle.Fill;
            preCloneDescription.Margin = new Padding(16, 2, 6, 2);
            technicianPanel.Controls.Add(preCloneDescription, 1, 1);

            Label technicianWarning = new Label();
            technicianWarning.Text = "Pre-Clone and repair tools can change Windows or disks. The Final System Check intentionally performs the store's required finishing actions.";
            technicianWarning.ForeColor = Color.FromArgb(150, 60, 0);
            technicianWarning.Dock = DockStyle.Fill;
            technicianWarning.Margin = new Padding(6, 0, 6, 0);
            technicianWarning.TextAlign = ContentAlignment.MiddleLeft;
            technicianPanel.Controls.Add(technicianWarning, 0, 2);
            technicianPanel.SetColumnSpan(technicianWarning, 2);
            technicianTab.Controls.Add(technicianPanel);

            statusPanel.Dock = DockStyle.Fill;
            statusPanel.BackColor = Color.FromArgb(232, 245, 236);
            statusPanel.Padding = new Padding(12, 7, 12, 5);
            statusLabel.Text = "Ready";
            statusLabel.Dock = DockStyle.Fill;
            statusLabel.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            statusLabel.ForeColor = Color.FromArgb(26, 92, 60);
            statusPanel.Controls.Add(statusLabel);
            progress.Style = ProgressBarStyle.Marquee;
            progress.MarqueeAnimationSpeed = 25;
            progress.Visible = false;
            progress.Dock = DockStyle.Right;
            progress.Width = 210;
            statusPanel.Controls.Add(progress);
            layout.Controls.Add(statusPanel, 0, 4);

            inputPanel.Dock = DockStyle.Fill;
            inputPanel.BackColor = Color.White;
            inputPanel.Padding = new Padding(14, 6, 14, 8);

            TableLayoutPanel inputLayout = new TableLayoutPanel();
            inputLayout.Dock = DockStyle.Fill;
            inputLayout.ColumnCount = 3;
            inputLayout.RowCount = 2;
            inputLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            inputLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 104F));
            inputLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 146F));
            inputLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            inputLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            inputPanel.Controls.Add(inputLayout);
            promptLabel.Text = "Technician response (enabled when the scanner asks a question)";
            promptLabel.Dock = DockStyle.Fill;
            promptLabel.AutoEllipsis = true;
            promptLabel.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            inputLayout.Controls.Add(promptLabel, 0, 0);
            inputLayout.SetColumnSpan(promptLabel, 3);
            responseText.Dock = DockStyle.Fill;
            responseText.Margin = new Padding(0, 2, 8, 1);
            responseText.BorderStyle = BorderStyle.FixedSingle;
            responseText.Enabled = false;
            responseText.KeyDown += HandleResponseKeyDown;
            inputLayout.Controls.Add(responseText, 0, 1);
            sendButton.Text = "Send";
            sendButton.Dock = DockStyle.Fill;
            sendButton.Margin = new Padding(0, 1, 8, 0);
            sendButton.Enabled = false;
            sendButton.Click += SendResponse;
            inputLayout.Controls.Add(sendButton, 1, 1);
            cancelButton.Text = "Cancel safely";
            cancelButton.AccessibleName = "Cancel the running tool safely";
            cancelButton.Dock = DockStyle.Fill;
            cancelButton.Margin = new Padding(0, 1, 0, 0);
            cancelButton.FlatStyle = FlatStyle.Flat;
            cancelButton.FlatAppearance.BorderColor = Color.FromArgb(180, 92, 28);
            cancelButton.Enabled = false;
            cancelButton.Click += CancelRunningTool;
            inputLayout.Controls.Add(cancelButton, 2, 1);
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
            output.WordWrap = true;
            output.Dock = DockStyle.Fill;
            output.DetectUrls = false;
            output.ScrollBars = RichTextBoxScrollBars.Vertical;
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
                    "Signatures {0}  •  {1} product families\r\n{2}; {3}",
                    engineLayout.Catalog.Version,
                    engineLayout.Catalog.ProductCount,
                    engineLayout.Catalog.SourceDescription,
                    engineLayout.Catalog.SignatureDescription);
                statusLabel.Text = "Ready — signature catalog validated";
                SetStatusAppearance(Color.FromArgb(232, 245, 236), Color.FromArgb(26, 92, 60));
                SetActionControlsEnabled(true);
            }
            catch (Exception exception)
            {
                engineLayout = null;
                catalogLabel.Text = "Signature catalog error";
                statusLabel.Text = "Scanner unavailable: " + exception.Message;
                SetStatusAppearance(Color.FromArgb(253, 232, 232), Color.FromArgb(145, 35, 35));
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
                timeoutCancellationRequested = false;
                runningDisplayName = displayName;
                currentStage = "Starting scanner engine";
                engineStartedUtc = DateTime.UtcNow;
                engineTimeout = GetEngineTimeout(displayName);
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
                currentStage = "Waiting for technician response";
                promptLabel.Text = args.Prompt;
                promptLabel.ForeColor = Color.FromArgb(117, 77, 0);
                inputPanel.BackColor = Color.FromArgb(255, 248, 225);
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
                promptLabel.ForeColor = SystemColors.ControlText;
                inputPanel.BackColor = Color.White;
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
                else if (args.ExitCode == 7 && String.Equals(runningDisplayName, "Post-scam evidence collection", StringComparison.Ordinal))
                    status = runningDisplayName + " completed — ATTENTION REQUIRED / INCOMPLETE";
                else if (args.ExitCode == 6)
                    status = runningDisplayName + " canceled safely";
                else
                    status = runningDisplayName + " stopped with exit code " + args.ExitCode;
                SetRunningState(false, status);
                SetCompletionAppearance(args.ExitCode);
                AppendOutput(status + ".", args.ExitCode == 0 ? Color.LightGreen : (args.ExitCode == 3 || args.ExitCode == 4 || args.ExitCode == 5 || args.ExitCode == 7 ? Color.Khaki : Color.Salmon));
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
                if (args.ExitCode == 7 && String.Equals(runningDisplayName, "Post-scam evidence collection", StringComparison.Ordinal))
                {
                    string reason = String.IsNullOrWhiteSpace(resultReason)
                        ? "Post-scam collection was incomplete. Review Collection failures in the saved HTML report and do not treat the computer as clean."
                        : resultReason;
                    MessageBox.Show(
                        reason + (openReportButton.Enabled ? "\r\n\r\nUse Open last report to review the findings." : String.Empty),
                        "Post-scam collection needs attention",
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
            if (engineTimeout.HasValue && elapsed >= engineTimeout.Value && !timeoutCancellationRequested)
            {
                timeoutCancellationRequested = true;
                AppendOutput("TIMEOUT: The safe runtime limit was reached. Cancellation was requested; the current Windows operation will stop at its next safe boundary.", Color.Khaki);
                engineHost.RequestCancellation();
            }
        }

        private static TimeSpan? GetEngineTimeout(string displayName)
        {
            if (String.Equals(displayName, "Remote-access scanner", StringComparison.OrdinalIgnoreCase)) return TimeSpan.FromHours(6);
            if (String.Equals(displayName, "Post-scam evidence collection", StringComparison.OrdinalIgnoreCase)) return TimeSpan.FromHours(4);
            if (String.Equals(displayName, "Final System Check", StringComparison.OrdinalIgnoreCase)) return TimeSpan.FromMinutes(45);
            if (String.Equals(displayName, "Pre-Clone Preparation", StringComparison.OrdinalIgnoreCase)) return TimeSpan.FromHours(49);
            return null;
        }

        private void CancelRunningTool(object sender, EventArgs args)
        {
            if (engineHost == null || !engineHost.IsRunning) return;
            DialogResult answer = MessageBox.Show(
                "Request safe cancellation?\r\n\r\nToolbox SFC and DISM will be interrupted promptly and must be run again before the computer is marked ready. An uninstaller, CHKDSK repair, or BitLocker operation already started may continue until it reaches a protected stopping point. Partial results must not be treated as clean.",
                "Cancel running tool",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
            engineHost.RequestCancellation();
            cancelButton.Enabled = false;
            statusLabel.Text = "Safe cancellation requested — waiting for the current operation";
            SetStatusAppearance(Color.FromArgb(255, 243, 205), Color.FromArgb(112, 73, 0));
            AppendOutput("Safe cancellation requested by the technician.", Color.Khaki);
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
                promptLabel.ForeColor = Color.FromArgb(40, 80, 105);
                inputPanel.BackColor = Color.FromArgb(237, 246, 252);
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

        private void SetStatusAppearance(Color background, Color foreground)
        {
            statusPanel.BackColor = background;
            statusLabel.ForeColor = foreground;
        }

        private void SetCompletionAppearance(int exitCode)
        {
            if (exitCode == 0)
                SetStatusAppearance(Color.FromArgb(232, 245, 236), Color.FromArgb(26, 92, 60));
            else if (exitCode == 3 || exitCode == 4 || exitCode == 5 || exitCode == 7)
                SetStatusAppearance(Color.FromArgb(255, 243, 205), Color.FromArgb(112, 73, 0));
            else if (exitCode == 6)
                SetStatusAppearance(Color.FromArgb(235, 238, 240), Color.FromArgb(70, 78, 84));
            else
                SetStatusAppearance(Color.FromArgb(253, 232, 232), Color.FromArgb(145, 35, 35));
        }

        private void SetRunningState(bool running, string status)
        {
            progress.Visible = running;
            statusLabel.Text = status;
            if (running)
                SetStatusAppearance(Color.FromArgb(225, 240, 250), Color.FromArgb(20, 76, 112));
            else if (status.StartsWith("Could not", StringComparison.OrdinalIgnoreCase))
                SetStatusAppearance(Color.FromArgb(253, 232, 232), Color.FromArgb(145, 35, 35));
            SetActionControlsEnabled(!running && engineLayout != null);
            reloadButton.Enabled = !running;
            cancelButton.Enabled = running;
            cancelButton.BackColor = running ? Color.FromArgb(255, 235, 214) : SystemColors.Control;
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
                DialogResult answer = MessageBox.Show(
                    "A scanner or technician tool is still running.\r\n\r\nChoose Yes to request cancellation, or No to leave it running. Toolbox SFC and DISM stop promptly; protected disk, BitLocker, or uninstall operations may need to reach a safe stopping point before the window can close.",
                    "Tool still running",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);
                if (answer == DialogResult.Yes)
                {
                    engineHost.RequestCancellation();
                    cancelButton.Enabled = false;
                    statusLabel.Text = "Safe cancellation requested — waiting for the current operation";
                    SetStatusAppearance(Color.FromArgb(255, 243, 205), Color.FromArgb(112, 73, 0));
                    AppendOutput("Safe cancellation requested by the technician.", Color.Khaki);
                }
            }
        }
    }
}
