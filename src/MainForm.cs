// Main window: 1. Patch Ymir (find the client addresses, write regedit_<build>.exe), 2. Record (checklist, start/stop Ymir, the
// sniffs), 3. Viewer (browse a sniff, also while Ymir records into it; search, export).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace YmirTool
{
    public sealed class MainForm : Form
    {
        static readonly Font Mono = new Font("Consolas", 9.5f);
        static readonly Color Good = Color.FromArgb(0, 120, 60), Bad = Color.FromArgb(190, 40, 30), Warn = Color.FromArgb(200, 110, 0), Dim = Color.DimGray;

        TabControl tabs;
        ComboBox language;
        Label languageLabel, status;
        readonly Timer timer = new Timer { Interval = 1000 };
        int tick;

        // 1. patch
        Label patchHelp, ymirLabel, ymirState, clientLabel, clientState;
        TextBox ymirPath, log;
        Button browse, refresh, find, create, openFolder;
        ListView addresses;
        int clientBuild;
        Dictionary<string, FoundAddress> found;
        static readonly string Build = DateTime.Now.ToString("HHmm");   // shows in the title so the running binary is identifiable
        string keySniff;               // the .pkt a found session address was confirmed against (set by ConfirmSession)
        bool fromKnownBuild;

        // 2. record
        Label recordHelp, checklistTitle, recordingsTitle, recordState;
        Label[] checkName = new Label[3], checkState = new Label[3];
        CheckBox clearCache, strict;
        Label recorderLabel;
        RadioButton useYmir, useSniffer;
        TextBox snifferPath;
        Button browseSniffer;
        Button startYmir, stopYmir, openDumps, openRecording;
        ListView recordings;
        List<Recording> recordingList = new List<Recording>();
        long lastDumpSize;

        // 3. viewer
        Label viewerHelp, pktInfo;
        Button openPkt, toLive, prev, next, export, copyHex, savePkt;
        CheckBox follow, summary;
        TextBox filter, searchBox, hex;
        ComboBox direction, searchMode;
        ListView packets, opcodes;
        PktFile pkt;
        List<int> shown = new List<int>();
        List<string[]> visibleSummary = new List<string[]>();
        int matchPacket = -1, matchOffset, matchLength;

        public MainForm()
        {
            Text = "Ymir Tool " + Program.Version + " build " + Build;
            Size = new Size(1180, 780);
            MinimumSize = new Size(900, 600);
            Font = new Font("Segoe UI", 10f);
            StartPosition = FormStartPosition.CenterScreen;
            BuildUi();
            string saved = Settings.Get("ymir", "");
            if (File.Exists(saved)) SetYmir(saved);
            ApplyLanguage();
            RefreshAll();
            timer.Tick += (s, e) => OnTimer();
            timer.Start();
        }

        // ------------------------------------------------------------------ layout helpers
        static Label Text_(bool bold = false) { return new Label { AutoSize = true, Margin = new Padding(0, 6, 10, 0), Font = bold ? new Font("Segoe UI", 10f, FontStyle.Bold) : null }; }
        static Label Help() { return new Label { AutoSize = true, ForeColor = Dim, Margin = new Padding(0, 0, 0, 10), MaximumSize = new Size(1100, 0) }; }
        static Button Btn() { return new Button { AutoSize = true, Padding = new Padding(8, 2, 8, 2), Margin = new Padding(0, 2, 8, 2) }; }
        static FlowLayoutPanel Row() { return new FlowLayoutPanel { AutoSize = true, WrapContents = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6) }; }
        static TableLayoutPanel Stack(int rows)
        {
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = rows, Padding = new Padding(12, 10, 12, 8) };
            return t;
        }

        void BuildUi()
        {
            tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(14, 5) };
            var tPatch = new TabPage(); var tRecord = new TabPage(); var tViewer = new TabPage();
            tabs.TabPages.AddRange(new[] { tPatch, tRecord, tViewer });

            // top bar: language
            var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 4, 8, 0) };
            language = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
            language.Items.AddRange(L.Names);
            language.SelectedIndex = L.Lang;
            language.SelectedIndexChanged += (s, e) => { L.Lang = language.SelectedIndex; L.Save(); ApplyLanguage(); };
            languageLabel = new Label { AutoSize = true, Margin = new Padding(0, 5, 6, 0) };
            top.Controls.Add(language); top.Controls.Add(languageLabel);

            var statusStrip = new Panel { Dock = DockStyle.Bottom, Height = 28, Padding = new Padding(10, 5, 10, 0), BackColor = SystemColors.ControlLight };
            status = new Label { Dock = DockStyle.Fill, AutoEllipsis = true };
            statusStrip.Controls.Add(status);

            // --- 1. patch
            var p = Stack(6);
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            p.RowStyles.Add(new RowStyle(SizeType.Absolute, 170));
            p.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            patchHelp = Help();
            var r1 = Row();
            ymirLabel = Text_(true); ymirPath = new TextBox { Width = 560, ReadOnly = true, Margin = new Padding(0, 3, 8, 0) };
            browse = Btn(); browse.Click += (s, e) => PickYmir();
            ymirState = Text_();
            r1.Controls.AddRange(new Control[] { ymirLabel, ymirPath, browse, ymirState });
            var r2 = Row();
            clientLabel = Text_(true); clientState = Text_(); refresh = Btn(); refresh.Click += (s, e) => RefreshAll();
            r2.Controls.AddRange(new Control[] { clientLabel, clientState, refresh });
            var r3 = Row();
            find = Btn(); find.Click += (s, e) => FindAddresses();
            create = Btn(); create.Click += (s, e) => CreateYmir();
            openFolder = Btn(); openFolder.Click += (s, e) => OpenFolder(File.Exists(ymirPath.Text) ? Path.GetDirectoryName(ymirPath.Text) : null);
            r3.Controls.AddRange(new Control[] { find, create, openFolder });
            addresses = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, Font = Mono };
            foreach (var w in new[] { 190, 170, 140, 260, 330 }) addresses.Columns.Add("", w);
            log = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = Mono, BackColor = SystemColors.Window };
            p.Controls.Add(patchHelp, 0, 0); p.Controls.Add(r1, 0, 1); p.Controls.Add(r2, 0, 2); p.Controls.Add(r3, 0, 3);
            p.Controls.Add(addresses, 0, 4); p.Controls.Add(log, 0, 5);
            tPatch.Controls.Add(p);

            // --- 2. record
            var r = Stack(8);
            for (int i = 0; i < 7; i++) r.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            r.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            recordHelp = Help();
            // recorder: Ymir (made in tab 1) or Forever Sniffer (ours: any client build; its location can be chosen)
            var recRow = Row();
            recorderLabel = Text_(true);
            useYmir = new RadioButton { AutoSize = true, Text = "Ymir", Margin = new Padding(0, 5, 12, 0) };
            useSniffer = new RadioButton { AutoSize = true, Margin = new Padding(0, 5, 12, 0) };
            (Settings.Get("recorder", "ymir") == "sniffer" ? useSniffer : useYmir).Checked = true;
            useSniffer.CheckedChanged += (s, e) => { Settings.Set("recorder", useSniffer.Checked ? "sniffer" : "ymir"); RecorderChanged(); };
            snifferPath = new TextBox { Width = 420, ReadOnly = true, Margin = new Padding(0, 3, 8, 0), Text = DefaultSniffer() };
            browseSniffer = Btn(); browseSniffer.Click += (s, e) => PickSniffer();
            strict = new CheckBox { AutoSize = true, Margin = new Padding(0, 6, 0, 0), Checked = Settings.Get("strict", "0") == "1" };
            strict.CheckedChanged += (s, e) => Settings.Set("strict", strict.Checked ? "1" : "0");
            recRow.Controls.AddRange(new Control[] { recorderLabel, useYmir, useSniffer, snifferPath, browseSniffer, strict });
            checklistTitle = Text_(true);
            var checks = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Fill, Margin = new Padding(10, 0, 0, 6) };
            checks.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            checks.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 3; i++)
            {
                checkName[i] = Text_(); checkState[i] = Text_();
                checks.Controls.Add(checkName[i], 0, i); checks.Controls.Add(checkState[i], 1, i);
            }
            var controls = Row();
            clearCache = new CheckBox { AutoSize = true, Margin = new Padding(0, 6, 16, 0), Checked = Settings.Get("clearcache", "1") == "1" };
            clearCache.CheckedChanged += (s, e) => Settings.Set("clearcache", clearCache.Checked ? "1" : "0");
            startYmir = Btn(); startYmir.Click += (s, e) => StartYmir();
            stopYmir = Btn(); stopYmir.Click += (s, e) => StopYmir();
            openDumps = Btn(); openDumps.Click += (s, e) => OpenFolder(DumpsFolder());
            controls.Controls.AddRange(new Control[] { startYmir, stopYmir, openDumps, clearCache });
            recordState = Text_(true);
            recordState.Margin = new Padding(0, 4, 0, 10);
            var recHead = Row();
            recordingsTitle = Text_(true);
            openRecording = Btn(); openRecording.Click += (s, e) => OpenSelectedRecording();
            recHead.Controls.AddRange(new Control[] { recordingsTitle, openRecording });
            recordings = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, Font = Mono, HideSelection = false };
            foreach (var w in new[] { 160, 80, 110, 520 }) recordings.Columns.Add("", w);
            recordings.DoubleClick += (s, e) => OpenSelectedRecording();
            r.Controls.Add(recordHelp, 0, 0); r.Controls.Add(recRow, 0, 1); r.Controls.Add(checklistTitle, 0, 2); r.Controls.Add(checks, 0, 3);
            r.Controls.Add(controls, 0, 4); r.Controls.Add(recordState, 0, 5); r.Controls.Add(recHead, 0, 6); r.Controls.Add(recordings, 0, 7);
            tRecord.Controls.Add(r);

            // --- 3. viewer
            var v = Stack(5);
            for (int i = 0; i < 4; i++) v.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            v.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            viewerHelp = Help();
            var bar1 = Row();
            openPkt = Btn(); openPkt.Click += (s, e) => OpenPktDialog();
            follow = new CheckBox { AutoSize = true, Margin = new Padding(4, 6, 8, 0), Checked = true };
            toLive = Btn(); toLive.Click += (s, e) => { follow.Checked = true; ScrollToEnd(); };
            filter = new TextBox { Width = 230, Margin = new Padding(12, 3, 8, 0) };
            filter.TextChanged += (s, e) => ApplyFilter();
            direction = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160, Margin = new Padding(0, 3, 8, 0) };
            direction.SelectedIndexChanged += (s, e) => ApplyFilter();
            summary = new CheckBox { AutoSize = true, Margin = new Padding(4, 6, 0, 0) };
            summary.CheckedChanged += (s, e) => { packets.Visible = !summary.Checked; opcodes.Visible = summary.Checked; ApplyFilter(); };
            bar1.Controls.AddRange(new Control[] { openPkt, follow, toLive, filter, direction, summary });
            var bar2 = Row();
            searchBox = new TextBox { Width = 260, Margin = new Padding(0, 3, 8, 0) };
            searchBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Search(e.Shift ? -1 : 1); } };
            searchMode = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110, Margin = new Padding(0, 3, 8, 0) };
            prev = Btn(); prev.Click += (s, e) => Search(-1);
            next = Btn(); next.Click += (s, e) => Search(1);
            export = Btn(); export.Click += (s, e) => ExportList();
            copyHex = Btn(); copyHex.Click += (s, e) => CopyHex();
            savePkt = Btn(); savePkt.Click += (s, e) => SavePacket();
            export.Margin = new Padding(24, 2, 8, 2);
            bar2.Controls.AddRange(new Control[] { searchBox, searchMode, prev, next, export, copyHex, savePkt });
            pktInfo = Text_(true);
            pktInfo.Margin = new Padding(0, 2, 0, 6);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            packets = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, VirtualMode = true, Font = Mono, HideSelection = false, GridLines = true };
            foreach (var w in new[] { 80, 90, 60, 60, 100, 430, 90 }) packets.Columns.Add("", w);
            packets.RetrieveVirtualItem += RetrievePacket;
            packets.SelectedIndexChanged += (s, e) => ShowPacket();
            opcodes = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, VirtualMode = true, Font = Mono, Visible = false, GridLines = true };
            foreach (var w in new[] { 60, 100, 430, 90, 160 }) opcodes.Columns.Add("", w);
            opcodes.RetrieveVirtualItem += (s, e) => e.Item = new ListViewItem(visibleSummary[e.ItemIndex]);
            opcodes.DoubleClick += (s, e) =>
            {
                if (opcodes.SelectedIndices.Count == 0) return;
                filter.Text = visibleSummary[opcodes.SelectedIndices[0]][1];
                summary.Checked = false;
            };
            hex = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Mono, BackColor = SystemColors.Window };
            split.Panel1.Controls.Add(packets); split.Panel1.Controls.Add(opcodes);
            split.Panel2.Controls.Add(hex);
            v.Controls.Add(viewerHelp, 0, 0); v.Controls.Add(bar1, 0, 1); v.Controls.Add(bar2, 0, 2); v.Controls.Add(pktInfo, 0, 3); v.Controls.Add(split, 0, 4);
            tViewer.Controls.Add(v);
            Load += (s, e) => { try { split.SplitterDistance = Math.Max(150, split.Height * 6 / 10); } catch { } };

            Controls.Add(tabs);
            Controls.Add(top);
            Controls.Add(statusStrip);
            AllowDrop = true;
            DragEnter += (s, e) => e.Effect = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
            DragDrop += (s, e) =>
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files == null || files.Length == 0) return;
                if (files[0].EndsWith(".pkt", StringComparison.OrdinalIgnoreCase)) LoadPkt(files[0]);
                else if (files[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) SetYmir(files[0]);
            };
        }

        void ApplyLanguage()
        {
            languageLabel.Text = L.Get("language");
            tabs.TabPages[0].Text = L.Get("tab.patch"); tabs.TabPages[1].Text = L.Get("tab.record"); tabs.TabPages[2].Text = L.Get("tab.viewer");
            patchHelp.Text = L.Get("help.patch"); recordHelp.Text = L.Get("help.record"); viewerHelp.Text = L.Get("help.viewer");
            ymirLabel.Text = L.Get("ymir"); browse.Text = L.Get("browse"); clientLabel.Text = L.Get("client"); refresh.Text = L.Get("refresh");
            find.Text = L.Get("find"); create.Text = L.Get("create"); openFolder.Text = L.Get("openfolder");
            Columns(addresses, "col.address", "col.original", "col.new", "col.method", "col.check");
            checklistTitle.Text = L.Get("checklist"); clearCache.Text = L.Get("clearcache");
            recorderLabel.Text = L.Get("recorder"); useSniffer.Text = L.Get("rec.sniffer"); browseSniffer.Text = L.Get("browse"); strict.Text = L.Get("strict");
            snifferPath.Enabled = browseSniffer.Enabled = strict.Enabled = useSniffer.Checked;
            startYmir.Text = L.Get("start"); stopYmir.Text = L.Get("stop"); openDumps.Text = L.Get("opendumps");
            recordingsTitle.Text = L.Get("recordings"); openRecording.Text = L.Get("openrec");
            Columns(recordings, "col.date", "col.build", "col.size", "col.file");
            openPkt.Text = L.Get("open"); follow.Text = L.Get("follow"); toLive.Text = L.Get("tolive"); summary.Text = L.Get("summary");
            prev.Text = L.Get("prev"); next.Text = L.Get("next"); export.Text = L.Get("export"); copyHex.Text = L.Get("copyhex"); savePkt.Text = L.Get("savepkt");
            SetCue(filter, L.Get("filter")); SetCue(searchBox, L.Get("search"));
            Refill(direction, L.Get("dir.all"), L.Get("dir.server"), L.Get("dir.client"));
            Refill(searchMode, L.Get("search.text"), L.Get("search.hex"));
            Columns(packets, "col.n", "col.time", "col.dir", "col.conn", "col.opcode", "col.name", "col.size");
            Columns(opcodes, "col.dir", "col.opcode", "col.name", "col.count", "col.sizes");
            if (File.Exists(ymirPath.Text)) SetYmir(ymirPath.Text);
            RefreshAll();
            ShowAddresses();
            UpdatePktInfo();
        }

        static void Columns(ListView lv, params string[] keys) { for (int i = 0; i < keys.Length; i++) lv.Columns[i].Text = L.Get(keys[i]); }
        static void Refill(ComboBox c, params string[] items)
        {
            int keep = Math.Max(0, c.SelectedIndex);
            c.Items.Clear(); c.Items.AddRange(items);
            c.SelectedIndex = Math.Min(keep, items.Length - 1);
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);
        static void SetCue(TextBox box, string text) { SendMessage(box.Handle, 0x1501, (IntPtr)1, text); }   // EM_SETCUEBANNER

        void Say(string text, Color color)
        {
            status.Text = text;
            status.ForeColor = color;
        }

        void Log(string text)
        {
            log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + text + Environment.NewLine);
        }

        static void OpenFolder(string folder)
        {
            if (folder != null && Directory.Exists(folder)) Process.Start("explorer.exe", "\"" + folder + "\"");
        }

        string YmirFolder() { return File.Exists(ymirPath.Text) ? Path.GetDirectoryName(ymirPath.Text) : null; }
        // the chosen recorder's folder (its dumps folder is where the sniffs go)
        string RecordFolder() { return useSniffer.Checked ? (SnifferExe() != null ? Path.GetDirectoryName(SnifferExe()) : null) : YmirFolder(); }
        string DumpsFolder() { var f = RecordFolder(); return f == null ? null : Path.Combine(f, "dumps"); }
        string RecorderProcess() { return useSniffer.Checked ? "ForeverSniffer" : "regedit"; }
        string SnifferExe() { return File.Exists(snifferPath.Text) ? snifferPath.Text : null; }

        // the remembered location, else ForeverSniffer.exe next to this tool
        static string DefaultSniffer()
        {
            string saved = Settings.Get("sniffer", "");
            if (File.Exists(saved)) return saved;
            string next = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ForeverSniffer.exe");
            return File.Exists(next) ? next : "";
        }

        void PickSniffer()
        {
            using (var dlg = new OpenFileDialog { Filter = "Forever Sniffer (ForeverSniffer.exe)|ForeverSniffer.exe|*.exe|*.exe", Title = L.Get("pick.sniffer") })
            {
                if (SnifferExe() != null) dlg.InitialDirectory = Path.GetDirectoryName(SnifferExe());
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                snifferPath.Text = dlg.FileName;
                Settings.Set("sniffer", dlg.FileName);
                RecorderChanged();
            }
        }

        void RecorderChanged()
        {
            snifferPath.Enabled = browseSniffer.Enabled = strict.Enabled = useSniffer.Checked;
            UpdateChecklist();
            RefreshRecordings();
            UpdateRecordState();
        }

        void OnTimer()
        {
            tick++;
            try
            {
                UpdateRecordState();
                if (tick % 5 == 0) { RefreshRecordings(); if (tabs.SelectedIndex == 0) RefreshClient(); }
                if (pkt != null && follow.Checked) FollowLive();
            }
            catch (Exception ex) { Say(ex.Message, Bad); }
        }

        void RefreshAll()
        {
            RefreshClient();
            UpdateChecklist();
            RefreshRecordings();
            UpdateRecordState();
        }

        // ------------------------------------------------------------------ 1. patch
        void PickYmir()
        {
            using (var dlg = new OpenFileDialog { Filter = "Ymir (regedit.exe)|*.exe", Title = L.Get("ymir") })
            {
                if (File.Exists(ymirPath.Text)) dlg.InitialDirectory = Path.GetDirectoryName(ymirPath.Text);
                if (dlg.ShowDialog(this) == DialogResult.OK) SetYmir(dlg.FileName);
            }
        }

        void SetYmir(string path)
        {
            ymirPath.Text = path;
            string why;
            try
            {
                var data = File.ReadAllBytes(path);
                why = YmirPatcher.CheckSource(data);
                if (why == null)
                {
                    // a copy patched earlier by this tool is accepted too: its own build number is what matters now
                    int build = YmirPatcher.ReadBuild(data);
                    var cur = YmirPatcher.ReadCurrent(data);
                    ymirState.Text = YmirPatcher.IsOriginal(data)
                        ? L.Get("ymir.ok")
                        : string.Format("OK: Ymir already patched to build {0} (locale 0x{1:x} table 0x{2:x} session 0x{3:x})",
                                        build, cur.LocaleIndex, cur.LocaleTable, cur.Session);
                }
                else ymirState.Text = L.Get("ymir.bad", why);
            }
            catch (Exception ex) { why = ex.Message; ymirState.Text = L.Get("ymir.bad", why); }
            ymirState.ForeColor = why == null ? Good : Bad;
            if (why == null) Settings.Set("ymir", path);
            UpdateButtons();
            UpdateChecklist();
            RefreshRecordings();
        }

        void RefreshClient()
        {
            int before = clientBuild;
            var p = LiveImage.FindClient();
            try
            {
                string exe = p != null ? p.MainModule.FileName : Settings.GameExe();
                if (exe != null)
                {
                    Settings.Set("game", exe);
                    string version = FileVersionInfo.GetVersionInfo(exe).FileVersion ?? "";
                    clientBuild = int.Parse(version.Split('.').Last());
                }
                if (p == null) { clientState.Text = (clientBuild > 0 ? "build " + clientBuild + " · " : "") + L.Get("noclient") + (LiveImage.LastError != null ? " [" + LiveImage.LastError + "]" : ""); clientState.ForeColor = Dim; }
                else { clientState.Text = string.Format("PID {0} · build {1} · {2}", p.Id, clientBuild, exe); clientState.ForeColor = SystemColors.ControlText; }
            }
            catch (Exception ex) { clientState.Text = ex.Message; clientState.ForeColor = Bad; }
            if (clientBuild != before) found = null;
            var known = clientBuild > 0 ? Finder.Known(clientBuild) : null;
            if (known != null && found == null)
            {
                fromKnownBuild = true;
                found = Finder.Keys.ToDictionary(k => k, k => new FoundAddress { Key = k, Rva = known.Get(k), Check = CheckState.Ok, Detail = L.Get("method.known") });
                // the locale addresses are static in the image, so a known build can show them without the game;
                // the session slot is only meaningful while the client runs, and only a sniff can confirm it
                if (p == null)
                {
                    found["session"].Check = CheckState.Unconfirmed;
                    found["session"].Detail = L.Get("method.known") + ", start the game to confirm";
                }
                Log(L.Get("known", clientBuild));
                ShowAddresses();
            }
            UpdateButtons();
            if (clientBuild != before) UpdateChecklist();
        }

        // Fingerprints only know where things looked right on an older build. When they fail, do what ForeverSniffer does: follow
        // every .data pointer, read the 40-byte key at +0x48 and keep the one that decrypts a real captured packet (AES-GCM tag
        // check). A wrong key cannot pass that, so the address is confirmed rather than guessed.
        bool ConfirmSession(LiveImage img, Dictionary<string, FoundAddress> result)
        {
            if (keySniff == null || !File.Exists(keySniff))
            {
                keySniff = NewestSniff();
                if (keySniff == null)
                {
                    Log("session key check skipped: no .pkt found");
                    Log("  looked in: " + string.Join("; ", SniffFolders().ToArray()));
                    return false;
                }
                Log("session key check uses " + keySniff);
            }
            List<KeySample> samples;
            string detail;
            try { samples = PktSamples.Load(keySniff, out detail); }
            catch (Exception ex) { Log("sniff unusable for the key check: " + ex.Message); return false; }
            Log("checking the session key against " + Path.GetFileName(keySniff) + ": " + detail);
            if (samples.Count == 0) { Log("that sniff holds no handshake (no challenges) - cannot confirm a key with it"); return false; }

            // A known build already has the session slot: check that one first, and if the key there decrypts the
            // capture the answer is settled - no scanning of tens of thousands of pointers needed.
            int tried = 0;
            int build = 0;
            try { var parts = (img.Version ?? "").Split('.'); int.TryParse(parts[parts.Length - 1], out build); }
            catch { build = 0; }
            var known = Finder.Known(build);
            if (known != null && known.Session != 0)
            {
                var at = img.ReadInt64(known.Session);
                var k0 = KeyCheck.ReadKeyAt(img, at);
                if (k0 != null && KeyCheck.Works(k0, samples))
                {
                    Log(string.Format("session key CONFIRMED at the known slot 0x{0:x} (pointer 0x{1:x}, key at +0x{2:x})",
                                      known.Session, at, KeyCheck.SessionKeyOffset));
                    result["session"] = new FoundAddress { Key = "session", Rva = known.Session, Check = CheckState.Ok, Detail = "key decrypts the sniff" };
                    return true;
                }
                Log(string.Format("the known slot 0x{0:x} does not hold a working key in this session; scanning instead", known.Session));
            }
            foreach (var slot in Finder.DataPointerSlots(img))
            {
                var key = KeyCheck.ReadKeyAt(img, slot.Value);
                if (key == null) continue;
                tried++;
                if (!KeyCheck.Works(key, samples)) continue;
                Log(string.Format("session key CONFIRMED: pointer at image RVA 0x{0:x}, key at +0x{1:x} - decrypts {2}",
                                  slot.Key, KeyCheck.SessionKeyOffset, Path.GetFileName(keySniff)));
                result["session"] = new FoundAddress { Key = "session", Rva = slot.Key, Check = CheckState.Ok, Detail = "key decrypts the sniff" };
                return true;
            }
            Log(string.Format("no .data pointer held a working key ({0} keys tried against {1} packet(s))", tried, samples.Count));
            return false;
        }

        // the newest .pkt in the recorder's dumps folder
        // every place a .pkt can be: the recorder's dumps folder, one next to this tool, and one next to each saved recorder path
        List<string> SniffFolders()
        {
            var dirs = new List<string>();
            var own = DumpsFolder();
            if (own != null) dirs.Add(own);
            dirs.Add(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dumps"));
            foreach (var key in new[] { "sniffer", "ymir" })
            {
                string saved;
                try { saved = Settings.Get(key, ""); } catch { continue; }
                if (string.IsNullOrEmpty(saved)) continue;
                var parent = Path.GetDirectoryName(saved);
                if (!string.IsNullOrEmpty(parent)) dirs.Add(Path.Combine(parent, "dumps"));
            }
            return dirs;
        }

        string NewestSniff()
        {
            var dirs = SniffFolders();


            string best = null;
            DateTime bestTime = DateTime.MinValue;
            foreach (var d in dirs)
            {
                if (string.IsNullOrEmpty(d) || !Directory.Exists(d)) continue;
                foreach (var f in Directory.GetFiles(d, "*.pkt"))
                {
                    var when = File.GetLastWriteTimeUtc(f);
                    if (when > bestTime) { bestTime = when; best = f; }
                }
            }
            return best;
        }
        void UpdateButtons()
        {
            find.Enabled = LiveImage.FindClient() != null;
            bool targetOk = false;
            try
            {
                targetOk = clientBuild > 0 && File.Exists(ymirPath.Text)
                           && YmirPatcher.CheckTarget(File.ReadAllBytes(ymirPath.Text), clientBuild) == null;
            }
            catch { targetOk = false; }
            // Ymir needs three addresses, not three confirmations: a failed search leaves Rva = 0 or a stretch of code,
            // which is what must never reach a copy of Ymir. Unconfirmed means "from the build table, not checked in this
            // session" - the session slot can only be checked while the game runs, so it must not block patching.
            bool foundOk = found != null && found.Values.All(f => f.Check != CheckState.Failed && f.Rva != 0);
            create.Enabled = targetOk && foundOk && ymirState.ForeColor == Good;
        }

        async void FindAddresses()
        {
            var p = LiveImage.FindClient();
            if (p == null) { RefreshClient(); return; }
            find.Enabled = false; create.Enabled = false;
            try
            {
                var near = Finder.AllBuilds().Where(b => b.Build <= clientBuild).LastOrDefault() ?? Finder.KnownBuilds.Last();
                using (var img = new LiveImage(p))
                {
                    Log(L.Get("searching", clientBuild, near.Build));
                    Say(L.Get("searching", clientBuild, near.Build), Dim);
                    int fpBuild = 0;
                    var result = await Task.Run(() => Finder.FindAll(img, near, out fpBuild));
                    found = result;
                    fromKnownBuild = false;
                    ShowAddresses();
                    foreach (var f in result.Values)
                        Log(string.Format("{0,-13} 0x{1:x}  {2}/{3} (next best {4})  {5}", f.Key, f.Rva, f.Score, f.MaxScore, f.RunnerUp, f.Detail));
                    // the patterns failed: confirm the session key against a captured packet instead
                    FoundAddress sess;
                    bool sessionOk = result.TryGetValue("session", out sess) && sess.Check == CheckState.Ok;
                    if (!sessionOk && ConfirmSession(img, result))
                    {
                        found = result;
                        ShowAddresses();
                        UpdateButtons();
                    }
                    if (result.Values.All(f => f.Check == CheckState.Ok))
                    {
                        Finder.Learn(img, clientBuild, result);
                        Log(L.Get("learned", clientBuild)); Say(L.Get("learned", clientBuild), Good);
                    }
                    else
                    {
                        Log(L.Get("notall"));
                        Say(L.Get("notall"), Warn);
                        Log("Create patched Ymir stays off until all three addresses check out (look at the Check column).");
                    }
                }
            }
            catch (Exception ex) { Log("ERROR: " + ex.Message); Say(ex.Message, Bad); }
            find.Enabled = true;
            UpdateButtons();
        }

        void ShowAddresses()
        {
            addresses.Items.Clear();
            var original = Finder.Known(YmirPatcher.OriginalBuild);
            // what the chosen Ymir itself holds - the file can already be patched, so these are not always the 70124 numbers
            BuildAddresses current = null;
            int ymirBuild = 0;
            try
            {
                if (File.Exists(ymirPath.Text))
                {
                    var data = File.ReadAllBytes(ymirPath.Text);
                    current = YmirPatcher.ReadCurrent(data);
                    ymirBuild = YmirPatcher.ReadBuild(data);
                }
            }
            catch { }
            foreach (var key in Finder.Keys)
            {
                var item = new ListViewItem(L.Get("addr." + key));
                item.SubItems.Add("0x" + (current != null ? current.Get(key) : original.Get(key)).ToString("x"));
                FoundAddress f;
                if (found != null && found.TryGetValue(key, out f))
                {
                    item.SubItems.Add("0x" + f.Rva.ToString("x"));
                    item.SubItems.Add(fromKnownBuild ? L.Get("method.known") : L.Get("method.fp", f.Score, f.MaxScore, f.RunnerUp));
                    item.SubItems.Add(L.Get(f.Check == CheckState.Ok ? "check.ok" : f.Check == CheckState.Unconfirmed ? "check.unconfirmed" : "check.failed", f.Detail));
                    item.ForeColor = f.Check == CheckState.Ok ? Good : f.Check == CheckState.Unconfirmed ? Warn : Bad;
                }
                addresses.Items.Add(item);
            }
            var build = new ListViewItem("Build");
            build.SubItems.Add((ymirBuild > 0 ? ymirBuild : YmirPatcher.OriginalBuild).ToString());
            build.SubItems.Add(clientBuild > 0 ? clientBuild.ToString() : "");
            addresses.Items.Add(build);
        }

        void CreateYmir()
        {
            try
            {
                var a = new BuildAddresses { Build = clientBuild };
                foreach (var key in Finder.Keys) a.Set(key, found[key].Rva);
                var source = File.ReadAllBytes(ymirPath.Text);
                string cannot = YmirPatcher.CheckTarget(source, clientBuild);
                if (cannot != null) { Log("ERROR: " + cannot); Say(cannot, Bad); return; }
                var output = YmirPatcher.OutputPath(ymirPath.Text, clientBuild);
                if (File.Exists(output) && MessageBox.Show(this, L.Get("overwrite", Path.GetFileName(output)), Text, MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                var patched = YmirPatcher.Patch(source, clientBuild, a);
                File.WriteAllBytes(output, patched);
                Log(L.Get("written", output, YmirPatcher.Spots.Length)); Say(L.Get("written", output, YmirPatcher.Spots.Length), Good);
                UpdateChecklist();
            }
            catch (Exception ex) { Log("ERROR: " + ex.Message); Say(ex.Message, Bad); }
        }

        // ------------------------------------------------------------------ 2. record
        string ymirForClient;

        void UpdateChecklist()
        {
            string npcap = YmirRunner.NpcapProblem();
            SetCheck(0, L.Get("chk.npcap"), npcap == null, npcap == null ? L.Get("ok.npcap") : npcap);
            if (useSniffer.Checked)
            {
                // Forever Sniffer: listens on every adapter unless interface.cfg names one; works with any client build
                string exe = SnifferExe();
                string cfg = exe == null ? null : YmirRunner.Adapter(Path.GetDirectoryName(exe));
                SetCheck(1, L.Get("chk.adapter"), true, cfg ?? L.Get("sniffer.adapter"));
                SetCheck(2, L.Get("pick.sniffer"), exe != null, exe ?? L.Get("no.sniffer"));
                return;
            }
            string folder = YmirFolder();
            string adapter = folder == null ? null : YmirRunner.Adapter(folder);
            SetCheck(1, L.Get("chk.adapter"), adapter != null, adapter != null ? L.Get("ok.adapter") + ": " + adapter : L.Get("no.adapter"));
            ymirForClient = folder != null && clientBuild > 0 ? YmirRunner.YmirFor(folder, clientBuild) : null;
            SetCheck(2, clientBuild > 0 ? L.Get("chk.ymir", clientBuild) : L.Get("chk.nobuild"), ymirForClient != null,
                     ymirForClient != null ? Path.GetFileName(ymirForClient) : L.Get("no.ymir"));
        }

        void SetCheck(int i, string name, bool ok, string state)
        {
            checkName[i].Text = (ok ? "✔  " : "✖  ") + name;
            checkName[i].ForeColor = ok ? Good : Bad;
            checkState[i].Text = state;
            checkState[i].ForeColor = ok ? SystemColors.ControlText : Bad;
        }

        void UpdateRecordState()
        {
            string folder = RecordFolder();
            var running = folder == null ? new List<Process>() : YmirRunner.Running(folder, RecorderProcess());
            bool ready = useSniffer.Checked ? SnifferExe() != null : ymirForClient != null;
            startYmir.Enabled = running.Count == 0 && ready && YmirRunner.NpcapProblem() == null;
            stopYmir.Enabled = running.Count > 0;
            if (running.Count == 0) { recordState.Text = L.Get("state.off"); recordState.ForeColor = Dim; lastDumpSize = 0; return; }
            var newest = YmirRunner.Recordings(folder).FirstOrDefault();
            if (newest != null && newest.Modified > running[0].StartTime)
            {
                bool growing = newest.Size > lastDumpSize && lastDumpSize > 0;
                lastDumpSize = newest.Size;
                recordState.Text = L.Get("state.rec", Path.GetFileName(newest.Path), YmirRunner.FormatSize(newest.Size), growing ? L.Get("growing") : "");
                recordState.ForeColor = Good;
            }
            else { recordState.Text = L.Get("state.on", running[0].Id); recordState.ForeColor = Good; }
        }

        void StartYmir()
        {
            try
            {
                UpdateChecklist();
                if (useSniffer.Checked ? SnifferExe() == null : ymirForClient == null) return;
                if (clearCache.Checked)
                {
                    string cache = YmirRunner.CacheFolder(Settings.GameExe());
                    if (LiveImage.FindClient() != null) Say(L.Get("cache.gamerunning"), Warn);
                    else if (cache != null && Directory.Exists(cache)) { Directory.Delete(cache, true); Say(L.Get("cache.deleted", cache), Dim); }
                }
                if (useSniffer.Checked) YmirRunner.Start(SnifferExe(), strict.Checked ? "--strict" : "");
                else YmirRunner.Start(ymirForClient);
                Say(L.Get("started"), Good);
            }
            catch (Exception ex) { Say(ex.Message, Bad); }
            UpdateRecordState();
        }

        async void StopYmir()
        {
            string folder = RecordFolder();
            var running = folder == null ? new List<Process>() : YmirRunner.Running(folder, RecorderProcess());
            if (running.Count == 0) return;
            stopYmir.Enabled = false;
            bool ok = await Task.Run(() => running.All(p => YmirRunner.Stop(p, 10000)));
            Say(L.Get(ok ? "stopped" : "notstopped"), ok ? Good : Warn);
            UpdateRecordState();
        }

        void RefreshRecordings()
        {
            string folder = RecordFolder();
            var list = folder == null ? new List<Recording>() : YmirRunner.Recordings(folder);
            bool same = list.Count == recordingList.Count && list.Zip(recordingList, (a, b) => a.Path == b.Path && a.Size == b.Size).All(x => x);
            if (same) return;
            string selected = recordings.SelectedItems.Count > 0 ? (string)recordings.SelectedItems[0].Tag : null;
            recordingList = list;
            recordings.BeginUpdate();
            recordings.Items.Clear();
            foreach (var rec in list)
            {
                var item = new ListViewItem(rec.Started.ToString("yyyy-MM-dd HH:mm")) { Tag = rec.Path };
                item.SubItems.Add(rec.Build > 0 ? rec.Build.ToString() : "?");
                item.SubItems.Add(YmirRunner.FormatSize(rec.Size));
                item.SubItems.Add(Path.GetFileName(rec.Path));
                if (rec.Path == selected) item.Selected = true;
                recordings.Items.Add(item);
            }
            recordings.EndUpdate();
        }

        void OpenSelectedRecording()
        {
            if (recordings.SelectedItems.Count > 0) LoadPkt((string)recordings.SelectedItems[0].Tag);
        }

        // ------------------------------------------------------------------ 3. viewer
        void OpenPktDialog()
        {
            using (var dlg = new OpenFileDialog { Filter = "Ymir sniff (*.pkt)|*.pkt" })
            {
                var dumps = DumpsFolder();
                if (dumps != null && Directory.Exists(dumps)) dlg.InitialDirectory = dumps;
                if (dlg.ShowDialog(this) == DialogResult.OK) LoadPkt(dlg.FileName);
            }
        }

        async void LoadPkt(string path)
        {
            tabs.SelectedIndex = 2;
            Say(L.Get("loading", path), Dim);
            try
            {
                var opened = await Task.Run(() => PktFile.Open(path));
                pkt = opened;
                matchPacket = -1;
                hex.Text = "";
                ApplyFilter();
                if (follow.Checked) ScrollToEnd();
                Say(pkt.Problem ?? "", pkt.Problem == null ? Dim : Warn);
            }
            catch (Exception ex) { pkt = null; ApplyFilter(); Say(path + ": " + ex.Message, Bad); }
        }

        void FollowLive()
        {
            int added;
            try { added = pkt.Refresh(); }
            catch (IOException) { return; }             // file busy for a moment
            if (added == 0) return;
            int start = pkt.Packets.Count - added;
            for (int i = start; i < pkt.Packets.Count; i++) if (Matches(pkt.Packets[i])) shown.Add(i);
            packets.VirtualListSize = shown.Count;
            BuildSummary();
            UpdatePktInfo();
            ScrollToEnd();
        }

        void ScrollToEnd()
        {
            if (shown.Count > 0 && packets.Visible) packets.EnsureVisible(shown.Count - 1);
        }

        bool filterIsHex; uint filterOpcode; string filterText = "";

        bool Matches(PacketInfo p)
        {
            int dir = direction.SelectedIndex;
            if (dir == 1 && !p.FromServer || dir == 2 && p.FromServer) return false;
            if (filterText.Length == 0) return true;
            if (filterIsHex && p.Opcode == filterOpcode) return true;
            return Opcodes.Name(p.Opcode, p.FromServer).IndexOf(filterText, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        void ApplyFilter()
        {
            filterText = filter.Text.Trim();
            string h = filterText.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? filterText.Substring(2) : filterText;
            filterIsHex = h.Length >= 4 && uint.TryParse(h, System.Globalization.NumberStyles.HexNumber, null, out filterOpcode);
            shown = new List<int>();
            if (pkt != null)
                for (int i = 0; i < pkt.Packets.Count; i++) if (Matches(pkt.Packets[i])) shown.Add(i);
            packets.VirtualListSize = shown.Count;
            packets.Invalidate();
            BuildSummary();
            UpdatePktInfo();
        }

        void BuildSummary()
        {
            if (pkt == null) { visibleSummary = new List<string[]>(); opcodes.VirtualListSize = 0; return; }
            if (!summary.Checked) return;
            int dir = direction.SelectedIndex;
            visibleSummary = pkt.Packets.Where(p => !(dir == 1 && !p.FromServer || dir == 2 && p.FromServer))
                .GroupBy(p => new { p.FromServer, p.Opcode }).OrderByDescending(g => g.Count())
                .Select(g => new[] { g.Key.FromServer ? "S" : "C", "0x" + g.Key.Opcode.ToString("X6"), Opcodes.Name(g.Key.Opcode, g.Key.FromServer),
                                     g.Count().ToString("N0"), g.Min(p => p.Length) + " - " + g.Max(p => p.Length) })
                .Where(r => filterText.Length == 0 || r[1].IndexOf(filterText, StringComparison.OrdinalIgnoreCase) >= 0 || r[2].IndexOf(filterText, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();
            opcodes.VirtualListSize = visibleSummary.Count;
            opcodes.Invalidate();
        }

        void UpdatePktInfo()
        {
            if (pkt == null) { pktInfo.Text = L.Get("nopkt"); return; }
            int last = pkt.Packets.Count > 0 ? pkt.Packets[pkt.Packets.Count - 1].TimeMs : 0;
            pktInfo.Text = L.Get("pktinfo", Path.GetFileName(pkt.Path), pkt.Build, pkt.Started.ToString("yyyy-MM-dd HH:mm"),
                                 pkt.Packets.Count, shown.Count, TimeSpan.FromMilliseconds(Math.Max(0, last)).ToString(@"h\:mm\:ss"));
        }

        void RetrievePacket(object sender, RetrieveVirtualItemEventArgs e)
        {
            if (pkt == null || e.ItemIndex >= shown.Count) { e.Item = new ListViewItem(""); return; }
            int i = shown[e.ItemIndex];
            var p = pkt.Packets[i];
            var item = new ListViewItem(i.ToString());
            item.SubItems.Add(TimeSpan.FromMilliseconds(Math.Max(0, p.TimeMs)).ToString(@"m\:ss\.fff"));
            item.SubItems.Add(p.FromServer ? "S" : "C");
            item.SubItems.Add(p.Connection.ToString());
            item.SubItems.Add("0x" + p.Opcode.ToString("X6"));
            item.SubItems.Add(Opcodes.Name(p.Opcode, p.FromServer));
            item.SubItems.Add(p.Length.ToString("N0"));
            if (!p.FromServer) item.ForeColor = Color.SteelBlue;
            if (i == matchPacket) item.BackColor = Color.LightYellow;
            e.Item = item;
        }

        int SelectedPacket() { return pkt != null && packets.SelectedIndices.Count > 0 ? shown[packets.SelectedIndices[0]] : -1; }

        void ShowPacket()
        {
            int i = SelectedPacket();
            if (i < 0) return;
            var p = pkt.Packets[i];
            bool marked = i == matchPacket;
            hex.Text = string.Format("#{0}  {1} 0x{2:X6} {3}  ·  {4:N0} bytes{5}", i, p.FromServer ? "SMSG" : "CMSG", p.Opcode, Opcodes.Name(p.Opcode, p.FromServer), p.Length,
                                     Environment.NewLine + Environment.NewLine)
                       + PktFile.HexDump(pkt.Payload(p, 65536), p.Length, marked ? matchOffset : 0, marked ? matchLength : 0);
        }

        byte[] SearchPattern()
        {
            string s = searchBox.Text;
            if (s.Length == 0) return null;
            if (searchMode.SelectedIndex == 0) return Encoding.UTF8.GetBytes(s);
            var parts = s.Replace(",", " ").Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 1 && parts[0].Length > 2 && parts[0].Length % 2 == 0)
                parts = Enumerable.Range(0, parts[0].Length / 2).Select(i => parts[0].Substring(i * 2, 2)).ToArray();
            var b = new byte[parts.Length];
            for (int i = 0; i < parts.Length; i++)
                if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out b[i])) { Say(L.Get("badhex"), Warn); return null; }
            return b;
        }

        void Search(int step)
        {
            if (pkt == null || shown.Count == 0) return;
            var pattern = SearchPattern();
            if (pattern == null || pattern.Length == 0) return;
            bool ignoreCase = searchMode.SelectedIndex == 0;
            int from = packets.SelectedIndices.Count > 0 ? packets.SelectedIndices[0] + step : (step > 0 ? 0 : shown.Count - 1);
            for (int row = from; row >= 0 && row < shown.Count; row += step)
            {
                var p = pkt.Packets[shown[row]];
                int at = pkt.Find(p, pattern, ignoreCase);
                if (at < 0) continue;
                matchPacket = shown[row]; matchOffset = at; matchLength = pattern.Length;
                follow.Checked = false;
                packets.SelectedIndices.Clear();
                packets.SelectedIndices.Add(row);
                packets.EnsureVisible(row);
                packets.Invalidate();
                ShowPacket();
                Say(L.Get("found", matchPacket, at), Good);
                return;
            }
            Say(L.Get("notfound", L.Get(step > 0 ? "dir.down" : "dir.up")), Warn);
        }

        void ExportList()
        {
            if (pkt == null) return;
            using (var dlg = new SaveFileDialog { Filter = "CSV|*.csv", FileName = Path.GetFileNameWithoutExtension(pkt.Path) + ".csv" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    var sb = new StringBuilder("index,time_ms,direction,connection,opcode,name,size\r\n");
                    foreach (int i in shown)
                    {
                        var p = pkt.Packets[i];
                        sb.AppendFormat("{0},{1},{2},{3},0x{4:X6},{5},{6}\r\n", i, p.TimeMs, p.FromServer ? "S" : "C", p.Connection, p.Opcode, Opcodes.Name(p.Opcode, p.FromServer), p.Length);
                    }
                    File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
                    Say(L.Get("exported", shown.Count, dlg.FileName), Good);
                }
                catch (Exception ex) { Say(ex.Message, Bad); }
            }
        }

        void CopyHex()
        {
            int i = SelectedPacket();
            if (i < 0) return;
            var b = pkt.Payload(pkt.Packets[i], int.MaxValue);
            try
            {
                Clipboard.SetText(BitConverter.ToString(b).Replace("-", " "));
                Say(L.Get("copied", b.Length), Good);
            }
            catch (Exception ex) { Say(ex.Message, Bad); }
        }

        void SavePacket()
        {
            int i = SelectedPacket();
            if (i < 0) return;
            var p = pkt.Packets[i];
            using (var dlg = new SaveFileDialog { Filter = "Binary|*.bin", FileName = string.Format("packet_{0}_0x{1:X6}.bin", i, p.Opcode) })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try { File.WriteAllBytes(dlg.FileName, pkt.Payload(p, int.MaxValue)); Say(dlg.FileName, Good); }
                catch (Exception ex) { Say(ex.Message, Bad); }
            }
        }
    }
}
