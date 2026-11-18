using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using PktmonGui.Core;

namespace PktmonGui;

public sealed class MainForm : Form
{
    private static readonly Font Mono = new(FontFamily.GenericMonospace, 9f);
    private readonly ToolStripStatusLabel _status = new("Ready");
    private PktmonFeatures _features = PktmonFeatures.All;
    private List<CaptureComponent> _components = [];

    // ---- capture setup ----
    private readonly RadioButton _scopeNics = new() { Text = "All network adapters (NIC level, recommended)", AutoSize = true, Checked = true };
    private readonly RadioButton _scopeSel = new() { Text = "Only the adapters ticked below", AutoSize = true };
    private readonly RadioButton _scopeAll = new() { Text = "All components (can show the same packet several times)", AutoSize = true };
    private readonly CheckedListBox _adapters = new() { Height = 90, Width = 540, CheckOnClick = true, IntegralHeight = false, Enabled = false };
    private readonly DataGridView _filters = new()
    {
        Height = 170, Width = 540, AllowUserToResizeRows = false, RowHeadersVisible = false, BackgroundColor = SystemColors.Window,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, EditMode = DataGridViewEditMode.EditOnEnter, AllowUserToAddRows = true,
    };
    private readonly ComboBox _preset = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
    private readonly NumericUpDown _pktSize = new() { Minimum = 0, Maximum = 65535, Value = 0, Width = 70 };
    private readonly CheckBox _fullPackets = new() { Text = "Full packets", AutoSize = true, Checked = true };
    private readonly ComboBox _type = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
    private readonly ComboBox _logMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130 };
    private readonly NumericUpDown _fileMb = new() { Minimum = 1, Maximum = 100000, Value = 512, Width = 80 };
    private readonly TextBox _folder = new() { Width = 340, Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PktmonCaptures") };
    private readonly CheckBox _txt = new() { Text = "Also write a text version (etl2txt)", AutoSize = true };
    private readonly TextBox _commands = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Mono, BackColor = SystemColors.Window };

    // ---- run ----
    private readonly Button _start = new() { Text = "Start capture", Width = 130, Height = 34 };
    private readonly Button _stop = new() { Text = "Stop", Width = 90, Height = 34, Enabled = false };
    private readonly Label _elapsed = new() { Text = "00:00:00", AutoSize = true, Font = new Font("Segoe UI", 14f, FontStyle.Bold), Margin = new Padding(14, 4, 14, 0) };
    private readonly Label _counters = new() { Text = "Packets: –   Drops: –", AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
    private readonly Button _openFolder = new() { Text = "Open folder", AutoSize = true, Enabled = false };
    private readonly Button _openWireshark = new() { Text = "Open in Wireshark", AutoSize = true, Enabled = false };
    private readonly Button _remote = new() { Text = "Remote script…", AutoSize = true };
    private readonly TextBox _log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = Mono, BackColor = SystemColors.Window };
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    private readonly System.Windows.Forms.Timer _debounce = new() { Interval = 250 };
    private DateTime _startedAt;
    private bool _running, _busy;
    private string? _lastDir, _lastEtl, _lastPcap;

    // ---- drops tab ----
    private readonly Button _dropsLoad = new() { Text = "Analyse last capture", AutoSize = true, Enabled = false };
    private readonly Button _dropsOpen = new() { Text = "Open .etl file…", AutoSize = true };
    private readonly DataGridView _dropGroups = Grid();
    private readonly DataGridView _dropRows = Grid();
    private List<DropEntry> _drops = [];
    private readonly PacketsPage _packets = new();

    private static DataGridView Grid() => new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, BackgroundColor = SystemColors.Window,
    };

    public MainForm()
    {
        Text = "Pktmon GUI";
        Size = new Size(1200, 860);
        MinimumSize = new Size(1000, 700);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.AddRange([BuildCaptureTab(), _packets, BuildDropsTab()]);
        _packets.StatusChanged += t => _status.Text = t;
        _packets.LiveComponents = () => _components;
        var bar = new StatusStrip(); bar.Items.Add(_status);
        Controls.Add(tabs); Controls.Add(bar);

        if (!PktmonCli.IsAdmin())
            Controls.Add(new Label { Dock = DockStyle.Top, Height = 28, Text = "  Not running as administrator: pktmon will refuse to work. Restart this tool as administrator.", BackColor = Color.FromArgb(255, 244, 206) });

        _type.Items.AddRange(["All packets", "Flow only", "Drops only"]); _type.SelectedIndex = 0;
        _logMode.Items.AddRange(["Circular", "Multi-file"]); _logMode.SelectedIndex = 0;
        _preset.Items.Add("Add preset…"); _preset.Items.AddRange(FilterSpec.Presets.Names); _preset.SelectedIndex = 0;

        _scopeSel.CheckedChanged += (_, _) => { _adapters.Enabled = _scopeSel.Checked; Changed(); };
        _scopeNics.CheckedChanged += (_, _) => Changed(); _scopeAll.CheckedChanged += (_, _) => Changed();
        _fullPackets.CheckedChanged += (_, _) => { _pktSize.Enabled = !_fullPackets.Checked; Changed(); };
        _pktSize.Enabled = false;
        foreach (var c in new Control[] { _pktSize, _type, _logMode, _fileMb, _folder, _txt, _adapters }) { if (c is ComboBox cb) cb.SelectedIndexChanged += (_, _) => Changed(); else if (c is NumericUpDown n) n.ValueChanged += (_, _) => Changed(); else if (c is TextBox t) t.TextChanged += (_, _) => Changed(); else if (c is CheckBox k) k.CheckedChanged += (_, _) => Changed(); else if (c is CheckedListBox l) l.ItemCheck += (_, _) => BeginInvoke(Changed); }
        BuildFilterColumns();
        _filters.CellValueChanged += (_, _) => Changed();
        _filters.RowsRemoved += (_, _) => Changed();
        _filters.CurrentCellDirtyStateChanged += (_, _) => { if (_filters.IsCurrentCellDirty) _filters.CommitEdit(DataGridViewDataErrorContexts.Commit); };
        _preset.SelectedIndexChanged += (_, _) => AddPreset();
        _debounce.Tick += (_, _) => { _debounce.Stop(); UpdateCommands(); };
        _tick.Tick += async (_, _) => await OnTickAsync();
        _start.Click += async (_, _) => await StartAsync();
        _stop.Click += async (_, _) => await StopAsync();
        _openFolder.Click += (_, _) => { if (_lastDir != null) Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_lastDir}\"") { UseShellExecute = true }); };
        _openWireshark.Click += (_, _) => OpenWireshark();
        _remote.Click += (_, _) => ShowRemoteScript();
        _dropsLoad.Click += async (_, _) => await AnalyseDropsAsync(_lastEtl);
        _dropsOpen.Click += async (_, _) => { using var d = new OpenFileDialog { Filter = "pktmon logs|*.etl|All files|*.*" }; if (d.ShowDialog(this) == DialogResult.OK) await AnalyseDropsAsync(d.FileName); };
        _dropGroups.SelectionChanged += (_, _) => ShowDropDetails();
        FormClosing += (_, _) => Cleanup();
        SystemEvents.SessionEnding += (_, _) => Cleanup();
        Shown += async (_, _) => await OnShownAsync();
        UpdateCommands();
    }

    // ================= layout =================

    private TabPage BuildCaptureTab()
    {
        var page = new TabPage("Capture") { Padding = new Padding(8) };
        var left = new FlowLayoutPanel { Dock = DockStyle.Left, Width = 580, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };

        left.Controls.Add(Box("1. Capture on", Stack(_scopeNics, _scopeSel, _adapters, _scopeAll)));
        var fh = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        fh.Controls.AddRange([new Label { Text = "Presets:", AutoSize = true, Margin = new Padding(0, 6, 4, 0) }, _preset,
            Btn("Remove selected", () => { foreach (DataGridViewRow r in _filters.SelectedRows) if (!r.IsNewRow) _filters.Rows.Remove(r); }),
            Btn("Clear", () => { _filters.Rows.Clear(); Changed(); })]);
        left.Controls.Add(Box("2. Filters (ALL fields of ANY row; none = capture all)", Stack(fh, _filters)));

        var opt = new TableLayoutPanel { AutoSize = true, ColumnCount = 2 };
        void Row(string l, Control c) { opt.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 6) }); opt.Controls.Add(c); }
        Row("Packet size:", Flow(_fullPackets, new Label { Text = "or bytes:", AutoSize = true, Margin = new Padding(8, 6, 4, 0) }, _pktSize));
        Row("Capture:", _type);
        Row("Log:", Flow(_logMode, new Label { Text = "max MB:", AutoSize = true, Margin = new Padding(8, 6, 4, 0) }, _fileMb));
        Row("Save to:", Flow(_folder, Btn("…", () => { using var d = new FolderBrowserDialog { SelectedPath = _folder.Text }; if (d.ShowDialog(this) == DialogResult.OK) _folder.Text = d.SelectedPath; })));
        opt.Controls.Add(new Label()); opt.Controls.Add(_txt);
        left.Controls.Add(Box("3. Options", opt));

        var run = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        run.Controls.AddRange([_start, _stop, _elapsed, _counters]);
        var after = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 0) };
        after.Controls.AddRange([_openFolder, _openWireshark, _remote]);

        var cmdBox = new GroupBox { Text = "Commands this run will execute (read-only — handy for learning pktmon)", Dock = DockStyle.Top, Height = 230, Padding = new Padding(6) };
        cmdBox.Controls.Add(_commands);
        var logBox = new GroupBox { Text = "Log", Dock = DockStyle.Fill, Padding = new Padding(6) };
        logBox.Controls.Add(_log);
        var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 0, 0, 0) };
        right.Controls.Add(logBox);
        var runPanel = new Panel { Dock = DockStyle.Top, Height = 92 };
        runPanel.Controls.Add(after); after.Location = new Point(0, 48);
        runPanel.Controls.Add(run);
        right.Controls.Add(runPanel);
        right.Controls.Add(cmdBox);
        right.Controls.SetChildIndex(cmdBox, 1); right.Controls.SetChildIndex(runPanel, 0);
        page.Controls.Add(right); page.Controls.Add(left);
        return page;
    }

    private TabPage BuildDropsTab()
    {
        var page = new TabPage("Drops") { Padding = new Padding(8) };
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false };
        top.Controls.AddRange([_dropsLoad, _dropsOpen, new Label { Text = "Reads the capture with etl2txt and groups dropped packets by reason and component.", AutoSize = true, Margin = new Padding(12, 8, 0, 0), ForeColor = SystemColors.GrayText }]);
        _dropGroups.Columns.Add("reason", "Drop reason"); _dropGroups.Columns.Add("comp", "Component id"); _dropGroups.Columns.Add("count", "Packets");
        _dropRows.Columns.Add("time", "Time"); _dropRows.Columns.Add("comp", "Component"); _dropRows.Columns.Add("reason", "Reason"); _dropRows.Columns.Add("raw", "Raw line");
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 240 };
        split.Panel1.Controls.Add(Box("Grouped by reason", _dropGroups, DockStyle.Fill));
        split.Panel2.Controls.Add(Box("Dropped packets for the selected group", _dropRows, DockStyle.Fill));
        page.Controls.Add(split); page.Controls.Add(top);
        return page;
    }

    private static GroupBox Box(string title, Control c, DockStyle dock = DockStyle.None)
    {
        var g = new GroupBox { Text = title, AutoSize = dock == DockStyle.None, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(8), Margin = new Padding(0, 0, 0, 8), Dock = dock };
        if (dock == DockStyle.None) g.MinimumSize = new Size(560, 0);
        g.Controls.Add(c); c.Dock = dock == DockStyle.None ? DockStyle.Top : DockStyle.Fill;
        return g;
    }

    private static Control Stack(params Control[] cs)
    {
        var f = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true };
        f.Controls.AddRange(cs);
        return f;
    }

    private static Control Flow(params Control[] cs) { var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false }; f.Controls.AddRange(cs); return f; }
    private static Button Btn(string t, Action a) { var b = new Button { Text = t, AutoSize = true }; b.Click += (_, _) => a(); return b; }

    private void BuildFilterColumns()
    {
        _filters.Columns.Add("name", "Name");
        _filters.Columns.Add(Combo("proto", "Protocol", FilterSpec.Protocols));
        _filters.Columns.Add("ip1", "IP / CIDR 1"); _filters.Columns.Add("ip2", "IP 2");
        _filters.Columns.Add("p1", "Port 1"); _filters.Columns.Add("p2", "Port 2");
        _filters.Columns.Add("mac1", "MAC 1"); _filters.Columns.Add("mac2", "MAC 2");
        _filters.Columns.Add("vlan", "VLAN");
        _filters.Columns.Add(Combo("dl", "Data link", FilterSpec.DataLinks));
    }

    private static DataGridViewComboBoxColumn Combo(string name, string header, string[] items)
    {
        var c = new DataGridViewComboBoxColumn { Name = name, HeaderText = header, FlatStyle = FlatStyle.Flat };
        c.Items.AddRange(items);
        return c;
    }

    // ================= model =================

    private List<FilterSpec> ReadFilters()
    {
        var list = new List<FilterSpec>();
        foreach (DataGridViewRow r in _filters.Rows)
        {
            if (r.IsNewRow) continue;
            string C(string n) => r.Cells[n].Value?.ToString()?.Trim() ?? "";
            var f = new FilterSpec
            {
                Name = C("name"), Protocol = C("proto") is { Length: > 0 } p ? p : "Any", Ip1 = C("ip1"), Ip2 = C("ip2"), Port1 = C("p1"), Port2 = C("p2"),
                Mac1 = C("mac1"), Mac2 = C("mac2"), Vlan = C("vlan"), DataLink = C("dl") is { Length: > 0 } d ? d : "Any",
            };
            if (!f.IsEmpty || f.Name.Length > 0) list.Add(f);
        }
        return list;
    }

    private CaptureOptions ReadOptions(string etlPath) => new()
    {
        AllComponents = _scopeAll.Checked,
        ComponentIds = _scopeSel.Checked ? _adapters.CheckedItems.OfType<CaptureComponent>().Select(c => c.Id).ToList() : [],
        Type = (CaptureType)_type.SelectedIndex,
        PacketSize = _fullPackets.Checked ? 0 : (int)_pktSize.Value,
        LogMode = _logMode.SelectedIndex == 1 ? LogMode.MultiFile : LogMode.Circular,
        FileSizeMb = (int)_fileMb.Value,
        EtlPath = etlPath,
        ConvertToText = _txt.Checked,
    };

    private void Changed() { _debounce.Stop(); _debounce.Start(); }

    private void UpdateCommands()
    {
        try
        {
            var o = ReadOptions(Path.Combine(_folder.Text, "capture-<time>", "capture.etl"));
            _commands.Text = string.Join(Environment.NewLine, CommandBuilder.Preview(o, ReadFilters(), _features));
        }
        catch (ArgumentException ex) { _commands.Text = "(fix this to see the commands)\r\n" + ex.Message; }
    }

    private void AddPreset()
    {
        if (_preset.SelectedIndex <= 0) return;
        string name = (string)_preset.SelectedItem!;
        string? host = null;
        if (name.StartsWith("HTTPS"))
        {
            host = Ask("HTTPS to one host", "IP address of the host (or a CIDR range):");
            if (string.IsNullOrWhiteSpace(host)) { _preset.SelectedIndex = 0; return; }
        }
        foreach (var f in FilterSpec.Presets.Get(name, host?.Trim()))
            _filters.Rows.Add(f.Name, f.Protocol, f.Ip1, f.Ip2, f.Port1, f.Port2, f.Mac1, f.Mac2, f.Vlan, f.DataLink);
        _preset.SelectedIndex = 0;
        Changed();
    }

    // ================= startup / cleanup =================

    private async Task OnShownAsync()
    {
        if (!PktmonCli.Exists) { Log("pktmon.exe was not found. This tool needs Windows 10 1809 or later."); _start.Enabled = false; return; }
        try
        {
            _features = await PktmonCli.DetectFeaturesAsync();
            Log($"pktmon found. Supports: pcapng conversion {(_features.Etl2Pcap ? "yes" : "NO")}, packet size {(_features.PktSize ? "yes" : "no")}, component selection {(_features.CompSelector ? "yes" : "no")}, log modes {(_features.LogMode ? "yes" : "no")}.");
            if (!_features.Etl2Pcap) Log("This Windows build can't convert to pcapng; you'll get an .etl file (and the text version if ticked).");
            if (PktmonCli.IsAdmin())
            {
                var (running, filters, status) = await PktmonCli.CheckLeftoversAsync();
                if (running || filters)
                {
                    var a = MessageBox.Show(this, "A pktmon capture or filters from an earlier session appear to still be active:\n\n" + Truncate(status, 400) + "\n\nStop it and clear the filters now?", "Leftover capture", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                    if (a == DialogResult.Yes) { await PktmonCli.CleanupAsync(); Log("Stopped the leftover capture and cleared filters."); }
                }
                await LoadComponentsAsync();
            }
        }
        catch (Exception ex) { Log("Startup check failed: " + ex.Message); }
        UpdateCommands();
    }

    private async Task LoadComponentsAsync()
    {
        var r = _features.Json ? await PktmonCli.RunAsync("list --json") : await PktmonCli.RunAsync("list");
        if (!r.Ok && _features.Json) r = await PktmonCli.RunAsync("list");
        _components = Parsers.ParseComponents(r.Output);
        var nics = _components.Where(c => c.Type.Contains("adapter", StringComparison.OrdinalIgnoreCase) || c.Type.Contains("nic", StringComparison.OrdinalIgnoreCase) || c.Type.Length == 0).ToList();
        _adapters.Items.Clear();
        foreach (var c in nics) _adapters.Items.Add(c);
        Log($"{nics.Count} network adapter component(s) found.");
    }

    private void Cleanup()
    {
        _tick.Stop();
        if (_running || _prepared) { PktmonCli.CleanupBlocking(); _running = false; _prepared = false; }
    }

    private bool _prepared;

    // ================= capture =================

    private async Task StartAsync()
    {
        if (_running || _busy) return;
        var filters = ReadFilters();
        for (int i = 0; i < filters.Count; i++)
            if (filters[i].Validate() is { } err) { MessageBox.Show(this, $"Filter row {i + 1}: {err}", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        if (filters.Count > FilterSpec.MaxFilters) { MessageBox.Show(this, $"pktmon supports at most {FilterSpec.MaxFilters} filters.", Text); return; }
        if (_scopeSel.Checked && _adapters.CheckedItems.Count == 0) { MessageBox.Show(this, "Tick at least one adapter, or choose 'All network adapters'.", Text); return; }

        _lastDir = Path.Combine(_folder.Text, $"capture-{DateTime.Now:yyyyMMdd-HHmmss}");
        try { Directory.CreateDirectory(_lastDir); } catch (Exception ex) { MessageBox.Show(this, "Can't create the output folder: " + ex.Message, Text); return; }
        _lastEtl = Path.Combine(_lastDir, "capture.etl");
        try { ComponentNames.Save(_lastDir, _components); } catch { /* names are a convenience; never block a capture */ }
        var opt = ReadOptions(_lastEtl);

        SetBusy(true);
        _log.Clear();
        _prepared = true;
        try
        {
            if (!await Exec("filter remove", true)) throw new InvalidOperationException("Could not clear filters.");
            for (int i = 0; i < filters.Count; i++)
                if (!await Exec(filters[i].ToArguments(i), true)) throw new InvalidOperationException("A filter was rejected by pktmon.");
            string args = CommandBuilder.StartArguments(opt, _features, out var skipped);
            foreach (var s in skipped) Log("Note: this pktmon build doesn't support " + s);
            if (!await Exec(args, true)) throw new InvalidOperationException("pktmon refused to start the capture.");
            _running = true; _startedAt = DateTime.Now; _tick.Start();
            _start.Enabled = false; _stop.Enabled = true; _openFolder.Enabled = _openWireshark.Enabled = false; _dropsLoad.Enabled = false;
            _status.Text = "Capturing…";
        }
        catch (Exception ex)
        {
            Log("ERROR: " + ex.Message + " — cleaning up.");
            await PktmonCli.CleanupAsync(); _prepared = false;
            MessageBox.Show(this, ex.Message + "\n\nSee the log for pktmon's message.", "Couldn't start", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally { SetBusy(false); }
    }

    private async Task StopAsync()
    {
        if (!_running || _busy) return;
        SetBusy(true);
        _tick.Stop();
        try
        {
            await Exec("stop", true);
            _running = false;
            await Exec("filter remove", true);
            _prepared = false;
            string pcap = Path.ChangeExtension(_lastEtl!, ".pcapng");
            if (_features.Etl2Pcap)
            {
                Log("Converting to pcapng… (this can take a while for big captures)");
                if (await Exec(CommandBuilder.Etl2PcapArguments(_lastEtl!, pcap), true) && File.Exists(pcap)) _lastPcap = pcap;
            }
            if (_txt.Checked) await Exec(CommandBuilder.Etl2TxtArguments(_lastEtl!, Path.ChangeExtension(_lastEtl!, ".txt")), true);
            Log($"Done. Files are in {_lastDir}");
            _openFolder.Enabled = true; _openWireshark.Enabled = _lastPcap != null && FindWireshark() != null; _dropsLoad.Enabled = true;
            _packets.SetLastCapture(_lastEtl!);
            _status.Text = "Capture saved";
        }
        finally
        {
            _start.Enabled = true; _stop.Enabled = false; SetBusy(false);
        }
    }

    private async Task OnTickAsync()
    {
        _elapsed.Text = (DateTime.Now - _startedAt).ToString(@"hh\:mm\:ss");
        if (_busy) return;
        try
        {
            var r = await PktmonCli.RunAsync("counters");
            var (p, d) = Parsers.ParseCounterTotals(r.Output);
            _counters.Text = $"Packets: {p:N0}   Drops: {d:N0}";
        }
        catch { /* counters are informational */ }
    }

    private async Task<bool> Exec(string args, bool log)
    {
        if (log) Log("> pktmon " + args);
        var r = await PktmonCli.RunAsync(args);
        if (log && r.Combined.Length > 0) Log(Truncate(r.Combined, 1500));
        if (!r.Ok) Log($"(pktmon exit code {r.ExitCode})");
        return r.Ok;
    }

    private void SetBusy(bool busy) { _busy = busy; UseWaitCursor = busy; if (busy) { _start.Enabled = false; } else if (!_running) _start.Enabled = true; }

    // ================= extras =================

    private static string? FindWireshark()
    {
        foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var p = Path.Combine(root, "Wireshark", "Wireshark.exe");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    private void OpenWireshark()
    {
        var w = FindWireshark();
        if (w == null || _lastPcap == null) return;
        Process.Start(new ProcessStartInfo(w, $"\"{_lastPcap}\"") { UseShellExecute = true });
    }

    private void ShowRemoteScript()
    {
        var filters = ReadFilters();
        foreach (var f in filters) if (f.Validate() is { } err) { MessageBox.Show(this, err, Text); return; }
        var o = ReadOptions("$etl");
        string script = CommandBuilder.RemoteScript(o, filters, _features, 60);
        using var f2 = new Form { Text = "Remote capture script", Size = new Size(820, 520), StartPosition = FormStartPosition.CenterParent, Font = Font };
        var tb = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Mono, Text = script.Replace("\n", Environment.NewLine), ReadOnly = true };
        var copy = new Button { Text = "Copy to clipboard", Dock = DockStyle.Bottom, Height = 34 };
        copy.Click += (_, _) => { Clipboard.SetText(tb.Text); copy.Text = "Copied"; };
        f2.Controls.Add(tb); f2.Controls.Add(copy);
        f2.ShowDialog(this);
    }

    private async Task AnalyseDropsAsync(string? etl)
    {
        if (etl == null || !File.Exists(etl)) { MessageBox.Show(this, "No capture file to analyse yet.", Text); return; }
        UseWaitCursor = true;
        try
        {
            string tmp = Path.Combine(Path.GetTempPath(), "pktmon-drops-" + Guid.NewGuid().ToString("N") + ".txt");
            var r = await PktmonCli.RunAsync(CommandBuilder.Etl2TxtArguments(etl, tmp));
            if (!r.Ok || !File.Exists(tmp)) { MessageBox.Show(this, "etl2txt failed:\n" + Truncate(r.Combined, 500), Text); return; }
            _drops = DropParser.Parse(await File.ReadAllTextAsync(tmp));
            File.Delete(tmp);
            _dropGroups.Rows.Clear(); _dropRows.Rows.Clear();
            foreach (var (reason, comp, count) in DropParser.Group(_drops)) _dropGroups.Rows.Add(reason, comp < 0 ? "?" : comp.ToString(), count);
            _status.Text = $"{_drops.Count} dropped packets in {_dropGroups.Rows.Count} group(s)";
            if (_drops.Count == 0) MessageBox.Show(this, "No dropped packets found in this capture (or this pktmon build formats drop lines differently — check the .txt export).", Text);
        }
        finally { UseWaitCursor = false; }
    }

    private void ShowDropDetails()
    {
        _dropRows.Rows.Clear();
        if (_dropGroups.CurrentRow == null) return;
        string reason = _dropGroups.CurrentRow.Cells[0].Value?.ToString() ?? "";
        string comp = _dropGroups.CurrentRow.Cells[1].Value?.ToString() ?? "";
        foreach (var d in _drops.Where(d => d.Reason == reason && (d.Component?.ToString() ?? "?") == comp).Take(2000))
            _dropRows.Rows.Add(d.Time, d.Component, d.Reason, d.Raw);
    }

    private void Log(string s) => _log.AppendText(s + Environment.NewLine);
    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private string? Ask(string title, string label)
    {
        using var f = new Form { Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, MaximizeBox = false, MinimizeBox = false, ClientSize = new Size(380, 110), Font = Font };
        var lbl = new Label { Text = label, Left = 12, Top = 10, Width = 356 };
        var tb = new TextBox { Left = 12, Top = 38, Width = 356 };
        var ok = new Button { Text = "OK", Left = 208, Top = 72, Width = 76, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", Left = 292, Top = 72, Width = 76, DialogResult = DialogResult.Cancel };
        f.Controls.AddRange([lbl, tb, ok, cancel]); f.AcceptButton = ok; f.CancelButton = cancel;
        return f.ShowDialog(this) == DialogResult.OK ? tb.Text : null;
    }
}
