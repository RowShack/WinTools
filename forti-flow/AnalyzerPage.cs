using System.Text;
using FortiFlow.Core;

namespace FortiFlow;

/// <summary>Input tab (paste / open file) plus the analysis view (packet list + timeline) in one page.</summary>
public sealed class AnalyzerPage : UserControl
{
    sealed record Item(object Source, string Text, string Sub, Verdict Verdict);

    readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    readonly TabPage _inputTab = new("1. Paste or open");
    readonly TabPage _resultTab = new("2. Packets");

    // input tab
    readonly TextBox _input = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9.5f), AcceptsTab = false,
        PlaceholderText = "Paste the output of 'diagnose debug flow' here (SSH/CLI text, or the Time,Message CSV exported from the web GUI)…",
    };
    readonly Button _open = new() { Text = "Open .txt / .log / .csv…", AutoSize = true };
    readonly Button _analyze = new() { Text = "Analyze", AutoSize = true, Font = new Font("Segoe UI", 9f, FontStyle.Bold) };
    readonly Button _cancel = new() { Text = "Cancel", AutoSize = true, Enabled = false };
    readonly Button _clear = new() { Text = "Clear", AutoSize = true };
    readonly Button _rules = new() { Text = "Rules ▾", AutoSize = true };
    readonly Label _rulesInfo = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(8, 8, 0, 0) };
    readonly Label _status = new() { Dock = DockStyle.Bottom, AutoSize = false, Height = 22, ForeColor = SystemColors.GrayText, Padding = new Padding(2, 4, 0, 0) };

    // results tab
    readonly ComboBox _mode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100 };
    readonly TextBox _filter = new() { Width = 190, PlaceholderText = "ip, port, policy, verdict…" };
    readonly CheckBox _hideFast = new() { Text = "Hide fast-path / offloaded", AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    readonly CheckBox _collapse = new() { Text = "Collapse policy checks", AutoSize = true, Checked = true, Margin = new Padding(10, 6, 0, 0) };
    readonly Button _copy = new() { Text = "Copy selected", AutoSize = true };
    readonly Button _copyAll = new() { Text = "Copy all", AutoSize = true };
    readonly Button _export = new() { Text = "Export…", AutoSize = true };
    readonly Label _count = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(10, 8, 0, 0) };
    readonly ListBox _list = new()
    {
        Dock = DockStyle.Fill, DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 42, IntegralHeight = false, BorderStyle = BorderStyle.FixedSingle,
    };
    readonly TimelineView _timeline = new() { Dock = DockStyle.Fill };

    AnalysisResult? _result;
    RuleSet _ruleSet = RuleSet.LoadDefault();
    string? _rulesPath;
    string? _sourceText;       // set when a big file was loaded and is not shown in the text box
    CancellationTokenSource? _cts;
    List<Item> _items = new();
    bool _suppress;

    static string SettingsFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinTools", "forti-flow", "rules-path.txt");
    static string NextToExe => Path.Combine(AppContext.BaseDirectory, "forti-flow.rules.json");

    public event Action<string>? StatusChanged;

    public AnalyzerPage()
    {
        Dock = DockStyle.Fill;
        BuildInputTab();
        BuildResultTab();
        _tabs.TabPages.AddRange([_inputTab, _resultTab]);
        Controls.Add(_tabs);
        _mode.Items.AddRange(["Packets", "Sessions"]); _mode.SelectedIndex = 0;
        LoadRules(StartupRulesPath());
        _timeline.Clear("Nothing analysed yet. Paste output on the first tab and press Analyze.");
    }

    // ---------- layout ----------

    void BuildInputTab()
    {
        _inputTab.Padding = new Padding(8);
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        bar.Controls.AddRange([_open, _analyze, _cancel, _clear, new Label { Width = 16 }, _rules, _rulesInfo]);
        var hint = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 40, Padding = new Padding(2, 6, 0, 0), ForeColor = SystemColors.GrayText, Text = "Paste the output of 'diagnose debug flow' below (SSH/CLI text, or the Time,Message CSV exported from the FortiGate web GUI), then press Analyze (Ctrl+Enter). Nothing is sent anywhere; parsing happens on this PC." };
        _inputTab.Controls.Add(_input);
        _inputTab.Controls.Add(hint);
        _inputTab.Controls.Add(bar);
        _inputTab.Controls.Add(_status);
        _inputTab.Controls.SetChildIndex(_input, 0);
        _inputTab.Controls.SetChildIndex(hint, 1);

        _open.Click += async (_, _) => await OpenFile();
        _analyze.Click += async (_, _) => await Analyze();
        _cancel.Click += (_, _) => _cts?.Cancel();
        _clear.Click += (_, _) => { _input.Clear(); _sourceText = null; _result = null; Refill(); _status.Text = ""; };
        _input.TextChanged += (_, _) => { if (!_suppress) _sourceText = null; };
        _input.KeyDown += async (_, e) => { if (e.Control && e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await Analyze(); } };

        var menu = new ContextMenuStrip();
        menu.Items.Add("Choose rules file…", null, (_, _) => ChooseRules());
        menu.Items.Add("Reload rules", null, (_, _) => LoadRules(_rulesPath ?? StartupRulesPath(), reanalyse: true));
        menu.Items.Add("Use built-in rules only", null, (_, _) => { _rulesPath = null; SaveRulesPath(null); LoadRules(null, reanalyse: true); });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Save built-in rules as… (starting point for your own)", null, (_, _) => SaveDefaultRules());
        _rules.Click += (_, _) => menu.Show(_rules, new Point(0, _rules.Height));
    }

    void BuildResultTab()
    {
        _resultTab.Padding = new Padding(6);
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        top.Controls.AddRange([new Label { Text = "Show", AutoSize = true, Margin = new Padding(0, 8, 4, 0) }, _mode,
            new Label { Text = "Filter", AutoSize = true, Margin = new Padding(10, 8, 4, 0) }, _filter, _hideFast, _collapse,
            _copy, _copyAll, _export, _count]);

        var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1, SplitterWidth = 6 };
        split.Panel1.Controls.Add(_list);
        split.Panel2.Controls.Add(_timeline);
        split.HandleCreated += (_, _) => { split.Panel1MinSize = 220; split.SplitterDistance = 400; };

        _resultTab.Controls.Add(split);
        _resultTab.Controls.Add(top);
        _resultTab.Controls.SetChildIndex(split, 0);

        _list.DrawItem += DrawListItem;
        _list.SelectedIndexChanged += (_, _) => ShowSelected();
        _mode.SelectedIndexChanged += (_, _) => Refill();
        _filter.TextChanged += (_, _) => Refill();
        _hideFast.CheckedChanged += (_, _) => Refill();
        _collapse.CheckedChanged += (_, _) => { _timeline.CollapsePolicyChecks = _collapse.Checked; ShowSelected(); };
        _copy.Click += (_, _) => CopyText(SelectedPackets());
        _copyAll.Click += (_, _) => CopyText(ShownPackets());
        _export.Click += (_, _) => ExportShown();
    }

    // ---------- loading and analysing ----------

    async Task OpenFile()
    {
        using var dlg = new OpenFileDialog { Filter = "Debug flow output (*.txt;*.log;*.csv)|*.txt;*.log;*.csv|All files|*.*", Title = "Open debug flow output" };
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        try
        {
            var text = await File.ReadAllTextAsync(dlg.FileName);
            _suppress = true;
            if (text.Length <= 400_000) { _input.Text = text; _sourceText = null; }
            else { _input.Text = $"[{Path.GetFileName(dlg.FileName)} - {text.Length / 1024:N0} KB loaded. Not shown here to keep the window fast; press Analyze or Clear.]"; _sourceText = text; }
            _suppress = false;
            await Analyze();
        }
        catch (Exception ex) { _suppress = false; MessageBox.Show(FindForm(), ex.Message, "Could not open file", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    async Task Analyze()
    {
        var text = _sourceText ?? _input.Text;
        if (string.IsNullOrWhiteSpace(text)) { _status.Text = "Nothing to analyse - paste some output first."; return; }
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var cts = _cts;
        _analyze.Enabled = false; _cancel.Enabled = true; _open.Enabled = false;
        _status.Text = "Analysing…";
        try
        {
            var r = await FlowAnalyzer.AnalyzeAsync(text, _ruleSet, cts.Token);
            _result = r;
            Refill();
            var fmt = r.Format switch { InputFormat.GuiCsv => "web GUI CSV export", InputFormat.CliPrefixed => "CLI with id=/trace_id= prefixes", InputFormat.CliPlain => "plain CLI messages", _ => "unrecognised" };
            _status.Text = $"{r.Packets.Count} packets, {r.Sessions.Count} sessions · input: {fmt} · {r.IgnoredLines} noise lines ignored · {r.UnknownLines} unrecognised lines shown raw";
            if (r.Packets.Count == 0) _status.Text = "No packets found. Is this 'diagnose debug flow' output? (" + fmt + ")";
            else _tabs.SelectedTab = _resultTab;
            StatusChanged?.Invoke(_status.Text);
        }
        catch (OperationCanceledException) { _status.Text = "Analysis cancelled."; }
        catch (Exception ex) { _status.Text = "Error: " + ex.Message; }
        finally { _analyze.Enabled = true; _cancel.Enabled = false; _open.Enabled = true; }
    }

    // ---------- rules ----------

    static string? StartupRulesPath()
    {
        try
        {
            if (File.Exists(SettingsFile)) { var p = File.ReadAllText(SettingsFile).Trim(); if (p.Length > 0) return p; }
        }
        catch { }
        return File.Exists(NextToExe) ? NextToExe : null;
    }

    static void SaveRulesPath(string? p)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
            File.WriteAllText(SettingsFile, p ?? "");
        }
        catch { }
    }

    void ChooseRules()
    {
        using var dlg = new OpenFileDialog { Filter = "Rules file (*.json)|*.json|All files|*.*", Title = "Choose a FortiFlow rules file" };
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        _rulesPath = dlg.FileName;
        SaveRulesPath(_rulesPath);
        LoadRules(_rulesPath, reanalyse: true);
    }

    void LoadRules(string? path, bool reanalyse = false)
    {
        _rulesPath = path;
        _ruleSet = RuleSet.Load(path);
        var unv = _ruleSet.Rules.Count(r => !r.Verified);
        _rulesInfo.Text = $"Rules: {_ruleSet.Source} ({_ruleSet.Rules.Count} patterns, {unv} unverified)";
        if (_ruleSet.Messages.Count > 0)
        {
            _rulesInfo.ForeColor = Color.Firebrick;
            _rulesInfo.Text += "  ⚠ " + _ruleSet.Messages[0];
            if (IsHandleCreated || reanalyse)
                MessageBox.Show(FindForm(), string.Join(Environment.NewLine, _ruleSet.Messages), "Rules file problems", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        else _rulesInfo.ForeColor = SystemColors.GrayText;
        if (reanalyse && _result != null) _ = Analyze();
    }

    void SaveDefaultRules()
    {
        using var dlg = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = "forti-flow.rules.json", Title = "Save the built-in rules" };
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, RuleSet.GetEmbeddedJson(), new UTF8Encoding(false));
        _status.Text = "Saved built-in rules. Edit the copy, then Rules ▾ > Choose rules file…. Your file only needs the rules you add or change.";
    }

    // ---------- list ----------

    IEnumerable<PacketTrace> VisiblePackets(IEnumerable<PacketTrace> src)
    {
        var f = _filter.Text.Trim();
        foreach (var p in src)
        {
            if (_hideFast.Checked && p.IsOffloaded) continue;
            if (f.Length > 0 && !Matches(p, f)) continue;
            yield return p;
        }
    }

    static bool Matches(PacketTrace p, string f)
    {
        var cmp = StringComparison.OrdinalIgnoreCase;
        return p.Label.Contains(f, cmp) || Exporter.VerdictText(p.Verdict).Contains(f, cmp) || (p.SessionId?.Contains(f, cmp) ?? false)
            || p.Iface.Contains(f, cmp) || (p.Policy?.Contains(f, cmp) ?? false) || (p.Tunnel?.Contains(f, cmp) ?? false)
            || p.Steps.Any(s => s.Title.Contains(f, cmp) || s.Detail.Contains(f, cmp));
    }

    void Refill()
    {
        _items = new List<Item>();
        if (_result != null)
        {
            if (_mode.SelectedIndex == 1)
            {
                foreach (var s in _result.Sessions)
                {
                    var vis = VisiblePackets(s.Packets).ToList();
                    if (vis.Count == 0) continue;
                    _items.Add(new Item(s, s.Label, string.Join("  ", vis.Take(4).Select(p => $"#{p.Index} {(p.Direction == "reply" ? "reply" : "orig")}")) + (vis.Count > 4 ? " …" : ""), s.Verdict));
                }
            }
            else
            {
                foreach (var p in VisiblePackets(_result.Packets))
                    _items.Add(new Item(p, p.Label, p.Explanation.Length > 0 ? p.VerdictTitle + (p.UsesUnverifiedRule ? "  (unverified rule)" : "") : p.VerdictTitle, p.Verdict));
            }
        }
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var i in _items) _list.Items.Add(i);
        _list.EndUpdate();
        _count.Text = _result == null ? "" : $"{_items.Count} shown / {(_mode.SelectedIndex == 1 ? _result.Sessions.Count : _result.Packets.Count)}";
        if (_items.Count > 0) _list.SelectedIndex = 0; else ShowSelected();
    }

    void ShowSelected()
    {
        if (_list.SelectedItem is not Item it)
        {
            _timeline.Clear(_result == null ? "Nothing analysed yet. Paste output on the first tab and press Analyze." : "Nothing matches the current filter.");
            return;
        }
        if (it.Source is PacketTrace p) _timeline.ShowPacket(p);
        else if (it.Source is SessionGroup s) _timeline.ShowSession(s, x => VisiblePackets(new[] { x }).Any());
    }

    void DrawListItem(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0 || e.Index >= _list.Items.Count) return;
        var it = (Item)_list.Items[e.Index];
        var g = e.Graphics;
        bool sel = (e.State & DrawItemState.Selected) != 0;
        using (var back = new SolidBrush(sel ? SystemColors.Highlight : _list.BackColor)) g.FillRectangle(back, e.Bounds);
        var col = TimelineView.VerdictColor(it.Verdict);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var circle = new Rectangle(e.Bounds.X + 8, e.Bounds.Y + 9, 24, 24);
        using (var b = new SolidBrush(col)) g.FillEllipse(b, circle);
        var glyph = it.Verdict switch { Verdict.Forwarded => "✓", Verdict.Dropped => "✕", Verdict.LocalIn => "⌂", _ => "?" };
        using (var f = new Font("Segoe UI Symbol", 10f, FontStyle.Bold))
            TextRenderer.DrawText(g, glyph, f, circle, Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        var fore = sel ? SystemColors.HighlightText : SystemColors.WindowText;
        var sub = sel ? SystemColors.HighlightText : col;
        var r1 = new Rectangle(e.Bounds.X + 40, e.Bounds.Y + 3, e.Bounds.Width - 44, 18);
        var r2 = new Rectangle(e.Bounds.X + 40, e.Bounds.Y + 21, e.Bounds.Width - 44, 18);
        TextRenderer.DrawText(g, it.Text, e.Font, r1, fore, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.Left);
        using (var f2 = new Font(e.Font!, FontStyle.Regular))
            TextRenderer.DrawText(g, it.Sub, f2, r2, sub, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.Left);
        using (var pen = new Pen(Color.FromArgb(230, 230, 230))) g.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
    }

    // ---------- copy / export ----------

    List<PacketTrace> SelectedPackets()
    {
        if (_list.SelectedItem is not Item it) return new();
        return it.Source is PacketTrace p ? new() { p } : ((SessionGroup)it.Source).Packets.Where(x => VisiblePackets(new[] { x }).Any()).ToList();
    }

    List<PacketTrace> ShownPackets() =>
        _items.SelectMany(i => i.Source is PacketTrace p ? new[] { p } : ((SessionGroup)i.Source).Packets.ToArray()).Distinct().OrderBy(p => p.Index).ToList();

    void CopyText(List<PacketTrace> packets)
    {
        if (packets.Count == 0) { _count.Text = "nothing to copy"; return; }
        Clipboard.SetText(Exporter.ToText(packets));
        _count.Text = $"copied {packets.Count} packet(s)";
    }

    void ExportShown()
    {
        var packets = ShownPackets();
        if (packets.Count == 0) { _count.Text = "nothing to export"; return; }
        using var dlg = new SaveFileDialog
        {
            Filter = "Text summary (*.txt)|*.txt|CSV, one row per packet (*.csv)|*.csv|HTML report (*.html)|*.html",
            FileName = "forti-flow-report", Title = "Export the packets currently shown",
        };
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        var content = dlg.FilterIndex switch { 2 => Exporter.ToCsv(packets), 3 => Exporter.ToHtml(packets), _ => Exporter.ToText(packets) };
        try { File.WriteAllText(dlg.FileName, content, new UTF8Encoding(true)); _count.Text = $"exported {packets.Count} packet(s)"; }
        catch (Exception ex) { MessageBox.Show(FindForm(), ex.Message, "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    // used by the screenshot/test harness and by "open with" later
    public Task LoadTextAsync(string text, bool showResults = true)
    {
        _suppress = true; _input.Text = text.Length <= 400_000 ? text : ""; _sourceText = text.Length <= 400_000 ? null : text; _suppress = false;
        return Analyze();
    }

    public void SelectIndex(int i) { if (i >= 0 && i < _list.Items.Count) _list.SelectedIndex = i; }
    public int ListCount => _list.Items.Count;
    public void FindAndSelect(Func<PacketTrace, bool> pred)
    {
        for (int i = 0; i < _list.Items.Count; i++)
            if (((Item)_list.Items[i]).Source is PacketTrace p && pred(p)) { _list.SelectedIndex = i; return; }
    }
    public void ShowInputTab() => _tabs.SelectedTab = _inputTab;
    public void SetMode(int i) => _mode.SelectedIndex = i;
}
