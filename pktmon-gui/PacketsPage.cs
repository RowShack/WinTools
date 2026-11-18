using PktmonGui.Core;

namespace PktmonGui;

/// <summary>Packets tab: opens a pktmon .etl capture in-app (via etl2txt), with filtering, a detail pane, copy and CSV export.</summary>
public sealed class PacketsPage : TabPage
{
    private readonly Button _openLast = new() { Text = "Open last capture", AutoSize = true, Enabled = false };
    private readonly Button _open = new() { Text = "Open .etl file…", AutoSize = true };
    private readonly Button _cancel = new() { Text = "Cancel", AutoSize = true, Enabled = false };
    private readonly TextBox _filter = new() { Width = 260, PlaceholderText = "filter: ip, port, protocol, text… (\"drop\" = drops only)" };
    private readonly ComboBox _dir = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
    private readonly ComboBox _comp = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
    private readonly CheckBox _hideAck = new() { Text = "Hide plain ACKs", AutoSize = true, Margin = new Padding(12, 6, 0, 0) };
    private readonly Label _count = new() { AutoSize = true, Margin = new Padding(12, 8, 0, 0), ForeColor = SystemColors.GrayText };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false, VirtualMode = true,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = true, BackgroundColor = SystemColors.Window,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None, ClipboardCopyMode = DataGridViewClipboardCopyMode.Disable,
    };
    private readonly TextBox _detail = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9f), BackColor = SystemColors.Window };
    private List<PacketRow> _all = [];
    private List<PacketRow> _view = [];
    private CancellationTokenSource? _cts;
    private string? _lastEtl;

    public event Action<string>? StatusChanged;

    public PacketsPage() : base("Packets")
    {
        Padding = new Padding(8);
        _dir.Items.AddRange(["All", "Rx", "Tx"]); _dir.SelectedIndex = 0;
        _comp.Items.Add("All"); _comp.SelectedIndex = 0;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        var export = new Button { Text = "Export CSV…", AutoSize = true };
        var copy = new Button { Text = "Copy rows", AutoSize = true };
        top.Controls.AddRange([_openLast, _open, _cancel, new Label { Text = "Filter", AutoSize = true, Margin = new Padding(16, 8, 4, 0) }, _filter,
            new Label { Text = "Dir", AutoSize = true, Margin = new Padding(8, 8, 4, 0) }, _dir,
            new Label { Text = "Component", AutoSize = true, Margin = new Padding(8, 8, 4, 0) }, _comp, _hideAck, export, copy, _count]);
        var legend = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 4, 0, 4) };
        foreach (var (cat, text) in new[] { (PacketCategory.TcpSyn, "TCP connect"), (PacketCategory.TcpData, "TCP data"), (PacketCategory.TcpAck, "TCP ACK"), (PacketCategory.TcpFin, "TCP close"),
                     (PacketCategory.TcpReset, "TCP reset"), (PacketCategory.Dns, "DNS"), (PacketCategory.Udp, "UDP"), (PacketCategory.Arp, "ARP"), (PacketCategory.Icmp, "ICMP / ping"), (PacketCategory.Drop, "Dropped") })
            legend.Controls.Add(new Label { Text = text, AutoSize = true, Padding = new Padding(6, 2, 6, 2), Margin = new Padding(0, 0, 6, 0), BackColor = Back(cat), ForeColor = Fore(cat), BorderStyle = BorderStyle.FixedSingle });

        foreach (var (name, head, w) in new[] { ("no", "#", 50), ("time", "Time", 100), ("dir", "Dir", 55), ("comp", "Comp", 45), ("size", "Bytes", 55),
                     ("src", "From", 175), ("dst", "To", 215), ("proto", "Proto", 55), ("sum", "What it is", 330), ("info", "Technical details", 520) })
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = name, HeaderText = head, Width = w, SortMode = DataGridViewColumnSortMode.NotSortable });
        _grid.Columns["size"]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 420 };
        split.Panel1.Controls.Add(_grid);
        var box = new GroupBox { Text = "Selected packet", Dock = DockStyle.Fill, Padding = new Padding(6) };
        box.Controls.Add(_detail);
        split.Panel2.Controls.Add(box);
        Controls.Add(split); Controls.Add(legend); Controls.Add(top);

        _grid.CellValueNeeded += (_, e) =>
        {
            if (e.RowIndex >= _view.Count) return;
            var r = _view[e.RowIndex];
            e.Value = _grid.Columns[e.ColumnIndex].Name switch
            {
                "no" => r.Index, "time" => r.Time.Length > 11 ? r.Time[11..^6] : r.Time, "dir" => r.Direction == "Tx" ? "▲ Tx" : r.Direction == "Rx" ? "▼ Rx" : r.Direction,
                "comp" => r.Component, "size" => r.Size, "src" => Humanize.Endpoint(r.Source), "dst" => Humanize.Endpoint(r.Destination), "proto" => r.Protocol,
                "sum" => r.Summary, _ => r.Info,
            };
        };
        _grid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || e.RowIndex >= _view.Count) return;
            var r = _view[e.RowIndex];
            e.CellStyle!.BackColor = Back(r.Category); e.CellStyle.ForeColor = Fore(r.Category);
            e.CellStyle.SelectionBackColor = ControlPaint.Dark(Back(r.Category), 0.15f); e.CellStyle.SelectionForeColor = Color.White;
            string col = _grid.Columns[e.ColumnIndex].Name;
            if (col == "dir") e.CellStyle.ForeColor = r.Direction == "Tx" ? Color.DarkGreen : Color.DarkBlue;
            if (col == "sum") e.CellStyle.Font = new Font(_grid.Font, FontStyle.Bold);
            if (col == "info") e.CellStyle.ForeColor = Color.DimGray;
        };
        _grid.SelectionChanged += (_, _) =>
        {
            int i = _grid.CurrentRow?.Index ?? -1;
            _detail.Text = i >= 0 && i < _view.Count ? Describe(_view[i]) : "";
        };
        _filter.TextChanged += (_, _) => ApplyFilter();
        _dir.SelectedIndexChanged += (_, _) => ApplyFilter();
        _comp.SelectedIndexChanged += (_, _) => ApplyFilter();
        _hideAck.CheckedChanged += (_, _) => ApplyFilter();
        _openLast.Click += async (_, _) => await LoadAsync(_lastEtl);
        _open.Click += async (_, _) =>
        {
            using var d = new OpenFileDialog { Filter = "pktmon logs|*.etl|All files|*.*" };
            if (d.ShowDialog(FindForm()) == DialogResult.OK) await LoadAsync(d.FileName);
        };
        _cancel.Click += (_, _) => _cts?.Cancel();
        export.Click += (_, _) => Export();
        copy.Click += (_, _) => CopyRows();
    }

    /// <summary>Tell the tab which capture is the latest one so "Open last capture" works.</summary>
    public void SetLastCapture(string etl) { _lastEtl = etl; _openLast.Enabled = true; }

    public async Task LoadAsync(string? etl)
    {
        if (etl == null || !File.Exists(etl)) { MessageBox.Show(FindForm(), "No capture file to open yet.", "Packets"); return; }
        _cts?.Cancel(); _cts = new CancellationTokenSource(); var ct = _cts.Token;
        _open.Enabled = _openLast.Enabled = false; _cancel.Enabled = true; _count.Text = "Converting…";
        string tmp = Path.Combine(Path.GetTempPath(), "pktmon-view-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var r = await PktmonCli.RunAsync(CommandBuilder.Etl2TxtArguments(etl, tmp), ct);
            if (!r.Ok || !File.Exists(tmp)) { MessageBox.Show(FindForm(), "etl2txt failed:\n" + r.Combined, "Packets"); _count.Text = ""; return; }
            _count.Text = "Parsing…";
            string text = await File.ReadAllTextAsync(tmp, ct);   // etl2txt writes UTF-16 with a BOM; this detects it
            _all = await Task.Run(() => PacketParser.Parse(text), ct);
            _comp.Items.Clear(); _comp.Items.Add("All");
            foreach (var c in _all.Select(p => p.Component).Distinct().Order()) _comp.Items.Add(c.ToString());
            _comp.SelectedIndex = 0;
            ApplyFilter();
            StatusChanged?.Invoke($"{_all.Count} packet events in {Path.GetFileName(etl)}");
            if (_all.Count == 0) MessageBox.Show(FindForm(), "No packet events were found. Was the capture empty, or does this pktmon build format lines differently? Try the \"Also write a text version\" option and look at the .txt.", "Packets");
        }
        catch (OperationCanceledException) { _count.Text = "cancelled"; }
        finally
        {
            try { File.Delete(tmp); } catch { }
            _open.Enabled = true; _openLast.Enabled = _lastEtl != null; _cancel.Enabled = false;
        }
    }

    private void ApplyFilter()
    {
        string f = _filter.Text;
        string dir = _dir.SelectedItem as string ?? "All";
        string comp = _comp.SelectedItem as string ?? "All";
        _view = _all.Where(p => (dir == "All" || p.Direction == dir) && (comp == "All" || p.Component.ToString() == comp) && p.Matches(f) && !(_hideAck.Checked && p.Category == PacketCategory.TcpAck)).ToList();
        _grid.RowCount = 0; _grid.RowCount = _view.Count;
        int drops = _view.Count(p => p.IsDrop);
        _count.Text = $"{_view.Count} of {_all.Count} packet events" + (drops > 0 ? $" ({drops} drops)" : "");
    }

    // Soft row colours so the kind of traffic stands out at a glance; the legend above the grid uses the same ones.
    private static Color Back(PacketCategory c) => c switch
    {
        PacketCategory.Drop => Color.FromArgb(255, 205, 205), PacketCategory.TcpReset => Color.FromArgb(255, 220, 190), PacketCategory.TcpSyn => Color.FromArgb(205, 240, 205),
        PacketCategory.TcpData => Color.FromArgb(232, 245, 252), PacketCategory.TcpAck => Color.FromArgb(246, 246, 246), PacketCategory.TcpFin => Color.FromArgb(255, 240, 190),
        PacketCategory.Dns => Color.FromArgb(205, 225, 255), PacketCategory.Udp => Color.FromArgb(232, 222, 250), PacketCategory.Arp => Color.FromArgb(255, 250, 200),
        PacketCategory.Icmp => Color.FromArgb(205, 245, 240), _ => Color.White,
    };

    private static Color Fore(PacketCategory c) => c switch { PacketCategory.Drop => Color.DarkRed, PacketCategory.TcpReset => Color.Maroon, _ => Color.Black };

    private static string Describe(PacketRow r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine(r.IsDrop ? "DROPPED PACKET" : $"{r.Protocol} packet".Trim());
        if (r.Summary.Length > 0) sb.AppendLine(r.Summary);
        sb.AppendLine();
        sb.AppendLine($"When:       {r.Time}");
        sb.AppendLine($"Direction:  {(r.Direction == "Tx" ? "Tx - sent by this PC" : r.Direction == "Rx" ? "Rx - received by this PC" : r.Direction)} (component {r.Component}, {r.Type})");
        if (r.Source.Length > 0) sb.AppendLine($"From:       {Humanize.Endpoint(r.Source)}");
        if (r.Destination.Length > 0) sb.AppendLine($"To:         {Humanize.Endpoint(r.Destination)}");
        sb.AppendLine($"Size:       {r.Size} bytes");
        if (r.IsDrop) sb.AppendLine($"Drop reason: {r.DropReason}");
        sb.AppendLine().AppendLine("--- raw pktmon text ---").Append(r.Raw);
        return sb.ToString();
    }

    private void Export()
    {
        if (_view.Count == 0) return;
        using var d = new SaveFileDialog { Filter = "CSV|*.csv", FileName = "packets.csv" };
        if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
        File.WriteAllText(d.FileName, PacketParser.ToCsv(_view), new System.Text.UTF8Encoding(true));
        StatusChanged?.Invoke($"Exported {_view.Count} rows to {d.FileName}");
    }

    private void CopyRows()
    {
        var rows = _grid.SelectedRows.Count > 1 ? _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.Index).Order().Where(i => i < _view.Count).Select(i => _view[i]) : _view;
        if (!rows.Any()) return;
        Clipboard.SetText(string.Join(Environment.NewLine, rows.Select(r => $"{r.Index}\t{r.Time}\t{r.Direction}\t{r.Component}\t{r.Size}\t{r.Source}\t{r.Destination}\t{r.Protocol}\t{(r.IsDrop ? "DROP " + r.DropReason + " " : "")}{r.Info}")));
        StatusChanged?.Invoke("Rows copied");
    }
}
