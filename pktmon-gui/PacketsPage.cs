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
            new Label { Text = "Component", AutoSize = true, Margin = new Padding(8, 8, 4, 0) }, _comp, export, copy, _count]);

        foreach (var (name, head, w) in new[] { ("no", "#", 55), ("time", "Time", 130), ("dir", "Dir", 40), ("comp", "Comp", 50), ("size", "Size", 55),
                     ("src", "Source", 190), ("dst", "Destination", 190), ("proto", "Protocol", 70), ("info", "Info", 600) })
            _grid.Columns.Add(new DataGridViewTextBoxColumn { Name = name, HeaderText = head, Width = w, SortMode = DataGridViewColumnSortMode.NotSortable });
        _grid.Columns["size"]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 420 };
        split.Panel1.Controls.Add(_grid);
        var box = new GroupBox { Text = "Selected packet (raw pktmon text)", Dock = DockStyle.Fill, Padding = new Padding(6) };
        box.Controls.Add(_detail);
        split.Panel2.Controls.Add(box);
        Controls.Add(split); Controls.Add(top);

        _grid.CellValueNeeded += (_, e) =>
        {
            if (e.RowIndex >= _view.Count) return;
            var r = _view[e.RowIndex];
            e.Value = _grid.Columns[e.ColumnIndex].Name switch
            {
                "no" => r.Index, "time" => r.Time[11..], "dir" => r.Direction, "comp" => r.Component, "size" => r.Size,
                "src" => r.Source, "dst" => r.Destination, "proto" => r.Protocol, _ => r.IsDrop ? $"DROP: {r.DropReason} {r.Info}".Trim() : r.Info,
            };
        };
        _grid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || e.RowIndex >= _view.Count || !_view[e.RowIndex].IsDrop) return;
            e.CellStyle!.ForeColor = Color.Firebrick; e.CellStyle.BackColor = Color.MistyRose;
        };
        _grid.SelectionChanged += (_, _) =>
        {
            int i = _grid.CurrentRow?.Index ?? -1;
            _detail.Text = i >= 0 && i < _view.Count ? _view[i].Raw : "";
        };
        _filter.TextChanged += (_, _) => ApplyFilter();
        _dir.SelectedIndexChanged += (_, _) => ApplyFilter();
        _comp.SelectedIndexChanged += (_, _) => ApplyFilter();
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
        _view = _all.Where(p => (dir == "All" || p.Direction == dir) && (comp == "All" || p.Component.ToString() == comp) && p.Matches(f)).ToList();
        _grid.RowCount = 0; _grid.RowCount = _view.Count;
        int drops = _view.Count(p => p.IsDrop);
        _count.Text = $"{_view.Count} of {_all.Count} packet events" + (drops > 0 ? $" ({drops} drops)" : "");
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
