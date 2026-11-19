using ScottPlot.WinForms;
using WifiRoamLog.Core;
using SpColor = ScottPlot.Color;

namespace WifiRoamLog;

/// <summary>"Visible APs" tab: neighbouring BSSIDs from the BSS list plus a channel overlap view. Reading the list never scans; only the Refresh button asks the driver for a scan (rate limited).</summary>
public sealed class VisibleApsView : UserControl
{
    private readonly IWlanApi _api;
    private readonly Func<Guid?> _iface;
    private readonly Func<string, string> _apName;
    private readonly Func<string> _currentBssid;
    private readonly ScanThrottle _throttle = new(TimeSpan.FromSeconds(15));
    private readonly Button _refresh = new() { Text = "Refresh (scan)", AutoSize = true };
    private readonly ComboBox _band = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
    private readonly Label _note = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(10, 6, 3, 3) };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoGenerateColumns = false, BackgroundColor = SystemColors.Window, BorderStyle = BorderStyle.None,
    };
    private readonly FormsPlot _plot = new() { Dock = DockStyle.Fill };
    private List<Row> _rows = [];
    private bool _busy;

    private sealed record Row(string Ssid, string Ap, string Bssid, int Rssi, int? Channel, WifiBand Band, int Freq, string Phy, string Security, bool Connected);

    public VisibleApsView(IWlanApi api, Func<Guid?> iface, Func<string, string> apName, Func<string> currentBssid)
    {
        Dock = DockStyle.Fill;
        _api = api; _iface = iface; _apName = apName; _currentBssid = currentBssid;
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), WrapContents = false };
        _band.Items.AddRange(["2.4 GHz", "5 GHz", "6 GHz"]); _band.SelectedIndex = 1;
        bar.Controls.AddRange([_refresh, new Label { Text = "Overlap view:", AutoSize = true, Margin = new Padding(14, 6, 3, 3) }, _band, _note]);

        void Col(string name, string prop, int w, bool right = false) =>
            _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = name, DataPropertyName = prop, Width = w, SortMode = DataGridViewColumnSortMode.Automatic, DefaultCellStyle = { Alignment = right ? DataGridViewContentAlignment.MiddleRight : DataGridViewContentAlignment.MiddleLeft } });
        Col("SSID", "Ssid", 150); Col("AP name", "Ap", 150); Col("BSSID", "Bssid", 135); Col("RSSI (dBm)", "Rssi", 80, true); Col("Channel", "Channel", 62, true);
        Col("Band", "BandText", 65); Col("MHz", "Freq", 52, true); Col("PHY", "Phy", 140); Col("Security", "Security", 120); Col("", "Mark", 95);

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        split.Panel1.Controls.Add(_grid);
        split.Panel2.Controls.Add(_plot);
        Controls.Add(split);
        Controls.Add(bar);
        _plot.Plot.Layout.Fixed(new ScottPlot.PixelPadding(56, 14, 44, 10));
        _refresh.Click += async (_, _) => await RefreshAsync(scan: true);
        _band.SelectedIndexChanged += (_, _) => DrawOverlap();
        HandleCreated += (_, _) => { try { split.SplitterDistance = Math.Max(60, (int)(split.Height * 0.52)); } catch { } };
    }

    /// <summary>Re-reads the cached BSS list (no scan). Called when the tab is shown.</summary>
    public void ReloadCached() => _ = RefreshAsync(scan: false);

    public async Task RefreshAsync(bool scan)
    {
        if (_busy) return;
        if (_iface() is not { } id) { _note.Text = "No Wi-Fi adapter selected."; return; }
        _busy = true; _refresh.Enabled = false;
        try
        {
            if (scan)
            {
                if (_throttle.TryAcquire(DateTime.Now))
                {
                    _note.Text = "Scanning…";
                    try { await Task.Run(() => _api.Scan(id)); await Task.Delay(4000); }
                    catch (WlanException ex) { _note.Text = "Scan not started: " + ex.Message; }
                }
                else _note.Text = $"Scan skipped (limited to one per 15 s; {_throttle.Remaining(DateTime.Now).TotalSeconds:0} s left): showing the cached list.";
            }
            var (bss, nets) = await Task.Run(() =>
            {
                var b = _api.GetBssList(id);
                IReadOnlyList<AvailableNetwork> n = [];
                try { n = _api.GetAvailableNetworks(id); } catch (WlanException) { }
                return (b, n);
            });
            Fill(bss, nets);
            if (!_note.Text.StartsWith("Scan skipped") && !_note.Text.StartsWith("Scan not"))
                _note.Text = $"{bss.Count} access points, read {DateTime.Now:HH:mm:ss}" + (scan ? " (after a fresh scan)" : " (cached list, no scan)");
        }
        catch (WlanException ex) { _note.Text = "Could not read the AP list: " + ex.Message; }
        finally { _busy = false; _refresh.Enabled = true; }
    }

    private void Fill(IReadOnlyList<BssEntry> bss, IReadOnlyList<AvailableNetwork> nets)
    {
        string cur = _currentBssid();
        _rows = bss.Select(b => new Row(
            b.Ssid.Length == 0 ? "(hidden)" : b.Ssid, string.IsNullOrEmpty(b.Bssid) ? "" : _apName(b.Bssid), b.Bssid, b.RssiDbm, WifiMath.FrequencyToChannel(b.FrequencyMhz),
            WifiMath.BandFromFrequency(b.FrequencyMhz), b.FrequencyMhz, WifiMath.PhyName(b.PhyType),
            nets.FirstOrDefault(n => n.Ssid == b.Ssid && b.Ssid.Length > 0)?.Security ?? "", cur.Length > 0 && b.Bssid == cur)).OrderByDescending(r => r.Rssi).ToList();
        _grid.DataSource = _rows.Select(r => new RowView(r)).ToList();
        foreach (DataGridViewRow gr in _grid.Rows)
            if (gr.DataBoundItem is RowView rv && rv.R.Connected) { gr.DefaultCellStyle.BackColor = System.Drawing.Color.FromArgb(227, 242, 253); gr.DefaultCellStyle.Font = new Font(_grid.Font, FontStyle.Bold); }
        DrawOverlap();
    }

    private sealed class RowView(Row r)
    {
        public Row R => r;
        public string Ssid => r.Ssid; public string Ap => r.Ap; public string Bssid => r.Bssid; public int Rssi => r.Rssi; public int? Channel => r.Channel;
        public string BandText => WifiMath.BandName(r.Band); public int Freq => r.Freq; public string Phy => r.Phy; public string Security => r.Security;
        public string Mark => r.Connected ? "connected" : "";
    }

    private static SpColor ColorFor(string key)
    {
        string[] pal = ["#1565C0", "#2E7D32", "#EF6C00", "#6A1B9A", "#00838F", "#AD1457", "#827717", "#4E342E", "#455A64", "#C62828"];
        int h = 17; foreach (char c in key) h = h * 31 + c;
        return SpColor.FromHex(pal[(h & 0x7fffffff) % pal.Length]);
    }

    private void DrawOverlap()
    {
        var plot = _plot.Plot;
        plot.Clear();
        var band = _band.SelectedIndex switch { 0 => WifiBand.Band24, 2 => WifiBand.Band6, _ => WifiBand.Band5 };
        var rows = _rows.Where(r => r.Band == band && r.Channel is not null).ToList();
        plot.Axes.Bottom.Label.Text = band == WifiBand.Band24 ? "Channel (2.4 GHz: an AP spans ~4 channels, neighbours overlap)" : $"Channel ({WifiMath.BandName(band)}: 20 MHz blocks, no overlap between channels)";
        plot.Axes.Left.Label.Text = "RSSI (dBm)";
        double lo, hi;
        if (band == WifiBand.Band24)
        {
            foreach (var r in rows)
            {
                double c = r.Channel!.Value; double y = r.Rssi;
                var poly = plot.Add.Polygon([new ScottPlot.Coordinates(c - 2.2, -100), new ScottPlot.Coordinates(c - 1.7, y), new ScottPlot.Coordinates(c + 1.7, y), new ScottPlot.Coordinates(c + 2.2, -100)]);
                Style(poly, r);
            }
            lo = -1; hi = 17;
            plot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericManual(Enumerable.Range(1, 14).Select(i => new ScottPlot.Tick(i, i.ToString())).ToArray());
        }
        else
        {
            foreach (var r in rows)
            {
                double c = r.Channel!.Value; double y = r.Rssi;
                var poly = plot.Add.Polygon([new ScottPlot.Coordinates(c - 1.9, -100), new ScottPlot.Coordinates(c - 1.9, y), new ScottPlot.Coordinates(c + 1.9, y), new ScottPlot.Coordinates(c + 1.9, -100)]);
                Style(poly, r);
            }
            var chans = rows.Select(r => r.Channel!.Value).Distinct().OrderBy(c => c).ToList();
            if (chans.Count == 0) chans = band == WifiBand.Band5 ? [36, 40, 44, 48, 100, 149, 153, 157, 161] : [1, 5, 9, 13, 17, 21, 25, 29, 33, 37];
            lo = chans.Min() - 8; hi = chans.Max() + 8;
            plot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericManual(chans.Select(c => new ScottPlot.Tick(c, c.ToString())).ToArray());
        }
        // one label per (channel, AP name): several BSSIDs of one AP share a label; different APs on one channel are stacked
        foreach (var ch in rows.GroupBy(r => r.Channel!.Value))
        {
            int k = 0;
            foreach (var g in ch.GroupBy(r => r.Ap.Length > 0 ? r.Ap : r.Ssid).OrderByDescending(g => g.Max(r => r.Rssi)))
            {
                var best = g.OrderByDescending(r => r.Rssi).First();
                var t = plot.Add.Text((g.Any(r => r.Connected) ? "(connected) " : "") + g.Key, ch.Key, ch.Max(r => r.Rssi) + 2 + 6 * k++);
                t.LabelFontSize = 10; t.LabelFontColor = ColorFor(best.Bssid); t.LabelAlignment = ScottPlot.Alignment.LowerCenter;
            }
        }
        if (rows.Count == 0)
        {
            var t = plot.Add.Text("No access points seen on this band", (lo + hi) / 2, -60); t.LabelFontSize = 14; t.LabelFontColor = SpColor.FromHex("#888888");
        }
        plot.Axes.SetLimits(lo, hi, -100, -20);
        _plot.Refresh();
    }

    private static void Style(ScottPlot.Plottables.Polygon poly, Row r)
    {
        var c = ColorFor(r.Bssid);
        poly.FillColor = c.WithAlpha(0.28); poly.LineColor = c; poly.LineWidth = r.Connected ? 3 : 1.2f;
    }
}
