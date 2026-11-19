using System.Drawing.Imaging;
using ScottPlot.WinForms;
using WifiRoamLog.Core;
using SpColor = ScottPlot.Color;

namespace WifiRoamLog;

/// <summary>RSSI chart over a latency chart on one shared time axis, with roam / disconnect markers. Used for the live session and for opened logs.</summary>
public sealed class ChartView : UserControl
{
    private readonly FormsPlot _rssi = new() { Dock = DockStyle.Fill };
    private readonly FormsPlot _lat = new() { Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer _syncTimer = new() { Interval = 150 };
    private SessionData? _data;
    private long _renderedVersion = -1;
    private double _setL = double.NaN, _setR = double.NaN;
    private DateTime? _highlight;
    private int _windowMinutes = 15;

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Func<string, string> ApName { get; set; } = _ => "";
    /// <summary>True while a live session feeds the data: follow mode keeps the right edge at "now".</summary>
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool Live { get; set; }
    public bool Follow { get; private set; } = true;
    public event Action<bool>? FollowChanged;

    public ChartView()
    {
        var table = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1, Margin = Padding.Empty };
        table.RowStyles.Add(new RowStyle(SizeType.Percent, 56));
        table.RowStyles.Add(new RowStyle(SizeType.Percent, 44));
        table.Controls.Add(_rssi, 0, 0);
        table.Controls.Add(_lat, 0, 1);
        Controls.Add(table);
        foreach (var p in new[] { _rssi, _lat })
        {
            p.Plot.Axes.DateTimeTicksBottom();
            p.Plot.Layout.Fixed(new ScottPlot.PixelPadding(62, 14, 46, 8));
            p.Plot.Legend.Alignment = ScottPlot.Alignment.UpperLeft;
        }
        _rssi.Plot.Layout.Fixed(new ScottPlot.PixelPadding(62, 14, 46, 26));
        _rssi.Plot.YLabel("RSSI (dBm)");
        _lat.Plot.YLabel("Latency (ms)");
        _syncTimer.Tick += (_, _) => DetectUserNavigation();
        _syncTimer.Start();
    }

    public void SetData(SessionData data, bool live)
    {
        _data = data; Live = live; _renderedVersion = -1;
        SetFollow(live);
        if (!live) ShowWholeOrFirstWindow();
        Redraw(true);
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public int WindowMinutes
    {
        get => _windowMinutes;
        set { _windowMinutes = value; if (Follow) Redraw(true); else ShowWholeOrFirstWindow(); Redraw(true); }
    }

    public void SetFollow(bool on)
    {
        if (Follow == on) return;
        Follow = on;
        FollowChanged?.Invoke(on);
        if (on) Redraw(true);
    }

    public void Highlight(DateTime? t) { _highlight = t; Redraw(true); }

    /// <summary>Scrolls so that t is in the middle of the visible window (events table selection).</summary>
    public void CenterOn(DateTime t)
    {
        SetFollow(false);
        double half = VisibleSpanDays() / 2;
        double c = t.ToOADate();
        ApplyX(c - half, c + half);
        _highlight = t;
        Redraw(true);
    }

    private double VisibleSpanDays() => _windowMinutes <= 0 ? 15.0 / 1440 : _windowMinutes / 1440.0;

    private void ShowWholeOrFirstWindow()
    {
        if (_data is null) return;
        var s = _data.Samples(); var p = _data.Pings();
        DateTime? first = null, last = null;
        if (s.Length > 0) { first = s[0].Time; last = s[^1].Time; }
        if (p.Length > 0) { first = first is null || p[0].Time < first ? p[0].Time : first; last = last is null || p[^1].Time > last ? p[^1].Time : last; }
        if (first is null || last is null) return;
        double l = first.Value.ToOADate(), r = last.Value.ToOADate();
        if (_windowMinutes > 0) r = Math.Min(r, l + VisibleSpanDays());
        if (r - l < 1.0 / 86400 * 10) r = l + 10.0 / 86400;
        ApplyX(l, r);
    }

    private void ApplyX(double l, double r)
    {
        _setL = l; _setR = r;
        _rssi.Plot.Axes.SetLimitsX(l, r);
        _lat.Plot.Axes.SetLimitsX(l, r);
    }

    /// <summary>The user panned or zoomed one of the plots with the mouse: mirror it on the other and stop following.</summary>
    private void DetectUserNavigation()
    {
        if (double.IsNaN(_setL)) return;
        foreach (var (src, dst) in new[] { (_rssi, _lat), (_lat, _rssi) })
        {
            var lim = src.Plot.Axes.GetLimits();
            if (Math.Abs(lim.Left - _setL) > 1e-9 || Math.Abs(lim.Right - _setR) > 1e-9)
            {
                _setL = lim.Left; _setR = lim.Right;
                dst.Plot.Axes.SetLimitsX(lim.Left, lim.Right);
                SetFollow(false);
                Redraw(true);
                return;
            }
        }
    }

    /// <summary>Called every second by the owner; cheap when nothing changed.</summary>
    public void Tick() => Redraw(false);

    private void Redraw(bool force)
    {
        if (_data is null) return;
        long v = _data.Version;
        if (!force && !(Live && Follow) && v == _renderedVersion) return;
        _renderedVersion = v;

        if (Follow)
        {
            double right = Live ? DateTime.Now.ToOADate() : LastTime()?.ToOADate() ?? DateTime.Now.ToOADate();
            double span = _windowMinutes <= 0 ? Math.Max(15.0 / 1440, right - (FirstTime()?.ToOADate() ?? right)) : VisibleSpanDays();
            ApplyX(right - span, right + span * 0.01);
        }
        double l = _setL, r = _setR;
        if (double.IsNaN(l)) { ShowWholeOrFirstWindow(); l = _setL; r = _setR; }
        if (double.IsNaN(l)) return;

        var samples = _data.Samples(); var pings = _data.Pings(); var events = _data.Events();
        DrawRssi(samples, events, l, r);
        DrawLatency(pings, events, l, r);
        _rssi.Refresh(); _lat.Refresh();
    }

    private DateTime? LastTime() { var s = _data!.Samples(); var p = _data.Pings(); DateTime? a = s.Length > 0 ? s[^1].Time : null; DateTime? b = p.Length > 0 ? p[^1].Time : null; return a is null ? b : b is null ? a : a > b ? a : b; }
    private DateTime? FirstTime() { var s = _data!.Samples(); var p = _data.Pings(); DateTime? a = s.Length > 0 ? s[0].Time : null; DateTime? b = p.Length > 0 ? p[0].Time : null; return a is null ? b : b is null ? a : a < b ? a : b; }

    private static int Stride(int n) => Math.Max(1, n / 4000);

    private void DrawRssi(WifiSample[] samples, WifiEvent[] events, double l, double r)
    {
        var plot = _rssi.Plot;
        plot.Clear();
        // quality bands
        AddBand(plot, l, r, -67, -20, "#E8F5E9");
        AddBand(plot, l, r, -75, -67, "#FFF8E1");
        AddBand(plot, l, r, -100, -75, "#FFEBEE");
        // connected runs as separate lines so disconnects show as gaps
        var xs = new List<double>(); var ys = new List<double>();
        void Flush()
        {
            if (xs.Count == 0) return;
            var sc = plot.Add.Scatter(xs.ToArray(), ys.ToArray());
            sc.LineWidth = 1.8f; sc.MarkerSize = xs.Count < 40 ? 4 : 0; sc.Color = SpColor.FromHex("#1565C0");
            if (!_legendAdded) { sc.LegendText = "RSSI"; _legendAdded = true; }
            xs.Clear(); ys.Clear();
        }
        _legendAdded = false;
        var visible = samples.Where(s => { double x = s.Time.ToOADate(); return x >= l - 0.01 && x <= r + 0.01; }).ToList();
        int stride = Stride(visible.Count), i = 0;
        foreach (var s in visible)
        {
            if (s.IsConnected && s.RssiDbm is { } rssi) { if (i++ % stride == 0) { xs.Add(s.Time.ToOADate()); ys.Add(rssi); } }
            else if (!s.IsConnected && s.State is WlanState.Disconnected or WlanState.NotReady) Flush();
        }
        Flush();
        AddEventMarkers(plot, events, l, r, labels: true);
        plot.Axes.SetLimitsY(-100, -20);
        plot.Axes.SetLimitsX(l, r);
        _rssi.Plot.Axes.Bottom.Label.Text = "";
    }

    private bool _legendAdded, _lostLegend;

    private static void AddBand(ScottPlot.Plot plot, double l, double r, double y1, double y2, string hex)
    {
        var s = plot.Add.HorizontalSpan(y1, y2);
        s.FillColor = SpColor.FromHex(hex); s.LineWidth = 0;
    }

    private void DrawLatency(PingSample[] pings, WifiEvent[] events, double l, double r)
    {
        var plot = _lat.Plot;
        plot.Clear();
        var vis = pings.Where(p => { double x = p.Time.ToOADate(); return x >= l - 0.01 && x <= r + 0.01; }).ToList();
        double top = 10;
        _lostLegend = false;
        foreach (var (target, hex, name) in new[] { (PingTarget.Gateway, "#2E7D32", "Gateway"), (PingTarget.Target, "#EF6C00", "Target") })
        {
            var ok = vis.Where(p => p.Target == target && p.RttMs is not null).ToList();
            var lost = vis.Where(p => p.Target == target && p.Lost).ToList();
            string addr = vis.LastOrDefault(p => p.Target == target)?.Address ?? "";
            int stride = Stride(ok.Count);
            var pick = ok.Where((_, idx) => idx % stride == 0).ToList();
            if (pick.Count > 0)
            {
                var sc = plot.Add.Scatter(pick.Select(p => p.Time.ToOADate()).ToArray(), pick.Select(p => p.RttMs!.Value).ToArray());
                sc.LineWidth = 1.4f; sc.MarkerSize = pick.Count < 40 ? 3 : 0; sc.Color = SpColor.FromHex(hex);
                sc.LegendText = addr.Length > 0 ? $"{name} {addr}" : name;
                top = Math.Max(top, ok.Max(p => p.RttMs!.Value));
            }
            if (lost.Count > 0)
            {
                var lx = lost.Where((_, idx) => idx % Stride(lost.Count) == 0).Select(p => p.Time.ToOADate()).ToArray();
                var ls = plot.Add.Scatter(lx, lx.Select(_ => 0.0).ToArray());
                ls.LineWidth = 0; ls.MarkerShape = ScottPlot.MarkerShape.Cross; ls.MarkerSize = 7; ls.MarkerLineWidth = 2; ls.Color = SpColor.FromHex("#C62828");
                if (!_lostLegend) { ls.LegendText = "Lost ping"; _lostLegend = true; }
            }
        }
        AddEventMarkers(plot, events, l, r, labels: false);
        plot.Axes.SetLimitsY(-top * 0.06, top * 1.15);
        plot.Axes.SetLimitsX(l, r);
        plot.Axes.Bottom.Label.Text = "";
        plot.ShowLegend(ScottPlot.Alignment.UpperLeft);
    }

    private void AddEventMarkers(ScottPlot.Plot plot, WifiEvent[] events, double l, double r, bool labels)
    {
        var inView = events.Where(e => e.Kind is WifiEventKind.Roam or WifiEventKind.Disconnect or WifiEventKind.ConnectFail or WifiEventKind.Connect
                                        && e.Time.ToOADate() >= l && e.Time.ToOADate() <= r).ToList();
        bool label = labels;
        double lastLabelX = double.MinValue, minGap = (r - l) * 0.11;
        foreach (var e in inView)
        {
            var (hex, text) = e.Kind switch
            {
                WifiEventKind.Roam => ("#6A1B9A", "roam → " + Short(e.NewAp, e.NewBssid)),
                WifiEventKind.Disconnect => ("#C62828", "disconnect"),
                WifiEventKind.ConnectFail => ("#C62828", "connect failed"),
                _ => ("#2E7D32", "connect " + Short(e.NewAp, e.NewBssid)),
            };
            var vl = plot.Add.VerticalLine(e.Time.ToOADate());
            vl.Color = SpColor.FromHex(hex); vl.LineWidth = 1.4f; vl.LinePattern = ScottPlot.LinePattern.Dashed;
            if (label && e.Time.ToOADate() - lastLabelX >= minGap)
            {
                lastLabelX = e.Time.ToOADate();
                vl.Text = text.Trim();
                vl.LabelFontSize = 11; vl.LabelFontColor = SpColor.FromHex(hex); vl.LabelBackgroundColor = SpColor.FromHex("#FFFFFF").WithAlpha(0.75);
                vl.LabelOppositeAxis = true;
            }
        }
        if (_highlight is { } h && h.ToOADate() >= l && h.ToOADate() <= r)
        {
            var hl = plot.Add.VerticalLine(h.ToOADate());
            hl.Color = SpColor.FromHex("#FF6F00"); hl.LineWidth = 3;
        }
    }

    private static string Short(string ap, string bssid) => ap.Length > 0 ? ap : bssid.Length >= 8 ? bssid[^8..] : bssid;

    /// <summary>Renders both plots, stacked, to one PNG with a title strip.</summary>
    public void ExportPng(string path, string title)
    {
        int w = 1400, h1 = 520, h2 = 380, head = 36;
        using var a = new Bitmap(new MemoryStream(_rssi.Plot.GetImage(w, h1).GetImageBytes()));
        using var b = new Bitmap(new MemoryStream(_lat.Plot.GetImage(w, h2).GetImageBytes()));
        using var bmp = new Bitmap(w, head + h1 + h2);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(System.Drawing.Color.White);
            using var f = new Font("Segoe UI", 12f, FontStyle.Bold);
            g.DrawString(title, f, Brushes.Black, 10, 6);
            g.DrawImage(a, 0, head); g.DrawImage(b, 0, head + h1);
        }
        bmp.Save(path, ImageFormat.Png);
    }
}
