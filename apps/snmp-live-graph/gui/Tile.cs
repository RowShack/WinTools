using ScottPlot.WinForms;
using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

/// <summary>One interface on screen: header with current/average/peak and a live in/out chart.</summary>
public sealed class Tile : Panel
{
    private readonly Label _title = new() { AutoSize = true, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Location = new Point(8, 6) };
    private readonly Label _line = new() { AutoSize = true, Location = new Point(8, 30), Font = new Font("Segoe UI", 9f) };
    private readonly FormsPlot _plot = new() { Dock = DockStyle.Bottom, Height = 165 };
    private readonly Button _png = new() { Text = "PNG…", AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private readonly Button _thr = new() { Text = "Thresholds…", AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private readonly Button _close = new() { Text = "✕", Width = 28, Anchor = AnchorStyles.Top | AnchorStyles.Right };

    public readonly History History = new();
    public readonly Stats InStats = new(), OutStats = new();
    public string Key { get; }
    public string Series { get; }
    public InterfaceInfo If { get; }
    private PollPoint? _last;
    private bool _paused;
    private ScottPlot.IYAxis? _errAxis;     // right-hand errors/s axis, only present while an errors threshold is set
    private readonly string _device;

    /// <summary>Optional alarm levels; null or empty = none.</summary>
    public Threshold? Threshold { get; private set; }

    public event Action<Tile>? CloseRequested;
    public event Action<Tile>? ThresholdChanged;

    public Tile(string key, string device, InterfaceInfo iface)
    {
        Key = key; If = iface; _device = device; Series = $"{device} {iface.Name}";
        Height = 230; Width = 900; BorderStyle = BorderStyle.FixedSingle; Margin = new Padding(0, 0, 0, 6);
        SetTitle(iface.StatusText);
        LayoutButtons();
        _close.Click += (_, _) => CloseRequested?.Invoke(this);
        _png.Click += (_, _) => SavePng();
        _thr.Click += (_, _) => EditThresholds();
        Controls.AddRange([_title, _line, _thr, _png, _close, _plot]);
        _plot.Plot.Axes.DateTimeTicksBottom();
        _plot.Plot.Axes.Left.TickGenerator = new ScottPlot.TickGenerators.NumericAutomatic { LabelFormatter = v => RateCalculator.FormatBps(v) };
        _plot.Plot.Legend.Alignment = ScottPlot.Alignment.UpperLeft;
        Resize += (_, _) => LayoutButtons();
        _line.Text = "waiting for the first two samples…";
    }

    private void LayoutButtons()
    {
        _close.Location = new Point(Width - 40, 4);
        _png.Location = new Point(Width - 40 - _png.Width - 6, 4);
        _thr.Location = new Point(_png.Left - _thr.Width - 6, 4);
        _line.MaximumSize = new Size(Math.Max(200, Width - 20), 0);   // wrap instead of running off the tile
    }

    private void SetTitle(string status) =>
        _title.Text = $"{_device} · {If.Name}" + (If.Alias.Length > 0 ? $"  \"{If.Alias}\"" : "") + $"   ({If.Speed}, {status})";

    public void SetThreshold(Threshold? t) { Threshold = t is { IsSet: true } ? t : null; _thr.Font = new Font(_thr.Font, Threshold != null ? FontStyle.Bold : FontStyle.Regular); }

    private void EditThresholds()
    {
        using var dlg = new ThresholdDialog(Threshold, If.HighSpeedMbps);
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        SetThreshold(dlg.Result);
        ThresholdChanged?.Invoke(this);
        Redraw();
    }

    public void Add(PollPoint p)
    {
        if (_paused) return;
        History.Add(p);
        _last = p;
        if (p.OperStatus > 0) SetTitle(InterfaceInfo.StatusName(p.OperStatus));
        if (p.InBps is double i) InStats.Add(i);
        if (p.OutBps is double o) OutStats.Add(o);
    }

    public void Pause(bool paused) => _paused = paused;

    public void Clear() { History.Clear(); InStats.Clear(); OutStats.Clear(); _last = null; _line.Text = "cleared"; Redraw(); }

    public void SetWindow(TimeSpan w) => History.Window = w;

    public void Redraw()
    {
        var pts = History.Points;
        _plot.Plot.Clear();
        var inPts = pts.Where(p => p.InBps.HasValue).ToList();
        var outPts = pts.Where(p => p.OutBps.HasValue).ToList();
        if (inPts.Count > 0)
        {
            var s = _plot.Plot.Add.Scatter(inPts.Select(p => p.Time.ToLocalTime().ToOADate()).ToArray(), inPts.Select(p => p.InBps!.Value).ToArray());
            s.LegendText = "In"; s.MarkerSize = 0; s.LineWidth = 1.6f; s.Color = ScottPlot.Color.FromHex("#2E7D32");
        }
        if (outPts.Count > 0)
        {
            var s = _plot.Plot.Add.Scatter(outPts.Select(p => p.Time.ToLocalTime().ToOADate()).ToArray(), outPts.Select(p => p.OutBps!.Value).ToArray());
            s.LegendText = "Out"; s.MarkerSize = 0; s.LineWidth = 1.6f; s.Color = ScottPlot.Color.FromHex("#1565C0");
        }
        var red = ScottPlot.Color.FromHex("#C62828");
        var th = Threshold;
        if (th?.UtilPercent is double up && ThresholdEvaluator.UtilisationAsBps(up, If.HighSpeedMbps) is double bpsLine)
        {
            var hl = _plot.Plot.Add.HorizontalLine(bpsLine);
            hl.LineColor = red; hl.LineWidth = 1.5f; hl.LinePattern = ScottPlot.LinePattern.Dashed; hl.LegendText = $"Utilisation {up:0.#}%";
        }
        double errTop = 0;
        if (th?.ErrorsPerSec is double ep)
        {
            _errAxis ??= _plot.Plot.Axes.AddRightAxis();
            _errAxis.Label.Text = "errors/s";
            var ePts = pts.Select(p => (p.Time, V: ThresholdEvaluator.ErrorsOf(p))).Where(x => x.V.HasValue).ToList();
            if (ePts.Count > 0)
            {
                var es = _plot.Plot.Add.Scatter(ePts.Select(x => x.Time.ToLocalTime().ToOADate()).ToArray(), ePts.Select(x => x.V!.Value).ToArray());
                es.Axes.YAxis = _errAxis; es.LegendText = "Errors/s (right axis)"; es.MarkerSize = 0; es.LineWidth = 1.2f; es.Color = ScottPlot.Color.FromHex("#EF6C00");
                errTop = ePts.Max(x => x.V!.Value);
            }
            var el = _plot.Plot.Add.HorizontalLine(ep);
            el.Axes.YAxis = _errAxis; el.LineColor = ScottPlot.Color.FromHex("#EF6C00"); el.LineWidth = 1.5f; el.LinePattern = ScottPlot.LinePattern.Dashed;
            el.LegendText = $"Errors {ep:0.##}/s";
            errTop = Math.Max(errTop, ep);
        }
        else if (_errAxis != null) { _plot.Plot.Axes.Remove(_errAxis); _errAxis = null; }
        _plot.Plot.ShowLegend();
        if (inPts.Count + outPts.Count > 0 || th != null)
        {
            _plot.Plot.Axes.AutoScale();
            var lim = _plot.Plot.Axes.GetLimits();
            _plot.Plot.Axes.SetLimitsY(0, Math.Max(lim.Top * 1.1, 1000));
            if (_errAxis != null) _plot.Plot.Axes.SetLimitsY(0, Math.Max(errTop * 1.2, 1), _errAxis);
        }
        var breach = ThresholdEvaluator.Evaluate(_last, th);
        bool alarm = breach != Breach.None;
        _title.ForeColor = alarm ? Color.Firebrick : SystemColors.ControlText;
        BackColor = alarm ? Color.MistyRose : SystemColors.Control;
        _plot.Plot.DataBackground.Color = alarm ? ScottPlot.Color.FromHex("#FFEBEE") : ScottPlot.Colors.White;
        _plot.Refresh();

        if (_last is { } l)
        {
            string F(double? v) => v is double d ? RateCalculator.FormatBps(d) : "–";
            string U(double? v) => v is double d ? $"{d:0.#}%" : "n/a";
            string R(double? v) => v is double d ? $"{d:0.##}/s" : "–";
            _line.Text = $"In: {F(InStats.Current)} (avg {F(InStats.Average)}, peak {F(InStats.Peak)}) {U(l.InUtil)}     " +
                         $"Out: {F(OutStats.Current)} (avg {F(OutStats.Average)}, peak {F(OutStats.Peak)}) {U(l.OutUtil)}     " +
                         $"Errors in/out {R(l.InErrors)} / {R(l.OutErrors)}    Discards in/out {R(l.InDiscards)} / {R(l.OutDiscards)}";
            if (alarm)
                _line.Text = "⚠ " + string.Join(" and ", new[] { breach.HasFlag(Breach.Utilisation) ? $"utilisation above {th!.UtilPercent:0.#}%" : null,
                    breach.HasFlag(Breach.Errors) ? $"errors above {th!.ErrorsPerSec:0.##}/s" : null }.Where(x => x != null)) + "     " + _line.Text;
        }
    }

    public void SavePng(string? path = null)
    {
        if (path == null)
        {
            using var d = new SaveFileDialog { FileName = Series.Replace('/', '-').Replace(' ', '_') + ".png", Filter = "PNG image|*.png" };
            if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
            path = d.FileName;
        }
        _plot.Plot.SavePng(path, 1200, 500);
    }
}
