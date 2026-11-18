using ScottPlot.WinForms;
using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

/// <summary>One ad-hoc OID on screen: the value over time (gauge), or its per-second rate when treated as a counter.</summary>
public sealed class OidTile : Panel
{
    private readonly Label _title = new() { AutoSize = true, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Location = new Point(8, 6) };
    private readonly Label _line = new() { AutoSize = true, Location = new Point(8, 30), Font = new Font("Segoe UI", 9f) };
    private readonly FormsPlot _plot = new() { Dock = DockStyle.Bottom, Height = 140 };
    private readonly Button _png = new() { Text = "PNG…", AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private readonly Button _close = new() { Text = "✕", Width = 28, Anchor = AnchorStyles.Top | AnchorStyles.Right };
    private bool _paused;
    private CustomPoint? _last;

    public readonly CustomHistory History = new();
    public readonly Stats Stats = new();
    public string Key { get; }
    public string Series { get; }
    public CustomOidSpec Spec { get; }

    public event Action<OidTile>? CloseRequested;

    public OidTile(string key, string device, CustomOidSpec spec)
    {
        Key = key; Spec = spec; Series = $"{device} {spec.Title}";
        Height = 205; Width = 900; BorderStyle = BorderStyle.FixedSingle; Margin = new Padding(0, 0, 0, 6);
        string kind = spec.AsCounter ? "rate per second" : "value";
        _title.Text = $"{device} · {spec.Title}   ({spec.Oid}, {kind}{(spec.Unit.Length > 0 ? ", " + spec.Unit : "")})";
        _line.Text = "waiting for the first sample…";
        LayoutButtons();
        _close.Click += (_, _) => CloseRequested?.Invoke(this);
        _png.Click += (_, _) => SavePng();
        Controls.AddRange([_title, _line, _png, _close, _plot]);
        _plot.Plot.Axes.DateTimeTicksBottom();
        Resize += (_, _) => LayoutButtons();
    }

    private void LayoutButtons()
    {
        _close.Location = new Point(Width - 40, 4);
        _png.Location = new Point(Width - 40 - _png.Width - 6, 4);
    }

    public void Add(CustomPoint p)
    {
        if (_paused) return;
        History.Add(p); _last = p;
        if (p.Value is double v) Stats.Add(v);
    }

    public void Pause(bool paused) => _paused = paused;
    public void Clear() { History.Clear(); Stats.Clear(); _last = null; _line.Text = "cleared"; Redraw(); }
    public void SetWindow(TimeSpan w) => History.Window = w;

    private string Fmt(double? v) => v is double d ? $"{d:0.##}{(Spec.Unit.Length > 0 ? " " + Spec.Unit : "")}{(Spec.AsCounter ? "/s" : "")}" : "–";

    public void Redraw()
    {
        var pts = History.Points.Where(p => p.Value.HasValue).ToList();
        _plot.Plot.Clear();
        if (pts.Count > 0)
        {
            var s = _plot.Plot.Add.Scatter(pts.Select(p => p.Time.ToLocalTime().ToOADate()).ToArray(), pts.Select(p => p.Value!.Value).ToArray());
            s.MarkerSize = pts.Count < 30 ? 4 : 0; s.LineWidth = 1.6f; s.Color = ScottPlot.Color.FromHex("#6A1B9A");
            _plot.Plot.Axes.AutoScale();
            var lim = _plot.Plot.Axes.GetLimits();
            double lo = Math.Min(0, lim.Bottom), hi = lim.Top <= lo ? lo + 1 : lim.Top + (lim.Top - lo) * 0.1;
            _plot.Plot.Axes.SetLimitsY(lo, hi);
        }
        _plot.Refresh();

        bool problem = _last?.Problem != null;
        _title.ForeColor = problem ? Color.Firebrick : SystemColors.ControlText;
        if (_last is { Problem: { } msg }) _line.Text = "⚠ " + msg;
        else if (_last != null)
            _line.Text = Stats.Current is null ? "waiting for a second sample to calculate the rate…"
                : $"Now {Fmt(Stats.Current)}   (avg {Fmt(Stats.Average)}, peak {Fmt(Stats.Peak)})";
    }

    public void SavePng(string? path = null)
    {
        if (path == null)
        {
            using var d = new SaveFileDialog { FileName = Series.Replace('/', '-').Replace(' ', '_').Replace(':', '-') + ".png", Filter = "PNG image|*.png" };
            if (d.ShowDialog(FindForm()) != DialogResult.OK) return;
            path = d.FileName;
        }
        _plot.Plot.SavePng(path, 1200, 450);
    }
}
