using System.Drawing.Drawing2D;
using HostTop.Core;

namespace HostTop;

/// <summary>Small custom-drawn history chart (no charting dependency): download as a filled area, upload as a line.</summary>
public static class Sparkline
{
    public static readonly Color DownColor = Color.FromArgb(46, 125, 214);
    public static readonly Color UpColor = Color.FromArgb(230, 126, 34);

    public static double Max(double[] down, double[] up)
    {
        double m = 0;
        foreach (var v in down) if (v > m) m = v;
        foreach (var v in up) if (v > m) m = v;
        return m;
    }

    public static void Draw(Graphics g, Rectangle r, double[] down, double[] up, double max)
    {
        if (r.Width < 4 || r.Height < 4 || down.Length < 2) return;
        if (max <= 0) max = 1;
        var old = g.SmoothingMode; g.SmoothingMode = SmoothingMode.AntiAlias;
        PointF Pt(int i, double v, int n) => new(r.Left + (float)i * (r.Width - 1) / (n - 1), r.Bottom - 1 - (float)(v / max * (r.Height - 2)));

        int n = down.Length;
        var area = new PointF[n + 2];
        area[0] = new PointF(r.Left, r.Bottom - 1);
        for (int i = 0; i < n; i++) area[i + 1] = Pt(i, down[i], n);
        area[n + 1] = new PointF(r.Right - 1, r.Bottom - 1);
        using (var b = new SolidBrush(Color.FromArgb(90, DownColor))) g.FillPolygon(b, area);
        using (var p = new Pen(DownColor, 1.2f)) g.DrawLines(p, area[1..(n + 1)]);

        if (up.Length == n)
        {
            var line = new PointF[n];
            for (int i = 0; i < n; i++) line[i] = Pt(i, up[i], n);
            using var p = new Pen(UpColor, 1.2f);
            g.DrawLines(p, line);
        }
        g.SmoothingMode = old;
    }
}

/// <summary>Larger sparkline with scale and legend, used for the selected row.</summary>
public sealed class SparklineControl : Control
{
    private double[] _down = [], _up = [];
    private string _caption = "";
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Func<double, string> RateFormat { get; set; } = v => v.ToString("0");

    public SparklineControl()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Height = 96;
    }

    public void SetData(string caption, double[] down, double[] up)
    {
        _caption = caption; _down = down; _up = up; Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(SystemColors.Window);
        using var border = new Pen(SystemColors.ControlLight);
        g.DrawRectangle(border, 0, 0, Width - 1, Height - 1);
        var chart = new Rectangle(8, 22, Width - 16, Height - 30);
        double max = Sparkline.Max(_down, _up);
        using var f = new Font(Font.FontFamily, 8.5f);
        TextRenderer.DrawText(g, _caption.Length == 0 ? "Select a row to see its last 60 seconds" : _caption, f, new Point(6, 3), SystemColors.ControlText);
        if (_down.Length > 1)
        {
            using var grid = new Pen(Color.FromArgb(40, 128, 128, 128));
            g.DrawLine(grid, chart.Left, chart.Top, chart.Right, chart.Top);
            Sparkline.Draw(g, chart, _down, _up, max);
            var legend = $"▼ down  ▲ up   peak {RateFormat(max)}";
            var sz = TextRenderer.MeasureText(legend, f);
            TextRenderer.DrawText(g, legend, f, new Point(Width - sz.Width - 8, 3), SystemColors.GrayText);
        }
    }
}
