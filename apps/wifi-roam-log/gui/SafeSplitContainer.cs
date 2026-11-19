using System.Runtime.InteropServices;

namespace WifiRoamLog;

/// <summary>SplitContainer that survives the well-known GDI+ failure in RepaintSplitterRect (painting at zero size, while hidden / minimised, or during a layout race).
/// Painting is skipped when there is nothing to paint into, and a GDI+ error is swallowed (the next paint repairs it). The splitter ratio is applied only once the size is valid.</summary>
internal sealed class SafeSplitContainer : SplitContainer
{
    private double _ratio = -1;
    private int _min1 = 40, _min2 = 40;

    public SafeSplitContainer() { DoubleBuffered = true; }

    /// <summary>Wanted share of Panel1 (0..1); applied now if the control has a valid size, else on the first valid resize.</summary>
    public void SetRatio(double ratio, int panel1Min, int panel2Min)
    {
        _ratio = ratio; _min1 = panel1Min; _min2 = panel2Min;
        TryApply();
    }

    private bool HasRoom => IsHandleCreated && Visible && ClientSize.Width > 0 && ClientSize.Height > 0 && WindowState() != FormWindowState.Minimized;

    private FormWindowState WindowState() => FindForm()?.WindowState ?? FormWindowState.Normal;

    private void TryApply()
    {
        if (_ratio < 0 || !HasRoom) return;
        int total = Orientation == Orientation.Horizontal ? Height : Width;
        if (total < _min1 + _min2 + SplitterWidth + 2) return;
        try
        {
            Panel1MinSize = Math.Min(_min1, Math.Max(0, total - SplitterWidth - 1));
            Panel2MinSize = Math.Min(_min2, Math.Max(0, total - SplitterWidth - Panel1MinSize - 1));
            int d = (int)(total * _ratio);
            SplitterDistance = Math.Clamp(d, Panel1MinSize, total - Panel2MinSize - SplitterWidth);
            _ratio = -1;
        }
        catch (InvalidOperationException) { /* size changed under us: retry on the next resize */ }
    }

    protected override void OnSizeChanged(EventArgs e) { base.OnSizeChanged(e); TryApply(); }
    protected override void OnVisibleChanged(EventArgs e) { base.OnVisibleChanged(e); TryApply(); }
    protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); TryApply(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (!HasRoom || e.ClipRectangle.Width <= 0 || e.ClipRectangle.Height <= 0) return;
        try { base.OnPaint(e); }
        catch (ExternalException) { }
        catch (ArgumentException) { }
    }
}
