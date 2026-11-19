using System.Drawing.Drawing2D;

namespace WifiRoamLog;

/// <summary>Generates the window / tray icon in code (a Wi-Fi fan), so the exe needs no resource files.</summary>
internal static class AppIcon
{
    public static Icon Create()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(System.Drawing.Color.Transparent);
            using var bg = new SolidBrush(System.Drawing.Color.FromArgb(21, 101, 192));
            g.FillEllipse(bg, 0, 0, 31, 31);
            using var pen = new Pen(System.Drawing.Color.White, 2.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            foreach (int r in new[] { 20, 13, 6 })
                g.DrawArc(pen, 16 - r, 25 - r, r * 2, r * 2, 225, 90);
            g.FillEllipse(Brushes.White, 13.5f, 22.5f, 5, 5);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }
}
