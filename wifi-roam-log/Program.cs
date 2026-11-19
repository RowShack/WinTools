namespace WifiRoamLog;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        bool Has(string a) => args.Contains(a, StringComparer.OrdinalIgnoreCase);
        string? Val(string a) { int i = Array.FindIndex(args, x => x.Equals(a, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var opt = new StartOptions
        {
            Demo = Has("--demo"), Minimized = Has("--minimized"), AutoStart = Has("--autostart"),
            Screenshot = Val("--screenshot"), ScreenshotTab = Val("--tab") ?? "live", ShotDelaySeconds = double.TryParse(Val("--shot-delay"), out var d) ? d : 2.5,
        };
        Application.Run(new MainForm(opt));
    }
}
