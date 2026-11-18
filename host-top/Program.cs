namespace HostTop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        bool demo = args.Contains("--demo", StringComparer.OrdinalIgnoreCase);
        int si = Array.FindIndex(args, a => a.Equals("--screenshot", StringComparison.OrdinalIgnoreCase));
        string? shot = si >= 0 && si + 1 < args.Length ? args[si + 1] : null;
        Application.Run(new MainForm(demo, shot));
    }
}
