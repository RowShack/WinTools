using System.Runtime.InteropServices;

namespace DhcpFinder;

internal static class Program
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Contains("--cli", StringComparer.OrdinalIgnoreCase))
        {
            AttachConsole(-1);
            return RunCli(args).GetAwaiter().GetResult();
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    // Usage: DhcpFinder.exe --cli [--seconds N] [--random-mac]
    private static async Task<int> RunCli(string[] args)
    {
        int secs = 5;
        int idx = Array.FindIndex(args, a => a.Equals("--seconds", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < args.Length) int.TryParse(args[idx + 1], out secs);
        bool randomMac = args.Contains("--random-mac", StringComparer.OrdinalIgnoreCase);

        Console.WriteLine();
        var adapters = DhcpScanner.GetAdapters();
        var tasks = adapters.Select(a => DhcpScanner.ProbeAsync(a, TimeSpan.FromSeconds(secs), randomMac, 3,
            Console.WriteLine, CancellationToken.None));
        var offers = (await Task.WhenAll(tasks)).SelectMany(x => x).ToList();

        Console.WriteLine();
        Console.WriteLine($"Found {offers.Select(o => o.ServerId).Distinct().Count()} DHCP server(s):");
        foreach (var o in offers)
            Console.WriteLine($"  {o.ServerId,-16} on {o.Adapter}  offered {o.OfferedIp}  gw {string.Join(",", o.Routers)}  dns {string.Join(",", o.DnsServers)}");
        return 0;
    }
}
