using System.Net;
using HostTop.Core;

namespace HostTop;

/// <summary>Fake traffic for UI testing (<c>host-top.exe --demo</c>): no ETW session is started.</summary>
public sealed class DemoTraffic : IProcessResolver
{
    private sealed record Flow(int Pid, FlowProtocol P, string Local, int LPort, string Remote, int RPort, double Down, double Up);

    private static readonly Dictionary<int, (string Name, string Path)> Procs = new()
    {
        [4] = ("System", ""),
        [1204] = ("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        [2310] = ("Teams.exe", @"C:\Users\demo\AppData\Local\Microsoft\Teams\Teams.exe"),
        [3380] = ("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe"),
        [880] = ("svchost.exe", @"C:\Windows\System32\svchost.exe"),
        [5120] = ("mstsc.exe", @"C:\Windows\System32\mstsc.exe"),
        [6044] = ("Code.exe", @"C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    };

    private static readonly Flow[] Flows =
    [
        new(1204, FlowProtocol.Tcp, "192.168.1.23", 50412, "142.250.180.78", 443, 900_000, 40_000),
        new(1204, FlowProtocol.Udp, "192.168.1.23", 51000, "142.250.180.100", 443, 400_000, 20_000),
        new(1204, FlowProtocol.Tcp, "192.168.1.23", 50420, "151.101.1.69", 443, 250_000, 8_000),
        new(2310, FlowProtocol.Udp, "192.168.1.23", 50001, "52.114.132.20", 3478, 120_000, 110_000),
        new(3380, FlowProtocol.Tcp, "192.168.1.23", 50500, "13.107.42.12", 443, 60_000, 1_400_000),
        new(880, FlowProtocol.Tcp, "192.168.1.23", 50600, "20.190.151.9", 443, 30_000, 4_000),
        new(880, FlowProtocol.Udp, "192.168.1.23", 50700, "192.168.1.1", 53, 3_000, 1_000),
        new(4, FlowProtocol.Tcp, "192.168.1.23", 50800, "192.168.1.20", 445, 2_800_000, 150_000),
        new(5120, FlowProtocol.Tcp, "192.168.1.23", 50900, "10.20.0.15", 3389, 500_000, 25_000),
        new(6044, FlowProtocol.Tcp, "192.168.1.23", 51100, "140.82.112.4", 443, 80_000, 12_000),
        new(6044, FlowProtocol.Tcp, "::1", 51200, "::1", 9229, 20_000, 20_000),
        new(1204, FlowProtocol.Tcp, "2001:db8::23", 51300, "2606:4700::6810:84e5", 443, 150_000, 6_000),
    ];

    private readonly Random _rnd = new(7);

    public ProcIdentity Resolve(int pid) => Procs.TryGetValue(pid, out var p) ? new ProcIdentity(pid, 1, p.Name, p.Path.Length == 0 ? null : p.Path) : new ProcIdentity(pid, 1, $"PID {pid}", null);

    public static Task<string?> FakeDns(IPAddress ip, CancellationToken ct) => Task.FromResult<string?>(ip.ToString() switch
    {
        "142.250.180.78" => "ams15s48-in-f14.1e100.net", "151.101.1.69" => "cdn.stackoverflow.com", "52.114.132.20" => "teams.microsoft.com",
        "13.107.42.12" => "onedrive.live.com", "192.168.1.20" => "fileserver.lan", "10.20.0.15" => "jump01.corp.example", "140.82.112.4" => "lb-140-82-112-4-iad.github.com",
        _ => null,
    });

    /// <summary>Generates roughly 100 ms worth of traffic for every flow.</summary>
    public void Pump(FlowAggregator agg)
    {
        double t = Environment.TickCount64 / 1000.0;
        foreach (var f in Flows)
        {
            double wave = 0.55 + 0.45 * Math.Sin(t / 3 + f.LPort);
            double jitter = 0.7 + _rnd.NextDouble() * 0.6;
            long down = (long)(f.Down * wave * jitter / 10), up = (long)(f.Up * wave * jitter / 10);
            var l = IPAddress.Parse(f.Local); var r = IPAddress.Parse(f.Remote);
            if (down > 0) agg.Add(new FlowEvent(DateTime.Now, f.Pid, f.P, l, f.LPort, r, f.RPort, down, false));
            if (up > 0) agg.Add(new FlowEvent(DateTime.Now, f.Pid, f.P, l, f.LPort, r, f.RPort, up, true));
        }
    }
}
