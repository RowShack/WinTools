using System.Net;
using MtuFinder.Core;

namespace MtuFinder.Tests;

/// <summary>Manual check against the real network. Set WINTOOLS_LIVE=1 to run.</summary>
public class LiveSmoke
{
    [Fact]
    public async Task Live()
    {
        if (Environment.GetEnvironmentVariable("WINTOOLS_LIVE") != "1") return;
        var big = await new IcmpProbe().SendAsync(IPAddress.Parse("8.8.8.8"), 1473, TimeSpan.FromSeconds(2), default);
        Console.WriteLine($"oversize 1473 DF: {big.Status} mtu={big.ReportedMtu} {big.Detail}");
        foreach (var t in new[] { "8.8.8.8", "2001:4860:4860::8888", "127.0.0.1" })
        {
            var ip = IPAddress.Parse(t);
            var ifc = NetInfo.InterfaceFor(ip);
            var r = await new MtuSearcher(new IcmpProbe(ifc?.Address),
                new SearchOptions { LocalMtu = ifc?.Mtu, Timeout = TimeSpan.FromMilliseconds(1200) }).RunAsync(ip);
            Console.WriteLine($"{t}: {r.Outcome} mtu={r.PathMtu} local={ifc?.Mtu} ({ifc})");
            foreach (var a in r.Attempts.TakeLast(6)) Console.WriteLine("   " + a);
            foreach (var n in r.Notes) Console.WriteLine("   NOTE " + n);
        }
    }
}
