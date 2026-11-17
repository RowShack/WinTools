using System.Net;
using System.Net.Sockets;
using PortProbe.Core;

namespace PortProbe.Tests;

public class PortSpecTests
{
    [Fact]
    public void ParsesMixedSpec()
    {
        Assert.True(PortSpecParser.TryParse("443, 8080-8082, udp:514, udp:1812-1813", out var s, out _));
        Assert.Equal(
            ["443", "8080", "8081", "8082", "udp:514", "udp:1812", "udp:1813"],
            s.Select(x => x.ToString()).ToArray());
    }

    [Fact] public void DefaultsToTcp_AndAcceptsExplicitTcpPrefix() { PortSpecParser.TryParse("tcp:22 TCP:23", out var s, out _); Assert.All(s, x => Assert.Equal(Proto.Tcp, x.Proto)); Assert.Equal(2, s.Count); }
    [Fact] public void DedupesRepeats() { PortSpecParser.TryParse("80,80,79-81", out var s, out _); Assert.Equal(3, s.Count); }
    [Fact] public void SameNumberDifferentProtocolsAreDistinct() { PortSpecParser.TryParse("53, udp:53", out var s, out _); Assert.Equal(2, s.Count); }

    [Theory]
    [InlineData("")] [InlineData("abc")] [InlineData("0")] [InlineData("65536")] [InlineData("90-80")] [InlineData("udp:")] [InlineData("1-70000")] [InlineData("80-")] [InlineData("-80")]
    public void RejectsBadInput(string text)
    {
        Assert.False(PortSpecParser.TryParse(text, out _, out var err));
        Assert.NotEmpty(err);
    }

    [Fact]
    public void RejectsHugeRanges()
    {
        Assert.False(PortSpecParser.TryParse("1-65535", out _, out var err));
        Assert.Contains("Too many", err);
    }

    [Fact]
    public void CompactMergesRanges()
    {
        PortSpecParser.TryParse("443, 8080-8090, 22, udp:514, udp:515", out var s, out _);
        Assert.Equal("22,443,8080-8090", PortSpecParser.Compact(s, Proto.Tcp));
        Assert.Equal("514-515", PortSpecParser.Compact(s, Proto.Udp));
        Assert.Equal("", PortSpecParser.Compact([], Proto.Tcp));
    }
}

public class LoopbackProbeTests
{
    private static readonly IPAddress Lo = IPAddress.Loopback;
    private static readonly ProbeOptions Opt = new() { Timeout = TimeSpan.FromMilliseconds(800), BannerWait = TimeSpan.FromMilliseconds(400) };

    // Windows reports a refused connection to a closed LOOPBACK port only after ~2 s (SYN retries); remote hosts answer at once.
    private static readonly ProbeOptions SlowRefuse = new() { Timeout = TimeSpan.FromSeconds(5) };

    private static int FreeTcpPort() { var l = new TcpListener(Lo, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    private static int FreeUdpPort() { using var u = new UdpClient(new IPEndPoint(Lo, 0)); return ((IPEndPoint)u.Client.LocalEndPoint!).Port; }

    [Fact]
    public async Task TcpListener_IsReportedAsOurListener_WithBanner()
    {
        int port = FreeTcpPort();
        using var l = new PortListener();
        Assert.Empty(l.Start([new PortSpec(Proto.Tcp, port)], Lo));
        var r = await Prober.ProbeTcpAsync(Lo, port, Opt, default);
        Assert.Equal(PortState.OpenListener, r.State);
        Assert.StartsWith("PORTPROBE", r.Banner);
    }

    [Fact]
    public async Task UdpListener_Echoes()
    {
        int port = FreeUdpPort();
        using var l = new PortListener();
        Assert.Empty(l.Start([new PortSpec(Proto.Udp, port)], Lo));
        var r = await Prober.ProbeUdpAsync(Lo, port, Opt, default);
        Assert.Equal(PortState.OpenListener, r.State);
    }

    [Fact]
    public async Task ClosedTcpPort_IsRefused_NotFiltered()
    {
        var r = await Prober.ProbeTcpAsync(Lo, FreeTcpPort(), SlowRefuse, default);
        Assert.Equal(PortState.Refused, r.State);
    }

    [Fact]
    public async Task ClosedUdpPort_IsRefusedViaIcmp()
    {
        var r = await Prober.ProbeUdpAsync(Lo, FreeUdpPort(), Opt, default);
        Assert.Equal(PortState.Refused, r.State);
    }

    [Fact]
    public async Task OtherTcpService_IsOpenOther_AndSilentServiceToo()
    {
        var silent = new TcpListener(Lo, 0); silent.Start();
        int port = ((IPEndPoint)silent.LocalEndpoint).Port;
        _ = Task.Run(async () => { using var c = await silent.AcceptTcpClientAsync(); await Task.Delay(1500); });
        var r = await Prober.ProbeTcpAsync(Lo, port, Opt, default);
        silent.Stop();
        Assert.Equal(PortState.OpenOther, r.State);
        Assert.Null(r.Banner);

        var talker = new TcpListener(Lo, 0); talker.Start();
        int p2 = ((IPEndPoint)talker.LocalEndpoint).Port;
        _ = Task.Run(async () => { using var c = await talker.AcceptTcpClientAsync(); await c.GetStream().WriteAsync("SSH-2.0-OpenSSH\r\n"u8.ToArray()); await Task.Delay(500); });
        var r2 = await Prober.ProbeTcpAsync(Lo, p2, Opt, default);
        talker.Stop();
        Assert.Equal(PortState.OpenOther, r2.State);
        Assert.Equal("SSH-2.0-OpenSSH", r2.Banner);
    }

    [Fact]
    public async Task UnroutableTarget_IsFilteredOrUnreachable_NeverOpen()
    {
        var r = await Prober.ProbeTcpAsync(IPAddress.Parse("192.0.2.1"), 80, new ProbeOptions { Timeout = TimeSpan.FromMilliseconds(400) }, default);
        Assert.True(r.State is PortState.Filtered or PortState.Unreachable, r.State.ToString());
    }

    [Fact]
    public async Task RunAsync_ReturnsResultsInInputOrder_AndHonoursParallelism()
    {
        int a = FreeTcpPort(), b = FreeTcpPort();
        using var l = new PortListener();
        l.Start([new PortSpec(Proto.Tcp, b)], Lo);
        var specs = new[] { new PortSpec(Proto.Tcp, a), new PortSpec(Proto.Tcp, b) };
        var res = await Prober.RunAsync(Lo, specs, new ProbeOptions { Timeout = TimeSpan.FromSeconds(5), Parallelism = 1 }, null, default);
        Assert.Equal([PortState.Refused, PortState.OpenListener], res.Select(r => r.State).ToArray());
    }

    [Fact]
    public void ListenerReportsPortInUse()
    {
        int port = FreeTcpPort();
        using var l1 = new PortListener(); using var l2 = new PortListener();
        l1.Start([new PortSpec(Proto.Tcp, port)], Lo);
        var fails = l2.Start([new PortSpec(Proto.Tcp, port)], Lo);
        Assert.Single(fails);
    }

    [Fact]
    public async Task ListenerEmitsEvents()
    {
        int port = FreeTcpPort();
        using var l = new PortListener();
        var got = new TaskCompletionSource<ListenerEvent>();
        l.Event += e => got.TrySetResult(e);
        l.Start([new PortSpec(Proto.Tcp, port)], Lo);
        await Prober.ProbeTcpAsync(Lo, port, Opt, default);
        var e = await got.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(port, e.Port);
        Assert.Contains("connection from", e.Message);
    }

    [Fact]
    public void EveryStateHasAnExplanation()
    {
        foreach (var p in Enum.GetValues<Proto>())
            foreach (var s in Enum.GetValues<PortState>())
                Assert.False(string.IsNullOrWhiteSpace(PortResult.Explain(p, s)));
    }
}
