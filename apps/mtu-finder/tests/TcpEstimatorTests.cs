using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using MtuFinder.Core;

namespace MtuFinder.Tests;

/// <summary>Simulated TCP path: segments whose IP packet exceeds PathMtu are never acknowledged.</summary>
internal sealed class FakeTcpProbe(int pathMtu, int mss = 1460, bool refuse = false, bool resetOnData = false, bool blackhole = false, int optionBytes = 0) : ITcpPathProbe
{
    public int Calls;
    public Task<TcpProbeResult> ProbeAsync(IPEndPoint target, int payloadSize, TimeSpan timeout, CancellationToken ct)
    {
        Calls++;
        bool v6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        if (refuse) return Task.FromResult(new TcpProbeResult(TcpProbeStatus.ConnectFailed, Detail: "ConnectionRefused"));
        if (payloadSize == 0) return Task.FromResult(new TcpProbeResult(TcpProbeStatus.Delivered, mss, optionBytes));
        if (resetOnData) return Task.FromResult(new TcpProbeResult(TcpProbeStatus.Error, mss, optionBytes, "reset"));
        bool ok = !blackhole && payloadSize + optionBytes + TcpMtuEstimator.HeaderOverhead(v6) <= pathMtu;
        return Task.FromResult(new TcpProbeResult(ok ? TcpProbeStatus.Delivered : TcpProbeStatus.Stalled, mss, optionBytes));
    }
}

public class TcpEstimatorTests
{
    private static readonly IPAddress V4 = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress V6 = IPAddress.Parse("2001:db8::1");
    private static SearchOptions Fast() => new() { TriesPerSize = 2, Timeout = TimeSpan.FromMilliseconds(1), LocalMtu = 1500 };

    [Theory]
    [InlineData(1500)] [InlineData(1492)] [InlineData(1400)] [InlineData(1280)] [InlineData(700)]
    public async Task FindsMtu_WhenOversizeSegmentsAreDropped(int mtu)
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(mtu), Fast()).RunAsync(V4, 443);
        Assert.Equal(TcpEstimateOutcome.Estimated, r.Outcome);
        Assert.Equal(mtu, r.EstimatedMtu);
        Assert.Equal(mtu - 40, r.EstimatedMss);
        Assert.Contains(r.Notes, n => n.Contains("ESTIMATE"));
    }

    [Fact]
    public async Task FullSizeWorking_IsOneConnectPlusOneProbe()
    {
        var f = new FakeTcpProbe(1500);
        var r = await new TcpMtuEstimator(f, Fast()).RunAsync(V4, 80);
        Assert.Equal(1500, r.EstimatedMtu);
        Assert.Equal(2, f.Calls);
    }

    [Fact]
    public async Task IPv6_UsesLargerHeader()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1400, mss: 1440), Fast()).RunAsync(V6, 443);
        Assert.Equal(1400, r.EstimatedMtu);
        Assert.Equal(1340, r.EstimatedMss);
    }

    [Fact]
    public async Task TimestampOption_IsAccountedFor()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1400, optionBytes: 12), Fast()).RunAsync(V4, 443);
        Assert.Equal(1400, r.EstimatedMtu);
    }

    [Fact]
    public async Task SmallNegotiatedMss_IsCappedAndNoted()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1500, mss: 1360), Fast()).RunAsync(V4, 443);
        Assert.Equal(1400, r.EstimatedMtu);
        Assert.Contains(r.Notes, n => n.Contains("clamps MSS"));
    }

    [Fact]
    public async Task Refused_ReportsConnectFailed()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1500, refuse: true), Fast()).RunAsync(V4, 9);
        Assert.Equal(TcpEstimateOutcome.ConnectFailed, r.Outcome);
        Assert.Null(r.EstimatedMtu);
    }

    [Fact]
    public async Task ResetOnData_IsInconclusive()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1500, resetOnData: true), Fast()).RunAsync(V4, 443);
        Assert.Equal(TcpEstimateOutcome.Inconclusive, r.Outcome);
        Assert.Null(r.EstimatedMtu);
    }

    [Fact]
    public async Task NothingAcknowledged_IsInconclusive()
    {
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1500, blackhole: true), Fast()).RunAsync(V4, 443);
        Assert.Equal(TcpEstimateOutcome.Inconclusive, r.Outcome);
    }

    [Fact]
    public async Task Cancel_ReturnsCancelled()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        var r = await new TcpMtuEstimator(new FakeTcpProbe(1500), Fast()).RunAsync(V4, 443, null, cts.Token);
        Assert.Equal(TcpEstimateOutcome.Cancelled, r.Outcome);
    }

    [Fact]
    public void ParsesTcpInfoV0()
    {
        var b = new byte[TcpInfo.V0Size];
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(0), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 1460);
        b[16] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(28), 55);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(68), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(80), 2);
        var i = TcpInfo.ParseV0(b);
        Assert.Equal((4, 1460, true, 55u, 7u, 2u), (i.State, i.Mss, i.TimestampsEnabled, i.BytesInFlight, i.BytesRetrans, i.TimeoutEpisodes));
    }

    /// <summary>Real sockets on loopback: proves SIO_TCP_INFO works on this OS and a segment is ACKed. Skipped off Windows.</summary>
    [Fact]
    public async Task RealProbe_Loopback_ReadsMssAndSeesAck()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        _ = Task.Run(async () => { while (true) { var c = await l.AcceptTcpClientAsync(); _ = Task.Run(async () => { var buf = new byte[65536]; try { while (await c.GetStream().ReadAsync(buf) > 0) { } } catch { } }); } });
        var ep = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)l.LocalEndpoint).Port);
        var p = new TcpPathProbe();
        var c0 = await p.ProbeAsync(ep, 0, TimeSpan.FromSeconds(2), default);
        Console.WriteLine($"loopback connect: {c0}");
        Assert.Equal(TcpProbeStatus.Delivered, c0.Status);
        Assert.True(c0.Mss > 500, $"mss {c0.Mss}");
        var d = await p.ProbeAsync(ep, 1000, TimeSpan.FromSeconds(2), default);
        Console.WriteLine($"loopback 1000: {d}");
        Assert.Equal(TcpProbeStatus.Delivered, d.Status);
        var r = await new TcpMtuEstimator(p, new SearchOptions { Timeout = TimeSpan.FromSeconds(1), LocalMtu = 65535 }).RunAsync(IPAddress.Loopback, ep.Port);
        Console.WriteLine($"loopback estimate: {r.Outcome} mss={r.NegotiatedMss} mtu={r.EstimatedMtu}");
        Assert.Equal(TcpEstimateOutcome.Estimated, r.Outcome);
    }

    [Fact]
    public async Task RealProbe_ClosedPort_ConnectFailed()
    {
        if (!OperatingSystem.IsWindows()) return;
        int port; using (var l = new TcpListener(IPAddress.Loopback, 0)) { l.Start(); port = ((IPEndPoint)l.LocalEndpoint).Port; }
        var r = await new TcpPathProbe().ProbeAsync(new IPEndPoint(IPAddress.Loopback, port), 0, TimeSpan.FromSeconds(2), default);
        Assert.Equal(TcpProbeStatus.ConnectFailed, r.Status);
    }
}
