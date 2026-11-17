using System.Net;
using MtuFinder.Core;

namespace MtuFinder.Tests;

/// <summary>Simulated path: packets larger than PathMtu fail either with 'too big' or silently.</summary>
internal sealed class FakeProbe(int pathMtu, bool silentDrop = false, bool reportMtu = false, bool blockAll = false, Func<int, bool>? lose = null) : IEchoProbe
{
    public int Sent;
    public Task<ProbeResult> SendAsync(IPAddress target, int payloadSize, TimeSpan timeout, CancellationToken ct)
    {
        Sent++;
        bool v6 = target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        int total = payloadSize + MtuSearcher.HeaderOverhead(v6);
        if (blockAll) return Task.FromResult(new ProbeResult(ProbeStatus.TimedOut));
        if (lose?.Invoke(Sent) == true) return Task.FromResult(new ProbeResult(ProbeStatus.TimedOut));
        if (total > pathMtu)
            return Task.FromResult(silentDrop ? new ProbeResult(ProbeStatus.TimedOut)
                : new ProbeResult(ProbeStatus.PacketTooBig, null, reportMtu ? pathMtu : null));
        return Task.FromResult(new ProbeResult(ProbeStatus.Success, 5));
    }
}

public class SearcherTests
{
    private static readonly IPAddress V4 = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress V6 = IPAddress.Parse("2001:db8::1");

    private static SearchOptions Fast(int? localMtu = null) => new() { TriesPerSize = 3, Timeout = TimeSpan.FromMilliseconds(1), LocalMtu = localMtu };

    [Theory]
    [InlineData(1500)] [InlineData(1492)] [InlineData(1400)] [InlineData(1350)] [InlineData(1280)] [InlineData(1000)] [InlineData(576)]
    public async Task FindsExactMtu_WhenRoutersReplyTooBig(int mtu)
    {
        var r = await new MtuSearcher(new FakeProbe(mtu), Fast()).RunAsync(V4);
        Assert.Equal(MtuOutcome.Found, r.Outcome);
        Assert.Equal(mtu, r.PathMtu);
        Assert.Equal(mtu - 28, r.MaxPayload);
        Assert.Equal(mtu - 40, r.RecommendedMss);
        Assert.False(r.SilentDropSuspected);
    }

    [Theory]
    [InlineData(1500)] [InlineData(1438)] [InlineData(1280)]
    public async Task FindsExactMtu_IPv6(int mtu)
    {
        var r = await new MtuSearcher(new FakeProbe(mtu), Fast()).RunAsync(V6);
        Assert.Equal(mtu, r.PathMtu);
        Assert.Equal(mtu - 60, r.RecommendedMss);
    }

    [Theory]
    [InlineData(1492)] [InlineData(1401)] [InlineData(700)]
    public async Task FindsExactMtu_WhenOversizedPacketsAreSilentlyDropped(int mtu)
    {
        var r = await new MtuSearcher(new FakeProbe(mtu, silentDrop: true), Fast()).RunAsync(V4);
        Assert.Equal(mtu, r.PathMtu);
        Assert.True(r.SilentDropSuspected);
        Assert.Contains(r.Notes, n => n.Contains("black hole", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UsesReportedMtu_ToNeedFewerProbes()
    {
        var withHint = new FakeProbe(1400, reportMtu: true);
        var without = new FakeProbe(1400);
        var a = await new MtuSearcher(withHint, Fast()).RunAsync(V4);
        var b = await new MtuSearcher(without, Fast()).RunAsync(V4);
        Assert.Equal(1400, a.PathMtu); Assert.Equal(1400, b.PathMtu);
        Assert.True(withHint.Sent < without.Sent);
    }

    [Fact]
    public async Task IgnoresNonsenseReportedMtu_AndStillTerminates()
    {
        // Router claims an MTU larger than what failed: must not loop.
        var probe = new LyingProbe();
        var r = await new MtuSearcher(probe, Fast()).RunAsync(V4);
        Assert.Equal(MtuOutcome.Found, r.Outcome);
        Assert.Equal(1300, r.PathMtu);
    }

    private sealed class LyingProbe : IEchoProbe
    {
        public Task<ProbeResult> SendAsync(IPAddress t, int size, TimeSpan to, CancellationToken ct) =>
            Task.FromResult(size + 28 <= 1300 ? new ProbeResult(ProbeStatus.Success, 1) : new ProbeResult(ProbeStatus.PacketTooBig, null, 9000));
    }

    [Fact]
    public async Task ReportsNoReply_WhenIcmpBlocked_NotAWrongMtu()
    {
        var r = await new MtuSearcher(new FakeProbe(1500, blockAll: true), Fast()).RunAsync(V4);
        Assert.Equal(MtuOutcome.NoReply, r.Outcome);
        Assert.Null(r.PathMtu);
        Assert.Null(r.RecommendedMss);
    }

    [Fact]
    public async Task PacketLoss_IsNotMistakenForMtuLimit()
    {
        // Every 2nd packet is lost; with 3 tries per size the true MTU must still be found.
        var r = await new MtuSearcher(new FakeProbe(1450, lose: n => n % 2 == 0), Fast()).RunAsync(V4);
        Assert.Equal(1450, r.PathMtu);
    }

    [Fact]
    public async Task LocalMtuCapsTheSearch_AndSupportsJumboFrames()
    {
        var r = await new MtuSearcher(new FakeProbe(9000), Fast(localMtu: 9000)).RunAsync(V4);
        Assert.Equal(9000, r.PathMtu);
        var small = new FakeProbe(1500);
        var r2 = await new MtuSearcher(small, Fast(localMtu: 1400)).RunAsync(V4);
        Assert.Equal(1400, r2.PathMtu);
    }

    [Fact]
    public async Task UnreachableBaseline_IsReported()
    {
        var r = await new MtuSearcher(new UnreachableProbe(), Fast()).RunAsync(V4);
        Assert.Equal(MtuOutcome.Unreachable, r.Outcome);
    }

    private sealed class UnreachableProbe : IEchoProbe
    {
        public Task<ProbeResult> SendAsync(IPAddress t, int s, TimeSpan to, CancellationToken ct) => Task.FromResult(new ProbeResult(ProbeStatus.Unreachable));
    }

    [Fact]
    public async Task Cancellation_ReturnsCancelled()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        var r = await new MtuSearcher(new FakeProbe(1500), Fast()).RunAsync(V4, null, cts.Token);
        Assert.Equal(MtuOutcome.Cancelled, r.Outcome);
    }

    [Fact]
    public void MssAndOverheadMaths()
    {
        Assert.Equal(1460, MtuSearcher.MssFor(1500, false));
        Assert.Equal(1440, MtuSearcher.MssFor(1500, true));
        Assert.Equal(28, MtuSearcher.HeaderOverhead(false));
        Assert.Equal(48, MtuSearcher.HeaderOverhead(true));
    }
}
