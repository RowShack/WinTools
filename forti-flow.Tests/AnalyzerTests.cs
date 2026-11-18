using FortiFlow.Core;

namespace FortiFlow.Tests;

public class AnalyzerTests
{
    static readonly RuleSet Rules = RuleSet.LoadDefault();

    internal static string Sample(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", name));
    internal static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", name));

    static AnalysisResult Small() => FlowAnalyzer.Analyze(Sample("gui-export-100-packets.csv"), Rules);
    static AnalysisResult Big() => FlowAnalyzer.Analyze(Sample("gui-export-1000-packets.csv"), Rules);

    [Fact]
    public void Sample100_HasExpectedPacketCount()
    {
        var r = Small();
        Assert.Equal(InputFormat.GuiCsv, r.Format);
        Assert.Equal(98, r.Packets.Count);
    }

    [Fact]
    public void Sample1000_HasExpectedPacketCount_AndIsFast()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = Big();
        sw.Stop();
        // 714 "received a packet" lines; plus one block whose header line is missing from the export itself
        Assert.Equal(714, r.Packets.Count(p => p.HasHeader));
        Assert.Equal(715, r.Packets.Count);
        Assert.True(sw.ElapsedMilliseconds < 3000, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void AllowedWithSnat_IsForwarded()
    {
        var r = Big();
        var p = r.Packets.First(x => x.Steps.Any(s => s.Title == "Source NAT") && x.Verdict == Verdict.Forwarded);
        Assert.True(p.IsFastPath);   // in the samples SNAT only shows on established (fast path) sessions
        Assert.NotNull(p.Deciding);
        // reply of the same session shows the NAT reversal, not a VIP
        var reply = r.Packets.First(x => x.SessionId == p.SessionId && x.Direction == "reply" && x.Steps.Any(s => s.Card == "nat"));
        Assert.Contains(reply.Steps, s => s.Title.StartsWith("NAT reversal"));
        Assert.Equal(Verdict.Forwarded, reply.Verdict);
    }

    [Fact]
    public void NewSessionAllowedByPolicy_IsForwarded_AndDecidedByAllowLine()
    {
        var p = Small().Packets.First(x => x.NewSession && x.Steps.Any(s => s.Card == "policy" && s.Title.StartsWith("Allowed by policy 281")));
        Assert.Equal(Verdict.Forwarded, p.Verdict);
        Assert.Equal("281", p.Policy);
        Assert.Equal("policy", p.Deciding!.Card); // the sample trace ends at "Allowed by Policy-281"
        Assert.Contains(p.Steps, s => s.Card == "route" && s.Title.Contains("Switch-Uplink"));
        Assert.Contains(p.Steps, s => s.Card == "policy-check" && s.Title.StartsWith("Policy 281 matched after checking 5 others"));
    }

    [Fact]
    public void HandWrittenAllowedPlusSnat_IsForwarded()
    {
        var p = FlowAnalyzer.Analyze(Fixture("cli-prefixed-handwritten.txt"), Rules).Packets[0];
        Assert.Equal(Verdict.Forwarded, p.Verdict);
        Assert.Contains(p.Steps, s => s.Title == "Allowed by policy 7");
        Assert.Contains(p.Steps, s => s.Card == "nat" && s.Detail.Contains("203.0.113.4:49152"));
    }

    [Fact]
    public void IpsecFlow_IsForwardedThroughTunnel()
    {
        var r = Big();
        var p = r.Packets.First(x => x.Steps.Any(s => s.Card == "ipsec" && s.Title.StartsWith("Enter IPsec tunnel VPN-SiteB")));
        Assert.Equal(Verdict.Forwarded, p.Verdict);
        Assert.Equal("VPN-SiteB", p.Tunnel);
        Assert.Contains(p.Steps, s => s.Card == "egress" && s.Title.Contains("VLAN3030"));
    }

    [Fact]
    public void NoSessionPacket_IsNotReportedAsDropped()
    {
        var r = Big().Packets.Concat(Small().Packets).Where(x => x.NoSession).ToList();
        Assert.NotEmpty(r);
        foreach (var p in r)
        {
            Assert.NotEqual(Verdict.Dropped, p.Verdict);
            Assert.Contains(p.Steps, s => s.Title == "No session matched");
        }
    }

    [Fact]
    public void LocalIn_FirstActDropLineDoesNotMeanDropped()
    {
        var r = Big();
        // packet to the FortiGate itself: route 'via root', check chain contains act-drop before the final accept
        var p = r.Packets.First(x => x.Dst == "10.0.200.10" && x.DstPort == "8443" && x.NewSession);
        Assert.Contains(p.Lines, l => l.Text.Contains("act-drop"));
        Assert.Equal("root", p.Egress);
        Assert.Equal(Verdict.LocalIn, p.Verdict);
        Assert.Contains("act-accept", p.Deciding!.Lines[0].Text);
        // and the reply arrives from 'local'
        var reply = r.Packets.First(x => x.SessionId == p.SessionId && x.Direction == "reply");
        Assert.Equal("local", reply.Iface);
        Assert.Equal(Verdict.Forwarded, reply.Verdict);
    }

    [Fact]
    public void LaterPacketsOfALocalInSession_AreLocalIn_NotUnknown()
    {
        var r = Big();
        var first = r.Packets.First(x => x.Egress == "root" && x.NewSession && x.Verdict == Verdict.LocalIn);
        var later = r.Packets.Where(x => x.SessionId == first.SessionId && x.Direction == "original" && x != first).ToList();
        Assert.NotEmpty(later);
        Assert.All(later, p => Assert.Equal(Verdict.LocalIn, p.Verdict));
    }

    [Fact]
    public void Requests_AndReplies_AreLinkedBySessionId()
    {
        var r = Small();
        var s = r.Sessions.First(x => x.Packets.Any(p => p.Direction == "original") && x.Packets.Any(p => p.Direction == "reply"));
        Assert.True(s.Packets.Select(p => p.Index).SequenceEqual(s.Packets.Select(p => p.Index).OrderBy(i => i)));
        Assert.All(s.Packets, p => Assert.Equal(s.Id, p.SessionId));
    }

    [Fact]
    public void PolicyChecks_AreCollapsedIntoOneCard()
    {
        var p = Small().Packets.First(x => x.Steps.Any(s => s.Card == "policy-check" && s.Children.Count > 3));
        var card = p.Steps.First(s => s.Card == "policy-check" && s.Children.Count > 3);
        Assert.Contains("matched after checking", card.Title);
    }

    [Fact]
    public void OffloadAttemptWithoutEgress_IsForwarded()
    {
        var p = Small().Packets.First(x => x.Steps.Any(s => s.Title.StartsWith("Offload attempt")) && x.Direction == "original" && !x.Steps.Any(s => s.Card == "egress"));
        Assert.Equal(Verdict.Forwarded, p.Verdict);
        Assert.Contains("NPU", p.VerdictTitle);
    }

    [Fact]
    public void FastPathPackets_AreFlagged()
    {
        var r = Small();
        Assert.Contains(r.Packets, p => p.IsFastPath && p.Verdict == Verdict.Forwarded);
    }

    [Fact]
    public void ExplicitDropMessage_WinsAndIsUnverified()
    {
        var r = FlowAnalyzer.Analyze(Fixture("cli-prefixed-handwritten.txt"), Rules);
        var denied = r.Packets.Single(p => p.DstPort == "22");
        Assert.Equal(Verdict.Dropped, denied.Verdict);
        Assert.True(denied.DecidedByUnverifiedRule);
        Assert.Contains("implicit deny", denied.Explanation, StringComparison.OrdinalIgnoreCase);
        var rpf = r.Packets.Single(p => p.DstPort == "25");
        Assert.Equal(Verdict.Dropped, rpf.Verdict);
        Assert.Contains("reverse path", rpf.Deciding!.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnknownLines_AreKeptRaw()
    {
        var r = FlowAnalyzer.Analyze(
            "vd-root:0 received a packet(proto=6, 192.0.2.1:1000->192.0.2.2:80) tun_id=0.0.0.0 from port1. flag [S], seq 1, ack 0, win 1\n" +
            "some brand new message 123\n", Rules);
        var p = Assert.Single(r.Packets);
        var unk = Assert.Single(p.Steps, s => s.Card == "unknown");
        Assert.Equal("some brand new message 123", unk.Lines[0].Text);
        Assert.Equal(1, r.UnknownLines);
    }

    [Fact]
    public async Task AnalyzeAsync_CanBeCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => FlowAnalyzer.AnalyzeAsync(Sample("gui-export-1000-packets.csv"), Rules, cts.Token));
    }
}
