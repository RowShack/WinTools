using FortiFlow.Core;

namespace FortiFlow.Tests;

public class InputFormatTests
{
    static readonly RuleSet Rules = RuleSet.LoadDefault();

    [Fact]
    public void CliPrefixed_GroupsByTraceId()
    {
        var r = FlowAnalyzer.Analyze(AnalyzerTests.Fixture("cli-prefixed-handwritten.txt"), Rules);
        Assert.Equal(InputFormat.CliPrefixed, r.Format);
        Assert.Equal(3, r.Packets.Count);
        Assert.Equal(new int?[] { 1, 2, 3 }, r.Packets.Select(p => p.TraceId).ToArray());
        var p1 = r.Packets[0];
        Assert.Equal(Verdict.Forwarded, p1.Verdict);
        Assert.Equal("192.0.2.10", p1.Src);
        Assert.Equal("443", p1.DstPort);
        Assert.Contains(p1.Steps, s => s.Title == "Source NAT");
        Assert.Equal("2026-11-18 10:00:01", p1.Time);
    }

    [Fact]
    public void CliPlain_SplitsAtReceivedLine_AndLinksReply()
    {
        var r = FlowAnalyzer.Analyze(AnalyzerTests.Fixture("cli-plain-handwritten.txt"), Rules);
        Assert.Equal(InputFormat.CliPlain, r.Format);
        Assert.Equal(2, r.Packets.Count);
        Assert.Equal("ICMP", r.Packets[0].ProtoName);
        var s = Assert.Single(r.Sessions);
        Assert.Equal("0000b001", s.Id);
        Assert.Equal(new[] { "original", "reply" }, s.Packets.Select(p => p.Direction).ToArray());
        Assert.All(r.Packets, p => Assert.Equal(Verdict.Forwarded, p.Verdict));
    }

    [Fact]
    public void Noise_Crlf_Timestamps_AndPrompts_AreTolerated()
    {
        var text = "FGT # diagnose debug enable\r\n\r\n" +
                   "[10:00:01] vd-root received a packet(proto=17, 192.0.2.1:5000->198.51.100.9:53) from port1.\r\n" +
                   "10:00:01.123 allocate a new session-000000ff\r\n" +
                   "\x1b[0mfind a route: flag=00000000 gw-198.51.100.1 via port2\r\n" +
                   "--More--\r\n" +
                   "Allowed by Policy-3:\r\n" +
                   "send out via dev-port2, dst-mac-00:00:5e:00:53:01\r\n" +
                   "FGT # \r\n";
        var r = FlowAnalyzer.Analyze(text, Rules);
        var p = Assert.Single(r.Packets);
        Assert.Equal("UDP", p.ProtoName);
        Assert.Equal("53", p.DstPort);
        Assert.Equal(Verdict.Forwarded, p.Verdict);
        Assert.Equal(0, r.UnknownLines);
    }

    [Fact]
    public void WrappedPrefixedLine_IsJoined()
    {
        var text = "id=20085 trace_id=7 func=print_pkt_detail line=5842 msg=\"vd-root:0 received a packet(proto=6, 192.0.2.10:49152->198.51.100.5:\n" +
                   "443) tun_id=0.0.0.0 from port2. flag [S], seq 1, ack 0, win 8192\"\n" +
                   "id=20085 trace_id=7 func=x line=1 msg=\"send out via dev-port1, dst-mac-00:00:5e:00:53:01\"\n";
        var r = FlowAnalyzer.Analyze(text, Rules);
        var p = Assert.Single(r.Packets);
        Assert.Equal("443", p.DstPort);
        Assert.Equal(Verdict.Forwarded, p.Verdict);
    }

    [Fact]
    public void InterleavedTraceIds_AreSeparated()
    {
        var text =
            "id=1 trace_id=1 func=a line=1 msg=\"vd-root:0 received a packet(proto=6, 192.0.2.1:1->192.0.2.2:80) from p1. flag [S], seq 1, ack 0, win 1\"\n" +
            "id=1 trace_id=2 func=a line=1 msg=\"vd-root:0 received a packet(proto=6, 192.0.2.3:1->192.0.2.4:80) from p1. flag [S], seq 1, ack 0, win 1\"\n" +
            "id=1 trace_id=1 func=a line=2 msg=\"send out via dev-p2, dst-mac-00:00:5e:00:53:01\"\n" +
            "id=1 trace_id=2 func=a line=2 msg=\"reverse path check fail, drop\"\n";
        var r = FlowAnalyzer.Analyze(text, Rules);
        Assert.Equal(2, r.Packets.Count);
        Assert.Equal(Verdict.Forwarded, r.Packets[0].Verdict);
        Assert.Equal(Verdict.Dropped, r.Packets[1].Verdict);
    }

    [Fact]
    public void EmptyOrGarbageInput_DoesNotThrow()
    {
        Assert.Empty(FlowAnalyzer.Analyze("", Rules).Packets);
        var r = FlowAnalyzer.Analyze("hello\nworld\n", Rules);
        Assert.Equal(2, r.UnknownLines);
    }
}

public class RulesTests
{
    [Fact]
    public void EmbeddedRules_Load_AndAreWellFormed()
    {
        var set = RuleSet.LoadDefault();
        Assert.Empty(set.Messages);
        Assert.True(set.Rules.Count > 30);
        Assert.All(set.Rules, r => Assert.NotNull(r.Regex));
        Assert.Contains(set.Rules, r => !r.Verified);
        Assert.All(set.Rules.Where(r => r.Verified), r => Assert.NotEmpty(r.Versions ?? Array.Empty<string>()));
        Assert.All(set.Rules.Where(r => !r.Verified), r => Assert.Contains(r.Effect, new[] { "drop", "none" }));
        foreach (var k in new[] { "forwarded", "dropped", "local-in", "unknown" }) Assert.True(set.Verdicts.ContainsKey(k));
    }

    static string TempFile(string content)
    {
        var p = Path.Combine(Path.GetTempPath(), "fortiflow-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public void BrokenJson_FallsBackToEmbedded_WithMessage()
    {
        var f = TempFile("{ this is not json");
        try
        {
            var set = RuleSet.Load(f);
            Assert.Equal(RuleSet.LoadDefault().Rules.Count, set.Rules.Count);
            Assert.Contains(set.Messages, m => m.Contains("not usable"));
            Assert.Contains(set.Messages, m => m.Contains("invalid JSON"));
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void MissingFile_FallsBack()
    {
        var set = RuleSet.Load(Path.Combine(Path.GetTempPath(), "does-not-exist-fortiflow.json"));
        Assert.True(set.Rules.Count > 30);
        Assert.NotEmpty(set.Messages);
    }

    [Fact]
    public void BadRegex_SkipsOnlyThatRule()
    {
        var f = TempFile("""{"rules":[{"id":"bad","pattern":"([unclosed","card":"info","title":"x"},{"id":"good","pattern":"^custom thing (?<n>\\d+)","card":"info","title":"Custom {n}"}]}""");
        try
        {
            var set = RuleSet.Load(f);
            Assert.DoesNotContain(set.Rules, r => r.Id == "bad");
            Assert.Equal("good", set.Rules[0].Id);          // override rules are tried first
            Assert.Contains(set.Messages, m => m.Contains("'bad'"));
            var r = FlowAnalyzer.Analyze("vd-root:0 received a packet(proto=6, 192.0.2.1:1->192.0.2.2:80) from p1. flag [S], seq 1, ack 0, win 1\ncustom thing 42\n", set);
            Assert.Contains(r.Packets[0].Steps, s => s.Title == "Custom 42");
            Assert.Equal(0, r.UnknownLines);
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void OverrideRule_WithSameId_ReplacesBuiltIn()
    {
        var f = TempFile("""{"rules":[{"id":"send-out","pattern":"^send out via dev-(?<dev>[^,\\s]+)","card":"egress","title":"MY EGRESS {dev}","effect":"forward"}]}""");
        try
        {
            var set = RuleSet.Load(f);
            Assert.Single(set.Rules, r => r.Id == "send-out");
            var r = FlowAnalyzer.Analyze("vd-root:0 received a packet(proto=6, 192.0.2.1:1->192.0.2.2:80) from p1. flag [S], seq 1, ack 0, win 1\nsend out via dev-port9, dst-mac-00:00:5e:00:53:01\n", set);
            Assert.Contains(r.Packets[0].Steps, s => s.Title == "MY EGRESS port9");
        }
        finally { File.Delete(f); }
    }
}
