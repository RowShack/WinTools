using FortiFlow.Core;

namespace FortiFlow.Tests;

public class CommandGeneratorTests
{
    [Fact]
    public void RefusesWithoutAnyFilter()
    {
        var r = CommandGenerator.Generate(new CommandRequest { Count = 50 });
        Assert.False(r.Ok);
        Assert.Contains("unfiltered", r.Error);
        Assert.Empty(r.Start);
    }

    [Fact]
    public void FullFilterSequence_IsInTheRightOrder()
    {
        var r = CommandGenerator.Generate(new CommandRequest
        {
            Vdom = "root", Source = "192.0.2.10", Destination = "198.51.100.5", Port = "443", Protocol = "tcp", Count = 30,
        });
        Assert.True(r.Ok);
        Assert.Equal(new[]
        {
            "# Multi-VDOM units: run this inside the VDOM first ('config vdom' then 'edit <name>').",
            "diagnose debug reset",
            "diagnose debug flow filter vd 0",
            "diagnose debug flow filter saddr 192.0.2.10",
            "diagnose debug flow filter daddr 198.51.100.5",
            "diagnose debug flow filter dport 443",
            "diagnose debug flow filter proto 6",
            "diagnose debug flow show function-name enable",
            "diagnose debug flow trace start 30",
            "diagnose debug enable",
        }, r.Start.ToArray());
        Assert.Equal(new[] { "diagnose debug disable", "diagnose debug reset" }, r.Stop.ToArray());
        Assert.NotEmpty(r.Warnings); // saddr+daddr hides replies
    }

    [Fact]
    public void SingleAddress_UsesAddr_AndPortScopes()
    {
        var r = CommandGenerator.Generate(new CommandRequest { Destination = "198.51.100.5", Port = "53", PortScope = PortScope.Either, Protocol = "udp" });
        Assert.True(r.Ok);
        Assert.Contains("diagnose debug flow filter addr 198.51.100.5", r.Start);
        Assert.Contains("diagnose debug flow filter port 53", r.Start);
        Assert.Contains("diagnose debug flow filter proto 17", r.Start);
        var one = CommandGenerator.Generate(new CommandRequest { Source = "192.0.2.1", BothDirections = false });
        Assert.Contains("diagnose debug flow filter saddr 192.0.2.1", one.Start);
    }

    [Theory]
    [InlineData("999.1.1.1", "", "", "")]
    [InlineData("", "not-an-ip", "", "")]
    [InlineData("192.0.2.1", "", "70000", "")]
    [InlineData("192.0.2.1", "", "", "banana")]
    public void InvalidInput_IsRejected(string src, string dst, string port, string proto)
    {
        var r = CommandGenerator.Generate(new CommandRequest { Source = src, Destination = dst, Port = port, Protocol = proto });
        Assert.False(r.Ok);
        Assert.NotEmpty(r.Error);
    }

    [Fact]
    public void ProtocolAloneCountsAsAFilter_AndVdomNameIsRejected()
    {
        Assert.True(CommandGenerator.Generate(new CommandRequest { Protocol = "icmp" }).Ok);
        Assert.False(CommandGenerator.Generate(new CommandRequest { Vdom = "customerA", Protocol = "icmp" }).Ok);
        Assert.True(CommandGenerator.Generate(new CommandRequest { Vdom = "3", Protocol = "icmp" }).Ok);
    }
}

public class ExporterTests
{
    static AnalysisResult Result() =>
        FlowAnalyzer.Analyze(AnalyzerTests.Fixture("cli-prefixed-handwritten.txt"), RuleSet.LoadDefault());

    [Fact]
    public void Csv_HasHeaderAndOneRowPerPacket()
    {
        var csv = Exporter.ToCsv(Result().Packets);
        var lines = csv.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("Packet,Time,TraceId", lines[0]);
        Assert.Equal(4, lines.Length);
        Assert.Contains("Dropped", lines[2]);
    }

    [Fact]
    public void TextAndHtml_ContainVerdictAndEncodeHtml()
    {
        var r = Result();
        var txt = Exporter.ToText(r.Packets);
        Assert.Contains("Verdict: Forwarded", txt);
        Assert.Contains("unverified", txt);
        var html = Exporter.ToHtml(r.Packets);
        Assert.Contains("<html", html);
        Assert.DoesNotContain("<script", html);
    }
}
