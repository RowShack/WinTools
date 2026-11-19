using PktmonGui.Core;

namespace PktmonGui.Tests;

public class FilterTests
{
    [Fact]
    public void BuildsFullCommand()
    {
        var f = new FilterSpec { Name = "web", Protocol = "TCP", Ip1 = "10.0.0.5", Port1 = "443", Mac1 = "00-11-22-33-44-55", Vlan = "20", DataLink = "IPv4" };
        Assert.Equal("filter add web -m 00-11-22-33-44-55 -v 20 -d IPv4 -t TCP -i 10.0.0.5 -p 443", f.ToArguments(0));
    }

    [Fact] public void TwoIpsAndPortsAreBothPassed() =>
        Assert.Equal("filter add F1 -t UDP -i 10.0.0.1 10.0.0.2 -p 53 5353", new FilterSpec { Protocol = "UDP", Ip1 = "10.0.0.1", Ip2 = "10.0.0.2", Port1 = "53", Port2 = "5353" }.ToArguments(0));

    [Fact] public void NamesWithSpacesAreQuoted_AndUnsafeCharactersRemoved()
    {
        Assert.Equal("\"my filter\"", FilterSpec.Quote("my filter"));
        Assert.DoesNotContain("&", FilterSpec.Quote("a & b | c \" d"));
        Assert.DoesNotContain("\"\"", FilterSpec.Quote("\"\""));
        Assert.Equal("___", FilterSpec.Quote("***"));
        Assert.Equal("filter", FilterSpec.Quote("   "));
    }

    [Theory]
    [InlineData("10.0.0.0/24", true)] [InlineData("2001:db8::1", true)] [InlineData("2001:db8::/64", true)] [InlineData("10.0.0.0/33", false)]
    [InlineData("300.1.1.1", false)] [InlineData("abc", false)] [InlineData("fe80::1%5", false)] [InlineData("10.0.0.1; calc", false)]
    public void IpValidation(string ip, bool valid) =>
        Assert.Equal(valid, new FilterSpec { Ip1 = ip }.Validate() == null);

    [Theory]
    [InlineData("0", false)] [InlineData("65536", false)] [InlineData("x", false)] [InlineData("1", true)] [InlineData("65535", true)]
    public void PortValidation(string port, bool valid) =>
        Assert.Equal(valid, new FilterSpec { Protocol = "TCP", Port1 = port }.Validate() == null);

    [Fact] public void PortsNeedTcpOrUdp() => Assert.NotNull(new FilterSpec { Port1 = "80" }.Validate());
    [Fact] public void EmptyFilterRejected() => Assert.NotNull(new FilterSpec().Validate());
    [Fact] public void SecondValueNeedsFirst() { Assert.NotNull(new FilterSpec { Ip2 = "1.1.1.1" }.Validate()); Assert.NotNull(new FilterSpec { Protocol = "TCP", Port2 = "80" }.Validate()); }
    [Theory] [InlineData("00-11-22-33-44-55", true)] [InlineData("00:11:22:33:44:55", true)] [InlineData("001122334455", true)] [InlineData("00-11-22", false)] [InlineData("zz-11-22-33-44-55", false)]
    public void MacValidation(string mac, bool valid) => Assert.Equal(valid, new FilterSpec { Mac1 = mac }.Validate() == null);
    [Theory] [InlineData("0", true)] [InlineData("4095", true)] [InlineData("4096", false)] [InlineData("-1", false)]
    public void VlanValidation(string v, bool valid) => Assert.Equal(valid, new FilterSpec { Vlan = v }.Validate() == null);
    [Fact] public void ToArgumentsThrowsWhenInvalid() => Assert.Throws<ArgumentException>(() => new FilterSpec { Ip1 = "nope" }.ToArguments(0));

    [Fact]
    public void AllPresetsProduceValidFilters()
    {
        foreach (var name in FilterSpec.Presets.Names)
        {
            var list = FilterSpec.Presets.Get(name, "10.1.1.1");
            Assert.NotEmpty(list);
            Assert.True(list.Count <= FilterSpec.MaxFilters);
            for (int i = 0; i < list.Count; i++) Assert.Null(list[i].Validate());
        }
    }
}

public class CommandTests
{
    private static readonly PktmonFeatures F = PktmonFeatures.All;

    [Fact]
    public void DefaultsToNicsAndFullPackets()
    {
        string a = CommandBuilder.StartArguments(new CaptureOptions { EtlPath = @"C:\caps\a.etl" }, F, out var skipped);
        Assert.Equal("start --capture --comp nics --pkt-size 0 --file-name \"C:\\caps\\a.etl\" --file-size 512 --log-mode circular", a);
        Assert.Empty(skipped);
    }

    [Fact]
    public void ExplicitComponentsAndDropsOnly()
    {
        var o = new CaptureOptions { ComponentIds = [7, 12], Type = CaptureType.Drop, PacketSize = null, LogMode = LogMode.MultiFile, FileSizeMb = 100 };
        string a = CommandBuilder.StartArguments(o, F, out _);
        Assert.Contains("--comp 7 12", a); Assert.Contains("--type drop", a); Assert.DoesNotContain("--pkt-size", a); Assert.Contains("--log-mode multi-file", a);
    }

    [Fact]
    public void OlderBuildsSkipUnsupportedFlags_AndSayWhich()
    {
        var old = new PktmonFeatures(false, false, false, false, false, false);
        string a = CommandBuilder.StartArguments(new CaptureOptions { Type = CaptureType.Drop }, old, out var skipped);
        Assert.DoesNotContain("--comp", a); Assert.DoesNotContain("--pkt-size", a); Assert.DoesNotContain("--log-mode", a); Assert.DoesNotContain("--type", a);
        Assert.True(skipped.Count >= 4);
    }

    [Fact]
    public void FeatureDetectionFromHelpText()
    {
        var f = PktmonFeatures.FromHelp("start etl2pcap etl2txt", "--pkt-size --log-mode --comp --type", "pktmon list --json");
        Assert.True(f.Etl2Pcap && f.PktSize && f.LogMode && f.CompSelector && f.TypeSelector && f.Json);
        var g = PktmonFeatures.FromHelp("start etl2txt", "--comp", "pktmon list");
        Assert.False(g.Etl2Pcap); Assert.False(g.PktSize); Assert.True(g.CompSelector); Assert.False(g.Json);
    }

    [Fact]
    public void PreviewIncludesCleanupAndConversion()
    {
        var cmds = CommandBuilder.Preview(new CaptureOptions { EtlPath = @"C:\c\x.etl", ConvertToText = true }, [new FilterSpec { Protocol = "TCP", Port1 = "443" }], F);
        Assert.Equal("pktmon filter remove", cmds[0]);
        Assert.Contains(cmds, c => c.StartsWith("pktmon filter add"));
        Assert.Contains(cmds, c => c.Contains("etl2pcap") && c.Contains("x.pcapng"));
        Assert.Contains(cmds, c => c.Contains("etl2txt") && c.Contains("x.txt"));
        Assert.Equal("pktmon filter remove", cmds[^1]);
        Assert.True(cmds.IndexOf("pktmon stop") > cmds.FindIndex(c => c.StartsWith("pktmon start")));
    }

    [Fact]
    public void RemoteScript_AlwaysCleansUpInFinally()
    {
        string s = CommandBuilder.RemoteScript(new CaptureOptions(), [new FilterSpec { Protocol = "UDP", Port1 = "53" }], F, 30);
        Assert.Contains("try {", s);
        Assert.Contains("} finally {", s);
        Assert.True(s.IndexOf("pktmon stop") > s.IndexOf("finally"));
        Assert.Contains("Start-Sleep -Seconds 30", s);
        Assert.Contains("--file-name $etl", s);
        Assert.Contains("filter add", s);
    }
}

public class ParserTests
{
    [Fact]
    public void ParsesJsonComponentsWithNestedGroups()
    {
        const string json = """
        [{"Type":"Network Adapter","Components":[
          {"Id":7,"Name":"Ethernet 2","Properties":[{"Name":"MAC Address","Value":"AA-BB-CC-00-11-22"},{"Name":"IP","Value":"192.168.1.10"}]},
          {"Id":9,"Name":"Wi-Fi","Properties":[]}]},
         {"Type":"Protocol","Components":[{"Id":20,"Name":"TCPIP"}]}]
        """;
        var c = Parsers.ParseComponents(json);
        Assert.Equal([7, 9, 20], c.Select(x => x.Id).ToArray());
        Assert.Equal("AA-BB-CC-00-11-22", c[0].Mac);
        Assert.Equal("192.168.1.10", c[0].Ip);
        Assert.Equal("Network Adapter", c[0].Type);
        Assert.Equal("Protocol", c[2].Type);
    }

    [Fact]
    public void FallsBackToTextParsing()
    {
        const string text = "Network adapters:\n  ID  Name\n   7  Ethernet 2  00-11-22-33-44-55  10.0.0.2\n  12  Wi-Fi\n";
        var c = Parsers.ParseComponents(text);
        Assert.Equal([7, 12], c.Select(x => x.Id).ToArray());
        Assert.Equal("Ethernet 2", c[0].Name);
        Assert.Equal("10.0.0.2", c[0].Ip);
    }

    [Theory] [InlineData("")] [InlineData("garbage without ids")]
    public void NothingParsedGivesEmptyList(string s) => Assert.Empty(Parsers.ParseComponents(s));

    [Fact]
    public void ParsesDropsAndGroupsByReason()
    {
        const string txt = """
            23:11:32.213070900 PktGroupId 844424930131969, PktNumber 1, Appearance 1, Direction Rx , Type Ethernet , Component 9, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66, DropReason VLAN tag not found, DropLocation 0xE000127C
            23:11:32.213070901 PktGroupId 2, PktNumber 1, Appearance 1, Direction Rx , Type Ethernet , Component 9, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66, DropReason VLAN tag not found, DropLocation 0xE000127C
            23:11:33.000000000 PktGroupId 3, PktNumber 1, Appearance 1, Direction Tx , Type Ethernet , Component 4, Edge 1, Filter 1, OriginalSize 60, LoggedSize 60
            23:11:34.000000000 PktGroupId 4, PktNumber 1, Appearance 1, Direction Rx , Type Ethernet , Component 20, Edge 1, Filter 1, OriginalSize 60, LoggedSize 60, DropReason Neighbor discovery failed, DropLocation 0xE0001234
            """;
        var drops = DropParser.Parse(txt);
        Assert.Equal(3, drops.Count);
        Assert.Equal("VLAN tag not found", drops[0].Reason);
        Assert.Equal(9, drops[0].Component);
        Assert.Equal("23:11:32.213070900", drops[0].Time);
        var g = DropParser.Group(drops);
        Assert.Equal(("VLAN tag not found", 9, 2), g[0]);
        Assert.Equal(2, g.Count);
    }

    [Fact] public void NoDropsInNormalTraffic() => Assert.Empty(DropParser.Parse("23:11:33.0 PktGroupId 3, Component 4, OriginalSize 60"));

    [Fact]
    public void CounterTotals_AreBestEffort_NeverThrow()
    {
        const string txt = """
            Flow counters:
             Id  Name        Packets  Bytes
              7  Ethernet 2  1,234    456,789
              9  Wi-Fi       66       4,000

            Drop counters:
             Id  Name        Packets  Bytes
              7  Ethernet 2  5        300
            """;
        var (p, d) = Parsers.ParseCounterTotals(txt);
        Assert.Equal(1300, p);
        Assert.Equal(5, d);
        Assert.Equal((0, 0), Parsers.ParseCounterTotals("totally unexpected output"));
        Assert.Equal((0, 0), Parsers.ParseCounterTotals(""));
    }
}
