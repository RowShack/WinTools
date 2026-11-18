using PktmonGui.Core;

namespace PktmonGui.Tests;

/// <summary>Lines taken from a real <c>pktmon etl2txt</c> run on Windows 11 (Wi-Fi and Hyper-V Ethernet).</summary>
public class PacketTests
{
    private const string Sample = """
        [00] AF04.4C58::2026-11-18 19:10:36.579468200 [MSNT_SystemTrace] Event: Header, BufferSize: 16777216, Version: 131082
        [02]0000.0000::2026-11-18 19:10:36.766434400 [Microsoft-Windows-PktMon] PktGroupId 562949953422180, PktNumber 1, Appearance 0, Direction Tx , Type Ethernet , Component 163, Edge 1, Filter 0, OriginalSize 42, LoggedSize 42
        	00-15-5D-A1-C9-16 > 00-15-5D-6F-F2-94, ethertype ARP (0x0806), length 42: Request who-has 172.19.176.1 tell 172.19.186.198, length 28
        [07]2C18.0A8C::2026-11-18 19:10:37.100000000 [Microsoft-Windows-PktMon] PktGroupId 1970324836974658, PktNumber 1, Appearance 0, Direction Tx , Type WiFi , Component 18, Edge 1, Filter 0, OriginalSize 79, LoggedSize 79
        	BSSID:94-2A-6F-CE-38-11 SA:DC-90-09-64-2A-94 DA:94-2A-6F-CE-38-11 LLC, dsap SNAP (0xaa) Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Ethernet (0x000000), ethertype IPv4 (0x0800), length 40: 192.168.15.76.65354 > 160.79.104.10.443: Flags [.], ack 2328430980, win 251, length 0
        [07]2C18.0A8C::2026-11-18 19:10:37.200000000 [Microsoft-Windows-PktMon] PktGroupId 1970324836974659, PktNumber 1, Appearance 0, Direction Tx , Type WiFi , Component 18, Edge 1, Filter 0, OriginalSize 62, LoggedSize 62
        	BSSID:94-2A-6F-CE-38-11 SA:DC-90-09-64-2A-94 DA:94-2A-6F-CE-38-11 LLC, dsap SNAP (0xaa) Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Ethernet (0x000000), ethertype IPv4 (0x0800), length 62: 192.168.15.76.56022 > 192.168.15.1.53: 50807+ A? web.whatsapp.com. (34)
        [02]0004.7344::2026-11-18 19:10:37.146093700 [Microsoft-Windows-PktMon] Drop: PktGroupId 562949953422193, PktNumber 1, Appearance 0, Direction Rx , Type WiFi , Component 18, Filter 0, DropReason Unsupported EtherType , DropLocation 0xE0001007, OriginalSize 60, LoggedSize 60
        	Drop: unknown 802.11 frame type (3)
        """;

    [Fact]
    public void SkipsNonPacketEvents_AndParsesTheRest()
    {
        var rows = PacketParser.Parse(Sample);
        Assert.Equal(4, rows.Count);
        Assert.Equal([1, 2, 3, 4], rows.Select(r => r.Index).ToArray());
    }

    [Fact]
    public void ParsesArp()
    {
        var r = PacketParser.Parse(Sample)[0];
        Assert.Equal("ARP", r.Protocol); Assert.Equal("172.19.186.198", r.Source); Assert.Equal("172.19.176.1", r.Destination);
        Assert.Equal("Tx", r.Direction); Assert.Equal(163, r.Component); Assert.Equal(42, r.Size); Assert.False(r.IsDrop);
    }

    [Fact]
    public void ParsesTcpWithPorts()
    {
        var r = PacketParser.Parse(Sample)[1];
        Assert.Equal("TCP", r.Protocol); Assert.Equal("192.168.15.76:65354", r.Source); Assert.Equal("160.79.104.10:443", r.Destination);
        Assert.StartsWith("Flags [.]", r.Info); Assert.Equal("WiFi", r.Type); Assert.Equal("19:10:37.100000000", r.Time[11..]);
    }

    [Fact]
    public void ParsesDnsOverUdp()
    {
        var r = PacketParser.Parse(Sample)[2];
        Assert.Equal("DNS", r.Protocol); Assert.Equal("192.168.15.1:53", r.Destination); Assert.Contains("web.whatsapp.com", r.Info);
    }

    [Fact]
    public void ParsesDrops_WithReason()
    {
        var r = PacketParser.Parse(Sample)[3];
        Assert.True(r.IsDrop); Assert.Equal("Unsupported EtherType", r.DropReason); Assert.Equal("Rx", r.Direction);
        Assert.Contains("unknown 802.11 frame type", r.Info);
    }

    [Fact]
    public void FilterMatchesWordsAndDropKeyword()
    {
        var rows = PacketParser.Parse(Sample);
        Assert.Equal(1, rows.Count(r => r.Matches("443")));
        Assert.Equal(1, rows.Count(r => r.Matches("tcp 160.79")));
        Assert.Equal(1, rows.Count(r => r.Matches("drop")));
        Assert.Equal(4, rows.Count(r => r.Matches("")));
        Assert.Equal(0, rows.Count(r => r.Matches("tcp nonsense")));
    }

    [Fact]
    public void ParsesIpv6AndIcmp()
    {
        const string t = """
            [01]0000.0000::2026-01-01 10:00:00.000000100 [Microsoft-Windows-PktMon] PktGroupId 1, PktNumber 1, Appearance 0, Direction Rx , Type Ethernet , Component 5, Edge 1, Filter 0, OriginalSize 94, LoggedSize 94
            	aa-bb-cc-dd-ee-01 > aa-bb-cc-dd-ee-02, ethertype IPv6 (0x86dd), length 94: fe80::1.546 > ff02::1:2.547: UDP, length 40
            [01]0000.0000::2026-01-01 10:00:01.000000100 [Microsoft-Windows-PktMon] PktGroupId 2, PktNumber 1, Appearance 0, Direction Rx , Type Ethernet , Component 5, Edge 1, Filter 0, OriginalSize 74, LoggedSize 74
            	aa-bb-cc-dd-ee-01 > aa-bb-cc-dd-ee-02, ethertype IPv4 (0x0800), length 74: 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 40
            """;
        var rows = PacketParser.Parse(t);
        Assert.Equal("fe80::1:546", rows[0].Source); Assert.Equal("ff02::1:2:547", rows[0].Destination); Assert.Equal("UDP", rows[0].Protocol);
        Assert.Equal("ICMP", rows[1].Protocol); Assert.Equal("10.0.0.1", rows[1].Source);
    }

    [Fact]
    public void JunkInput_DoesNotThrow()
    {
        Assert.Empty(PacketParser.Parse(""));
        Assert.Empty(PacketParser.Parse("garbage\r\n\tmore garbage\r\n[01] PktGroupId nonsense"));
    }

    [Fact]
    public void CsvQuotesAndHasHeader()
    {
        string csv = PacketParser.ToCsv(PacketParser.Parse(Sample).Take(1));
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("no,time,direction", lines[0]); Assert.Contains("\"172.19.186.198\"", lines[1]);
    }
}

public class HumanizeTests
{
    [Theory]
    [InlineData("Flags [S], seq 1, win 64240, length 0", PacketCategory.TcpSyn, "Opening a connection to https (443)")]
    [InlineData("Flags [S.], seq 1, ack 2, win 16, length 0", PacketCategory.TcpSyn, "Server accepts")]
    [InlineData("Flags [.], ack 5, win 251, length 0", PacketCategory.TcpAck, "Acknowledgement")]
    [InlineData("Flags [P.], seq 1:40, ack 5, win 16, length 39", PacketCategory.TcpData, "Sending 39 bytes")]
    [InlineData("Flags [F.], seq 1, ack 5, win 16, length 0", PacketCategory.TcpFin, "Closing")]
    [InlineData("Flags [R.], seq 1, ack 5, win 0, length 0", PacketCategory.TcpReset, "reset")]
    public void TcpFlagsBecomeEnglish(string info, PacketCategory cat, string text)
    {
        var (c, s) = Humanize.Describe("TCP", "10.0.0.5:50000", "10.0.0.9:443", info, false, "");
        Assert.Equal(cat, c); Assert.Contains(text, s);
    }

    [Fact]
    public void DnsQueryAndAnswer()
    {
        Assert.Contains("what is web.whatsapp.com", Humanize.Describe("DNS", "a:1", "b:53", "50807+ A? web.whatsapp.com. (34)", false, "").Item2);
        Assert.Contains("does not exist", Humanize.Describe("DNS", "b:53", "a:1", "53282 NXDomain 0/1/0 (109)", false, "").Item2);
    }

    [Fact]
    public void DropsAndPortNames()
    {
        Assert.Equal((PacketCategory.Drop, "Dropped: Unsupported EtherType"), Humanize.Describe("", "", "", "", true, "Unsupported EtherType"));
        Assert.Equal("1.2.3.4:443 (https)", Humanize.Endpoint("1.2.3.4:443"));
        Assert.Equal("1.2.3.4:50000", Humanize.Endpoint("1.2.3.4:50000"));
        Assert.Equal("fe80::1:546", Humanize.Endpoint("fe80::1:546"));
    }
}
