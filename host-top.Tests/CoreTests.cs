using System.Net;
using HostTop.Core;

namespace HostTop.Tests;

internal sealed class FakeProcs : IProcessResolver
{
    public ProcIdentity Resolve(int pid) => new(pid, 1, pid == 100 ? "chrome.exe" : pid == 200 ? "svchost.exe" : $"p{pid}.exe", $"C:\\x\\p{pid}.exe");
}

public class AggregatorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static IPAddress IP(string s) => IPAddress.Parse(s);

    private static FlowEvent Ev(int pid, string remote, int rport, long bytes, bool send, FlowProtocol p = FlowProtocol.Tcp, int lport = 50000, string local = "192.168.1.10")
        => new(T0, pid, p, IP(local), lport, IP(remote), rport, bytes, send);

    [Fact]
    public void RatesAreBytesPerSecondOverTheBucket()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 1000, false));
        a.Add(Ev(100, "8.8.8.8", 443, 500, false));
        a.Add(Ev(100, "8.8.8.8", 443, 200, true));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Equal(1500, s.DownRate);
        Assert.Equal(200, s.UpRate);
        var h = Assert.Single(s.Hosts);
        Assert.Equal(1500, h.DownRate);
        Assert.Equal(1500, h.TotalDown);
        Assert.Equal(200, h.TotalUp);
    }

    [Fact]
    public void RateScalesWithElapsedTime()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 3000, false));
        var s = a.Tick(T0.AddSeconds(2));
        Assert.Equal(1500, s.DownRate);
    }

    [Fact]
    public void TotalsAccumulateAndRateFallsToZero()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 1000, false));
        a.Tick(T0.AddSeconds(1));
        var s = a.Tick(T0.AddSeconds(2));
        Assert.Equal(0, s.Hosts[0].DownRate);
        Assert.Equal(1000, s.Hosts[0].TotalDown);
        Assert.Equal(1000, s.TotalDown);
    }

    [Fact]
    public void HistoryIsOldestFirstAndSixtyLong()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 100, false)); a.Tick(T0.AddSeconds(1));
        a.Add(Ev(100, "8.8.8.8", 443, 300, false)); var s = a.Tick(T0.AddSeconds(2));
        var h = s.Hosts[0].DownHistory;
        Assert.Equal(60, h.Length);
        Assert.Equal(100, h[58]);
        Assert.Equal(300, h[59]);
        Assert.Equal(0, h[0]);
    }

    [Fact]
    public void HistoryWrapsAfterSixtyTicks()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        FlowSnapshot s = null!;
        for (int i = 1; i <= 70; i++) { a.Add(Ev(100, "8.8.8.8", 443, i, false)); s = a.Tick(T0.AddSeconds(i)); }
        var h = s.Hosts[0].DownHistory;
        Assert.Equal(70, h[59]);
        Assert.Equal(11, h[0]);
    }

    [Fact]
    public void GroupsConnectionsHostsAndProcesses()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 100, false, lport: 50001));
        a.Add(Ev(100, "8.8.8.8", 443, 100, false, lport: 50002));
        a.Add(Ev(200, "8.8.8.8", 443, 100, true, lport: 50003));
        a.Add(Ev(100, "1.1.1.1", 443, 100, true, lport: 50004));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Equal(2, s.Hosts.Count);
        Assert.Equal(2, s.Processes.Count);
        Assert.Equal(4, s.Connections.Count);
        var h = s.Hosts.Single(x => x.Name == "8.8.8.8");
        Assert.Equal(3, h.Count);
        Assert.Equal("chrome.exe, svchost.exe", h.Related);
        var p = s.Processes.Single(x => x.Pid == 100);
        Assert.Equal(2, p.Count);
        Assert.Contains("1.1.1.1", p.Related);
    }

    [Fact]
    public void UdpIsGroupedByLocalPortAndRemoteEndpointIgnoringLocalAddress()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 100, true, FlowProtocol.Udp, 5000, "192.168.1.10"));
        a.Add(Ev(100, "8.8.8.8", 443, 50, false, FlowProtocol.Udp, 5000, "10.0.0.5"));
        a.Add(Ev(100, "8.8.8.8", 443, 50, false, FlowProtocol.Udp, 5001, "10.0.0.5"));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Equal(2, s.Connections.Count);
        var c = s.Connections.Single(x => x.Local == "*:5000");
        Assert.Equal(100, c.UpRate);
        Assert.Equal(50, c.DownRate);
        Assert.Equal("8.8.8.8:443", c.RemoteEndpoint);
        Assert.Equal(FlowProtocol.Udp, c.Protocol);
    }

    [Fact]
    public void TcpConnectionsKeepLocalAddress()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 10, true, local: "192.168.1.10"));
        a.Add(Ev(100, "8.8.8.8", 443, 10, true, local: "10.9.9.9"));
        Assert.Equal(2, a.Tick(T0.AddSeconds(1)).Connections.Count);
    }

    [Fact]
    public void Ipv6EndpointsAreBracketed()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "2606:4700::1111", 443, 10, false, local: "2001:db8::5"));
        var c = a.Tick(T0.AddSeconds(1)).Connections.Single();
        Assert.Equal("[2001:db8::5]:50000", c.Local);
        Assert.Equal("[2606:4700::1111]:443", c.RemoteEndpoint);
        Assert.Equal(NetClass.Internet, c.Class);
    }

    [Fact]
    public void LoopbackHiddenByDefaultButNotInMachineTotalsOfTheWire()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "127.0.0.1", 8080, 1000, false, local: "127.0.0.1"));
        a.Add(Ev(100, "8.8.8.8", 443, 400, false));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Single(s.Hosts);
        Assert.Equal(400, s.DownRate);
        Assert.Equal(1000, s.LoopbackDownRate);

        a.IncludeLoopback = true;
        a.Add(Ev(100, "127.0.0.1", 8080, 1000, false, local: "127.0.0.1"));
        s = a.Tick(T0.AddSeconds(2));
        Assert.Equal(2, s.Hosts.Count);
        Assert.Equal(0, s.DownRate);
    }

    [Fact]
    public void HideLanAndHideInternetDropTheTraffic()
    {
        var a = new FlowAggregator(new FakeProcs()) { IncludeLan = false };
        a.Tick(T0);
        a.Add(Ev(100, "192.168.1.50", 445, 100, false));
        a.Add(Ev(100, "8.8.8.8", 443, 100, false));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Equal("8.8.8.8", Assert.Single(s.Hosts).Name);
        Assert.Single(s.Processes);
        Assert.Equal(200, s.DownRate); // machine total still counts everything on the wire

        a.IncludeLan = true; a.IncludeInternet = false;
        a.Add(Ev(100, "192.168.1.50", 445, 100, false));
        a.Add(Ev(100, "8.8.8.8", 443, 100, false));
        s = a.Tick(T0.AddSeconds(2));
        Assert.Equal("192.168.1.50", s.Hosts.Single(h => h.DownRate > 0).Name);
    }

    [Fact]
    public void ReusedPidWithNewStartTimeIsASeparateProcessRow()
    {
        var r = new SwitchingProcs();
        var a = new FlowAggregator(r);
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 10, true));
        r.Start = 2;
        a.Add(Ev(100, "8.8.8.8", 443, 10, true));
        Assert.Equal(2, a.Tick(T0.AddSeconds(1)).Processes.Count);
    }

    private sealed class SwitchingProcs : IProcessResolver
    {
        public long Start = 1;
        public ProcIdentity Resolve(int pid) => new(pid, Start, "x.exe", null);
    }

    [Fact]
    public void IdleRowsExpire()
    {
        var a = new FlowAggregator(new FakeProcs()) { IdleExpiry = TimeSpan.FromSeconds(10) };
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 10, true));
        Assert.Single(a.Tick(T0.AddSeconds(1)).Hosts);
        Assert.Single(a.Tick(T0.AddSeconds(5)).Hosts);
        var s = a.Tick(T0.AddSeconds(20));
        Assert.Empty(s.Hosts); Assert.Empty(s.Connections); Assert.Empty(s.Processes);
        Assert.Equal(10, s.TotalUp);
    }

    [Fact]
    public void ConnectionCountOnlyCountsRecentlyActive()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "8.8.8.8", 443, 10, true, lport: 1));
        a.Tick(T0.AddSeconds(1));
        a.Add(Ev(100, "8.8.8.8", 443, 10, true, lport: 2));
        var s = a.Tick(T0.AddSeconds(60));
        Assert.Equal(1, s.Hosts[0].Count);
    }

    [Fact]
    public void ServiceNameFilledFromPort()
    {
        var a = new FlowAggregator(new FakeProcs());
        a.Tick(T0);
        a.Add(Ev(100, "10.1.1.1", 445, 10, true));
        var s = a.Tick(T0.AddSeconds(1));
        Assert.Equal("SMB (445)", s.Connections[0].Service);
        Assert.Equal("SMB (445)", s.Hosts[0].Service);
    }
}

public class ClassifierTests
{
    [Theory]
    [InlineData("10.1.2.3", NetClass.Lan)]
    [InlineData("172.16.0.1", NetClass.Lan)]
    [InlineData("172.31.255.1", NetClass.Lan)]
    [InlineData("172.32.0.1", NetClass.Internet)]
    [InlineData("192.168.0.9", NetClass.Lan)]
    [InlineData("169.254.1.1", NetClass.Lan)]
    [InlineData("100.64.0.1", NetClass.Lan)]
    [InlineData("100.128.0.1", NetClass.Internet)]
    [InlineData("224.0.0.251", NetClass.Lan)]
    [InlineData("255.255.255.255", NetClass.Lan)]
    [InlineData("8.8.8.8", NetClass.Internet)]
    [InlineData("127.0.0.1", NetClass.Loopback)]
    [InlineData("::1", NetClass.Loopback)]
    [InlineData("fe80::1", NetClass.Lan)]
    [InlineData("fd12:3456::1", NetClass.Lan)]
    [InlineData("ff02::fb", NetClass.Lan)]
    [InlineData("2606:4700::1111", NetClass.Internet)]
    [InlineData("::ffff:192.168.1.1", NetClass.Lan)]
    [InlineData("::ffff:8.8.8.8", NetClass.Internet)]
    public void Classify(string ip, NetClass expected) => Assert.Equal(expected, AddressClassifier.Classify(IPAddress.Parse(ip)));

    [Fact]
    public void TrafficToOwnAddressIsLoopback() =>
        Assert.Equal(NetClass.Loopback, AddressClassifier.Classify(IPAddress.Parse("192.168.1.10"), IPAddress.Parse("192.168.1.10")));
}

public class ServiceNameTests
{
    [Theory]
    [InlineData(FlowProtocol.Tcp, 443, "HTTPS")]
    [InlineData(FlowProtocol.Tcp, 445, "SMB")]
    [InlineData(FlowProtocol.Tcp, 3389, "RDP")]
    [InlineData(FlowProtocol.Udp, 53, "DNS")]
    [InlineData(FlowProtocol.Udp, 443, "QUIC (HTTP/3)")]
    public void Known(FlowProtocol p, int port, string name) => Assert.Equal(name, ServiceNames.Get(p, port));

    [Fact] public void Unknown() => Assert.Null(ServiceNames.Get(FlowProtocol.Tcp, 54321));

    [Fact]
    public void DescribeFallsBackToLocalPortForInboundTraffic()
    {
        Assert.Equal("RDP (3389)", ServiceNames.Describe(FlowProtocol.Tcp, 3389, 51234));
        Assert.Equal("HTTPS (443)", ServiceNames.Describe(FlowProtocol.Tcp, 51234, 443));
        Assert.Equal("", ServiceNames.Describe(FlowProtocol.Tcp, 51234, 51235));
    }
}

public class FormatAndCsvTests
{
    [Theory]
    [InlineData(0, true, "0")]
    [InlineData(125000, true, "1.00 Mbit/s")]
    [InlineData(1250000, true, "10.0 Mbit/s")]
    [InlineData(1500, false, "1.50 KB/s")]
    [InlineData(10, false, "10 B/s")]
    public void Rate(double v, bool bits, string expected) => Assert.Equal(expected, Format.Rate(v, bits));

    [Fact] public void Bytes() { Assert.Equal("512 B", Format.Bytes(512)); Assert.Equal("1.5 KB", Format.Bytes(1536)); }

    [Fact]
    public void CsvQuotesCommasQuotesAndNewlines()
    {
        var csv = CsvExport.Build(["a", "b"], [["x,y", "say \"hi\""], ["line\nbreak", ""]]);
        Assert.Equal("a,b\r\n\"x,y\",\"say \"\"hi\"\"\"\r\n\"line\nbreak\",\r\n", csv);
    }

    [Fact]
    public void TsvFlattensTabsAndNewlines() =>
        Assert.Equal("a\tb\r\nx y\tz w\r\n", CsvExport.BuildTsv(["a", "b"], [["x\ty", "z\nw"]]));

    [Fact]
    public void FilterTermsAreAndedAndSupportExclusion()
    {
        Assert.True(RowFilter.Matches("chrome.exe 8.8.8.8 HTTPS", "chrome https"));
        Assert.False(RowFilter.Matches("chrome.exe 8.8.8.8", "chrome firefox"));
        Assert.False(RowFilter.Matches("chrome.exe 8.8.8.8", "-chrome"));
        Assert.True(RowFilter.Matches("anything", "  "));
    }
}

public class DecoderTests
{
    private static Func<string, object?> P(Dictionary<string, object?> d) => n => d.GetValueOrDefault(n);
    private static readonly DateTime T = new(2026, 1, 1);
    /// <summary>A port as the provider delivers it: network byte order (443 = 0xBB01 when read little-endian).</summary>
    private static ushort Net(int port) => (ushort)(((port & 0xFF) << 8) | (port >> 8));

    [Theory]
    [InlineData((ushort)0xBB01, 443)]
    [InlineData((short)-17663, 443)]   // same bits as a signed value, as seen on a real machine
    [InlineData(0x6C07, 1900)]
    public void PortIsByteSwappedAndUnsigned(object raw, int expected) => Assert.Equal(expected, EtwDecoder.ToPort(raw));

    [Fact]
    public void TcpSendLocalIsSource()
    {
        var e = EtwDecoder.Decode(10, T, P(new() { ["PID"] = 42u, ["size"] = 1460u, ["saddr"] = "192.168.1.10", ["daddr"] = "8.8.8.8", ["sport"] = Net(50000), ["dport"] = Net(443) }))!.Value;
        Assert.True(e.IsSend);
        Assert.Equal(FlowProtocol.Tcp, e.Protocol);
        Assert.Equal("192.168.1.10", e.Local.ToString());
        Assert.Equal(50000, e.LocalPort);
        Assert.Equal("8.8.8.8", e.Remote.ToString());
        Assert.Equal(443, e.RemotePort);
        Assert.Equal(42, e.Pid);
        Assert.Equal(1460, e.Bytes);
    }

    [Fact]
    public void UdpReceiveLocalIsDestination()
    {
        var e = EtwDecoder.Decode(43, T, P(new() { ["PID"] = 7, ["size"] = 100, ["saddr"] = "1.1.1.1", ["daddr"] = "192.168.1.10", ["sport"] = Net(53), ["dport"] = Net(5555) }))!.Value;
        Assert.False(e.IsSend);
        Assert.Equal(FlowProtocol.Udp, e.Protocol);
        Assert.Equal("1.1.1.1", e.Remote.ToString());
        Assert.Equal(53, e.RemotePort);
        Assert.Equal(5555, e.LocalPort);
    }

    [Fact]
    public void Ipv6AndRawAddressForms()
    {
        var b = IPAddress.Parse("2001:db8::1").GetAddressBytes();
        var e = EtwDecoder.Decode(26, T, P(new() { ["PID"] = 1, ["size"] = 1, ["saddr"] = b, ["daddr"] = IPAddress.Parse("2606:4700::1111"), ["sport"] = Net(1), ["dport"] = Net(2) }))!.Value;
        Assert.Equal("2001:db8::1", e.Local.ToString());
        // IPv4 as a uint holding the bytes in network order (memory order 1.2.3.4)
        var ip = EtwDecoder.ToAddress(BitConverter.ToUInt32([1, 2, 3, 4], 0));
        Assert.Equal("1.2.3.4", ip!.ToString());
    }

    [Fact] public void UnknownEventIdOrMissingFieldGivesNull()
    {
        Assert.Null(EtwDecoder.Decode(12, T, P([])));
        Assert.Null(EtwDecoder.Decode(10, T, P(new() { ["PID"] = 1 })));
    }
}

public class GeoAndResolverTests
{
    [Fact]
    public void GeoLooksUpV4AndV6Ranges()
    {
        var db = GeoIpDatabase.FromLines([
            "# comment", "8.8.8.0,8.8.8.255,US,Google LLC", "\"1.0.0.0\",\"1.0.0.255\",AU", "2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,US,Cloudflare", "garbage"]);
        Assert.Equal(3, db.Count);
        Assert.Equal("US · Google LLC", db.Lookup(IPAddress.Parse("8.8.8.8")));
        Assert.Equal("AU", db.Lookup(IPAddress.Parse("1.0.0.1")));
        Assert.Equal("US · Cloudflare", db.Lookup(IPAddress.Parse("2606:4700::1111")));
        Assert.Null(db.Lookup(IPAddress.Parse("9.9.9.9")));
    }

    [Fact]
    public async Task ResolverNeverBlocksAndCaches()
    {
        int calls = 0;
        var gate = new TaskCompletionSource();
        var r = new HostResolver(async (ip, ct) => { Interlocked.Increment(ref calls); await gate.Task; return "dns.google"; });
        var ip = IPAddress.Parse("8.8.8.8");
        Assert.Null(r.TryGet(ip));      // returns immediately
        Assert.Null(r.TryGet(ip));
        gate.SetResult();
        for (int i = 0; i < 100 && r.TryGet(ip) == null; i++) await Task.Delay(20);
        Assert.Equal("dns.google", r.TryGet(ip));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ResolverRemembersFailures()
    {
        var r = new HostResolver((ip, ct) => Task.FromResult<string?>(null));
        var ip = IPAddress.Parse("203.0.113.9");
        r.TryGet(ip);
        for (int i = 0; i < 100 && !r.IsResolved(ip); i++) await Task.Delay(20);
        Assert.True(r.IsResolved(ip));
        Assert.Null(r.TryGet(ip));
    }
}

public class RecorderTests
{
    [Fact]
    public void RecordsActiveHostsAndStopsAfterDuration()
    {
        var path = Path.GetTempFileName();
        try
        {
            var t0 = new DateTime(2026, 1, 1, 12, 0, 0);
            var a = new FlowAggregator(new FakeProcs());
            var rec = new CsvRecorder(path, TimeSpan.FromSeconds(2), t0);
            a.Tick(t0);
            for (int i = 1; i <= 4; i++)
            {
                a.Add(new FlowEvent(t0, 100, FlowProtocol.Tcp, IPAddress.Parse("192.168.1.2"), 1, IPAddress.Parse("8.8.8.8"), 443, 1000, false));
                rec.Record(a.Tick(t0.AddSeconds(i)));
            }
            Assert.True(rec.Finished);
            var lines = File.ReadAllLines(path);
            Assert.Equal(3, lines.Length); // header + 2 seconds
            Assert.Contains("8.8.8.8", lines[1]);
            Assert.Contains("1000", lines[1]);
        }
        finally { File.Delete(path); }
    }
}
