using System.Net;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using SnmpLiveGraph.Core;
using SnmpException = SnmpLiveGraph.Core.SnmpException;

namespace SnmpLiveGraph.Tests;

/// <summary>A minimal SNMPv2c agent (GET / GETNEXT / GETBULK) over a sorted OID table, so the real client code runs end to end.</summary>
internal sealed class FakeAgent : IDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _cts = new();
    public SortedDictionary<ObjectIdentifier, ISnmpData> Mib { get; } = new();
    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
    public string Community { get; } = "public";
    public int Requests;

    public FakeAgent() { _ = Task.Run(Loop); }

    public void Set(string oid, ISnmpData value) => Mib[new ObjectIdentifier(oid)] = value;

    private async Task Loop()
    {
        var registry = new UserRegistry();
        while (!_cts.IsCancellationRequested)
        {
            UdpReceiveResult r;
            try { r = await _udp.ReceiveAsync(_cts.Token); } catch { return; }
            try
            {
                Interlocked.Increment(ref Requests);
                var msg = MessageFactory.ParseMessages(r.Buffer, registry).First();
                var reply = Handle(msg);
                if (reply != null) await _udp.SendAsync(reply, reply.Length, r.RemoteEndPoint);
            }
            catch { /* ignore malformed */ }
        }
    }

    private byte[]? Handle(ISnmpMessage msg)
    {
        var pdu = msg.Pdu();
        var vars = new List<Variable>();
        switch (pdu.TypeCode)
        {
            case SnmpType.GetRequestPdu:
                foreach (var v in pdu.Variables)
                    vars.Add(Mib.TryGetValue(v.Id, out var d) ? new Variable(v.Id, d) : new Variable(v.Id, new NoSuchInstance()));
                break;
            case SnmpType.GetNextRequestPdu:
                foreach (var v in pdu.Variables) vars.Add(Next(v.Id));
                break;
            case SnmpType.GetBulkRequestPdu:
                int max = pdu.ErrorIndex.ToInt32();   // in GETBULK the error-index field carries max-repetitions
                foreach (var v in pdu.Variables)
                {
                    var cur = v.Id;
                    for (int i = 0; i < max; i++) { var n = Next(cur); vars.Add(n); cur = n.Id; if (n.Data is EndOfMibView) break; }
                }
                break;
            default: return null;
        }
        var resp = new ResponseMessage(pdu.RequestId.ToInt32(), msg.Version, new OctetString(Community), ErrorCode.NoError, 0, vars);
        return resp.ToBytes();
    }

    private Variable Next(ObjectIdentifier id)
    {
        foreach (var kv in Mib) if (kv.Key.CompareTo(id) > 0) return new Variable(kv.Key, kv.Value);
        return new Variable(id, new EndOfMibView());
    }

    public void Dispose() { _cts.Cancel(); _udp.Dispose(); }
}

public class FakeAgentTests
{
    private static FakeAgent MakeAgent()
    {
        var a = new FakeAgent();
        a.Set("1.3.6.1.2.1.1.1.0", new OctetString("Test router"));
        a.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(123456));
        a.Set("1.3.6.1.2.1.1.5.0", new OctetString("rtr1"));
        foreach (var (idx, name, alias, mbps) in new[] { (1, "Gi0/1", "uplink", 1000), (2, "Gi0/2", "", 1000), (10, "Tu1", "vpn", 100) })
        {
            a.Set($"1.3.6.1.2.1.2.2.1.2.{idx}", new OctetString("desc-" + name));
            a.Set($"1.3.6.1.2.1.2.2.1.8.{idx}", new Integer32(idx == 2 ? 2 : 1));
            a.Set($"1.3.6.1.2.1.31.1.1.1.1.{idx}", new OctetString(name));
            a.Set($"1.3.6.1.2.1.31.1.1.1.18.{idx}", new OctetString(alias));
            a.Set($"1.3.6.1.2.1.31.1.1.1.15.{idx}", new Gauge32((uint)mbps));
        }
        return a;
    }

    private static SnmpSession Session(FakeAgent a) => new(new SnmpTarget { Host = "127.0.0.1", Port = a.Port, Community = a.Community, TimeoutMs = 2000 });

    [Fact]
    public async Task SystemInfo_ViaGet()
    {
        using var a = MakeAgent();
        var info = await Session(a).GetSystemInfoAsync(default);
        Assert.Equal("rtr1", info.Name);
        Assert.Equal("Test router", info.Description);
        Assert.Equal(123456, info.UpTimeTicks);
    }

    [Fact]
    public async Task MissingOid_IsNullNotError()
    {
        using var a = MakeAgent();
        var r = await Session(a).GetAsync(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.99.0"], default);
        Assert.NotNull(r["1.3.6.1.2.1.1.5.0"]);
        Assert.Null(r["1.3.6.1.2.1.99.0"]);
    }

    [Fact]
    public async Task DiscoversInterfaces_WithNamesAliasesSpeedsAndStatus()
    {
        using var a = MakeAgent();
        var ifs = await InterfaceDiscovery.DiscoverAsync(Session(a), default);
        Assert.Equal([1, 2, 10], ifs.Select(i => i.Index).ToArray());
        Assert.Equal("Gi0/1", ifs[0].Name); Assert.Equal("uplink", ifs[0].Alias); Assert.Equal(1000, ifs[0].HighSpeedMbps); Assert.Equal("up", ifs[0].StatusText);
        Assert.Equal("down", ifs[1].StatusText);
        Assert.Equal(100, ifs[2].HighSpeedMbps);
    }

    [Fact]
    public async Task Poller_ComputesRates_FromHcCounters()
    {
        using var a = MakeAgent();
        a.Set("1.3.6.1.2.1.31.1.1.1.6.1", new Counter64(1_000_000));
        a.Set("1.3.6.1.2.1.31.1.1.1.10.1", new Counter64(2_000_000));
        a.Set("1.3.6.1.2.1.2.2.1.14.1", new Counter32(0)); a.Set("1.3.6.1.2.1.2.2.1.20.1", new Counter32(0));
        a.Set("1.3.6.1.2.1.2.2.1.13.1", new Counter32(0)); a.Set("1.3.6.1.2.1.2.2.1.19.1", new Counter32(0));
        var session = Session(a);
        var ifs = await InterfaceDiscovery.DiscoverAsync(session, default);
        var poller = new DevicePoller(session, [ifs[0]]);
        var points = new List<PollPoint>();
        poller.Point += (_, p) => points.Add(p);

        await poller.PollOnceAsync(default);          // first sample: no rate yet
        Assert.False(points[0].InBps.HasValue);
        await Task.Delay(1100);
        a.Set("1.3.6.1.2.1.31.1.1.1.6.1", new Counter64(1_000_000 + 1_250_000));   // +1.25 MB in ~1.1 s
        a.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(123456 + 110));
        await poller.PollOnceAsync(default);
        Assert.True(points[1].InBps > 8_000_000 && points[1].InBps < 10_500_000, $"in bps = {points[1].InBps}");
        Assert.True(points[1].InUtil > 0.5 && points[1].InUtil < 1.1);
        Assert.Equal(0.0, points[1].OutBps);
    }

    [Fact]
    public async Task Poller_FallsBackTo32BitCounters_WhenHcMissing()
    {
        using var a = MakeAgent();
        a.Set("1.3.6.1.2.1.2.2.1.10.1", new Counter32(4_294_967_000));   // near wrap
        a.Set("1.3.6.1.2.1.2.2.1.16.1", new Counter32(0));
        var session = Session(a);
        var ifs = await InterfaceDiscovery.DiscoverAsync(session, default);
        var poller = new DevicePoller(session, [ifs[0]]);
        var points = new List<PollPoint>(); poller.Point += (_, p) => points.Add(p);
        await poller.PollOnceAsync(default);
        await Task.Delay(1000);
        a.Set("1.3.6.1.2.1.2.2.1.10.1", new Counter32(500));            // wrapped
        a.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(123456 + 100));
        await poller.PollOnceAsync(default);
        Assert.True(points[1].InBps > 4_000 && points[1].InBps < 8_000, $"in bps = {points[1].InBps}");   // ~796 octets/s
    }

    [Fact]
    public async Task Timeout_IsExplained()
    {
        var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));   // nobody answers
        int port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var s = new SnmpSession(new SnmpTarget { Host = "127.0.0.1", Port = port, TimeoutMs = 400 });
        var ex = await Assert.ThrowsAsync<SnmpException>(() => s.GetSystemInfoAsync(default));
        Assert.Contains("timeout", ex.Message, StringComparison.OrdinalIgnoreCase);
        udp.Dispose();
    }
}

public class SessionTests
{
    [Fact]
    public void SecretsAreEncrypted_AndRoundTrip()
    {
        var t = new SnmpTarget { Host = "10.0.0.1", Community = "s3cretCommunity", Version = SnmpVersion.V3, User = "u", AuthPassword = "authPassw0rd", PrivPassword = "privPassw0rd" };
        var saved = SessionStore.ToSaved(t, [new InterfaceInfo(3, "Gi0/3", "", 1000, 1)]);
        string path = Path.Combine(Path.GetTempPath(), "slg-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            SessionStore.Save(path, new SavedSession { Devices = [saved], IntervalSeconds = 7 });
            string raw = File.ReadAllText(path);
            Assert.DoesNotContain("s3cretCommunity", raw); Assert.DoesNotContain("authPassw0rd", raw); Assert.DoesNotContain("privPassw0rd", raw);
            var back = SessionStore.Load(path);
            Assert.Equal(7, back.IntervalSeconds);
            var t2 = SessionStore.ToTarget(back.Devices[0]);
            Assert.Equal("s3cretCommunity", t2.Community); Assert.Equal("authPassw0rd", t2.AuthPassword); Assert.Equal("privPassw0rd", t2.PrivPassword);
            Assert.Equal([3], back.Devices[0].InterfaceIndexes);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void HistoryKeepsOnlyTheWindow()
    {
        var h = new History { Window = TimeSpan.FromMinutes(5) };
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        for (int i = 0; i <= 600; i += 60) h.Add(new PollPoint(t0.AddSeconds(i), 1, 1, null, null, null, null, null, null, RateSkip.None));
        Assert.Equal(6, h.Points.Count);                    // minutes 5..10
        Assert.Equal(t0.AddSeconds(300), h.Points[0].Time);
    }

    [Fact]
    public void CsvHasHeaderAndInvariantNumbers()
    {
        var p = new PollPoint(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), 1234.5, null, 12.34, null, 0, 0, 0, 0, RateSkip.None);
        string csv = CsvExport.Build([("rtr1 Gi0/1", p)]);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("time_utc,interface", lines[0]);
        Assert.Contains("1234.5", lines[1]); Assert.Contains("\"rtr1 Gi0/1\"", lines[1]);
    }
}
