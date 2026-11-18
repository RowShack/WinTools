using Lextm.SharpSnmpLib;
using SnmpLiveGraph.Core;

namespace SnmpLiveGraph.Tests;

public class ThresholdTests
{
    private static PollPoint P(double? inUtil, double? outUtil, double? inErr, double? outErr) =>
        new(DateTime.UtcNow, null, null, inUtil, outUtil, inErr, outErr, 0, 0, RateSkip.None);

    [Fact]
    public void NothingSet_NothingExceeded() => Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(P(99, 99, 5, 5), new Threshold()));

    [Fact]
    public void Utilisation_UsesBusierDirection_AndIsStrictlyGreater()
    {
        var t = new Threshold { UtilPercent = 80 };
        Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(P(80, 10, 0, 0), t));
        Assert.Equal(Breach.Utilisation, ThresholdEvaluator.Evaluate(P(10, 80.1, 0, 0), t));
    }

    [Fact]
    public void Errors_AreSummed()
    {
        var t = new Threshold { ErrorsPerSec = 1 };
        Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(P(null, null, 0.5, 0.5), t));
        Assert.Equal(Breach.Errors, ThresholdEvaluator.Evaluate(P(null, null, 0.6, 0.5), t));
    }

    [Fact]
    public void UnknownValues_NeverBreach()
    {
        var t = new Threshold { UtilPercent = 1, ErrorsPerSec = 0 };
        Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(P(null, null, null, null), t));
        Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(null, t));
        Assert.Equal(Breach.None, ThresholdEvaluator.Evaluate(P(50, 50, 1, 1), null));
    }

    [Fact]
    public void BothCanBreach() =>
        Assert.Equal(Breach.Utilisation | Breach.Errors, ThresholdEvaluator.Evaluate(P(90, 0, 3, 0), new Threshold { UtilPercent = 50, ErrorsPerSec = 1 }));

    [Fact]
    public void UtilisationAsBps()
    {
        Assert.Equal(800_000_000, ThresholdEvaluator.UtilisationAsBps(80, 1000));
        Assert.Null(ThresholdEvaluator.UtilisationAsBps(80, 0));
    }
}

public class StatusTrackerTests
{
    [Fact]
    public void FirstSampleIsBaseline_ThenChangesAreReported()
    {
        var t = new StatusTracker();
        Assert.Null(t.Observe(1, 1));
        Assert.Null(t.Observe(1, 1));
        Assert.Equal(1, t.Observe(1, 2));      // up -> down
        Assert.Null(t.Observe(1, 2));
        Assert.Equal(2, t.Observe(1, 1));      // down -> up
    }

    [Fact]
    public void InterfacesAreIndependent_AndUnknownIgnored()
    {
        var t = new StatusTracker();
        t.Observe(1, 1); t.Observe(2, 2);
        Assert.Null(t.Observe(2, 0));          // missing value doesn't count as a change
        Assert.Null(t.Observe(2, 2));
        Assert.Equal(1, t.Observe(1, 7));
    }

    [Fact]
    public void LogExportsTextAndCsv()
    {
        var log = new StatusLog();
        log.Add(new StatusChange(new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc), "rtr1", 1, "Gi0/1", 1, 2));
        Assert.Contains("rtr1  Gi0/1: up -> down", log.ToText());
        var csv = log.ToCsv().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("time_utc,device,interface,from,to", csv[0]);
        Assert.EndsWith("\"rtr1\",\"Gi0/1\",up,down", csv[1]);
        Assert.True(log.Items[0].WentDown);
    }
}

public class OidParsingTests
{
    [Fact]
    public void NumericTypes()
    {
        Assert.Equal(42, OidParser.Parse(new Gauge32(42)).Value);
        Assert.Equal(-5, OidParser.Parse(new Integer32(-5)).Value);
        Assert.Equal(7, OidParser.Parse(new Counter32(7)).Value);
        Assert.Equal(5e9, OidParser.Parse(new Counter64(5_000_000_000)).Value);
        Assert.Equal(4.5, OidParser.Parse(new Integer32(45), 0.1).Value!.Value, 6);
    }

    [Theory]
    [InlineData("45.5", 45.5)] [InlineData(" 12 % ", 12)] [InlineData("7", 7)]
    public void NumericText_IsAccepted(string text, double expected) => Assert.Equal(expected, OidParser.Parse(new OctetString(text)).Value);

    [Fact]
    public void Text_GivesClearMessage()
    {
        var r = OidParser.Parse(new OctetString("FortiGate-60F"));
        Assert.Null(r.Value); Assert.Contains("text, not a number", r.Problem);
    }

    [Fact]
    public void Missing_GivesClearMessage()
    {
        var r = OidParser.Parse(null);
        Assert.Null(r.Value); Assert.Contains("not found", r.Problem);
    }

    [Fact]
    public void OtherTypes_AreNotNumeric() => Assert.Contains("not numeric", OidParser.Parse(new IP(System.Net.IPAddress.Loopback.GetAddressBytes())).Problem);

    [Theory]
    [InlineData("1.3.6.1.4.1.12356.101.4.1.3.0", true)] [InlineData(".1.3.6.1.2.1.1.3.0", true)]
    [InlineData("", false)] [InlineData("fgSysCpuUsage.0", false)] [InlineData("1.3", false)] [InlineData("1.3.6..1", false)]
    public void OidValidation(string oid, bool ok) => Assert.Equal(ok, CustomOidSpec.Validate(oid) is null);

    [Fact]
    public void Presets_AreWellFormed_AndIncludeTheSpecifiedOnes()
    {
        Assert.All(OidPresets.All, p => Assert.Null(CustomOidSpec.Validate(p.Oid)));
        Assert.Contains(OidPresets.All, p => p.Oid == "1.3.6.1.4.1.12356.101.4.1.3.0");
        Assert.Contains(OidPresets.All, p => p.Oid == "1.3.6.1.4.1.12356.101.4.1.8.0");
        Assert.Contains(OidPresets.All, p => p.Oid.StartsWith("1.3.6.1.4.1.9.9.109.1.1.1.1.6"));
        Assert.Contains(OidPresets.All, p => p.Oid == "1.3.6.1.2.1.25.3.3.1.2");
    }
}

public class ExtrasSessionTests
{
    [Fact]
    public void ThresholdsAndCustomOids_RoundTripThroughSessionFile()
    {
        var t = new SnmpTarget { Host = "10.0.0.1", Community = "c" };
        var ifs = new[] { new InterfaceInfo(3, "Gi0/3", "", 1000, 1), new InterfaceInfo(4, "Gi0/4", "", 1000, 1) };
        var th = new Dictionary<int, Threshold> { [3] = new() { UtilPercent = 80, ErrorsPerSec = 0.5 }, [4] = new() };   // [4] is empty: not saved
        var cu = new[] { new CustomOidSpec { Name = "CPU", Oid = "1.3.6.1.4.1.12356.101.4.1.3.0", Unit = "%" },
                         new CustomOidSpec { Name = "Pkts", Oid = "1.3.6.1.2.1.2.2.1.11.1", AsCounter = true, Scale = 8 } };
        string path = Path.Combine(Path.GetTempPath(), "slg-x-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            SessionStore.Save(path, new SavedSession { Devices = [SessionStore.ToSaved(t, ifs, th, cu)] });
            var d = SessionStore.Load(path).Devices[0];
            Assert.Single(d.Thresholds);
            Assert.Equal(80, d.Thresholds[3].UtilPercent); Assert.Equal(0.5, d.Thresholds[3].ErrorsPerSec);
            Assert.Equal(2, d.CustomOids.Count);
            Assert.Equal("CPU", d.CustomOids[0].Name); Assert.False(d.CustomOids[0].AsCounter);
            Assert.True(d.CustomOids[1].AsCounter); Assert.Equal(8, d.CustomOids[1].Scale);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void OldSessionFilesWithoutNewFields_StillLoad()
    {
        string path = Path.Combine(Path.GetTempPath(), "slg-old-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"Devices\":[{\"Host\":\"1.2.3.4\",\"InterfaceIndexes\":[1]}],\"IntervalSeconds\":3}");
            var d = SessionStore.Load(path).Devices[0];
            Assert.Empty(d.Thresholds); Assert.Empty(d.CustomOids);
        }
        finally { File.Delete(path); }
    }
}

public class ExtrasAgentTests
{
    private static SnmpSession Session(FakeAgent a) => new(new SnmpTarget { Host = "127.0.0.1", Port = a.Port, Community = a.Community, TimeoutMs = 2000 });

    private static FakeAgent Agent()
    {
        var a = new FakeAgent();
        a.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(1000));
        a.Set("1.3.6.1.2.1.1.5.0", new OctetString("fw1"));
        a.Set("1.3.6.1.2.1.2.2.1.2.1", new OctetString("port1"));
        a.Set("1.3.6.1.2.1.2.2.1.8.1", new Integer32(1));
        a.Set("1.3.6.1.2.1.31.1.1.1.15.1", new Gauge32(1000));
        a.Set("1.3.6.1.2.1.31.1.1.1.6.1", new Counter64(0)); a.Set("1.3.6.1.2.1.31.1.1.1.10.1", new Counter64(0));
        a.Set("1.3.6.1.4.1.12356.101.4.1.3.0", new Gauge32(37));
        a.Set("1.3.6.1.4.1.12356.101.4.1.8.0", new Gauge32(12000));
        a.Set("1.3.6.1.2.1.25.3.3.1.2.196608", new Integer32(11));   // hrProcessorLoad, instance index varies
        a.Set("1.3.6.1.2.1.25.3.3.1.2.196609", new Integer32(22));
        a.Set("1.3.6.1.2.1.1.1.0", new OctetString("FortiGate-60F"));
        return a;
    }

    [Fact]
    public async Task Probe_Scalar_Table_Text_And_Missing()
    {
        using var a = Agent(); var s = Session(a);
        var cpu = await OidProbe.ProbeAsync(s, ".1.3.6.1.4.1.12356.101.4.1.3.0", 1, default);
        Assert.Equal(37, cpu.Reading.Value); Assert.Equal(1, cpu.Instances);

        var table = await OidProbe.ProbeAsync(s, "1.3.6.1.2.1.25.3.3.1.2", 1, default);   // no index -> first row
        Assert.Equal("1.3.6.1.2.1.25.3.3.1.2.196608", table.ResolvedOid); Assert.Equal(11, table.Reading.Value); Assert.Equal(2, table.Instances);

        var text = await OidProbe.ProbeAsync(s, "1.3.6.1.2.1.1.1.0", 1, default);
        Assert.Null(text.Reading.Value); Assert.Contains("text", text.Reading.Problem);

        var none = await OidProbe.ProbeAsync(s, "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1", 1, default);
        Assert.Null(none.Reading.Value); Assert.Contains("not found", none.Reading.Problem); Assert.Equal(0, none.Instances);
    }

    [Fact]
    public async Task Poller_CustomGauge_Counter_AndProblems()
    {
        using var a = Agent();
        a.Set("1.3.6.1.2.1.2.2.1.11.1", new Counter32(1000));
        var s = Session(a);
        var poller = new DevicePoller(s, []);                   // no interfaces: custom OIDs only
        poller.SetCustomOids([
            new CustomOidSpec { Name = "cpu", Oid = "1.3.6.1.4.1.12356.101.4.1.3.0" },
            new CustomOidSpec { Name = "rate", Oid = "1.3.6.1.2.1.2.2.1.11.1", AsCounter = true },
            new CustomOidSpec { Name = "txt", Oid = "1.3.6.1.2.1.1.1.0" },
            new CustomOidSpec { Name = "gone", Oid = "1.3.6.1.2.1.99.9.0" }]);
        var got = new List<(string, CustomPoint)>();
        poller.CustomPoint += (sp, p) => got.Add((sp.Name, p));

        await poller.PollOnceAsync(default);
        await Task.Delay(1100);
        a.Set("1.3.6.1.2.1.2.2.1.11.1", new Counter32(1500));
        a.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(1110));
        await poller.PollOnceAsync(default);

        CustomPoint Last(string n) => got.Last(g => g.Item1 == n).Item2;
        Assert.Equal(37, Last("cpu").Value);
        Assert.Null(Last("rate").Problem); Assert.InRange(Last("rate").Value!.Value, 300, 520);   // ~500 in ~1.1 s
        Assert.Contains("text", Last("txt").Problem);
        Assert.Contains("not found", Last("gone").Problem);
        Assert.Null(got.First(g => g.Item1 == "rate").Item2.Value);   // first counter sample: no rate yet, and no error
    }

    [Fact]
    public async Task Poller_ReportsStatusChanges_OnlyOnce()
    {
        using var a = Agent();
        a.Set("1.3.6.1.2.1.2.2.1.14.1", new Counter32(0));
        var s = Session(a);
        var ifs = await InterfaceDiscovery.DiscoverAsync(s, default);
        var poller = new DevicePoller(s, ifs);
        var changes = new List<StatusChange>(); poller.StatusChanged += c => changes.Add(c);
        var points = new List<PollPoint>(); poller.Point += (_, p) => points.Add(p);

        await poller.PollOnceAsync(default);
        Assert.Empty(changes); Assert.Equal(1, points[0].OperStatus);
        a.Set("1.3.6.1.2.1.2.2.1.8.1", new Integer32(2));
        await poller.PollOnceAsync(default);
        await poller.PollOnceAsync(default);
        a.Set("1.3.6.1.2.1.2.2.1.8.1", new Integer32(1));
        await poller.PollOnceAsync(default);

        Assert.Equal(2, changes.Count);
        Assert.True(changes[0].WentDown); Assert.Equal("port1", changes[0].Interface);
        Assert.True(changes[1].CameUp);
    }

    [Fact]
    public async Task Poller_CatchesChangeBetweenDiscoveryAndFirstPoll()
    {
        using var a = Agent();
        var s = Session(a);
        var ifs = await InterfaceDiscovery.DiscoverAsync(s, default);   // up
        a.Set("1.3.6.1.2.1.2.2.1.8.1", new Integer32(2));              // goes down before polling starts
        var poller = new DevicePoller(s, ifs);
        var changes = new List<StatusChange>(); poller.StatusChanged += c => changes.Add(c);
        await poller.PollOnceAsync(default);
        Assert.Single(changes); Assert.True(changes[0].WentDown);
    }
}
