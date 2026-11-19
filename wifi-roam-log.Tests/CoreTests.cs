using System.Net;
using WifiRoamLog.Core;

namespace WifiRoamLog.Tests;

public class WifiMathTests
{
    [Theory]
    [InlineData(-100, 0)] [InlineData(-75, 50)] [InlineData(-50, 100)] [InlineData(-30, 100)] [InlineData(-120, 0)]
    public void RssiToPercent(int rssi, int pct) => Assert.Equal(pct, WifiMath.RssiToPercent(rssi));

    [Theory]
    [InlineData(0, -100)] [InlineData(50, -75)] [InlineData(100, -50)] [InlineData(150, -50)]
    public void PercentToRssi(int pct, int rssi) => Assert.Equal(rssi, WifiMath.PercentToRssi(pct));

    [Theory]
    [InlineData(-45, "Excellent")] [InlineData(-55, "Very good")] [InlineData(-65, "Good")] [InlineData(-69, "Fair")] [InlineData(-75, "Weak")] [InlineData(-90, "Poor")]
    public void SignalLabels(int rssi, string label) => Assert.Equal(label, WifiMath.SignalLabel(rssi));

    [Theory]
    [InlineData(2412, 1, WifiBand.Band24)] [InlineData(2437, 6, WifiBand.Band24)] [InlineData(2472, 13, WifiBand.Band24)] [InlineData(2484, 14, WifiBand.Band24)]
    [InlineData(5180, 36, WifiBand.Band5)] [InlineData(5200, 40, WifiBand.Band5)] [InlineData(5745, 149, WifiBand.Band5)] [InlineData(5825, 165, WifiBand.Band5)]
    [InlineData(5955, 1, WifiBand.Band6)] [InlineData(6135, 37, WifiBand.Band6)] [InlineData(5935, 2, WifiBand.Band6)] [InlineData(7115, 233, WifiBand.Band6)]
    public void ChannelAndBandFromFrequency(int mhz, int channel, WifiBand band)
    {
        Assert.Equal(channel, WifiMath.FrequencyToChannel(mhz));
        Assert.Equal(band, WifiMath.BandFromFrequency(mhz));
    }

    [Fact]
    public void UnknownFrequency()
    {
        Assert.Null(WifiMath.FrequencyToChannel(1000));
        Assert.Equal(WifiBand.Unknown, WifiMath.BandFromFrequency(3000));
    }

    [Fact]
    public void PhyNames()
    {
        Assert.Equal("802.11ax (Wi-Fi 6/6E)", WifiMath.PhyName(10));
        Assert.Equal("", WifiMath.PhyName(0));
        Assert.Equal("PHY 99", WifiMath.PhyName(99));
    }

    [Fact]
    public void AuthNames()
    {
        Assert.Equal("Open", WifiMath.AuthName(false, 1));
        Assert.Equal("WPA3-Personal", WifiMath.AuthName(true, 9));
        Assert.Equal("WPA2-Personal", WifiMath.AuthName(true, 7));
    }
}

public class ApMapTests
{
    private static ApMap Map(params (string prefix, string name)[] e)
    {
        var m = new ApMap();
        foreach (var (p, n) in e) m.Add(new ApMapEntry(Bssid.Parse(p)!, n, ""));
        return m;
    }

    [Theory]
    [InlineData("94:2A:6F:5D:A1:11", "94:2a:6f:5d:a1:11")]
    [InlineData("94-2a-6f-5d-a1-11", "94:2a:6f:5d:a1:11")]
    [InlineData("942a6f5da111", "94:2a:6f:5d:a1:11")]
    [InlineData("942a.6f5d.a111", "94:2a:6f:5d:a1:11")]
    [InlineData("00:00:00:00:00:00", "")]
    [InlineData("zz:00", "")]
    [InlineData("", "")]
    public void BssidNormalize(string input, string expected) => Assert.Equal(expected, Bssid.Normalize(input));

    [Fact]
    public void DefaultMatchesFirstFiveOctets_VirtualBssidOffsetInLastOctet()
    {
        var m = Map(("94:2a:6f:5d:a1", "FAP-2F-East"));
        Assert.Equal("FAP-2F-East", m.NameFor("94:2a:6f:5d:a1:10"));
        Assert.Equal("FAP-2F-East", m.NameFor("94:2a:6f:5d:a1:11"));   // second SSID, offset +1
        Assert.Equal("FAP-2F-East", m.NameFor("94:2a:6f:5d:a1:0f"));   // 2.4 GHz radio
        Assert.Equal("", m.NameFor("94:2a:6f:ce:39:10"));
    }

    [Fact]
    public void FullBssidEntryStillMatchesAnotherSsidOfSameAp()
    {
        var m = Map(("94:2a:6f:5d:a1:10", "AP1"));
        Assert.Equal("AP1", m.NameFor("94:2a:6f:5d:a1:11"));
        Assert.Equal("", m.NameFor("94:2a:6f:5d:a1:11", new ApMatchOptions(6)));
        Assert.Equal("AP1", m.NameFor("94:2a:6f:5d:a1:10", new ApMatchOptions(6)));
    }

    [Fact]
    public void PrefixLengthIsConfigurable()
    {
        var m = Map(("94:2a:6f", "Vendor-OUI"));
        Assert.Equal("Vendor-OUI", m.NameFor("94:2a:6f:5d:a1:10", new ApMatchOptions(3)));
        Assert.Equal("Vendor-OUI", m.NameFor("94:2a:6f:5d:a1:10"));   // entry shorter than 5: compares 3
        Assert.Equal("", m.NameFor("94:2b:6f:5d:a1:10", new ApMatchOptions(3)));
    }

    [Fact]
    public void IgnoreFirstOctetHandlesLocallyAdministeredVariants()
    {
        var m = Map(("94:2a:6f:5d:a1", "FAP-East"));
        Assert.Equal("", m.NameFor("9a:2a:6f:5d:a1:10"));
        Assert.Equal("FAP-East", m.NameFor("9a:2a:6f:5d:a1:10", new ApMatchOptions(5, true)));
        Assert.Equal("FAP-East", m.NameFor("a2:2a:6f:5d:a1:10", new ApMatchOptions(5, true)));
    }

    [Fact]
    public void IgnoreFirstOctetWithOneOctetPrefixMatchesNothing()
    {
        var m = Map(("94", "x"));
        Assert.Null(m.Lookup("94:2a:6f:5d:a1:10", new ApMatchOptions(1, true)));
    }

    [Fact]
    public void LongestEntryWins()
    {
        var m = Map(("94:2a:6f", "Generic"), ("94:2a:6f:5d:a1", "Specific"));
        Assert.Equal("Specific", m.NameFor("94:2a:6f:5d:a1:10"));
        Assert.Equal("Generic", m.NameFor("94:2a:6f:00:00:10"));
    }

    [Fact]
    public void InvalidBssidGivesNoMatch()
    {
        var m = Map(("94:2a:6f", "x"));
        Assert.Null(m.Lookup(""));
        Assert.Null(m.Lookup("94:2a:6f"));
        Assert.Null(m.Lookup(null));
    }

    [Fact]
    public void ImporterHeaderQuotesAndLocation()
    {
        var r = ApMapImporter.Parse("BSSID prefix,AP name,Location\r\n94:2a:6f:5d:a1,\"FAP-2F, East\",\"Floor 2, east wing\"\r\n94-2a-6f-d1-07,FAP-3F-West,Floor 3\r\n");
        Assert.Empty(r.Errors);
        Assert.Equal(2, r.Map.Count);
        Assert.Equal("FAP-2F, East", r.Map.Entries[0].Name);
        Assert.Equal("Floor 2, east wing", r.Map.Entries[0].Location);
        Assert.Equal("FAP-2F, East (Floor 2, east wing)", r.Map.Entries[0].Label);
        Assert.Equal("Floor 3", r.Map.Entries[1].Location);
    }

    [Fact]
    public void ImporterHandlesBomCommentsAndBlankLines()
    {
        var r = ApMapImporter.Parse("﻿# my APs\n\n94:2a:6f:5d:a1,AP1\n");
        Assert.Empty(r.Errors);
        Assert.Equal("AP1", r.Map.Entries[0].Name);
        Assert.Equal("", r.Map.Entries[0].Location);
    }

    [Fact]
    public void ImporterReportsBadLinesButKeepsGoodOnes()
    {
        var r = ApMapImporter.Parse("bssid,name\nnot-a-mac,AP0\n94:2a:6f:5d:a1,\n94:2a:6f:ce:39\n94:2a:6f:ce:3a,\"open quote\n94:2a:6f:ce:3b,Good\n");
        Assert.Single(r.Map.Entries);
        Assert.Equal("Good", r.Map.Entries[0].Name);
        Assert.Equal(4, r.Errors.Count);
        Assert.Contains("Line 2", r.Errors[0]);
        Assert.Contains("empty AP name", r.Errors[1]);
    }

    [Fact]
    public void ImporterSemicolonDelimiter()
    {
        var r = ApMapImporter.Parse("94:2a:6f:5d:a1;AP1;Lobby\n");
        Assert.Equal("Lobby", r.Map.Entries[0].Location);
    }

    [Fact]
    public void ImporterReadsFileWithBomEncoding()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "BSSID,AP,Loc\n94:2a:6f:5d:a1,Café-AP,Bar\n", new System.Text.UTF8Encoding(true));
            var r = ApMapImporter.ParseFile(path);
            Assert.Equal("Café-AP", r.Map.Entries[0].Name);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void SampleCsvInRepoParses()
    {
        var dir = AppContext.BaseDirectory;
        string? file = null;
        for (var d = new DirectoryInfo(dir); d != null; d = d.Parent)
        {
            var c = Path.Combine(d.FullName, "wifi-roam-log", "sample-ap-map.csv");
            if (File.Exists(c)) { file = c; break; }
        }
        Assert.NotNull(file);
        var r = ApMapImporter.ParseFile(file!);
        Assert.Empty(r.Errors);
        Assert.True(r.Map.Count >= 3);
    }
}

public class RoamInferrerTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 10, 0, 0);
    private static WifiSample S(int sec, string bssid, string ssid = "Corp", WlanState st = WlanState.Connected) =>
        new() { Time = T0.AddSeconds(sec), State = st, Ssid = ssid, Bssid = bssid };

    [Fact]
    public void BssidChangeInSameSsidIsInferredRoam()
    {
        var r = new RoamInferrer();
        Assert.Empty(r.Observe(S(0, "aa:aa:aa:aa:aa:01")));
        Assert.Empty(r.Observe(S(2, "aa:aa:aa:aa:aa:01")));
        var ev = Assert.Single(r.Observe(S(4, "bb:bb:bb:bb:bb:02")));
        Assert.Equal(WifiEventKind.Roam, ev.Kind);
        Assert.Equal(WifiEventSource.Inferred, ev.Source);
        Assert.Equal("aa:aa:aa:aa:aa:01", ev.OldBssid);
        Assert.Equal("bb:bb:bb:bb:bb:02", ev.NewBssid);
        Assert.Null(ev.DurationMs);
    }

    [Fact]
    public void SsidChangeIsNotARoam()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01", "Corp"));
        var ev = Assert.Single(r.Observe(S(2, "bb:bb:bb:bb:bb:02", "Guest")));
        Assert.Equal(WifiEventKind.Connect, ev.Kind);
        Assert.Contains("not a roam", ev.Detail);
    }

    [Fact]
    public void FlappingProducesOneEventPerChangeAndFlagsPingPong()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01"));
        var e1 = Assert.Single(r.Observe(S(2, "bb:bb:bb:bb:bb:02")));
        var e2 = Assert.Single(r.Observe(S(4, "aa:aa:aa:aa:aa:01")));
        var e3 = Assert.Single(r.Observe(S(6, "bb:bb:bb:bb:bb:02")));
        Assert.DoesNotContain("ping-pong", e1.Detail);
        Assert.Contains("ping-pong", e2.Detail);
        Assert.Contains("ping-pong", e3.Detail);
    }

    [Fact]
    public void PingPongNotFlaggedAfterLongTime()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01"));
        r.Observe(S(2, "bb:bb:bb:bb:bb:02"));
        var e = Assert.Single(r.Observe(S(300, "aa:aa:aa:aa:aa:01")));
        Assert.DoesNotContain("ping-pong", e.Detail);
    }

    [Fact]
    public void DisconnectAndReconnect()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01"));
        var d = Assert.Single(r.Observe(S(2, "", "", WlanState.Disconnected)));
        Assert.Equal(WifiEventKind.Disconnect, d.Kind);
        Assert.Equal("aa:aa:aa:aa:aa:01", d.OldBssid);
        Assert.Empty(r.Observe(S(4, "", "", WlanState.Disconnected)));
        var c = Assert.Single(r.Observe(S(6, "bb:bb:bb:bb:bb:02")));
        Assert.Equal(WifiEventKind.Connect, c.Kind);
    }

    [Fact]
    public void EmptyBssidOrErrorsNeverProduceEvents()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01"));
        Assert.Empty(r.Observe(S(2, "", "")));   // location blocked: connected but blank
        Assert.Empty(r.Observe(new WifiSample { Time = T0.AddSeconds(4), State = WlanState.Unknown, ErrorCode = 5 }));
        Assert.Empty(r.Observe(S(6, "aa:aa:aa:aa:aa:01")));
    }

    [Fact]
    public void TransitionalStatesAreIgnored()
    {
        var r = new RoamInferrer();
        r.Observe(S(0, "aa:aa:aa:aa:aa:01"));
        Assert.Empty(r.Observe(S(2, "", "", WlanState.Associating)));
        Assert.Single(r.Observe(S(4, "bb:bb:bb:bb:bb:02")));
    }
}

public class RoamTrackerAndMergerTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 10, 0, 0);

    [Fact]
    public void RoamDurationFromStartAndEnd()
    {
        var t = new RoamTracker();
        t.Start(T0, "aa:aa:aa:aa:aa:01");
        var ev = t.End(T0.AddMilliseconds(137), "Corp", "zz", "bb:bb:bb:bb:bb:02");
        Assert.Equal(137, ev.DurationMs);
        Assert.Equal("aa:aa:aa:aa:aa:01", ev.OldBssid);
        Assert.Equal(WifiEventSource.Notified, ev.Source);
    }

    [Fact]
    public void RoamEndWithoutStartHasNoDurationAndUsesFallbackOld()
    {
        var ev = new RoamTracker().End(T0, "Corp", "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02");
        Assert.Null(ev.DurationMs);
        Assert.Equal("aa:aa:aa:aa:aa:01", ev.OldBssid);
    }

    [Fact]
    public void DurationNeverNegative()
    {
        var t = new RoamTracker();
        t.Start(T0, "a");
        Assert.Equal(0, t.End(T0.AddSeconds(-1), "s", "", "b").DurationMs);
    }

    private static WifiEvent Roam(int sec, WifiEventSource src, string nb = "bb:bb:bb:bb:bb:02") =>
        new() { Time = T0.AddSeconds(sec), Kind = WifiEventKind.Roam, Source = src, NewBssid = nb };

    [Fact]
    public void InferredEventEmittedAfterGraceWhenNoNotification()
    {
        var m = new EventMerger();
        m.AddInferred(Roam(0, WifiEventSource.Inferred));
        Assert.Empty(m.Flush(T0.AddSeconds(2)));
        var due = Assert.Single(m.Flush(T0.AddSeconds(5)));
        Assert.Equal(WifiEventSource.Inferred, due.Source);
        Assert.Empty(m.Flush(T0.AddSeconds(30)));
    }

    [Fact]
    public void LateNotificationReplacesPendingInferred()
    {
        var m = new EventMerger();
        m.AddInferred(Roam(0, WifiEventSource.Inferred));
        m.AddNotified(Roam(1, WifiEventSource.Notified));
        Assert.Empty(m.Flush(T0.AddSeconds(60)));
    }

    [Fact]
    public void EarlierNotificationSuppressesInferred()
    {
        var m = new EventMerger();
        m.AddNotified(Roam(-1, WifiEventSource.Notified));
        m.AddInferred(Roam(1, WifiEventSource.Inferred));
        Assert.Empty(m.FlushAll());
    }

    [Fact]
    public void DifferentNewBssidIsNotSuppressed()
    {
        var m = new EventMerger();
        m.AddNotified(Roam(0, WifiEventSource.Notified, "bb:bb:bb:bb:bb:02"));
        m.AddInferred(Roam(8, WifiEventSource.Inferred, "cc:cc:cc:cc:cc:03"));
        Assert.Single(m.FlushAll());
    }

    [Fact]
    public void FarApartNotificationDoesNotSuppress()
    {
        var m = new EventMerger();
        m.AddNotified(Roam(0, WifiEventSource.Notified));
        m.AddInferred(Roam(60, WifiEventSource.Inferred));
        Assert.Single(m.FlushAll());
    }

    [Fact]
    public void DisconnectMatchesOnlyDisconnect()
    {
        var m = new EventMerger();
        m.AddInferred(new WifiEvent { Time = T0, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Inferred });
        m.AddNotified(Roam(0, WifiEventSource.Notified));
        Assert.Single(m.FlushAll());
        m.AddInferred(new WifiEvent { Time = T0, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Inferred });
        m.AddNotified(new WifiEvent { Time = T0, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Notified });
        Assert.Empty(m.FlushAll());
    }
}

public class LatencyTests
{
    private static PingSample P(double? rtt) => new(DateTime.Now, PingTarget.Gateway, "1.1.1.1", rtt, rtt is null ? "TimedOut" : "Success");

    [Fact]
    public void AggregatesLossAndStats()
    {
        var s = LatencyStats.Compute([P(10), P(20), P(null), P(30)]);
        Assert.Equal(4, s.Count);
        Assert.Equal(1, s.Lost);
        Assert.Equal(25, s.LossPct);
        Assert.Equal(20, s.AvgMs);
        Assert.Equal(10, s.MinMs);
        Assert.Equal(30, s.MaxMs);
        Assert.Equal(30, s.LastMs);
        Assert.Equal(10, s.JitterMs);   // mean |difference| of consecutive replies 10,20,30; the lost ping is skipped
    }

    [Fact]
    public void AllLost()
    {
        var s = LatencyStats.Compute([P(null), P(null)]);
        Assert.Equal(100, s.LossPct);
        Assert.Null(s.AvgMs);
        Assert.Null(s.LastMs);
    }

    [Fact]
    public void EmptyIsEmpty() => Assert.Equal(LatencyStats.Empty, LatencyStats.Compute([]));

    [Fact]
    public void WindowKeepsOnlyCapacity()
    {
        var w = new LatencyWindow(3);
        for (int i = 1; i <= 10; i++) w.Add(P(i));
        Assert.Equal(3, w.Stats.Count);
        Assert.Equal(9, w.Stats.AvgMs);
    }
}

public class LocationAndThrottleTests
{
    [Fact]
    public void ConnectedWithEmptySsidIsBlocked() =>
        Assert.Equal(LocationState.Blocked, LocationCheck.Evaluate(new WlanConnection { State = WlanState.Connected, Ssid = "", Bssid = "" }));

    [Fact]
    public void ConnectedWithZeroBssidIsBlocked() =>
        Assert.Equal(LocationState.Blocked, LocationCheck.Evaluate(new WlanConnection { State = WlanState.Connected, Ssid = "Corp", Bssid = "00:00:00:00:00:00" }));

    [Fact]
    public void AccessDeniedIsBlocked() =>
        Assert.Equal(LocationState.Blocked, LocationCheck.Evaluate(new WlanConnection { ErrorCode = 5 }));

    [Fact]
    public void NormalConnectionIsOk() =>
        Assert.Equal(LocationState.Ok, LocationCheck.Evaluate(new WlanConnection { State = WlanState.Connected, Ssid = "Corp", Bssid = "aa:bb:cc:dd:ee:ff" }));

    [Fact]
    public void DisconnectedIsNotBlocked() =>
        Assert.Equal(LocationState.NotConnected, LocationCheck.Evaluate(new WlanConnection { State = WlanState.Disconnected }));

    [Fact]
    public void NullIsNoAdapter() => Assert.Equal(LocationState.NoAdapter, LocationCheck.Evaluate(null));

    [Fact]
    public void ScanThrottleLimitsRate()
    {
        var t = new ScanThrottle(TimeSpan.FromSeconds(10));
        var now = new DateTime(2026, 1, 1);
        Assert.True(t.TryAcquire(now));
        Assert.False(t.TryAcquire(now.AddSeconds(5)));
        Assert.Equal(TimeSpan.FromSeconds(5), t.Remaining(now.AddSeconds(5)));
        Assert.True(t.TryAcquire(now.AddSeconds(10)));
    }
}

public class CsvTests
{
    [Fact]
    public void EscapeAndParseRoundTrip()
    {
        var line = Csv.Join("a,b", "say \"hi\"", "", "plain");
        var f = Csv.ParseLine(line)!;
        Assert.Equal(["a,b", "say \"hi\"", "", "plain"], f);
    }

    [Fact]
    public void UnterminatedQuoteReturnsNull() => Assert.Null(Csv.ParseLine("a,\"b"));
}

public class SessionLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wrl-test-" + Guid.NewGuid().ToString("N"));
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static readonly DateTime T0 = new(2026, 3, 4, 10, 15, 30, 123);

    private static WifiSample Sample(int s) => new()
    {
        Time = T0.AddSeconds(s), State = WlanState.Connected, Ssid = "Corp, \"main\"", Bssid = "94:2a:6f:5d:a1:11", ApName = "FAP-2F-East", RssiDbm = -61, SignalPct = 78, Channel = 40,
        FrequencyMhz = 5200, Band = WifiBand.Band5, Phy = "802.11ax (Wi-Fi 6/6E)", RxMbps = 866.7, TxMbps = 780,
    };

    [Fact]
    public void RowsAreReadableWhileWriterIsStillOpen_CrashSafety()
    {
        using var w = new SessionLogWriter(_dir, T0);
        w.AppendSample(Sample(0));
        w.AppendEvent(new WifiEvent { Time = T0, Kind = WifiEventKind.Roam, Source = WifiEventSource.Notified, OldBssid = "a", NewBssid = "b", DurationMs = 120, Detail = "x" });
        w.AppendPing(new PingSample(T0, PingTarget.Gateway, "192.168.1.1", 3.5, "Success"));
        // nothing disposed or flushed explicitly: simulates the process dying right now
        var loaded = SessionLogReader.Load(w.Folder);
        Assert.Single(loaded.Samples);
        Assert.Single(loaded.Events);
        Assert.Single(loaded.Pings);
        Assert.Equal(0, loaded.SkippedLines);
    }

    [Fact]
    public void RoundTripPreservesFields()
    {
        using (var w = new SessionLogWriter(_dir, T0, "adapter: test"))
        {
            w.AppendSample(Sample(0));
            w.AppendSample(new WifiSample { Time = T0.AddSeconds(2), State = WlanState.Disconnected });
            w.AppendEvent(new WifiEvent { Time = T0.AddSeconds(1), Kind = WifiEventKind.Roam, Source = WifiEventSource.Inferred, Ssid = "Corp", OldBssid = "a", NewBssid = "b", OldAp = "AP1", NewAp = "AP2", DurationMs = null, Detail = "has, comma" });
            w.AppendPing(new PingSample(T0, PingTarget.Target, "8.8.8.8", null, "TimedOut"));
        }
        var l = SessionLogReader.Load(Path.Combine(Directory.GetDirectories(_dir)[0], "events.csv"));   // pointing at a file loads its folder
        Assert.Equal(2, l.Samples.Length);
        var s = l.Samples[0];
        Assert.Equal(T0, s.Time);
        Assert.Equal("Corp, \"main\"", s.Ssid);
        Assert.Equal(-61, s.RssiDbm);
        Assert.Equal(WifiBand.Band5, s.Band);
        Assert.Equal(866.7, s.RxMbps);
        Assert.Equal(WlanState.Disconnected, l.Samples[1].State);
        Assert.Null(l.Samples[1].RssiDbm);
        var e = Assert.Single(l.Events);
        Assert.Equal("has, comma", e.Detail);
        Assert.Equal("AP2", e.NewAp);
        Assert.Null(e.DurationMs);
        Assert.Equal(WifiEventSource.Inferred, e.Source);
        var p = Assert.Single(l.Pings);
        Assert.True(p.Lost);
        Assert.Equal(PingTarget.Target, p.Target);
    }

    [Fact]
    public void TruncatedLastLineIsSkipped()
    {
        string folder;
        using (var w = new SessionLogWriter(_dir, T0)) { folder = w.Folder; w.AppendSample(Sample(0)); w.AppendSample(Sample(2)); }
        File.AppendAllText(Path.Combine(folder, "samples.csv"), "2026-03-04 10:15:3");
        var l = SessionLogReader.Load(folder);
        Assert.Equal(2, l.Samples.Length);
        Assert.Equal(1, l.SkippedLines);
    }

    [Fact]
    public void SessionFolderIsTimestampedAndUnique()
    {
        using var a = new SessionLogWriter(_dir, T0);
        using var b = new SessionLogWriter(_dir, T0);
        Assert.NotEqual(a.Folder, b.Folder);
        Assert.StartsWith("2026-03-04_101530", Path.GetFileName(a.Folder));
        Assert.True(File.Exists(Path.Combine(a.Folder, "session.txt")));
    }

    [Fact]
    public void SessionTxtGetsStopLine()
    {
        string folder;
        using (var w = new SessionLogWriter(_dir, T0, "info line")) folder = w.Folder;
        var txt = File.ReadAllText(Path.Combine(folder, "session.txt"));
        Assert.Contains("Started: 2026-03-04 10:15:30.123", txt);
        Assert.Contains("info line", txt);
        Assert.Contains("Stopped:", txt);
    }

    [Fact]
    public void WritesAfterDisposeAreIgnored()
    {
        var w = new SessionLogWriter(_dir, T0);
        w.Dispose();
        w.AppendSample(Sample(0));   // must not throw
        Assert.Null(w.LastError);
    }

    [Fact]
    public void LoadOfEmptyFolderThrows()
    {
        Directory.CreateDirectory(_dir);
        Assert.Throws<InvalidDataException>(() => SessionLogReader.Load(_dir));
    }

    [Fact]
    public void SessionDataKeepsEventsSortedAndTrims()
    {
        var d = new SessionData { MaxSamples = 10 };
        d.AddEvent(new WifiEvent { Time = T0.AddSeconds(5) });
        d.AddEvent(new WifiEvent { Time = T0.AddSeconds(1) });
        Assert.Equal(T0.AddSeconds(1), d.Events()[0].Time);
        for (int i = 0; i < 50; i++) d.AddSample(Sample(i));
        Assert.InRange(d.Samples().Length, 10, 11);
        Assert.Equal(T0.AddSeconds(49), d.LastSample()!.Time);
    }

    [Fact]
    public void EventExportCsvAndText()
    {
        var ev = new[] { new WifiEvent { Time = T0, Kind = WifiEventKind.Roam, Source = WifiEventSource.Notified, OldBssid = "a", NewBssid = "b", NewAp = "AP2", DurationMs = 120, Detail = "d" } };
        var csv = EventExport.ToCsv(ev);
        Assert.StartsWith("time,event,source", csv);
        Assert.Contains("Roam,Notified", csv);
        var txt = EventExport.ToText(ev);
        Assert.Contains("120 ms", txt);
        Assert.Contains("AP2", txt);
    }

    [Fact]
    public void SettingsRoundTripAndCorruptFileFallsBack()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "s.json");
        new AppSettings { Target = "10.1.1.1", PrefixOctets = 4, CloseToTray = true }.Save(path);
        var s = AppSettings.Load(path);
        Assert.Equal("10.1.1.1", s.Target);
        Assert.Equal(4, s.PrefixOctets);
        Assert.True(s.CloseToTray);
        File.WriteAllText(path, "{ not json");
        Assert.Equal("8.8.8.8", AppSettings.Load(path).Target);
        Assert.Null(AppSettings.Load(Path.Combine(_dir, "missing.json")).CloseToTray);
    }
}

/// <summary>Scriptable fake of the Wi-Fi stack.</summary>
internal sealed class FakeWlan : IWlanApi
{
    public static readonly Guid Id = Guid.NewGuid();
    public volatile WlanConnection Conn = new() { State = WlanState.Connected, Ssid = "Corp", Bssid = "aa:aa:aa:aa:aa:01", PhyType = 10, SignalQuality = 80, RssiDbm = -60, Channel = 40, RxKbps = 800_000, TxKbps = 600_000 };
    public Action<WlanNotification>? Handler;
    public bool Unregistered;
    public int Scans;
    public IReadOnlyList<WlanInterfaceInfo> EnumInterfaces() => [new(Id, "Fake", WlanState.Connected)];
    public WlanConnection QueryConnection(Guid iface) => Conn;
    public IReadOnlyList<BssEntry> GetBssList(Guid iface) => [new("Corp", "aa:aa:aa:aa:aa:01", -60, 80, 5200, 10), new("Corp", "bb:bb:bb:bb:bb:02", -55, 90, 2437, 10)];
    public IReadOnlyList<AvailableNetwork> GetAvailableNetworks(Guid iface) => [];
    public void Scan(Guid iface) => Scans++;
    public IDisposable RegisterNotifications(Action<WlanNotification> handler) { Handler = handler; return new Reg(this); }
    public void Dispose() { }
    private sealed class Reg(FakeWlan f) : IDisposable { public void Dispose() { f.Unregistered = true; } }
    public void Notify(WlanNotificationKind k, uint reason = 0, string? text = null) => Handler!(new WlanNotification(DateTime.Now, Id, k, reason, text, "Corp", "fake"));
}

internal sealed class FakePinger : IPinger
{
    public Task<(double? RttMs, string Status)> PingAsync(IPAddress a, int t, CancellationToken ct) =>
        Task.FromResult<(double?, string)>(a.ToString() == "192.168.1.1" ? (2.5, "Success") : (null, "TimedOut"));
}

internal sealed class FakeGateway : IGatewayProvider
{
    public IPAddress? Gw = IPAddress.Parse("192.168.1.1");
    public IPAddress? GetGateway(Guid g) => Gw;
}

public class MonitorTests
{
    private static async Task<(List<WifiSample> samples, List<WifiEvent> events, List<PingSample> pings)> RunAsync(FakeWlan api, FakeGateway gw, Func<Task> script, string target = "10.9.9.9", bool useNames = false)
    {
        var samples = new List<WifiSample>(); var events = new List<WifiEvent>(); var pings = new List<PingSample>();
        var map = new ApMap(); map.Add(new ApMapEntry(Bssid.Parse("bb:bb:bb:bb:bb")!, "AP-B", ""));
        var mon = new WifiMonitor(api, new FakePinger(), gw, new WifiMonitorOptions
        {
            InterfaceGuid = FakeWlan.Id, SampleInterval = TimeSpan.FromMilliseconds(100), PingInterval = TimeSpan.FromMilliseconds(100), Target = target,
            GatewayRecheck = TimeSpan.FromMilliseconds(150), ApNameResolver = b => map.NameFor(b),
        });
        mon.SampleReady += s => { lock (samples) samples.Add(s); };
        mon.EventLogged += e => { lock (events) events.Add(e); };
        mon.PingReady += p => { lock (pings) pings.Add(p); };
        using var cts = new CancellationTokenSource();
        var run = mon.RunAsync(cts.Token);
        await script();
        cts.Cancel();
        await run;
        return (samples, events, pings);
    }

    [Fact]
    public async Task SamplesAndPingsFlowAndUnregisterOnStop()
    {
        var api = new FakeWlan();
        var (samples, _, pings) = await RunAsync(api, new FakeGateway(), () => Task.Delay(700));
        Assert.NotEmpty(samples);
        var s = samples[0];
        Assert.Equal("Corp", s.Ssid);
        Assert.Equal(-60, s.RssiDbm);
        Assert.Equal(40, s.Channel);
        Assert.Equal(WifiBand.Band5, s.Band);
        Assert.Equal(5200, s.FrequencyMhz);
        Assert.Equal(800, s.RxMbps);
        Assert.Contains(pings, p => p.Target == PingTarget.Gateway && p.RttMs == 2.5);
        Assert.Contains(pings, p => p.Target == PingTarget.Target && p.Lost);
        Assert.True(api.Unregistered);
    }

    [Fact]
    public async Task NotifiedRoamHasDurationAndNoDuplicateInferred()
    {
        var api = new FakeWlan();
        var (_, events, _) = await RunAsync(api, new FakeGateway(), async () =>
        {
            await Task.Delay(300);
            api.Notify(WlanNotificationKind.RoamStart);
            await Task.Delay(80);
            api.Conn = api.Conn with { Bssid = "bb:bb:bb:bb:bb:02", Channel = 6 };
            api.Notify(WlanNotificationKind.RoamEnd);
            await Task.Delay(700);   // sampling sees the BSSID change too; the inferred event must be merged away
        });
        var roams = events.Where(e => e.Kind == WifiEventKind.Roam).ToList();
        var r = Assert.Single(roams);
        Assert.Equal(WifiEventSource.Notified, r.Source);
        Assert.Equal("aa:aa:aa:aa:aa:01", r.OldBssid);
        Assert.Equal("bb:bb:bb:bb:bb:02", r.NewBssid);
        Assert.Equal("AP-B", r.NewAp);
        Assert.InRange(r.DurationMs!.Value, 40, 600);
        Assert.Contains(events, e => e.Kind == WifiEventKind.RoamStart);
    }

    [Fact]
    public async Task DriverWithoutNotificationsGetsInferredRoamAfterGrace()
    {
        var api = new FakeWlan();
        var (_, events, _) = await RunAsync(api, new FakeGateway(), async () =>
        {
            await Task.Delay(300);
            api.Conn = api.Conn with { Bssid = "bb:bb:bb:bb:bb:02" };
            await Task.Delay(400);
        });
        var r = Assert.Single(events, e => e.Kind == WifiEventKind.Roam);   // flushed at stop at the latest
        Assert.Equal(WifiEventSource.Inferred, r.Source);
        Assert.Equal("AP-B", r.NewAp);
    }

    [Fact]
    public async Task ConnectionFailureNotificationIsLoggedWithReason()
    {
        var api = new FakeWlan();
        var (_, events, _) = await RunAsync(api, new FakeGateway(), async () =>
        {
            await Task.Delay(250);
            api.Notify(WlanNotificationKind.ConnectionFailed, 0x50001, "The network is not available");
            api.Notify(WlanNotificationKind.Disconnected, 0, null);
            await Task.Delay(100);
        });
        var f = Assert.Single(events, e => e.Kind == WifiEventKind.ConnectFail);
        Assert.Contains("not available", f.Detail);
        Assert.Contains(events, e => e.Kind == WifiEventKind.Disconnect && e.Source == WifiEventSource.Notified);
    }

    [Fact]
    public async Task GatewayChangeIsDetectedAndLogged()
    {
        var api = new FakeWlan(); var gw = new FakeGateway();
        var (_, events, pings) = await RunAsync(api, gw, async () =>
        {
            await Task.Delay(300);
            gw.Gw = IPAddress.Parse("10.0.0.1");
            await Task.Delay(500);
        });
        Assert.Contains(events, e => e.Kind == WifiEventKind.Info && e.Detail.Contains("gateway changed"));
        Assert.Contains(pings, p => p.Target == PingTarget.Gateway && p.Address == "10.0.0.1");
    }

    [Fact]
    public async Task LocationBlockedRaisesStateChange()
    {
        var api = new FakeWlan { Conn = new WlanConnection { State = WlanState.Connected, Ssid = "", Bssid = "", SignalQuality = 70 } };
        var states = new List<LocationState>();
        var mon = new WifiMonitor(api, new FakePinger(), new FakeGateway(), new WifiMonitorOptions { InterfaceGuid = FakeWlan.Id, SampleInterval = TimeSpan.FromMilliseconds(100), Target = "" });
        mon.LocationChanged += s => states.Add(s);
        using var cts = new CancellationTokenSource(500);
        await mon.RunAsync(cts.Token);
        Assert.Equal([LocationState.Blocked], states);
    }
}
