using SnmpLiveGraph.Core;

namespace SnmpLiveGraph.Tests;

public class RateTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static CounterSample S(int sec, ulong v, long up = 0) => new(T0.AddSeconds(sec), v, up == 0 ? sec * 100L + 1000 : up);

    [Fact]
    public void FirstSampleHasNoRate()
    {
        var r = new RateCalculator(64).Next(S(0, 100));
        Assert.False(r.HasValue); Assert.Equal(RateSkip.FirstSample, r.Skipped);
    }

    [Fact]
    public void SimpleRate()
    {
        var c = new RateCalculator(64);
        c.Next(S(0, 1000));
        var r = c.Next(S(2, 3000));
        Assert.Equal(1000.0, r.PerSecond);   // 2000 octets in 2 s
        Assert.Equal(RateSkip.None, r.Skipped);
    }

    [Fact]
    public void ThirtyTwoBitWrapIsHandled()
    {
        var c = new RateCalculator(32);
        c.Next(S(0, 4_294_967_000));
        var r = c.Next(S(1, 500));            // wrapped: 296 to reach 2^32, plus 500
        Assert.Equal(796.0, r.PerSecond);
    }

    [Fact]
    public void SixtyFourBitDecreaseIsAReset_NotAWrap()
    {
        var c = new RateCalculator(64);
        c.Next(S(0, 5_000_000));
        var r = c.Next(S(1, 100));
        Assert.False(r.HasValue); Assert.Equal(RateSkip.CounterReset, r.Skipped);
        // and the next interval works normally again
        Assert.Equal(900.0, c.Next(S(2, 1000)).PerSecond);
    }

    [Fact]
    public void DeviceRestartDetectedViaSysUpTime_EvenIfCounterLooksPlausible()
    {
        var c = new RateCalculator(32);
        c.Next(new CounterSample(T0, 1_000_000, 500_000));
        var r = c.Next(new CounterSample(T0.AddSeconds(1), 2_000_000, 100));   // uptime went backwards, counter went up
        Assert.Equal(RateSkip.DeviceRestarted, r.Skipped);
        Assert.False(r.HasValue);
    }

    [Fact]
    public void RestartSkipsOnlyOneSample()
    {
        var c = new RateCalculator(32);
        c.Next(new CounterSample(T0, 10, 1000));
        c.Next(new CounterSample(T0.AddSeconds(1), 5, 50));       // restart
        var r = c.Next(new CounterSample(T0.AddSeconds(2), 105, 150));
        Assert.Equal(100.0, r.PerSecond);
    }

    [Fact]
    public void MissingSamples_LongGapIsSkippedNotAveraged()
    {
        var c = new RateCalculator(32, TimeSpan.FromSeconds(60));
        c.Next(S(0, 0));
        var r = c.Next(S(120, 1_000_000));
        Assert.Equal(RateSkip.GapTooLong, r.Skipped);
        Assert.Equal(1000.0, c.Next(S(121, 1_001_000)).PerSecond);
    }

    [Fact]
    public void ShortGapStillGivesCorrectAverageRate()
    {
        var c = new RateCalculator(64);
        c.Next(S(0, 0));
        Assert.Equal(500.0, c.Next(S(10, 5000)).PerSecond);   // one missed poll: rate over 10 s
    }

    [Fact]
    public void NonPositiveIntervalIsRejected()
    {
        var c = new RateCalculator(64);
        c.Next(S(5, 0));
        Assert.Equal(RateSkip.NonPositiveInterval, c.Next(S(5, 10)).Skipped);
        Assert.Equal(RateSkip.NonPositiveInterval, c.Next(S(4, 20)).Skipped);
    }

    [Fact]
    public void ZeroTrafficIsZeroRate_NotSkipped()
    {
        var c = new RateCalculator(64);
        c.Next(S(0, 777));
        var r = c.Next(S(1, 777));
        Assert.True(r.HasValue); Assert.Equal(0.0, r.PerSecond);
    }

    [Fact]
    public void ResetClearsHistory()
    {
        var c = new RateCalculator(64);
        c.Next(S(0, 0)); c.Reset();
        Assert.Equal(RateSkip.FirstSample, c.Next(S(1, 100)).Skipped);
    }

    [Theory]
    [InlineData(125_000_000.0, 1000, 100.0)]   // 1 Gbps link, 1 Gbit/s traffic
    [InlineData(12_500_000.0, 1000, 10.0)]
    [InlineData(0.0, 1000, 0.0)]
    public void Utilisation(double octetsPerSec, long mbps, double expectedPercent) =>
        Assert.Equal(expectedPercent, RateCalculator.Utilisation(RateCalculator.ToBitsPerSecond(octetsPerSec), mbps)!.Value, 6);

    [Fact] public void UtilisationUnknownWhenSpeedIsZero() => Assert.Null(RateCalculator.Utilisation(1_000_000, 0));

    [Theory]
    [InlineData(500, "500 bps")] [InlineData(1500, "1.5 kbps")] [InlineData(2_500_000, "2.5 Mbps")] [InlineData(3_000_000_000, "3 Gbps")]
    public void Formatting(double bps, string expected)
    {
        var old = System.Globalization.CultureInfo.CurrentCulture;
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;   // UI uses the user's culture; test pins one
        try { Assert.Equal(expected, RateCalculator.FormatBps(bps)); } finally { System.Globalization.CultureInfo.CurrentCulture = old; }
    }

    [Fact]
    public void StatsTrackCurrentAveragePeak()
    {
        var s = new Stats();
        Assert.Null(s.Average);
        s.Add(10); s.Add(30); s.Add(20);
        Assert.Equal(20, s.Current); Assert.Equal(20, s.Average); Assert.Equal(30, s.Peak);
        s.Clear(); Assert.Null(s.Current); Assert.Null(s.Peak);
    }
}
