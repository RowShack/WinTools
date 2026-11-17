namespace SnmpLiveGraph.Core;

public enum RateSkip { None, FirstSample, DeviceRestarted, CounterReset, NonPositiveInterval, GapTooLong }

/// <summary>One raw reading of a counter plus the device's sysUpTime (hundredths of a second) at that moment.</summary>
public readonly record struct CounterSample(DateTime Time, ulong Value, long UpTimeTicks);

public readonly record struct RateResult(double? PerSecond, RateSkip Skipped)
{
    public bool HasValue => PerSecond.HasValue;
}

/// <summary>
/// Turns successive counter readings into per-second rates. Handles 32-bit wrap, counter resets
/// (detected through sysUpTime going backwards) and missing samples (long gaps are skipped, not averaged).
/// </summary>
public sealed class RateCalculator(int counterBits, TimeSpan? maxGap = null)
{
    private readonly ulong _modulus = counterBits >= 64 ? 0 : 1UL << counterBits;
    private readonly TimeSpan _maxGap = maxGap ?? TimeSpan.FromMinutes(5);
    private CounterSample? _prev;

    public int CounterBits { get; } = counterBits;

    public void Reset() => _prev = null;

    public RateResult Next(CounterSample s)
    {
        var prev = _prev;
        _prev = s;
        if (prev is null) return new(null, RateSkip.FirstSample);

        var p = prev.Value;
        double seconds = (s.Time - p.Time).TotalSeconds;
        if (seconds <= 0) return new(null, RateSkip.NonPositiveInterval);

        // The device rebooted or its SNMP agent restarted: counters restarted from zero, the delta is meaningless.
        if (s.UpTimeTicks < p.UpTimeTicks) return new(null, RateSkip.DeviceRestarted);

        if (seconds > _maxGap.TotalSeconds) return new(null, RateSkip.GapTooLong);

        ulong delta;
        if (s.Value >= p.Value) delta = s.Value - p.Value;
        else if (_modulus != 0)
        {
            // 32-bit counter wrapped. Only plausible if we did not skip so long that it could wrap twice (checked by _maxGap).
            delta = s.Value + _modulus - p.Value;
        }
        else return new(null, RateSkip.CounterReset);   // 64-bit counters do not wrap in practice: a decrease is a reset

        return new(delta / seconds, RateSkip.None);
    }

    /// <summary>Bits per second from an octet rate.</summary>
    public static double ToBitsPerSecond(double octetsPerSecond) => octetsPerSecond * 8.0;

    /// <summary>Utilisation percent; <paramref name="highSpeedMbps"/> is ifHighSpeed. Null when the speed is unknown (0).</summary>
    public static double? Utilisation(double bitsPerSecond, long highSpeedMbps) =>
        highSpeedMbps <= 0 ? null : Math.Min(999.0, bitsPerSecond / (highSpeedMbps * 1_000_000.0) * 100.0);

    public static string FormatBps(double bps) => bps switch
    {
        >= 1e9 => $"{bps / 1e9:0.##} Gbps",
        >= 1e6 => $"{bps / 1e6:0.##} Mbps",
        >= 1e3 => $"{bps / 1e3:0.##} kbps",
        _ => $"{bps:0} bps",
    };
}

/// <summary>Running current / average / peak for a series shown on screen.</summary>
public sealed class Stats
{
    private double _sum; private long _n;
    public double? Current { get; private set; }
    public double? Peak { get; private set; }
    public double? Average => _n == 0 ? null : _sum / _n;

    public void Add(double v) { Current = v; _sum += v; _n++; Peak = Peak is double p ? Math.Max(p, v) : v; }
    public void Clear() { _sum = 0; _n = 0; Current = null; Peak = null; }
}
