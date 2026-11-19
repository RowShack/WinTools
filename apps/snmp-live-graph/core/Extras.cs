using System.Globalization;
using System.Text;
using Lextm.SharpSnmpLib;

namespace SnmpLiveGraph.Core;

// ================= 1. thresholds =================

/// <summary>Optional alarm levels for one interface tile. Null = not set.</summary>
public sealed class Threshold
{
    /// <summary>Utilisation percent of ifHighSpeed (applies to the busier of in/out).</summary>
    public double? UtilPercent { get; set; }
    /// <summary>Errors per second (in + out).</summary>
    public double? ErrorsPerSec { get; set; }
    public bool IsSet => UtilPercent.HasValue || ErrorsPerSec.HasValue;
}

[Flags] public enum Breach { None = 0, Utilisation = 1, Errors = 2 }

public static class ThresholdEvaluator
{
    public static double? UtilisationOf(PollPoint p) =>
        p.InUtil is null ? p.OutUtil : p.OutUtil is null ? p.InUtil : Math.Max(p.InUtil.Value, p.OutUtil.Value);

    public static double? ErrorsOf(PollPoint p) =>
        p.InErrors is null ? p.OutErrors : p.OutErrors is null ? p.InErrors : p.InErrors.Value + p.OutErrors.Value;

    /// <summary>Which thresholds the sample exceeds (strictly greater). Values that are unknown never count as exceeded.</summary>
    public static Breach Evaluate(PollPoint? p, Threshold? t)
    {
        if (p is null || t is null) return Breach.None;
        var b = Breach.None;
        if (t.UtilPercent is double u && UtilisationOf(p) is double uu && uu > u) b |= Breach.Utilisation;
        if (t.ErrorsPerSec is double e && ErrorsOf(p) is double ee && ee > e) b |= Breach.Errors;
        return b;
    }

    /// <summary>The utilisation threshold as bits/s for drawing on the bps axis; null if the link speed is unknown.</summary>
    public static double? UtilisationAsBps(double percent, long highSpeedMbps) =>
        highSpeedMbps <= 0 ? null : percent / 100.0 * highSpeedMbps * 1_000_000.0;
}

// ================= 3. interface status change log =================

public sealed record StatusChange(DateTime Time, string Device, int IfIndex, string Interface, int From, int To)
{
    public string FromText => InterfaceInfo.StatusName(From);
    public string ToText => InterfaceInfo.StatusName(To);
    public bool WentDown => To != 1 && From == 1;
    public bool CameUp => To == 1 && From != 1;
}

/// <summary>Detects ifOperStatus changes from successive samples. The first value seen for an interface is only a baseline.</summary>
public sealed class StatusTracker
{
    private readonly Dictionary<int, int> _last = [];

    /// <summary>Records a sample; returns the previous status when it differs (0 / unknown samples are ignored).</summary>
    public int? Observe(int ifIndex, int status)
    {
        if (status <= 0) return null;
        if (!_last.TryGetValue(ifIndex, out int prev)) { _last[ifIndex] = status; return null; }
        _last[ifIndex] = status;
        return prev != status ? prev : null;
    }

    /// <summary>Sets the baseline only if nothing has been observed yet for this interface.</summary>
    public void Seed(int ifIndex, int status) { if (status > 0) _last.TryAdd(ifIndex, status); }

    public void Forget(int ifIndex) => _last.Remove(ifIndex);
}

public sealed class StatusLog
{
    private readonly List<StatusChange> _items = [];
    public IReadOnlyList<StatusChange> Items => _items;
    public void Add(StatusChange c) => _items.Add(c);
    public void Clear() => _items.Clear();

    public static string Line(StatusChange c) =>
        $"{c.Time.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {c.Device}  {c.Interface}: {c.FromText} -> {c.ToText}";

    public string ToText() => string.Join("\r\n", _items.Select(Line));

    public string ToCsv()
    {
        var sb = new StringBuilder("time_utc,device,interface,from,to\r\n");
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        foreach (var c in _items) sb.Append($"{c.Time:O},{Q(c.Device)},{Q(c.Interface)},{c.FromText},{c.ToText}\r\n");
        return sb.ToString();
    }
}

// ================= 2. ad-hoc OID graphs =================

/// <summary>A numeric OID graphed as its own tile. Saved in sessions.</summary>
public sealed class CustomOidSpec
{
    public string Name { get; set; } = "";
    /// <summary>Full instance OID (e.g. ending .0 for scalars, or with the table index), no leading dot.</summary>
    public string Oid { get; set; } = "";
    /// <summary>Treat the value as a counter and graph its per-second rate instead of the raw value.</summary>
    public bool AsCounter { get; set; }
    /// <summary>Multiplier applied to every value (e.g. 0.1 for tenths of a degree).</summary>
    public double Scale { get; set; } = 1;
    public string Unit { get; set; } = "";
    public string Title => Name.Length > 0 ? Name : Oid;

    public static string Normalise(string oid) => oid.Trim().TrimStart('.');

    /// <summary>Validates dotted-numeric OID syntax; returns an error message or null.</summary>
    public static string? Validate(string oid)
    {
        oid = Normalise(oid);
        if (oid.Length == 0) return "Enter an OID.";
        var parts = oid.Split('.');
        if (parts.Length < 3 || parts.Any(p => p.Length == 0 || !p.All(char.IsAsciiDigit)))
            return "That doesn't look like a numeric OID. Use dotted numbers such as 1.3.6.1.4.1.12356.101.4.1.3.0 (names from MIB files are not supported).";
        return null;
    }
}

public sealed record OidPreset(string Group, string Name, string Oid, string Unit, bool AsCounter, string Note)
{
    public override string ToString() => $"{Group}: {Name}";
}

public static class OidPresets
{
    // Verified against oidref.com (FORTINET-FORTIGATE-MIB, CISCO-PROCESS-MIB, HOST-RESOURCES-MIB / RFC 2790).
    public static readonly IReadOnlyList<OidPreset> All =
    [
        new("FortiGate", "CPU usage % (fgSysCpuUsage)", "1.3.6.1.4.1.12356.101.4.1.3.0", "%", false, "Gauge 0-100, scalar."),
        new("FortiGate", "Active sessions (fgSysSesCount)", "1.3.6.1.4.1.12356.101.4.1.8.0", "sessions", false, "Gauge, scalar."),
        new("FortiGate", "Memory usage % (fgSysMemUsage)", "1.3.6.1.4.1.12356.101.4.1.4.0", "%", false, "Gauge 0-100, scalar."),
        new("Cisco", "CPU 5 s % (cpmCPUTotal5secRev, index 1)", "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1", "%", false,
            "CISCO-PROCESS-MIB table column (deprecated but widely implemented). The row index is device specific; 1 is typical. If it isn't found, the Test button will use the first row it finds."),
        new("Host (HOST-RESOURCES-MIB)", "Processor load % (hrProcessorLoad)", "1.3.6.1.2.1.25.3.3.1.2", "%", false,
            "Table column indexed by hrDeviceIndex, so the instance number varies. Test finds the first processor; append .<index> to pick another."),
        new("Host (HOST-RESOURCES-MIB)", "Storage used (hrStorageUsed)", "1.3.6.1.2.1.25.2.3.1.6", "units", false,
            "In hrStorageAllocationUnits, per storage row. Append the row index (walk hrStorageDescr 1.3.6.1.2.1.25.2.3.1.3 to find RAM / disks)."),
        new("Host (HOST-RESOURCES-MIB)", "Storage size (hrStorageSize)", "1.3.6.1.2.1.25.2.3.1.5", "units", false,
            "In hrStorageAllocationUnits, per storage row. Compare with the 'used' graph of the same row."),
    ];
}

public sealed record OidReading(double? Value, string? Problem)
{
    public bool Ok => Value.HasValue;
}

public static class OidParser
{
    /// <summary>Turns an SNMP value into a number, or explains in plain words why it can't be graphed.</summary>
    public static OidReading Parse(ISnmpData? d, double scale = 1)
    {
        double? v = d switch
        {
            null => null,
            Counter64 c64 => (double)c64.ToUInt64(),
            Counter32 c => c.ToUInt32(),
            Gauge32 g => g.ToUInt32(),
            Integer32 i => i.ToInt32(),
            TimeTicks t => t.ToUInt32(),
            OctetString s => double.TryParse(s.ToString().Trim().TrimEnd('%').Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : null,
            _ => null,
        };
        if (v is double ok && double.IsFinite(ok)) return new(ok * scale, null);
        if (d is null) return new(null, "OID not found on the device (no such object / instance). For table columns, append the row index.");
        if (d is OctetString os) return new(null, $"The device returned text, not a number: \"{Trunc(os.ToString())}\".");
        return new(null, $"The value is not numeric (type {d.TypeCode}: \"{Trunc(d.ToString() ?? "")}\").");
    }

    private static string Trunc(string s) => s.Length <= 40 ? s : s[..40] + "…";
}

public sealed record CustomPoint(DateTime Time, double? Value, string? Problem);

public sealed class CustomHistory
{
    private readonly List<CustomPoint> _points = [];
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(15);
    public IReadOnlyList<CustomPoint> Points => _points;

    public void Add(CustomPoint p)
    {
        _points.Add(p);
        var cutoff = p.Time - Window;
        int drop = 0;
        while (drop < _points.Count && _points[drop].Time < cutoff) drop++;
        if (drop > 0) _points.RemoveRange(0, drop);
    }

    public void Clear() => _points.Clear();
}

public sealed record ProbeResult(string ResolvedOid, OidReading Reading, int Instances);

public static class OidProbe
{
    /// <summary>
    /// Reads an OID once. If it has no value as given (typical for a table column without its row index), the subtree is walked
    /// and the first row is used; <see cref="ProbeResult.Instances"/> says how many rows exist.
    /// </summary>
    public static async Task<ProbeResult> ProbeAsync(SnmpSession s, string oid, double scale, CancellationToken ct)
    {
        oid = CustomOidSpec.Normalise(oid);
        var r = await s.GetAsync([oid], ct);
        var data = r.Values.FirstOrDefault();
        if (data is not null) return new(oid, OidParser.Parse(data, scale), 1);

        var rows = await s.WalkAsync(oid, ct);
        if (rows.Count == 0) return new(oid, OidParser.Parse(null), 0);
        return new(rows[0].Oid, OidParser.Parse(rows[0].Data, scale), rows.Count);
    }
}
