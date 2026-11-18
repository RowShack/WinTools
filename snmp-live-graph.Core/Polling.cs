using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lextm.SharpSnmpLib;

namespace SnmpLiveGraph.Core;

public sealed record InterfaceInfo(int Index, string Name, string Alias, long HighSpeedMbps, int OperStatus)
{
    public string StatusText => StatusName(OperStatus);
    public static string StatusName(int s) => s switch { 1 => "up", 2 => "down", 3 => "testing", 4 => "unknown", 5 => "dormant", 6 => "not-present", 7 => "lower-layer-down", _ => "?" };
    public string Speed => HighSpeedMbps <= 0 ? "speed unknown" : HighSpeedMbps >= 1000 ? $"{HighSpeedMbps / 1000.0:0.##} Gbps" : $"{HighSpeedMbps} Mbps";
    public override string ToString() => $"{Name}{(Alias.Length > 0 ? "  \"" + Alias + "\"" : "")}  [{StatusText}, {Speed}]";
}

public static class InterfaceDiscovery
{
    public static async Task<List<InterfaceInfo>> DiscoverAsync(SnmpSession s, CancellationToken ct)
    {
        var names = Index(await s.WalkAsync(SnmpSession.Oids.IfName, ct));
        var descr = Index(await s.WalkAsync(SnmpSession.Oids.IfDescr, ct));
        var alias = Index(await s.WalkAsync(SnmpSession.Oids.IfAlias, ct));
        var oper = Index(await s.WalkAsync(SnmpSession.Oids.IfOperStatus, ct));
        var hs = Index(await s.WalkAsync(SnmpSession.Oids.IfHighSpeed, ct));
        var sp = Index(await s.WalkAsync(SnmpSession.Oids.IfSpeed, ct));

        var all = descr.Keys.Union(names.Keys).OrderBy(i => i);
        var list = new List<InterfaceInfo>();
        foreach (var i in all)
        {
            string name = names.GetValueOrDefault(i)?.ToString() is { Length: > 0 } n ? n : descr.GetValueOrDefault(i)?.ToString() ?? $"if{i}";
            long mbps = Num(hs.GetValueOrDefault(i)) is long h && h > 0 ? h : Num(sp.GetValueOrDefault(i)) / 1_000_000;
            list.Add(new InterfaceInfo(i, name, alias.GetValueOrDefault(i)?.ToString()?.Trim() ?? "", mbps, (int)Num(oper.GetValueOrDefault(i))));
        }
        return list;
    }

    /// <summary>Maps the trailing OID component (ifIndex) to the value.</summary>
    public static Dictionary<int, ISnmpData> Index(IEnumerable<(string Oid, ISnmpData Data)> rows)
    {
        var d = new Dictionary<int, ISnmpData>();
        foreach (var (oid, data) in rows)
            if (int.TryParse(oid[(oid.LastIndexOf('.') + 1)..], out int i)) d[i] = data;
        return d;
    }

    public static long Num(ISnmpData? d) => d switch
    {
        Counter64 c64 => (long)c64.ToUInt64(),
        Counter32 c => c.ToUInt32(),
        Gauge32 g => g.ToUInt32(),
        Integer32 i => i.ToInt32(),
        TimeTicks t => t.ToUInt32(),
        _ => long.TryParse(d?.ToString(), out var v) ? v : 0,
    };

    public static ulong NumU(ISnmpData? d) => d switch
    {
        Counter64 c64 => c64.ToUInt64(),
        Counter32 c => c.ToUInt32(),
        Gauge32 g => g.ToUInt32(),
        Integer32 i => (ulong)Math.Max(0, i.ToInt32()),
        TimeTicks t => t.ToUInt32(),
        _ => ulong.TryParse(d?.ToString(), out var v) ? v : 0,
    };
}

public sealed record PollPoint(DateTime Time, double? InBps, double? OutBps, double? InUtil, double? OutUtil,
    double? InErrors, double? OutErrors, double? InDiscards, double? OutDiscards, RateSkip Skipped, int OperStatus = 0);

/// <summary>Polls all selected interfaces of one device with batched GETs and turns counters into rates.</summary>
public sealed class DevicePoller
{
    private sealed class Channel
    {
        public InterfaceInfo If = null!;
        public RateCalculator? InOct, OutOct;
        public readonly RateCalculator InErr = new(32), OutErr = new(32), InDisc = new(32), OutDisc = new(32);
    }

    private readonly SnmpSession _session;
    private readonly Dictionary<int, Channel> _channels = [];
    private bool? _use64;
    private readonly StatusTracker _status = new();
    private readonly Dictionary<string, CustomChannel> _custom = [];

    private sealed class CustomChannel
    {
        public CustomOidSpec Spec = null!;
        public RateCalculator? Rate;
    }

    public DevicePoller(SnmpSession session, IEnumerable<InterfaceInfo> interfaces)
    {
        _session = session;
        foreach (var i in interfaces) _channels[i.Index] = new Channel { If = i };
    }

    public SnmpTarget Target => _session.Target;
    public event Action<InterfaceInfo, PollPoint>? Point;
    public event Action<string>? Error;
    public event Action? Recovered;
    /// <summary>Raised when an interface's ifOperStatus differs from the previous poll.</summary>
    public event Action<StatusChange>? StatusChanged;
    public event Action<CustomOidSpec, CustomPoint>? CustomPoint;

    /// <summary>Sets the ad-hoc OIDs polled alongside the interfaces (keeps rate state for OIDs that stay).</summary>
    public void SetCustomOids(IEnumerable<CustomOidSpec> specs)
    {
        var keep = specs.GroupBy(x => x.Oid).ToDictionary(g => g.Key, g => g.First());
        foreach (var k in _custom.Keys.Where(k => !keep.ContainsKey(k)).ToList()) _custom.Remove(k);
        foreach (var sp in keep.Values)
            if (_custom.TryGetValue(sp.Oid, out var ch)) { if (ch.Spec.AsCounter != sp.AsCounter) ch.Rate = null; ch.Spec = sp; }
            else _custom[sp.Oid] = new CustomChannel { Spec = sp };
    }

    public bool HasWork => _channels.Count > 0 || _custom.Count > 0;

    public void SetInterfaces(IEnumerable<InterfaceInfo> interfaces)
    {
        var keep = interfaces.ToDictionary(i => i.Index);
        foreach (var k in _channels.Keys.Where(k => !keep.ContainsKey(k)).ToList()) _channels.Remove(k);
        foreach (var i in keep.Values) if (!_channels.ContainsKey(i.Index)) _channels[i.Index] = new Channel { If = i };
    }

    public async Task RunAsync(TimeSpan interval, CancellationToken ct)
    {
        bool failing = false;
        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                await PollOnceAsync(ct);
                if (failing) { failing = false; Recovered?.Invoke(); }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex) { failing = true; Error?.Invoke(ex.Message); }
        }
        while (await WaitAsync(timer, ct));
    }

    private static async Task<bool> WaitAsync(PeriodicTimer t, CancellationToken ct)
    {
        try { return await t.WaitForNextTickAsync(ct); } catch (OperationCanceledException) { return false; }
    }

    public async Task PollOnceAsync(CancellationToken ct)
    {
        var chans = _channels.Values.ToList();
        var customs = _custom.Values.ToList();
        if (chans.Count == 0 && customs.Count == 0) return;
        if (chans.Count > 0) _use64 ??= await Detect64Async(chans[0].If.Index, ct);
        bool hc = _use64 ?? false;
        string inOid = hc ? SnmpSession.Oids.IfHCIn : SnmpSession.Oids.IfIn32;
        string outOid = hc ? SnmpSession.Oids.IfHCOut : SnmpSession.Oids.IfOut32;

        var oids = new List<string> { SnmpSession.Oids.SysUpTime };
        foreach (var c in chans)
        {
            int i = c.If.Index;
            oids.AddRange([$"{inOid}.{i}", $"{outOid}.{i}", $"{SnmpSession.Oids.IfInErrors}.{i}", $"{SnmpSession.Oids.IfOutErrors}.{i}",
                           $"{SnmpSession.Oids.IfInDiscards}.{i}", $"{SnmpSession.Oids.IfOutDiscards}.{i}",
                           $"{SnmpSession.Oids.IfOperStatus}.{i}"]);
        }
        foreach (var cu in customs) oids.Add(cu.Spec.Oid);

        var values = new Dictionary<string, ISnmpData?>();
        foreach (var batch in oids.Chunk(40))                       // keep each request small enough for any agent
            foreach (var kv in await _session.GetAsync(batch, ct)) values[kv.Key] = kv.Value;
        var now = DateTime.UtcNow;
        long uptime = values.GetValueOrDefault(SnmpSession.Oids.SysUpTime) is TimeTicks tt ? tt.ToUInt32() : 0;

        foreach (var cu in customs)
        {
            var sp = cu.Spec;
            values.TryGetValue(sp.Oid, out var raw);
            CustomPoint cp;
            if (!sp.AsCounter) { var rd = OidParser.Parse(raw, sp.Scale); cp = new CustomPoint(now, rd.Value, rd.Problem); }
            else if (raw is Counter32 or Counter64 or Gauge32 or Integer32 or TimeTicks)
            {
                cu.Rate ??= new RateCalculator(raw is Counter64 ? 64 : 32);
                var rr = cu.Rate.Next(new CounterSample(now, InterfaceDiscovery.NumU(raw), uptime));
                cp = new CustomPoint(now, rr.PerSecond * sp.Scale, null);   // null value without a problem = first sample / skipped sample
            }
            else { var rd = OidParser.Parse(raw, sp.Scale); cp = new CustomPoint(now, null, rd.Problem ?? "Not a counter value."); }
            CustomPoint?.Invoke(sp, cp);
        }

        foreach (var c in chans)
        {
            int i = c.If.Index;
            int status = (int)InterfaceDiscovery.Num(values.GetValueOrDefault($"{SnmpSession.Oids.IfOperStatus}.{i}"));
            _status.Seed(i, c.If.OperStatus);   // baseline from discovery; no-op once the interface has been seen
            if (_status.Observe(i, status) is int from)
                StatusChanged?.Invoke(new StatusChange(now, Target.ToString(), i, c.If.Name, from, status));
            c.InOct ??= new RateCalculator(hc ? 64 : 32);
            c.OutOct ??= new RateCalculator(hc ? 64 : 32);
            RateResult R(RateCalculator calc, string oid)
            {
                var v = values.GetValueOrDefault($"{oid}.{i}");
                return v is null ? new RateResult(null, RateSkip.FirstSample) : calc.Next(new CounterSample(now, InterfaceDiscovery.NumU(v), uptime));
            }
            var rin = R(c.InOct, inOid);
            var rout = R(c.OutOct, outOid);
            var rie = R(c.InErr, SnmpSession.Oids.IfInErrors);
            var roe = R(c.OutErr, SnmpSession.Oids.IfOutErrors);
            var rid = R(c.InDisc, SnmpSession.Oids.IfInDiscards);
            var rod = R(c.OutDisc, SnmpSession.Oids.IfOutDiscards);

            double? inBps = rin.PerSecond is double a ? RateCalculator.ToBitsPerSecond(a) : null;
            double? outBps = rout.PerSecond is double b ? RateCalculator.ToBitsPerSecond(b) : null;
            Point?.Invoke(c.If, new PollPoint(now, inBps, outBps,
                inBps is double ib ? RateCalculator.Utilisation(ib, c.If.HighSpeedMbps) : null,
                outBps is double ob ? RateCalculator.Utilisation(ob, c.If.HighSpeedMbps) : null,
                rie.PerSecond, roe.PerSecond, rid.PerSecond, rod.PerSecond, rin.Skipped, status));
        }
    }

    private async Task<bool> Detect64Async(int ifIndex, CancellationToken ct)
    {
        var r = await _session.GetAsync([$"{SnmpSession.Oids.IfHCIn}.{ifIndex}"], ct);
        return r.Values.FirstOrDefault() is not null;
    }
}

/// <summary>Poll results kept in memory for the chosen window (oldest points are dropped).</summary>
public sealed class History
{
    private readonly List<PollPoint> _points = [];
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(15);
    public IReadOnlyList<PollPoint> Points => _points;

    public void Add(PollPoint p)
    {
        _points.Add(p);
        var cutoff = p.Time - Window;
        int drop = 0;
        while (drop < _points.Count && _points[drop].Time < cutoff) drop++;
        if (drop > 0) _points.RemoveRange(0, drop);
    }

    public void Clear() => _points.Clear();
}

public sealed class SavedDevice
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public string User { get; set; } = "";
    public int Port { get; set; } = 161;
    public SnmpVersion Version { get; set; }
    public AuthProto Auth { get; set; }
    public PrivProto Priv { get; set; }
    public string? ProtectedCommunity { get; set; }
    public string? ProtectedAuthPassword { get; set; }
    public string? ProtectedPrivPassword { get; set; }
    public List<int> InterfaceIndexes { get; set; } = [];
    /// <summary>Per-interface alarm levels, keyed by ifIndex.</summary>
    public Dictionary<int, Threshold> Thresholds { get; set; } = [];
    /// <summary>Ad-hoc OID tiles of this device.</summary>
    public List<CustomOidSpec> CustomOids { get; set; } = [];
    public Dictionary<int, string> InterfaceNames { get; set; } = [];
}

public sealed class SavedSession
{
    public List<SavedDevice> Devices { get; set; } = [];
    public int IntervalSeconds { get; set; } = 5;
    public int WindowMinutes { get; set; } = 15;
}

/// <summary>Sessions are stored as JSON; community strings and passwords are DPAPI-encrypted for the current user.</summary>
public static class SessionStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string Protect(string s) =>
        s.Length == 0 ? "" : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(s), null, DataProtectionScope.CurrentUser));

    public static string Unprotect(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), null, DataProtectionScope.CurrentUser)); }
        catch (CryptographicException) { return ""; }
    }

    public static SavedDevice ToSaved(SnmpTarget t, IEnumerable<InterfaceInfo> selected,
        IReadOnlyDictionary<int, Threshold>? thresholds = null, IEnumerable<CustomOidSpec>? customOids = null)
    {
        var list = selected.ToList();
        return new SavedDevice
        {
            Name = t.Name, Host = t.Host, Port = t.Port, Version = t.Version, User = t.User, Auth = t.Auth, Priv = t.Priv,
            ProtectedCommunity = Protect(t.Community), ProtectedAuthPassword = Protect(t.AuthPassword), ProtectedPrivPassword = Protect(t.PrivPassword),
            InterfaceIndexes = list.Select(i => i.Index).ToList(), InterfaceNames = list.ToDictionary(i => i.Index, i => i.Name),
            Thresholds = (thresholds ?? new Dictionary<int, Threshold>()).Where(kv => kv.Value.IsSet && list.Any(i => i.Index == kv.Key))
                .ToDictionary(kv => kv.Key, kv => new Threshold { UtilPercent = kv.Value.UtilPercent, ErrorsPerSec = kv.Value.ErrorsPerSec }),
            CustomOids = (customOids ?? []).Select(c => new CustomOidSpec { Name = c.Name, Oid = c.Oid, AsCounter = c.AsCounter, Scale = c.Scale, Unit = c.Unit }).ToList(),
        };
    }

    public static SnmpTarget ToTarget(SavedDevice d) => new()
    {
        Name = d.Name, Host = d.Host, Port = d.Port, Version = d.Version, User = d.User, Auth = d.Auth, Priv = d.Priv,
        Community = Unprotect(d.ProtectedCommunity), AuthPassword = Unprotect(d.ProtectedAuthPassword), PrivPassword = Unprotect(d.ProtectedPrivPassword),
    };

    public static void Save(string path, SavedSession s) => File.WriteAllText(path, JsonSerializer.Serialize(s, Json));
    public static SavedSession Load(string path) => JsonSerializer.Deserialize<SavedSession>(File.ReadAllText(path)) ?? new();
}

public static class CsvExport
{
    public static string Build(IEnumerable<(string Series, PollPoint P)> rows)
    {
        var sb = new StringBuilder("time_utc,interface,in_bps,out_bps,in_util_pct,out_util_pct,in_errors_s,out_errors_s,in_discards_s,out_discards_s\r\n");
        static string F(double? v) => v?.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture) ?? "";
        foreach (var (s, p) in rows)
            sb.Append($"{p.Time:O},\"{s.Replace("\"", "\"\"")}\",{F(p.InBps)},{F(p.OutBps)},{F(p.InUtil)},{F(p.OutUtil)},{F(p.InErrors)},{F(p.OutErrors)},{F(p.InDiscards)},{F(p.OutDiscards)}\r\n");
        return sb.ToString();
    }

    public static string BuildCustom(IEnumerable<(string Series, CustomPoint P)> rows)
    {
        var sb = new StringBuilder("time_utc,series,value,note\r\n");
        foreach (var (s, p) in rows)
            sb.Append($"{p.Time:O},\"{s.Replace("\"", "\"\"")}\",{p.Value?.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture)},\"{(p.Problem ?? "").Replace("\"", "\"\"")}\"\r\n");
        return sb.ToString();
    }
}
