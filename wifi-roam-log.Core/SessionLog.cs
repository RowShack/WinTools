using System.Globalization;
using System.Text;

namespace WifiRoamLog.Core;

/// <summary>Thread-safe in-memory store behind the charts and the events table (live session or an opened log).</summary>
public sealed class SessionData
{
    private readonly object _gate = new();
    private readonly List<WifiSample> _samples = [];
    private readonly List<WifiEvent> _events = [];
    private readonly List<PingSample> _pings = [];
    public int MaxSamples { get; init; } = 100_000;
    public int MaxPings { get; init; } = 300_000;
    private long _version;
    public long Version => Interlocked.Read(ref _version);

    public void AddSample(WifiSample s) { lock (_gate) { _samples.Add(s); Trim(_samples, MaxSamples); _version++; } }
    public void AddPing(PingSample p) { lock (_gate) { _pings.Add(p); Trim(_pings, MaxPings); _version++; } }
    public void AddEvent(WifiEvent e)
    {
        lock (_gate)
        {
            int i = _events.Count;
            while (i > 0 && _events[i - 1].Time > e.Time) i--;   // keep sorted; usually appends
            _events.Insert(i, e);
            _version++;
        }
    }
    private static void Trim<T>(List<T> l, int max) { if (l.Count > max + max / 10) l.RemoveRange(0, l.Count - max); }

    public WifiSample[] Samples() { lock (_gate) return _samples.ToArray(); }
    public WifiEvent[] Events() { lock (_gate) return _events.ToArray(); }
    public PingSample[] Pings() { lock (_gate) return _pings.ToArray(); }
    public WifiSample? LastSample() { lock (_gate) return _samples.Count > 0 ? _samples[^1] : null; }
    public WifiEvent? LastRoam() { lock (_gate) return _events.LastOrDefault(e => e.Kind == WifiEventKind.Roam); }

    public void Clear() { lock (_gate) { _samples.Clear(); _events.Clear(); _pings.Clear(); _version++; } }
}

public static class LogFormat
{
    public const string TimeFormat = "yyyy-MM-dd HH:mm:ss.fff";
    public static readonly string[] SampleHeader = ["time", "state", "ssid", "bssid", "ap_name", "rssi_dbm", "signal_pct", "channel", "frequency_mhz", "band", "phy", "rx_mbps", "tx_mbps", "error_code"];
    public static readonly string[] EventHeader = ["time", "event", "source", "ssid", "old_bssid", "new_bssid", "old_ap", "new_ap", "duration_ms", "detail"];
    public static readonly string[] PingHeader = ["time", "target", "address", "rtt_ms", "status"];

    private static string N(double? v, string fmt = "0.##") => v is null ? "" : v.Value.ToString(fmt, CultureInfo.InvariantCulture);
    private static string I(int? v) => v is null ? "" : v.Value.ToString(CultureInfo.InvariantCulture);
    public static string T(DateTime t) => t.ToString(TimeFormat, CultureInfo.InvariantCulture);

    public static string SampleLine(WifiSample s) => Csv.Join(T(s.Time), s.State.ToString(), s.Ssid, s.Bssid, s.ApName, I(s.RssiDbm), I(s.SignalPct), I(s.Channel), I(s.FrequencyMhz),
        s.Band == WifiBand.Unknown ? "" : WifiMath.BandName(s.Band), s.Phy, N(s.RxMbps), N(s.TxMbps), s.ErrorCode.ToString(CultureInfo.InvariantCulture));

    public static string EventLine(WifiEvent e) => Csv.Join(T(e.Time), e.Kind.ToString(), e.Source.ToString(), e.Ssid, e.OldBssid, e.NewBssid, e.OldAp, e.NewAp, N(e.DurationMs, "0"), e.Detail);

    public static string PingLine(PingSample p) => Csv.Join(T(p.Time), p.Target.ToString(), p.Address, N(p.RttMs, "0.###"), p.Status);

    public static bool TryTime(string s, out DateTime t) => DateTime.TryParseExact(s, TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out t);

    public static WifiSample? ParseSample(IReadOnlyList<string> f)
    {
        if (f.Count < 14 || !TryTime(f[0], out var t) || !Enum.TryParse<WlanState>(f[1], out var st)) return null;
        return new WifiSample
        {
            Time = t, State = st, Ssid = f[2], Bssid = f[3], ApName = f[4], RssiDbm = PI(f[5]), SignalPct = PI(f[6]), Channel = PI(f[7]), FrequencyMhz = PI(f[8]),
            Band = f[9] switch { "2.4 GHz" => WifiBand.Band24, "5 GHz" => WifiBand.Band5, "6 GHz" => WifiBand.Band6, _ => WifiBand.Unknown },
            Phy = f[10], RxMbps = PD(f[11]), TxMbps = PD(f[12]), ErrorCode = uint.TryParse(f[13], out var ec) ? ec : 0,
        };
    }

    public static WifiEvent? ParseEvent(IReadOnlyList<string> f)
    {
        if (f.Count < 10 || !TryTime(f[0], out var t) || !Enum.TryParse<WifiEventKind>(f[1], out var k) || !Enum.TryParse<WifiEventSource>(f[2], out var src)) return null;
        return new WifiEvent { Time = t, Kind = k, Source = src, Ssid = f[3], OldBssid = f[4], NewBssid = f[5], OldAp = f[6], NewAp = f[7], DurationMs = PD(f[8]), Detail = f[9] };
    }

    public static PingSample? ParsePing(IReadOnlyList<string> f)
    {
        if (f.Count < 5 || !TryTime(f[0], out var t) || !Enum.TryParse<PingTarget>(f[1], out var tg)) return null;
        return new PingSample(t, tg, f[2], PD(f[3]), f[4]);
    }

    private static int? PI(string s) => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
    private static double? PD(string s) => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null;
}

/// <summary>Appends to samples.csv / events.csv / pings.csv in a timestamped session folder. Every row is written and flushed immediately,
/// so the files survive a crash (and can be read by other programs while logging).</summary>
public sealed class SessionLogWriter : IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _samples, _events, _pings;
    private readonly string _infoPath;
    private bool _disposed;
    public string Folder { get; }
    public string? LastError { get; private set; }

    public static string DefaultBaseFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WifiRoamLog");

    public SessionLogWriter(string baseFolder, DateTime start, string info = "")
    {
        string name = start.ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
        string folder = Path.Combine(baseFolder, name);
        for (int i = 2; Directory.Exists(folder); i++) folder = Path.Combine(baseFolder, name + "_" + i);
        Directory.CreateDirectory(folder);
        Folder = folder;
        _samples = Open("samples.csv", LogFormat.SampleHeader);
        _events = Open("events.csv", LogFormat.EventHeader);
        _pings = Open("pings.csv", LogFormat.PingHeader);
        _infoPath = Path.Combine(folder, "session.txt");
        File.WriteAllText(_infoPath, $"Started: {LogFormat.T(start)}{Environment.NewLine}{info}{Environment.NewLine}", new UTF8Encoding(false));
    }

    private StreamWriter Open(string file, string[] header)
    {
        var fs = new FileStream(Path.Combine(Folder, file), FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);
        var w = new StreamWriter(fs, new UTF8Encoding(true)) { AutoFlush = true, NewLine = "\r\n" };
        w.WriteLine(string.Join(',', header));
        return w;
    }

    private void Write(StreamWriter w, string line)
    {
        lock (_gate)
        {
            if (_disposed) return;
            try { w.WriteLine(line); }
            catch (Exception ex) { LastError = ex.Message; }
        }
    }

    public void AppendSample(WifiSample s) => Write(_samples, LogFormat.SampleLine(s));
    public void AppendEvent(WifiEvent e) => Write(_events, LogFormat.EventLine(e));
    public void AppendPing(PingSample p) => Write(_pings, LogFormat.PingLine(p));

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                _samples.Dispose(); _events.Dispose(); _pings.Dispose();
                File.AppendAllText(_infoPath, $"Stopped: {LogFormat.T(DateTime.Now)}{Environment.NewLine}", new UTF8Encoding(false));
            }
            catch (Exception ex) { LastError = ex.Message; }
        }
    }
}

public sealed record LoadedSession(string Folder, WifiSample[] Samples, WifiEvent[] Events, PingSample[] Pings, int SkippedLines);

public static class SessionLogReader
{
    /// <summary>Loads a session folder, or the folder that contains the given CSV file. Unreadable lines (e.g. a half-written last line after a crash) are skipped and counted.</summary>
    public static LoadedSession Load(string path, CancellationToken ct = default)
    {
        string folder = Directory.Exists(path) ? path : Path.GetDirectoryName(Path.GetFullPath(path)) ?? path;
        int skipped = 0;
        var samples = Read(Path.Combine(folder, "samples.csv"), LogFormat.ParseSample, ref skipped, ct);
        var events = Read(Path.Combine(folder, "events.csv"), LogFormat.ParseEvent, ref skipped, ct);
        var pings = Read(Path.Combine(folder, "pings.csv"), LogFormat.ParsePing, ref skipped, ct);
        if (samples.Count == 0 && events.Count == 0 && pings.Count == 0)
            throw new InvalidDataException("No samples.csv / events.csv / pings.csv with data found in " + folder);
        return new LoadedSession(folder, [.. samples.OrderBy(s => s.Time)], [.. events.OrderBy(e => e.Time)], [.. pings.OrderBy(p => p.Time)], skipped);
    }

    private static List<T> Read<T>(string file, Func<IReadOnlyList<string>, T?> parse, ref int skipped, CancellationToken ct) where T : class
    {
        var res = new List<T>();
        if (!File.Exists(file)) return res;
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sr = new StreamReader(fs, Encoding.UTF8, true);
        string? line = sr.ReadLine();   // header
        while ((line = sr.ReadLine()) is not null)
        {
            ct.ThrowIfCancellationRequested();
            if (line.Length == 0) continue;
            var f = Csv.ParseLine(line);
            var item = f is null ? null : parse(f);
            if (item is null) skipped++; else res.Add(item);
        }
        return res;
    }

    public static SessionData ToSessionData(LoadedSession s)
    {
        var d = new SessionData { MaxSamples = int.MaxValue / 2, MaxPings = int.MaxValue / 2 };
        foreach (var x in s.Samples) d.AddSample(x);
        foreach (var x in s.Events) d.AddEvent(x);
        foreach (var x in s.Pings) d.AddPing(x);
        return d;
    }
}

public static class EventExport
{
    public static string ToCsv(IEnumerable<WifiEvent> events) =>
        string.Join("\r\n", new[] { string.Join(',', LogFormat.EventHeader) }.Concat(events.Select(LogFormat.EventLine))) + "\r\n";

    public static string ToText(IEnumerable<WifiEvent> events) =>
        string.Join("\r\n", events.Select(e =>
            $"{LogFormat.T(e.Time)}\t{e.Kind}\t{e.Source}\t{e.Ssid}\t{(e.OldAp.Length > 0 ? e.OldAp : e.OldBssid)}\t{(e.NewAp.Length > 0 ? e.NewAp : e.NewBssid)}\t{(e.DurationMs is { } d ? d.ToString("0") + " ms" : "")}\t{e.Detail}")) + "\r\n";
}
