using System.Net;

namespace HostTop.Core;

/// <summary>
/// Collects <see cref="FlowEvent"/>s and turns them into per-second rates, totals and 60 s history for three views:
/// by remote host, by process and by connection. Add() may be called from any thread; Tick() closes the current
/// bucket (call it about once a second) and returns an immutable snapshot.
/// </summary>
public sealed class FlowAggregator
{
    public const int HistoryLength = 60;
    private static readonly TimeSpan ConnActive = TimeSpan.FromSeconds(30);

    private sealed class Entry
    {
        public long PendDown, PendUp, TotalDown, TotalUp;
        public double DownRate, UpRate;
        public readonly double[] DownHist = new double[HistoryLength];
        public readonly double[] UpHist = new double[HistoryLength];
        public int Pos;           // next write position in the ring
        public DateTime LastActive;
        public NetClass Class;
        // descriptive data
        public IPAddress? Remote;
        public ProcIdentity? Proc;
        public FlowProtocol Protocol;
        public string Local = "", RemoteEndpoint = "", Service = "";
        public HashSet<string>? Names;           // host: process names
        public HashSet<IPAddress>? RemoteHosts;  // process: remote IPs
        public HashSet<string>? Services;        // host: service names

        public void Close(double dt, DateTime now)
        {
            DownRate = PendDown / dt; UpRate = PendUp / dt;
            DownHist[Pos] = DownRate; UpHist[Pos] = UpRate;
            Pos = (Pos + 1) % HistoryLength;
            if (PendDown > 0 || PendUp > 0) LastActive = now;
            PendDown = PendUp = 0;
        }

        public double[] Ordered(double[] ring)
        {
            var r = new double[HistoryLength];
            for (int i = 0; i < HistoryLength; i++) r[i] = ring[(Pos + i) % HistoryLength];
            return r;
        }
    }

    private readonly object _lock = new();
    private readonly IProcessResolver _procs;
    private readonly Dictionary<IPAddress, Entry> _hosts = [];
    private readonly Dictionary<string, Entry> _processes = [];
    private readonly Dictionary<string, Entry> _conns = [];
    private DateTime? _lastTick;
    private long _wireDown, _wireUp, _loopDown, _loopUp;           // pending in current bucket
    private long _totalDown, _totalUp;
    private double _downRate, _upRate, _loopDownRate, _loopUpRate;

    public bool IncludeLoopback { get; set; }
    public bool IncludeLan { get; set; } = true;
    public bool IncludeInternet { get; set; } = true;
    /// <summary>Rows with no traffic for this long are dropped.</summary>
    public TimeSpan IdleExpiry { get; set; } = TimeSpan.FromMinutes(5);

    public FlowAggregator(IProcessResolver procs) => _procs = procs;

    public void Add(FlowEvent e)
    {
        var cls = AddressClassifier.Classify(e.Remote, e.Local);
        var proc = _procs.Resolve(e.Pid);
        lock (_lock)
        {
            // Machine totals ignore the view toggles, but loopback never touches the wire.
            if (cls == NetClass.Loopback) { if (e.IsSend) _loopUp += e.Bytes; else _loopDown += e.Bytes; }
            else
            {
                if (e.IsSend) { _wireUp += e.Bytes; _totalUp += e.Bytes; } else { _wireDown += e.Bytes; _totalDown += e.Bytes; }
            }

            if (cls == NetClass.Loopback && !IncludeLoopback) return;
            if (cls == NetClass.Lan && !IncludeLan) return;
            if (cls == NetClass.Internet && !IncludeInternet) return;

            var remote = e.Remote.IsIPv4MappedToIPv6 ? e.Remote.MapToIPv4() : e.Remote;
            var service = ServiceNames.Describe(e.Protocol, e.LocalPort, e.RemotePort);

            if (!_hosts.TryGetValue(remote, out var h))
                _hosts[remote] = h = new Entry { Remote = remote, Class = cls, Names = [], Services = [] };
            Touch(h, e);
            h.Names!.Add(proc.Name);
            if (service != "") h.Services!.Add(service);

            if (!_processes.TryGetValue(proc.Id, out var p))
                _processes[proc.Id] = p = new Entry { Proc = proc, Class = cls, RemoteHosts = [] };
            Touch(p, e);
            p.RemoteHosts!.Add(remote);

            // UDP has no connections: group by local port + remote endpoint (local address varies with the interface used).
            var local = e.Protocol == FlowProtocol.Udp ? "*:" + e.LocalPort : Endpoint(e.Local, e.LocalPort);
            var rem = Endpoint(remote, e.RemotePort);
            var key = $"{proc.Id}|{e.Protocol}|{local}|{rem}";
            if (!_conns.TryGetValue(key, out var c))
                _conns[key] = c = new Entry { Proc = proc, Remote = remote, Class = cls, Protocol = e.Protocol, Local = local, RemoteEndpoint = rem, Service = service };
            Touch(c, e);
        }
    }

    private static void Touch(Entry en, FlowEvent e)
    {
        if (e.IsSend) { en.PendUp += e.Bytes; en.TotalUp += e.Bytes; } else { en.PendDown += e.Bytes; en.TotalDown += e.Bytes; }
    }

    public static string Endpoint(IPAddress a, int port) =>
        a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{a}]:{port}" : $"{a}:{port}";

    /// <summary>Closes the current bucket. <paramref name="now"/> is passed in so tests control time.</summary>
    public FlowSnapshot Tick(DateTime now)
    {
        lock (_lock)
        {
            double dt = _lastTick is { } lt ? Math.Max((now - lt).TotalSeconds, 0.001) : 1.0;
            _lastTick = now;

            _downRate = _wireDown / dt; _upRate = _wireUp / dt;
            _loopDownRate = _loopDown / dt; _loopUpRate = _loopUp / dt;
            _wireDown = _wireUp = _loopDown = _loopUp = 0;

            foreach (var d in new IEnumerable<Entry>[] { _hosts.Values, _processes.Values, _conns.Values })
                foreach (var en in d) en.Close(dt, now);

            Prune(_hosts, now); Prune(_processes, now); Prune(_conns, now);

            // active connection count per host
            var connCount = new Dictionary<IPAddress, int>();
            foreach (var c in _conns.Values)
                if (now - c.LastActive <= ConnActive) connCount[c.Remote!] = connCount.GetValueOrDefault(c.Remote!) + 1;

            var hosts = _hosts.Values.Select(h => new FlowRow
            {
                Id = h.Remote!.ToString(), Name = h.Remote.ToString(), Remote = h.Remote, Class = h.Class,
                DownRate = h.DownRate, UpRate = h.UpRate, TotalDown = h.TotalDown, TotalUp = h.TotalUp,
                Count = connCount.GetValueOrDefault(h.Remote), Related = string.Join(", ", h.Names!.Order()),
                Service = string.Join(", ", h.Services!.Order()),
                DownHistory = h.Ordered(h.DownHist), UpHistory = h.Ordered(h.UpHist),
            }).ToList();

            var procs = _processes.Values.Select(p => new FlowRow
            {
                Id = p.Proc!.Id, Name = p.Proc.Name, Pid = p.Proc.Pid, Path = p.Proc.Path, Class = p.Class,
                DownRate = p.DownRate, UpRate = p.UpRate, TotalDown = p.TotalDown, TotalUp = p.TotalUp,
                Count = p.RemoteHosts!.Count, Related = Summarise(p.RemoteHosts.Select(x => x.ToString())),
                DownHistory = p.Ordered(p.DownHist), UpHistory = p.Ordered(p.UpHist),
            }).ToList();

            var conns = _conns.Select(kv => new FlowRow
            {
                Id = kv.Key, Name = kv.Value.Proc!.Name, Pid = kv.Value.Proc.Pid, Path = kv.Value.Proc.Path,
                Remote = kv.Value.Remote, Class = kv.Value.Class, Protocol = kv.Value.Protocol,
                Local = kv.Value.Local, RemoteEndpoint = kv.Value.RemoteEndpoint, Service = kv.Value.Service,
                DownRate = kv.Value.DownRate, UpRate = kv.Value.UpRate, TotalDown = kv.Value.TotalDown, TotalUp = kv.Value.TotalUp,
                DownHistory = kv.Value.Ordered(kv.Value.DownHist), UpHistory = kv.Value.Ordered(kv.Value.UpHist),
            }).ToList();

            return new FlowSnapshot
            {
                Time = now, Hosts = hosts, Processes = procs, Connections = conns,
                DownRate = _downRate, UpRate = _upRate, TotalDown = _totalDown, TotalUp = _totalUp,
                LoopbackDownRate = _loopDownRate, LoopbackUpRate = _loopUpRate,
            };
        }
    }

    private void Prune<TKey>(Dictionary<TKey, Entry> d, DateTime now) where TKey : notnull
    {
        List<TKey>? dead = null;
        foreach (var kv in d) if (now - kv.Value.LastActive > IdleExpiry) (dead ??= []).Add(kv.Key);
        if (dead != null) foreach (var k in dead) d.Remove(k);
    }

    private static string Summarise(IEnumerable<string> items)
    {
        var l = items.Order().ToList();
        return l.Count <= 3 ? string.Join(", ", l) : string.Join(", ", l.Take(3)) + $" +{l.Count - 3}";
    }

    public void Clear()
    {
        lock (_lock)
        {
            _hosts.Clear(); _processes.Clear(); _conns.Clear();
            _totalDown = _totalUp = 0; _wireDown = _wireUp = _loopDown = _loopUp = 0; _lastTick = null;
        }
    }
}
