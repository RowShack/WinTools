namespace WifiRoamLog.Core;

/// <summary>Infers connect / disconnect / roam events from the sequence of samples (for drivers that send no roam notifications).
/// Only Connected and Disconnected samples are definitive; transitional or failed samples are ignored. A BSSID change inside the same SSID is a roam;
/// an SSID change is a new connection, not a roam. Empty SSID/BSSID (location blocked) never produces an event.</summary>
public sealed class RoamInferrer
{
    public TimeSpan PingPongWindow { get; init; } = TimeSpan.FromSeconds(30);

    private WifiSample? _prev;
    private string _lastRoamFrom = "";
    private DateTime _lastRoamTime = DateTime.MinValue;

    public IReadOnlyList<WifiEvent> Observe(WifiSample s)
    {
        if (s.ErrorCode != 0) return [];
        if (s.State is not (WlanState.Connected or WlanState.Disconnected)) return [];
        var prev = _prev;
        _prev = s;
        if (prev is null) return [];

        if (prev.IsConnected && !s.IsConnected)
            return [new WifiEvent { Time = s.Time, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Inferred, Ssid = prev.Ssid, OldBssid = prev.Bssid, Detail = "Connection lost (seen between samples)" }];

        if (!prev.IsConnected && s.IsConnected)
            return [new WifiEvent { Time = s.Time, Kind = WifiEventKind.Connect, Source = WifiEventSource.Inferred, Ssid = s.Ssid, NewBssid = s.Bssid, Detail = "Connected (seen between samples)" }];

        if (!prev.IsConnected) return [];

        if (prev.Ssid.Length > 0 && s.Ssid.Length > 0 && !string.Equals(prev.Ssid, s.Ssid, StringComparison.Ordinal))
            return [new WifiEvent { Time = s.Time, Kind = WifiEventKind.Connect, Source = WifiEventSource.Inferred, Ssid = s.Ssid, OldBssid = prev.Bssid, NewBssid = s.Bssid, Detail = $"SSID changed from '{prev.Ssid}' to '{s.Ssid}' (not a roam)" }];

        if (prev.Bssid.Length > 0 && s.Bssid.Length > 0 && !string.Equals(prev.Bssid, s.Bssid, StringComparison.OrdinalIgnoreCase))
        {
            string detail = "BSSID changed between samples; roam duration unknown";
            if (string.Equals(_lastRoamFrom, s.Bssid, StringComparison.OrdinalIgnoreCase) && s.Time - _lastRoamTime <= PingPongWindow)
                detail += $" (ping-pong: back to previous AP within {(s.Time - _lastRoamTime).TotalSeconds:0} s)";
            _lastRoamFrom = prev.Bssid;
            _lastRoamTime = s.Time;
            return [new WifiEvent { Time = s.Time, Kind = WifiEventKind.Roam, Source = WifiEventSource.Inferred, Ssid = s.Ssid, OldBssid = prev.Bssid, NewBssid = s.Bssid, Detail = detail }];
        }
        return [];
    }
}

/// <summary>Pairs roam start/end notifications into one Roam event with a duration.</summary>
public sealed class RoamTracker
{
    private DateTime? _start;
    private string _old = "";

    public void Start(DateTime time, string oldBssid) { _start = time; _old = oldBssid; }

    /// <summary>Completes a roam. Duration is null when no start notification was seen.</summary>
    public WifiEvent End(DateTime time, string ssid, string fallbackOldBssid, string newBssid)
    {
        double? dur = _start is { } s ? Math.Max(0, (time - s).TotalMilliseconds) : null;
        var old = _start is not null && _old.Length > 0 ? _old : fallbackOldBssid;
        _start = null; _old = "";
        return new WifiEvent
        {
            Time = time, Kind = WifiEventKind.Roam, Source = WifiEventSource.Notified, Ssid = ssid, OldBssid = old, NewBssid = newBssid, DurationMs = dur,
            Detail = dur is null ? "Roam completed (no start notification seen)" : $"Roam took {dur:0} ms",
        };
    }
}

/// <summary>Merges notified and inferred events. A notified event wins; an inferred event is held for a grace period so that a notification arriving
/// slightly later can replace it, and is dropped when a matching notified event was seen within the match window.</summary>
public sealed class EventMerger
{
    public TimeSpan Grace { get; init; } = TimeSpan.FromSeconds(4);
    public TimeSpan MatchWindow { get; init; } = TimeSpan.FromSeconds(10);

    private readonly List<WifiEvent> _pending = [];
    private readonly List<WifiEvent> _recentNotified = [];

    public void AddInferred(WifiEvent e)
    {
        if (_recentNotified.Any(n => Matches(e, n))) return;
        _pending.Add(e);
    }

    /// <summary>Registers a notified event; returns it for emission (matching pending inferred events are discarded).</summary>
    public WifiEvent AddNotified(WifiEvent e)
    {
        int i = _pending.FindIndex(p => Matches(p, e));
        if (i >= 0) _pending.RemoveAt(i);
        _recentNotified.Add(e);
        if (_recentNotified.Count > 50) _recentNotified.RemoveRange(0, _recentNotified.Count - 50);
        return e;
    }

    /// <summary>Returns inferred events whose grace period has elapsed.</summary>
    public List<WifiEvent> Flush(DateTime now)
    {
        var due = _pending.Where(p => now - p.Time >= Grace).ToList();
        foreach (var d in due) _pending.Remove(d);
        return due;
    }

    public List<WifiEvent> FlushAll()
    {
        var all = _pending.ToList();
        _pending.Clear();
        return all;
    }

    private bool Matches(WifiEvent inferred, WifiEvent notified)
    {
        if (notified.Source != WifiEventSource.Notified) return false;
        if (Math.Abs((inferred.Time - notified.Time).TotalSeconds) > MatchWindow.TotalSeconds) return false;
        bool kindOk = inferred.Kind switch
        {
            WifiEventKind.Disconnect => notified.Kind == WifiEventKind.Disconnect,
            WifiEventKind.Connect or WifiEventKind.Roam => notified.Kind is WifiEventKind.Connect or WifiEventKind.Roam,
            _ => false,
        };
        if (!kindOk) return false;
        if (inferred.NewBssid.Length > 0 && notified.NewBssid.Length > 0 && !string.Equals(inferred.NewBssid, notified.NewBssid, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }
}

public sealed record LatencyStats(int Count, int Lost, double LossPct, double? AvgMs, double? MinMs, double? MaxMs, double? LastMs, double? JitterMs)
{
    public static readonly LatencyStats Empty = new(0, 0, 0, null, null, null, null, null);

    public static LatencyStats Compute(IEnumerable<PingSample> pings)
    {
        int n = 0, lost = 0;
        var rtts = new List<double>();
        double? last = null;
        foreach (var p in pings)
        {
            n++;
            if (p.RttMs is { } r) { rtts.Add(r); last = r; } else { lost++; last = null; }
        }
        if (n == 0) return Empty;
        double? jitter = null;
        if (rtts.Count > 1)
        {
            double sum = 0;
            for (int i = 1; i < rtts.Count; i++) sum += Math.Abs(rtts[i] - rtts[i - 1]);
            jitter = sum / (rtts.Count - 1);
        }
        return new LatencyStats(n, lost, 100.0 * lost / n, rtts.Count > 0 ? rtts.Average() : null, rtts.Count > 0 ? rtts.Min() : null, rtts.Count > 0 ? rtts.Max() : null, last, jitter);
    }
}

/// <summary>Rolling window of the most recent pings for one target (header display).</summary>
public sealed class LatencyWindow(int capacity = 60)
{
    private readonly Queue<PingSample> _q = new();
    public void Add(PingSample p) { _q.Enqueue(p); while (_q.Count > capacity) _q.Dequeue(); }
    public LatencyStats Stats => LatencyStats.Compute(_q);
    public void Clear() => _q.Clear();
}

public enum LocationState { Ok, NotConnected, Blocked, NoAdapter }

public static class LocationCheck
{
    public const uint ErrorAccessDenied = 5;

    /// <summary>Windows 11 hides SSID/BSSID (or denies the call) when Location access is off for desktop apps.</summary>
    public static LocationState Evaluate(WlanConnection? c)
    {
        if (c is null) return LocationState.NoAdapter;
        if (c.ErrorCode == ErrorAccessDenied) return LocationState.Blocked;
        if (c.ErrorCode != 0) return LocationState.NotConnected;
        if (c.State != WlanState.Connected) return LocationState.NotConnected;
        if (string.IsNullOrEmpty(c.Ssid) || string.IsNullOrEmpty(Bssid.Normalize(c.Bssid))) return LocationState.Blocked;
        return LocationState.Ok;
    }

    public const string Steps =
        "Windows is hiding the Wi-Fi network name / AP address from this app. Turn on Location access:\n" +
        "Settings > Privacy & security > Location > switch on \"Location services\" and \"Let desktop apps access your location\".";
}

/// <summary>Limits WlanScan calls so the app never disrupts roaming with repeated scans.</summary>
public sealed class ScanThrottle(TimeSpan minInterval)
{
    private DateTime _last = DateTime.MinValue;
    public bool TryAcquire(DateTime now)
    {
        if (now - _last < minInterval) return false;
        _last = now;
        return true;
    }
    public TimeSpan Remaining(DateTime now) => now - _last >= minInterval ? TimeSpan.Zero : minInterval - (now - _last);
}
