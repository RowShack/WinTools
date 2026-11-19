using System.Net;

namespace WifiRoamLog.Core;

/// <summary>Generated demo data (--demo): two fake APs, a walk between them, a few roams, one drop-out. Never talks to the real Wi-Fi stack.</summary>
public sealed class DemoWlanApi : IWlanApi
{
    public static readonly Guid DemoGuid = new("11111111-2222-3333-4444-555555555555");
    private readonly Func<DateTime> _clock;
    private readonly DateTime _t0;
    public DemoWlanApi(Func<DateTime>? clock = null) { _clock = clock ?? (() => DateTime.Now); _t0 = _clock(); }

    public static (string Bssid, int Freq, int Ch) ApA => ("94:2a:6f:5d:a1:11", 5200, 40);
    public static (string Bssid, int Freq, int Ch) ApB => ("94:2a:6f:d1:07:21", 5745, 149);

    public IReadOnlyList<WlanInterfaceInfo> EnumInterfaces() => [new(DemoGuid, "Demo Wi-Fi 6E adapter (generated data)", WlanState.Connected)];

    public WlanConnection QueryConnection(Guid iface)
    {
        double t = (_clock() - _t0).TotalSeconds;
        var ap = ((int)(t / 120)) % 2 == 0 ? ApA : ApB;
        int rssi = (int)(-58 + 10 * Math.Sin(t / 25.0) - (t % 120) / 12.0);
        return new WlanConnection { State = WlanState.Connected, Ssid = "Corp-WiFi", Bssid = ap.Bssid, PhyType = 10, SignalQuality = WifiMath.RssiToPercent(rssi), RxKbps = 866_000, TxKbps = 780_000, RssiDbm = rssi, Channel = ap.Ch };
    }

    public IReadOnlyList<BssEntry> GetBssList(Guid iface) =>
    [
        new("Corp-WiFi", "94:2a:6f:5d:a1:11", -52, 96, 5200, 10),
        new("Corp-WiFi", "94:2a:6f:5d:a1:10", -50, 100, 5200, 10),
        new("Corp-WiFi", "94:2a:6f:5d:a1:0f", -55, 90, 2437, 10),
        new("Corp-Guest", "9a:2a:6f:5d:a1:10", -51, 98, 5200, 10),
        new("Corp-WiFi", "94:2a:6f:d1:07:21", -68, 64, 5745, 10),
        new("Corp-WiFi", "94:2a:6f:d1:07:1f", -71, 58, 2412, 10),
        new("Corp-WiFi", "94:2a:6f:a8:11:21", -74, 52, 5180, 10),
        new("Corp-WiFi", "94:2a:6f:a8:11:20", -77, 46, 5955, 11),
        new("Lab-IoT", "e4:5f:01:22:33:44", -79, 42, 2462, 7),
        new("", "e4:5f:01:22:33:45", -84, 32, 2412, 7),
        new("HomeNet-4F", "3c:84:6a:11:22:33", -81, 38, 2437, 7),
        new("Corp-WiFi", "94:2a:6f:ee:90:11", -86, 28, 5500, 10),
    ];

    public IReadOnlyList<AvailableNetwork> GetAvailableNetworks(Guid iface) =>
    [
        new("Corp-WiFi", 96, true, "WPA3-Enterprise"), new("Corp-Guest", 98, true, "WPA2-Personal"), new("Lab-IoT", 42, true, "WPA2-Personal"), new("HomeNet-4F", 38, true, "WPA2-Personal"),
    ];

    public void Scan(Guid iface) { }
    public IDisposable RegisterNotifications(Action<WlanNotification> handler) => new NullDisposable();
    public void Dispose() { }
    private sealed class NullDisposable : IDisposable { public void Dispose() { } }

    /// <summary>Fills a session with 'minutes' of plausible history ending at 'end'.</summary>
    public static void Populate(SessionData d, DateTime end, int minutes, ApMap? map, ApMatchOptions? opt, int seed = 7)
    {
        var rnd = new Random(seed);
        var start = end.AddMinutes(-minutes);
        var roamAt = new[] { 0.22, 0.47, 0.50, 0.81 };   // fractions of the span; 0.47/0.50 is a ping-pong
        var aps = new[] { ApA, ApB };
        int cur = 0;
        int nextRoam = 0;
        bool wasOutage = false;
        string Name(string b) => map?.NameFor(b, opt) ?? "";
        for (var t = start; t <= end; t = t.AddSeconds(2))
        {
            double frac = (t - start).TotalSeconds / (minutes * 60.0);
            while (nextRoam < roamAt.Length && frac >= roamAt[nextRoam])
            {
                int old = cur; cur = 1 - cur;
                double dur0 = 90 + rnd.Next(200);
                var ev = new WifiEvent
                {
                    Time = t, Kind = WifiEventKind.Roam, Source = nextRoam == 1 ? WifiEventSource.Inferred : WifiEventSource.Notified, Ssid = "Corp-WiFi",
                    OldBssid = aps[old].Bssid, NewBssid = aps[cur].Bssid, OldAp = Name(aps[old].Bssid), NewAp = Name(aps[cur].Bssid),
                    DurationMs = nextRoam == 1 ? null : dur0,
                    Detail = nextRoam == 1 ? "BSSID changed between samples; roam duration unknown" : $"Roam took {dur0:0} ms",
                };
                d.AddEvent(ev);
                nextRoam++;
            }
            bool outage = frac is > 0.64 and < 0.655;
            if (outage != wasOutage)
            {
                d.AddEvent(outage
                    ? new WifiEvent { Time = t, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Notified, Ssid = "Corp-WiFi", OldBssid = aps[cur].Bssid, OldAp = Name(aps[cur].Bssid), Detail = "Disconnected: the radio was reset" }
                    : new WifiEvent { Time = t, Kind = WifiEventKind.Connect, Source = WifiEventSource.Notified, Ssid = "Corp-WiFi", NewBssid = aps[cur].Bssid, NewAp = Name(aps[cur].Bssid), Detail = "Connected" });
                wasOutage = outage;
            }
            double drift = (frac * 6) % 1;   // walk away from the AP, then get a better one
            if (outage) d.AddSample(new WifiSample { Time = t, State = WlanState.Disconnected });
            else
            {
                int rssi = (int)(-48 - 26 * drift + 3 * Math.Sin(t.Ticks / 4e9) + rnd.Next(-2, 3));
                var ap = aps[cur];
                d.AddSample(new WifiSample
                {
                    Time = t, State = WlanState.Connected, Ssid = "Corp-WiFi", Bssid = ap.Bssid, ApName = Name(ap.Bssid), RssiDbm = rssi, SignalPct = WifiMath.RssiToPercent(rssi),
                    Channel = ap.Ch, FrequencyMhz = ap.Freq, Band = WifiMath.BandFromFrequency(ap.Freq), Phy = "802.11ax (Wi-Fi 6/6E)", RxMbps = 866, TxMbps = 780,
                });
            }
            // pings once per second (two per sample step)
            for (int k = 0; k < 2; k++)
            {
                var pt = t.AddSeconds(k);
                double gw = 2 + rnd.NextDouble() * 3 + (frac > 0.2 && frac < 0.23 ? rnd.Next(10, 60) : 0);
                double tg = 18 + rnd.NextDouble() * 6 + (frac > 0.2 && frac < 0.23 ? rnd.Next(10, 90) : 0);
                bool lost = outage || rnd.NextDouble() < (drift > 0.85 ? 0.04 : 0.003);
                d.AddPing(new PingSample(pt, PingTarget.Gateway, "192.168.10.1", lost ? null : gw, lost ? "TimedOut" : "Success"));
                bool lost2 = lost || rnd.NextDouble() < 0.002;
                d.AddPing(new PingSample(pt, PingTarget.Target, "8.8.8.8", lost2 ? null : tg, lost2 ? "TimedOut" : "Success"));
            }
        }
    }
}

public sealed class DemoPinger : IPinger
{
    private readonly Random _r = new(3);
    public async Task<(double? RttMs, string Status)> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct)
    {
        await Task.Delay(5, ct).ConfigureAwait(false);
        bool gw = address.ToString().StartsWith("192.168.", StringComparison.Ordinal);
        lock (_r) return (gw ? 2 + _r.NextDouble() * 3 : 18 + _r.NextDouble() * 6, "Success");
    }
}

public sealed class DemoGatewayProvider : IGatewayProvider
{
    public IPAddress? GetGateway(Guid wifiInterface) => IPAddress.Parse("192.168.10.1");
}
