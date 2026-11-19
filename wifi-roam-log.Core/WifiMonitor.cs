using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;

namespace WifiRoamLog.Core;

public interface IPinger
{
    Task<(double? RttMs, string Status)> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct);
}

public interface IGatewayProvider
{
    IPAddress? GetGateway(Guid wifiInterface);
}

public sealed class SystemPinger : IPinger
{
    public async Task<(double? RttMs, string Status)> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var p = new Ping();
            var sw = Stopwatch.StartNew();
            var r = await p.SendPingAsync(address, TimeSpan.FromMilliseconds(timeoutMs), cancellationToken: ct).ConfigureAwait(false);
            // Reply.RoundtripTime has 1 ms resolution; use the stopwatch for sub-ms LAN gateways.
            double rtt = r.RoundtripTime == 0 ? Math.Round(sw.Elapsed.TotalMilliseconds, 2) : r.RoundtripTime;
            return r.Status == IPStatus.Success ? (rtt, "Success") : (null, r.Status.ToString());
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return (null, ex.InnerException?.GetType().Name ?? ex.GetType().Name); }
    }
}

public sealed class NetworkGatewayProvider : IGatewayProvider
{
    public IPAddress? GetGateway(Guid wifiInterface)
    {
        string id = wifiInterface.ToString("B");
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!string.Equals(ni.Id, id, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var g in ni.GetIPProperties().GatewayAddresses)
                if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)) return g.Address;
        }
        return null;
    }
}

public sealed class WifiMonitorOptions
{
    public Guid InterfaceGuid { get; init; }
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan PingInterval { get; init; } = TimeSpan.FromSeconds(1);
    public int PingTimeoutMs { get; init; } = 1000;
    public string Target { get; init; } = "8.8.8.8";
    public TimeSpan GatewayRecheck { get; init; } = TimeSpan.FromSeconds(10);
    public Func<string, string>? ApNameResolver { get; init; }
    public Func<DateTime> Clock { get; init; } = () => DateTime.Now;
}

/// <summary>Background sampling: Wi-Fi state every N seconds, pings to gateway and target, notification events, roam inference. Raises events from background threads.</summary>
public sealed class WifiMonitor
{
    private readonly IWlanApi _api;
    private readonly IPinger _pinger;
    private readonly IGatewayProvider _gateways;
    private readonly WifiMonitorOptions _o;
    private readonly object _gate = new();
    private readonly RoamInferrer _inferrer = new();
    private readonly RoamTracker _tracker = new();
    private readonly EventMerger _merger = new();
    private string _lastBssid = "", _lastSsid = "";
    private LocationState? _loc;

    public event Action<WifiSample>? SampleReady;
    public event Action<WifiEvent>? EventLogged;
    public event Action<PingSample>? PingReady;
    public event Action<LocationState>? LocationChanged;
    public IPAddress? CurrentGateway { get; private set; }

    public WifiMonitor(IWlanApi api, IPinger pinger, IGatewayProvider gateways, WifiMonitorOptions options)
    {
        _api = api; _pinger = pinger; _gateways = gateways; _o = options;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        IDisposable? reg = null;
        try
        {
            try { reg = _api.RegisterNotifications(OnNotification); }
            catch (Exception ex) { Emit(Info($"Could not register for Wi-Fi notifications ({ex.Message}); relying on inferred events")); }

            var tasks = new List<Task> { Task.Run(() => SampleLoop(ct), CancellationToken.None) };
            tasks.Add(Task.Run(() => PingLoop(PingTarget.Gateway, ct), CancellationToken.None));
            if (!string.IsNullOrWhiteSpace(_o.Target)) tasks.Add(Task.Run(() => PingLoop(PingTarget.Target, ct), CancellationToken.None));
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            reg?.Dispose();   // unregister before returning so nothing is left running
            lock (_gate) foreach (var e in _merger.FlushAll()) Emit(e);
        }
    }

    private WifiEvent Info(string detail) => new() { Time = _o.Clock(), Kind = WifiEventKind.Info, Source = WifiEventSource.Notified, Detail = detail };

    private async Task SampleLoop(CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        TimeSpan next = TimeSpan.Zero;
        while (!ct.IsCancellationRequested)
        {
            if (sw.Elapsed >= next)
            {
                next = sw.Elapsed + _o.SampleInterval;
                try { TakeSample(); }
                catch (Exception ex) { Emit(Info("Sample failed: " + ex.Message)); }
            }
            lock (_gate) foreach (var e in _merger.Flush(_o.Clock())) Emit(e);
            try { await Task.Delay(250, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    internal WifiSample BuildSample(DateTime now)
    {
        var c = _api.QueryConnection(_o.InterfaceGuid);
        var loc = LocationCheck.Evaluate(c);
        if (_loc != loc) { _loc = loc; LocationChanged?.Invoke(loc); }
        int? freq = null;
        if (c.State == WlanState.Connected)
        {
            try
            {
                var bss = _api.GetBssList(_o.InterfaceGuid);
                var m = bss.FirstOrDefault(b => c.Bssid.Length > 0 && b.Bssid == c.Bssid)
                        ?? (c.Bssid.Length == 0 ? bss.Where(b => b.Ssid == c.Ssid && c.Ssid.Length > 0).OrderByDescending(b => b.RssiDbm).FirstOrDefault() : null);
                if (m is not null) freq = m.FrequencyMhz;
            }
            catch (WlanException) { /* BSS list unavailable (e.g. location blocked): channel from the connection query is still used */ }
        }
        int? channel = freq is { } f ? WifiMath.FrequencyToChannel(f) ?? c.Channel : c.Channel;
        var band = freq is { } f2 ? WifiMath.BandFromFrequency(f2) : channel is { } ch ? WifiMath.BandFromChannel(ch) : WifiBand.Unknown;
        bool conn = c.State == WlanState.Connected;
        return new WifiSample
        {
            Time = now, State = c.State, Ssid = c.Ssid, Bssid = c.Bssid,
            ApName = c.Bssid.Length > 0 ? _o.ApNameResolver?.Invoke(c.Bssid) ?? "" : "",
            RssiDbm = conn ? c.RssiDbm ?? (c.SignalQuality > 0 ? WifiMath.PercentToRssi(c.SignalQuality) : null) : null,
            SignalPct = conn ? c.SignalQuality : null,
            Channel = conn ? channel : null, FrequencyMhz = freq, Band = conn ? band : WifiBand.Unknown,
            Phy = conn ? WifiMath.PhyName(c.PhyType) : "",
            RxMbps = conn ? c.RxKbps / 1000.0 : null, TxMbps = conn ? c.TxKbps / 1000.0 : null,
            ErrorCode = c.ErrorCode,
        };
    }

    private void TakeSample()
    {
        var s = BuildSample(_o.Clock());
        lock (_gate)
        {
            if (s.IsConnected && s.Bssid.Length > 0) { _lastBssid = s.Bssid; _lastSsid = s.Ssid; }
            SampleReady?.Invoke(s);
            foreach (var e in _inferrer.Observe(s)) _merger.AddInferred(e);
        }
    }

    private void OnNotification(WlanNotification n)
    {
        if (n.Interface != _o.InterfaceGuid) return;
        try
        {
            lock (_gate)
            {
                var now = _o.Clock();
                switch (n.Kind)
                {
                    case WlanNotificationKind.RoamStart:
                        _tracker.Start(now, _lastBssid);
                        Emit(_merger.AddNotified(new WifiEvent { Time = now, Kind = WifiEventKind.RoamStart, Source = WifiEventSource.Notified, Ssid = _lastSsid, OldBssid = _lastBssid, Detail = "Roam started (notification)" }));
                        break;
                    case WlanNotificationKind.RoamEnd:
                    {
                        var c = _api.QueryConnection(_o.InterfaceGuid);
                        string nb = c.Bssid.Length > 0 ? c.Bssid : "";
                        var ev = _tracker.End(now, c.Ssid.Length > 0 ? c.Ssid : _lastSsid, _lastBssid, nb);
                        ev = ev with { OldAp = Resolve(ev.OldBssid), NewAp = Resolve(ev.NewBssid) };
                        if (nb.Length > 0) { _lastBssid = nb; _lastSsid = c.Ssid; }
                        Emit(_merger.AddNotified(ev));
                        break;
                    }
                    case WlanNotificationKind.ConnectionComplete when n.ReasonCode == 0:
                    {
                        var c = _api.QueryConnection(_o.InterfaceGuid);
                        if (c.Bssid.Length > 0) { _lastBssid = c.Bssid; _lastSsid = c.Ssid; }
                        Emit(_merger.AddNotified(new WifiEvent { Time = now, Kind = WifiEventKind.Connect, Source = WifiEventSource.Notified, Ssid = c.Ssid.Length > 0 ? c.Ssid : n.Ssid ?? "", NewBssid = c.Bssid, NewAp = Resolve(c.Bssid), Detail = "Connected" }));
                        break;
                    }
                    case WlanNotificationKind.ConnectionComplete:
                    case WlanNotificationKind.ConnectionFailed:
                        Emit(_merger.AddNotified(new WifiEvent { Time = now, Kind = WifiEventKind.ConnectFail, Source = WifiEventSource.Notified, Ssid = n.Ssid ?? "", Detail = $"Connection failed: {n.ReasonText ?? $"reason 0x{n.ReasonCode:x}"}" }));
                        break;
                    case WlanNotificationKind.Disconnected:
                        Emit(_merger.AddNotified(new WifiEvent { Time = now, Kind = WifiEventKind.Disconnect, Source = WifiEventSource.Notified, Ssid = n.Ssid ?? _lastSsid, OldBssid = _lastBssid, OldAp = Resolve(_lastBssid), Detail = n.ReasonText is null ? "Disconnected" : $"Disconnected: {n.ReasonText}" }));
                        break;
                }
            }
        }
        catch (Exception ex) { Emit(Info("Notification handling failed: " + ex.Message)); }
    }

    private string Resolve(string bssid) => bssid.Length > 0 ? _o.ApNameResolver?.Invoke(bssid) ?? "" : "";

    private void Emit(WifiEvent e)
    {
        if (e.OldBssid.Length > 0 && e.OldAp.Length == 0) e = e with { OldAp = Resolve(e.OldBssid) };
        if (e.NewBssid.Length > 0 && e.NewAp.Length == 0) e = e with { NewAp = Resolve(e.NewBssid) };
        EventLogged?.Invoke(e);
    }

    private async Task PingLoop(PingTarget which, CancellationToken ct)
    {
        IPAddress? addr = null;
        DateTime lastResolve = DateTime.MinValue;
        var sw = Stopwatch.StartNew();
        TimeSpan next = TimeSpan.Zero;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var wait = next - sw.Elapsed;
                if (wait > TimeSpan.Zero) await Task.Delay(wait, ct).ConfigureAwait(false);
                next = sw.Elapsed + _o.PingInterval;
                var now = _o.Clock();
                if (addr is null || now - lastResolve >= (which == PingTarget.Gateway ? _o.GatewayRecheck : TimeSpan.FromSeconds(60)))
                {
                    var fresh = await ResolveAsync(which, ct).ConfigureAwait(false);
                    lastResolve = now;
                    if (which == PingTarget.Gateway)
                    {
                        if (!Equals(fresh, addr) && addr is not null)
                            Emit(Info($"Default gateway changed: {addr} -> {fresh?.ToString() ?? "none"}"));
                        CurrentGateway = fresh;
                    }
                    addr = fresh ?? (which == PingTarget.Target ? addr : null);
                }
                if (addr is null)
                {
                    if (which == PingTarget.Target) PingReady?.Invoke(new PingSample(now, which, _o.Target, null, "DnsFailed"));
                    continue;   // no gateway known: nothing to ping
                }
                var (rtt, status) = await _pinger.PingAsync(addr, _o.PingTimeoutMs, ct).ConfigureAwait(false);
                PingReady?.Invoke(new PingSample(now, which, addr.ToString(), rtt, status));
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task<IPAddress?> ResolveAsync(PingTarget which, CancellationToken ct)
    {
        try
        {
            if (which == PingTarget.Gateway) return _gateways.GetGateway(_o.InterfaceGuid);
            if (IPAddress.TryParse(_o.Target.Trim(), out var ip)) return ip;
            var all = await Dns.GetHostAddressesAsync(_o.Target.Trim(), ct).ConfigureAwait(false);
            return all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault();
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }
}

/// <summary>Settings stored in %AppData%\WifiRoamLog\settings.json. Holds no secrets.</summary>
public sealed class AppSettings
{
    public int IntervalSeconds { get; set; } = 2;
    public string Target { get; set; } = "8.8.8.8";
    public int PrefixOctets { get; set; } = 5;
    public bool IgnoreFirstOctet { get; set; }
    public int WindowMinutes { get; set; } = 15;
    public string LogFolder { get; set; } = "";
    public string ApMapPath { get; set; } = "";
    public string AdapterGuid { get; set; } = "";
    /// <summary>null = not asked yet; true = closing the window minimises to tray while logging; false = closing exits.</summary>
    public bool? CloseToTray { get; set; }

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WifiRoamLog", "settings.json");

    public static AppSettings Load(string? path = null)
    {
        try
        {
            path ??= DefaultPath;
            if (File.Exists(path)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path)) ?? new AppSettings();
        }
        catch { /* corrupt file: start from defaults */ }
        return new AppSettings();
    }

    public void Save(string? path = null)
    {
        try
        {
            path ??= DefaultPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* settings are a convenience only */ }
    }

    public string EffectiveLogFolder => string.IsNullOrWhiteSpace(LogFolder) ? SessionLogWriter.DefaultBaseFolder : LogFolder;
}
