namespace WifiRoamLog.Core;

public enum WlanState { Unknown, NotReady, Connected, AdHoc, Disconnecting, Disconnected, Associating, Discovering, Authenticating }
public enum WifiBand { Unknown, Band24, Band5, Band6 }
public enum WifiEventKind { Connect, Disconnect, RoamStart, Roam, ConnectFail, Info }
public enum WifiEventSource { Notified, Inferred }
public enum PingTarget { Gateway, Target }

public sealed record WlanInterfaceInfo(Guid Id, string Description, WlanState State)
{
    public override string ToString() => Description;
}

/// <summary>Result of querying the current connection of one adapter. ErrorCode != 0 means the query failed.</summary>
public sealed record WlanConnection
{
    public WlanState State { get; init; }
    public string Ssid { get; init; } = "";
    public string Bssid { get; init; } = "";
    public string Profile { get; init; } = "";
    public int PhyType { get; init; }
    public int SignalQuality { get; init; }
    public long RxKbps { get; init; }
    public long TxKbps { get; init; }
    public int? RssiDbm { get; init; }
    public int? Channel { get; init; }
    public uint ErrorCode { get; init; }
}

public sealed record BssEntry(string Ssid, string Bssid, int RssiDbm, int LinkQuality, int FrequencyMhz, int PhyType);

public sealed record AvailableNetwork(string Ssid, int SignalQuality, bool SecurityEnabled, string Security);

public enum WlanNotificationKind { ConnectionStart, ConnectionComplete, ConnectionFailed, Disconnecting, Disconnected, RoamStart, RoamEnd, Other }

public sealed record WlanNotification(DateTime Time, Guid Interface, WlanNotificationKind Kind, uint ReasonCode, string? ReasonText, string? Ssid, string Raw);

public sealed record WifiSample
{
    public DateTime Time { get; init; }
    public WlanState State { get; init; }
    public string Ssid { get; init; } = "";
    public string Bssid { get; init; } = "";
    public string ApName { get; init; } = "";
    public int? RssiDbm { get; init; }
    public int? SignalPct { get; init; }
    public int? Channel { get; init; }
    public int? FrequencyMhz { get; init; }
    public WifiBand Band { get; init; }
    public string Phy { get; init; } = "";
    public double? RxMbps { get; init; }
    public double? TxMbps { get; init; }
    public uint ErrorCode { get; init; }
    public bool IsConnected => State == WlanState.Connected;
}

public sealed record WifiEvent
{
    public DateTime Time { get; init; }
    public WifiEventKind Kind { get; init; }
    public WifiEventSource Source { get; init; }
    public string Ssid { get; init; } = "";
    public string OldBssid { get; init; } = "";
    public string NewBssid { get; init; } = "";
    public string OldAp { get; init; } = "";
    public string NewAp { get; init; } = "";
    public double? DurationMs { get; init; }
    public string Detail { get; init; } = "";
}

public sealed record PingSample(DateTime Time, PingTarget Target, string Address, double? RttMs, string Status)
{
    public bool Lost => RttMs is null;
}
