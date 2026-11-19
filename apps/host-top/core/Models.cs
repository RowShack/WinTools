using System.Net;

namespace HostTop.Core;

public enum FlowProtocol { Tcp, Udp }

/// <summary>Where the remote end of a flow sits.</summary>
public enum NetClass { Loopback, Lan, Internet }

/// <summary>One send or receive event as reported by ETW (bytes on one socket operation).</summary>
public readonly record struct FlowEvent(
    DateTime Time, int Pid, FlowProtocol Protocol,
    IPAddress Local, int LocalPort, IPAddress Remote, int RemotePort,
    long Bytes, bool IsSend);

/// <summary>One row of any of the three tables. Which fields are filled depends on the table.</summary>
public sealed class FlowRow
{
    public string Id { get; init; } = "";
    /// <summary>Main label: remote IP (host table), process name (process and connection tables).</summary>
    public string Name { get; init; } = "";
    public IPAddress? Remote { get; init; }
    public NetClass Class { get; init; }
    public int Pid { get; init; }
    public string? Path { get; init; }
    public FlowProtocol? Protocol { get; init; }
    public string Local { get; init; } = "";
    public string RemoteEndpoint { get; init; } = "";
    public string Service { get; init; } = "";
    public double DownRate { get; init; }
    public double UpRate { get; init; }
    public long TotalDown { get; init; }
    public long TotalUp { get; init; }
    /// <summary>Connections active in the last 30 s (host table) or remote hosts count (process table).</summary>
    public int Count { get; init; }
    /// <summary>Processes involved (host table) or remote hosts (process table), comma separated.</summary>
    public string Related { get; init; } = "";
    /// <summary>Per-second bytes/s for the last 60 s, oldest first.</summary>
    public double[] DownHistory { get; init; } = [];
    public double[] UpHistory { get; init; } = [];

    public string SearchText => string.Join(' ', Name, Remote?.ToString() ?? "", Pid == 0 ? "" : Pid.ToString(), Path ?? "",
        Protocol?.ToString() ?? "", Local, RemoteEndpoint, Service, Related);
}

public sealed class FlowSnapshot
{
    public DateTime Time { get; init; }
    public IReadOnlyList<FlowRow> Hosts { get; init; } = [];
    public IReadOnlyList<FlowRow> Processes { get; init; } = [];
    public IReadOnlyList<FlowRow> Connections { get; init; } = [];
    /// <summary>Machine totals on the wire (loopback excluded), bytes/s.</summary>
    public double DownRate { get; init; }
    public double UpRate { get; init; }
    public long TotalDown { get; init; }
    public long TotalUp { get; init; }
    public double LoopbackDownRate { get; init; }
    public double LoopbackUpRate { get; init; }
}
