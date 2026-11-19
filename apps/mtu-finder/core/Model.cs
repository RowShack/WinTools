using System.Net;

namespace MtuFinder.Core;

public enum ProbeStatus { Success, PacketTooBig, TimedOut, Unreachable, Error }

/// <summary>Result of one echo request. ReportedMtu is the next-hop MTU if the router told us.</summary>
public sealed record ProbeResult(ProbeStatus Status, int? RttMs = null, int? ReportedMtu = null, string? Detail = null);

public sealed record ProbeAttempt(int PayloadSize, int Try, ProbeResult Result)
{
    public override string ToString() =>
        $"payload {PayloadSize,5} (try {Try}): {Result.Status}" +
        (Result.RttMs is int r ? $", {r} ms" : "") +
        (Result.ReportedMtu is int m ? $", router says MTU {m}" : "") +
        (Result.Detail is { Length: > 0 } d ? $" ({d})" : "");
}

public enum MtuOutcome
{
    /// <summary>A path MTU was determined.</summary>
    Found,
    /// <summary>No echo reply even at a tiny size: ICMP is filtered or the host is down. No MTU can be reported.</summary>
    NoReply,
    /// <summary>The network told us the destination is unreachable.</summary>
    Unreachable,
    /// <summary>Run was cancelled.</summary>
    Cancelled,
}

public sealed record MtuResult(
    MtuOutcome Outcome,
    IPAddress Target,
    int? MaxPayload,
    int? PathMtu,
    int? RecommendedMss,
    int? LocalInterfaceMtu,
    bool SilentDropSuspected,
    IReadOnlyList<ProbeAttempt> Attempts,
    IReadOnlyList<string> Notes)
{
    public bool IsV6 => Target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
}

public sealed class SearchOptions
{
    public int TriesPerSize { get; init; } = 3;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMilliseconds(1500);
    /// <summary>Local interface MTU if known; caps the search. Default assumes 1500.</summary>
    public int? LocalMtu { get; init; }
    public int BaselinePayload { get; init; } = 32;
}

public interface IEchoProbe
{
    /// <summary>Sends one echo request with Don't-Fragment (IPv4) and the given payload size.</summary>
    Task<ProbeResult> SendAsync(IPAddress target, int payloadSize, TimeSpan timeout, CancellationToken ct);
}
