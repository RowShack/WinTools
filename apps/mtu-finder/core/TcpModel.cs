using System.Buffers.Binary;
using System.Net;

namespace MtuFinder.Core;

public enum TcpProbeStatus
{
    /// <summary>Data was sent and acknowledged with no retransmission.</summary>
    Delivered,
    /// <summary>Data was not acknowledged in time, or had to be retransmitted (typical of a dropped oversized packet).</summary>
    Stalled,
    /// <summary>The TCP connection could not be made (refused, timed out, unreachable).</summary>
    ConnectFailed,
    /// <summary>The connection broke or the OS would not tell us its state; the answer for this size is unknown.</summary>
    Error,
}

/// <summary>Result of one TCP probe. Mss is the negotiated maximum segment size; OptionBytes is per-segment TCP option overhead (e.g. 12 for timestamps).</summary>
public sealed record TcpProbeResult(TcpProbeStatus Status, int? Mss = null, int OptionBytes = 0, string? Detail = null);

public interface ITcpPathProbe
{
    /// <summary>
    /// Connects to the endpoint (Don't-Fragment on) and, if <paramref name="payloadSize"/> &gt; 0, sends exactly one segment of that many
    /// bytes and reports whether it was acknowledged. A fresh connection is used for every call.
    /// </summary>
    Task<TcpProbeResult> ProbeAsync(IPEndPoint target, int payloadSize, TimeSpan timeout, CancellationToken ct);
}

public enum TcpEstimateOutcome
{
    /// <summary>An estimate was produced (still only an estimate).</summary>
    Estimated,
    /// <summary>Could not connect to the port.</summary>
    ConnectFailed,
    /// <summary>Connected, but the answers were not usable (server resets on data, or even small segments are not acknowledged).</summary>
    Inconclusive,
    Cancelled,
}

public sealed record TcpProbeAttempt(int PayloadSize, int Try, TcpProbeResult Result)
{
    public override string ToString() =>
        $"TCP payload {PayloadSize,5} (try {Try}): {Result.Status}" + (Result.Detail is { Length: > 0 } d ? $" ({d})" : "");
}

/// <summary>An ESTIMATE of the path MTU from TCP behaviour. Never present this as a measured value.</summary>
public sealed record TcpMtuEstimate(
    TcpEstimateOutcome Outcome,
    IPAddress Target,
    int Port,
    int? NegotiatedMss,
    int? EstimatedMtu,
    int? EstimatedMss,
    IReadOnlyList<TcpProbeAttempt> Attempts,
    IReadOnlyList<string> Notes)
{
    public bool IsV6 => Target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
}

/// <summary>Parses the Windows TCP_INFO_v0 structure returned by SIO_TCP_INFO.</summary>
public static class TcpInfo
{
    public const int V0Size = 88;

    public readonly record struct Info(int State, int Mss, bool TimestampsEnabled, uint BytesInFlight, uint BytesRetrans, uint TimeoutEpisodes);

    public static Info ParseV0(ReadOnlySpan<byte> b)
    {
        if (b.Length < 84) throw new ArgumentException("TCP_INFO buffer too small", nameof(b));
        return new Info(
            State: BinaryPrimitives.ReadInt32LittleEndian(b[0..]),
            Mss: (int)BinaryPrimitives.ReadUInt32LittleEndian(b[4..]),
            TimestampsEnabled: b[16] != 0,
            BytesInFlight: BinaryPrimitives.ReadUInt32LittleEndian(b[28..]),
            BytesRetrans: BinaryPrimitives.ReadUInt32LittleEndian(b[68..]),
            TimeoutEpisodes: BinaryPrimitives.ReadUInt32LittleEndian(b[80..]));
    }
}
