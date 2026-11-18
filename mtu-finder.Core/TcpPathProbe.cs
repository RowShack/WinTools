using System.Net;
using System.Net.Sockets;

namespace MtuFinder.Core;

/// <summary>Real TCP probe: connect with Don't-Fragment, read the negotiated MSS via SIO_TCP_INFO, send one segment, watch for the ACK.</summary>
public sealed class TcpPathProbe(IPAddress? sourceAddress = null) : ITcpPathProbe
{
    private const int SIO_TCP_INFO = unchecked((int)0xD8000027);

    public async Task<TcpProbeResult> ProbeAsync(IPEndPoint target, int payloadSize, TimeSpan timeout, CancellationToken ct)
    {
        using var s = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try { if (target.AddressFamily == AddressFamily.InterNetwork) s.DontFragment = true; } catch { /* v4 default already DF for TCP */ }
        try
        {
            if (sourceAddress is not null && sourceAddress.AddressFamily == target.AddressFamily) s.Bind(new IPEndPoint(sourceAddress, 0));
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeout > TimeSpan.FromSeconds(3) ? timeout : TimeSpan.FromSeconds(3));
                try { await s.ConnectAsync(target, cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(TcpProbeStatus.ConnectFailed, Detail: "connection timed out"); }
                catch (SocketException ex) { return new(TcpProbeStatus.ConnectFailed, Detail: ex.SocketErrorCode.ToString()); }
            }

            TcpInfo.Info info;
            try { info = Query(s); }
            catch (Exception ex) when (ex is SocketException or NotSupportedException or ArgumentException)
            { return new(TcpProbeStatus.Error, Detail: "cannot read TCP_INFO (needs Windows 10 1703 or later): " + ex.Message); }

            int opt = info.TimestampsEnabled ? 12 : 0;
            if (payloadSize <= 0) return new(TcpProbeStatus.Delivered, info.Mss, opt);

            int max = info.Mss - opt;
            if (payloadSize > max) return new(TcpProbeStatus.Error, info.Mss, opt, $"payload {payloadSize} exceeds usable MSS {max}");

            try { await s.SendAsync(new byte[payloadSize], SocketFlags.None, ct).ConfigureAwait(false); }
            catch (SocketException ex) { return new(TcpProbeStatus.Error, info.Mss, opt, "send failed: " + ex.SocketErrorCode); }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                TcpInfo.Info cur;
                try { cur = Query(s); }
                catch (SocketException ex) { return new(TcpProbeStatus.Error, info.Mss, opt, "connection ended before ACK was seen: " + ex.SocketErrorCode); }
                if (cur.BytesRetrans > 0) return new(TcpProbeStatus.Stalled, info.Mss, opt, "retransmission");
                if (cur.BytesInFlight == 0) return new(TcpProbeStatus.Delivered, info.Mss, opt);
                if (sw.Elapsed > timeout) return new(TcpProbeStatus.Stalled, info.Mss, opt, "no ACK");
                await Task.Delay(10, ct).ConfigureAwait(false);
            }
        }
        catch (SocketException ex) { return new(TcpProbeStatus.Error, Detail: ex.SocketErrorCode.ToString()); }
    }

    private static TcpInfo.Info Query(Socket s)
    {
        byte[] input = [0, 0, 0, 0];             // version 0
        byte[] output = new byte[TcpInfo.V0Size];
        s.IOControl((IOControlCode)SIO_TCP_INFO, input, output);
        return TcpInfo.ParseV0(output);
    }
}
