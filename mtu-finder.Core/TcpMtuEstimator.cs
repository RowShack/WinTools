using System.Net;
using System.Net.Sockets;

namespace MtuFinder.Core;

/// <summary>
/// ESTIMATES the path MTU without ICMP: connects to a TCP port, learns the negotiated MSS, then sends single segments of
/// increasing size with Don't-Fragment and looks for the size at which they stop being acknowledged.
/// </summary>
public sealed class TcpMtuEstimator(ITcpPathProbe probe, SearchOptions? options = null)
{
    private readonly SearchOptions _opt = options ?? new SearchOptions();

    public static int HeaderOverhead(bool v6) => v6 ? 60 : 40;   // IP + TCP headers without options
    public const int MinimumPayload = 256;

    public async Task<TcpMtuEstimate> RunAsync(IPAddress target, int port, IProgress<TcpProbeAttempt>? progress = null, CancellationToken ct = default)
    {
        bool v6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        int hdr = HeaderOverhead(v6);
        var ep = new IPEndPoint(target, port);
        var attempts = new List<TcpProbeAttempt>();
        var notes = new List<string>();
        int? mss = null;

        TcpMtuEstimate Done(TcpEstimateOutcome o, int? payload = null, int opt = 0)
        {
            int? mtu = payload is int p ? p + opt + hdr : null;
            return new TcpMtuEstimate(o, target, port, mss, mtu, mtu is int m ? m - hdr : null, attempts, notes);
        }

        async Task<TcpProbeResult> TrySize(int size)
        {
            TcpProbeResult last = new(TcpProbeStatus.Stalled);
            for (int t = 1; t <= _opt.TriesPerSize; t++)
            {
                ct.ThrowIfCancellationRequested();
                last = await probe.ProbeAsync(ep, size, _opt.Timeout, ct).ConfigureAwait(false);
                var a = new TcpProbeAttempt(size, t, last);
                attempts.Add(a); progress?.Report(a);
                if (last.Status != TcpProbeStatus.Stalled) break;   // only stalls are retried
            }
            return last;
        }

        try
        {
            var conn = await TrySize(0);
            if (conn.Status == TcpProbeStatus.ConnectFailed) { notes.Add($"Could not connect to port {port} ({conn.Detail}). Pick a TCP port that is open on the target."); return Done(TcpEstimateOutcome.ConnectFailed); }
            if (conn.Status != TcpProbeStatus.Delivered || conn.Mss is not int m0)
            { notes.Add("Connected, but the connection details could not be read: " + conn.Detail); return Done(TcpEstimateOutcome.Inconclusive); }
            mss = m0;
            int opt = conn.OptionBytes;
            int hi = m0 - opt;
            int lo = Math.Min(MinimumPayload, hi);
            if (hi < 1) { notes.Add($"Negotiated MSS {m0} is too small to probe."); return Done(TcpEstimateOutcome.Inconclusive); }

            int local = (_opt.LocalMtu ?? 1500) - hdr;
            if (m0 < local - 12)
                notes.Add($"The connection negotiated MSS {m0}, smaller than this machine's link allows ({local}). Either something on the path clamps MSS or the far end advertised a small one; the true path MTU may be larger than the estimate.");

            // Full-size segment first: the usual case is that it just works.
            var top = await TrySize(hi);
            if (top.Status == TcpProbeStatus.Delivered) return Finish(hi);
            if (top.Status == TcpProbeStatus.Error) return Inconclusive(top);

            // Establish that a small segment gets through, otherwise the search means nothing.
            var floor = await TrySize(lo);
            if (floor.Status != TcpProbeStatus.Delivered)
            {
                notes.Add(floor.Status == TcpProbeStatus.Error ? "The server closes the connection as soon as it receives data, so acknowledgements cannot be observed. Try a different port." : $"Even a {lo}-byte segment was not acknowledged, so the result is unusable (heavy loss, or the service drops unexpected data).");
                return Done(TcpEstimateOutcome.Inconclusive);
            }

            int high = hi - 1;
            while (lo < high)
            {
                int mid = (lo + high + 1) / 2;
                var r = await TrySize(mid);
                if (r.Status == TcpProbeStatus.Delivered) lo = mid;
                else if (r.Status == TcpProbeStatus.Stalled) high = mid - 1;
                else return Inconclusive(r);
            }
            notes.Add("Segments larger than the estimate were not acknowledged. If ICMP 'packet too big' messages were blocked, this is a PMTUD black hole: clamp MSS on the tunnel or firewall.");
            return Finish(lo);

            TcpMtuEstimate Finish(int payload)
            {
                notes.Add("This is an ESTIMATE from TCP behaviour, not a measurement. It can be wrong if a middlebox rewrites the MSS or proxies the connection, or if the server mishandles data.");
                return Done(TcpEstimateOutcome.Estimated, payload, opt);
            }
            TcpMtuEstimate Inconclusive(TcpProbeResult r)
            {
                notes.Add("The connection was reset or unreadable while probing (" + r.Detail + "). Try a port whose service tolerates incoming data.");
                return Done(TcpEstimateOutcome.Inconclusive);
            }
        }
        catch (OperationCanceledException) { return Done(TcpEstimateOutcome.Cancelled); }
    }
}
