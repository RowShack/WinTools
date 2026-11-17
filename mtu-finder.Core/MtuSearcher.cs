using System.Net;
using System.Net.Sockets;

namespace MtuFinder.Core;

/// <summary>Finds the largest echo payload that gets through and derives path MTU and MSS from it.</summary>
public sealed class MtuSearcher(IEchoProbe probe, SearchOptions? options = null)
{
    private readonly SearchOptions _opt = options ?? new SearchOptions();

    public static int HeaderOverhead(bool v6) => v6 ? 48 : 28;     // IP header + 8-byte ICMP header
    public static int MssFor(int pathMtu, bool v6) => pathMtu - (v6 ? 60 : 40);
    public static int MinimumMtu(bool v6) => v6 ? 1280 : 576;

    public async Task<MtuResult> RunAsync(IPAddress target, IProgress<ProbeAttempt>? progress = null, CancellationToken ct = default)
    {
        bool v6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        int hdr = HeaderOverhead(v6);
        var attempts = new List<ProbeAttempt>();
        var notes = new List<string>();
        bool sawTimeoutAboveLo = false;

        MtuResult Done(MtuOutcome o, int? payload = null, bool silent = false)
        {
            int? mtu = payload is int p ? p + hdr : null;
            return new MtuResult(o, target, payload, mtu, mtu is int m ? MssFor(m, v6) : null, _opt.LocalMtu, silent, attempts, notes);
        }

        // Tries one size up to TriesPerSize times. Packet-too-big and unreachable are definitive: no retry.
        async Task<ProbeResult> TrySize(int size)
        {
            ProbeResult last = new(ProbeStatus.TimedOut);
            for (int t = 1; t <= _opt.TriesPerSize; t++)
            {
                ct.ThrowIfCancellationRequested();
                last = await probe.SendAsync(target, size, _opt.Timeout, ct).ConfigureAwait(false);
                var a = new ProbeAttempt(size, t, last);
                attempts.Add(a); progress?.Report(a);
                if (last.Status != ProbeStatus.TimedOut) break;
            }
            return last;
        }

        try
        {
            // 1. Baseline: does anything come back at all?
            var baseline = await TrySize(_opt.BaselinePayload);
            if (baseline.Status == ProbeStatus.Unreachable) { notes.Add("The network reported the destination unreachable."); return Done(MtuOutcome.Unreachable); }
            if (baseline.Status != ProbeStatus.Success)
            {
                notes.Add("No echo reply even with a tiny packet. ICMP is probably blocked (firewall) or the host is down, so the path MTU cannot be measured this way. Try the TCP-based estimate if available.");
                return Done(MtuOutcome.NoReply);
            }

            // 2. Upper bound from the local interface (or 1500).
            int hi = (_opt.LocalMtu ?? 1500) - hdr;
            int lo = _opt.BaselinePayload;
            if (hi <= lo) { notes.Add("Local interface MTU is unusually small."); return Done(MtuOutcome.Found, lo); }

            // 3. Try the maximum first: the common case is that the full size works.
            var top = await TrySize(hi);
            if (top.Status == ProbeStatus.Success) return Done(MtuOutcome.Found, hi);
            Note(top, hi);
            bool hinted = IsHint(top, hi, lo, hdr);
            hi = NextHi(top, hi, lo, hdr);

            // 4. Binary search between known-good lo and failing-minus-one hi.
            while (lo < hi)
            {
                int mid = hinted ? hi : (lo + hi + 1) / 2;   // verify a router-reported MTU first
                hinted = false;
                var r = await TrySize(mid);
                if (r.Status == ProbeStatus.Success) { lo = mid; continue; }
                Note(r, mid);
                hinted = IsHint(r, mid, lo, hdr);
                hi = Math.Max(NextHi(r, mid, lo, hdr), lo);
            }

            if (lo + hdr < MinimumMtu(v6))
                notes.Add($"Result {lo + hdr} is below the minimum MTU for {(v6 ? "IPv6" : "IPv4")} ({MinimumMtu(v6)}); treat it with suspicion (heavy packet loss?).");
            if (sawTimeoutAboveLo)
                notes.Add("Oversized packets were silently dropped rather than answered with 'packet too big'. A device on the path is probably filtering ICMP, so TCP sessions can stall (PMTUD black hole). Clamp MSS on the tunnel/firewall.");
            return Done(MtuOutcome.Found, lo, sawTimeoutAboveLo);

            void Note(ProbeResult r, int size) { if (r.Status == ProbeStatus.TimedOut) sawTimeoutAboveLo = true; }
        }
        catch (OperationCanceledException)
        {
            return Done(MtuOutcome.Cancelled);
        }
    }

    /// <summary>
    /// New upper bound after a failure at <paramref name="failedSize"/>: if a router reported its MTU and that is a
    /// sensible smaller size, jump to it (the loop still verifies it); otherwise just step below the failure.
    /// Always strictly less than failedSize, so the search cannot loop.
    /// </summary>
    private static bool IsHint(ProbeResult r, int failedSize, int lo, int hdr) =>
        r.ReportedMtu is int m && m - hdr >= lo && m - hdr < failedSize;

    private static int NextHi(ProbeResult r, int failedSize, int lo, int hdr)
    {
        return IsHint(r, failedSize, lo, hdr) ? r.ReportedMtu!.Value - hdr : failedSize - 1;
    }
}
