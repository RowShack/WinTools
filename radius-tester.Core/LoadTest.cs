using System.Diagnostics;

namespace RadiusTester.Core;

public sealed record LoadTestResult(int Sent, int Accepted, int Rejected, int Challenged, int NoReply, int Errors, double ElapsedSeconds,
    double AchievedRate, double MinMs, double P50Ms, double P90Ms, double P95Ms, double P99Ms, double MaxMs, double MeanMs)
{
    public int Failures => NoReply + Errors;
    public override string ToString() =>
        $"Sent {Sent} in {ElapsedSeconds:0.0} s ({AchievedRate:0.0}/s) | accept {Accepted}, reject {Rejected}, challenge {Challenged}, no reply {NoReply}, errors {Errors} | " +
        $"latency ms: min {MinMs:0.0} p50 {P50Ms:0.0} p90 {P90Ms:0.0} p95 {P95Ms:0.0} p99 {P99Ms:0.0} max {MaxMs:0.0}";
}

public static class LoadTest
{
    /// <summary>Nearest-rank percentile of an ascending-sorted list (p in 0..100).</summary>
    public static double Percentile(IReadOnlyList<double> sorted, double p)
    {
        if (sorted.Count == 0) return 0;
        int rank = (int)Math.Ceiling(p / 100.0 * sorted.Count);
        return sorted[Math.Clamp(rank, 1, sorted.Count) - 1];
    }

    public static LoadTestResult Summarize(IEnumerable<(Verdict V, double Ms)> samples, double elapsed)
    {
        var all = samples.ToList();
        var lat = all.Where(s => s.V is Verdict.Accept or Verdict.Reject or Verdict.Challenge or Verdict.StatusOk or Verdict.AccountingOk).Select(s => s.Ms).Order().ToList();
        int Count(params Verdict[] vs) => all.Count(s => vs.Contains(s.V));
        return new LoadTestResult(all.Count, Count(Verdict.Accept, Verdict.StatusOk, Verdict.AccountingOk), Count(Verdict.Reject), Count(Verdict.Challenge), Count(Verdict.NoReply),
            Count(Verdict.NetworkError, Verdict.BadReply, Verdict.Other), elapsed, elapsed > 0 ? all.Count / elapsed : 0,
            lat.Count > 0 ? lat[0] : 0, Percentile(lat, 50), Percentile(lat, 90), Percentile(lat, 95), Percentile(lat, 99), lat.Count > 0 ? lat[^1] : 0, lat.Count > 0 ? lat.Average() : 0);
    }

    /// <summary>Sends <paramref name="count"/> Access-Requests (or Status-Server pings) at about <paramref name="perSecond"/>, each on its own socket, without retries.</summary>
    public static async Task<LoadTestResult> RunAsync(ServerProfile profile, AuthRequest template, int count, double perSecond, bool statusServer,
        IProgress<(int Done, int Total)>? progress, CancellationToken ct, IRadiusTransport? transport = null, int maxInFlight = 200)
    {
        var p = new ServerProfile
        {
            Host = profile.Host, AuthPort = profile.AuthPort, AcctPort = profile.AcctPort, Secret = profile.Secret, TimeoutSeconds = profile.TimeoutSeconds, Retries = 0,
            NasIp = profile.NasIp, NasIdentifier = profile.NasIdentifier, SendMessageAuthenticator = profile.SendMessageAuthenticator, Transport = profile.Transport,
            RadSecPort = profile.RadSecPort, ClientCertPfxPath = profile.ClientCertPfxPath, ClientCertPfxPassword = profile.ClientCertPfxPassword,
            ClientCertThumbprint = profile.ClientCertThumbprint, IgnoreServerCertErrors = profile.IgnoreServerCertErrors,
        };
        var client = new RadiusClient(p, transport);
        var results = new (Verdict V, double Ms)[count];
        using var gate = new SemaphoreSlim(Math.Max(1, maxInFlight));
        var tasks = new List<Task>(count);
        int done = 0;
        var sw = Stopwatch.StartNew();
        double interval = perSecond > 0 ? 1000.0 / perSecond : 0;
        try
        {
            for (int i = 0; i < count && !ct.IsCancellationRequested; i++)
            {
                if (interval > 0)
                {
                    double due = i * interval;
                    while (sw.Elapsed.TotalMilliseconds < due && !ct.IsCancellationRequested)
                    {
                        double wait = due - sw.Elapsed.TotalMilliseconds;
                        if (wait > 2) await Task.Delay((int)Math.Min(wait, 20), ct).ConfigureAwait(false); else await Task.Yield();
                    }
                }
                await gate.WaitAsync(ct).ConfigureAwait(false);
                int idx = i;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var built = statusServer ? client.BuildStatusServer() : client.BuildAccessRequest(template);
                        var t0 = Stopwatch.StartNew();
                        var ex = await client.SendAsync("load", built, ct).ConfigureAwait(false);
                        results[idx] = (ex.Verdict, ex.Rtt.TotalMilliseconds > 0 ? ex.Rtt.TotalMilliseconds : t0.Elapsed.TotalMilliseconds);
                    }
                    catch (OperationCanceledException) { results[idx] = (Verdict.NetworkError, 0); }
                    catch (Exception) { results[idx] = (Verdict.NetworkError, 0); }
                    finally { gate.Release(); progress?.Report((Interlocked.Increment(ref done), count)); }
                }, CancellationToken.None));
            }
        }
        catch (OperationCanceledException) { }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        var sent = results.Take(tasks.Count).ToList();
        return Summarize(sent, sw.Elapsed.TotalSeconds);
    }
}
