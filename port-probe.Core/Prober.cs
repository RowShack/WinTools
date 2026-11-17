using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PortProbe.Core;

public enum PortState
{
    /// <summary>Reached a PortProbe listener (banner/echo verified): the path is open end to end.</summary>
    OpenListener,
    /// <summary>Connected, but something other than PortProbe answered (or stayed silent).</summary>
    OpenOther,
    /// <summary>The host answered "nothing listening" (TCP RST / ICMP port unreachable).</summary>
    Refused,
    /// <summary>No answer at all: usually a firewall silently dropping the traffic (or host down).</summary>
    Filtered,
    /// <summary>A router/firewall said the network or host is unreachable.</summary>
    Unreachable,
    /// <summary>UDP only: no reply. Open-but-silent and filtered look identical.</summary>
    NoReply,
    Error,
}

public sealed record PortResult(Proto Proto, int Port, PortState State, int? LatencyMs, string? Banner, string? Detail)
{
    public string Explanation => Explain(Proto, State);

    public static string Explain(Proto proto, PortState state) => (proto, state) switch
    {
        (_, PortState.OpenListener) => "Reached the PortProbe listener. The firewall path to this port is open in both directions used by the test.",
        (Proto.Tcp, PortState.OpenOther) => "Connected, but not to PortProbe. A real service (or something that accepts all connections, such as a proxy or load balancer) is on this port. The path is open.",
        (Proto.Udp, PortState.OpenOther) => "A reply came back, but not from PortProbe. Something is answering on this UDP port.",
        (Proto.Tcp, PortState.Refused) => "Host replied 'connection refused' (TCP reset). The packet REACHED the host, so no firewall is blocking it; there is just no service listening. If you expected a service, start it.",
        (Proto.Udp, PortState.Refused) => "Host replied 'port unreachable' (ICMP). The packet reached the host and nothing is listening on that UDP port.",
        (_, PortState.Filtered) => "No answer within the timeout. Usually a firewall is silently dropping the traffic (or the host is down / the route is missing). Different from 'refused', which proves the host was reached.",
        (_, PortState.Unreachable) => "A router or firewall reported the network or host unreachable (ICMP unreachable / no route). Check routing and firewall 'reject' rules.",
        (_, PortState.NoReply) => "No UDP reply. UDP gives no confirmation: either the port is open but silent, or the traffic was blocked. Use a PortProbe listener on the target to get a definite answer.",
        _ => "The probe failed for a local reason (see details).",
    };
}

public sealed record TlsInfo(bool Handshake, string? Subject, string? Issuer, DateTime? NotAfter, string? Protocol, string? Errors, string? Detail)
{
    public int? DaysLeft => NotAfter is DateTime d ? (int)(d - DateTime.UtcNow).TotalDays : null;
}

public sealed class ProbeOptions
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(2);
    public int Parallelism { get; init; } = 50;
    /// <summary>How long to wait for a banner after a TCP connect.</summary>
    public TimeSpan BannerWait { get; init; } = TimeSpan.FromMilliseconds(600);
}

public static class Prober
{
    public const string Signature = "PORTPROBE";

    public static async Task<List<PortResult>> RunAsync(IPAddress target, IReadOnlyList<PortSpec> specs, ProbeOptions opt,
        IProgress<PortResult>? progress, CancellationToken ct)
    {
        var results = new PortResult?[specs.Count];
        using var gate = new SemaphoreSlim(Math.Max(1, opt.Parallelism));
        var tasks = specs.Select(async (spec, i) =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                var r = spec.Proto == Proto.Tcp
                    ? await ProbeTcpAsync(target, spec.Port, opt, ct).ConfigureAwait(false)
                    : await ProbeUdpAsync(target, spec.Port, opt, ct).ConfigureAwait(false);
                results[i] = r;
                progress?.Report(r);
            }
            finally { gate.Release(); }
        });
        try { await Task.WhenAll(tasks).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* return what finished */ }
        return results.Where(r => r != null).Select(r => r!).ToList();
    }

    public static async Task<PortResult> ProbeTcpAsync(IPAddress target, int port, ProbeOptions opt, CancellationToken ct)
    {
        using var client = new TcpClient(target.AddressFamily);
        var sw = Stopwatch.StartNew();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(opt.Timeout);
        try
        {
            await client.ConnectAsync(target, port, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new PortResult(Proto.Tcp, port, PortState.Filtered, null, null, "timeout");
        }
        catch (SocketException se)
        {
            return se.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => new PortResult(Proto.Tcp, port, PortState.Refused, (int)sw.ElapsedMilliseconds, null, "reset"),
                SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.HostDown or SocketError.NetworkDown
                    => new PortResult(Proto.Tcp, port, PortState.Unreachable, null, null, se.SocketErrorCode.ToString()),
                SocketError.TimedOut => new PortResult(Proto.Tcp, port, PortState.Filtered, null, null, "timeout"),
                _ => new PortResult(Proto.Tcp, port, PortState.Error, null, null, se.SocketErrorCode.ToString()),
            };
        }

        int latency = (int)sw.ElapsedMilliseconds;
        string? banner = null;
        try
        {
            using var bt = CancellationTokenSource.CreateLinkedTokenSource(ct);
            bt.CancelAfter(opt.BannerWait);
            var buf = new byte[256];
            int n = await client.GetStream().ReadAsync(buf, bt.Token).ConfigureAwait(false);
            if (n > 0) banner = Encoding.ASCII.GetString(buf, 0, n).Replace('\0', ' ').Trim();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* silent service: wants us to talk first */ }
        catch (IOException) { }
        catch (SocketException) { }

        if (banner != null && banner.StartsWith(Signature, StringComparison.Ordinal))
            return new PortResult(Proto.Tcp, port, PortState.OpenListener, latency, banner, null);
        return new PortResult(Proto.Tcp, port, PortState.OpenOther, latency, banner, banner == null ? "no banner (service waits for the client to speak first)" : null);
    }

    public static async Task<PortResult> ProbeUdpAsync(IPAddress target, int port, ProbeOptions opt, CancellationToken ct)
    {
        using var udp = new UdpClient(target.AddressFamily);
        var sw = Stopwatch.StartNew();
        try
        {
            udp.Connect(target, port);   // connected UDP: ICMP port-unreachable surfaces as ConnectionReset
            await udp.SendAsync(Encoding.ASCII.GetBytes(Signature + "?"), ct).ConfigureAwait(false);
            using var rt = CancellationTokenSource.CreateLinkedTokenSource(ct);
            rt.CancelAfter(opt.Timeout);
            var resp = await udp.ReceiveAsync(rt.Token).ConfigureAwait(false);
            string text = Encoding.ASCII.GetString(resp.Buffer).Replace('\0', ' ').Trim();
            return text.StartsWith(Signature, StringComparison.Ordinal)
                ? new PortResult(Proto.Udp, port, PortState.OpenListener, (int)sw.ElapsedMilliseconds, text, null)
                : new PortResult(Proto.Udp, port, PortState.OpenOther, (int)sw.ElapsedMilliseconds, text.Length > 0 ? text : null, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new PortResult(Proto.Udp, port, PortState.NoReply, null, null, "timeout");
        }
        catch (SocketException se)
        {
            return se.SocketErrorCode switch
            {
                SocketError.ConnectionReset or SocketError.ConnectionRefused => new PortResult(Proto.Udp, port, PortState.Refused, (int)sw.ElapsedMilliseconds, null, "ICMP port unreachable"),
                SocketError.NetworkUnreachable or SocketError.HostUnreachable => new PortResult(Proto.Udp, port, PortState.Unreachable, null, null, se.SocketErrorCode.ToString()),
                _ => new PortResult(Proto.Udp, port, PortState.Error, null, null, se.SocketErrorCode.ToString()),
            };
        }
    }

    /// <summary>TCP connect + TLS handshake; records the certificate (accepts any cert so we can inspect bad ones).</summary>
    public static async Task<TlsInfo> CheckTlsAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        SslPolicyErrors errors = SslPolicyErrors.None;
        X509Certificate2? cert = null;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(client.GetStream(), false, (_, c, _, e) =>
            {
                errors = e;
                if (c != null) cert = new X509Certificate2(c);
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None,   // let the OS choose
            }, cts.Token).ConfigureAwait(false);
            string errText = errors == SslPolicyErrors.None ? "none (certificate is trusted and matches the name)" : errors.ToString();
            return new TlsInfo(true, cert?.Subject, cert?.Issuer, cert?.NotAfter.ToUniversalTime(), ssl.SslProtocol.ToString(), errText, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new TlsInfo(false, null, null, null, null, null, "timeout"); }
        catch (Exception ex) { return new TlsInfo(false, cert?.Subject, cert?.Issuer, cert?.NotAfter.ToUniversalTime(), null, errors == SslPolicyErrors.None ? null : errors.ToString(), ex.Message); }
    }
}
