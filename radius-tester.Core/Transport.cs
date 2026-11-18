using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace RadiusTester.Core;

public sealed record TransportResult(byte[]? Reply, int Attempts, TimeSpan Rtt, TimeSpan Total, string? Error, IReadOnlyList<string> Notes);

/// <summary>Sends one encoded RADIUS request and waits for the matching reply (retransmitting where the transport needs it).</summary>
public interface IRadiusTransport
{
    Task<TransportResult> ExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, int retries, CancellationToken ct);
}

public sealed class UdpTransport : IRadiusTransport
{
    public async Task<TransportResult> ExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, int retries, CancellationToken ct)
    {
        var total = Stopwatch.StartNew();
        IPAddress addr;
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            addr = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.First();
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or InvalidOperationException)
        {
            return new(null, 0, default, total.Elapsed, $"Could not resolve '{host}': {ex.Message}", []);
        }

        using var sock = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try { sock.Connect(new IPEndPoint(addr, port)); }
        catch (SocketException ex) { return new(null, 0, default, total.Elapsed, "Socket error: " + ex.Message, []); }

        var buf = new byte[4096];
        byte id = request[1];
        int attempts = 0;
        for (int i = 0; i <= Math.Max(0, retries); i++)
        {
            attempts++;
            var sent = Stopwatch.StartNew();
            try { await sock.SendAsync(request, SocketFlags.None, ct).ConfigureAwait(false); }
            catch (SocketException ex) { return new(null, attempts, default, total.Elapsed, "Send failed: " + ex.Message, []); }
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            try
            {
                while (true)
                {
                    int n = await sock.ReceiveAsync(buf, SocketFlags.None, cts.Token).ConfigureAwait(false);
                    if (n >= 20 && buf[1] == id) return new(buf[..n], attempts, sent.Elapsed, total.Elapsed, null, []);
                    // wrong identifier or runt datagram: keep waiting
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* timed out: retransmit */ }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                return new(null, attempts, default, total.Elapsed, "ICMP port unreachable: nothing is listening on that UDP port (or a firewall actively rejected it).", []);
            }
            catch (SocketException ex) { return new(null, attempts, default, total.Elapsed, "Receive failed: " + ex.Message, []); }
        }
        return new(null, attempts, default, total.Elapsed, null, []);
    }
}

public sealed record RadSecOptions(X509Certificate2? ClientCertificate, bool IgnoreCertErrors);

/// <summary>RADIUS over TLS (RFC 6614): one TCP/TLS connection per exchange, packets framed by their RADIUS length field.</summary>
public sealed class RadSecTransport(RadSecOptions options) : IRadiusTransport
{
    public async Task<TransportResult> ExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, int retries, CancellationToken ct)
    {
        var total = Stopwatch.StartNew();
        var notes = new List<string>();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            using var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            notes.Add($"TCP connected to {tcp.Client.RemoteEndPoint} in {total.ElapsedMilliseconds} ms");
            var problems = new List<string>();
            using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, chain, errors) =>
            {
                if (errors != SslPolicyErrors.None) problems.AddRange(TlsErrors(errors, chain));
                if (cert != null) notes.Add($"Server certificate: {cert.Subject} (issuer {cert.Issuer})");
                return errors == SslPolicyErrors.None || options.IgnoreCertErrors;
            });
            var auth = new SslClientAuthenticationOptions { TargetHost = host, EnabledSslProtocols = SslProtocols.None };
            if (options.ClientCertificate != null) auth.ClientCertificates = new X509CertificateCollection { options.ClientCertificate };
            try { await ssl.AuthenticateAsClientAsync(auth, cts.Token).ConfigureAwait(false); }
            catch (Exception ex) when (ex is AuthenticationException or IOException)
            {
                var detail = problems.Count > 0 ? " Certificate problems: " + string.Join(" ", problems) : "";
                return new(null, 1, default, total.Elapsed, "TLS handshake failed: " + (ex.InnerException?.Message ?? ex.Message) + detail, notes);
            }
            notes.Add($"TLS {ssl.SslProtocol}, cipher {ssl.NegotiatedCipherSuite}" + (options.ClientCertificate != null ? ", client certificate presented" : ", no client certificate"));
            foreach (var p in problems.Distinct()) notes.Add("Ignored certificate problem: " + p);

            var sent = Stopwatch.StartNew();
            await ssl.WriteAsync(request, cts.Token).ConfigureAwait(false);
            await ssl.FlushAsync(cts.Token).ConfigureAwait(false);
            var hdr = new byte[20];
            await ssl.ReadExactlyAsync(hdr, cts.Token).ConfigureAwait(false);
            int len = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(2));
            if (len < 20 || len > 4096) return new(null, 1, default, total.Elapsed, $"Server sent an invalid RADIUS length ({len}) over TLS.", notes);
            var reply = new byte[len];
            hdr.CopyTo(reply, 0);
            await ssl.ReadExactlyAsync(reply.AsMemory(20), cts.Token).ConfigureAwait(false);
            return new(reply, 1, sent.Elapsed, total.Elapsed, null, notes);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(null, 1, default, total.Elapsed, null, notes);   // timeout: no reply
        }
        catch (EndOfStreamException)
        {
            return new(null, 1, default, total.Elapsed, "The server closed the TLS connection without replying (client certificate rejected, or this client is not authorised).", notes);
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return new(null, 1, default, total.Elapsed, "Connection failed: " + (ex.InnerException?.Message ?? ex.Message), notes);
        }
    }

    private static IEnumerable<string> TlsErrors(SslPolicyErrors e, X509Chain? chain)
    {
        if (e.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)) yield return "certificate name does not match the host.";
        if (e.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) yield return "server presented no certificate.";
        if (e.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
            foreach (var s in chain?.ChainStatus.Select(s => s.Status.ToString()).Distinct() ?? ["chain not trusted"])
                yield return "chain: " + s + ".";
    }
}
