using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthMailTest.Core;

/// <summary>One line of a step-by-step result (DNS, TCP, TLS, bind...).</summary>
public sealed record TestStep(string Name, bool Ok, int? Ms, string Detail)
{
    public override string ToString() => $"{(Ok ? "OK  " : "FAIL")}  {Name}{(Ms is int m ? $"  ({m} ms)" : "")}{(Detail.Length > 0 ? " — " + Detail : "")}";
}

public sealed record CertDetails(
    string Subject, string Issuer, DateTime NotBefore, DateTime NotAfter, string Thumbprint,
    IReadOnlyList<string> SubjectAltNames, IReadOnlyList<string> Chain, IReadOnlyList<string> Problems, string Protocol)
{
    public int DaysLeft => (int)Math.Floor((NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
    public bool Trusted => Problems.Count == 0;
}

public static class TlsInspector
{
    /// <summary>
    /// Performs a TLS client handshake on <paramref name="inner"/>, recording the certificate and its problems in plain English.
    /// Certificate errors only abort the handshake when <paramref name="ignoreCertErrors"/> is false.
    /// </summary>
    public static async Task<(SslStream Stream, CertDetails Cert)> HandshakeAsync(Stream inner, string host, bool ignoreCertErrors, CancellationToken ct)
    {
        X509Certificate2? cert = null;
        var problems = new List<string>();
        var chainInfo = new List<string>();
        var ssl = new SslStream(inner, false, (_, c, chain, errors) =>
        {
            if (c != null) cert = new X509Certificate2(c);
            problems.AddRange(Explain(errors, chain));
            if (chain != null)
                foreach (var el in chain.ChainElements)
                    chainInfo.Add(el.Certificate.Subject + (el.ChainElementStatus.Length > 0 ? "  [" + string.Join(", ", el.ChainElementStatus.Select(s => s.Status)) + "]" : ""));
            return errors == SslPolicyErrors.None || ignoreCertErrors;
        });
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host, EnabledSslProtocols = SslProtocols.None }, ct).ConfigureAwait(false);
        }
        catch
        {
            ssl.Dispose();
            throw new TlsHandshakeException("TLS handshake failed", cert is null ? null : Build(cert, problems, chainInfo, "none"), problems);
        }
        return (ssl, Build(cert!, problems, chainInfo, ssl.SslProtocol.ToString()));
    }

    private static CertDetails Build(X509Certificate2 c, List<string> problems, List<string> chain, string proto) =>
        new(c.Subject, c.Issuer, c.NotBefore, c.NotAfter, c.Thumbprint, SubjectAltNames(c), chain.Distinct().ToList(), problems.Distinct().ToList(), proto);

    public static List<string> SubjectAltNames(X509Certificate2 c)
    {
        var ext = c.Extensions["2.5.29.17"];
        if (ext == null) return [];
        return ext.Format(true).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
    }

    /// <summary>Plain-English version of certificate validation failures.</summary>
    public static List<string> Explain(SslPolicyErrors errors, X509Chain? chain)
    {
        var list = new List<string>();
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) list.Add("The server did not present a certificate.");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)) list.Add("The certificate's name (subject / SAN) does not match the host you connected to. Connect using a name listed in the certificate.");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && chain != null)
        {
            foreach (var s in chain.ChainStatus.Select(s => s.Status).Distinct())
                list.Add(ExplainChain(s));
        }
        else if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors)) list.Add("The certificate chain is not trusted.");
        return list;
    }

    public static string ExplainChain(X509ChainStatusFlags f) => f switch
    {
        X509ChainStatusFlags.NotTimeValid => "The certificate has expired or is not valid yet. Check its dates and this PC's clock.",
        X509ChainStatusFlags.UntrustedRoot => "Issued by a CA that this PC does not trust (self-signed or private CA). Install the CA certificate in the Windows trust store.",
        X509ChainStatusFlags.PartialChain => "The chain can't be completed to a trusted root, usually because the server isn't sending its intermediate certificate.",
        X509ChainStatusFlags.Revoked => "The certificate has been revoked.",
        X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation => "Revocation status could not be checked (CRL/OCSP unreachable from this PC).",
        X509ChainStatusFlags.NotSignatureValid => "A signature in the chain is invalid.",
        X509ChainStatusFlags.NotValidForUsage => "The certificate is not valid for server authentication.",
        X509ChainStatusFlags.InvalidBasicConstraints or X509ChainStatusFlags.InvalidExtension => "A certificate in the chain has invalid constraints/extensions.",
        _ => $"Certificate chain problem: {f}.",
    };

    public static string Describe(Exception ex) => ex switch
    {
        TlsHandshakeException t when t.InnerException is not null => Describe(t.InnerException),
        AuthenticationException a when a.Message.Contains("decryption", StringComparison.OrdinalIgnoreCase) || a.InnerException?.Message.Contains("decryption", StringComparison.OrdinalIgnoreCase) == true
            => "TLS protocol or cipher mismatch: the server and this PC share no TLS version/cipher (server may be limited to TLS 1.0/1.1, or this is not a TLS port).",
        AuthenticationException a when a.Message.Contains("remote certificate", StringComparison.OrdinalIgnoreCase) => "The server's certificate was rejected (see certificate problems).",
        AuthenticationException a => "TLS handshake failed: " + (a.InnerException?.Message ?? a.Message),
        _ => ex.Message,
    };
}

public sealed class TlsHandshakeException(string message, CertDetails? cert, IReadOnlyList<string> problems) : Exception(message)
{
    public CertDetails? Cert { get; } = cert;
    public IReadOnlyList<string> Problems { get; } = problems;
}

public static class Timing
{
    public static async Task<(T Value, int Ms)> TimeAsync<T>(Func<Task<T>> f)
    {
        var sw = Stopwatch.StartNew();
        var v = await f().ConfigureAwait(false);
        return (v, (int)sw.ElapsedMilliseconds);
    }
}
