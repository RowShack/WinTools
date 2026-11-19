using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace AuthMailTest.Core;

public enum SmtpSecurity { None, SslOnConnect, StartTls }

public sealed class SmtpRequest
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 25;
    public SmtpSecurity Security { get; set; } = SmtpSecurity.None;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public string MailFrom { get; set; } = "";
    public string RcptTo { get; set; } = "";
    public bool IgnoreCertErrors { get; set; }
    public int TimeoutSeconds { get; set; } = 10;
    public string EhloName { get; set; } = Environment.MachineName;

    public static int DefaultPort(SmtpSecurity s) => s switch { SmtpSecurity.SslOnConnect => 465, SmtpSecurity.StartTls => 587, _ => 25 };
}

public enum RelayOutcome { NotTested, Accepted, Rejected, Error }

public sealed class SmtpResult
{
    public List<TestStep> Steps { get; } = [];
    public List<string> Transcript { get; } = [];
    public List<string> Capabilities { get; } = [];
    public List<string> AuthMechanisms { get; } = [];
    public CertDetails? Cert { get; set; }
    public RelayOutcome Relay { get; set; } = RelayOutcome.NotTested;
    public string? RelayDetail { get; set; }
    public List<string> Hints { get; } = [];
    public bool Success => Steps.Count > 0 && Steps.All(s => s.Ok);
    public string TranscriptText => string.Join(Environment.NewLine, Transcript);
}

public sealed record SmtpReply(int Code, string Text, IReadOnlyList<string> Lines)
{
    public bool IsOk => Code is >= 200 and < 400;
}

/// <summary>
/// A small raw SMTP client so we control (and can log) the whole conversation, including MAIL FROM / RCPT TO / RSET
/// without ever sending DATA. Passwords never reach the transcript.
/// </summary>
public static class SmtpTester
{
    public static async Task<SmtpResult> RunAsync(SmtpRequest req, IProgress<TestStep>? progress, CancellationToken ct)
    {
        var res = new SmtpResult();
        void Add(TestStep s) { res.Steps.Add(s); progress?.Report(s); }
        var timeout = TimeSpan.FromSeconds(Math.Max(1, req.TimeoutSeconds));
        var sw = Stopwatch.StartNew();
        TcpClient? tcp = null;
        SmtpSession? s = null;
        try
        {
            // connect
            tcp = new TcpClient();
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeout);
                try { await tcp.ConnectAsync(req.Host, req.Port, cts.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("connect timed out"); }
            }
            Add(new TestStep($"TCP connect to {req.Host}:{req.Port}", true, (int)sw.ElapsedMilliseconds, ""));

            Stream stream = tcp.GetStream();
            if (req.Security == SmtpSecurity.SslOnConnect)
            {
                sw.Restart();
                var (ssl, cert) = await TlsInspector.HandshakeAsync(stream, req.Host, true, ct);
                res.Cert = cert;
                bool fatal = !req.IgnoreCertErrors && !cert.Trusted;
                Add(new TestStep("TLS handshake (SSL on connect)", !fatal, (int)sw.ElapsedMilliseconds, CertSummary(cert)));
                stream = ssl;
                if (fatal) { res.Hints.Add("The server's certificate isn't trusted by this PC. Fix the certificate or tick 'Ignore certificate errors' to continue the test."); return res; }
            }

            s = new SmtpSession(stream, res.Transcript, timeout, ct);

            // banner
            sw.Restart();
            var banner = await s.ReadReplyAsync();
            Add(new TestStep("Server banner", banner.Code == 220, (int)sw.ElapsedMilliseconds, $"{banner.Code} {banner.Text}"));
            if (banner.Code != 220) { res.Hints.Add(SmtpHints.ForReply(banner.Code, banner.Text)); return res; }

            // EHLO
            sw.Restart();
            var ehlo = await s.CommandAsync($"EHLO {req.EhloName}");
            if (!ehlo.IsOk) { Add(new TestStep("EHLO", false, (int)sw.ElapsedMilliseconds, $"{ehlo.Code} {ehlo.Text}")); res.Hints.Add(SmtpHints.ForReply(ehlo.Code, ehlo.Text)); return res; }
            ReadCaps(ehlo, res);
            Add(new TestStep("EHLO", true, (int)sw.ElapsedMilliseconds, "capabilities: " + (res.Capabilities.Count == 0 ? "none" : string.Join(", ", res.Capabilities))));

            // STARTTLS
            if (req.Security == SmtpSecurity.StartTls)
            {
                sw.Restart();
                if (!res.Capabilities.Any(c => c.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase)))
                {
                    Add(new TestStep("STARTTLS", false, (int)sw.ElapsedMilliseconds, "server does not offer STARTTLS"));
                    res.Hints.Add("The server doesn't advertise STARTTLS on this port. Try 'SSL on connect' (usually port 465), or the server may not support encryption here.");
                    return res;
                }
                var st = await s.CommandAsync("STARTTLS");
                if (st.Code != 220) { Add(new TestStep("STARTTLS", false, (int)sw.ElapsedMilliseconds, $"{st.Code} {st.Text}")); res.Hints.Add(SmtpHints.ForReply(st.Code, st.Text)); return res; }
                var (ssl, cert) = await TlsInspector.HandshakeAsync(stream, req.Host, true, ct);
                res.Cert = cert;
                bool fatal = !req.IgnoreCertErrors && !cert.Trusted;
                Add(new TestStep("STARTTLS + TLS handshake", !fatal, (int)sw.ElapsedMilliseconds, CertSummary(cert)));
                if (fatal) { res.Hints.Add("The server's certificate isn't trusted by this PC. Fix the certificate or tick 'Ignore certificate errors' to continue the test."); return res; }
                s.ReplaceStream(ssl);
                res.Capabilities.Clear(); res.AuthMechanisms.Clear();
                var ehlo2 = await s.CommandAsync($"EHLO {req.EhloName}");
                ReadCaps(ehlo2, res);
            }

            if (res.AuthMechanisms.Count > 0)
                Add(new TestStep("AUTH methods offered", true, null, string.Join(", ", res.AuthMechanisms)));

            // AUTH
            if (req.User.Length > 0)
            {
                sw.Restart();
                var r = await AuthenticateAsync(s, res, req);
                Add(new TestStep($"Authenticate as {req.User}", r.IsOk, (int)sw.ElapsedMilliseconds, $"{r.Code} {r.Text}"));
                if (!r.IsOk) { res.Hints.Add(SmtpHints.ForReply(r.Code, r.Text)); return res; }
            }

            // relay test: MAIL FROM + RCPT TO, then RSET (never DATA)
            if (req.MailFrom.Length > 0 && req.RcptTo.Length > 0)
            {
                sw.Restart();
                var mf = await s.CommandAsync($"MAIL FROM:<{Sanitize(req.MailFrom)}>");
                if (!mf.IsOk)
                {
                    Add(new TestStep("MAIL FROM", false, (int)sw.ElapsedMilliseconds, $"{mf.Code} {mf.Text}"));
                    res.Relay = RelayOutcome.Rejected; res.RelayDetail = $"Sender rejected: {mf.Code} {mf.Text}";
                    res.Hints.Add(SmtpHints.ForReply(mf.Code, mf.Text));
                }
                else
                {
                    var rc = await s.CommandAsync($"RCPT TO:<{Sanitize(req.RcptTo)}>");
                    bool ok = rc.Code is 250 or 251;
                    Add(new TestStep("RCPT TO (relay test)", ok, (int)sw.ElapsedMilliseconds, $"{rc.Code} {rc.Text}"));
                    res.Relay = ok ? RelayOutcome.Accepted : RelayOutcome.Rejected;
                    res.RelayDetail = ok
                        ? "The server would accept mail for this recipient from this connection. (If the recipient's domain is hosted on this server that is normal; if it is an outside domain, this server relays for you.)"
                        : $"The server refused the recipient: {rc.Code} {rc.Text}";
                    if (!ok) res.Hints.Add(SmtpHints.ForReply(rc.Code, rc.Text));
                    await s.CommandAsync("RSET");
                }
            }

            try { await s.CommandAsync("QUIT"); } catch { /* server may just close */ }
        }
        catch (TlsHandshakeException ex)
        {
            res.Cert = ex.Cert ?? res.Cert;
            Add(new TestStep("TLS handshake", false, (int)sw.ElapsedMilliseconds, TlsInspector.Describe(ex)));
            res.Hints.Add(SmtpHints.ForException(ex));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { Add(new TestStep("Cancelled", false, null, "")); }
        catch (Exception ex)
        {
            Add(new TestStep("SMTP", false, (int)sw.ElapsedMilliseconds, ex.Message));
            res.Hints.Add(SmtpHints.ForException(ex, req.Port));
        }
        finally { s?.Dispose(); tcp?.Dispose(); }
        return res;
    }

    private static string CertSummary(CertDetails c) =>
        $"{c.Protocol}; {c.Subject}; expires {c.NotAfter:yyyy-MM-dd} ({c.DaysLeft} days); {(c.Trusted ? "trusted" : "problems: " + string.Join(" ", c.Problems))}";

    private static string Sanitize(string addr) => addr.Replace("\r", "").Replace("\n", "").Replace("<", "").Replace(">", "").Trim();

    private static void ReadCaps(SmtpReply ehlo, SmtpResult res)
    {
        foreach (var line in ehlo.Lines.Skip(1))
        {
            string l = line.Trim();
            if (l.Length == 0) continue;
            if (l.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase) && (l.Length == 4 || l[4] is ' ' or '='))
            {
                res.AuthMechanisms.AddRange(l[4..].TrimStart(' ', '=').Split(' ', StringSplitOptions.RemoveEmptyEntries));
            }
            res.Capabilities.Add(l.Split(' ')[0].ToUpperInvariant());
        }
        res.Capabilities.RemoveAll(c => c == "AUTH");
        res.Capabilities.Add("AUTH");
        if (res.AuthMechanisms.Count == 0) res.Capabilities.Remove("AUTH");
    }

    private static async Task<SmtpReply> AuthenticateAsync(SmtpSession s, SmtpResult res, SmtpRequest req)
    {
        bool plain = res.AuthMechanisms.Contains("PLAIN", StringComparer.OrdinalIgnoreCase);
        bool login = res.AuthMechanisms.Contains("LOGIN", StringComparer.OrdinalIgnoreCase);
        if (res.AuthMechanisms.Count == 0)
            return new SmtpReply(504, "Server did not offer AUTH (after TLS if required). Cannot authenticate.", []);
        if (!plain && !login)
            return new SmtpReply(504, $"Server only offers {string.Join(", ", res.AuthMechanisms)}; this tool supports PLAIN and LOGIN.", []);
        if (plain)
        {
            string tok = Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{req.User}\0{req.Password}"));
            return await s.CommandAsync("AUTH PLAIN " + tok, "AUTH PLAIN [credentials hidden]");
        }
        var r = await s.CommandAsync("AUTH LOGIN");
        if (r.Code != 334) return r;
        r = await s.CommandAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(req.User)), "[user name hidden]");
        if (r.Code != 334) return r;
        return await s.CommandAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(req.Password)), "[password hidden]");
    }
}

internal sealed class SmtpSession : IDisposable
{
    private Stream _stream;
    private StreamReader _reader;
    private readonly List<string> _log;
    private readonly TimeSpan _timeout;
    private readonly CancellationToken _ct;

    public SmtpSession(Stream stream, List<string> log, TimeSpan timeout, CancellationToken ct)
    { _stream = stream; _reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true); _log = log; _timeout = timeout; _ct = ct; }

    public void ReplaceStream(Stream s) { _reader.Dispose(); _stream = s; _reader = new StreamReader(s, Encoding.ASCII, false, 1024, true); }

    public async Task<SmtpReply> CommandAsync(string cmd, string? logAs = null)
    {
        _log.Add("C: " + (logAs ?? cmd));
        var bytes = Encoding.ASCII.GetBytes(cmd + "\r\n");
        await _stream.WriteAsync(bytes, _ct).ConfigureAwait(false);
        await _stream.FlushAsync(_ct).ConfigureAwait(false);
        return await ReadReplyAsync().ConfigureAwait(false);
    }

    /// <summary>Reads a (possibly multi-line) reply: "250-..." continues, "250 ..." ends.</summary>
    public async Task<SmtpReply> ReadReplyAsync()
    {
        var lines = new List<string>();
        int code = 0;
        while (true)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
            cts.CancelAfter(_timeout);
            string? line;
            try { line = await _reader.ReadLineAsync(cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!_ct.IsCancellationRequested) { throw new TimeoutException("the server did not answer in time"); }
            if (line == null) throw new IOException("the server closed the connection");
            _log.Add("S: " + line);
            if (line.Length < 3 || !int.TryParse(line.AsSpan(0, 3), out int c)) throw new IOException("unexpected reply: " + line);
            code = c;
            lines.Add(line.Length > 4 ? line[4..] : "");
            if (line.Length == 3 || line[3] != '-') break;
        }
        return new SmtpReply(code, lines[0], lines);
    }

    public void Dispose() { try { _reader.Dispose(); } catch { } }
}

public static class SmtpHints
{
    public static string ForReply(int code, string text)
    {
        string t = text.ToLowerInvariant();
        if (t.Contains("5.7.57") || t.Contains("client was not authenticated") || t.Contains("smtp auth") && t.Contains("disabled") || t.Contains("basic authentication") && t.Contains("disabled"))
            return $"{code}: SMTP authentication is disabled or not allowed for this account/tenant (typical for Microsoft 365: SMTP AUTH or basic auth is switched off). Enable authenticated SMTP for the mailbox or use an app/connector.";
        if (t.Contains("relay") && (code == 550 || code == 554 || code == 530 || code == 454 || code == 553 || code == 551))
            return $"{code}: Relay denied. The server does not accept mail for that recipient from this client. Authenticate, send from an allowed IP address, or use a recipient in a domain the server hosts.";
        return code switch
        {
            421 => "421: The service is unavailable or closing the channel: server busy, too many connections, or the client IP is rate-limited/greylisted. Retry later.",
            450 or 451 or 452 => $"{code}: Temporary failure (greylisting, rate limit or a full mailbox/queue). Retry later.",
            454 => "454: Temporary authentication or TLS failure. If this followed STARTTLS, TLS isn't available on the server right now; otherwise relay access was temporarily denied.",
            500 or 501 or 502 or 503 or 504 => $"{code}: The server rejected the command syntax or sequence. It may not support what was asked (for instance an AUTH method or STARTTLS).",
            530 => "530: Authentication required (often 'STARTTLS first' too). Enable authentication and, for ports 587/25, use STARTTLS before AUTH.",
            534 => "534: The authentication mechanism is too weak: use a TLS connection first.",
            535 => "535: Authentication failed: wrong user name or password, an app password / MFA is required, or this account is not allowed to use SMTP AUTH.",
            538 => "538: Encryption required for this authentication mechanism: use SSL/STARTTLS.",
            550 => "550: Mailbox or command rejected (unknown recipient, blocked sender, or a policy such as SPF/relay). Read the message text for the reason.",
            551 or 553 => $"{code}: Address rejected: the server wants a different or valid sender/recipient address (check MAIL FROM against what the server allows).",
            552 => "552: Message or mailbox size limit exceeded.",
            554 => "554: Transaction failed: usually your IP address or sender is blocked or flagged as spam, or the policy rejected the connection. Check blocklists and the sending IP's reputation.",
            >= 500 => $"{code}: Permanent failure. Read the server's message text for the reason.",
            >= 400 => $"{code}: Temporary failure. Retry later.",
            _ => "",
        };
    }

    public static string ForException(Exception ex, int? port = null)
    {
        if (ex is TlsHandshakeException || ex is System.Security.Authentication.AuthenticationException || ex.InnerException is System.Security.Authentication.AuthenticationException)
            return TlsInspector.Describe(ex) + " Make sure the security mode matches the port: 465 = SSL on connect, 587 = STARTTLS, 25 = usually none/STARTTLS.";
        if (ex is TimeoutException) return port == 25
            ? "Connection timed out on port 25. Many ISPs and cloud providers block outbound port 25: try 587 or 465, or test from a network that allows it."
            : "Timed out: a firewall is probably dropping traffic to this port, or the server is down.";
        if (ex is SocketException se)
            return se.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => "Connection refused: the server is reachable but nothing listens on this port (wrong port, or SMTP service not running).",
                SocketError.HostNotFound or SocketError.NoData => "The host name could not be resolved. Check the spelling and DNS.",
                SocketError.TimedOut => port == 25 ? "Connection timed out on port 25 — often blocked by an ISP/cloud provider. Try 587 or 465." : "Timed out: a firewall is probably dropping the traffic.",
                _ => "Network error: " + se.Message,
            };
        if (ex is IOException io && io.Message.Contains("closed", StringComparison.OrdinalIgnoreCase))
            return "The server closed the connection. If you chose SSL-on-connect for a plain port (or the reverse), the security mode doesn't match the port; otherwise the server may be rejecting your IP.";
        return "";
    }
}
