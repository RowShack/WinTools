using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace AuthMailTest.Core;

public enum LdapMode { Ldap389, Ldaps636, StartTls }
public enum LdapBind { Simple, Negotiate, Anonymous }

public sealed class LdapRequest
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 389;
    public LdapMode Mode { get; set; } = LdapMode.Ldap389;
    public LdapBind Bind { get; set; } = LdapBind.Negotiate;
    public string User { get; set; } = "";          // DN or UPN for simple; DOMAIN\user or UPN for negotiate (empty = current user)
    public string Password { get; set; } = "";
    public bool IgnoreCertErrors { get; set; }
    public int TimeoutSeconds { get; set; } = 8;
    // optional search
    public bool DoSearch { get; set; }
    public string BaseDn { get; set; } = "";
    public string Filter { get; set; } = "(objectClass=*)";
    public string Attributes { get; set; } = "cn,distinguishedName";
    public SearchScope Scope { get; set; } = SearchScope.Subtree;
    public int SizeLimit { get; set; } = 200;

    public static int DefaultPort(LdapMode m) => m == LdapMode.Ldaps636 ? 636 : 389;
}

public sealed record LdapEntry(string Dn, IReadOnlyDictionary<string, string> Attributes);

public sealed class LdapResult
{
    public List<TestStep> Steps { get; } = [];
    public CertDetails? Cert { get; set; }
    public List<LdapEntry> Entries { get; } = [];
    public bool Success => Steps.Count > 0 && Steps.All(s => s.Ok);
    public string? Explanation { get; set; }
}

public static class LdapTester
{
    /// <summary>
    /// Runs DNS → TCP → TLS → bind → search, stopping at the first failure. Returns plain-English explanations.
    /// </summary>
    public static async Task<LdapResult> RunAsync(LdapRequest req, IProgress<TestStep>? progress, CancellationToken ct)
    {
        var res = new LdapResult();
        void Add(TestStep s) { res.Steps.Add(s); progress?.Report(s); }
        var timeout = TimeSpan.FromSeconds(Math.Max(1, req.TimeoutSeconds));
        var sw = Stopwatch.StartNew();

        // 1. DNS
        IPAddress[] addrs;
        try
        {
            addrs = IPAddress.TryParse(req.Host, out var lit) ? [lit] : await Dns.GetHostAddressesAsync(req.Host, ct);
            Add(new TestStep("DNS resolve", true, (int)sw.ElapsedMilliseconds, string.Join(", ", addrs.Select(a => a.ToString()))));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Add(new TestStep("DNS resolve", false, (int)sw.ElapsedMilliseconds, ex.Message));
            res.Explanation = "The name could not be resolved. Check the spelling, the DNS server this PC uses, and whether the name exists.";
            return res;
        }

        // 2. TCP
        sw.Restart();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(addrs[0], req.Port, cts.Token);
            Add(new TestStep($"TCP connect to port {req.Port}", true, (int)sw.ElapsedMilliseconds, addrs[0].ToString()));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Add(new TestStep($"TCP connect to port {req.Port}", false, (int)sw.ElapsedMilliseconds, "timed out"));
            res.Explanation = "No answer: a firewall is probably dropping traffic to this port, or the server is down.";
            return res;
        }
        catch (SocketException ex)
        {
            Add(new TestStep($"TCP connect to port {req.Port}", false, (int)sw.ElapsedMilliseconds, ex.SocketErrorCode.ToString()));
            res.Explanation = ex.SocketErrorCode == SocketError.ConnectionRefused
                ? "The server answered 'refused': it is reachable but nothing is listening on that port (wrong port, or LDAP service not running)."
                : "Could not connect: " + ex.Message;
            return res;
        }

        // 3. TLS for LDAPS: inspect the certificate ourselves so we can show the details
        if (req.Mode == LdapMode.Ldaps636)
        {
            sw.Restart();
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(addrs[0], req.Port, ct);
                var (ssl, cert) = await TlsInspector.HandshakeAsync(tcp.GetStream(), req.Host, true, ct);
                using (ssl) { }
                res.Cert = cert;
                bool fatal = !req.IgnoreCertErrors && !cert.Trusted;
                Add(new TestStep("TLS handshake (LDAPS)", !fatal, (int)sw.ElapsedMilliseconds,
                    $"{cert.Protocol}, {(cert.Trusted ? "certificate trusted" : "certificate problems: " + string.Join(" ", cert.Problems))}"));
                if (fatal) { res.Explanation = "The server's certificate isn't trusted by this PC. Fix the certificate/trust, or tick 'Ignore certificate errors' for a test."; return res; }
            }
            catch (TlsHandshakeException ex)
            {
                res.Cert = ex.Cert;
                Add(new TestStep("TLS handshake (LDAPS)", false, (int)sw.ElapsedMilliseconds, TlsInspector.Describe(ex)));
                res.Explanation = "Port " + req.Port + " did not complete a TLS handshake. Is this really an LDAPS port?";
                return res;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Add(new TestStep("TLS handshake (LDAPS)", false, (int)sw.ElapsedMilliseconds, ex.Message));
                return res;
            }
        }

        // 4. LDAP bind (blocking API → background thread)
        sw.Restart();
        CertDetails? startTlsCert = null;
        try
        {
            var entries = await Task.Run(() => BindAndSearch(req, timeout, c => startTlsCert = c, Add, sw), ct);
            res.Entries.AddRange(entries);
            if (startTlsCert != null) res.Cert = startTlsCert;
        }
        catch (LdapException ex)
        {
            Add(new TestStep(StepForFailure(req), false, (int)sw.ElapsedMilliseconds, $"LDAP error {ex.ErrorCode}: {ex.Message}"));
            res.Explanation = LdapErrors.Explain(ex.ErrorCode, ex.ServerErrorMessage ?? ex.Message);
            if (startTlsCert != null) res.Cert = startTlsCert;
        }
        catch (DirectoryOperationException ex)
        {
            int code = (int)(ex.Response?.ResultCode ?? 0);
            Add(new TestStep("LDAP search", false, (int)sw.ElapsedMilliseconds, ex.Message));
            res.Explanation = LdapErrors.Explain(code, ex.Response?.ErrorMessage ?? ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Add(new TestStep("LDAP", false, (int)sw.ElapsedMilliseconds, ex.Message));
        }
        return res;
    }

    private static string StepForFailure(LdapRequest r) => r.Mode == LdapMode.StartTls ? "StartTLS / bind" : "LDAP bind";

    private static List<LdapEntry> BindAndSearch(LdapRequest req, TimeSpan timeout, Action<CertDetails> onCert, Action<TestStep> add, Stopwatch sw)
    {
        var id = new LdapDirectoryIdentifier(req.Host, req.Port, false, false);
        using var conn = new LdapConnection(id) { Timeout = timeout };
        conn.SessionOptions.ProtocolVersion = 3;
        conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (req.Mode == LdapMode.Ldaps636) conn.SessionOptions.SecureSocketLayer = true;

        conn.SessionOptions.VerifyServerCertificate = (c, cert) =>
        {
            var x = new X509Certificate2(cert);
            using var chain = new X509Chain();
            bool ok = chain.Build(x);
            var problems = chain.ChainStatus.Select(s => TlsInspector.ExplainChain(s.Status)).Distinct().ToList();
            if (!ok || false) { /* recorded below */ }
            onCert(new CertDetails(x.Subject, x.Issuer, x.NotBefore, x.NotAfter, x.Thumbprint, TlsInspector.SubjectAltNames(x),
                chain.ChainElements.Select(e => e.Certificate.Subject).ToList(), problems, req.Mode == LdapMode.StartTls ? "StartTLS" : "TLS"));
            return ok || req.IgnoreCertErrors;
        };

        if (req.Mode == LdapMode.StartTls)
        {
            sw.Restart();
            conn.AuthType = AuthType.Anonymous;
            conn.SessionOptions.StartTransportLayerSecurity(null);
            add(new TestStep("StartTLS upgrade", true, (int)sw.ElapsedMilliseconds, "TLS established on the LDAP connection"));
        }

        sw.Restart();
        switch (req.Bind)
        {
            case LdapBind.Anonymous:
                conn.AuthType = AuthType.Anonymous;
                conn.Bind();
                break;
            case LdapBind.Simple:
                if (req.Mode == LdapMode.Ldap389)
                    add(new TestStep("Warning", true, null, "Simple bind over plain LDAP (389) sends the password unencrypted. Prefer LDAPS or StartTLS."));
                conn.AuthType = AuthType.Basic;
                conn.Bind(new NetworkCredential(req.User, req.Password));
                break;
            default:
                conn.AuthType = AuthType.Negotiate;
                if (string.IsNullOrWhiteSpace(req.User)) conn.Bind();
                else conn.Bind(new NetworkCredential(req.User, req.Password));
                break;
        }
        add(new TestStep($"Bind ({req.Bind}{(req.Bind == LdapBind.Negotiate && string.IsNullOrWhiteSpace(req.User) ? ", current Windows user" : "")})", true, (int)sw.ElapsedMilliseconds, "success"));

        var entries = new List<LdapEntry>();
        if (req.DoSearch)
        {
            sw.Restart();
            var attrs = req.Attributes.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries);
            var sr = new SearchRequest(req.BaseDn, req.Filter, req.Scope, attrs.Length > 0 ? attrs : null) { SizeLimit = req.SizeLimit, TimeLimit = timeout };
            var resp = (SearchResponse)conn.SendRequest(sr);
            foreach (SearchResultEntry e in resp.Entries)
            {
                var d = new Dictionary<string, string>();
                foreach (string name in e.Attributes.AttributeNames)
                {
                    var a = e.Attributes[name];
                    var vals = new List<string>();
                    for (int i = 0; i < a.Count; i++) vals.Add(a[i] is byte[] b ? $"<{b.Length} bytes>" : a[i]?.ToString() ?? "");
                    d[name] = string.Join("; ", vals);
                }
                entries.Add(new LdapEntry(e.DistinguishedName, d));
            }
            add(new TestStep("Search", true, (int)sw.ElapsedMilliseconds, $"{entries.Count} entr{(entries.Count == 1 ? "y" : "ies")} returned"));
        }
        return entries;
    }
}

public static class DcLocator
{
    public sealed record DcRecord(string Host, int Port, int Priority, int Weight);

    /// <summary>Finds domain controllers via _ldap._tcp.dc._msdcs.&lt;domain&gt; SRV records.</summary>
    public static async Task<List<DcRecord>> FindAsync(string domain, CancellationToken ct = default)
    {
        domain = domain.Trim().TrimEnd('.');
        if (domain.Length == 0 || !domain.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_'))
            throw new ArgumentException("Enter a valid DNS domain name, e.g. corp.example.com");

        string script = $"$ErrorActionPreference='Stop'; @(Resolve-DnsName -Type SRV -Name '_ldap._tcp.dc._msdcs.{domain}' -ErrorAction Stop | Where-Object {{ $_.Type -eq 'SRV' }} | ForEach-Object {{ [pscustomobject]@{{H=[string]$_.NameTarget;P=[int]$_.Port;Pr=[int]$_.Priority;W=[int]$_.Weight}} }}) | ConvertTo-Json -Compress";
        string json = await RunPs(script, ct);
        return ParseSrvJson(json);
    }

    public static List<DcRecord> ParseSrvJson(string json)
    {
        json = json.Trim();
        if (json.Length == 0) return [];
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : [doc.RootElement];
        return items.Select(e => new DcRecord(e.GetProperty("H").GetString() ?? "", e.GetProperty("P").GetInt32(), e.GetProperty("Pr").GetInt32(), e.GetProperty("W").GetInt32()))
            .OrderBy(r => r.Priority).ThenByDescending(r => r.Weight).ToList();
    }

    private static async Task<string> RunPs(string script, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var o = p.StandardOutput.ReadToEndAsync(ct); var e = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
        {
            string msg = (await e).Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "DNS query failed.";
            throw new InvalidOperationException(msg.Contains("DNS name does not exist", StringComparison.OrdinalIgnoreCase) ? "No domain controller SRV records found for that domain (DNS name does not exist)." : msg);
        }
        return await o;
    }
}
