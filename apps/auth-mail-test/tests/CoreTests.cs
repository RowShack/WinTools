using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AuthMailTest.Core;

namespace AuthMailTest.Tests;

public class LdapErrorTests
{
    [Theory]
    [InlineData("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v4563", "invalid credentials")]
    [InlineData("... data 525, v1db1", "not found")]
    [InlineData("... data 530, v1db1", "logon-hours")]
    [InlineData("... data 531, v1db1", "workstation")]
    [InlineData("... data 532, v1db1", "expired")]
    [InlineData("... data 533, v1db1", "disabled")]
    [InlineData("... data 701, v1db1", "Account expired")]
    [InlineData("... data 773, v1db1", "reset")]
    [InlineData("... data 775, v1db1", "locked")]
    [InlineData("... DATA 52E, v1db1", "invalid credentials")]
    public void DecodesAdSubCodes(string message, string expectedFragment) =>
        Assert.Contains(expectedFragment, LdapErrors.DecodeAdSubCode(message)!, StringComparison.OrdinalIgnoreCase);

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("nothing useful")] [InlineData("data 999, v1")] [InlineData("metadata 52e")]
    public void IgnoresMessagesWithoutKnownSubCode(string? message) => Assert.Null(LdapErrors.DecodeAdSubCode(message));

    [Fact]
    public void CombinesSubCodeAndResultCode()
    {
        var s = LdapErrors.Explain(49, "... data 775, v1");
        Assert.Contains("locked out", s);
        Assert.Contains("Invalid credentials", s);
    }

    [Theory]
    [InlineData(49)] [InlineData(53)] [InlineData(81)] [InlineData(32)] [InlineData(8)] [InlineData(50)] [InlineData(34)]
    public void CommonResultCodesHaveExplanations(int code) => Assert.DoesNotContain("LDAP result code", LdapErrors.ExplainResultCode(code));

    [Fact] public void UnknownCodeStillReturnsSomething() => Assert.Contains("1234", LdapErrors.ExplainResultCode(1234));
}

public class DcLocatorTests
{
    [Fact]
    public void ParsesAndOrdersSrvRecords()
    {
        var r = DcLocator.ParseSrvJson("""[{"H":"dc2.corp.test","P":389,"Pr":0,"W":50},{"H":"dc1.corp.test","P":389,"Pr":0,"W":100},{"H":"dc3.corp.test","P":389,"Pr":10,"W":100}]""");
        Assert.Equal(["dc1.corp.test", "dc2.corp.test", "dc3.corp.test"], r.Select(x => x.Host).ToArray());
    }

    [Fact] public void ParsesSingleObject() => Assert.Single(DcLocator.ParseSrvJson("""{"H":"dc1.x","P":389,"Pr":0,"W":100}"""));
    [Fact] public void EmptyJsonGivesNoRecords() => Assert.Empty(DcLocator.ParseSrvJson("  "));

    [Theory]
    [InlineData("")] [InlineData("a'; Remove-Item x")] [InlineData("bad name")]
    public async Task RejectsUnsafeDomainNames(string d) => await Assert.ThrowsAsync<ArgumentException>(() => DcLocator.FindAsync(d));
}

public class ProfileTests
{
    [Fact]
    public void PasswordIsEncryptedAtRest_AndRoundTrips()
    {
        string path = Path.Combine(Path.GetTempPath(), "wintools-test-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var p = new SavedProfile { Name = "dc1", Kind = "ldap", Fields = { ["host"] = "dc1.corp" }, ProtectedPassword = ProfileStore.Protect("S3cret!Pass") };
            ProfileStore.Save([p], path);
            string raw = File.ReadAllText(path);
            Assert.DoesNotContain("S3cret", raw);
            var loaded = ProfileStore.Load(path);
            Assert.Equal("dc1.corp", loaded[0].Fields["host"]);
            Assert.Equal("S3cret!Pass", ProfileStore.Unprotect(loaded[0].ProtectedPassword));
        }
        finally { File.Delete(path); }
    }

    [Fact] public void CorruptBlobReturnsNullInsteadOfThrowing() => Assert.Null(ProfileStore.Unprotect(Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })));
    [Fact] public void MissingFileLoadsEmpty() => Assert.Empty(ProfileStore.Load(Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid() + ".json")));
}

public class HintTests
{
    [Theory]
    [InlineData(530, "Authentication required")]
    [InlineData(535, "Authentication failed")]
    [InlineData(554, "blocked")]
    [InlineData(421, "unavailable")]
    [InlineData(550, "rejected")]
    public void KnownCodes(int code, string fragment) => Assert.Contains(fragment, SmtpHints.ForReply(code, "x"), StringComparison.OrdinalIgnoreCase);

    [Fact] public void RelayDeniedIsRecognisedFromText() => Assert.Contains("Relay denied", SmtpHints.ForReply(550, "5.7.1 Relaying denied"));
    [Fact] public void M365SmtpAuthDisabled() => Assert.Contains("Microsoft 365", SmtpHints.ForReply(535, "5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled; basic authentication disabled"));
    [Fact] public void Port25TimeoutMentionsIsp() => Assert.Contains("port 25", SmtpHints.ForException(new TimeoutException(), 25), StringComparison.OrdinalIgnoreCase);
    [Fact] public void RefusedConnection() => Assert.Contains("refused", SmtpHints.ForException(new SocketException((int)SocketError.ConnectionRefused), 587), StringComparison.OrdinalIgnoreCase);
}

/// <summary>A tiny scripted SMTP server so the conversation, redaction and relay logic can be tested for real.</summary>
internal sealed class FakeSmtpServer : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    private readonly X509Certificate2? _cert;
    private readonly bool _sslOnConnect, _offerStartTls, _relayOk;
    private readonly string _authUser, _authPass;
    public List<string> Received { get; } = [];
    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;

    public FakeSmtpServer(bool sslOnConnect = false, bool offerStartTls = false, bool relayOk = true, string authUser = "bob", string authPass = "pw")
    {
        _sslOnConnect = sslOnConnect; _offerStartTls = offerStartTls; _relayOk = relayOk; _authUser = authUser; _authPass = authPass;
        if (sslOnConnect || offerStartTls) _cert = MakeCert();
        _l.Start();
        _ = Task.Run(Accept);
    }

    public static X509Certificate2 MakeCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    private async Task Accept()
    {
        try { while (true) { var c = await _l.AcceptTcpClientAsync(); _ = Task.Run(() => Serve(c)); } } catch { }
    }

    private async Task Serve(TcpClient c)
    {
        try
        {
            using var _ = c;
            Stream s = c.GetStream();
            if (_sslOnConnect) { var ssl = new SslStream(s); await ssl.AuthenticateAsServerAsync(_cert!); s = ssl; }
            var r = new StreamReader(s, Encoding.ASCII, false, 1024, true);
            async Task W(string line) { await s.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n")); await s.FlushAsync(); }
            await W("220 fake.test ESMTP ready");
            bool tls = _sslOnConnect;
            while (await r.ReadLineAsync() is { } line)
            {
                Received.Add(line);
                string u = line.ToUpperInvariant();
                if (u.StartsWith("EHLO"))
                {
                    var caps = new List<string> { "fake.test greets you", "SIZE 1000000" };
                    if (_offerStartTls && !tls) caps.Add("STARTTLS");
                    if (tls || !_offerStartTls) caps.Add("AUTH PLAIN LOGIN");
                    for (int i = 0; i < caps.Count; i++) await W($"250{(i == caps.Count - 1 ? " " : "-")}{caps[i]}");
                }
                else if (u == "STARTTLS")
                {
                    await W("220 go ahead");
                    var ssl = new SslStream(s); await ssl.AuthenticateAsServerAsync(_cert!); s = ssl; r = new StreamReader(s, Encoding.ASCII, false, 1024, true); tls = true;
                }
                else if (u.StartsWith("AUTH PLAIN"))
                {
                    var parts = Encoding.UTF8.GetString(Convert.FromBase64String(line[11..])).Split('\0');
                    await W(parts[1] == _authUser && parts[2] == _authPass ? "235 2.7.0 Authentication successful" : "535 5.7.8 Authentication credentials invalid");
                }
                else if (u.StartsWith("MAIL FROM")) await W("250 sender ok");
                else if (u.StartsWith("RCPT TO")) await W(_relayOk ? "250 recipient ok" : "550 5.7.1 Relaying denied");
                else if (u == "RSET") await W("250 reset");
                else if (u == "QUIT") { await W("221 bye"); break; }
                else if (u.StartsWith("DATA")) { await W("354 go"); }
                else await W("502 not implemented");
            }
        }
        catch { }
    }

    public void Dispose() => _l.Stop();
}

public class SmtpTesterTests
{
    private static SmtpRequest Req(FakeSmtpServer s, SmtpSecurity sec = SmtpSecurity.None) => new()
    { Host = "127.0.0.1", Port = s.Port, Security = sec, TimeoutSeconds = 5, IgnoreCertErrors = true, EhloName = "tester" };

    [Fact]
    public async Task PlainConversation_ShowsBannerEhloAndCaps()
    {
        using var s = new FakeSmtpServer();
        var r = await SmtpTester.RunAsync(Req(s), null, default);
        Assert.True(r.Success, string.Join("\n", r.Steps));
        Assert.Contains("S: 220 fake.test ESMTP ready", r.Transcript);
        Assert.Contains("C: EHLO tester", r.Transcript);
        Assert.Contains("SIZE", r.Capabilities);
        Assert.Contains("PLAIN", r.AuthMechanisms);
        Assert.Contains("LOGIN", r.AuthMechanisms);
    }

    [Fact]
    public async Task AuthSucceeds_AndPasswordNeverAppearsInTranscript()
    {
        using var s = new FakeSmtpServer();
        var req = Req(s); req.User = "bob"; req.Password = "pw";
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.True(r.Success, string.Join("\n", r.Steps));
        string token = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0bob\0pw"));
        Assert.DoesNotContain(token, r.TranscriptText);
        Assert.Contains("C: AUTH PLAIN [credentials hidden]", r.Transcript);
        Assert.Contains("S: 235 2.7.0 Authentication successful", r.Transcript);
        // but the server really did receive the credentials
        Assert.Contains(s.Received, l => l.Contains(token));
    }

    [Fact]
    public async Task WrongPassword_FailsWith535Hint()
    {
        using var s = new FakeSmtpServer();
        var req = Req(s); req.User = "bob"; req.Password = "wrong";
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.False(r.Success);
        Assert.Contains(r.Hints, h => h.StartsWith("535"));
    }

    [Fact]
    public async Task RelayTest_Accepted_SendsRsetAndNeverData()
    {
        using var s = new FakeSmtpServer(relayOk: true);
        var req = Req(s); req.MailFrom = "a@x.test"; req.RcptTo = "b@y.test";
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.Equal(RelayOutcome.Accepted, r.Relay);
        Assert.Contains(s.Received, l => l == "RSET");
        Assert.DoesNotContain(s.Received, l => l.StartsWith("DATA", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RelayTest_Denied()
    {
        using var s = new FakeSmtpServer(relayOk: false);
        var req = Req(s); req.MailFrom = "a@x.test"; req.RcptTo = "b@y.test";
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.Equal(RelayOutcome.Rejected, r.Relay);
        Assert.Contains(r.Hints, h => h.Contains("Relay denied"));
    }

    [Fact]
    public async Task StartTls_UpgradesAndReportsCertificate()
    {
        using var s = new FakeSmtpServer(offerStartTls: true);
        var req = Req(s, SmtpSecurity.StartTls); req.User = "bob"; req.Password = "pw";
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.True(r.Success, string.Join("\n", r.Steps));
        Assert.NotNull(r.Cert);
        Assert.Contains("CN=localhost", r.Cert!.Subject);
        Assert.False(r.Cert.Trusted);                       // self-signed
        Assert.Contains(r.Cert.Problems, p => p.Contains("trust", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("C: STARTTLS", r.Transcript);
    }

    [Fact]
    public async Task UntrustedCertificate_StopsTheTestUnlessIgnored()
    {
        using var s = new FakeSmtpServer(offerStartTls: true);
        var req = Req(s, SmtpSecurity.StartTls); req.IgnoreCertErrors = false;
        var r = await SmtpTester.RunAsync(req, null, default);
        Assert.False(r.Success);
        Assert.Contains(r.Hints, h => h.Contains("certificate"));
    }

    [Fact]
    public async Task SslOnConnect_Works()
    {
        using var s = new FakeSmtpServer(sslOnConnect: true);
        var r = await SmtpTester.RunAsync(Req(s, SmtpSecurity.SslOnConnect), null, default);
        Assert.True(r.Success, string.Join("\n", r.Steps));
        Assert.NotNull(r.Cert);
    }

    [Fact]
    public async Task StartTlsRequestedButNotOffered_ExplainsIt()
    {
        using var s = new FakeSmtpServer(offerStartTls: false);
        var r = await SmtpTester.RunAsync(Req(s, SmtpSecurity.StartTls), null, default);
        Assert.False(r.Success);
        Assert.Contains(r.Hints, h => h.Contains("STARTTLS"));
    }

    [Fact]
    public async Task WrongSecurityModeForPlainPort_FailsWithHint()
    {
        using var s = new FakeSmtpServer();    // plain server, but we ask for SSL on connect
        var r = await SmtpTester.RunAsync(Req(s, SmtpSecurity.SslOnConnect), null, default);
        Assert.False(r.Success);
        Assert.Contains(r.Hints, h => h.Length > 0);
    }

    [Fact]
    public async Task ClosedPort_IsExplained()
    {
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int port = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop();
        var r = await SmtpTester.RunAsync(new SmtpRequest { Host = "127.0.0.1", Port = port, TimeoutSeconds = 5 }, null, default);
        Assert.False(r.Success);
        Assert.Contains(r.Hints, h => h.Contains("refused", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task HeaderInjectionInAddresses_IsStripped()
    {
        using var s = new FakeSmtpServer();
        var req = Req(s); req.MailFrom = "a@x.test\r\nDATA"; req.RcptTo = "b@y.test";
        await SmtpTester.RunAsync(req, null, default);
        Assert.DoesNotContain(s.Received, l => l.Equals("DATA", StringComparison.OrdinalIgnoreCase));
    }
}
