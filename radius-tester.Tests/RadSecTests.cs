using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RadiusTester.Core;

namespace RadiusTester.Tests;

public class RadSecTests
{
    private static X509Certificate2 SelfSigned(string cn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=" + cn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false));
        using var c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(c.Export(X509ContentType.Pfx, "p"), "p");   // re-import so SChannel gets a persisted key
    }

    /// <summary>One-connection-at-a-time RadSec server on loopback; reports whether the client offered a certificate.</summary>
    private sealed class Server : IDisposable
    {
        private readonly TcpListener _l = new(IPAddress.Loopback, 0);
        public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
        public volatile bool ClientCertSeen;
        public Server(X509Certificate2 cert)
        {
            _l.Start();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        using var tcp = await _l.AcceptTcpClientAsync();
                        using var ssl = new SslStream(tcp.GetStream(), false);
                        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = cert, ClientCertificateRequired = true, RemoteCertificateValidationCallback = (_, c, _, _) => { if (c != null) ClientCertSeen = true; return true; } });
                        var hdr = new byte[20];
                        await ssl.ReadExactlyAsync(hdr);
                        var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(2)) - 20];
                        await ssl.ReadExactlyAsync(body);
                        var req = RadiusPacket.Decode([.. hdr, .. body]);
                        await ssl.WriteAsync(FakeRadiusServer.Reply(RadiusCode.AccessAccept, req, ServerProfile.RadSecSecret, [RadiusAttribute.Text(Attr.ReplyMessage, "radsec ok")]));
                        await ssl.FlushAsync();
                        await Task.Delay(100);
                    }
                    catch (ObjectDisposedException) { return; }
                    catch (SocketException) { return; }
                    catch { }
                }
            });
        }
        public void Dispose() => _l.Stop();
    }

    [Fact]
    public async Task Radsec_exchange_uses_fixed_radsec_secret_and_presents_client_certificate()
    {
        using var serverCert = SelfSigned("localhost");
        using var clientCert = SelfSigned("client");
        using var srv = new Server(serverCert);
        var prof = new ServerProfile { Host = "127.0.0.1", Transport = TransportKind.RadSec, RadSecPort = srv.Port, Secret = "ignored-for-radsec", IgnoreServerCertErrors = true, TimeoutSeconds = 5 };
        var client = new RadiusClient(prof, new RadSecTransport(new RadSecOptions(clientCert, true)));
        var ex = (await client.AuthenticateAsync(new AuthRequest { UserName = "u", Password = "p" }, null, null, CancellationToken.None)).Last!;
        Assert.True(ex.Verdict == Verdict.Accept, ex.Error + " | " + string.Join("; ", ex.Notes));
        Assert.Equal("radsec ok", ex.ReplyMessage);
        Assert.True(ex.ResponseAuthenticatorValid);
        Assert.True(srv.ClientCertSeen);
        Assert.Contains(ex.Notes, n => n.Contains("client certificate presented"));
    }

    [Fact]
    public async Task Radsec_untrusted_server_certificate_fails_with_explanation_unless_ignored()
    {
        using var serverCert = SelfSigned("localhost");
        using var srv = new Server(serverCert);
        var prof = new ServerProfile { Host = "127.0.0.1", Transport = TransportKind.RadSec, RadSecPort = srv.Port, TimeoutSeconds = 5 };
        var client = new RadiusClient(prof, new RadSecTransport(new RadSecOptions(null, false)));
        var ex = (await client.AuthenticateAsync(new AuthRequest { UserName = "u", Password = "p" }, null, null, CancellationToken.None)).Last!;
        Assert.Equal(Verdict.NetworkError, ex.Verdict);
        Assert.Contains("TLS handshake failed", ex.Error);
    }
}
