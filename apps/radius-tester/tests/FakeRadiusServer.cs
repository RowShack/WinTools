using System.Net;
using System.Net.Sockets;
using System.Text;
using RadiusTester.Core;

namespace RadiusTester.Tests;

/// <summary>Tiny in-process UDP RADIUS server. The handler returns the encoded reply, or null to stay silent.</summary>
public sealed class FakeRadiusServer : IDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _cts = new();
    public string Secret { get; }
    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
    public List<(RadiusPacket Packet, byte[] Bytes)> Received { get; } = [];
    public Func<RadiusPacket, byte[], int, byte[]?> Handler { get; set; } = (_, _, _) => null;

    public FakeRadiusServer(string secret)
    {
        Secret = secret;
        _ = Task.Run(Loop);
    }

    private async Task Loop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var r = await _udp.ReceiveAsync(_cts.Token);
                RadiusPacket p;
                try { p = RadiusPacket.Decode(r.Buffer); } catch { continue; }
                int n;
                lock (Received) { Received.Add((p, r.Buffer)); n = Received.Count; }
                var reply = Handler(p, r.Buffer, n);
                if (reply != null) await _udp.SendAsync(reply, r.RemoteEndPoint, _cts.Token);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { }
        }
    }

    /// <summary>Builds a reply signed with <paramref name="secret"/>; optionally with a Message-Authenticator (placed first).</summary>
    public static byte[] Reply(byte code, RadiusPacket req, string secret, IEnumerable<RadiusAttribute>? attrs = null, bool messageAuth = true)
    {
        var key = Encoding.UTF8.GetBytes(secret);
        var p = new RadiusPacket { Code = code, Identifier = req.Identifier, Authenticator = req.Authenticator };
        if (messageAuth) p.Attributes.Add(new RadiusAttribute(Attr.MessageAuthenticator, new byte[16]));
        if (attrs != null) p.Attributes.AddRange(attrs);
        var bytes = p.Encode();
        if (messageAuth)
            RadiusCrypto.MessageAuthenticator(bytes, key, req.Authenticator).CopyTo(bytes, RadiusPacket.FindAttributeOffset(bytes, Attr.MessageAuthenticator) + 2);
        RadiusCrypto.ResponseAuthenticator(bytes, req.Authenticator, key).CopyTo(bytes, 4);
        return bytes;
    }

    public byte[] Reply(byte code, RadiusPacket req, IEnumerable<RadiusAttribute>? attrs = null, bool messageAuth = true) => Reply(code, req, Secret, attrs, messageAuth);

    public string? UserPassword(RadiusPacket req) =>
        req.Find(Attr.UserPassword) is { } a ? Encoding.UTF8.GetString(RadiusCrypto.RevealPassword(a.Value, Encoding.UTF8.GetBytes(Secret), req.Authenticator)) : null;

    public void Dispose() { _cts.Cancel(); _udp.Dispose(); }
}
