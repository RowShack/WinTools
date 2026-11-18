using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RadiusTester.Core;

public enum AuthMethod { Pap, Chap, MsChapV2, EapMd5 }
public enum ExchangeKind { Access, Accounting, StatusServer }
public enum Verdict { Accept, Reject, Challenge, AccountingOk, StatusOk, NoReply, BadReply, NetworkError, Other }

public sealed class AuthRequest
{
    public string UserName { get; set; } = "";
    public string Password { get; set; } = "";
    public AuthMethod Method { get; set; } = AuthMethod.Pap;
    public List<RadiusAttribute> Extra { get; set; } = [];
}

public sealed class AcctRequest
{
    public const int Start = 1, Stop = 2, Interim = 3;
    public int StatusType { get; set; } = Start;
    public string SessionId { get; set; } = "";
    public string UserName { get; set; } = "";
    public string FramedIp { get; set; } = "";
    public string Class { get; set; } = "";               // plain text, or 0x-prefixed hex
    public string CallingStationId { get; set; } = "";
    public uint? SessionTime { get; set; }
    public uint? InputOctets { get; set; }
    public uint? OutputOctets { get; set; }
    public uint? TerminateCause { get; set; }
    public List<RadiusAttribute> Extra { get; set; } = [];
}

public sealed record MsChapState(byte Ident, byte[] PeerChallenge, byte[] AuthChallenge, byte[] NtResponse, string UserName, string Password);
public sealed record BuiltRequest(RadiusPacket Packet, byte[] Bytes, ExchangeKind Kind, AuthMethod? Method, bool HasMessageAuthenticator, MsChapState? MsChap = null);
public sealed record ChallengePrompt(string ReplyMessage, int Round, RadiusExchange Exchange);

public sealed class RadiusExchange
{
    public string Label { get; init; } = "";
    public DateTime Time { get; init; } = DateTime.Now;
    public ExchangeKind Kind { get; init; }
    public AuthMethod? Method { get; init; }
    public required RadiusPacket Request { get; init; }
    public required byte[] RequestBytes { get; init; }
    public bool RequestHadMessageAuthenticator { get; init; }
    public RadiusPacket? Reply { get; set; }
    public byte[]? ReplyBytes { get; set; }
    public TimeSpan Rtt { get; set; }
    public TimeSpan Total { get; set; }
    public int Attempts { get; set; }
    public string? Error { get; set; }
    public bool? ResponseAuthenticatorValid { get; set; }
    public bool? ReplyHasMessageAuthenticator { get; set; }
    public bool? MessageAuthenticatorValid { get; set; }
    public Verdict Verdict { get; set; }
    public List<string> Notes { get; } = [];
    public List<string> Hints { get; } = [];
    public string Endpoint { get; set; } = "";

    public bool Trusted => Reply != null && ResponseAuthenticatorValid == true && MessageAuthenticatorValid != false;
    public string ReplyMessage => Reply == null ? "" : string.Join(" ", Reply.FindAll(Attr.ReplyMessage).Select(a => Encoding.UTF8.GetString(a.Value)));
    public byte[]? State => Reply?.Find(Attr.State)?.Value;

    public string VerdictText => Verdict switch
    {
        Verdict.Accept => "ACCESS-ACCEPT",
        Verdict.Reject => "ACCESS-REJECT",
        Verdict.Challenge => "ACCESS-CHALLENGE",
        Verdict.AccountingOk => "ACCOUNTING-RESPONSE (accepted)",
        Verdict.StatusOk => "SERVER ALIVE (Status-Server answered)",
        Verdict.NoReply => "NO REPLY",
        Verdict.NetworkError => "NETWORK ERROR",
        Verdict.BadReply => $"INVALID REPLY ({(Reply == null ? "malformed" : RadiusCode.Name(Reply.Code))} failed authenticity check)",
        _ => Reply == null ? "UNKNOWN" : $"UNEXPECTED REPLY: {RadiusCode.Name(Reply.Code)}",
    };
}

public sealed class AuthSession
{
    public List<RadiusExchange> Exchanges { get; } = [];
    public RadiusExchange? Last => Exchanges.Count > 0 ? Exchanges[^1] : null;
    public bool ChallengeAbandoned { get; set; }
}

public sealed partial class RadiusClient
{
    private int _nextId = RandomNumberGenerator.GetInt32(256);
    public ServerProfile Profile { get; }
    public IRadiusTransport Transport { get; }

    public RadiusClient(ServerProfile profile, IRadiusTransport? transport = null)
    {
        Profile = profile;
        Transport = transport ?? (profile.Transport == TransportKind.RadSec
            ? new RadSecTransport(new RadSecOptions(profile.LoadClientCertificate(), profile.IgnoreServerCertErrors))
            : new UdpTransport());
    }

    private byte NextId() => (byte)(Interlocked.Increment(ref _nextId) & 0xFF);
    private bool UseMessageAuth(bool force) => force || Profile.SendMessageAuthenticator;

    // ================= request builders =================

    private void AddNasAttributes(RadiusPacket p)
    {
        bool any = false;
        if (IPAddress.TryParse(Profile.NasIp, out var ip))
        {
            p.Attributes.Add(ip.AddressFamily == AddressFamily.InterNetwork ? new RadiusAttribute(Attr.NasIpAddress, ip.GetAddressBytes()) : new RadiusAttribute(Attr.NasIpv6Address, ip.GetAddressBytes()));
            any = true;
        }
        if (!string.IsNullOrWhiteSpace(Profile.NasIdentifier)) { p.Attributes.Add(RadiusAttribute.Text(Attr.NasIdentifier, Profile.NasIdentifier)); any = true; }
        if (!any) p.Attributes.Add(RadiusAttribute.Text(Attr.NasIdentifier, "radius-tester"));
    }

    private BuiltRequest Finish(RadiusPacket p, ExchangeKind kind, AuthMethod? method, bool ma, MsChapState? ms = null)
    {
        var bytes = p.Encode();
        if (kind == ExchangeKind.Accounting)
        {
            RadiusCrypto.AccountingRequestAuthenticator(bytes, Profile.SecretBytes).CopyTo(bytes, 4);
        }
        else if (ma) RadiusCrypto.SetMessageAuthenticator(bytes, Profile.SecretBytes);
        return new BuiltRequest(RadiusPacket.Decode(bytes), bytes, kind, method, ma, ms);
    }

    public BuiltRequest BuildAccessRequest(AuthRequest r, byte[]? state = null, IEnumerable<RadiusAttribute>? eapMessages = null, bool? methodOverrideToPap = null)
    {
        var method = methodOverrideToPap == true ? AuthMethod.Pap : r.Method;
        bool eap = eapMessages != null;
        bool ma = UseMessageAuth(eap);
        var secret = Profile.SecretBytes;
        var p = new RadiusPacket { Code = RadiusCode.AccessRequest, Identifier = NextId(), Authenticator = RadiusPacket.RandomAuthenticator() };
        if (ma) p.Attributes.Add(new RadiusAttribute(Attr.MessageAuthenticator, new byte[16]));   // first, as recommended against BlastRADIUS
        p.Attributes.Add(RadiusAttribute.Text(Attr.UserName, r.UserName));
        MsChapState? ms = null;
        if (eap) { }
        else if (method == AuthMethod.Pap)
            p.Attributes.Add(new RadiusAttribute(Attr.UserPassword, RadiusCrypto.HidePassword(Encoding.UTF8.GetBytes(r.Password), secret, p.Authenticator)));
        else if (method == AuthMethod.Chap)
        {
            byte ident = (byte)RandomNumberGenerator.GetInt32(256);
            var challenge = RandomNumberGenerator.GetBytes(16);
            p.Attributes.Add(new RadiusAttribute(Attr.ChapPassword, RadiusCrypto.ChapPassword(ident, Encoding.UTF8.GetBytes(r.Password), challenge)));
            p.Attributes.Add(new RadiusAttribute(Attr.ChapChallenge, challenge));
        }
        else if (method == AuthMethod.MsChapV2)
        {
            byte ident = (byte)RandomNumberGenerator.GetInt32(256);
            var auth = RandomNumberGenerator.GetBytes(16);
            var peer = RandomNumberGenerator.GetBytes(16);
            var nt = MsChapV2.NtResponse(auth, peer, r.UserName, r.Password);
            p.Attributes.Add(RadiusAttribute.Vsa(311, 11, auth));
            p.Attributes.Add(RadiusAttribute.Vsa(311, 25, MsChapV2.BuildResponseAttribute(ident, peer, nt)));
            ms = new MsChapState(ident, peer, auth, nt, r.UserName, r.Password);
        }
        AddNasAttributes(p);
        if (state is { Length: > 0 }) p.Attributes.Add(new RadiusAttribute(Attr.State, state));
        if (eapMessages != null) p.Attributes.AddRange(eapMessages);
        p.Attributes.AddRange(r.Extra);
        return Finish(p, ExchangeKind.Access, eap ? AuthMethod.EapMd5 : method, ma, ms);
    }

    public BuiltRequest BuildAccountingRequest(AcctRequest a)
    {
        var p = new RadiusPacket { Code = RadiusCode.AccountingRequest, Identifier = NextId() };
        p.Attributes.Add(RadiusAttribute.Int(Attr.AcctStatusType, (uint)a.StatusType));
        p.Attributes.Add(RadiusAttribute.Text(Attr.AcctSessionId, a.SessionId));
        if (a.UserName.Length > 0) p.Attributes.Add(RadiusAttribute.Text(Attr.UserName, a.UserName));
        if (a.FramedIp.Length > 0)
        {
            if (!IPAddress.TryParse(a.FramedIp, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) throw new FormatException($"Framed-IP-Address '{a.FramedIp}' is not an IPv4 address.");
            p.Attributes.Add(new RadiusAttribute(Attr.FramedIpAddress, ip.GetAddressBytes()));
        }
        if (a.Class.Length > 0)
            p.Attributes.Add(new RadiusAttribute(Attr.Class, a.Class.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? RadiusDictionary.ParseHex(a.Class[2..]) : Encoding.UTF8.GetBytes(a.Class)));
        if (a.CallingStationId.Length > 0) p.Attributes.Add(RadiusAttribute.Text(Attr.CallingStationId, a.CallingStationId));
        if (a.SessionTime is uint st) p.Attributes.Add(RadiusAttribute.Int(Attr.AcctSessionTime, st));
        if (a.InputOctets is uint io) p.Attributes.Add(RadiusAttribute.Int(Attr.AcctInputOctets, io));
        if (a.OutputOctets is uint oo) p.Attributes.Add(RadiusAttribute.Int(Attr.AcctOutputOctets, oo));
        if (a.TerminateCause is uint tc) p.Attributes.Add(RadiusAttribute.Int(Attr.AcctTerminateCause, tc));
        p.Attributes.Add(RadiusAttribute.Int(Attr.AcctDelayTime, 0));
        AddNasAttributes(p);
        p.Attributes.AddRange(a.Extra);
        return Finish(p, ExchangeKind.Accounting, null, false);
    }

    public BuiltRequest BuildStatusServer()
    {
        var p = new RadiusPacket { Code = RadiusCode.StatusServer, Identifier = NextId(), Authenticator = RadiusPacket.RandomAuthenticator() };
        p.Attributes.Add(new RadiusAttribute(Attr.MessageAuthenticator, new byte[16]));   // mandatory for Status-Server (RFC 5997)
        AddNasAttributes(p);
        return Finish(p, ExchangeKind.StatusServer, null, true);
    }

    // ================= sending =================

    public async Task<RadiusExchange> SendAsync(string label, BuiltRequest b, CancellationToken ct, bool statusOnAcctPort = false)
    {
        var secret = Profile.SecretBytes;
        bool accounting = b.Kind == ExchangeKind.Accounting || (b.Kind == ExchangeKind.StatusServer && statusOnAcctPort);
        int port = Profile.Transport == TransportKind.RadSec ? Profile.RadSecPort : accounting ? Profile.AcctPort : Profile.AuthPort;
        var ex = new RadiusExchange
        {
            Label = label, Kind = b.Kind, Method = b.Method, Request = b.Packet, RequestBytes = b.Bytes,
            RequestHadMessageAuthenticator = b.HasMessageAuthenticator, Endpoint = $"{Profile.Host}:{port} ({(Profile.Transport == TransportKind.RadSec ? "RadSec/TLS" : "UDP")})",
        };
        var tr = await Transport.ExchangeAsync(Profile.Host, port, b.Bytes, Profile.Timeout, Profile.Transport == TransportKind.RadSec ? 0 : Profile.Retries, ct).ConfigureAwait(false);
        ex.Attempts = tr.Attempts; ex.Rtt = tr.Rtt; ex.Total = tr.Total; ex.Error = tr.Error;
        ex.Notes.AddRange(tr.Notes);
        if (tr.Reply == null)
        {
            ex.Verdict = tr.Error != null ? Verdict.NetworkError : Verdict.NoReply;
        }
        else
        {
            ex.ReplyBytes = tr.Reply;
            try { ex.Reply = RadiusPacket.Decode(tr.Reply); }
            catch (RadiusFormatException fe) { ex.Error = "Malformed reply: " + fe.Message; ex.Verdict = Verdict.BadReply; }
            if (ex.Reply != null)
            {
                var expected = RadiusCrypto.ResponseAuthenticator(tr.Reply, b.Packet.Authenticator, secret);
                ex.ResponseAuthenticatorValid = CryptographicOperations.FixedTimeEquals(expected, ex.Reply.Authenticator);
                ex.ReplyHasMessageAuthenticator = RadiusPacket.FindAttributeOffset(tr.Reply, Attr.MessageAuthenticator) >= 0;
                if (ex.ReplyHasMessageAuthenticator == true && (Profile.SendMessageAuthenticator || b.Kind == ExchangeKind.StatusServer))
                    ex.MessageAuthenticatorValid = SafeVerifyMa(tr.Reply, secret, b.Packet.Authenticator);
                ex.Verdict = Classify(ex);
                if (b.MsChap != null) CheckMsChap(ex, b.MsChap);
            }
        }
        RadiusHints.Analyze(ex, Profile);
        return ex;
    }

    private static bool SafeVerifyMa(byte[] reply, byte[] secret, byte[] reqAuth)
    {
        try { return RadiusCrypto.VerifyMessageAuthenticator(reply, secret, reqAuth); } catch (RadiusFormatException) { return false; }
    }

    private static Verdict Classify(RadiusExchange e)
    {
        var code = e.Reply!.Code;
        bool expected = e.Kind switch
        {
            ExchangeKind.Access => code is RadiusCode.AccessAccept or RadiusCode.AccessReject or RadiusCode.AccessChallenge,
            ExchangeKind.Accounting => code == RadiusCode.AccountingResponse,
            _ => code is RadiusCode.AccessAccept or RadiusCode.AccountingResponse,
        };
        if (!expected) return Verdict.Other;
        if (!e.Trusted) return Verdict.BadReply;
        return code switch
        {
            RadiusCode.AccessAccept => e.Kind == ExchangeKind.StatusServer ? Verdict.StatusOk : Verdict.Accept,
            RadiusCode.AccessReject => Verdict.Reject,
            RadiusCode.AccessChallenge => Verdict.Challenge,
            _ => e.Kind == ExchangeKind.StatusServer ? Verdict.StatusOk : Verdict.AccountingOk,
        };
    }

    public static byte[]? FindVendorAttribute(RadiusPacket p, uint vendor, int vendorType)
    {
        foreach (var a in p.FindAll(Attr.VendorSpecific))
            if (a.TryReadVsa(out var v, out var subs) && v == vendor)
                foreach (var s in subs) if (s.Type == vendorType) return s.Data;
        return null;
    }

    private static void CheckMsChap(RadiusExchange e, MsChapState ms)
    {
        if (e.Reply!.Code == RadiusCode.AccessAccept)
        {
            var succ = FindVendorAttribute(e.Reply, 311, 26);
            if (succ is not { Length: > 1 }) { e.Notes.Add("MS-CHAPv2: Access-Accept carried no MS-CHAP2-Success, so the server did not prove it knows the password."); return; }
            var text = Encoding.ASCII.GetString(succ, 1, succ.Length - 1);
            var expect = MsChapV2.AuthenticatorResponse(ms.Password, ms.NtResponse, ms.PeerChallenge, ms.AuthChallenge, ms.UserName);
            if (text.StartsWith(expect, StringComparison.OrdinalIgnoreCase)) e.Notes.Add("MS-CHAPv2 mutual authentication OK: the server's authenticator response (S=…) matches.");
            else e.Notes.Add("MS-CHAPv2 FAILED mutual authentication: the S=… value from the server does not match what is expected for this password.");
        }
    }

    // ================= flows =================

    /// <summary>
    /// Runs an authentication, answering Access-Challenge rounds via <paramref name="onChallenge"/> (returns the OTP/response text, or null to stop).
    /// The reply to a challenge is always sent as PAP with the State attribute echoed back, which is how OTP/MFA proxies expect it.
    /// </summary>
    public async Task<AuthSession> AuthenticateAsync(AuthRequest req, Func<ChallengePrompt, CancellationToken, Task<string?>>? onChallenge,
        Action<RadiusExchange>? onExchange, CancellationToken ct, IEnumerable<IEapMethod>? eapMethods = null)
    {
        if (req.Method == AuthMethod.EapMd5) return await AuthenticateEapAsync(req, eapMethods ?? [new EapMd5Method()], onExchange, ct).ConfigureAwait(false);
        var session = new AuthSession();
        var built = BuildAccessRequest(req);
        for (int round = 0; round < 10; round++)
        {
            var ex = await SendAsync(round == 0 ? $"Access-Request ({req.Method})" : $"Access-Request (challenge response #{round})", built, ct).ConfigureAwait(false);
            session.Exchanges.Add(ex);
            onExchange?.Invoke(ex);
            if (ex.Verdict != Verdict.Challenge) break;
            if (onChallenge == null) { session.ChallengeAbandoned = true; break; }
            var answer = await onChallenge(new ChallengePrompt(ex.ReplyMessage, round + 1, ex), ct).ConfigureAwait(false);
            if (answer == null) { session.ChallengeAbandoned = true; break; }
            var next = new AuthRequest { UserName = req.UserName, Password = answer, Method = AuthMethod.Pap, Extra = req.Extra };
            built = BuildAccessRequest(next, ex.State, methodOverrideToPap: true);
        }
        return session;
    }

    public Task<RadiusExchange> AccountingAsync(AcctRequest a, CancellationToken ct) =>
        SendAsync($"Accounting-Request ({a.StatusType switch { 1 => "Start", 2 => "Stop", 3 => "Interim-Update", _ => a.StatusType.ToString() }})", BuildAccountingRequest(a), ct);

    public Task<RadiusExchange> StatusServerAsync(CancellationToken ct, bool acctPort = false) =>
        SendAsync("Status-Server", BuildStatusServer(), ct, acctPort);
}
