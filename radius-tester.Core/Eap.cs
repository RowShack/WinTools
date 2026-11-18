using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace RadiusTester.Core;

/// <summary>An EAP packet (RFC 3748): Code, Identifier, Length, then Type + data for Request/Response.</summary>
public sealed record EapPacket(byte Code, byte Id, byte Type, byte[] Data)
{
    public const byte Request = 1, Response = 2, Success = 3, Failure = 4;
    public const byte TypeIdentity = 1, TypeNak = 3, TypeMd5 = 4;

    public byte[] Encode()
    {
        bool hasType = Code is Request or Response;
        int len = 4 + (hasType ? 1 + Data.Length : 0);
        var b = new byte[len];
        b[0] = Code; b[1] = Id;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)len);
        if (hasType) { b[4] = Type; Data.CopyTo(b, 5); }
        return b;
    }

    public static EapPacket Parse(byte[] b)
    {
        if (b.Length < 4) throw new RadiusFormatException("EAP packet shorter than 4 bytes.");
        int len = Math.Min(b.Length, BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(2)));
        if (len < 4) throw new RadiusFormatException("EAP length field is invalid.");
        bool hasType = b[0] is Request or Response && len >= 5;
        return new EapPacket(b[0], b[1], hasType ? b[4] : (byte)0, hasType ? b[5..len] : []);
    }

    public static string TypeName(int t) => t switch
    {
        1 => "Identity", 3 => "NAK", 4 => "MD5-Challenge", 6 => "GTC", 13 => "EAP-TLS", 17 => "LEAP", 18 => "EAP-SIM", 21 => "EAP-TTLS",
        23 => "EAP-AKA", 25 => "PEAP", 26 => "EAP-MSCHAPv2", 43 => "EAP-FAST", 52 => "EAP-PWD", _ => $"type {t}",
    };
}

/// <summary>
/// Extension point for EAP methods. A method answers an EAP-Request of its own type; the client handles
/// Identity, NAK and the RADIUS carriage (EAP-Message fragments, State, Message-Authenticator).
/// PEAP / EAP-TLS / EAP-TTLS are deliberately not implemented; add them by implementing this interface.
/// </summary>
public interface IEapMethod
{
    byte Type { get; }
    /// <summary>Builds the EAP-Response for the given EAP-Request, or null if it cannot be answered.</summary>
    EapPacket? Respond(EapPacket request, string identity, string password);
}

public sealed class EapMd5Method : IEapMethod
{
    public byte Type => EapPacket.TypeMd5;

    public EapPacket? Respond(EapPacket request, string identity, string password)
    {
        if (request.Data.Length < 1 || request.Data[0] == 0 || request.Data.Length < 1 + request.Data[0]) return null;
        var challenge = request.Data[1..(1 + request.Data[0])];
        var hash = MD5.HashData([request.Id, .. Encoding.UTF8.GetBytes(password), .. challenge]);
        return new EapPacket(EapPacket.Response, request.Id, Type, [16, .. hash]);
    }

    /// <summary>Builds the expected response value, exposed for tests (RFC 3748 section 5.4).</summary>
    public static byte[] ResponseValue(byte id, string password, byte[] challenge) =>
        MD5.HashData([id, .. Encoding.UTF8.GetBytes(password), .. challenge]);
}

public sealed partial class RadiusClient
{
    private static List<RadiusAttribute> Fragment(byte[] eap)
    {
        var list = new List<RadiusAttribute>();
        for (int i = 0; i < eap.Length; i += 253) list.Add(new RadiusAttribute(Attr.EapMessage, eap[i..Math.Min(eap.Length, i + 253)]));
        return list;
    }

    public static byte[]? ReadEapMessage(RadiusPacket p)
    {
        var parts = p.FindAll(Attr.EapMessage).ToList();
        return parts.Count == 0 ? null : parts.SelectMany(a => a.Value).ToArray();
    }

    private async Task<AuthSession> AuthenticateEapAsync(AuthRequest req, IEnumerable<IEapMethod> methods, Action<RadiusExchange>? onExchange, CancellationToken ct)
    {
        var session = new AuthSession();
        var table = methods.ToDictionary(m => m.Type);
        byte[]? state = null;
        var eap = new EapPacket(EapPacket.Response, 1, EapPacket.TypeIdentity, Encoding.UTF8.GetBytes(req.UserName));
        bool nakSent = false;
        for (int round = 0; round < 12; round++)
        {
            var built = BuildAccessRequest(req, state, Fragment(eap.Encode()));
            var ex = await SendAsync(round == 0 ? "Access-Request (EAP-Response/Identity)" : $"Access-Request (EAP-Response/{EapPacket.TypeName(eap.Type)})", built, ct).ConfigureAwait(false);
            session.Exchanges.Add(ex);
            onExchange?.Invoke(ex);
            if (ex.Reply == null) break;
            var raw = ReadEapMessage(ex.Reply);
            EapPacket? inner = null;
            try { if (raw != null) inner = EapPacket.Parse(raw); } catch (RadiusFormatException fe) { ex.Notes.Add("EAP: " + fe.Message); }
            if (inner != null) ex.Notes.Add($"EAP in reply: code {inner.Code}" + (inner.Code is EapPacket.Request or EapPacket.Response ? $", {EapPacket.TypeName(inner.Type)}" : inner.Code == EapPacket.Success ? " (Success)" : inner.Code == EapPacket.Failure ? " (Failure)" : ""));
            if (ex.Verdict != Verdict.Challenge || inner is not { Code: EapPacket.Request }) break;
            state = ex.State;
            if (inner.Type == EapPacket.TypeIdentity) { eap = new EapPacket(EapPacket.Response, inner.Id, EapPacket.TypeIdentity, Encoding.UTF8.GetBytes(req.UserName)); continue; }
            if (table.TryGetValue(inner.Type, out var m))
            {
                var resp = m.Respond(inner, req.UserName, req.Password);
                if (resp == null) { ex.Notes.Add("EAP: the server's request could not be parsed by the " + EapPacket.TypeName(inner.Type) + " handler."); break; }
                eap = resp;
                continue;
            }
            if (nakSent) { ex.Notes.Add($"EAP: the server insists on {EapPacket.TypeName(inner.Type)}, which this tool does not implement."); break; }
            nakSent = true;
            ex.Notes.Add($"EAP: the server proposed {EapPacket.TypeName(inner.Type)}; replying with NAK and asking for {string.Join("/", table.Keys.Select(k => EapPacket.TypeName(k)))}.");
            eap = new EapPacket(EapPacket.Response, inner.Id, EapPacket.TypeNak, [.. table.Keys]);
        }
        return session;
    }
}
