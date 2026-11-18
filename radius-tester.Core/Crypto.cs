using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace RadiusTester.Core;

/// <summary>RADIUS packet-level crypto (RFC 2865 / 2866 / 3579 / 5997) and the CHAP-Password of RFC 2865.</summary>
public static class RadiusCrypto
{
    /// <summary>User-Password hiding, RFC 2865 section 5.2.</summary>
    public static byte[] HidePassword(byte[] password, byte[] secret, byte[] requestAuthenticator)
    {
        if (password.Length > 128) throw new ArgumentException("Password longer than 128 bytes cannot be sent in User-Password.");
        int n = Math.Max(16, (password.Length + 15) / 16 * 16);
        var padded = new byte[n];
        password.CopyTo(padded, 0);
        var result = new byte[n];
        var prev = requestAuthenticator;
        for (int i = 0; i < n; i += 16)
        {
            var b = MD5.HashData([.. secret, .. prev]);
            for (int j = 0; j < 16; j++) result[i + j] = (byte)(padded[i + j] ^ b[j]);
            prev = result[i..(i + 16)];
        }
        return result;
    }

    public static byte[] RevealPassword(byte[] hidden, byte[] secret, byte[] requestAuthenticator)
    {
        var result = new byte[hidden.Length];
        var prev = requestAuthenticator;
        for (int i = 0; i + 16 <= hidden.Length; i += 16)
        {
            var b = MD5.HashData([.. secret, .. prev]);
            for (int j = 0; j < 16; j++) result[i + j] = (byte)(hidden[i + j] ^ b[j]);
            prev = hidden[i..(i + 16)];
        }
        int end = result.Length;
        while (end > 0 && result[end - 1] == 0) end--;
        return result[..end];
    }

    /// <summary>MD5(Code+ID+Length+RequestAuth+Attributes+Secret): the Response Authenticator of a reply.</summary>
    public static byte[] ResponseAuthenticator(byte[] reply, byte[] requestAuthenticator, byte[] secret)
    {
        int len = BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(2));
        var buf = new byte[len + secret.Length];
        reply.AsSpan(0, len).CopyTo(buf);
        requestAuthenticator.CopyTo(buf, 4);
        secret.CopyTo(buf, len);
        return MD5.HashData(buf);
    }

    /// <summary>Accounting-Request authenticator (RFC 2866 section 3): MD5 over the packet with 16 zero octets in the authenticator field.</summary>
    public static byte[] AccountingRequestAuthenticator(byte[] request, byte[] secret)
    {
        int len = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2));
        var buf = new byte[len + secret.Length];
        request.AsSpan(0, len).CopyTo(buf);
        buf.AsSpan(4, 16).Clear();
        secret.CopyTo(buf, len);
        return MD5.HashData(buf);
    }

    /// <summary>
    /// HMAC-MD5 Message-Authenticator (RFC 3579 section 3.2) over the packet with the attribute value zeroed.
    /// For a reply pass the request's authenticator as <paramref name="authenticatorOverride"/> (it replaces the header field in the hash).
    /// </summary>
    public static byte[] MessageAuthenticator(byte[] packet, byte[] secret, byte[]? authenticatorOverride = null)
    {
        int len = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2));
        var buf = packet[..len];
        int off = RadiusPacket.FindAttributeOffset(buf, Attr.MessageAuthenticator);
        if (off < 0 || buf[off + 1] != 18) throw new RadiusFormatException("Packet has no valid Message-Authenticator attribute.");
        buf.AsSpan(off + 2, 16).Clear();
        authenticatorOverride?.CopyTo(buf, 4);
        return HMACMD5.HashData(secret, buf);
    }

    /// <summary>Writes the Message-Authenticator into an encoded request (header authenticator already final).</summary>
    public static void SetMessageAuthenticator(byte[] packet, byte[] secret)
    {
        var mac = MessageAuthenticator(packet, secret);
        mac.CopyTo(packet, RadiusPacket.FindAttributeOffset(packet, Attr.MessageAuthenticator) + 2);
    }

    public static bool VerifyMessageAuthenticator(byte[] packet, byte[] secret, byte[]? authenticatorOverride = null)
    {
        int off = RadiusPacket.FindAttributeOffset(packet, Attr.MessageAuthenticator);
        if (off < 0 || packet[off + 1] != 18) return false;
        var expected = MessageAuthenticator(packet, secret, authenticatorOverride);
        return CryptographicOperations.FixedTimeEquals(expected, packet.AsSpan(off + 2, 16));
    }

    /// <summary>CHAP-Password value: ident + MD5(ident + password + challenge) (RFC 2865 section 5.3).</summary>
    public static byte[] ChapPassword(byte ident, byte[] password, byte[] challenge) =>
        [ident, .. MD5.HashData([ident, .. password, .. challenge])];
}

/// <summary>MS-CHAPv2 (RFC 2759) and the RADIUS attribute layout of RFC 2548.</summary>
public static class MsChapV2
{
    private static readonly byte[] Magic1 = Encoding.ASCII.GetBytes("Magic server to client signing constant");
    private static readonly byte[] Magic2 = Encoding.ASCII.GetBytes("Pad to make it do more than one iteration");

    public static byte[] NtPasswordHash(string password) => Md4.Hash(Encoding.Unicode.GetBytes(password));
    public static byte[] HashNtPasswordHash(byte[] ntHash) => Md4.Hash(ntHash);

    /// <summary>Strips a DOMAIN\ prefix, as RFC 2759 requires for the challenge hash.</summary>
    public static string StripDomain(string userName)
    {
        int i = userName.LastIndexOf('\\');
        return i >= 0 ? userName[(i + 1)..] : userName;
    }

    public static byte[] ChallengeHash(byte[] peerChallenge, byte[] authenticatorChallenge, string userName) =>
        SHA1.HashData([.. peerChallenge, .. authenticatorChallenge, .. Encoding.UTF8.GetBytes(StripDomain(userName))])[..8];

    public static byte[] ChallengeResponse(byte[] challenge8, byte[] ntHash)
    {
        var z = new byte[21];
        ntHash.CopyTo(z, 0);
        var result = new byte[24];
        for (int i = 0; i < 3; i++)
            DesEncryptBlock(z[(i * 7)..(i * 7 + 7)], challenge8).CopyTo(result, i * 8);
        return result;
    }

    public static byte[] NtResponse(byte[] authenticatorChallenge, byte[] peerChallenge, string userName, string password) =>
        ChallengeResponse(ChallengeHash(peerChallenge, authenticatorChallenge, userName), NtPasswordHash(password));

    /// <summary>The "S=(40 hex)" string the server must return for mutual authentication (RFC 2759 section 8.7).</summary>
    public static string AuthenticatorResponse(string password, byte[] ntResponse, byte[] peerChallenge, byte[] authenticatorChallenge, string userName)
    {
        var phh = HashNtPasswordHash(NtPasswordHash(password));
        var digest = SHA1.HashData([.. phh, .. ntResponse, .. Magic1]);
        var ch = ChallengeHash(peerChallenge, authenticatorChallenge, userName);
        var final = SHA1.HashData([.. digest, .. ch, .. Magic2]);
        return "S=" + Convert.ToHexString(final);
    }

    /// <summary>MS-CHAP2-Response (MS vendor type 25) value: Ident, Flags(0), Peer-Challenge[16], Reserved[8], NT-Response[24] (RFC 2548 section 2.3.2).</summary>
    public static byte[] BuildResponseAttribute(byte ident, byte[] peerChallenge, byte[] ntResponse)
    {
        var b = new byte[50];
        b[0] = ident; b[1] = 0;
        peerChallenge.CopyTo(b, 2);
        ntResponse.CopyTo(b, 26);
        return b;
    }

    private static byte[] DesEncryptBlock(byte[] key7, byte[] block8)
    {
        var k = new byte[8];
        k[0] = key7[0];
        k[1] = (byte)((key7[0] << 7) | (key7[1] >> 1));
        k[2] = (byte)((key7[1] << 6) | (key7[2] >> 2));
        k[3] = (byte)((key7[2] << 5) | (key7[3] >> 3));
        k[4] = (byte)((key7[3] << 4) | (key7[4] >> 4));
        k[5] = (byte)((key7[4] << 3) | (key7[5] >> 5));
        k[6] = (byte)((key7[5] << 2) | (key7[6] >> 6));
        k[7] = (byte)(key7[6] << 1);
        for (int i = 0; i < 8; i++)   // odd parity in the low bit
        {
            int v = k[i] & 0xFE, bits = System.Numerics.BitOperations.PopCount((uint)v);
            k[i] = (byte)(v | (bits % 2 == 0 ? 1 : 0));
        }
        using var des = DES.Create();
        des.Mode = CipherMode.ECB; des.Padding = PaddingMode.None;
        using var enc = des.CreateEncryptor(k, null);
        return enc.TransformFinalBlock(block8, 0, 8);
    }

    /// <summary>Human text for the "E=nnn" codes in an MS-CHAP-Error attribute.</summary>
    public static string ExplainError(int code) => code switch
    {
        646 => "Logon not permitted at this time of day (restricted logon hours).",
        647 => "The account is disabled.",
        648 => "The password has expired and must be changed.",
        649 => "The account has no dial-in / network access permission.",
        691 => "Authentication failure: wrong user name or password (or the domain rejected the credentials).",
        709 => "Error changing the password.",
        _ => $"MS-CHAP error {code}.",
    };
}

/// <summary>Minimal MD4 (RFC 1320), needed for the NT password hash; .NET has no MD4.</summary>
public static class Md4
{
    public static byte[] Hash(byte[] data)
    {
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        long bitLen = (long)data.Length * 8;
        int padLen = (int)((55 - data.Length % 64 + 64) % 64) + 1;
        var m = new byte[data.Length + padLen + 8];
        data.CopyTo(m, 0);
        m[data.Length] = 0x80;
        BinaryPrimitives.WriteInt64LittleEndian(m.AsSpan(m.Length - 8), bitLen);
        var x = new uint[16];
        int[] r2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        int[] r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        int[] s1 = [3, 7, 11, 19], s2 = [3, 5, 9, 13], s3 = [3, 9, 11, 15];
        for (int off = 0; off < m.Length; off += 64)
        {
            for (int i = 0; i < 16; i++) x[i] = BinaryPrimitives.ReadUInt32LittleEndian(m.AsSpan(off + i * 4));
            uint aa = a, bb = b, cc = c, dd = d;
            for (int i = 0; i < 16; i++)
            {
                uint t = Rol(a + ((b & c) | (~b & d)) + x[i], s1[i % 4]);
                (a, b, c, d) = (d, t, b, c);
            }
            for (int i = 0; i < 16; i++)
            {
                uint t = Rol(a + ((b & c) | (b & d) | (c & d)) + x[r2[i]] + 0x5A827999, s2[i % 4]);
                (a, b, c, d) = (d, t, b, c);
            }
            for (int i = 0; i < 16; i++)
            {
                uint t = Rol(a + (b ^ c ^ d) + x[r3[i]] + 0x6ED9EBA1, s3[i % 4]);
                (a, b, c, d) = (d, t, b, c);
            }
            a += aa; b += bb; c += cc; d += dd;
        }
        var res = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(res, a);
        BinaryPrimitives.WriteUInt32LittleEndian(res.AsSpan(4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(res.AsSpan(8), c);
        BinaryPrimitives.WriteUInt32LittleEndian(res.AsSpan(12), d);
        return res;
    }

    private static uint Rol(uint v, int s) => (v << s) | (v >> (32 - s));
}
