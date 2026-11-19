using System.Text;
using RadiusTester.Core;

namespace RadiusTester.Tests;

public class CryptoTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex.Replace(" ", ""));
    private static string X(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    // ---- RFC 2865 section 7.1 example (secret "xyzzy5461", User-Name nemo, User-Password arctangent) ----
    private static readonly byte[] Secret = Encoding.ASCII.GetBytes("xyzzy5461");
    private static readonly byte[] Rfc2865Ra = H("0f403f9473978057bd83d5cb98f4227a");
    private const string Rfc2865Packet =
        "01000038" + "0f403f9473978057bd83d5cb98f4227a" + "0106" + "6e656d6f" + "0212" + "0dbe708d93d413ce3196e43f782a0aee" + "0406c0a80110" + "05060000" + "0003";

    [Fact]
    public void Pap_password_hiding_matches_RFC2865_example()
    {
        var hidden = RadiusCrypto.HidePassword(Encoding.ASCII.GetBytes("arctangent"), Secret, Rfc2865Ra);
        Assert.Equal("0dbe708d93d413ce3196e43f782a0aee", X(hidden));
        Assert.Equal("arctangent", Encoding.ASCII.GetString(RadiusCrypto.RevealPassword(hidden, Secret, Rfc2865Ra)));
    }

    [Fact]
    public void Pap_multi_block_round_trip()
    {
        var pw = Encoding.UTF8.GetBytes("a-much-longer-password-with-ünicode-and-more-than-32-bytes");
        var hidden = RadiusCrypto.HidePassword(pw, Secret, Rfc2865Ra);
        Assert.Equal(0, hidden.Length % 16);
        Assert.True(hidden.Length > 32);
        Assert.Equal(pw, RadiusCrypto.RevealPassword(hidden, Secret, Rfc2865Ra));
    }

    [Fact]
    public void Rfc2865_access_request_encodes_byte_for_byte()
    {
        var p = new RadiusPacket { Code = 1, Identifier = 0, Authenticator = Rfc2865Ra };
        p.Attributes.Add(RadiusAttribute.Text(1, "nemo"));
        p.Attributes.Add(new RadiusAttribute(2, H("0dbe708d93d413ce3196e43f782a0aee")));
        p.Attributes.Add(new RadiusAttribute(4, H("c0a80110")));
        p.Attributes.Add(RadiusAttribute.Int(5, 3));
        Assert.Equal(Rfc2865Packet, X(p.Encode()));
        var d = RadiusPacket.Decode(H(Rfc2865Packet));
        Assert.Equal(4, d.Attributes.Count);
        Assert.Equal("nemo", Encoding.ASCII.GetString(d.Find(1)!.Value));
    }

    [Fact]
    public void Response_authenticator_is_md5_of_reply_with_request_authenticator()
    {
        // Access-Accept id 0x2a, Reply-Message "ok". Expected value computed with an independent implementation (Python hashlib).
        var reply = H("022a0018" + new string('0', 32) + "12046f6b");
        Assert.Equal("f3770c1dbd9569d28903055068293411", X(RadiusCrypto.ResponseAuthenticator(reply, Rfc2865Ra, Secret)));
    }

    [Fact]
    public void Accounting_request_authenticator_matches_independent_computation()
    {
        var acct = H("0407001f" + new string('0', 32) + "280600000001" + "2c05616263");
        Assert.Equal("cbd9a5e0a145d37ef5183c2ebeeb0d03", X(RadiusCrypto.AccountingRequestAuthenticator(acct, Secret)));
    }

    [Fact]
    public void Message_authenticator_is_hmac_md5_with_zeroed_field_and_verifies()
    {
        // Status-Server packet (RFC 5997 layout: Message-Authenticator mandatory). Expected HMAC computed independently with Python.
        var pkt = H("0c2a002c" + "0f403f9473978057bd83d5cb98f4227a" + "5012" + new string('0', 32) + "04060a000001");
        Assert.Equal("ebc44672c4528b2d4d134d394f8227b2", X(RadiusCrypto.MessageAuthenticator(pkt, Secret)));
        RadiusCrypto.SetMessageAuthenticator(pkt, Secret);
        Assert.True(RadiusCrypto.VerifyMessageAuthenticator(pkt, Secret));
        pkt[^1] ^= 1;   // tamper
        Assert.False(RadiusCrypto.VerifyMessageAuthenticator(pkt, Secret));
    }

    [Fact]
    public void Chap_password_is_ident_plus_md5()
    {
        var chal = H("000102030405060708090a0b0c0d0e0f");
        var v = RadiusCrypto.ChapPassword(7, Encoding.ASCII.GetBytes("secretpw"), chal);
        Assert.Equal(17, v.Length);
        Assert.Equal(7, v[0]);
        Assert.Equal(X(System.Security.Cryptography.MD5.HashData([7, .. Encoding.ASCII.GetBytes("secretpw"), .. chal])), X(v[1..]));
    }

    // ---- RFC 1320 MD4 test suite ----
    [Theory]
    [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
    [InlineData("a", "bde52cb31de33e46245e05fbdbd6fb24")]
    [InlineData("abc", "a448017aaf21d8525fc10ae87aa6729d")]
    [InlineData("message digest", "d9130a8164549fe818874806e1c7014b")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")]
    [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")]
    public void Md4_matches_RFC1320(string input, string expected) => Assert.Equal(expected, X(Md4.Hash(Encoding.ASCII.GetBytes(input))));

    // ---- RFC 2759 section 9.2 test vectors ----
    private const string User = "User", Pass = "clientPass";
    private static readonly byte[] AuthChal = H("5B5D7C7D7B3F2F3E3C2C602132262628");
    private static readonly byte[] PeerChal = H("21402324255E262A28295F2B3A337C7E");

    [Fact] public void MsChapV2_challenge_hash_RFC2759() => Assert.Equal("d02e4386bce91226", X(MsChapV2.ChallengeHash(PeerChal, AuthChal, User)));
    [Fact] public void MsChapV2_nt_password_hash_RFC2759() => Assert.Equal("44ebba8d5312b8d611474411f56989ae", X(MsChapV2.NtPasswordHash(Pass)));
    [Fact] public void MsChapV2_hash_of_hash_RFC2759() => Assert.Equal("41c00c584bd2d91c4017a2a12fa59f3f", X(MsChapV2.HashNtPasswordHash(MsChapV2.NtPasswordHash(Pass))));
    [Fact] public void MsChapV2_nt_response_RFC2759() => Assert.Equal("82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df", X(MsChapV2.NtResponse(AuthChal, PeerChal, User, Pass)));

    [Fact]
    public void MsChapV2_authenticator_response_RFC2759()
    {
        var nt = H("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        Assert.Equal("S=407A5589115FD0D6209F510FE9C04566932CDA56", MsChapV2.AuthenticatorResponse(Pass, nt, PeerChal, AuthChal, User));
    }

    [Fact]
    public void MsChapV2_strips_domain_from_username_for_challenge_hash()
        => Assert.Equal(X(MsChapV2.ChallengeHash(PeerChal, AuthChal, "User")), X(MsChapV2.ChallengeHash(PeerChal, AuthChal, "CORP\\User")));

    [Fact]
    public void MsChapV2_response_attribute_layout_RFC2548()
    {
        var nt = MsChapV2.NtResponse(AuthChal, PeerChal, User, Pass);
        var a = MsChapV2.BuildResponseAttribute(0x2a, PeerChal, nt);
        Assert.Equal(50, a.Length);                  // Ident(1) Flags(1) Peer-Challenge(16) Reserved(8) NT-Response(24)
        Assert.Equal(0x2a, a[0]); Assert.Equal(0, a[1]);
        Assert.Equal(PeerChal, a[2..18]);
        Assert.All(a[18..26], b => Assert.Equal(0, b));
        Assert.Equal(nt, a[26..]);
    }

    [Fact]
    public void Eap_md5_response_is_md5_of_id_password_challenge()
    {
        var chal = H("00112233445566778899aabbccddeeff");
        var req = new EapPacket(EapPacket.Request, 9, EapPacket.TypeMd5, [16, .. chal, .. Encoding.ASCII.GetBytes("srv")]);
        var resp = new EapMd5Method().Respond(req, "bob", "pw")!;
        Assert.Equal(9, resp.Id); Assert.Equal(EapPacket.Response, resp.Code);
        Assert.Equal(16, resp.Data[0]);
        Assert.Equal(X(EapMd5Method.ResponseValue(9, "pw", chal)), X(resp.Data[1..]));
        var round = EapPacket.Parse(resp.Encode());
        Assert.Equal(resp.Data, round.Data);
    }
}
