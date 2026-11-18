using System.Text;
using RadiusTester.Core;

namespace RadiusTester.Tests;

public class DictionaryAndStoreTests
{
    private static readonly RadiusDictionary Dict = RadiusDictionary.LoadBuiltIn();

    [Fact]
    public void Built_in_dictionaries_cover_standard_and_three_vendors()
    {
        Assert.Equal(1, Dict.Find("User-Name")!.Type);
        Assert.Equal(80, Dict.Find(0, 80)!.Type);
        Assert.Equal(25u, (uint)Dict.Find("MS-CHAP2-Response")!.Type);
        Assert.Equal(311u, Dict.Find("MS-CHAP2-Response")!.Vendor);
        Assert.Equal(12356u, Dict.Find("Fortinet-Group-Name")!.Vendor);
        Assert.Equal(9u, Dict.Find("Cisco-AVPair")!.Vendor);
        Assert.Equal("Fortinet", Dict.VendorName(12356));
        Assert.Empty(Dict.LoadWarnings);
    }

    [Fact]
    public void Values_encode_by_name_number_ip_and_date()
    {
        Assert.Equal([0, 0, 0, 1], Dict.Encode("Acct-Status-Type", "Start").Value);
        Assert.Equal([0, 0, 0, 3], Dict.Encode("Acct-Status-Type", "3").Value);
        Assert.Equal([10, 0, 0, 9], Dict.Encode("Framed-IP-Address", "10.0.0.9").Value);
        Assert.Equal([0xDE, 0xAD], Dict.Encode("Class", "0xdead").Value);
        Assert.Equal("hello", Encoding.UTF8.GetString(Dict.Encode("Class", "hello").Value));
        Assert.Equal([0x65, 0x8D, 0x0A, 0x80], Dict.Encode("Event-Timestamp", "1703742080").Value);
        var v = Dict.Encode("Cisco-AVPair", "shell:priv-lvl=15");
        Assert.Equal(26, v.Type);
        Assert.True(v.TryReadVsa(out var vendor, out var subs));
        Assert.Equal(9u, vendor); Assert.Equal(1, subs[0].Type);
        Assert.Equal("shell:priv-lvl=15", Encoding.UTF8.GetString(subs[0].Data));
        var generic = Dict.Encode("Vendor-4874-Attr-3", "0x0102");
        Assert.True(generic.TryReadVsa(out var gv, out var gs)); Assert.Equal(4874u, gv); Assert.Equal([1, 2], gs[0].Data);
    }

    [Theory]
    [InlineData("Framed-IP-Address", "not-an-ip")]
    [InlineData("Acct-Status-Type", "Bogus")]
    [InlineData("Nonexistent-Attr", "x")]
    [InlineData("NAS-Port", "-1")]
    public void Bad_values_give_readable_errors(string name, string value) => Assert.Throws<FormatException>(() => Dict.Encode(name, value));

    [Fact]
    public void Decoding_names_values_and_vendor_attributes()
    {
        var p = new RadiusPacket { Code = 2 };
        p.Attributes.Add(RadiusAttribute.Int(Attr.ServiceType, 2));
        p.Attributes.Add(Dict.Encode("Fortinet-Group-Name", "admins"));
        p.Attributes.Add(RadiusAttribute.Vsa(99999, 7, [1, 2]));
        p.Attributes.Add(new RadiusAttribute(200, [0xFF]));
        var d = RadiusFormatter.Decode(p, Dict);
        Assert.Equal("Framed-User (2)", d[0].Value);
        Assert.Equal("Fortinet-Group-Name", d[1].Name); Assert.Equal("Fortinet", d[1].Vendor); Assert.Equal("admins", d[1].Value);
        Assert.Equal("Vendor-99999-Attr-7", d[2].Name); Assert.Equal("0x0102", d[2].Value);
        Assert.Equal("Attr-200", d[3].Name);
    }

    [Fact]
    public void Freeradius_format_file_loads_vendor_blocks_values_and_includes()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        File.WriteAllText(Path.Combine(dir, "dictionary.inc"), "ATTRIBUTE Included-Attr 3000 string\n");
        var main = Path.Combine(dir, "dictionary.acme");
        File.WriteAllText(main, """
            # test dictionary
            $INCLUDE dictionary.inc
            VENDOR Acme 55555
            BEGIN-VENDOR Acme
            ATTRIBUTE Acme-Level 1 integer
            ATTRIBUTE Acme-Tag   2 string  has_tag
            ATTRIBUTE Acme-Nested 3.1 string
            VALUE Acme-Level Low 1
            VALUE Acme-Level High 2
            END-VENDOR Acme
            ATTRIBUTE After-Vendor 3001 ipaddr
            """);
        var d = RadiusDictionary.LoadBuiltIn();
        Assert.Equal(4, d.LoadFile(main));   // Included-Attr, Acme-Level, Acme-Tag, After-Vendor (TLV skipped)
        Assert.Equal(55555u, d.Find("Acme-Level")!.Vendor);
        Assert.Equal(0u, d.Find("After-Vendor")!.Vendor);
        Assert.Equal([0, 0, 0, 2], d.Encode("Acme-Level", "High").Value[^4..]);
        Assert.Equal(3000, d.Find("Included-Attr")!.Type);
        Assert.Null(d.Find("Acme-Nested"));
    }

    [Fact]
    public void Profile_round_trips_with_dpapi_protected_secrets_and_no_plaintext_on_disk()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory().FullName, "p.json");
        var p = new ServerProfile { Host = "radius.example", AuthPort = 1645, Secret = "S3cr3t-Value!", Retries = 4, NasIdentifier = "fw1", ClientCertPfxPassword = "pfx-pass-XYZ" };
        ProfileStore.Save([SavedProfile.From("lab", p, "alice", "MsChapV2", "UserPw-123")], path);
        var json = File.ReadAllText(path);
        Assert.DoesNotContain("S3cr3t-Value!", json);
        Assert.DoesNotContain("pfx-pass-XYZ", json);
        Assert.DoesNotContain("UserPw-123", json);
        var loaded = ProfileStore.Load(path).Single();
        var (back, ok) = loaded.ToProfile();
        Assert.True(ok);
        Assert.Equal("S3cr3t-Value!", back.Secret); Assert.Equal("pfx-pass-XYZ", back.ClientCertPfxPassword);
        Assert.Equal(1645, back.AuthPort); Assert.Equal(4, back.Retries);
        Assert.Equal("UserPw-123", ProfileStore.Unprotect(loaded.ProtectedUserPassword));
        Assert.Equal("MsChapV2", loaded.Method);
    }

    [Fact]
    public void Profile_with_undecryptable_secret_is_reported()
    {
        var s = new SavedProfile { Name = "x", ProtectedSecret = Convert.ToBase64String(new byte[40]) };
        Assert.False(s.ToProfile().SecretsOk);
    }

    [Fact]
    public void Session_log_masks_passwords_and_never_contains_secret()
    {
        var prof = new ServerProfile { Host = "h", Secret = "TOPSECRET-1" };
        var c = new RadiusClient(prof, new NullTransport());
        var b = c.BuildAccessRequest(new AuthRequest { UserName = "bob", Password = "hunter2-pass" });
        var ex = new RadiusExchange { Request = b.Packet, RequestBytes = b.Bytes, Verdict = Verdict.NoReply, Endpoint = "h:1812" };
        var log = new SessionLog();
        log.Add(ex, Dict, prof);
        var txt = log.ToText();
        Assert.DoesNotContain("hunter2-pass", txt);
        Assert.DoesNotContain("TOPSECRET-1", txt);
        Assert.Contains("User-Name", txt); Assert.Contains("Access-Request", txt); Assert.Contains("0000  ", txt);
    }

    private sealed class NullTransport : IRadiusTransport
    {
        public Task<TransportResult> ExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, int retries, CancellationToken ct) =>
            Task.FromResult(new TransportResult(null, 1, default, default, null, []));
    }
}
