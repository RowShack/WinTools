using System.Text;

namespace RadiusTester.Core;

public sealed record DecodedAttribute(string Name, string Vendor, int Type, string DataType, string Value, int Length);

public static class RadiusFormatter
{
    public static List<DecodedAttribute> Decode(RadiusPacket p, RadiusDictionary dict, byte[]? requestAuthenticator = null, byte[]? secret = null)
    {
        var list = new List<DecodedAttribute>();
        foreach (var a in p.Attributes)
        {
            if (a.Type == Attr.VendorSpecific && a.TryReadVsa(out var vendor, out var subs))
            {
                foreach (var (t, data) in subs)
                {
                    var d = t >= 0 ? dict.Find(vendor, t) : null;
                    list.Add(new DecodedAttribute(d?.Name ?? (t >= 0 ? $"Vendor-{vendor}-Attr-{t}" : $"Vendor-{vendor}-Unparsed"), dict.VendorName(vendor), t,
                        d?.DataType ?? "octets", DecodeVsa(dict, d, data, vendor, t), data.Length));
                }
                continue;
            }
            var da = dict.Find(0, a.Type);
            string val;
            if (a.Type == Attr.UserPassword && requestAuthenticator != null && secret != null && p.Code == RadiusCode.AccessRequest)
                val = $"\"{Encoding.UTF8.GetString(RadiusCrypto.RevealPassword(a.Value, secret, requestAuthenticator))}\" (hidden on the wire as {Convert.ToHexString(a.Value)[..8]}…)";
            else if (a.Type == Attr.UserPassword) val = $"(hidden, {a.Value.Length} bytes)";
            else val = dict.DecodeValue(da, a.Value);
            list.Add(new DecodedAttribute(da?.Name ?? $"Attr-{a.Type}", "", a.Type, da?.DataType ?? "octets", val, a.Value.Length));
        }
        return list;
    }

    private static string DecodeVsa(RadiusDictionary dict, DictAttribute? d, byte[] data, uint vendor, int type)
    {
        if (vendor == 311 && type == 26 && data.Length > 1) return $"ident {data[0]}, " + dict.DecodeValue(d, data[1..]);
        if (vendor == 311 && type == 2 && data.Length > 1) return $"ident {data[0]}, " + dict.DecodeValue(d, data[1..]);
        return dict.DecodeValue(d, data);
    }

    public static string Hex(byte[]? b)
    {
        if (b == null) return "";
        var sb = new StringBuilder();
        for (int i = 0; i < b.Length; i += 16)
        {
            var row = b.Skip(i).Take(16).ToArray();
            sb.Append(i.ToString("x4")).Append("  ")
              .Append(string.Join(" ", row.Select(x => x.ToString("x2"))).PadRight(47)).Append("  ")
              .AppendLine(new string(row.Select(x => x is >= 32 and < 127 ? (char)x : '.').ToArray()));
        }
        return sb.ToString().TrimEnd();
    }

    public static string AttributeTable(IEnumerable<DecodedAttribute> attrs)
    {
        var sb = new StringBuilder();
        foreach (var a in attrs)
            sb.AppendLine($"  {(a.Vendor.Length > 0 ? a.Vendor + ": " : "")}{a.Name} [{a.Type}, {a.DataType}] = {a.Value}");
        return sb.ToString().TrimEnd();
    }

    /// <summary>Full text report of one exchange: verdict, checks, hints, decoded attributes and hex of both packets.</summary>
    public static string Report(RadiusExchange e, RadiusDictionary dict, ServerProfile p)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {e.Time:yyyy-MM-dd HH:mm:ss}  {e.Label}  ->  {e.Endpoint}");
        sb.AppendLine($"Verdict: {e.VerdictText}");
        if (e.Reply != null || e.Attempts > 0)
            sb.AppendLine($"Round-trip: {(e.Reply != null ? $"{e.Rtt.TotalMilliseconds:0.0} ms" : "n/a")}   Attempts: {e.Attempts}   Total: {e.Total.TotalMilliseconds:0} ms");
        if (e.Reply != null)
        {
            sb.AppendLine($"Response Authenticator: {Tri(e.ResponseAuthenticatorValid, "valid", "INVALID (wrong secret?)")}");
            sb.AppendLine($"Message-Authenticator (reply): {(e.ReplyHasMessageAuthenticator == true ? Tri(e.MessageAuthenticatorValid, "valid", "INVALID") : "not present")}");
        }
        if (e.Error != null) sb.AppendLine("Error: " + e.Error);
        foreach (var n in e.Notes) sb.AppendLine("Note: " + n);
        foreach (var h in e.Hints) sb.AppendLine("Hint: " + h);
        sb.AppendLine().AppendLine($"Request: {RadiusCode.Name(e.Request.Code)} id={e.Request.Identifier}, {e.RequestBytes.Length} bytes");
        sb.AppendLine(AttributeTable(Decode(e.Request, dict, e.Request.Authenticator, p.SecretBytes).Select(Mask)));
        sb.AppendLine(Hex(e.RequestBytes));
        if (e.Reply != null && e.ReplyBytes != null)
        {
            sb.AppendLine().AppendLine($"Reply: {RadiusCode.Name(e.Reply.Code)} id={e.Reply.Identifier}, {e.ReplyBytes.Length} bytes");
            sb.AppendLine(AttributeTable(Decode(e.Reply, dict)));
            sb.AppendLine(Hex(e.ReplyBytes));
        }
        return sb.ToString().TrimEnd();
    }

    /// <summary>The report deliberately shows the recovered password only inside the app; exported logs mask it.</summary>
    private static DecodedAttribute Mask(DecodedAttribute a) =>
        a.Type == Attr.UserPassword && a.Vendor.Length == 0 ? a with { Value = "(hidden)" } : a;

    private static string Tri(bool? v, string ok, string bad) => v switch { true => ok, false => bad, _ => "not checked" };
}

/// <summary>Chronological session log, exportable as TXT.</summary>
public sealed class SessionLog
{
    private readonly List<string> _entries = [];
    public int Count => _entries.Count;
    public void Add(string text) => _entries.Add(text);
    public void Add(RadiusExchange e, RadiusDictionary dict, ServerProfile p) => _entries.Add(RadiusFormatter.Report(e, dict, p));
    public void Clear() => _entries.Clear();
    public string ToText() => $"radius-tester session log, exported {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n(Shared secrets and passwords are never written to this log.)\r\n\r\n"
        + string.Join("\r\n\r\n", _entries);
}
