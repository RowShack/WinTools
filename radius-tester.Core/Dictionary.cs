using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace RadiusTester.Core;

public sealed class DictAttribute(string name, uint vendor, int type, string dataType)
{
    public string Name { get; } = name;
    public uint Vendor { get; } = vendor;
    public int Type { get; } = type;
    public string DataType { get; } = dataType.ToLowerInvariant();
    public Dictionary<long, string> ValueNames { get; } = [];
    public Dictionary<string, long> ValueNumbers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public override string ToString() => Name;
}

/// <summary>
/// An attribute dictionary in FreeRADIUS text format (ATTRIBUTE / VALUE / VENDOR / BEGIN-VENDOR / END-VENDOR / $INCLUDE).
/// Vendor attributes are assumed to use the standard 1-octet type / 1-octet length layout.
/// </summary>
public sealed class RadiusDictionary
{
    private readonly Dictionary<(uint, int), DictAttribute> _byId = [];
    private readonly Dictionary<string, DictAttribute> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<uint, string> _vendorNames = [];
    private readonly Dictionary<string, uint> _vendorIds = new(StringComparer.OrdinalIgnoreCase);
    public List<string> LoadWarnings { get; } = [];

    public IEnumerable<DictAttribute> Attributes => _byName.Values.OrderBy(a => a.Vendor).ThenBy(a => a.Type);
    public IReadOnlyDictionary<uint, string> Vendors => _vendorNames;

    public static RadiusDictionary LoadBuiltIn()
    {
        var d = new RadiusDictionary();
        var asm = typeof(RadiusDictionary).Assembly;
        foreach (var res in asm.GetManifestResourceNames().Where(n => n.EndsWith(".dict", StringComparison.OrdinalIgnoreCase)).OrderBy(n => n.Contains("standard") ? 0 : 1))
        {
            using var s = asm.GetManifestResourceStream(res)!;
            using var r = new StreamReader(s);
            d.LoadText(r.ReadToEnd());
        }
        return d;
    }

    public int LoadFile(string path)
    {
        int before = _byName.Count;
        LoadText(File.ReadAllText(path), path);
        return _byName.Count - before;
    }

    public void LoadText(string text, string? sourcePath = null, int depth = 0)
    {
        uint vendor = 0;
        int lineNo = 0;
        foreach (var raw in text.Split('\n'))
        {
            lineNo++;
            var line = raw.Split('#')[0].Trim();
            if (line.Length == 0) continue;
            var t = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            try
            {
                switch (t[0].ToUpperInvariant())
                {
                    case "VENDOR" when t.Length >= 3:
                        AddVendor(t[1], (uint)ParseNumber(t[2]));
                        break;
                    case "BEGIN-VENDOR" when t.Length >= 2:
                        if (!_vendorIds.TryGetValue(t[1], out vendor)) { LoadWarnings.Add($"Line {lineNo}: unknown vendor {t[1]}"); vendor = 0; }
                        break;
                    case "END-VENDOR":
                        vendor = 0;
                        break;
                    case "ATTRIBUTE" when t.Length >= 4:
                        if (t[2].Contains('.')) break;   // TLV sub-attribute: not supported, skipped
                        Add(new DictAttribute(t[1], vendor, (int)ParseNumber(t[2]), t[3].Split('[')[0]));
                        break;
                    case "VALUE" when t.Length >= 4:
                        if (_byName.TryGetValue(t[1], out var a)) { long n = ParseNumber(t[3]); a.ValueNames[n] = t[2]; a.ValueNumbers[t[2]] = n; }
                        break;
                    case "$INCLUDE" when t.Length >= 2 && depth < 5:
                        var inc = sourcePath is null ? t[1] : Path.Combine(Path.GetDirectoryName(sourcePath) ?? "", t[1]);
                        if (File.Exists(inc)) LoadText(File.ReadAllText(inc), inc, depth + 1);
                        else LoadWarnings.Add($"Line {lineNo}: $INCLUDE {t[1]} not found");
                        break;
                }
            }
            catch (FormatException) { LoadWarnings.Add($"Line {lineNo}: could not parse '{line}'"); }
            catch (OverflowException) { LoadWarnings.Add($"Line {lineNo}: number out of range in '{line}'"); }
        }
    }

    private void AddVendor(string name, uint id) { _vendorNames[id] = name; _vendorIds[name] = id; }
    private void Add(DictAttribute a) { _byId[(a.Vendor, a.Type)] = a; _byName[a.Name] = a; }

    private static long ParseNumber(string s) =>
        s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? Convert.ToInt64(s[2..], 16) : long.Parse(s, CultureInfo.InvariantCulture);

    public DictAttribute? Find(uint vendor, int type) => _byId.GetValueOrDefault((vendor, type));
    public DictAttribute? Find(string name) => _byName.GetValueOrDefault(name);
    public string VendorName(uint id) => _vendorNames.TryGetValue(id, out var n) ? n : $"Vendor-{id}";

    // ---------------- encoding ----------------

    private static readonly Regex GenericName = new(@"^(?:Vendor-(\d+)-)?Attr-(\d+)$", RegexOptions.IgnoreCase);

    /// <summary>Builds the (possibly Vendor-Specific wrapped) attribute for "name = value". Throws FormatException with a readable message.</summary>
    public RadiusAttribute Encode(string name, string value)
    {
        name = name.Trim();
        var attr = Find(name);
        if (attr is null)
        {
            var m = GenericName.Match(name);
            if (!m.Success) throw new FormatException($"Unknown attribute '{name}'. Use a dictionary name, or Attr-<n> / Vendor-<id>-Attr-<n> with an 0x… hex value.");
            attr = new DictAttribute(name, m.Groups[1].Success ? uint.Parse(m.Groups[1].Value) : 0, int.Parse(m.Groups[2].Value), "octets");
        }
        var data = EncodeValue(attr, value);
        return attr.Vendor == 0 ? new RadiusAttribute(attr.Type, data) : RadiusAttribute.Vsa(attr.Vendor, attr.Type, data);
    }

    public byte[] EncodeValue(DictAttribute attr, string value)
    {
        value = value.Trim();
        switch (attr.DataType)
        {
            case "string": return Encoding.UTF8.GetBytes(value);
            case "octets" or "abinary" or "tlv":
                return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? ParseHex(value[2..]) : Encoding.UTF8.GetBytes(value);
            case "ipaddr":
                if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) throw new FormatException($"'{value}' is not an IPv4 address.");
                return ip.GetAddressBytes();
            case "ipv6addr":
                if (!IPAddress.TryParse(value, out var ip6) || ip6.AddressFamily != AddressFamily.InterNetworkV6) throw new FormatException($"'{value}' is not an IPv6 address.");
                return ip6.GetAddressBytes();
            case "combo-ip":
                return (IPAddress.TryParse(value, out var any) ? any : throw new FormatException($"'{value}' is not an IP address.")).GetAddressBytes();
            case "ipv6prefix":
                var parts = value.Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var pfx) || !int.TryParse(parts[1], out int plen) || plen is < 0 or > 128)
                    throw new FormatException($"'{value}' is not an IPv6 prefix like 2001:db8::/32.");
                return [0, (byte)plen, .. pfx.GetAddressBytes()[..((plen + 7) / 8)]];
            case "ifid":
                var h = ParseHex(value.Replace(":", ""));
                if (h.Length != 8) throw new FormatException("Interface-Id needs 8 bytes (xxxx:xxxx:xxxx:xxxx).");
                return h;
            case "byte": return [(byte)ParseInteger(attr, value, byte.MaxValue)];
            case "short": { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)ParseInteger(attr, value, ushort.MaxValue)); return b; }
            case "integer64": { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, (ulong)ParseInteger(attr, value, long.MaxValue)); return b; }
            case "date":
                if (!long.TryParse(value, out _) && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dt))
                    value = dt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                goto default;
            default:   // integer, date, unknown 4-byte types
            {
                var b = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(b, (uint)ParseInteger(attr, value, uint.MaxValue));
                return b;
            }
        }
    }

    private static long ParseInteger(DictAttribute a, string v, long max)
    {
        if (a.ValueNumbers.TryGetValue(v, out long n)) return n;
        if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && long.TryParse(v[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out n) && n <= max) return n;
        if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) && n >= 0 && n <= max) return n;
        var known = a.ValueNumbers.Count > 0 ? " Known values: " + string.Join(", ", a.ValueNumbers.Keys.Take(8)) + "." : "";
        throw new FormatException($"'{v}' is not a valid value for {a.Name} (0..{max}).{known}");
    }

    public static byte[] ParseHex(string s)
    {
        s = s.Replace(" ", "");
        if (s.Length % 2 != 0) throw new FormatException("Hex value needs an even number of digits.");
        try { return Convert.FromHexString(s); } catch (FormatException) { throw new FormatException($"'{s}' is not valid hex."); }
    }

    // ---------------- decoding ----------------

    public string DecodeValue(DictAttribute? attr, byte[] v)
    {
        var type = attr?.DataType ?? "octets";
        try
        {
            switch (type)
            {
                case "string":
                    return IsPrintable(v) ? Encoding.UTF8.GetString(v) : "0x" + Convert.ToHexString(v);
                case "ipaddr" when v.Length == 4: return new IPAddress(v).ToString();
                case "ipv6addr" when v.Length == 16: return new IPAddress(v).ToString();
                case "combo-ip" when v.Length is 4 or 16: return new IPAddress(v).ToString();
                case "ipv6prefix" when v.Length >= 2 && v.Length <= 18:
                {
                    var full = new byte[16]; v[2..].CopyTo(full, 0);
                    return new IPAddress(full) + "/" + v[1];
                }
                case "ifid" when v.Length == 8: return string.Join(":", Enumerable.Range(0, 4).Select(i => Convert.ToHexString(v, i * 2, 2).ToLowerInvariant()));
                case "byte" when v.Length == 1: return Named(attr, v[0]);
                case "short" when v.Length == 2: return Named(attr, BinaryPrimitives.ReadUInt16BigEndian(v));
                case "integer64" when v.Length == 8: return BinaryPrimitives.ReadUInt64BigEndian(v).ToString(CultureInfo.InvariantCulture);
                case "date" when v.Length == 4:
                {
                    uint s = BinaryPrimitives.ReadUInt32BigEndian(v);
                    return DateTimeOffset.FromUnixTimeSeconds(s).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) + $" ({s})";
                }
                case "integer" when v.Length == 4: return Named(attr, BinaryPrimitives.ReadUInt32BigEndian(v));
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { }
        return "0x" + Convert.ToHexString(v);
    }

    private static string Named(DictAttribute? a, long n) =>
        a != null && a.ValueNames.TryGetValue(n, out var nm) ? $"{nm} ({n})" : n.ToString(CultureInfo.InvariantCulture);

    private static bool IsPrintable(byte[] v)
    {
        try
        {
            var s = new UTF8Encoding(false, true).GetString(v);
            return s.All(c => !char.IsControl(c) || c is '\r' or '\n' or '\t');
        }
        catch (DecoderFallbackException) { return false; }
    }
}
