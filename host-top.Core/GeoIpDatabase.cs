using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace HostTop.Core;

/// <summary>
/// Optional offline IP-to-location lookup. Loads a CSV the user supplies (nothing is downloaded). Format, one range per line:
/// <c>start_ip,end_ip,country[,asn or organisation ...]</c> — this is the layout of the free DB-IP "IP to Country Lite" and
/// "IP to ASN Lite" CSV files. Lines starting with # and unparsable lines are skipped. IPv4 and IPv6 ranges can be mixed.
/// </summary>
public sealed class GeoIpDatabase
{
    private readonly List<(UInt128 Start, UInt128 End, string Text)> _ranges = [];
    public int Count => _ranges.Count;

    public static GeoIpDatabase Load(string path)
    {
        var db = new GeoIpDatabase();
        foreach (var line in File.ReadLines(path)) db.AddLine(line);
        db._ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        return db;
    }

    public static GeoIpDatabase FromLines(IEnumerable<string> lines)
    {
        var db = new GeoIpDatabase();
        foreach (var l in lines) db.AddLine(l);
        db._ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        return db;
    }

    private void AddLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] == '#') return;
        var f = SplitCsv(line);
        if (f.Count < 3) return;
        if (!IPAddress.TryParse(f[0], out var a) || !IPAddress.TryParse(f[1], out var b)) return;
        var text = string.Join(" · ", f.Skip(2).Select(x => x.Trim()).Where(x => x.Length > 0));
        _ranges.Add((ToNumber(a), ToNumber(b), text));
    }

    private static List<string> SplitCsv(string line)
    {
        var res = new List<string>(); var sb = new System.Text.StringBuilder(); bool q = false;
        foreach (var c in line)
        {
            if (c == '"') q = !q;
            else if (c == ',' && !q) { res.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        res.Add(sb.ToString());
        return res;
    }

    /// <summary>IPv4 addresses are mapped into ::ffff:0:0/96 so both families share one sorted list.</summary>
    internal static UInt128 ToNumber(IPAddress a)
    {
        if (a.AddressFamily == AddressFamily.InterNetwork) a = a.MapToIPv6();
        var b = a.GetAddressBytes();
        UInt128 v = 0;
        foreach (var x in b) v = (v << 8) | x;
        return v;
    }

    public string? Lookup(IPAddress ip)
    {
        var n = ToNumber(ip);
        int lo = 0, hi = _ranges.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_ranges[mid].Start <= n) { best = mid; lo = mid + 1; } else hi = mid - 1;
        }
        return best >= 0 && n <= _ranges[best].End ? _ranges[best].Text : null;
    }
}
