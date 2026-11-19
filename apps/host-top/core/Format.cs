using System.Globalization;
using System.Text;

namespace HostTop.Core;

public static class Format
{
    public static string Rate(double bytesPerSec, bool bits)
    {
        if (bytesPerSec <= 0) return "0";
        var v = bits ? bytesPerSec * 8 : bytesPerSec;
        string[] u = bits ? ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"] : ["B/s", "KB/s", "MB/s", "GB/s"];
        int i = 0;
        while (v >= 1000 && i < u.Length - 1) { v /= 1000; i++; }
        var n = v >= 100 || i == 0 ? v.ToString("0", CultureInfo.InvariantCulture)
            : v >= 10 ? v.ToString("0.0", CultureInfo.InvariantCulture)
            : v.ToString("0.00", CultureInfo.InvariantCulture);
        return n + " " + u[i];
    }

    public static string Bytes(long b)
    {
        string[] u = ["B", "KB", "MB", "GB", "TB"];
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return (i == 0 ? v.ToString("0", CultureInfo.InvariantCulture) : v.ToString("0.0", CultureInfo.InvariantCulture)) + " " + u[i];
    }
}

public static class CsvExport
{
    public static string Quote(string? s)
    {
        s ??= "";
        return s.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    public static string Build(IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<string>> rows)
    {
        var sb = new StringBuilder();
        sb.Append(string.Join(',', headers.Select(Quote))).Append("\r\n");
        foreach (var r in rows) sb.Append(string.Join(',', r.Select(Quote))).Append("\r\n");
        return sb.ToString();
    }

    /// <summary>Tab separated text for the clipboard (pastes into Excel).</summary>
    public static string BuildTsv(IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<string>> rows)
    {
        static string C(string? s) => (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        var sb = new StringBuilder();
        sb.Append(string.Join('\t', headers.Select(C))).Append("\r\n");
        foreach (var r in rows) sb.Append(string.Join('\t', r.Select(C))).Append("\r\n");
        return sb.ToString();
    }
}

public static class RowFilter
{
    /// <summary>Space separated terms, all must match (case-insensitive substring). A leading '-' excludes.</summary>
    public static bool Matches(string haystack, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        foreach (var t in filter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (t.Length > 1 && t[0] == '-')
            {
                if (haystack.Contains(t[1..], StringComparison.OrdinalIgnoreCase)) return false;
            }
            else if (!haystack.Contains(t, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }
}
