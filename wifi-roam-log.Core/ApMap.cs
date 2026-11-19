using System.Globalization;
using System.Text;

namespace WifiRoamLog.Core;

public static class Bssid
{
    /// <summary>Parses "aa:bb:cc", "AA-BB-CC-DD", "aabbccddeeff", "aabb.ccdd" (1 to 6 octets).</summary>
    public static byte[]? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var hex = new string(text.Trim().Where(c => c is not (':' or '-' or '.' or ' ')).ToArray());
        if (hex.Length == 0 || hex.Length % 2 != 0 || hex.Length > 12) return null;
        var res = new byte[hex.Length / 2];
        for (int i = 0; i < res.Length; i++)
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out res[i])) return null;
        return res;
    }

    public static string Format(byte[] b) => WifiMath.FormatBssid(b);

    /// <summary>Normalised "aa:bb:cc:dd:ee:ff", or "" when empty / all zero / invalid.</summary>
    public static string Normalize(string? text)
    {
        var b = Parse(text);
        return b is null || b.All(x => x == 0) ? "" : Format(b);
    }
}

public sealed record ApMapEntry(byte[] Prefix, string Name, string Location)
{
    public string Label => string.IsNullOrEmpty(Location) ? Name : $"{Name} ({Location})";
}

/// <summary>PrefixOctets: how many leading octets of the BSSID are compared (default 5 = ignore the last octet, where controllers put the per-SSID virtual offset).
/// IgnoreFirstOctet: also skip octet 1 (some vendors flip the locally-administered bit there for extra SSIDs, e.g. 94:... / 9a:... / a2:...).</summary>
public sealed record ApMatchOptions(int PrefixOctets = 5, bool IgnoreFirstOctet = false);

public sealed class ApMap
{
    private readonly List<ApMapEntry> _entries = [];
    public IReadOnlyList<ApMapEntry> Entries => _entries;
    public int Count => _entries.Count;
    public void Add(ApMapEntry e) => _entries.Add(e);

    /// <summary>Best match: compares min(PrefixOctets, entry length) octets; among matches the entry with the longest prefix wins, then the first in file order.</summary>
    public ApMapEntry? Lookup(string? bssid, ApMatchOptions? options = null)
    {
        options ??= new ApMatchOptions();
        var b = Bssid.Parse(bssid);
        if (b is null || b.Length != 6) return null;
        int start = options.IgnoreFirstOctet ? 1 : 0;
        int k = Math.Clamp(options.PrefixOctets, 1, 6);
        ApMapEntry? best = null;
        foreach (var e in _entries)
        {
            int n = Math.Min(k, e.Prefix.Length);
            if (n - start <= 0) continue;
            bool ok = true;
            for (int i = start; i < n; i++) if (e.Prefix[i] != b[i]) { ok = false; break; }
            if (ok && (best is null || e.Prefix.Length > best.Prefix.Length)) best = e;
        }
        return best;
    }

    public string NameFor(string? bssid, ApMatchOptions? options = null) => Lookup(bssid, options)?.Name ?? "";
}

public sealed record ApMapImportResult(ApMap Map, List<string> Errors);

public static class ApMapImporter
{
    public static ApMapImportResult ParseFile(string path)
    {
        using var sr = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return Parse(sr.ReadToEnd());
    }

    /// <summary>Columns: BSSID prefix, AP name, location (optional). First row may be a header. A line starting with # is a comment. Bad lines are skipped and reported.</summary>
    public static ApMapImportResult Parse(string text)
    {
        var map = new ApMap();
        var errors = new List<string>();
        text = text.TrimStart('﻿');
        var lines = text.Split('\n');
        char? delim = null;
        bool sawData = false;
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) continue;
            delim ??= line.Contains(',') ? ',' : line.Contains(';') ? ';' : line.Contains('\t') ? '\t' : ',';
            var f = Csv.ParseLine(line, delim.Value);
            if (f is null) { errors.Add($"Line {i + 1}: unterminated quote"); continue; }
            var prefix = Bssid.Parse(f[0]);
            if (prefix is null)
            {
                if (!sawData && IsHeader(f[0])) { sawData = true; continue; }   // header row
                errors.Add($"Line {i + 1}: invalid BSSID prefix '{f[0].Trim()}'");
                continue;
            }
            sawData = true;
            if (f.Count < 2) { errors.Add($"Line {i + 1}: expected BSSID prefix and AP name"); continue; }
            var name = f[1].Trim();
            if (name.Length == 0) { errors.Add($"Line {i + 1}: empty AP name"); continue; }
            map.Add(new ApMapEntry(prefix, name, f.Count > 2 ? f[2].Trim() : ""));
        }
        return new ApMapImportResult(map, errors);
    }

    private static bool IsHeader(string first)
    {
        var s = first.Trim().ToLowerInvariant();
        return s.Contains("bssid") || s.Contains("prefix") || s.Contains("mac");
    }
}
