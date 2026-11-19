using System.Text;

namespace WifiRoamLog.Core;

public static class Csv
{
    public static string Escape(string? s)
    {
        s ??= "";
        return s.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    public static string Join(params string?[] fields) => string.Join(',', fields.Select(Escape));

    /// <summary>Splits one CSV line (RFC 4180 quotes). Returns null if a quote is left open. delimiter is comma, semicolon or tab.</summary>
    public static List<string>? ParseLine(string line, char delimiter = ',')
    {
        var res = new List<string>();
        var sb = new StringBuilder();
        bool inQ = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQ)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQ = false;
                }
                else sb.Append(c);
            }
            else if (c == '"' && sb.Length == 0) inQ = true;
            else if (c == delimiter) { res.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        if (inQ) return null;
        res.Add(sb.ToString());
        return res;
    }
}
