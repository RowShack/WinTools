namespace PortProbe.Core;

public enum Proto { Tcp, Udp }

public readonly record struct PortSpec(Proto Proto, int Port)
{
    public override string ToString() => Proto == Proto.Udp ? $"udp:{Port}" : $"{Port}";
}

/// <summary>Parses "443, 8080-8090, udp:514, udp:1812-1813" into individual ports.</summary>
public static class PortSpecParser
{
    public const int MaxPorts = 5000;

    public static bool TryParse(string text, out List<PortSpec> specs, out string error)
    {
        specs = [];
        error = "";
        var seen = new HashSet<PortSpec>();
        var tokens = text.Split([',', ';', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) { error = "Enter at least one port."; return false; }

        foreach (var raw in tokens)
        {
            string tok = raw.Trim();
            var proto = Proto.Tcp;
            if (tok.StartsWith("udp:", StringComparison.OrdinalIgnoreCase)) { proto = Proto.Udp; tok = tok[4..]; }
            else if (tok.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase)) tok = tok[4..];

            int lo, hi;
            int dash = tok.IndexOf('-');
            if (dash > 0)
            {
                if (!int.TryParse(tok[..dash], out lo) || !int.TryParse(tok[(dash + 1)..], out hi)) { error = $"'{raw}' is not a valid port range."; return false; }
            }
            else if (!int.TryParse(tok, out lo)) { error = $"'{raw}' is not a valid port."; return false; }
            else hi = lo;

            if (lo < 1 || hi > 65535) { error = $"'{raw}': ports must be between 1 and 65535."; return false; }
            if (lo > hi) { error = $"'{raw}': range start is greater than its end."; return false; }

            for (int p = lo; p <= hi; p++)
            {
                if (seen.Add(new PortSpec(proto, p)) )
                {
                    specs.Add(new PortSpec(proto, p));
                    if (specs.Count > MaxPorts) { error = $"Too many ports (limit {MaxPorts})."; return false; }
                }
            }
        }
        return true;
    }

    /// <summary>Compact form for one protocol, e.g. "443,8080-8090" (used for firewall rules).</summary>
    public static string Compact(IEnumerable<PortSpec> specs, Proto proto)
    {
        var ports = specs.Where(s => s.Proto == proto).Select(s => s.Port).Distinct().OrderBy(p => p).ToList();
        var parts = new List<string>();
        for (int i = 0; i < ports.Count;)
        {
            int j = i;
            while (j + 1 < ports.Count && ports[j + 1] == ports[j] + 1) j++;
            parts.Add(j == i ? $"{ports[i]}" : $"{ports[i]}-{ports[j]}");
            i = j + 1;
        }
        return string.Join(",", parts);
    }
}
