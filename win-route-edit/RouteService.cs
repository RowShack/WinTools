using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace WinRouteEdit;

public sealed record RouteEntry(
    string Prefix, string NextHop, int IfIndex, string IfAlias,
    int RouteMetric, int IfMetric, string Protocol, bool Persistent, bool Active)
{
    public int TotalMetric => RouteMetric + IfMetric;
    public bool IsOnLink => NextHop is "0.0.0.0" or "";
}

public sealed record InterfaceInfo(int Index, string Alias, int Metric)
{
    public override string ToString() => $"{Alias} (#{Index})";
}

/// <summary>
/// Reads and edits the IPv4 routing table through PowerShell's NetTCPIP cmdlets
/// (Get-/New-/Remove-NetRoute). All values interpolated into scripts are validated
/// (parsed IPs / integers) first, so no user text reaches the shell.
/// </summary>
public static class RouteService
{
    public static bool IsAdmin()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    // ---------- parsing / validation ----------

    /// <summary>Accepts "a.b.c.d", "a.b.c.d/24" or "a.b.c.d/255.255.255.0" and returns canonical CIDR.</summary>
    public static bool TryParsePrefix(string text, out string cidr, out string error)
    {
        cidr = ""; error = "";
        text = text.Trim();
        string ipPart = text, lenPart = "32";
        int slash = text.IndexOf('/');
        if (slash >= 0) { ipPart = text[..slash].Trim(); lenPart = text[(slash + 1)..].Trim(); }

        if (!TryIPv4(ipPart, out var ip)) { error = "Destination is not a valid IPv4 address."; return false; }

        int len;
        if (lenPart.Contains('.'))
        {
            if (!TryIPv4(lenPart, out var mask)) { error = "Subnet mask is not valid."; return false; }
            uint m = ToUInt(mask);
            len = 0;
            while (len < 32 && (m & (0x80000000u >> len)) != 0) len++;
            if (m != (len == 0 ? 0u : uint.MaxValue << (32 - len))) { error = "Subnet mask must be contiguous (e.g. 255.255.255.0)."; return false; }
        }
        else if (!int.TryParse(lenPart, out len) || len < 0 || len > 32)
        { error = "Prefix length must be 0–32."; return false; }

        uint net = ToUInt(ip);
        uint maskBits = len == 0 ? 0 : uint.MaxValue << (32 - len);
        if ((net & ~maskBits) != 0) { error = $"{ipPart} has host bits set for /{len}. Did you mean {FromUInt(net & maskBits)}/{len}?"; return false; }

        cidr = $"{ip}/{len}";
        return true;
    }

    public static bool TryIPv4(string text, out IPAddress ip)
    {
        ip = IPAddress.None;
        var parts = text.Trim().Split('.');
        if (parts.Length != 4 || !parts.All(p => p.Length is > 0 and <= 3 && p.All(char.IsAsciiDigit))) return false;
        return IPAddress.TryParse(text.Trim(), out ip!) && ip.AddressFamily == AddressFamily.InterNetwork;
    }

    private static uint ToUInt(IPAddress ip) { var b = ip.GetAddressBytes(); return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]); }
    private static IPAddress FromUInt(uint v) => new([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);
    public static long SortKey(string prefix)
    {
        int slash = prefix.IndexOf('/');
        string ip = slash >= 0 ? prefix[..slash] : prefix;
        int len = slash >= 0 && int.TryParse(prefix[(slash + 1)..], out var l) ? l : 32;
        return TryIPv4(ip, out var a) ? ((long)ToUInt(a) << 6) | (uint)len : long.MaxValue;
    }

    // ---------- reading ----------

    public static async Task<List<RouteEntry>> GetRoutesAsync()
    {
        const string script = """
            $ErrorActionPreference='Stop'
            $a = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{P=$_.DestinationPrefix;N=$_.NextHop;I=[int]$_.InterfaceIndex;A=[string]$_.InterfaceAlias;R=[int]$_.RouteMetric;M=[int]$_.InterfaceMetric;T=[string]$_.Protocol} })
            $p = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{P=$_.DestinationPrefix;N=$_.NextHop;I=[int]$_.InterfaceIndex;A=[string]$_.InterfaceAlias;R=[int]$_.RouteMetric;M=[int]$_.InterfaceMetric;T=[string]$_.Protocol} })
            [pscustomobject]@{Active=$a;Persistent=$p} | ConvertTo-Json -Depth 4 -Compress
            """;
        using var doc = JsonDocument.Parse(await Ps.RunAsync(script));
        var persistent = new HashSet<(string, string, int)>();
        var result = new List<RouteEntry>();

        foreach (var e in doc.RootElement.GetProperty("Persistent").EnumerateArray())
            persistent.Add((e.GetProperty("P").GetString()!, e.GetProperty("N").GetString()!, e.GetProperty("I").GetInt32()));

        var activeKeys = new HashSet<(string, string, int)>();
        foreach (var e in doc.RootElement.GetProperty("Active").EnumerateArray())
        {
            var key = (e.GetProperty("P").GetString()!, e.GetProperty("N").GetString()!, e.GetProperty("I").GetInt32());
            activeKeys.Add(key);
            result.Add(new RouteEntry(key.Item1, key.Item2, key.Item3, e.GetProperty("A").GetString() ?? "",
                e.GetProperty("R").GetInt32(), e.GetProperty("M").GetInt32(), e.GetProperty("T").GetString() ?? "",
                persistent.Contains(key), true));
        }
        // persistent routes that are saved but not currently active (e.g. adapter is down)
        foreach (var e in doc.RootElement.GetProperty("Persistent").EnumerateArray())
        {
            var key = (e.GetProperty("P").GetString()!, e.GetProperty("N").GetString()!, e.GetProperty("I").GetInt32());
            if (activeKeys.Contains(key)) continue;
            result.Add(new RouteEntry(key.Item1, key.Item2, key.Item3, e.GetProperty("A").GetString() ?? "",
                e.GetProperty("R").GetInt32(), e.GetProperty("M").GetInt32(), "Persistent", true, false));
        }
        return result;
    }

    public static async Task<List<InterfaceInfo>> GetInterfacesAsync()
    {
        const string script = """
            $ErrorActionPreference='Stop'
            @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' } | Sort-Object InterfaceMetric | ForEach-Object { [pscustomobject]@{I=[int]$_.InterfaceIndex;A=[string]$_.InterfaceAlias;M=[int]$_.InterfaceMetric} }) | ConvertTo-Json -Compress
            """;
        string json = (await Ps.RunAsync(script)).Trim();
        if (json.Length == 0) return [];
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray() : new[] { doc.RootElement }.AsEnumerable().Select(x => x);
        return items.Select(e => new InterfaceInfo(e.GetProperty("I").GetInt32(), e.GetProperty("A").GetString() ?? "", e.GetProperty("M").GetInt32())).ToList();
    }

    // ---------- editing ----------

    /// <summary>Adds a route. ifIndex null = let Windows pick the interface that reaches the gateway.</summary>
    public static async Task AddRouteAsync(string cidr, string nextHop, int metric, int? ifIndex, bool persistent)
    {
        if (!TryParsePrefix(cidr, out cidr, out var err)) throw new ArgumentException(err);
        if (!TryIPv4(nextHop, out var gw)) throw new ArgumentException("Gateway is not a valid IPv4 address (use 0.0.0.0 for on-link).");
        if (metric < 0 || metric > 9999) throw new ArgumentException("Metric must be 0–9999.");

        var sb = new StringBuilder("$ErrorActionPreference='Stop'\n");
        if (ifIndex is int i) sb.AppendLine($"$idx = {i}");
        else
        {
            if (gw.Equals(IPAddress.Any)) throw new ArgumentException("Choose an interface for an on-link (0.0.0.0) route.");
            sb.AppendLine($"$idx = (Find-NetRoute -RemoteIPAddress '{gw}' | Where-Object {{ $_.DestinationPrefix }} | Select-Object -First 1).InterfaceIndex");
            sb.AppendLine("if (-not $idx) { throw 'No interface can reach that gateway - pick an interface manually.' }");
        }
        string common = $"-DestinationPrefix '{cidr}' -NextHop '{gw}' -InterfaceIndex $idx -RouteMetric {metric} -Confirm:$false";
        sb.AppendLine($"New-NetRoute {common} -PolicyStore ActiveStore | Out-Null");
        if (persistent) sb.AppendLine($"New-NetRoute {common} -PolicyStore PersistentStore | Out-Null");
        await Ps.RunAsync(sb.ToString());
    }

    public static async Task DeleteRouteAsync(RouteEntry r)
    {
        if (!TryParsePrefix(r.Prefix, out var cidr, out _) || !TryIPv4(r.NextHop, out var gw))
            throw new ArgumentException($"Can't delete route {r.Prefix} via {r.NextHop}: unrecognised format.");
        string target = $"-DestinationPrefix '{cidr}' -NextHop '{gw}' -InterfaceIndex {r.IfIndex} -Confirm:$false";
        var sb = new StringBuilder("$ErrorActionPreference='Stop'\n");
        if (r.Active) sb.AppendLine($"Remove-NetRoute {target} -PolicyStore ActiveStore");
        if (r.Persistent) sb.AppendLine($"Remove-NetRoute {target} -PolicyStore PersistentStore");
        await Ps.RunAsync(sb.ToString());
    }
}

internal static class Ps
{
    public static async Task<string> RunAsync(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                     "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script })
            psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (p.ExitCode != 0)
        {
            string msg = (await stderr).Trim();
            // PowerShell error text is multi-line noise; keep the first meaningful line
            msg = msg.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "PowerShell command failed.";
            throw new InvalidOperationException(msg);
        }
        return await stdout;
    }
}
