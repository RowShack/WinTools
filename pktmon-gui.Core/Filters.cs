using System.Net;
using System.Text.RegularExpressions;

namespace PktmonGui.Core;

/// <summary>One packet filter row. A packet is reported if it matches ALL set conditions of AT LEAST ONE filter.</summary>
public sealed class FilterSpec
{
    public string Name { get; set; } = "";
    public string Ip1 { get; set; } = "";        // address or CIDR
    public string Ip2 { get; set; } = "";
    public string Port1 { get; set; } = "";
    public string Port2 { get; set; } = "";
    public string Protocol { get; set; } = "Any"; // Any | TCP | UDP | ICMP | ICMPv6
    public string Mac1 { get; set; } = "";
    public string Mac2 { get; set; } = "";
    public string Vlan { get; set; } = "";
    public string DataLink { get; set; } = "Any"; // Any | IPv4 | IPv6 | ARP

    public static readonly string[] Protocols = ["Any", "TCP", "UDP", "ICMP", "ICMPv6"];
    public static readonly string[] DataLinks = ["Any", "IPv4", "IPv6", "ARP"];
    public const int MaxFilters = 32;

    public bool IsEmpty => Ip1 + Ip2 + Port1 + Port2 + Mac1 + Mac2 + Vlan == "" && Protocol == "Any" && DataLink == "Any";

    private static readonly Regex MacRx = new(@"^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{12}$", RegexOptions.Compiled);

    /// <summary>Returns null when valid, otherwise a message for the user.</summary>
    public string? Validate()
    {
        foreach (var ip in new[] { Ip1, Ip2 }.Where(s => s.Length > 0))
            if (!ValidIp(ip)) return $"'{ip}' is not a valid IP address or CIDR range (e.g. 10.0.0.5 or 10.0.0.0/24).";
        foreach (var p in new[] { Port1, Port2 }.Where(s => s.Length > 0))
            if (!int.TryParse(p, out int n) || n is < 1 or > 65535) return $"'{p}' is not a valid port (1–65535).";
        foreach (var m in new[] { Mac1, Mac2 }.Where(s => s.Length > 0))
            if (!MacRx.IsMatch(m)) return $"'{m}' is not a valid MAC address (e.g. 00-11-22-33-44-55).";
        if (Vlan.Length > 0 && (!int.TryParse(Vlan, out int v) || v is < 0 or > 4095)) return $"'{Vlan}' is not a valid VLAN id (0–4095).";
        if ((Port1.Length > 0 || Port2.Length > 0) && Protocol is not ("TCP" or "UDP"))
            return "Ports only make sense together with protocol TCP or UDP.";
        if (Ip2.Length > 0 && Ip1.Length == 0) return "Fill the first IP before the second.";
        if (Port2.Length > 0 && Port1.Length == 0) return "Fill the first port before the second.";
        if (Mac2.Length > 0 && Mac1.Length == 0) return "Fill the first MAC before the second.";
        if (!Protocols.Contains(Protocol)) return $"Unknown protocol '{Protocol}'.";
        if (!DataLinks.Contains(DataLink)) return $"Unknown data link type '{DataLink}'.";
        if (IsEmpty) return "This filter has no conditions.";
        return null;
    }

    private static bool ValidIp(string s)
    {
        int slash = s.IndexOf('/');
        string addr = slash >= 0 ? s[..slash] : s;
        if (!IPAddress.TryParse(addr, out var ip) || addr.Contains('%')) return false;
        if (slash < 0) return true;
        int max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return int.TryParse(s[(slash + 1)..], out int len) && len >= 0 && len <= max;
    }

    /// <summary>Arguments for <c>pktmon filter add</c> (without the program name). Throws if invalid.</summary>
    public string ToArguments(int index)
    {
        var err = Validate();
        if (err != null) throw new ArgumentException(err);
        var parts = new List<string> { "filter", "add", Quote(string.IsNullOrWhiteSpace(Name) ? $"F{index + 1}" : Name) };
        if (Mac1.Length > 0) parts.AddRange(["-m", Mac1, ..(Mac2.Length > 0 ? new[] { Mac2 } : [])]);
        if (Vlan.Length > 0) parts.AddRange(["-v", Vlan]);
        if (DataLink != "Any") parts.AddRange(["-d", DataLink]);
        if (Protocol != "Any") parts.AddRange(["-t", Protocol]);
        if (Ip1.Length > 0) parts.AddRange(["-i", Ip1, ..(Ip2.Length > 0 ? new[] { Ip2 } : [])]);
        if (Port1.Length > 0) parts.AddRange(["-p", Port1, ..(Port2.Length > 0 ? new[] { Port2 } : [])]);
        return string.Join(" ", parts);
    }

    /// <summary>Filter names are shown to the user and put on a command line: keep them to a safe character set.</summary>
    public static string Quote(string name)
    {
        string clean = Regex.Replace(name, @"[^\w .\-]", "_").Trim();
        if (clean.Length == 0) clean = "filter";
        if (clean.Length > 40) clean = clean[..40];
        return clean.Contains(' ') ? $"\"{clean}\"" : clean;
    }

    public static class Presets
    {
        public static readonly string[] Names = ["DNS", "DHCP", "RDP", "SMB", "LDAP / Kerberos", "HTTPS to one host…"];

        public static List<FilterSpec> Get(string name, string? host = null) => name switch
        {
            "DNS" => [Tcp("DNS tcp", 53), Udp("DNS udp", 53)],
            "DHCP" => [Udp("DHCP server", 67), Udp("DHCP client", 68)],
            "RDP" => [Tcp("RDP", 3389), Udp("RDP udp", 3389)],
            "SMB" => [Tcp("SMB", 445)],
            "LDAP / Kerberos" => [Tcp("LDAP", 389), Tcp("LDAPS", 636), Tcp("GC", 3268), Tcp("Kerberos tcp", 88), Udp("Kerberos udp", 88), Tcp("kpasswd", 464)],
            "HTTPS to one host…" => [new FilterSpec { Name = "HTTPS " + (host ?? ""), Protocol = "TCP", Port1 = "443", Ip1 = host ?? "" }],
            _ => [],
        };

        private static FilterSpec Tcp(string n, int p) => new() { Name = n, Protocol = "TCP", Port1 = p.ToString() };
        private static FilterSpec Udp(string n, int p) => new() { Name = n, Protocol = "UDP", Port1 = p.ToString() };
    }
}
