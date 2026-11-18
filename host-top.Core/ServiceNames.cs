namespace HostTop.Core;

/// <summary>Well-known service names by port.</summary>
public static class ServiceNames
{
    private static readonly Dictionary<int, string> Tcp = new()
    {
        [20] = "FTP-data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS", [80] = "HTTP", [88] = "Kerberos",
        [110] = "POP3", [123] = "NTP", [135] = "RPC", [139] = "NetBIOS", [143] = "IMAP", [389] = "LDAP", [443] = "HTTPS", [445] = "SMB",
        [465] = "SMTPS", [514] = "Syslog", [587] = "SMTP submission", [636] = "LDAPS", [853] = "DNS over TLS", [993] = "IMAPS", [995] = "POP3S",
        [1433] = "SQL Server", [1521] = "Oracle", [3268] = "LDAP GC", [3269] = "LDAPS GC", [3306] = "MySQL", [3389] = "RDP",
        [5432] = "PostgreSQL", [5671] = "AMQPS", [5672] = "AMQP", [5985] = "WinRM", [5986] = "WinRM HTTPS", [6379] = "Redis",
        [8080] = "HTTP alt", [8443] = "HTTPS alt", [9389] = "AD Web Services", [27017] = "MongoDB",
    };

    private static readonly Dictionary<int, string> Udp = new()
    {
        [53] = "DNS", [67] = "DHCP server", [68] = "DHCP client", [88] = "Kerberos", [123] = "NTP", [137] = "NetBIOS NS", [138] = "NetBIOS DGM",
        [161] = "SNMP", [162] = "SNMP trap", [389] = "CLDAP", [443] = "QUIC (HTTP/3)", [500] = "IKE", [514] = "Syslog", [1194] = "OpenVPN",
        [1812] = "RADIUS", [1813] = "RADIUS acct", [1900] = "SSDP", [3389] = "RDP", [4500] = "IPsec NAT-T", [5353] = "mDNS",
        [5355] = "LLMNR", [51820] = "WireGuard",
    };

    public static string? Get(FlowProtocol proto, int port) =>
        (proto == FlowProtocol.Tcp ? Tcp : Udp).TryGetValue(port, out var s) ? s : null;

    /// <summary>Name for the remote port, falling back to the local port (inbound connections to a local service).</summary>
    public static string Describe(FlowProtocol proto, int localPort, int remotePort)
    {
        var s = Get(proto, remotePort);
        if (s != null) return $"{s} ({remotePort})";
        s = Get(proto, localPort);
        return s != null ? $"{s} ({localPort})" : "";
    }
}
