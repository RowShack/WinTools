using System.Net;
using System.Net.Sockets;

namespace HostTop.Core;

public static class AddressClassifier
{
    /// <summary>Classifies the remote address of a flow. Traffic to the machine's own address counts as loopback.</summary>
    public static NetClass Classify(IPAddress remote, IPAddress? local = null)
    {
        remote = Unmap(remote);
        if (local != null && !IsUnspecified(local) && Unmap(local).Equals(remote)) return NetClass.Loopback;
        if (IPAddress.IsLoopback(remote)) return NetClass.Loopback;
        return IsLan(remote) ? NetClass.Lan : NetClass.Internet;
    }

    private static bool IsUnspecified(IPAddress a) => a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any);

    private static IPAddress Unmap(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;

    public static bool IsLan(IPAddress a)
    {
        a = Unmap(a);
        var b = a.GetAddressBytes();
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)               // link-local
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // CGNAT / Tailscale
                || b[0] >= 224                                 // multicast, reserved, broadcast
                || b[0] == 0;
        }
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC                       // unique local fc00::/7
                || a.Equals(IPAddress.IPv6Any);
        }
        return false;
    }
}
