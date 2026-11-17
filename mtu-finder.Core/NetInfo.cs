using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MtuFinder.Core;

public sealed record LocalInterface(string Name, int Index, int Mtu, IPAddress? Address)
{
    public override string ToString() => Address is null ? Name : $"{Name} ({Address}, MTU {Mtu})";
}

public static class NetInfo
{
    /// <summary>Operational interfaces that have a unicast address of the family, with their MTU.</summary>
    public static List<LocalInterface> Interfaces(bool v6)
    {
        var list = new List<LocalInterface>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            try
            {
                var props = nic.GetIPProperties();
                int mtu = v6 ? props.GetIPv6Properties().Mtu : props.GetIPv4Properties().Mtu;
                int idx = v6 ? props.GetIPv6Properties().Index : props.GetIPv4Properties().Index;
                var addr = props.UnicastAddresses.Select(u => u.Address)
                    .FirstOrDefault(a => a.AddressFamily == (v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork) && !a.IsIPv6LinkLocal);
                if (addr is null) continue;
                list.Add(new LocalInterface(nic.Name, idx, mtu, addr));
            }
            catch (NetworkInformationException) { /* interface without this family */ }
        }
        return list;
    }

    /// <summary>The interface Windows would use to reach the target (connects a UDP socket; sends nothing).</summary>
    public static LocalInterface? InterfaceFor(IPAddress target)
    {
        try
        {
            using var s = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(target, 9);
            var local = ((IPEndPoint)s.LocalEndPoint!).Address;
            return Interfaces(target.AddressFamily == AddressFamily.InterNetworkV6).FirstOrDefault(i => i.Address!.Equals(local));
        }
        catch { return null; }
    }

    public static async Task<IPAddress?> ResolveAsync(string host, bool? v6, CancellationToken ct = default)
    {
        if (IPAddress.TryParse(host.Trim(), out var ip)) return ip;
        var addrs = await Dns.GetHostAddressesAsync(host.Trim(), ct);
        return addrs.FirstOrDefault(a => v6 == null || (a.AddressFamily == AddressFamily.InterNetworkV6) == v6)
               ?? addrs.FirstOrDefault(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6);
    }
}
