using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace MtuFinder.Core;

/// <summary>
/// Echo probe over the Windows IP Helper ICMP API. Unlike System.Net.NetworkInformation.Ping this lets us
/// pick the source address (and so the interface) and gives exact status codes.
/// IPv4 sets Don't-Fragment; IPv6 never fragments in routers, so oversize packets are answered with 'packet too big'.
/// </summary>
public sealed class IcmpProbe(IPAddress? source = null) : IEchoProbe
{
    private const uint IP_SUCCESS = 0, IP_PACKET_TOO_BIG = 11009, IP_REQ_TIMED_OUT = 11010;

    public Task<ProbeResult> SendAsync(IPAddress target, int payloadSize, TimeSpan timeout, CancellationToken ct) =>
        Task.Run(() => Send(target, payloadSize, (uint)timeout.TotalMilliseconds), ct);

    private ProbeResult Send(IPAddress target, int payloadSize, uint timeoutMs)
    {
        var payload = new byte[payloadSize];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(97 + i % 23);
        return target.AddressFamily == AddressFamily.InterNetworkV6
            ? SendV6(target, payload, timeoutMs)
            : SendV4(target, payload, timeoutMs);
    }

    // ---------------- IPv4 ----------------
    private ProbeResult SendV4(IPAddress target, byte[] payload, uint timeoutMs)
    {
        IntPtr h = IcmpCreateFile();
        if (h == new IntPtr(-1)) return new(ProbeStatus.Error, Detail: "IcmpCreateFile failed");
        var reply = Marshal.AllocHGlobal(payload.Length + 512);
        try
        {
            var opt = new IP_OPTION_INFORMATION { Ttl = 128, Flags = 0x02 /* IP_FLAG_DF */ };
            uint src = source is { AddressFamily: AddressFamily.InterNetwork } s ? BitConverter.ToUInt32(s.GetAddressBytes(), 0) : 0;
            uint dst = BitConverter.ToUInt32(target.GetAddressBytes(), 0);
            uint n = IcmpSendEcho2Ex(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, src, dst, payload, (ushort)payload.Length,
                ref opt, reply, (uint)(payload.Length + 512), timeoutMs);
            if (n == 0) return FromStatus((uint)Marshal.GetLastWin32Error(), null, 0);
            // ICMP_ECHO_REPLY: Address(4) Status(4) RoundTripTime(4) ...
            uint status = (uint)Marshal.ReadInt32(reply, 4);
            uint rtt = (uint)Marshal.ReadInt32(reply, 8);
            return FromStatus(status, rtt, rtt);
        }
        finally { Marshal.FreeHGlobal(reply); IcmpCloseHandle(h); }
    }

    // ---------------- IPv6 ----------------
    private ProbeResult SendV6(IPAddress target, byte[] payload, uint timeoutMs)
    {
        IntPtr h = Icmp6CreateFile();
        if (h == new IntPtr(-1)) return new(ProbeStatus.Error, Detail: "Icmp6CreateFile failed");
        var reply = Marshal.AllocHGlobal(payload.Length + 512);
        try
        {
            var src = ToSockAddr(source is { AddressFamily: AddressFamily.InterNetworkV6 } s ? s : IPAddress.IPv6Any);
            var dst = ToSockAddr(target);
            var opt = new IP_OPTION_INFORMATION { Ttl = 128 };
            uint n = Icmp6SendEcho2(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref src, ref dst, payload, (ushort)payload.Length,
                ref opt, reply, (uint)(payload.Length + 512), timeoutMs);
            if (n == 0) return FromStatus((uint)Marshal.GetLastWin32Error(), null, 0);
            // ICMPV6_ECHO_REPLY (packed): Address IPV6_ADDRESS_EX(26) Status(4) RoundTripTime(4)
            uint status = (uint)Marshal.ReadInt32(reply, 26);
            uint rtt = (uint)Marshal.ReadInt32(reply, 30);
            return FromStatus(status, rtt, rtt);
        }
        finally { Marshal.FreeHGlobal(reply); IcmpCloseHandle(h); }
    }

    private static SOCKADDR_IN6 ToSockAddr(IPAddress ip)
    {
        var a = new SOCKADDR_IN6 { Family = 23, Addr = new byte[16] };
        ip.GetAddressBytes().CopyTo(a.Addr, 0);
        a.ScopeId = (uint)ip.ScopeId;
        return a;
    }

    /// <summary>Maps an IP_STATUS code to our status. For packet-too-big the reply field may carry the next-hop MTU.</summary>
    internal static ProbeResult FromStatus(uint status, uint? rtt, uint mtuCandidate)
    {
        switch (status)
        {
            case IP_SUCCESS: return new(ProbeStatus.Success, (int)(rtt ?? 0));
            case IP_REQ_TIMED_OUT: return new(ProbeStatus.TimedOut);
            case IP_PACKET_TOO_BIG:
                // Only trust values that look like a real MTU.
                int? mtu = mtuCandidate is >= 576 and <= 65535 ? (int)mtuCandidate : null;
                return new(ProbeStatus.PacketTooBig, null, mtu);
            case >= 11002 and <= 11008: // net/host/protocol/port unreachable, no resources, bad option, hw error
                return new(ProbeStatus.Unreachable, Detail: $"IP_STATUS {status}");
            case 1229 or 1231 or 1232: // Win32: network/host unreachable (no route, no IPv6 connectivity)
                return new(ProbeStatus.Unreachable, Detail: status == 1231 ? "Network unreachable (no route)" : $"Win32 error {status}");
            case 11013 or 11014: // TTL expired
                return new(ProbeStatus.Unreachable, Detail: "TTL expired in transit");
            default:
                return new(ProbeStatus.Error, Detail: $"IP_STATUS {status}");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IP_OPTION_INFORMATION { public byte Ttl, Tos, Flags, OptionsSize; public IntPtr OptionsData; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN6
    {
        public ushort Family, Port; public uint FlowInfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Addr;
        public uint ScopeId;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr IcmpCreateFile();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr Icmp6CreateFile();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern bool IcmpCloseHandle(IntPtr h);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2Ex(IntPtr h, IntPtr evt, IntPtr apc, IntPtr ctx, uint source, uint dest,
        byte[] data, ushort size, ref IP_OPTION_INFORMATION opt, IntPtr reply, uint replySize, uint timeout);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint Icmp6SendEcho2(IntPtr h, IntPtr evt, IntPtr apc, IntPtr ctx, ref SOCKADDR_IN6 source, ref SOCKADDR_IN6 dest,
        byte[] data, ushort size, ref IP_OPTION_INFORMATION opt, IntPtr reply, uint replySize, uint timeout);
}
