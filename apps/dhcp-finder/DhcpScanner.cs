using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace DhcpFinder;

/// <summary>An IPv4 network adapter that can be probed.</summary>
public sealed record AdapterInfo(string Name, string Description, IPAddress Address, IPAddress Mask, byte[] Mac)
{
    public string MacText => string.Join("-", Mac.Select(b => b.ToString("X2")));
    public override string ToString() => $"{Name}  —  {Address}  ({Description})";
}

/// <summary>One DHCPOFFER received from a server.</summary>
public sealed class DhcpOffer
{
    public required string Adapter { get; init; }
    public required IPAddress ServerId { get; init; }
    public required IPAddress ReplySource { get; init; }
    public required IPAddress OfferedIp { get; init; }
    public IPAddress? RelayAgent { get; init; }
    public IPAddress? SubnetMask { get; init; }
    public List<IPAddress> Routers { get; init; } = [];
    public List<IPAddress> DnsServers { get; init; } = [];
    public string? DomainName { get; init; }
    public TimeSpan? LeaseTime { get; init; }
    public string? ServerHostName { get; init; }
    public int ResponseMs { get; init; }
}

public static class DhcpScanner
{
    private const int ServerPort = 67;
    private const int ClientPort = 68;
    private const uint MagicCookie = 0x63825363;

    public static List<AdapterInfo> GetAdapters()
    {
        var list = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var mac = nic.GetPhysicalAddress().GetAddressBytes();
            if (mac.Length != 6) continue;

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                list.Add(new AdapterInfo(nic.Name, nic.Description, ua.Address, ua.IPv4Mask, mac));
            }
        }
        return list;
    }

    /// <summary>
    /// Broadcasts DHCPDISCOVER on the adapter and collects every DHCPOFFER received
    /// within the listen window. No DHCPREQUEST is ever sent, so no lease is taken.
    /// </summary>
    public static async Task<List<DhcpOffer>> ProbeAsync(
        AdapterInfo adapter, TimeSpan listen, bool randomMac, int attempts,
        Action<string>? log, CancellationToken ct)
    {
        var offers = new List<DhcpOffer>();
        var mac = randomMac ? RandomMac() : adapter.Mac;
        var xid = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));

        using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        sock.EnableBroadcast = true;
        try
        {
            sock.Bind(new IPEndPoint(adapter.Address, ClientPort));
        }
        catch (SocketException ex)
        {
            log?.Invoke($"[{adapter.Name}] Could not bind {adapter.Address}:{ClientPort} — {ex.Message}");
            return offers;
        }

        var packet = BuildDiscover(xid, mac);
        var target = new IPEndPoint(IPAddress.Broadcast, ServerPort);
        var start = Environment.TickCount64;
        log?.Invoke($"[{adapter.Name}] Sending DHCPDISCOVER from {adapter.Address} (MAC {string.Join("-", mac.Select(b => b.ToString("X2")))}, xid 0x{xid:X8})");

        // Send a few discovers spaced across the window to tolerate packet loss.
        var sendTask = Task.Run(async () =>
        {
            for (int i = 0; i < attempts && !ct.IsCancellationRequested; i++)
            {
                try { await sock.SendToAsync(packet, SocketFlags.None, target, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                { log?.Invoke($"[{adapter.Name}] Send failed: {ex.Message}"); }
                try { await Task.Delay(listen / Math.Max(attempts, 1) , ct); } catch (OperationCanceledException) { }
            }
        }, ct);

        var buf = new byte[1500];
        var seen = new HashSet<string>();
        using var windowCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        windowCts.CancelAfter(listen);

        while (!windowCts.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await sock.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), windowCts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }

            var offer = ParseOffer(buf.AsSpan(0, res.ReceivedBytes), xid, adapter.Name,
                ((IPEndPoint)res.RemoteEndPoint).Address, (int)(Environment.TickCount64 - start));
            if (offer is null) continue;

            var key = $"{offer.ServerId}|{offer.ReplySource}";
            if (seen.Add(key))
            {
                offers.Add(offer);
                log?.Invoke($"[{adapter.Name}] OFFER from {offer.ServerId} (via {offer.ReplySource}) offering {offer.OfferedIp} in {offer.ResponseMs} ms");
            }
        }

        try { await sendTask; } catch { /* ignore */ }
        if (offers.Count == 0) log?.Invoke($"[{adapter.Name}] No offers received.");
        return offers;
    }

    private static byte[] RandomMac()
    {
        var m = RandomNumberGenerator.GetBytes(6);
        m[0] = (byte)((m[0] & 0xFC) | 0x02); // locally administered, unicast
        return m;
    }

    private static byte[] BuildDiscover(uint xid, byte[] mac)
    {
        var p = new byte[300];
        p[0] = 1;            // op: BOOTREQUEST
        p[1] = 1;            // htype: Ethernet
        p[2] = 6;            // hlen
        p[3] = 0;            // hops
        WriteU32(p, 4, xid);
        // secs = 0, flags = broadcast so servers reply to 255.255.255.255
        p[10] = 0x80;
        // ciaddr/yiaddr/siaddr/giaddr = 0
        Array.Copy(mac, 0, p, 28, 6);
        WriteU32(p, 236, MagicCookie);

        int o = 240;
        p[o++] = 53; p[o++] = 1; p[o++] = 1;                   // DHCPDISCOVER
        p[o++] = 61; p[o++] = 7; p[o++] = 1;                   // client identifier
        Array.Copy(mac, 0, p, o, 6); o += 6;
        p[o++] = 55; p[o++] = 6;                               // parameter request list
        p[o++] = 1; p[o++] = 3; p[o++] = 6; p[o++] = 15; p[o++] = 51; p[o++] = 54;
        var vendor = "DhcpFinder"u8.ToArray();
        p[o++] = 60; p[o++] = (byte)vendor.Length;             // vendor class
        Array.Copy(vendor, 0, p, o, vendor.Length); o += vendor.Length;
        p[o++] = 255;                                          // end
        return p;
    }

    private static DhcpOffer? ParseOffer(ReadOnlySpan<byte> d, uint xid, string adapter, IPAddress from, int ms)
    {
        if (d.Length < 240 || d[0] != 2) return null;               // BOOTREPLY
        if (ReadU32(d, 4) != xid) return null;
        if (ReadU32(d, 236) != MagicCookie) return null;

        byte msgType = 0;
        IPAddress? serverId = null, mask = null;
        var routers = new List<IPAddress>();
        var dns = new List<IPAddress>();
        string? domain = null;
        TimeSpan? lease = null;

        int i = 240;
        while (i < d.Length)
        {
            byte code = d[i++];
            if (code == 0) continue;
            if (code == 255 || i >= d.Length) break;
            int len = d[i++];
            if (i + len > d.Length) break;
            var v = d.Slice(i, len);
            switch (code)
            {
                case 53 when len >= 1: msgType = v[0]; break;
                case 54 when len >= 4: serverId = new IPAddress(v[..4]); break;
                case 1 when len >= 4: mask = new IPAddress(v[..4]); break;
                case 3: routers.AddRange(Addrs(v)); break;
                case 6: dns.AddRange(Addrs(v)); break;
                case 15: domain = System.Text.Encoding.ASCII.GetString(v).TrimEnd('\0'); break;
                case 51 when len >= 4: lease = TimeSpan.FromSeconds(ReadU32(v, 0)); break;
            }
            i += len;
        }

        if (msgType != 2) return null;                              // DHCPOFFER only

        var giaddr = new IPAddress(d.Slice(24, 4));
        var sname = System.Text.Encoding.ASCII.GetString(d.Slice(44, 64)).Split('\0')[0];

        return new DhcpOffer
        {
            Adapter = adapter,
            ServerId = serverId ?? new IPAddress(d.Slice(20, 4)),
            ReplySource = from,
            OfferedIp = new IPAddress(d.Slice(16, 4)),
            RelayAgent = giaddr.Equals(IPAddress.Any) ? null : giaddr,
            SubnetMask = mask,
            Routers = routers,
            DnsServers = dns,
            DomainName = string.IsNullOrWhiteSpace(domain) ? null : domain,
            LeaseTime = lease,
            ServerHostName = string.IsNullOrWhiteSpace(sname) ? null : sname,
            ResponseMs = ms,
        };
    }

    private static IEnumerable<IPAddress> Addrs(ReadOnlySpan<byte> v)
    {
        var r = new List<IPAddress>();
        for (int k = 0; k + 4 <= v.Length; k += 4) r.Add(new IPAddress(v.Slice(k, 4)));
        return r;
    }

    private static void WriteU32(byte[] b, int o, uint v)
    {
        b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v;
    }

    private static uint ReadU32(ReadOnlySpan<byte> b, int o) =>
        (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]);
}
