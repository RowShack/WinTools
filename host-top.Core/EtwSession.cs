using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace HostTop.Core;

/// <summary>Turns the payload of a Microsoft-Windows-Kernel-Network event into a <see cref="FlowEvent"/>. Kept free of ETW types so it can be unit-tested.</summary>
public static class EtwDecoder
{
    // Event ids of Microsoft-Windows-Kernel-Network.
    // 10/11 TCP send/receive IPv4, 26/27 TCP IPv6, 42/43 UDP IPv4, 58/59 UDP IPv6.
    public static readonly int[] EventIds = [10, 11, 26, 27, 42, 43, 58, 59];

    public static FlowEvent? Decode(int eventId, DateTime time, Func<string, object?> payload)
    {
        FlowProtocol proto; bool send;
        switch (eventId)
        {
            case 10: case 26: proto = FlowProtocol.Tcp; send = true; break;
            case 11: case 27: proto = FlowProtocol.Tcp; send = false; break;
            case 42: case 58: proto = FlowProtocol.Udp; send = true; break;
            case 43: case 59: proto = FlowProtocol.Udp; send = false; break;
            default: return null;
        }
        try
        {
            var pid = ToInt(payload("PID"));
            var size = ToLong(payload("size"));
            var daddr = ToAddress(payload("daddr"));
            var saddr = ToAddress(payload("saddr"));
            var dport = ToPort(payload("dport"));
            var sport = ToPort(payload("sport"));
            if (pid is null || daddr is null || saddr is null || dport is null || sport is null || size is null) return null;
            // Fields are packet-oriented: saddr/sport is the sender, daddr/dport the receiver.
            // For a send the local end is the source; for a receive the local end is the destination.
            return send
                ? new FlowEvent(time, pid.Value, proto, saddr, sport.Value, daddr, dport.Value, size.Value, true)
                : new FlowEvent(time, pid.Value, proto, daddr, dport.Value, saddr, sport.Value, size.Value, false);
        }
        catch { return null; }
    }

    /// <summary>
    /// The provider stores ports in network byte order, and TraceEvent may hand them back as a signed or unsigned 16-bit value.
    /// Take the low 16 bits unsigned and swap the bytes (confirmed on a real machine: 0x01BB arrives as 0xBB01).
    /// </summary>
    public static int? ToPort(object? o)
    {
        if (o is null) return null;
        int v = Convert.ToInt32(o, System.Globalization.CultureInfo.InvariantCulture) & 0xFFFF;
        return ((v & 0xFF) << 8) | (v >> 8);
    }

    private static int? ToInt(object? o) => o is null ? null : Convert.ToInt32(o, System.Globalization.CultureInfo.InvariantCulture);
    private static long? ToLong(object? o) => o is null ? null : Convert.ToInt64(o, System.Globalization.CultureInfo.InvariantCulture);

    public static IPAddress? ToAddress(object? o) => o switch
    {
        null => null,
        IPAddress a => a,
        byte[] b when b.Length is 4 or 16 => new IPAddress(b),
        uint u => new IPAddress(BitConverter.GetBytes(u)),   // stored in network byte order in the event
        int i => new IPAddress(BitConverter.GetBytes(i)),
        string s => IPAddress.TryParse(s, out var p) ? p : null,
        _ => null,
    };
}

/// <summary>
/// A real-time ETW session on Microsoft-Windows-Kernel-Network with a fixed name. It must be stopped on exit; if the process dies
/// the session would keep running, so <see cref="StopOrphan"/> is called at start-up to remove any leftover.
/// </summary>
public sealed class EtwSession : IDisposable
{
    public const string SessionName = "WinTools-HostTop";
    private static readonly Guid KernelNetwork = new("7dd42a49-5329-4832-8dfd-43d979153a88");

    private TraceEventSession? _session;
    private Task? _pump;

    public event Action<FlowEvent>? FlowReceived;
    public event Action<string>? Error;
    public bool IsRunning => _session != null;

    /// <summary>Stops a session of ours left behind by a crash. Returns true if one was found and stopped.</summary>
    public static bool StopOrphan()
    {
        try
        {
            if (!TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.OrdinalIgnoreCase)) return false;
            using var s = new TraceEventSession(SessionName, TraceEventSessionOptions.Attach);
            s.Stop();
            return true;
        }
        catch { return false; }
    }

    public void Start()
    {
        if (_session != null) return;
        StopOrphan();
        var s = new TraceEventSession(SessionName) { StopOnDispose = true };
        try
        {
            s.EnableProvider(KernelNetwork, TraceEventLevel.Informational, ulong.MaxValue);
            var parser = new RegisteredTraceEventParser(s.Source);
            parser.All += OnEvent;
        }
        catch { s.Dispose(); throw; }
        _session = s;
        _pump = Task.Run(() =>
        {
            try { s.Source.Process(); }
            catch (Exception ex) { Error?.Invoke(ex.Message); }
        });
    }

    private void OnEvent(TraceEvent e)
    {
        if (Array.IndexOf(EtwDecoder.EventIds, (int)e.ID) < 0) return;
        var fe = EtwDecoder.Decode((int)e.ID, e.TimeStamp, name => e.PayloadByName(name));
        if (fe is { } f) FlowReceived?.Invoke(f);
    }

    public void Stop()
    {
        var s = _session; _session = null;
        if (s == null) return;
        try { s.Stop(); } catch { }
        try { s.Dispose(); } catch { }
        try { _pump?.Wait(3000); } catch { }
    }

    public void Dispose() => Stop();
}
