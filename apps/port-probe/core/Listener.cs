using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PortProbe.Core;

public sealed record ListenerEvent(DateTime Time, Proto Proto, int Port, string Message)
{
    public override string ToString() => $"{Time:HH:mm:ss}  {(Proto == Proto.Udp ? "UDP" : "TCP")} {Port,-5}  {Message}";
}

/// <summary>
/// Opens TCP and UDP listeners. TCP: sends a banner naming this tool and host, then closes.
/// UDP: echoes back a signed reply. Every connection is reported through <see cref="Event"/>.
/// </summary>
public sealed class PortListener : IDisposable
{
    private readonly List<TcpListener> _tcp = [];
    private readonly List<UdpClient> _udp = [];
    private readonly CancellationTokenSource _cts = new();
    private readonly string _host = Environment.MachineName;

    public event Action<ListenerEvent>? Event;
    public int ActiveCount => _tcp.Count + _udp.Count;

    /// <summary>Starts a listener per port. Returns the ports that failed to open (already in use, no permission…).</summary>
    public List<(PortSpec Spec, string Error)> Start(IEnumerable<PortSpec> specs, IPAddress bindAddress)
    {
        var failures = new List<(PortSpec, string)>();
        foreach (var s in specs)
        {
            try
            {
                if (s.Proto == Proto.Tcp) StartTcp(s.Port, bindAddress); else StartUdp(s.Port, bindAddress);
            }
            catch (SocketException ex) { failures.Add((s, ex.SocketErrorCode == SocketError.AddressAlreadyInUse ? "port already in use" : ex.Message)); }
        }
        return failures;
    }

    private void StartTcp(int port, IPAddress addr)
    {
        var l = new TcpListener(addr, port);
        l.Start(64);
        _tcp.Add(l);
        _ = Task.Run(() => AcceptLoop(l, port));
    }

    private async Task AcceptLoop(TcpListener l, int port)
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await l.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false); }
            catch { return; }
            _ = Task.Run(async () =>
            {
                using (c)
                {
                    string remote = c.Client.RemoteEndPoint?.ToString() ?? "?";
                    try
                    {
                        var banner = Encoding.ASCII.GetBytes($"{Prober.Signature} v1 {_host}\r\n");
                        await c.GetStream().WriteAsync(banner, _cts.Token).ConfigureAwait(false);
                        Event?.Invoke(new ListenerEvent(DateTime.Now, Proto.Tcp, port, $"connection from {remote} — banner sent"));
                    }
                    catch (Exception ex) { Event?.Invoke(new ListenerEvent(DateTime.Now, Proto.Tcp, port, $"connection from {remote} — {ex.Message}")); }
                }
            });
        }
    }

    private void StartUdp(int port, IPAddress addr)
    {
        var u = new UdpClient(new IPEndPoint(addr, port));
        // Stop Windows turning ICMP errors for our replies into receive exceptions.
        try { u.Client.IOControl((IOControlCode)(-1744830452), [0], null); } catch { /* not supported: ignore */ }
        _udp.Add(u);
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try { r = await u.ReceiveAsync(_cts.Token).ConfigureAwait(false); }
                catch (SocketException) { continue; }
                catch { return; }
                try
                {
                    var reply = Encoding.ASCII.GetBytes($"{Prober.Signature}-ECHO v1 {_host}");
                    await u.SendAsync(reply, reply.Length, r.RemoteEndPoint).ConfigureAwait(false);
                    Event?.Invoke(new ListenerEvent(DateTime.Now, Proto.Udp, port, $"datagram from {r.RemoteEndPoint} ({r.Buffer.Length} bytes) — echoed"));
                }
                catch (Exception ex) { Event?.Invoke(new ListenerEvent(DateTime.Now, Proto.Udp, port, $"datagram from {r.RemoteEndPoint} — {ex.Message}")); }
            }
        });
    }

    public void Stop()
    {
        _cts.Cancel();
        foreach (var l in _tcp) try { l.Stop(); } catch { }
        foreach (var u in _udp) try { u.Close(); } catch { }
        _tcp.Clear(); _udp.Clear();
    }

    public void Dispose() { Stop(); _cts.Dispose(); }
}
