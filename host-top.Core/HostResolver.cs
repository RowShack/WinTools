using System.Collections.Concurrent;
using System.Net;

namespace HostTop.Core;

/// <summary>
/// Async cached reverse DNS. <see cref="TryGet"/> never blocks: it returns what is cached (or null) and starts a
/// background lookup the first time an address is asked for.
/// </summary>
public sealed class HostResolver
{
    private readonly ConcurrentDictionary<IPAddress, string> _cache = new();   // "" = looked up, no name
    private readonly ConcurrentDictionary<IPAddress, byte> _pending = new();
    private readonly SemaphoreSlim _gate = new(6);
    private readonly Func<IPAddress, CancellationToken, Task<string?>> _lookup;
    private readonly TimeSpan _timeout;
    private readonly CancellationTokenSource _cts = new();

    public bool Enabled { get; set; } = true;

    public HostResolver(Func<IPAddress, CancellationToken, Task<string?>>? lookup = null, TimeSpan? timeout = null)
    {
        _lookup = lookup ?? DefaultLookup;
        _timeout = timeout ?? TimeSpan.FromSeconds(4);
    }

    private static async Task<string?> DefaultLookup(IPAddress ip, CancellationToken ct)
    {
        try { return (await Dns.GetHostEntryAsync(ip).WaitAsync(ct).ConfigureAwait(false)).HostName; }
        catch { return null; }
    }

    public string? TryGet(IPAddress ip)
    {
        if (_cache.TryGetValue(ip, out var n)) return n == "" ? null : n;
        if (Enabled && _pending.TryAdd(ip, 0)) _ = ResolveAsync(ip);
        return null;
    }

    public bool IsResolved(IPAddress ip) => _cache.ContainsKey(ip);

    private async Task ResolveAsync(IPAddress ip)
    {
        string? name = null;
        try
        {
            await _gate.WaitAsync(_cts.Token).ConfigureAwait(false);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                cts.CancelAfter(_timeout);
                var t = _lookup(ip, cts.Token);
                if (await Task.WhenAny(t, Task.Delay(_timeout, _cts.Token)).ConfigureAwait(false) == t) name = await t.ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }
        catch { /* cancelled or failed: remember "no name" */ }
        _cache[ip] = name ?? "";
        _pending.TryRemove(ip, out _);
    }

    public void Stop() => _cts.Cancel();
}
