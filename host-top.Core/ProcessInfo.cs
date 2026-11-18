using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace HostTop.Core;

/// <summary>A process as seen when its traffic was first attributed. StartTicks distinguishes a reused PID.</summary>
public sealed record ProcIdentity(int Pid, long StartTicks, string Name, string? Path)
{
    public string Id => Pid + "/" + StartTicks;
}

public interface IProcessResolver
{
    ProcIdentity Resolve(int pid);
}

/// <summary>
/// Looks up process name/path by PID and caches the result: short-lived processes vanish, so the name is
/// stored the first time a PID is seen. Entries are re-validated every few seconds so a reused PID (new
/// start time) gets a fresh identity.
/// </summary>
public sealed class ProcessInfoCache : IProcessResolver
{
    private sealed class Entry { public ProcIdentity Id = null!; public DateTime Checked; public bool Gone; }

    private readonly Dictionary<int, Entry> _cache = [];
    private readonly object _lock = new();
    private readonly TimeSpan _recheck;

    public ProcessInfoCache(TimeSpan? recheck = null) => _recheck = recheck ?? TimeSpan.FromSeconds(10);

    public ProcIdentity Resolve(int pid)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            if (_cache.TryGetValue(pid, out var e) && (e.Gone || now - e.Checked < _recheck)) return e.Id;

            var fresh = Query(pid);
            if (fresh == null)
            {
                // Process already exited (or access denied). Keep what we knew; otherwise remember a placeholder.
                if (e != null) { e.Gone = true; return e.Id; }
                e = new Entry { Id = new ProcIdentity(pid, 0, FallbackName(pid, "exited"), null), Checked = now, Gone = true };
                _cache[pid] = e;
                return e.Id;
            }
            if (e == null || e.Id.StartTicks != fresh.StartTicks)
            {
                e = new Entry { Id = fresh, Checked = now };
                _cache[pid] = e;
            }
            else e.Checked = now;
            if (_cache.Count > 20000) _cache.Clear();
            return e.Id;
        }
    }

    private static string FallbackName(int pid, string why) => pid == 4 ? "System" : pid == 0 ? "Idle / kernel" : $"PID {pid} ({why})";

    private static ProcIdentity? Query(int pid)
    {
        if (pid == 0) return new ProcIdentity(0, 0, "Idle / kernel", null);
        if (pid == 4) return new ProcIdentity(4, 0, "System", null);
        try
        {
            using var p = Process.GetProcessById(pid);
            long start;
            try { start = p.StartTime.ToUniversalTime().Ticks; } catch { start = 0; }
            return new ProcIdentity(pid, start, p.ProcessName + ".exe", ImagePath(pid));
        }
        catch { return null; }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref int size);

    public static string? ImagePath(int pid)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }
}
