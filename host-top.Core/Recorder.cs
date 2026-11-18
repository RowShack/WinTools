using System.Globalization;
using System.Text;

namespace HostTop.Core;

/// <summary>Writes one CSV line per active remote host per second (time, host, down/up bytes per second, processes) for a fixed duration.</summary>
public sealed class CsvRecorder : IDisposable
{
    private readonly StreamWriter _w;
    private readonly DateTime _until;
    private readonly Func<string, string>? _nameOf;
    public bool Finished { get; private set; }
    public long Lines { get; private set; }

    public CsvRecorder(string path, TimeSpan duration, DateTime now, Func<string, string>? nameOf = null)
    {
        _w = new StreamWriter(path, false, new UTF8Encoding(false));
        _w.WriteLine("time,remote_ip,host_name,down_bytes_per_s,up_bytes_per_s,connections,processes");
        _until = now + duration; _nameOf = nameOf;
    }

    public void Record(FlowSnapshot snap)
    {
        if (Finished) return;
        foreach (var h in snap.Hosts)
        {
            if (h.DownRate <= 0 && h.UpRate <= 0) continue;
            _w.WriteLine(string.Join(',', new[]
            {
                snap.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), CsvExport.Quote(h.Name),
                CsvExport.Quote(_nameOf?.Invoke(h.Name) ?? ""), h.DownRate.ToString("0", CultureInfo.InvariantCulture),
                h.UpRate.ToString("0", CultureInfo.InvariantCulture), h.Count.ToString(CultureInfo.InvariantCulture), CsvExport.Quote(h.Related),
            }));
            Lines++;
        }
        _w.Flush();
        if (snap.Time >= _until) Dispose();
    }

    public void Dispose()
    {
        if (Finished) return;
        Finished = true; _w.Dispose();
    }
}
