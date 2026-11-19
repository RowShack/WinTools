using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PktmonGui.Core;

public enum CaptureType { All, Flow, Drop }
public enum LogMode { Circular, MultiFile }

public sealed class CaptureOptions
{
    /// <summary>Component ids to capture on; empty = NICs only (avoids duplicate packets from multiple layers).</summary>
    public List<int> ComponentIds { get; set; } = [];
    public bool AllComponents { get; set; }
    public CaptureType Type { get; set; } = CaptureType.All;
    /// <summary>0 = whole packet; null = pktmon default (128 bytes).</summary>
    public int? PacketSize { get; set; } = 0;
    public LogMode LogMode { get; set; } = LogMode.Circular;
    public int FileSizeMb { get; set; } = 512;
    public string EtlPath { get; set; } = "PktMon.etl";
    public bool ConvertToText { get; set; }
}

/// <summary>Flags we only pass if this build's pktmon says it knows them (checked from <c>pktmon start help</c>).</summary>
public sealed record PktmonFeatures(bool Etl2Pcap, bool PktSize, bool LogMode, bool CompSelector, bool TypeSelector, bool Json)
{
    public static readonly PktmonFeatures All = new(true, true, true, true, true, true);

    public static PktmonFeatures FromHelp(string mainHelp, string startHelp, string listHelp) => new(
        mainHelp.Contains("etl2pcap", StringComparison.OrdinalIgnoreCase),
        startHelp.Contains("--pkt-size", StringComparison.OrdinalIgnoreCase),
        startHelp.Contains("--log-mode", StringComparison.OrdinalIgnoreCase),
        startHelp.Contains("--comp", StringComparison.OrdinalIgnoreCase),
        startHelp.Contains("--type", StringComparison.OrdinalIgnoreCase),
        listHelp.Contains("--json", StringComparison.OrdinalIgnoreCase));
}

public static class CommandBuilder
{
    public static string StartArguments(CaptureOptions o, PktmonFeatures f, out List<string> skipped)
    {
        skipped = [];
        var a = new List<string> { "start", "--capture" };
        if (f.CompSelector)
        {
            if (o.AllComponents) a.AddRange(["--comp", "all"]);
            else if (o.ComponentIds.Count > 0) a.AddRange(["--comp", ..o.ComponentIds.Select(i => i.ToString())]);
            else a.AddRange(["--comp", "nics"]);
        }
        else skipped.Add("--comp (this pktmon build can't select components; all components are captured)");
        if (f.TypeSelector) { if (o.Type != CaptureType.All) a.AddRange(["--type", o.Type.ToString().ToLowerInvariant()]); }
        else if (o.Type != CaptureType.All) skipped.Add("--type");
        if (o.PacketSize is int ps)
        {
            if (f.PktSize) a.AddRange(["--pkt-size", Math.Max(0, ps).ToString()]); else skipped.Add("--pkt-size (packets will be truncated to the default size)");
        }
        a.AddRange(["--file-name", Quote(o.EtlPath), "--file-size", Math.Max(1, o.FileSizeMb).ToString()]);
        if (f.LogMode) a.AddRange(["--log-mode", o.LogMode == LogMode.MultiFile ? "multi-file" : "circular"]);
        else skipped.Add("--log-mode");
        return string.Join(" ", a);
    }

    public static string Etl2PcapArguments(string etl, string pcapng) => $"etl2pcap {Quote(etl)} --out {Quote(pcapng)}";
    public static string Etl2TxtArguments(string etl, string txt) => $"etl2txt {Quote(etl)} --out {Quote(txt)}";

    /// <summary>The exact command list a run executes, for the read-only "commands" pane.</summary>
    public static List<string> Preview(CaptureOptions o, IReadOnlyList<FilterSpec> filters, PktmonFeatures f)
    {
        var l = new List<string> { "pktmon filter remove" };
        for (int i = 0; i < filters.Count; i++) l.Add("pktmon " + filters[i].ToArguments(i));
        l.Add("pktmon " + StartArguments(o, f, out _));
        l.Add("pktmon stop");
        string pcap = Path.ChangeExtension(o.EtlPath, ".pcapng");
        if (f.Etl2Pcap) l.Add("pktmon " + Etl2PcapArguments(o.EtlPath, pcap));
        if (o.ConvertToText) l.Add("pktmon " + Etl2TxtArguments(o.EtlPath, Path.ChangeExtension(o.EtlPath, ".txt")));
        l.Add("pktmon filter remove");
        return l;
    }

    /// <summary>A copy-paste PowerShell script for servers where the GUI can't be run.</summary>
    public static string RemoteScript(CaptureOptions o, IReadOnlyList<FilterSpec> filters, PktmonFeatures f, int seconds)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Run in an ELEVATED PowerShell. Captures for a fixed time, always cleans up.");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine($"$etl = Join-Path $env:TEMP 'capture-{DateTime.Now:yyyyMMdd-HHmmss}.etl'");
        sb.AppendLine("try {");
        sb.AppendLine("  pktmon filter remove");
        for (int i = 0; i < filters.Count; i++) sb.AppendLine("  pktmon " + filters[i].ToArguments(i));
        var local = new CaptureOptions
        {
            ComponentIds = o.ComponentIds, AllComponents = o.AllComponents, Type = o.Type, PacketSize = o.PacketSize,
            LogMode = o.LogMode, FileSizeMb = o.FileSizeMb, EtlPath = "$etl",
        };
        sb.AppendLine("  pktmon " + StartArguments(local, f, out _).Replace("\"$etl\"", "$etl"));
        sb.AppendLine($"  Write-Host 'Capturing for {Math.Max(1, seconds)} seconds... reproduce the problem now.'");
        sb.AppendLine($"  Start-Sleep -Seconds {Math.Max(1, seconds)}");
        sb.AppendLine("} finally {");
        sb.AppendLine("  pktmon stop");
        sb.AppendLine("  pktmon filter remove");
        sb.AppendLine("}");
        if (f.Etl2Pcap) sb.AppendLine("pktmon etl2pcap $etl --out ($etl -replace '\\.etl$','.pcapng')");
        sb.AppendLine("Write-Host \"Saved: $etl\"");
        return sb.ToString();
    }

    private static string Quote(string path) => path.StartsWith('$') ? path : "\"" + path.Replace("\"", "") + "\"";
}

public sealed record CaptureComponent(int Id, string Name, string Type, string? Mac, string? Ip)
{
    public override string ToString() => $"{Name}{(Ip is null ? "" : "  " + Ip)}{(Mac is null ? "" : "  " + Mac)}  [id {Id}]";
}

/// <summary>Defensive parsers: the exact output of pktmon differs between Windows builds.</summary>
public static class Parsers
{
    private static readonly Regex MacRx = new(@"\b[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}\b", RegexOptions.Compiled);
    private static readonly Regex Ip4Rx = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

    /// <summary>Parses <c>pktmon list --json</c> (any nesting) or, failing that, the text output.</summary>
    public static List<CaptureComponent> ParseComponents(string output)
    {
        output = output.Trim();
        if (output.Length == 0) return [];
        try
        {
            using var doc = JsonDocument.Parse(output);
            var list = new List<CaptureComponent>();
            Walk(doc.RootElement, "", list);
            if (list.Count > 0) return list.DistinctBy(c => c.Id).ToList();
        }
        catch (JsonException) { /* fall through to text */ }
        return ParseComponentsText(output);
    }

    private static void Walk(JsonElement e, string groupType, List<CaptureComponent> acc)
    {
        if (e.ValueKind == JsonValueKind.Array) { foreach (var x in e.EnumerateArray()) Walk(x, groupType, acc); return; }
        if (e.ValueKind != JsonValueKind.Object) return;
        string type = Str(e, "Type") ?? Str(e, "ComponentType") ?? groupType;
        if (TryInt(e, "Id", out int id) && Str(e, "Name") is { } name)
        {
            string blob = e.GetRawText();
            acc.Add(new CaptureComponent(id, name, type, MacRx.Match(blob).Success ? MacRx.Match(blob).Value : null,
                Ip4Rx.Matches(blob).Select(m => m.Value).FirstOrDefault(v => v != "0.0.0.0")));
            return;
        }
        foreach (var p in e.EnumerateObject()) Walk(p.Value, type, acc);
    }

    private static string? Str(JsonElement e, string key) =>
        e.EnumerateObject().FirstOrDefault(p => p.Name.Equals(key, StringComparison.OrdinalIgnoreCase)) is { Value.ValueKind: JsonValueKind.String } p ? p.Value.GetString() : null;

    private static bool TryInt(JsonElement e, string key, out int v)
    {
        v = 0;
        foreach (var p in e.EnumerateObject())
            if (p.Name.Equals(key, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.Number) return p.Value.TryGetInt32(out v);
        return false;
    }

    /// <summary>Text fallback: lines that begin with a numeric id followed by a name.</summary>
    public static List<CaptureComponent> ParseComponentsText(string output)
    {
        var list = new List<CaptureComponent>();
        string group = "";
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]) && !char.IsDigit(line[0])) { group = line.Trim().TrimEnd(':'); continue; }
            var m = Regex.Match(line, @"^\s*(\d+)\s+(.+?)\s*$");
            if (!m.Success) continue;
            string rest = m.Groups[2].Value;
            list.Add(new CaptureComponent(int.Parse(m.Groups[1].Value), MacRx.Replace(Ip4Rx.Replace(rest, ""), "").Trim(), group,
                MacRx.Match(rest).Success ? MacRx.Match(rest).Value : null, Ip4Rx.Match(rest).Success ? Ip4Rx.Match(rest).Value : null));
        }
        return list;
    }

    /// <summary>Best-effort packet/drop totals from <c>pktmon counters</c> text: sums numbers following "Packets" style columns.</summary>
    public static (long Packets, long Drops) ParseCounterTotals(string text)
    {
        long packets = 0, drops = 0;
        bool inDrops = false;
        foreach (var line in text.Split('\n'))
        {
            string l = line.Trim();
            if (l.Length == 0) continue;
            if (Regex.IsMatch(l, @"drop", RegexOptions.IgnoreCase) && !Regex.IsMatch(l, @"\d")) { inDrops = true; continue; }
            if (Regex.IsMatch(l, @"flow|counters", RegexOptions.IgnoreCase) && !Regex.IsMatch(l, @"\d")) { inDrops = Regex.IsMatch(l, "drop", RegexOptions.IgnoreCase); continue; }
            // Trailing run of numeric columns, taken as (packets, bytes) pairs; an odd leftover is part of the name ("Ethernet 2").
            var tokens = l.Split([' ', '	'], StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 3 || !Regex.IsMatch(tokens[0], @"^\d+$")) continue;
            var nums = new List<long>();
            for (int i = tokens.Length - 1; i >= 1; i--)
            {
                if (!Regex.IsMatch(tokens[i], @"^\d{1,3}(,\d{3})*$|^\d+$")) break;
                nums.Insert(0, long.Parse(tokens[i].Replace(",", "")));
            }
            if (nums.Count % 2 == 1) nums.RemoveAt(0);
            for (int i = 0; i + 1 < nums.Count; i += 2)
                if (inDrops) drops += nums[i]; else packets += nums[i];
        }
        return (packets, drops);
    }
}

public sealed record DropEntry(string Time, int? Component, string Reason, string Raw);

public static class DropParser
{
    private static readonly Regex ReasonRx = new(@"DropReason\s+(?<r>.+?)(?:,\s*DropLocation|\s*$)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex CompRx = new(@"Component\s+(?<c>\d+)", RegexOptions.Compiled);
    private static readonly Regex TimeRx = new(@"^\s*(?:\[[^\]]*\]\s*)?(?<t>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)", RegexOptions.Compiled);

    /// <summary>Extracts dropped-packet lines from <c>pktmon etl2txt</c> output.</summary>
    public static List<DropEntry> Parse(string text)
    {
        var list = new List<DropEntry>();
        foreach (var line in text.Split('\n'))
        {
            var m = ReasonRx.Match(line);
            if (!m.Success) continue;
            string reason = m.Groups["r"].Value.Trim().TrimEnd(',');
            var c = CompRx.Match(line);
            var t = TimeRx.Match(line);
            list.Add(new DropEntry(t.Success ? t.Groups["t"].Value : "", c.Success ? int.Parse(c.Groups["c"].Value) : null, reason, line.Trim()));
        }
        return list;
    }

    public static List<(string Reason, int Component, int Count)> Group(IEnumerable<DropEntry> drops) =>
        drops.GroupBy(d => (d.Reason, d.Component ?? -1)).Select(g => (g.Key.Reason, g.Key.Item2, g.Count())).OrderByDescending(g => g.Item3).ToList();
}

public sealed record CliResult(int ExitCode, string Output, string Error)
{
    public bool Ok => ExitCode == 0;
    public string Combined => (Output + Environment.NewLine + Error).Trim();
}

public static class PktmonCli
{
    public static string ExePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe");
    public static bool Exists => File.Exists(ExePath);

    public static async Task<CliResult> RunAsync(string arguments, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(ExePath, arguments)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start pktmon.exe");
        var o = p.StandardOutput.ReadToEndAsync(ct); var e = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        return new CliResult(p.ExitCode, await o, await e);
    }

    public static bool IsAdmin()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public static async Task<PktmonFeatures> DetectFeaturesAsync(CancellationToken ct = default)
    {
        string main = (await RunAsync("help", ct)).Combined;
        string start = (await RunAsync("start help", ct)).Combined;
        string list = (await RunAsync("list help", ct)).Combined;
        return PktmonFeatures.FromHelp(main, start, list);
    }

    /// <summary>True if a capture or filters appear to be left over from a previous run (heuristic on text output).</summary>
    public static async Task<(bool Running, bool HasFilters, string StatusText)> CheckLeftoversAsync(CancellationToken ct = default)
    {
        var st = await RunAsync("status", ct);
        var fl = await RunAsync("filter list", ct);
        string s = st.Combined;
        bool running = s.Length > 0 && !Regex.IsMatch(s, @"not\s+running|no\s+(active|data)|stopped", RegexOptions.IgnoreCase) && Regex.IsMatch(s, @"running|capture|counters|component", RegexOptions.IgnoreCase);
        string f = fl.Combined;
        bool filters = f.Length > 0 && !Regex.IsMatch(f, @"no\s+filters|not\s+(found|configured)|empty", RegexOptions.IgnoreCase) && Regex.IsMatch(f, @"\d+\s+\S|filter", RegexOptions.IgnoreCase) && fl.Ok;
        return (running, filters, s);
    }

    /// <summary>Stops any capture and clears filters. Safe to call repeatedly.</summary>
    public static async Task CleanupAsync()
    {
        try { await RunAsync("stop"); } catch { }
        try { await RunAsync("filter remove"); } catch { }
    }

    /// <summary>Blocking cleanup for use while the process is closing.</summary>
    public static void CleanupBlocking()
    {
        foreach (var args in new[] { "stop", "filter remove" })
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo(ExePath, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                p?.WaitForExit(8000);
            }
            catch { }
        }
    }
}

/// <summary>Remembers which component id was which adapter/driver for one capture (ids can change after a reboot), stored as components.json beside the .etl.</summary>
public static class ComponentNames
{
    public const string FileName = "components.json";

    public static void Save(string folder, IEnumerable<CaptureComponent> components)
    {
        var list = components.Select(c => new { id = c.Id, name = c.Name, type = c.Type }).ToList();
        if (list.Count == 0) return;
        File.WriteAllText(Path.Combine(folder, FileName), JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>Returns the saved id to component map, or an empty one if the file is missing or unreadable.</summary>
    public static Dictionary<int, CaptureComponent> Load(string? folder)
    {
        var map = new Dictionary<int, CaptureComponent>();
        try
        {
            string path = Path.Combine(folder ?? "", FileName);
            if (!File.Exists(path)) return map;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var e in doc.RootElement.EnumerateArray())
                if (e.TryGetProperty("id", out var id) && id.TryGetInt32(out int i))
                    map[i] = new CaptureComponent(i, e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "", e.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "", null, null);
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException) { }
        return map;
    }

    /// <summary>"18 · Intel Wi-Fi 6 AX201", or just "18" when the name is unknown.</summary>
    public static string Label(int id, IReadOnlyDictionary<int, CaptureComponent> names) =>
        names.TryGetValue(id, out var c) && c.Name.Length > 0 ? $"{id} · {c.Name}" : id.ToString();
}
