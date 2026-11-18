using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace PktmonGui.Core;

/// <summary>One packet event from <c>pktmon etl2txt</c>: a header line plus the tab-indented decode lines under it.</summary>
public sealed class PacketRow
{
    public int Index { get; init; }
    public string Time { get; init; } = "";
    public string Direction { get; init; } = "";
    public string Type { get; init; } = "";
    public int Component { get; init; }
    public int Size { get; init; }
    public string Source { get; init; } = "";
    public string Destination { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string Info { get; init; } = "";
    public bool IsDrop { get; init; }
    public string DropReason { get; init; } = "";
    /// <summary>The unmodified text of this event, for the detail pane and "copy".</summary>
    public string Raw { get; init; } = "";

    /// <summary>Case-insensitive match of every space-separated word in <paramref name="filter"/> against the row's text.</summary>
    public bool Matches(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        foreach (var w in filter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (w == "drop" || w == "drops") { if (!IsDrop) return false; continue; }
            bool hit = Source.Contains(w, StringComparison.OrdinalIgnoreCase) || Destination.Contains(w, StringComparison.OrdinalIgnoreCase)
                || Protocol.Contains(w, StringComparison.OrdinalIgnoreCase) || Info.Contains(w, StringComparison.OrdinalIgnoreCase)
                || DropReason.Contains(w, StringComparison.OrdinalIgnoreCase);
            if (!hit) return false;
        }
        return true;
    }
}

/// <summary>Turns <c>pktmon etl2txt</c> text into <see cref="PacketRow"/>s. Defensive: lines it does not understand are skipped, never fatal.</summary>
public static class PacketParser
{
    private static readonly Regex Header = new(
        @"^\[\d+\][0-9A-Fa-f.]+::(?<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) \[[^\]]+\] (?<drop>Drop: )?PktGroupId \d+, PktNumber \d+, Appearance \d+, " +
        @"Direction (?<dir>\w+)\s*, Type (?<type>[^,]*?)\s*, Component (?<comp>\d+),(?: Edge \d+,)? Filter \d+(?:, DropReason (?<reason>[^,]*?)\s*, DropLocation \S+)?, OriginalSize (?<size>\d+)",
        RegexOptions.Compiled);

    private static readonly Regex V4Ports = new(@"(?<s>\d{1,3}(?:\.\d{1,3}){3})\.(?<sp>\d+) > (?<d>\d{1,3}(?:\.\d{1,3}){3})\.(?<dp>\d+): (?<rest>.*)", RegexOptions.Compiled);
    private static readonly Regex V4NoPorts = new(@"(?<s>\d{1,3}(?:\.\d{1,3}){3}) > (?<d>\d{1,3}(?:\.\d{1,3}){3}): (?<rest>.*)", RegexOptions.Compiled);
    private static readonly Regex V6Ports = new(@"(?<s>[0-9a-fA-F]*:[0-9a-fA-F:]+)\.(?<sp>\d+) > (?<d>[0-9a-fA-F]*:[0-9a-fA-F:]+)\.(?<dp>\d+): (?<rest>.*)", RegexOptions.Compiled);
    private static readonly Regex V6NoPorts = new(@"(?<s>[0-9a-fA-F]*:[0-9a-fA-F:]+) > (?<d>[0-9a-fA-F]*:[0-9a-fA-F:]+): (?<rest>.*)", RegexOptions.Compiled);
    private static readonly Regex Arp = new(@"ARP[^:]*: (?<rest>(?:Request who-has (?<t>[^\s,]+) tell (?<f>[^\s,]+)|Reply (?<rf>[^\s,]+) is-at (?<mac>[^\s,]+)).*)", RegexOptions.Compiled);
    private static readonly Regex MacPair = new(@"(?<s>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}) > (?<d>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", RegexOptions.Compiled);
    private static readonly Regex WifiMacs = new(@"SA:(?<s>[0-9A-Fa-f-]{17}).*?DA:(?<d>[0-9A-Fa-f-]{17})|DA:(?<d2>[0-9A-Fa-f-]{17}).*?SA:(?<s2>[0-9A-Fa-f-]{17})", RegexOptions.Compiled);
    private static readonly Regex EtherType = new(@"ethertype (?<t>\w+)", RegexOptions.Compiled);

    public static List<PacketRow> Parse(string text)
    {
        var rows = new List<PacketRow>();
        string? header = null;
        var detail = new List<string>();
        void Flush()
        {
            if (header == null) return;
            var row = Build(rows.Count + 1, header, detail);
            if (row != null) rows.Add(row);
            header = null; detail.Clear();
        }
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r', ' ');
            if (line.Length == 0) continue;
            if (line[0] == '[') { Flush(); if (line.Contains("PktGroupId", StringComparison.Ordinal)) header = line; }
            else if (header != null) detail.Add(line.Trim());
        }
        Flush();
        return rows;
    }

    private static PacketRow? Build(int index, string header, List<string> detail)
    {
        var m = Header.Match(header);
        if (!m.Success) return null;
        bool drop = m.Groups["drop"].Success;
        string d = string.Join(" ", detail);
        string src = "", dst = "", proto = "", info = d;

        Match x;
        if ((x = V4Ports.Match(d)).Success || (x = V6Ports.Match(d)).Success)
        {
            src = $"{x.Groups["s"].Value}:{x.Groups["sp"].Value}"; dst = $"{x.Groups["d"].Value}:{x.Groups["dp"].Value}";
            info = x.Groups["rest"].Value;
            proto = info.StartsWith("Flags [", StringComparison.Ordinal) ? "TCP" : "UDP";
            if (proto == "UDP" && (x.Groups["sp"].Value == "53" || x.Groups["dp"].Value == "53")) proto = "DNS";
        }
        else if ((x = V4NoPorts.Match(d)).Success || (x = V6NoPorts.Match(d)).Success)
        {
            src = x.Groups["s"].Value; dst = x.Groups["d"].Value; info = x.Groups["rest"].Value;
            proto = info.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase) ? info.Contains("ICMP6", StringComparison.OrdinalIgnoreCase) ? "ICMPv6" : "ICMP" : EtherTypeOf(d, "IP");
        }
        else if ((x = Arp.Match(d)).Success)
        {
            proto = "ARP"; info = x.Groups["rest"].Value;
            if (x.Groups["f"].Success) { src = x.Groups["f"].Value; dst = x.Groups["t"].Value; }
            else { src = x.Groups["rf"].Value; dst = ""; }
        }
        else
        {
            proto = EtherTypeOf(d, "");
            if ((x = MacPair.Match(d)).Success) { src = x.Groups["s"].Value; dst = x.Groups["d"].Value; }
            else if ((x = WifiMacs.Match(d)).Success) { src = x.Groups["s"].Success ? x.Groups["s"].Value : x.Groups["s2"].Value; dst = x.Groups["d"].Success ? x.Groups["d"].Value : x.Groups["d2"].Value; }
            int colon = d.IndexOf("length ", StringComparison.Ordinal);
            if (colon >= 0) { int c = d.IndexOf(':', colon); if (c >= 0) info = d[(c + 1)..].Trim(); }
        }
        if (drop && string.IsNullOrWhiteSpace(info)) info = "dropped";

        return new PacketRow
        {
            Index = index, Time = m.Groups["ts"].Value, Direction = m.Groups["dir"].Value, Type = m.Groups["type"].Value,
            Component = int.Parse(m.Groups["comp"].Value, CultureInfo.InvariantCulture), Size = int.Parse(m.Groups["size"].Value, CultureInfo.InvariantCulture),
            Source = src, Destination = dst, Protocol = proto, Info = info.Trim(), IsDrop = drop,
            DropReason = m.Groups["reason"].Success ? m.Groups["reason"].Value : "",
            Raw = header + (detail.Count > 0 ? Environment.NewLine + string.Join(Environment.NewLine, detail) : ""),
        };
    }

    private static string EtherTypeOf(string d, string fallback)
    {
        var m = EtherType.Match(d);
        return m.Success && m.Groups["t"].Value != "Unknown" ? m.Groups["t"].Value : fallback;
    }

    public static string ToCsv(IEnumerable<PacketRow> rows)
    {
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("no,time,direction,type,component,size,source,destination,protocol,drop_reason,info\r\n");
        foreach (var r in rows)
            sb.Append(r.Index.ToString(CultureInfo.InvariantCulture)).Append(',').Append(Q(r.Time)).Append(',').Append(r.Direction).Append(',').Append(Q(r.Type)).Append(',')
              .Append(r.Component.ToString(CultureInfo.InvariantCulture)).Append(',').Append(r.Size.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(Q(r.Source)).Append(',').Append(Q(r.Destination)).Append(',').Append(r.Protocol).Append(',').Append(Q(r.DropReason)).Append(',').Append(Q(r.Info)).Append("\r\n");
        return sb.ToString();
    }
}
