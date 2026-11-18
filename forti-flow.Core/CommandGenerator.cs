using System.Net;

namespace FortiFlow.Core;

public enum PortScope { Destination, Source, Either }

public sealed class CommandRequest
{
    /// <summary>VDOM name or index. Empty = do not filter on VDOM. "root" = index 0.</summary>
    public string Vdom { get; set; } = "";
    public string Source { get; set; } = "";
    public string Destination { get; set; } = "";
    public string Port { get; set; } = "";
    public PortScope PortScope { get; set; } = PortScope.Destination;
    /// <summary>tcp, udp, icmp, a protocol number, or empty for any.</summary>
    public string Protocol { get; set; } = "";
    public int Count { get; set; } = 20;
    /// <summary>With exactly one address given, use "addr" (either direction, so replies are traced too).</summary>
    public bool BothDirections { get; set; } = true;
}

public sealed class CommandResult
{
    public bool Ok { get; set; }
    public string Error { get; set; } = "";
    public List<string> Start { get; } = new();
    public List<string> Stop { get; } = new();
    public List<string> Warnings { get; } = new();

    public string StartText => string.Join(Environment.NewLine, Start);
    public string StopText => string.Join(Environment.NewLine, Stop);
}

public static class CommandGenerator
{
    public static CommandResult Generate(CommandRequest r)
    {
        var res = new CommandResult();
        var filters = new List<string>();
        var vd = (r.Vdom ?? "").Trim();
        var src = (r.Source ?? "").Trim();
        var dst = (r.Destination ?? "").Trim();
        var port = (r.Port ?? "").Trim();
        var proto = (r.Protocol ?? "").Trim().ToLowerInvariant();
        string? vdLine = null;

        if (vd.Length > 0)
        {
            if (vd.Equals("root", StringComparison.OrdinalIgnoreCase)) vdLine = "diagnose debug flow filter vd 0";
            else if (int.TryParse(vd, out var vi) && vi >= 0) vdLine = $"diagnose debug flow filter vd {vi}";
            else
            {
                res.Error = $"VDOM '{vd}': the flow filter takes the VDOM index, not the name. Enter 'root' or the index shown by 'diagnose sys vd list'.";
                return res;
            }
        }

        foreach (var (label, value) in new[] { ("Source", src), ("Destination", dst) })
        {
            if (value.Length > 0 && !IsAddress(value))
            {
                res.Error = $"{label} '{value}' is not a valid IPv4/IPv6 address.";
                return res;
            }
        }

        if (src.Length > 0 && dst.Length > 0)
        {
            filters.Add($"diagnose debug flow filter saddr {src}");
            filters.Add($"diagnose debug flow filter daddr {dst}");
            if (r.BothDirections)
                res.Warnings.Add("saddr + daddr only match one direction: reply packets (source and destination swapped) are not shown. Fill in only one address to trace both directions.");
        }
        else if (src.Length > 0 || dst.Length > 0)
        {
            var a = src.Length > 0 ? src : dst;
            if (r.BothDirections) filters.Add($"diagnose debug flow filter addr {a}");
            else filters.Add($"diagnose debug flow filter {(src.Length > 0 ? "saddr" : "daddr")} {a}");
        }

        if (port.Length > 0)
        {
            if (!int.TryParse(port, out var pn) || pn < 1 || pn > 65535)
            {
                res.Error = $"Port '{port}' is not a number between 1 and 65535.";
                return res;
            }
            var kw = r.PortScope switch { PortScope.Source => "sport", PortScope.Either => "port", _ => "dport" };
            filters.Add($"diagnose debug flow filter {kw} {pn}");
            if (proto == "icmp") res.Warnings.Add("ICMP has no ports - the port filter will match nothing.");
        }

        if (proto.Length > 0)
        {
            string? num = proto switch
            {
                "tcp" => "6", "udp" => "17", "icmp" => "1", "esp" => "50", "gre" => "47", "any" => null,
                _ => int.TryParse(proto, out var n) && n is >= 0 and <= 255 ? n.ToString() : "invalid",
            };
            if (num == "invalid") { res.Error = $"Protocol '{proto}' is not tcp, udp, icmp or a protocol number (0-255)."; return res; }
            if (num != null) filters.Add($"diagnose debug flow filter proto {num}");
        }

        if (filters.Count == 0)
        {
            res.Error = "Refusing to generate an unfiltered trace: on a busy firewall it floods the CPU and the console. " +
                        "Enter at least one of source, destination, port or protocol.";
            return res;
        }
        if (r.Count < 1) { res.Error = "Packet count must be at least 1."; return res; }
        if (r.Count > 1000) res.Warnings.Add("A trace count above 1000 produces a lot of output; use a smaller number if you can.");

        if (vdLine != null)
            res.Warnings.Add("Multi-VDOM units: run the commands inside the VDOM (type 'config vdom', then 'edit <name>') and use that VDOM's index here. Skip the VDOM field on single-VDOM units.");
        res.Start.Add("diagnose debug reset");
        if (vdLine != null) res.Start.Add(vdLine);
        res.Start.AddRange(filters);
        res.Start.Add("diagnose debug flow show function-name enable");
        res.Start.Add($"diagnose debug flow trace start {r.Count}");
        res.Start.Add("diagnose debug enable");

        res.Stop.Add("diagnose debug disable");
        res.Stop.Add("diagnose debug reset");
        res.Ok = true;
        return res;
    }

    static bool IsAddress(string s) => IPAddress.TryParse(s, out var ip) && !s.Contains('/') &&
        (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && s.Count(ch => ch == '.') == 3
         || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

    public static readonly string[] Notes =
    {
        "Established sessions can be offloaded to the NPU, so their packets do not appear in the trace. To see a new flow from the start, clear the session first ('diagnose sys session filter ...' then 'diagnose sys session clear') - ONLY on a test host: clearing sessions interrupts live traffic.",
        "Run these commands over SSH (or the console). The web GUI CLI console may not stream debug output.",
        "Always run the stop commands afterwards: debug output left enabled keeps costing CPU and is shown to every admin session. It also stops by itself after the packet count is reached, but 'diagnose debug disable' and 'diagnose debug reset' are still the clean way to finish.",
        "'show function-name enable' adds the id=/trace_id=/func= prefixes that FortiFlow uses to group lines per packet. The parser also reads output without them.",
    };
}
