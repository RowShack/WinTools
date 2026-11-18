namespace FortiFlow.Core;

public enum Verdict { Unknown, Forwarded, Dropped, LocalIn }

public enum InputFormat { Unknown, GuiCsv, CliPrefixed, CliPlain }

/// <summary>One cleaned-up message line from the input.</summary>
public sealed class LogLine
{
    public int Number { get; init; }
    public string Text { get; set; } = "";
    public string Raw { get; set; } = "";
    public int? TraceId { get; init; }
    public string? Time { get; init; }
    public string? Func { get; init; }
    /// <summary>True for the bare-number separator lines of the GUI export.</summary>
    public bool Separator { get; init; }
}

/// <summary>One card in the timeline of a packet.</summary>
public sealed class Step
{
    public string Card { get; set; } = "unknown";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public bool Minor { get; set; }
    public bool Verified { get; set; } = true;
    public string[] Versions { get; set; } = Array.Empty<string>();
    public string? RuleId { get; set; }
    public string? Explain { get; set; }
    public string? NextCheck { get; set; }
    public bool IsDeciding { get; set; }
    public string Effect { get; set; } = "none";
    public List<LogLine> Lines { get; } = new();
    /// <summary>Individual cards folded into this one (policy checks, technical details).</summary>
    public List<Step> Children { get; } = new();
    public Dictionary<string, string> Fields { get; } = new();
}

public sealed class PacketTrace
{
    public int Index { get; set; }
    public int? TraceId { get; set; }
    public string? Time { get; set; }
    public string Vdom { get; set; } = "";
    public string Proto { get; set; } = "";
    public string ProtoName { get; set; } = "";
    public string Src { get; set; } = "";
    public string SrcPort { get; set; } = "";
    public string Dst { get; set; } = "";
    public string DstPort { get; set; } = "";
    public string Iface { get; set; } = "";
    public string Flags { get; set; } = "";
    public string? SessionId { get; set; }
    /// <summary>"original", "reply" or "" when no session line was seen.</summary>
    public string Direction { get; set; } = "";
    public bool NewSession { get; set; }
    public bool NoSession { get; set; }
    public bool HasHeader { get; set; }
    public bool IsFastPath { get; set; }
    public string? Egress { get; set; }
    public string? OutDevice { get; set; }
    public string? Tunnel { get; set; }
    public string? Policy { get; set; }
    public List<LogLine> Lines { get; } = new();
    public List<Step> Steps { get; } = new();

    public Verdict Verdict { get; set; } = Verdict.Unknown;
    public string VerdictTitle { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string NextCheck { get; set; } = "";
    public Step? Deciding { get; set; }
    public bool DecidedByUnverifiedRule { get; set; }
    public bool UsesUnverifiedRule { get; set; }
    public List<string> Notes { get; } = new();

    internal bool HasStartLine;

    public string Label
    {
        get
        {
            if (!HasHeader) return $"#{Index} (no packet header)";
            var dir = Direction == "reply" ? "reply" : Direction == "original" ? "orig" : "";
            return $"#{Index}  {ProtoName} {Src}:{SrcPort} → {Dst}:{DstPort}" + (dir != "" ? $"  [{dir}]" : "");
        }
    }
}

public sealed class SessionGroup
{
    public string Id { get; set; } = "";
    public List<PacketTrace> Packets { get; } = new();
    public Verdict Verdict { get; set; }
    public string Label
    {
        get
        {
            var o = Packets.FirstOrDefault(p => p.Direction == "original") ?? Packets[0];
            return $"session {Id}  {o.ProtoName} {o.Src}:{o.SrcPort} → {o.Dst}:{o.DstPort}  ({Packets.Count} pkt)";
        }
    }
}

public sealed class AnalysisResult
{
    public List<PacketTrace> Packets { get; } = new();
    public List<SessionGroup> Sessions { get; } = new();
    public InputFormat Format { get; set; }
    public int TotalLines { get; set; }
    public int IgnoredLines { get; set; }
    public int UnknownLines { get; set; }
    public string RulesMessage { get; set; } = "";
}
