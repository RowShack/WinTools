using System.Net;
using System.Text;

namespace FortiFlow.Core;

public static class Exporter
{
    static string Csv(string? s)
    {
        s ??= "";
        return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    public static string VerdictText(Verdict v) => v switch
    {
        Verdict.Forwarded => "Forwarded", Verdict.Dropped => "Dropped", Verdict.LocalIn => "Local-in", _ => "Unknown",
    };

    public static string ToCsv(IEnumerable<PacketTrace> packets)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Packet,Time,TraceId,Session,Direction,Protocol,Source,SrcPort,Destination,DstPort,Interface,Flags,Verdict,DecidingLine,Explanation,NextCheck");
        foreach (var p in packets)
            sb.AppendLine(string.Join(",", new[]
            {
                p.Index.ToString(), Csv(p.Time), p.TraceId?.ToString() ?? "", Csv(p.SessionId), Csv(p.Direction), Csv(p.ProtoName),
                Csv(p.Src), p.SrcPort, Csv(p.Dst), p.DstPort, Csv(p.Iface), Csv(p.Flags), VerdictText(p.Verdict),
                Csv(p.Deciding?.Lines.FirstOrDefault()?.Text), Csv(p.Explanation), Csv(p.NextCheck),
            }));
        return sb.ToString();
    }

    public static string PacketToText(PacketTrace p)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Packet {p.Label}");
        if (p.Time != null) sb.AppendLine($"Time: {p.Time}");
        if (p.SessionId != null) sb.AppendLine($"Session: {p.SessionId} ({p.Direction})");
        sb.AppendLine($"Verdict: {VerdictText(p.Verdict)} - {p.VerdictTitle}");
        if (p.Deciding?.Lines.FirstOrDefault() is { } dl) sb.AppendLine($"Deciding line: {dl.Text}");
        if (p.Explanation.Length > 0) sb.AppendLine($"Explanation: {p.Explanation}");
        if (p.NextCheck.Length > 0) sb.AppendLine($"Next check: {p.NextCheck}");
        foreach (var n in p.Notes) sb.AppendLine($"Note: {n}");
        if (p.DecidedByUnverifiedRule) sb.AppendLine("(deciding rule is unverified - confirm against a real sample)");
        sb.AppendLine("Steps:");
        int i = 0;
        foreach (var s in p.Steps)
        {
            sb.AppendLine($"  {++i}. [{s.Card}] {s.Title}{(s.IsDeciding ? "   <== deciding" : "")}{(s.Verified ? "" : "   (unverified rule)")}");
            if (s.Detail.Length > 0 && s.Card != "detail") sb.AppendLine($"       {s.Detail}");
        }
        return sb.ToString();
    }

    public static string ToText(IEnumerable<PacketTrace> packets)
    {
        var sb = new StringBuilder();
        foreach (var p in packets) { sb.Append(PacketToText(p)); sb.AppendLine(); }
        return sb.ToString();
    }

    public static string ToHtml(IEnumerable<PacketTrace> packets, string title = "FortiFlow report")
    {
        string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + E(title) + "</title><style>");
        sb.AppendLine("body{font-family:Segoe UI,sans-serif;margin:24px;color:#222}h1{font-size:20px}.p{border:1px solid #ccc;border-radius:6px;margin:12px 0;padding:10px}");
        sb.AppendLine(".Forwarded{border-left:6px solid #2e9e4f}.Dropped{border-left:6px solid #d33}.LocalIn{border-left:6px solid #2d6fd6}.Unknown{border-left:6px solid #999}");
        sb.AppendLine(".dec{background:#fff3b0}li{margin:2px 0}code{font-family:Consolas,monospace;font-size:12px}</style></head><body>");
        sb.AppendLine("<h1>" + E(title) + "</h1>");
        foreach (var p in packets)
        {
            sb.AppendLine($"<div class=\"p {p.Verdict}\"><b>{E(p.Label)}</b> &mdash; {E(VerdictText(p.Verdict))}");
            if (p.Explanation.Length > 0) sb.AppendLine($"<p>{E(p.Explanation)}</p>");
            if (p.NextCheck.Length > 0) sb.AppendLine($"<p><i>Next check:</i> {E(p.NextCheck)}</p>");
            sb.AppendLine("<ol>");
            foreach (var s in p.Steps)
                sb.AppendLine($"<li class=\"{(s.IsDeciding ? "dec" : "")}\"><b>{E(s.Title)}</b>{(s.Verified ? "" : " <em>(unverified rule)</em>")}" +
                              (s.Detail.Length > 0 && s.Card != "detail" ? $"<br><code>{E(s.Detail)}</code>" : "") + "</li>");
            sb.AppendLine("</ol></div>");
        }
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }
}
