using System.Text.RegularExpressions;

namespace FortiFlow.Core;

/// <summary>Groups lines into packets, applies the rules and works out the verdict of every packet.</summary>
public static class FlowAnalyzer
{
    public static Task<AnalysisResult> AnalyzeAsync(string text, RuleSet rules, CancellationToken ct = default) =>
        Task.Run(() => Analyze(text, rules, ct), ct);

    public static AnalysisResult Analyze(string text, RuleSet rules, CancellationToken ct = default)
    {
        var input = InputReader.Read(text, ct);
        var result = new AnalysisResult { Format = input.Format, IgnoredLines = input.Ignored, TotalLines = input.TotalRaw };
        if (rules.Messages.Count > 0) result.RulesMessage = string.Join(Environment.NewLine, rules.Messages);

        var packets = Group(input.Lines, ct);
        int idx = 0;
        foreach (var p in packets)
        {
            ct.ThrowIfCancellationRequested();
            p.Index = ++idx;
            Build(p, rules);
            result.UnknownLines += p.Steps.Count(s => s.Card == "unknown");
            result.Packets.Add(p);
        }
        BuildSessions(result, rules);
        return result;
    }

    // ---------- grouping ----------

    static List<PacketTrace> Group(List<LogLine> lines, CancellationToken ct)
    {
        var packets = new List<PacketTrace>();
        var open = new Dictionary<int, PacketTrace>();
        PacketTrace? cur = null;
        int n = 0;
        foreach (var line in lines)
        {
            if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            if (line.Separator) { cur = null; continue; }
            bool isStart = line.Text.Contains("received a packet(", StringComparison.Ordinal);
            PacketTrace p;
            if (line.TraceId is int tid)
            {
                if (!open.TryGetValue(tid, out p!) || (isStart && p.HasStartLine))
                {
                    p = new PacketTrace { TraceId = tid, Time = line.Time };
                    open[tid] = p; packets.Add(p);
                }
            }
            else
            {
                if (cur == null || (isStart && cur.HasStartLine))
                {
                    cur = new PacketTrace { Time = line.Time };
                    packets.Add(cur);
                }
                p = cur;
            }
            if (isStart) p.HasStartLine = true;
            p.Time ??= line.Time;
            p.Lines.Add(line);
        }
        return packets;
    }

    // ---------- per-packet analysis ----------

    sealed class Ctx
    {
        public PacketTrace P = null!;
        public Step? Offload, Route, Forward, FastPath, PolicyAllow, PolicyMatch, Decision, StrongDrop, NoSession;
        public string? DecisionAct, MatchAct;
        public string? PolicyMatchPolicy;
    }

    static void Build(PacketTrace p, RuleSet rules)
    {
        var c = new Ctx { P = p };
        var flat = new List<Step>();
        foreach (var line in p.Lines)
        {
            var step = ApplyRules(line, p, rules, out var effect, out var groups);
            flat.Add(step);
            Process(step, effect, groups, c);
        }

        p.UsesUnverifiedRule = flat.Any(s => !s.Verified);
        ComputeVerdict(p, c, rules);
        p.Steps.AddRange(Fold(flat));
    }

    static Step ApplyRules(LogLine line, PacketTrace p, RuleSet rules, out string effect, out Dictionary<string, string> groups)
    {
        groups = new Dictionary<string, string>();
        effect = "none";
        foreach (var r in rules.Rules)
        {
            if (r.When != null && !Condition(r.When, p)) continue;
            Match m;
            try { m = r.Regex!.Match(line.Text); } catch (RegexMatchTimeoutException) { continue; }
            if (!m.Success) continue;

            foreach (Group g in m.Groups)
                if (g.Success && !int.TryParse(g.Name, out _)) groups[g.Name] = g.Value;
            groups["raw"] = line.Text;
            effect = r.Effect ?? "none";
            // Header fields must exist before templates are expanded
            if (effect == "received") FillHeader(p, groups);
            var vars = Vars(p, groups);
            var step = new Step
            {
                Card = r.Card, Title = Template.Expand(r.Title, vars), Detail = Template.Expand(r.Text, vars),
                Minor = r.Minor, Verified = r.Verified, Versions = r.Versions ?? Array.Empty<string>(),
                RuleId = r.Id, Explain = r.Explain, NextCheck = r.NextCheck, Effect = effect,
            };
            foreach (var kv in groups) step.Fields[kv.Key] = kv.Value;
            step.Lines.Add(line);
            return step;
        }
        var unk = new Step { Card = "unknown", Title = "Unrecognised line", Detail = line.Text, Effect = "none" };
        unk.Lines.Add(line);
        return unk;
    }

    static bool Condition(string when, PacketTrace p) => when switch
    {
        "reply" => p.Direction == "reply",
        "original" => p.Direction == "original",
        "new-session" => p.NewSession,
        "existing-session" => p.Direction != "" && !p.NewSession,
        "no-session" => p.NoSession,
        "local-in" => p.Egress == "root",
        _ => false,
    };

    static void FillHeader(PacketTrace p, Dictionary<string, string> g)
    {
        if (p.HasHeader) return;
        p.HasHeader = true;
        string G(string k) => g.TryGetValue(k, out var v) ? v : "";
        p.Vdom = G("vd"); p.Proto = G("proto"); p.ProtoName = ProtoName(p.Proto);
        p.Src = G("src"); p.SrcPort = G("sport"); p.Dst = G("dst"); p.DstPort = G("dport");
        p.Iface = G("iface");
        p.Flags = g.TryGetValue("flags", out var f) ? f : g.TryGetValue("itype", out var t) ? "icmp type " + t : "";
    }

    static void Process(Step s, string effect, Dictionary<string, string> g, Ctx c)
    {
        var p = c.P;
        string G(string k) => g.TryGetValue(k, out var v) ? v : "";
        switch (effect)
        {
            case "new-session":
                p.SessionId = G("session").ToLowerInvariant(); p.Direction = "original"; p.NewSession = true; break;
            case "existing-session":
                p.SessionId = G("session").ToLowerInvariant(); p.Direction = G("direction"); break;
            case "no-session":
                p.NoSession = true; c.NoSession = s; break;
            case "route":
                p.Egress = G("egress"); c.Route = s; break;
            case "policy-match":
                c.PolicyMatch = s; c.MatchAct = G("act"); c.PolicyMatchPolicy = G("policy"); break;
            case "policy-allow":
                c.PolicyAllow = s; p.Policy = G("policy"); break;
            case "decision":
                c.Decision = s; c.DecisionAct = G("act"); break;
            case "drop":
                c.StrongDrop ??= s; break;
            case "forward":
                c.Forward = s; p.OutDevice = G("dev"); break;
            case "offload":
                c.Offload ??= s; break;
            case "fast-path":
                p.IsFastPath = true; c.FastPath = s; break;
            case "ipsec":
                if (g.ContainsKey("tunnel")) p.Tunnel = G("tunnel"); break;
        }
    }

    static void ComputeVerdict(PacketTrace p, Ctx c, RuleSet rules)
    {
        Verdict v; Step? deciding = null; string key; bool offloadKey = false;
        // 1. explicit drop message  2. egress / fast path  3. allowed by policy
        // 4. local-in: route via 'root', verdict from the LAST policy result  5. last policy result says drop
        if (c.StrongDrop != null) { v = Verdict.Dropped; deciding = c.StrongDrop; }
        else if (c.Forward != null || c.FastPath != null)
        { v = Verdict.Forwarded; deciding = c.Forward ?? c.FastPath; }
        else if (c.Offload != null && p.Egress != "root")
        { v = Verdict.Forwarded; deciding = c.Offload; offloadKey = true; }
        else if (c.PolicyAllow != null && p.Egress != "root")
        { v = Verdict.Forwarded; deciding = c.PolicyAllow; }
        else if (p.Egress == "root" && c.DecisionAct != null)
        {
            if (c.DecisionAct == "accept") { v = Verdict.LocalIn; deciding = LastMatchOr(c, "accept"); }
            else { v = Verdict.Dropped; deciding = LastMatchOr(c, c.DecisionAct); }
        }
        else if (c.DecisionAct == "drop") { v = Verdict.Dropped; deciding = LastMatchOr(c, "drop"); }
        else if (p.Egress == "root") { v = Verdict.LocalIn; deciding = c.Route; }
        else { v = Verdict.Unknown; }

        p.Verdict = v;
        p.Deciding = deciding;
        if (deciding != null) { deciding.IsDeciding = true; p.DecidedByUnverifiedRule = !deciding.Verified; }

        key = v switch { Verdict.Forwarded => "forwarded", Verdict.Dropped => "dropped", Verdict.LocalIn => "local-in", _ => "unknown" };
        if (offloadKey) key = "forwarded-offload";
        rules.Verdicts.TryGetValue(key, out var vt);
        var vars = new Dictionary<string, string>
        {
            ["out"] = p.OutDevice ?? p.Tunnel ?? p.Egress ?? "an outgoing interface",
            ["dst"] = p.Dst, ["src"] = p.Src, ["policy"] = p.Policy ?? "",
            ["policyNote"] = p.IsFastPath ? "It matched an established session (fast path), so no new policy lookup happened."
                : p.Policy != null ? $"Allowed by policy {p.Policy}." : "",
        };
        p.VerdictTitle = vt?.Title ?? key;
        var explain = vt?.Explain ?? "";
        var next = vt?.NextCheck ?? "";
        if (deciding?.Explain is { Length: > 0 } e) explain = e;
        if (deciding?.NextCheck is { Length: > 0 } nx) next = nx;
        p.Explanation = Template.Expand(explain, vars).Trim();
        p.NextCheck = Template.Expand(next, vars).Trim();
        if (c.NoSession?.Explain is { Length: > 0 } ns && v != Verdict.Dropped) p.Notes.Add(ns);
        if (c.FastPath?.Explain is { Length: > 0 } fp && v == Verdict.Forwarded && deciding != c.FastPath) p.Notes.Add(fp);
        if (v == Verdict.Unknown && c.NoSession != null)
        {
            p.Explanation = c.NoSession.Explain ?? p.Explanation;
            p.NextCheck = c.NoSession.NextCheck ?? p.NextCheck;
            p.Deciding = c.NoSession; c.NoSession.IsDeciding = true;
        }
    }

    static Step? LastMatchOr(Ctx c, string act) =>
        c.PolicyMatch != null && c.MatchAct == act ? c.PolicyMatch : c.Decision;

    // ---------- folding noisy lines into collapsible cards ----------

    static List<Step> Fold(List<Step> flat)
    {
        var outList = new List<Step>();
        Step? group = null;
        foreach (var s in flat)
        {
            if (s.Effect == "policy-check")
            {
                if (group is { Card: "policy-check" }) { group.Children.Add(s); continue; }
                group = new Step { Card = "policy-check" };
                group.Children.Add(s); outList.Add(group); continue;
            }
            if (s.Minor && !s.IsDeciding)
            {
                if (group is { Card: "detail" }) { group.Children.Add(s); continue; }
                group = new Step { Card = "detail", Minor = true };
                group.Children.Add(s); outList.Add(group); continue;
            }
            group = null;
            outList.Add(s);
        }
        foreach (var g in outList.Where(x => x.Children.Count > 0)) Summarise(g);
        return outList;
    }

    static void Summarise(Step g)
    {
        foreach (var ch in g.Children) g.Lines.AddRange(ch.Lines);
        g.Verified = g.Children.All(x => x.Verified);
        if (g.Card == "detail")
        {
            g.Title = $"Technical details ({g.Children.Count} line{(g.Children.Count == 1 ? "" : "s")})";
            g.Detail = string.Join(Environment.NewLine, g.Children.Select(x => x.Lines[0].Text));
            return;
        }
        // policy checks
        var matched = g.Children.FirstOrDefault(x => x.Fields.GetValueOrDefault("ret") == "matched");
        var gnum = g.Children[0].Fields.GetValueOrDefault("gnum", "");
        var others = g.Children.Where(x => x != matched).Select(x => x.Fields.GetValueOrDefault("policy", "?")).ToList();
        if (matched != null)
        {
            var pol = matched.Fields.GetValueOrDefault("policy", "?");
            g.Title = $"Policy {Template.PolicyLabel(pol)} matched after checking {others.Count} other{(others.Count == 1 ? "" : "s")}";
            g.Detail = others.Count == 0 ? $"Policy group {gnum}: the first policy checked matched."
                : $"Policy group {gnum}: policy {pol} matched. Checked first and not matching: {string.Join(", ", others.Select(Template.PolicyLabel))}.";
        }
        else
        {
            g.Title = $"{g.Children.Count} policies checked, none matched";
            g.Detail = $"Policy group {gnum}: no match in {string.Join(", ", others.Select(Template.PolicyLabel))}.";
        }
    }

    // ---------- templates ----------

    static Dictionary<string, string> Vars(PacketTrace p, Dictionary<string, string> g)
    {
        var v = new Dictionary<string, string>
        {
            ["src"] = p.Src, ["sport"] = p.SrcPort, ["dst"] = p.Dst, ["dport"] = p.DstPort, ["iface"] = p.Iface, ["proto_name"] = p.ProtoName,
        };
        foreach (var kv in g) v[kv.Key] = kv.Value;
        v["proto_name"] = ProtoName(v.GetValueOrDefault("proto", p.Proto));
        if (g.ContainsKey("policy")) v["policy_label"] = Template.PolicyLabel(g["policy"]);
        var extra = "";
        if (g.TryGetValue("flags", out var fl) && fl.Length > 0) extra = $", TCP flags [{fl}] = {FlagText(fl)}";
        else if (g.TryGetValue("itype", out var it)) extra = $", ICMP type {it} ({IcmpText(it, g.GetValueOrDefault("icode", "0"))})";
        v["extra"] = extra;
        return v;
    }

    public static string ProtoName(string proto) => proto switch
    {
        "1" => "ICMP", "2" => "IGMP", "6" => "TCP", "17" => "UDP", "47" => "GRE", "50" => "ESP", "51" => "AH",
        "58" => "ICMPv6", "89" => "OSPF", "112" => "VRRP", "" => "?", _ => "proto " + proto,
    };

    public static string FlagText(string flags)
    {
        var parts = new List<string>();
        foreach (var ch in flags)
        {
            switch (ch)
            {
                case 'S': parts.Add("SYN"); break;
                case 'F': parts.Add("FIN"); break;
                case 'R': parts.Add("RST"); break;
                case 'P': parts.Add("PSH"); break;
                case 'U': parts.Add("URG"); break;
                case '.': parts.Add("ACK"); break;
            }
        }
        return parts.Count == 0 ? "none" : string.Join("+", parts);
    }

    static string IcmpText(string type, string code) => type switch
    {
        "0" => "echo reply", "8" => "echo request", "3" => "destination unreachable", "5" => "redirect",
        "11" => "time exceeded", "4" => "source quench", "13" => "timestamp request", "14" => "timestamp reply",
        _ => "code " + code,
    };

    // ---------- sessions ----------

    static void BuildSessions(AnalysisResult r, RuleSet rules)
    {
        var map = new Dictionary<string, SessionGroup>();
        foreach (var p in r.Packets)
        {
            if (p.SessionId == null) continue;
            if (!map.TryGetValue(p.SessionId, out var s))
            {
                s = new SessionGroup { Id = p.SessionId };
                map[p.SessionId] = s; r.Sessions.Add(s);
            }
            s.Packets.Add(p);
        }
        // Later packets of a session that was accepted as local-in only show "Find an existing session": same outcome.
        rules.Verdicts.TryGetValue("local-in-existing", out var lie);
        foreach (var s in r.Sessions)
        {
            if (lie == null || !s.Packets.Any(x => x.Verdict == Verdict.LocalIn && x.NewSession)) continue;
            foreach (var p in s.Packets.Where(x => x.Verdict == Verdict.Unknown && x.Direction == "original" && !x.NoSession))
            {
                p.Verdict = Verdict.LocalIn; p.VerdictTitle = lie.Title; p.Explanation = lie.Explain; p.NextCheck = lie.NextCheck;
            }
        }
        foreach (var s in r.Sessions)
        {
            s.Verdict = s.Packets.Any(x => x.Verdict == Verdict.Dropped) ? Verdict.Dropped
                : s.Packets.Any(x => x.Verdict == Verdict.LocalIn) ? Verdict.LocalIn
                : s.Packets.Any(x => x.Verdict == Verdict.Forwarded) ? Verdict.Forwarded : Verdict.Unknown;
        }
    }
}

public static class Template
{
    static readonly Regex Token = new(@"\{(\w+)\}", RegexOptions.Compiled);

    public static string Expand(string? template, IReadOnlyDictionary<string, string> vars) =>
        string.IsNullOrEmpty(template) ? "" : Token.Replace(template, m => vars.TryGetValue(m.Groups[1].Value, out var v) ? v : "");

    public static string PolicyLabel(string policy) =>
        policy == "4294967295" ? "4294967295 (implicit/default)" : policy;
}
