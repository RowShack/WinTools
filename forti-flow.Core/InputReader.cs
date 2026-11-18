using System.Text.RegularExpressions;

namespace FortiFlow.Core;

public sealed class InputParseResult
{
    public List<LogLine> Lines { get; } = new();
    public InputFormat Format { get; set; }
    public int Ignored { get; set; }
    public int TotalRaw { get; set; }
}

/// <summary>
/// Turns pasted text into a flat list of message lines. Understands the three layouts:
/// GUI "Time,Message" CSV export, CLI output with "id=.. trace_id=.. func=.. msg=" prefixes and plain CLI messages.
/// </summary>
public static class InputReader
{
    static readonly Regex Ansi = new(@"\x1B\[[0-9;?]*[A-Za-z]|\x08+|\r", RegexOptions.Compiled);
    static readonly Regex CsvLine = new(@"^(?<t>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*,(?<m>.*)$", RegexOptions.Compiled);
    static readonly Regex Prefixed = new(@"(?:^|\s)id=(?<id>\d+)\s+trace_id=(?<tid>\d+)\s+func=(?<func>\S+)\s+line=(?<line>\d+)\s+msg=""(?<msg>.*)$", RegexOptions.Compiled);
    static readonly Regex Timestamp = new(@"^\[?(?<t>(?:\d{4}[-/]\d{2}[-/]\d{2}[ T])?\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]?\s+(?<rest>\S.*)$", RegexOptions.Compiled);
    static readonly Regex Prompt = new(@"^[\w.\-]+(?: \([\w\-.]+\))? [#$](?: .*)?$", RegexOptions.Compiled);
    static readonly Regex Noise = new(@"^(?:--More--|diagnose |execute |config |end$|show |get |Press any key|Connection (?:to|closed)|Welcome|Time,Message$)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    static readonly Regex Number = new(@"^\d{1,9}$", RegexOptions.Compiled);

    public static InputParseResult Read(string text, CancellationToken ct = default)
    {
        var res = new InputParseResult();
        bool anyCsv = false, anyPrefixed = false, anyPlain = false;
        var rawLines = text.Replace("﻿", "").Split('\n');
        res.TotalRaw = rawLines.Length;
        LogLine? prev = null;
        bool prevOpen = false; // previous line is a wrapped/unfinished message
        int n = 0;

        foreach (var rl in rawLines)
        {
            if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            var raw = Ansi.Replace(rl, "").TrimEnd();
            if (raw.Length == 0) continue;
            var line = raw.Trim();

            if (Number.IsMatch(line))
            {
                res.Lines.Add(new LogLine { Number = n, Text = line, Raw = raw, Separator = true });
                prev = null; prevOpen = false;
                continue;
            }

            string? time = null; string msg; int? tid = null; string? func = null; bool open = false;

            var pm = Prefixed.Match(line);
            if (pm.Success)
            {
                anyPrefixed = true;
                var before = line[..pm.Index].Trim();
                var tm = Timestamp.Match(before + " x");
                time = tm.Success ? tm.Groups["t"].Value : (before.Length > 0 ? before : null);
                tid = int.Parse(pm.Groups["tid"].Value);
                func = pm.Groups["func"].Value;
                msg = pm.Groups["msg"].Value;
                if (msg.EndsWith('"')) msg = msg[..^1]; else open = true;
            }
            else
            {
                var cm = CsvLine.Match(line);
                if (cm.Success)
                {
                    anyCsv = true;
                    time = cm.Groups["t"].Value;
                    msg = cm.Groups["m"].Value.Trim();
                    if (msg.Length >= 2 && msg[0] == '"' && msg[^1] == '"') msg = msg[1..^1].Replace("\"\"", "\"");
                }
                else
                {
                    // wrapped continuation of a previous unfinished message
                    if (prev != null && prevOpen)
                    {
                        prev.Text += line;
                        prev.Raw += "\n" + raw;
                        prevOpen = IsOpen(prev.Text);
                        continue;
                    }
                    if (Prompt.IsMatch(line) || Noise.IsMatch(line)) { res.Ignored++; prev = null; prevOpen = false; continue; }
                    msg = line;
                    var tm = Timestamp.Match(line);
                    if (tm.Success) { time = tm.Groups["t"].Value; msg = tm.Groups["rest"].Value.Trim(); }
                    if (msg.Length >= 2 && msg[0] == '"' && msg[^1] == '"') msg = msg[1..^1];
                    anyPlain = true;
                }
            }

            if (msg.Length == 0) continue;
            var ll = new LogLine { Number = n, Text = msg, Raw = raw, TraceId = tid, Time = time, Func = func };
            res.Lines.Add(ll);
            prev = ll;
            prevOpen = open || IsOpen(msg);
        }

        res.Format = anyPrefixed ? InputFormat.CliPrefixed : anyCsv ? InputFormat.GuiCsv : anyPlain ? InputFormat.CliPlain : InputFormat.Unknown;
        return res;
    }

    // An unbalanced "(" (e.g. "received a packet(proto=6, ...") means the terminal wrapped the line.
    static bool IsOpen(string msg)
    {
        int bal = 0;
        foreach (var c in msg) { if (c == '(') bal++; else if (c == ')') bal--; }
        return bal > 0;
    }
}
