using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FortiFlow.Core;

/// <summary>One message pattern from the JSON rules file. See README for the schema.</summary>
public sealed class Rule
{
    public string Id { get; set; } = "";
    public string Pattern { get; set; } = "";
    public string Card { get; set; } = "info";
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
    public string Effect { get; set; } = "none";
    public string? When { get; set; }
    public bool Minor { get; set; }
    public string? Explain { get; set; }
    public string? NextCheck { get; set; }
    public string[]? Versions { get; set; }
    public bool Verified { get; set; } = true;
    public string? Notes { get; set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public Regex? Regex { get; set; }
}

public sealed class VerdictText
{
    public string Title { get; set; } = "";
    public string Explain { get; set; } = "";
    public string NextCheck { get; set; } = "";
}

public sealed class RuleFile
{
    public int SchemaVersion { get; set; } = 1;
    public bool ReplaceDefaults { get; set; }
    public List<Rule> Rules { get; set; } = new();
    public Dictionary<string, VerdictText> Verdicts { get; set; } = new();
}

public sealed class RuleSet
{
    public List<Rule> Rules { get; } = new();
    public Dictionary<string, VerdictText> Verdicts { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Messages for the user: load warnings, fallbacks, skipped rules.</summary>
    public List<string> Messages { get; } = new();
    public string Source { get; private set; } = "built-in rules";

    static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
    };

    public const string EmbeddedName = "FortiFlow.Core.default-rules.json";

    public static string GetEmbeddedJson()
    {
        using var s = typeof(RuleSet).Assembly.GetManifestResourceStream(EmbeddedName)
            ?? throw new InvalidOperationException("Embedded rules missing.");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    public static RuleSet LoadDefault()
    {
        var set = new RuleSet();
        set.AddFile(ParseFile(GetEmbeddedJson(), set.Messages, "built-in rules"), replace: false);
        return set;
    }

    /// <summary>
    /// Loads the built-in rules and, if the file exists, an override file on top of them.
    /// A broken override file never throws: the built-in rules are used and a message explains why.
    /// </summary>
    public static RuleSet Load(string? overridePath)
    {
        var set = LoadDefault();
        if (string.IsNullOrWhiteSpace(overridePath)) return set;
        if (!File.Exists(overridePath)) { set.Messages.Add($"Rules file not found: {overridePath}. Using built-in rules."); return set; }

        var msgs = new List<string>();
        RuleFile? file;
        try { file = ParseFile(File.ReadAllText(overridePath), msgs, Path.GetFileName(overridePath)); }
        catch (Exception ex) { file = null; msgs.Add($"Could not read {overridePath}: {ex.Message}"); }

        if (file == null || file.Rules.Count == 0 && file.Verdicts.Count == 0)
        {
            set.Messages.Add($"Rules file {Path.GetFileName(overridePath)} is not usable - using built-in rules instead.");
            set.Messages.AddRange(msgs);
            return set;
        }
        set.Messages.AddRange(msgs);
        if (file.ReplaceDefaults) { set.Rules.Clear(); }
        set.AddFile(file, file.ReplaceDefaults);
        set.Source = $"built-in rules + {Path.GetFileName(overridePath)}";
        if (file.ReplaceDefaults) set.Source = Path.GetFileName(overridePath);
        return set;
    }

    static RuleFile? ParseFile(string json, List<string> messages, string name)
    {
        RuleFile? file;
        try { file = JsonSerializer.Deserialize<RuleFile>(json, Json); }
        catch (JsonException ex) { messages.Add($"{name}: invalid JSON - {ex.Message}"); return null; }
        if (file == null) { messages.Add($"{name}: empty rules file."); return null; }
        var good = new List<Rule>();
        var seen = new HashSet<string>();
        foreach (var r in file.Rules)
        {
            if (string.IsNullOrWhiteSpace(r.Id)) { messages.Add($"{name}: a rule has no id - skipped."); continue; }
            if (!seen.Add(r.Id)) { messages.Add($"{name}: duplicate rule id '{r.Id}' - skipped."); continue; }
            try { r.Regex = new Regex(r.Pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)); }
            catch (ArgumentException ex) { messages.Add($"{name}: rule '{r.Id}' has an invalid pattern - skipped ({ex.Message})"); continue; }
            good.Add(r);
        }
        file.Rules = good;
        return file;
    }

    void AddFile(RuleFile? file, bool replace)
    {
        if (file == null) return;
        // Override rules go first so they win; a rule with an id that already exists replaces the built-in one.
        var ids = new HashSet<string>(file.Rules.Select(r => r.Id));
        if (!replace && Rules.Count > 0)
        {
            Rules.RemoveAll(r => ids.Contains(r.Id));
            Rules.InsertRange(0, file.Rules);
        }
        else Rules.AddRange(file.Rules);
        foreach (var kv in file.Verdicts) Verdicts[kv.Key] = kv.Value;
    }

    public static string Serialize(RuleFile f) => JsonSerializer.Serialize(f, Json);
}
