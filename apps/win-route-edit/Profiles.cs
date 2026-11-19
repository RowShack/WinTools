using System.Text.Json;

namespace WinRouteEdit;

public sealed class ProfileRoute
{
    public string Prefix { get; set; } = "";
    public string NextHop { get; set; } = "";
    public int Metric { get; set; } = 1;
    /// <summary>Null = let Windows choose the interface that reaches the gateway.</summary>
    public int? IfIndex { get; set; }
    public bool Persistent { get; set; }

    public override string ToString() => $"{Prefix} via {NextHop}";
}

public sealed class RouteProfile
{
    public string Name { get; set; } = "";
    public List<ProfileRoute> Routes { get; set; } = [];
    public override string ToString() => Name;
}

/// <summary>Profiles live in %AppData%\WinTools\Win-Route-Edit\profiles.json.</summary>
public static class ProfileStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string FilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WinTools", "Win-Route-Edit", "profiles.json");

    public static List<RouteProfile> Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<List<RouteProfile>>(File.ReadAllText(FilePath)) ?? []
                : [];
        }
        catch { return []; }
    }

    public static void Save(IEnumerable<RouteProfile> profiles)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(profiles.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(), Json));
    }

    /// <summary>Adds each route; returns a list of per-route failures (empty = all OK).</summary>
    public static async Task<List<string>> ApplyAsync(RouteProfile p)
    {
        var errors = new List<string>();
        foreach (var r in p.Routes)
        {
            try { await RouteService.AddRouteAsync(r.Prefix, r.NextHop, r.Metric, r.IfIndex, r.Persistent); }
            catch (Exception ex) { errors.Add($"{r}: {ex.Message}"); }
        }
        return errors;
    }

    /// <summary>Deletes routes in the profile that currently exist; returns failures.</summary>
    public static async Task<List<string>> RemoveAsync(RouteProfile p)
    {
        var errors = new List<string>();
        var current = await RouteService.GetRoutesAsync();
        foreach (var r in p.Routes)
        {
            RouteService.TryParsePrefix(r.Prefix, out var cidr, out _);
            var matches = current.Where(c => c.Prefix == cidr && c.NextHop == r.NextHop && (r.IfIndex is null || c.IfIndex == r.IfIndex)).ToList();
            foreach (var m in matches)
            {
                try { await RouteService.DeleteRouteAsync(m); }
                catch (Exception ex) { errors.Add($"{r}: {ex.Message}"); }
            }
        }
        return errors;
    }
}
