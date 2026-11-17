using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthMailTest.Core;

/// <summary>A saved LDAP or SMTP configuration. The password is stored only as a DPAPI (CurrentUser) blob.</summary>
public sealed class SavedProfile
{
    public string Name { get; set; } = "";
    public string Kind { get; set; } = "ldap";             // "ldap" | "smtp"
    public Dictionary<string, string> Fields { get; set; } = [];
    public string? ProtectedPassword { get; set; }
    public override string ToString() => Name;
}

public static class ProfileStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WinTools", "AuthMailTest", "profiles.json");

    public static string Protect(string secret) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser));

    public static string? Unprotect(string? blob)
    {
        if (string.IsNullOrEmpty(blob)) return "";
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob), null, DataProtectionScope.CurrentUser)); }
        catch (CryptographicException) { return null; }   // profile was saved by another Windows user/PC
    }

    public static List<SavedProfile> Load(string? path = null)
    {
        path ??= DefaultPath;
        try { return File.Exists(path) ? JsonSerializer.Deserialize<List<SavedProfile>>(File.ReadAllText(path)) ?? [] : []; }
        catch { return []; }
    }

    public static void Save(IEnumerable<SavedProfile> profiles, string? path = null)
    {
        path ??= DefaultPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(profiles.OrderBy(p => p.Kind).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(), Json));
    }
}
