using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace RadiusTester.Core;

public enum TransportKind { Udp, RadSec }

/// <summary>Everything the client needs to talk to one RADIUS server (secrets in clear: in memory only).</summary>
public sealed class ServerProfile
{
    public string Host { get; set; } = "";
    public int AuthPort { get; set; } = 1812;
    public int AcctPort { get; set; } = 1813;
    public string Secret { get; set; } = "";
    public double TimeoutSeconds { get; set; } = 3;
    public int Retries { get; set; } = 2;
    public string NasIp { get; set; } = "";
    public string NasIdentifier { get; set; } = "";
    /// <summary>Always send Message-Authenticator and validate it on replies (BlastRADIUS hardening). Turn off for legacy servers.</summary>
    public bool SendMessageAuthenticator { get; set; } = true;
    public TransportKind Transport { get; set; } = TransportKind.Udp;
    public int RadSecPort { get; set; } = 2083;
    public string ClientCertPfxPath { get; set; } = "";
    public string ClientCertPfxPassword { get; set; } = "";
    public string ClientCertThumbprint { get; set; } = "";
    public bool IgnoreServerCertErrors { get; set; }

    /// <summary>RFC 6614: the shared secret for RADIUS/TLS is the fixed string "radsec".</summary>
    public const string RadSecSecret = "radsec";
    public byte[] SecretBytes => Encoding.UTF8.GetBytes(Transport == TransportKind.RadSec ? RadSecSecret : Secret);
    public TimeSpan Timeout => TimeSpan.FromSeconds(Math.Max(0.1, TimeoutSeconds));

    public X509Certificate2? LoadClientCertificate()
    {
        if (!string.IsNullOrWhiteSpace(ClientCertPfxPath))
            return X509CertificateLoader.LoadPkcs12FromFile(ClientCertPfxPath, ClientCertPfxPassword, X509KeyStorageFlags.DefaultKeySet);
        if (!string.IsNullOrWhiteSpace(ClientCertThumbprint))
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Find(X509FindType.FindByThumbprint, ClientCertThumbprint.Replace(" ", ""), false).OfType<X509Certificate2>().FirstOrDefault()
                ?? throw new InvalidOperationException($"No certificate with thumbprint {ClientCertThumbprint} in CurrentUser\\My.");
        }
        return null;
    }
}

/// <summary>A saved profile as written to disk. Secrets are only stored as DPAPI (CurrentUser) blobs.</summary>
public sealed class SavedProfile
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int AuthPort { get; set; } = 1812;
    public int AcctPort { get; set; } = 1813;
    public double TimeoutSeconds { get; set; } = 3;
    public int Retries { get; set; } = 2;
    public string NasIp { get; set; } = "";
    public string NasIdentifier { get; set; } = "";
    public bool SendMessageAuthenticator { get; set; } = true;
    public TransportKind Transport { get; set; } = TransportKind.Udp;
    public int RadSecPort { get; set; } = 2083;
    public string ClientCertPfxPath { get; set; } = "";
    public string ClientCertThumbprint { get; set; } = "";
    public bool IgnoreServerCertErrors { get; set; }
    public string UserName { get; set; } = "";
    public string Method { get; set; } = "PAP";
    public string? ProtectedSecret { get; set; }
    public string? ProtectedPfxPassword { get; set; }
    public string? ProtectedUserPassword { get; set; }
    public override string ToString() => Name;

    public static SavedProfile From(string name, ServerProfile p, string userName, string method, string? userPassword)
    {
        var s = new SavedProfile
        {
            Name = name, Host = p.Host, AuthPort = p.AuthPort, AcctPort = p.AcctPort, TimeoutSeconds = p.TimeoutSeconds, Retries = p.Retries,
            NasIp = p.NasIp, NasIdentifier = p.NasIdentifier, SendMessageAuthenticator = p.SendMessageAuthenticator, Transport = p.Transport,
            RadSecPort = p.RadSecPort, ClientCertPfxPath = p.ClientCertPfxPath, ClientCertThumbprint = p.ClientCertThumbprint,
            IgnoreServerCertErrors = p.IgnoreServerCertErrors, UserName = userName, Method = method,
            ProtectedSecret = ProfileStore.Protect(p.Secret),
            ProtectedPfxPassword = string.IsNullOrEmpty(p.ClientCertPfxPassword) ? null : ProfileStore.Protect(p.ClientCertPfxPassword),
            ProtectedUserPassword = string.IsNullOrEmpty(userPassword) ? null : ProfileStore.Protect(userPassword),
        };
        return s;
    }

    /// <summary>Returns the profile, or null in <c>Secret</c> terms if the blobs could not be decrypted (saved by another Windows user/PC).</summary>
    public (ServerProfile Profile, bool SecretsOk) ToProfile()
    {
        var secret = ProfileStore.Unprotect(ProtectedSecret);
        var pfx = ProfileStore.Unprotect(ProtectedPfxPassword);
        var p = new ServerProfile
        {
            Host = Host, AuthPort = AuthPort, AcctPort = AcctPort, TimeoutSeconds = TimeoutSeconds, Retries = Retries, NasIp = NasIp,
            NasIdentifier = NasIdentifier, SendMessageAuthenticator = SendMessageAuthenticator, Transport = Transport, RadSecPort = RadSecPort,
            ClientCertPfxPath = ClientCertPfxPath, ClientCertThumbprint = ClientCertThumbprint, IgnoreServerCertErrors = IgnoreServerCertErrors,
            Secret = secret ?? "", ClientCertPfxPassword = pfx ?? "",
        };
        return (p, secret != null && pfx != null);
    }
}

public static class ProfileStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WinTools", "RadiusTester", "profiles.json");

    public static string Protect(string secret) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser));

    public static string? Unprotect(string? blob)
    {
        if (string.IsNullOrEmpty(blob)) return "";
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob), null, DataProtectionScope.CurrentUser)); }
        catch (CryptographicException) { return null; }   // saved by another Windows user/PC
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
        File.WriteAllText(path, JsonSerializer.Serialize(profiles.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(), Json));
    }
}
