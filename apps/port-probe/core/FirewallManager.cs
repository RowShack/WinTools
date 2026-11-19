using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace PortProbe.Core;

public sealed record FirewallStatus(bool IsAdmin, bool AnyProfileEnabled, bool InboundBlockedByDefault, string Summary);

/// <summary>
/// Temporary Windows Firewall allow rules for the listener. Every rule carries the group "WinTools PortProbe", so
/// <see cref="RemoveRulesAsync"/> removes exactly ours - called on stop, on exit, and at next launch (crash recovery).
/// Only validated port numbers are ever placed into scripts.
/// </summary>
public static class FirewallManager
{
    public const string Group = "WinTools PortProbe";

    public static bool IsAdmin()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public static async Task<FirewallStatus> GetStatusAsync()
    {
        const string script = """
            $ErrorActionPreference='Stop'
            @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{N=[string]$_.Name;E=[string]$_.Enabled;I=[string]$_.DefaultInboundAction} }) | ConvertTo-Json -Compress
            """;
        try
        {
            using var doc = JsonDocument.Parse(await RunPs(script));
            var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : [doc.RootElement];
            bool enabled = items.Any(e => e.GetProperty("E").GetString() == "True");
            bool blocked = items.Any(e => e.GetProperty("E").GetString() == "True" && e.GetProperty("I").GetString() is "Block" or "NotConfigured");
            string summary = enabled
                ? (blocked ? "Windows Firewall is on and blocks unsolicited inbound connections by default: listeners will not be reachable until allowed."
                           : "Windows Firewall is on but allows inbound by default.")
                : "Windows Firewall is off.";
            return new FirewallStatus(IsAdmin(), enabled, blocked, summary);
        }
        catch (Exception ex) { return new FirewallStatus(IsAdmin(), false, false, "Couldn't read firewall state: " + ex.Message); }
    }

    public static async Task AddRulesAsync(IEnumerable<PortSpec> specs)
    {
        var list = specs.ToList();
        var sb = new StringBuilder("$ErrorActionPreference='Stop'\n");
        foreach (var (proto, name) in new[] { (Proto.Tcp, "TCP"), (Proto.Udp, "UDP") })
        {
            string ports = PortSpecParser.Compact(list, proto);
            if (ports.Length == 0) continue;
            if (!ports.All(c => char.IsAsciiDigit(c) || c is ',' or '-')) throw new ArgumentException("Invalid port list.");
            sb.AppendLine($"New-NetFirewallRule -DisplayName 'WinTools PortProbe {name}' -Group '{Group}' -Direction Inbound -Action Allow -Protocol {name} -LocalPort '{ports}' -Profile Any | Out-Null");
        }
        await RunPs(sb.ToString());
    }

    public static Task RemoveRulesAsync() =>
        RunPs($"Remove-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue; exit 0");

    public static async Task<bool> HasLeftoverRulesAsync()
    {
        try { return (await RunPs($"@(Get-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue).Count")).Trim() is not ("0" or ""); }
        catch { return false; }
    }

    private static async Task<string> RunPs(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        if (p.ExitCode != 0)
            throw new InvalidOperationException((await e).Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "PowerShell command failed.");
        return await o;
    }
}
