using System.Text.RegularExpressions;

namespace AuthMailTest.Core;

public static class LdapErrors
{
    /// <summary>Active Directory sub-codes found in "data 52e" inside a bind error message.</summary>
    private static readonly Dictionary<string, string> AdSubCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["525"] = "User not found (no such account on this domain controller).",
        ["52e"] = "Invalid credentials: wrong password (or wrong user name format).",
        ["52f"] = "Account restriction: the account is blocked from logging on (policy restriction).",
        ["530"] = "Not permitted to log on at this time (logon-hours restriction).",
        ["531"] = "Not permitted to log on from this workstation (workstation restriction).",
        ["532"] = "Password expired: the user must change the password.",
        ["533"] = "Account disabled.",
        ["701"] = "Account expired.",
        ["773"] = "The user must reset their password before logging on.",
        ["775"] = "Account locked out.",
    };

    public static string? DecodeAdSubCode(string? message)
    {
        if (string.IsNullOrEmpty(message)) return null;
        var m = Regex.Match(message, @"\bdata\s+([0-9a-fA-F]{3})\b", RegexOptions.IgnoreCase);
        return m.Success && AdSubCodes.TryGetValue(m.Groups[1].Value, out var s) ? $"AD error {m.Groups[1].Value.ToLowerInvariant()}: {s}" : null;
    }

    public static string ExplainResultCode(int code) => code switch
    {
        0 => "Success.",
        1 => "Operations error: the server could not process the request (often an unauthenticated search on a server that requires a bind).",
        2 => "Protocol error.",
        4 => "Size limit exceeded: more results than the server allows in one search.",
        7 => "Authentication method not supported.",
        8 => "Strong authentication required: the server refuses this bind without TLS or a stronger method. Use LDAPS/StartTLS or Negotiate.",
        10 => "Referral: the object lives on another server.",
        13 => "Confidentiality required: the server requires an encrypted connection (LDAPS or StartTLS).",
        16 => "No such attribute.",
        32 => "No such object: the base DN doesn't exist (or isn't visible to this account).",
        34 => "Invalid DN syntax: check the user DN / base DN spelling.",
        48 => "Inappropriate authentication.",
        49 => "Invalid credentials: wrong user name or password.",
        50 => "Insufficient access: the account may not read this part of the directory.",
        51 => "Server busy.",
        52 => "Server unavailable.",
        53 => "Server unwilling to perform: commonly a simple bind without TLS when the server forbids it, or an empty password.",
        81 => "Server down: could not contact the LDAP server (check host, port and firewall).",
        82 => "Local error in the LDAP client library.",
        85 => "Timeout.",
        91 => "Connect error: could not connect to the server.",
        _ => $"LDAP result code {code}.",
    };

    /// <summary>Combine the result code explanation with any AD sub-code found in the server message.</summary>
    public static string Explain(int code, string? serverMessage)
    {
        var ad = DecodeAdSubCode(serverMessage);
        var generic = ExplainResultCode(code);
        return ad is null ? generic : $"{ad} ({generic.TrimEnd('.')})";
    }
}
