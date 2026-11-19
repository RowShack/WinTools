using System.Text;
using System.Text.RegularExpressions;

namespace RadiusTester.Core;

/// <summary>Plain-English interpretation of a RADIUS exchange.</summary>
public static class RadiusHints
{
    private static readonly Regex MsErr = new(@"E=(\d+)", RegexOptions.Compiled);

    public static void Analyze(RadiusExchange e, ServerProfile p)
    {
        var h = e.Hints;
        bool radsec = p.Transport == TransportKind.RadSec;
        switch (e.Verdict)
        {
            case Verdict.NoReply:
                h.Add($"No reply after {e.Attempts} attempt(s) of {p.Timeout.TotalSeconds:0.#} s. A RADIUS server silently drops packets it does not trust, so this almost always means one of:");
                if (radsec)
                {
                    h.Add("• Nothing is answering on the RadSec port (default TCP 2083) or the server is slow; check the port and firewall.");
                    h.Add("• The server does not accept this client (RadSec client not authorised, certificate not trusted by the server).");
                }
                else
                {
                    h.Add("• Wrong shared secret (the server discards requests whose Message-Authenticator doesn't verify).");
                    h.Add("• This PC's IP address is not registered as a RADIUS client / NAS on the server (NPS: RADIUS Clients; FreeRADIUS: clients.conf; FortiAuthenticator: RADIUS clients). If you are behind NAT, register the NAT address.");
                    h.Add($"• A firewall is blocking UDP {(e.Kind == ExchangeKind.Accounting ? p.AcctPort : p.AuthPort)} to the server or the reply back.");
                    h.Add("• Wrong host or port. Some servers use the legacy ports 1645/1646.");
                    if (p.SendMessageAuthenticator) h.Add("• A very old server may drop requests containing Message-Authenticator: try again with that option turned off.");
                    if (p.Timeout.TotalSeconds < 10) h.Add("• MFA/OTP proxies (Okta, Duo, Rublon) can take 10-60 s to answer: raise the timeout.");
                }
                if (e.Kind == ExchangeKind.StatusServer) h.Add("• Status-Server (RFC 5997) is optional: NPS does not implement it and FreeRADIUS needs a 'status' virtual server. Test with an Access-Request instead.");
                break;
            case Verdict.NetworkError:
                h.Add(e.Error ?? "Network error.");
                if (e.Error?.Contains("ICMP", StringComparison.OrdinalIgnoreCase) == true) h.Add("The host is reachable but refused the UDP port: the RADIUS service is not running there, or the wrong port is configured.");
                if (e.Error?.Contains("resolve", StringComparison.OrdinalIgnoreCase) == true) h.Add("Check the host name or use the IP address.");
                if (e.Error?.Contains("TLS", StringComparison.OrdinalIgnoreCase) == true) h.Add("RadSec needs a server certificate this PC trusts (or tick 'ignore certificate errors' for testing) and, usually, a client certificate the server trusts.");
                break;
            case Verdict.BadReply:
                if (e.ResponseAuthenticatorValid == false)
                    h.Add("The Response Authenticator does not match: the reply was not signed with the shared secret you entered. Almost always a wrong shared secret (or a proxy/NAT device altering the packet). The reply content below must not be trusted.");
                if (e.MessageAuthenticatorValid == false)
                    h.Add("The reply's Message-Authenticator is invalid: wrong shared secret, or something modified the packet in transit.");
                if (e.Error != null) h.Add(e.Error);
                break;
            case Verdict.Other:
                h.Add("The server answered with a packet type that does not belong to this request.");
                break;
            case Verdict.Reject:
                AnalyzeReject(e, h);
                break;
            case Verdict.Challenge:
                h.Add("The server wants more information (Access-Challenge), typical for OTP/MFA. Enter the code; it is sent back as PAP together with the State attribute.");
                break;
            case Verdict.Accept:
                h.Add("Authentication succeeded. Check the returned attributes (VLAN / group / Class / vendor attributes) match what your NAS policy expects.");
                break;
            case Verdict.AccountingOk:
                h.Add("The server acknowledged the accounting packet. Note a server can acknowledge without storing anything; check its accounting log or the NAS session table (e.g. FortiGate RSSO user list).");
                break;
            case Verdict.StatusOk:
                h.Add("The server is alive and the shared secret matches (Status-Server answered with a valid authenticator).");
                break;
        }
        if (e.Reply != null && e.ReplyHasMessageAuthenticator == false && e.Kind != ExchangeKind.Accounting && p.SendMessageAuthenticator
            && e.Verdict is Verdict.Accept or Verdict.Reject or Verdict.Challenge)
            h.Add("Note: the reply carried no Message-Authenticator. Servers patched for BlastRADIUS (CVE-2024-3596) add one; an unpatched server answers without it and is vulnerable to forged replies.");
        if (!e.RequestHadMessageAuthenticator && e.Kind == ExchangeKind.Access)
            h.Add("This request was sent without Message-Authenticator (disabled in the profile). Patched servers may reject or ignore such requests.");
    }

    private static void AnalyzeReject(RadiusExchange e, List<string> h)
    {
        var msg = e.ReplyMessage;
        if (msg.Length > 0) h.Add($"The server explained the rejection: \"{msg}\".");
        var chapErr = e.Reply == null ? null : RadiusClient.FindVendorAttribute(e.Reply, 311, 2);
        if (chapErr is { Length: > 1 })
        {
            var text = Encoding.ASCII.GetString(chapErr, 1, chapErr.Length - 1);
            var m = MsErr.Match(text);
            h.Add($"MS-CHAP-Error \"{text}\"" + (m.Success ? ": " + MsChapV2.ExplainError(int.Parse(m.Groups[1].Value)) : ""));
        }
        else if (msg.Length == 0)
            h.Add("The server gave no reason in the packet. Look at its log: NPS Security event 6273 (Reason Code), FreeRADIUS 'radiusd -X', FortiAuthenticator/ISE authentication logs.");
        h.Add("Common causes: wrong user name or password; account disabled, locked or expired; no matching policy for this NAS/client (NPS network policy conditions, FreeRADIUS unlang rules); or the user is not in the required group.");
        switch (e.Method)
        {
            case AuthMethod.Pap:
                h.Add("PAP was used. If credentials are right, the server may not allow PAP (NPS: enable 'Unencrypted authentication (PAP, SPAP)' in the network policy; FreeRADIUS: the user must have a cleartext or PAP-capable password source). Try CHAP or MS-CHAPv2.");
                break;
            case AuthMethod.Chap:
                h.Add("CHAP needs the server to hold the password in clear or reversibly encrypted form (AD: 'Store password using reversible encryption'). Against AD/NPS use MS-CHAPv2 instead.");
                break;
            case AuthMethod.MsChapV2:
                h.Add("MS-CHAPv2 against AD needs the server to be domain-joined (NPS) or ntlm_auth (FreeRADIUS). Use DOMAIN\\user if the server expects a domain.");
                break;
            case AuthMethod.EapMd5:
                h.Add("EAP-MD5 is disabled on most servers (and impossible against AD hashes). It mainly works against FreeRADIUS with clear-text passwords.");
                break;
        }
    }
}
