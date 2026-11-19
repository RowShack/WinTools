using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace SnmpLiveGraph.Core;

public enum SnmpVersion { V2c, V3 }
public enum AuthProto { None, SHA1, SHA256 }
public enum PrivProto { None, AES128 }

public sealed class SnmpTarget
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 161;
    public SnmpVersion Version { get; set; } = SnmpVersion.V2c;
    public string Community { get; set; } = "public";
    public string User { get; set; } = "";
    public AuthProto Auth { get; set; } = AuthProto.SHA1;
    public string AuthPassword { get; set; } = "";
    public PrivProto Priv { get; set; } = PrivProto.AES128;
    public string PrivPassword { get; set; } = "";
    public int TimeoutMs { get; set; } = 3000;
    public override string ToString() => string.IsNullOrWhiteSpace(Name) ? Host : Name;
}

public sealed record SystemInfo(string Name, string Description, long UpTimeTicks)
{
    public string UpTimeText { get { var t = TimeSpan.FromSeconds(UpTimeTicks / 100.0); return $"{(int)t.TotalDays}d {t.Hours}h {t.Minutes}m"; } }
}

public sealed class SnmpException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Thin wrapper over SharpSnmpLib for v2c and v3 (authPriv / authNoPriv / noAuth) GET and WALK.</summary>
public sealed class SnmpSession(SnmpTarget target)
{
    public static class Oids
    {
        public const string SysDescr = "1.3.6.1.2.1.1.1.0", SysUpTime = "1.3.6.1.2.1.1.3.0", SysName = "1.3.6.1.2.1.1.5.0";
        public const string IfName = "1.3.6.1.2.1.31.1.1.1.1", IfAlias = "1.3.6.1.2.1.31.1.1.1.18", IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15";
        public const string IfDescr = "1.3.6.1.2.1.2.2.1.2", IfSpeed = "1.3.6.1.2.1.2.2.1.5", IfOperStatus = "1.3.6.1.2.1.2.2.1.8";
        public const string IfHCIn = "1.3.6.1.2.1.31.1.1.1.6", IfHCOut = "1.3.6.1.2.1.31.1.1.1.10";
        public const string IfIn32 = "1.3.6.1.2.1.2.2.1.10", IfOut32 = "1.3.6.1.2.1.2.2.1.16";
        public const string IfInErrors = "1.3.6.1.2.1.2.2.1.14", IfOutErrors = "1.3.6.1.2.1.2.2.1.20";
        public const string IfInDiscards = "1.3.6.1.2.1.2.2.1.13", IfOutDiscards = "1.3.6.1.2.1.2.2.1.19";
    }

    public SnmpTarget Target { get; } = target;

    private IPEndPoint? _endpoint;
    private ISnmpMessage? _report;     // v3 discovery result (engine id, boots, time)
    private IPrivacyProvider? _privacy;

    private async Task<IPEndPoint> EndpointAsync(CancellationToken ct)
    {
        if (_endpoint != null) return _endpoint;
        IPAddress ip;
        if (!IPAddress.TryParse(Target.Host, out ip!))
        {
            var addrs = await Dns.GetHostAddressesAsync(Target.Host, ct);
            ip = addrs.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? addrs.FirstOrDefault()
                 ?? throw new SnmpException($"Could not resolve '{Target.Host}'.");
        }
        return _endpoint = new IPEndPoint(ip, Target.Port);
    }

    private async Task EnsureV3Async(IPEndPoint ep, CancellationToken ct)
    {
        if (_privacy != null) return;
        if (Target.User.Length == 0) throw new SnmpException("SNMPv3 needs a user name.");
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        _report = await discovery.GetResponseAsync(ep, ct).WaitAsync(TimeSpan.FromMilliseconds(Target.TimeoutMs), ct);

        IAuthenticationProvider auth = Target.Auth switch
        {
            AuthProto.SHA1 => new SHA1AuthenticationProvider(new OctetString(Target.AuthPassword)),
            AuthProto.SHA256 => new SHA256AuthenticationProvider(new OctetString(Target.AuthPassword)),
            _ => DefaultAuthenticationProvider.Instance,
        };
        _privacy = Target.Auth != AuthProto.None && Target.Priv == PrivProto.AES128
            ? new AESPrivacyProvider(new OctetString(Target.PrivPassword), auth)
            : new DefaultPrivacyProvider(auth);
    }

    /// <summary>GET several OIDs. Missing instances come back as null values.</summary>
    public async Task<Dictionary<string, ISnmpData?>> GetAsync(IEnumerable<string> oids, CancellationToken ct)
    {
        var ep = await EndpointAsync(ct);
        var vars = oids.Select(o => new Variable(new ObjectIdentifier(o))).ToList();
        try
        {
            IList<Variable> result;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Target.TimeoutMs);
            if (Target.Version == SnmpVersion.V2c)
                result = await Messenger.GetAsync(VersionCode.V2, ep, new OctetString(Target.Community), vars, timeout.Token);
            else
            {
                await EnsureV3Async(ep, ct);
                var req = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId,
                    new OctetString(Target.User), OctetString.Empty, vars, _privacy!, Messenger.MaxMessageSize, _report);
                var reply = await req.GetResponseAsync(ep, timeout.Token);
                if (reply.Pdu().ErrorStatus.ToInt32() != 0) throw new SnmpException("SNMP error: " + reply.Pdu().ErrorStatus);
                result = reply.Variables();
            }
            return result.ToDictionary(v => v.Id.ToString(), v => v.Data is NoSuchInstance or NoSuchObject or EndOfMibView ? null : (ISnmpData?)v.Data);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new SnmpException("No reply (timeout). Check the address, the SNMP settings and that the device allows this PC."); }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException) { throw new SnmpException("No reply (timeout). Check the address, the community/credentials and the device's SNMP access list."); }
        catch (SnmpException) { throw; }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw new SnmpException(Explain(ex), ex); }
    }

    /// <summary>Walks a subtree and returns (full OID, value) pairs.</summary>
    public async Task<List<(string Oid, ISnmpData Data)>> WalkAsync(string rootOid, CancellationToken ct)
    {
        var ep = await EndpointAsync(ct);
        var list = new List<Variable>();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Math.Max(Target.TimeoutMs * 4, 15000));
            if (Target.Version == SnmpVersion.V2c)
                await Messenger.BulkWalkAsync(VersionCode.V2, ep, new OctetString(Target.Community), OctetString.Empty, new ObjectIdentifier(rootOid),
                    list, 10, WalkMode.WithinSubtree, null, null, timeout.Token);
            else
            {
                await EnsureV3Async(ep, ct);
                await Messenger.BulkWalkAsync(VersionCode.V3, ep, new OctetString(Target.User), OctetString.Empty, new ObjectIdentifier(rootOid),
                    list, 10, WalkMode.WithinSubtree, _privacy, _report, timeout.Token);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new SnmpException("Timed out while walking " + rootOid); }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException) { throw new SnmpException("No reply (timeout) while walking " + rootOid); }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw new SnmpException(Explain(ex), ex); }
        return list.Select(v => (v.Id.ToString(), v.Data)).ToList();
    }

    public async Task<SystemInfo> GetSystemInfoAsync(CancellationToken ct)
    {
        var r = await GetAsync([Oids.SysDescr, Oids.SysUpTime, Oids.SysName], ct);
        if (r.Values.All(v => v is null)) throw new SnmpException("The device answered but returned no system information.");
        return new SystemInfo(Text(r, Oids.SysName), Text(r, Oids.SysDescr), r.TryGetValue(Oids.SysUpTime, out var up) && up is TimeTicks tt ? (long)tt.ToUInt32() : 0);
    }

    private static string Text(Dictionary<string, ISnmpData?> d, string oid) => d.TryGetValue(oid, out var v) && v is not null ? v.ToString()!.Trim() : "";

    internal static string Explain(Exception ex)
    {
        string m = ex.Message;
        if (m.Contains("authentication", StringComparison.OrdinalIgnoreCase) || m.Contains("wrong digest", StringComparison.OrdinalIgnoreCase))
            return "SNMPv3 authentication failed: check the user name, authentication protocol and password.";
        if (m.Contains("decrypt", StringComparison.OrdinalIgnoreCase)) return "SNMPv3 decryption failed: check the privacy protocol and password.";
        return "SNMP error: " + m;
    }
}
