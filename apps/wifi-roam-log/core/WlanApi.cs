using System.Runtime.InteropServices;
using System.Text;

namespace WifiRoamLog.Core;

public sealed class WlanException(string message, uint code) : Exception(message)
{
    public uint Code { get; } = code;
}

/// <summary>Everything the app needs from the Windows Native Wifi API. The real implementation is <see cref="WlanApi"/>; tests use fakes.</summary>
public interface IWlanApi : IDisposable
{
    IReadOnlyList<WlanInterfaceInfo> EnumInterfaces();
    WlanConnection QueryConnection(Guid iface);
    IReadOnlyList<BssEntry> GetBssList(Guid iface);
    IReadOnlyList<AvailableNetwork> GetAvailableNetworks(Guid iface);
    /// <summary>Asks the driver for a fresh scan (async in Windows; results appear in the BSS list a few seconds later). Only the Visible APs tab calls this.</summary>
    void Scan(Guid iface);
    /// <summary>Registers for connect / disconnect / roam notifications. Disposing unregisters.</summary>
    IDisposable RegisterNotifications(Action<WlanNotification> handler);
}

/// <summary>P/Invoke implementation over wlanapi.dll. Read-only apart from WlanScan.</summary>
public sealed class WlanApi : IWlanApi
{
    private const uint SourceAcm = 0x8, SourceMsm = 0x10;
    private IntPtr _handle;
    private readonly object _gate = new();

    public WlanApi()
    {
        uint rc = Native.WlanOpenHandle(2, IntPtr.Zero, out _, out _handle);
        if (rc != 0) { _handle = IntPtr.Zero; throw new WlanException(rc == 1062 ? "The WLAN AutoConfig service is not running (no Wi-Fi adapter on this PC?)" : $"WlanOpenHandle failed (error {rc})", rc); }
    }

    public IReadOnlyList<WlanInterfaceInfo> EnumInterfaces()
    {
        uint rc = Native.WlanEnumInterfaces(_handle, IntPtr.Zero, out var list);
        if (rc != 0) throw new WlanException($"WlanEnumInterfaces failed (error {rc})", rc);
        try
        {
            int n = Marshal.ReadInt32(list);
            var res = new List<WlanInterfaceInfo>();
            for (int i = 0; i < n; i++)
            {
                var p = list + 8 + i * 532;
                var guid = Marshal.PtrToStructure<Guid>(p);
                var desc = Marshal.PtrToStringUni(p + 16, 256).Split('\0')[0];
                res.Add(new WlanInterfaceInfo(guid, desc, MapState(Marshal.ReadInt32(p + 528))));
            }
            return res;
        }
        finally { Native.WlanFreeMemory(list); }
    }

    private static WlanState MapState(int s) => s switch
    {
        0 => WlanState.NotReady, 1 => WlanState.Connected, 2 => WlanState.AdHoc, 3 => WlanState.Disconnecting, 4 => WlanState.Disconnected,
        5 => WlanState.Associating, 6 => WlanState.Discovering, 7 => WlanState.Authenticating, _ => WlanState.Unknown,
    };

    public WlanConnection QueryConnection(Guid iface)
    {
        uint rc = Native.WlanQueryInterface(_handle, ref iface, 7 /*current_connection*/, IntPtr.Zero, out _, out var data, out _);
        if (rc == 5023 /*ERROR_INVALID_STATE: not connected*/)
        {
            var st = WlanState.Disconnected;
            if (Native.WlanQueryInterface(_handle, ref iface, 6, IntPtr.Zero, out _, out var sd, out _) == 0)
            {
                st = MapState(Marshal.ReadInt32(sd)); Native.WlanFreeMemory(sd);
            }
            return new WlanConnection { State = st };
        }
        if (rc != 0) return new WlanConnection { State = WlanState.Unknown, ErrorCode = rc };
        WlanConnection conn;
        try
        {
            string ssid = ReadSsid(data + 520);
            var mac = new byte[6];
            Marshal.Copy(data + 560, mac, 0, 6);
            conn = new WlanConnection
            {
                State = MapState(Marshal.ReadInt32(data)),
                Profile = Marshal.PtrToStringUni(data + 8, 256).Split('\0')[0],
                Ssid = ssid,
                Bssid = Bssid.Normalize(WifiMath.FormatBssid(mac)),
                PhyType = Marshal.ReadInt32(data + 568),
                SignalQuality = Marshal.ReadInt32(data + 576),
                RxKbps = (uint)Marshal.ReadInt32(data + 580),
                TxKbps = (uint)Marshal.ReadInt32(data + 584),
            };
        }
        finally { Native.WlanFreeMemory(data); }

        if (conn.State == WlanState.Connected)
        {
            int? rssi = null, ch = null;
            if (Native.WlanQueryInterface(_handle, ref iface, 0x10000102 /*rssi*/, IntPtr.Zero, out _, out var rd, out _) == 0)
            { rssi = Marshal.ReadInt32(rd); Native.WlanFreeMemory(rd); }
            if (Native.WlanQueryInterface(_handle, ref iface, 8 /*channel_number*/, IntPtr.Zero, out _, out var cd, out _) == 0)
            { int c = Marshal.ReadInt32(cd); Native.WlanFreeMemory(cd); if (c > 0) ch = c; }
            conn = conn with { RssiDbm = rssi, Channel = ch };
        }
        return conn;
    }

    private static string ReadSsid(IntPtr p)
    {
        int len = Math.Min(Marshal.ReadInt32(p), 32);
        if (len <= 0) return "";
        var b = new byte[len];
        Marshal.Copy(p + 4, b, 0, len);
        try { return new UTF8Encoding(false, true).GetString(b); }
        catch (DecoderFallbackException) { return Encoding.Latin1.GetString(b); }
    }

    public IReadOnlyList<BssEntry> GetBssList(Guid iface)
    {
        uint rc = Native.WlanGetNetworkBssList(_handle, ref iface, IntPtr.Zero, 3 /*any*/, false, IntPtr.Zero, out var list);
        if (rc != 0) throw new WlanException($"WlanGetNetworkBssList failed (error {rc})", rc);
        try
        {
            int n = Marshal.ReadInt32(list + 4);
            var res = new List<BssEntry>();
            for (int i = 0; i < n; i++)
            {
                var p = list + 8 + i * 360;
                var mac = new byte[6];
                Marshal.Copy(p + 40, mac, 0, 6);
                res.Add(new BssEntry(ReadSsid(p), Bssid.Normalize(WifiMath.FormatBssid(mac)), Marshal.ReadInt32(p + 56), Marshal.ReadInt32(p + 60),
                    Marshal.ReadInt32(p + 92) / 1000, Marshal.ReadInt32(p + 52)));
            }
            return res;
        }
        finally { Native.WlanFreeMemory(list); }
    }

    public IReadOnlyList<AvailableNetwork> GetAvailableNetworks(Guid iface)
    {
        uint rc = Native.WlanGetAvailableNetworkList(_handle, ref iface, 0, IntPtr.Zero, out var list);
        if (rc != 0) throw new WlanException($"WlanGetAvailableNetworkList failed (error {rc})", rc);
        try
        {
            int n = Marshal.ReadInt32(list);
            var res = new List<AvailableNetwork>();
            for (int i = 0; i < n; i++)
            {
                var p = list + 8 + i * 628;
                bool sec = Marshal.ReadInt32(p + 608) != 0;
                res.Add(new AvailableNetwork(ReadSsid(p + 512), Marshal.ReadInt32(p + 604), sec, WifiMath.AuthName(sec, Marshal.ReadInt32(p + 612))));
            }
            return res;
        }
        finally { Native.WlanFreeMemory(list); }
    }

    public void Scan(Guid iface)
    {
        uint rc = Native.WlanScan(_handle, ref iface, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (rc != 0) throw new WlanException($"WlanScan failed (error {rc})", rc);
    }

    public IDisposable RegisterNotifications(Action<WlanNotification> handler)
    {
        var reg = new Registration(this, handler);
        uint rc = Native.WlanRegisterNotification(_handle, SourceAcm | SourceMsm, false, reg.Callback, IntPtr.Zero, IntPtr.Zero, out _);
        if (rc != 0) throw new WlanException($"WlanRegisterNotification failed (error {rc})", rc);
        return reg;
    }

    private sealed class Registration : IDisposable
    {
        private readonly WlanApi _owner;
        private readonly Action<WlanNotification> _handler;
        public readonly Native.NotificationCallback Callback;   // kept alive as a field: native code holds only a raw pointer
        private int _disposed;

        public Registration(WlanApi owner, Action<WlanNotification> handler)
        {
            _owner = owner; _handler = handler; Callback = OnNotification;
        }

        private void OnNotification(IntPtr data, IntPtr context)
        {
            try
            {
                var n = Parse(data);
                if (n is not null) _handler(n);
            }
            catch { /* never throw into native code */ }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            lock (_owner._gate)
                if (_owner._handle != IntPtr.Zero)
                    Native.WlanRegisterNotification(_owner._handle, 0, false, null, IntPtr.Zero, IntPtr.Zero, out _);
        }
    }

    /// <summary>NOTIFICATION_DATA: source(4) code(4) guid(16) size(4) pData. ACM codes: 9 connection_start, 10 complete, 11 attempt_fail, 20 disconnecting, 21 disconnected.
    /// MSM codes: 5 roaming_start, 6 roaming_end. For connection notifications pData starts WLAN_CONNECTION_NOTIFICATION_DATA: mode(4) profile(512) ssid(36) bssType(4) secEnabled(4) reason(4).</summary>
    internal static WlanNotification? Parse(IntPtr p)
    {
        uint source = (uint)Marshal.ReadInt32(p);
        int code = Marshal.ReadInt32(p + 4);
        var guid = Marshal.PtrToStructure<Guid>(p + 8);
        int size = Marshal.ReadInt32(p + 24);
        IntPtr d = Marshal.ReadIntPtr(p + 32);   // 8-byte aligned pointer on x64
        string raw = $"src=0x{source:x} code={code}";
        WlanNotificationKind kind = WlanNotificationKind.Other;
        if (source == SourceAcm)
            kind = code switch { 9 => WlanNotificationKind.ConnectionStart, 10 => WlanNotificationKind.ConnectionComplete, 11 => WlanNotificationKind.ConnectionFailed, 20 => WlanNotificationKind.Disconnecting, 21 => WlanNotificationKind.Disconnected, _ => WlanNotificationKind.Other };
        else if (source == SourceMsm)
            kind = code switch { 5 => WlanNotificationKind.RoamStart, 6 => WlanNotificationKind.RoamEnd, _ => WlanNotificationKind.Other };
        if (kind == WlanNotificationKind.Other) return null;

        uint reason = 0; string? reasonText = null, ssid = null;
        bool connData = source == SourceAcm && kind is WlanNotificationKind.ConnectionStart or WlanNotificationKind.ConnectionComplete or WlanNotificationKind.ConnectionFailed or WlanNotificationKind.Disconnected or WlanNotificationKind.Disconnecting;
        if (connData && d != IntPtr.Zero && size >= 564)
        {
            ssid = ReadSsid(d + 516);
            if (kind is not (WlanNotificationKind.ConnectionStart or WlanNotificationKind.Disconnecting)) reason = (uint)Marshal.ReadInt32(d + 560);
            if (reason != 0)
            {
                var sb = new StringBuilder(512);
                reasonText = Native.WlanReasonCodeToString(reason, sb.Capacity, sb, IntPtr.Zero) == 0 ? sb.ToString() : $"reason 0x{reason:x}";
            }
        }
        return new WlanNotification(DateTime.Now, guid, kind, reason, reasonText, ssid, raw);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero) return;
            Native.WlanRegisterNotification(_handle, 0, false, null, IntPtr.Zero, IntPtr.Zero, out _);
            Native.WlanCloseHandle(_handle, IntPtr.Zero);
            _handle = IntPtr.Zero;
        }
    }

    internal static class Native
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void NotificationCallback(IntPtr data, IntPtr context);

        [DllImport("wlanapi.dll")] public static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr handle);
        [DllImport("wlanapi.dll")] public static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
        [DllImport("wlanapi.dll")] public static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] public static extern uint WlanQueryInterface(IntPtr handle, ref Guid iface, int opcode, IntPtr reserved, out uint size, out IntPtr data, out int valueType);
        [DllImport("wlanapi.dll")] public static extern uint WlanGetNetworkBssList(IntPtr handle, ref Guid iface, IntPtr ssid, int bssType, [MarshalAs(UnmanagedType.Bool)] bool securityEnabled, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] public static extern uint WlanGetAvailableNetworkList(IntPtr handle, ref Guid iface, uint flags, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")] public static extern uint WlanScan(IntPtr handle, ref Guid iface, IntPtr ssid, IntPtr rawData, IntPtr reserved);
        [DllImport("wlanapi.dll")] public static extern uint WlanRegisterNotification(IntPtr handle, uint source, [MarshalAs(UnmanagedType.Bool)] bool ignoreDuplicate, NotificationCallback? callback, IntPtr context, IntPtr reserved, out uint previousSource);
        [DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr p);
        [DllImport("wlanapi.dll", CharSet = CharSet.Unicode)] public static extern uint WlanReasonCodeToString(uint reason, int bufferSize, StringBuilder buffer, IntPtr reserved);
    }
}
