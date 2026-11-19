namespace WifiRoamLog.Core;

/// <summary>Pure helpers: signal conversions, channel/band from frequency, names of PHY and auth types.</summary>
public static class WifiMath
{
    /// <summary>Windows' own mapping: -100 dBm = 0 %, -50 dBm = 100 % (linear).</summary>
    public static int RssiToPercent(int rssiDbm) => Math.Clamp(2 * (rssiDbm + 100), 0, 100);

    public static int PercentToRssi(int percent) => Math.Clamp(percent, 0, 100) / 2 - 100;

    public static string SignalLabel(int rssiDbm) => rssiDbm switch
    {
        >= -50 => "Excellent",
        >= -60 => "Very good",
        >= -67 => "Good",
        >= -70 => "Fair",
        >= -80 => "Weak",
        _ => "Poor",
    };

    public static WifiBand BandFromFrequency(int mhz) => mhz switch
    {
        >= 2400 and <= 2500 => WifiBand.Band24,
        >= 4900 and <= 5900 => WifiBand.Band5,
        >= 5925 and <= 7125 => WifiBand.Band6,
        _ => WifiBand.Unknown,
    };

    public static string BandName(WifiBand b) => b switch
    {
        WifiBand.Band24 => "2.4 GHz",
        WifiBand.Band5 => "5 GHz",
        WifiBand.Band6 => "6 GHz",
        _ => "?",
    };

    public static int? FrequencyToChannel(int mhz)
    {
        switch (BandFromFrequency(mhz))
        {
            case WifiBand.Band24:
                if (mhz == 2484) return 14;
                return mhz >= 2412 && mhz <= 2472 && (mhz - 2407) % 5 == 0 ? (mhz - 2407) / 5 : null;
            case WifiBand.Band5:
                return (mhz - 5000) % 5 == 0 ? (mhz - 5000) / 5 : null;
            case WifiBand.Band6:
                if (mhz == 5935) return 2;
                return (mhz - 5950) % 5 == 0 ? (mhz - 5950) / 5 : null;
            default:
                return null;
        }
    }

    /// <summary>Best guess of the band when only a channel number is known (6 GHz channel numbers overlap 5 GHz, so 6 GHz can't be told apart).</summary>
    public static WifiBand BandFromChannel(int channel) => channel switch
    {
        >= 1 and <= 14 => WifiBand.Band24,
        >= 32 => WifiBand.Band5,
        _ => WifiBand.Unknown,
    };

    public static string PhyName(int dot11PhyType) => dot11PhyType switch
    {
        1 => "FHSS",
        2 => "DSSS",
        3 => "IR",
        4 => "802.11a",
        5 => "802.11b",
        6 => "802.11g",
        7 => "802.11n (Wi-Fi 4)",
        8 => "802.11ac (Wi-Fi 5)",
        9 => "802.11ad",
        10 => "802.11ax (Wi-Fi 6/6E)",
        11 => "802.11be (Wi-Fi 7)",
        0 => "",
        _ => $"PHY {dot11PhyType}",
    };

    public static string AuthName(bool securityEnabled, int dot11Auth)
    {
        if (!securityEnabled && dot11Auth <= 1) return "Open";
        return dot11Auth switch
        {
            1 => "Open",
            2 => "WEP/Shared",
            3 => "WPA-Enterprise",
            4 => "WPA-Personal",
            5 => "WPA-None",
            6 => "WPA2-Enterprise",
            7 => "WPA2-Personal",
            8 => "WPA3-Enterprise 192",
            9 => "WPA3-Personal",
            10 => "OWE",
            11 => "WPA3-Enterprise",
            _ => securityEnabled ? "Secured" : "Open",
        };
    }

    public static string FormatMbps(double? mbps) => mbps is null ? "" : mbps >= 100 ? $"{mbps:0}" : $"{mbps:0.#}";

    public static string FormatBssid(byte[] b) => string.Join(':', b.Select(x => x.ToString("x2")));
}
