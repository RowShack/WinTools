using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RadiusTester.Core;

public static class RadiusCode
{
    public const byte AccessRequest = 1, AccessAccept = 2, AccessReject = 3, AccountingRequest = 4, AccountingResponse = 5,
        AccessChallenge = 11, StatusServer = 12, StatusClient = 13;

    public static string Name(byte c) => c switch
    {
        1 => "Access-Request", 2 => "Access-Accept", 3 => "Access-Reject", 4 => "Accounting-Request", 5 => "Accounting-Response",
        11 => "Access-Challenge", 12 => "Status-Server", 13 => "Status-Client", 40 => "Disconnect-Request", 41 => "Disconnect-ACK",
        42 => "Disconnect-NAK", 43 => "CoA-Request", 44 => "CoA-ACK", 45 => "CoA-NAK", _ => $"Code-{c}",
    };
}

/// <summary>Well-known attribute type numbers used by the client.</summary>
public static class Attr
{
    public const int UserName = 1, UserPassword = 2, ChapPassword = 3, NasIpAddress = 4, NasPort = 5, ServiceType = 6, FramedIpAddress = 8,
        ReplyMessage = 18, State = 24, Class = 25, VendorSpecific = 26, CalledStationId = 30, CallingStationId = 31, NasIdentifier = 32,
        AcctStatusType = 40, AcctDelayTime = 41, AcctInputOctets = 42, AcctOutputOctets = 43, AcctSessionId = 44, AcctAuthentic = 45,
        AcctSessionTime = 46, AcctTerminateCause = 49, EventTimestamp = 55, ChapChallenge = 60, NasPortType = 61, EapMessage = 79,
        MessageAuthenticator = 80, NasIpv6Address = 95;
}

public sealed class RadiusFormatException(string message) : Exception(message);

public sealed class RadiusAttribute(int type, byte[] value)
{
    public int Type { get; } = type;
    public byte[] Value { get; } = value;

    public static RadiusAttribute Text(int type, string s) => new(type, System.Text.Encoding.UTF8.GetBytes(s));
    public static RadiusAttribute Int(int type, uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); return new(type, b); }

    /// <summary>Builds a Vendor-Specific attribute holding one sub-attribute (1-octet type, 1-octet length).</summary>
    public static RadiusAttribute Vsa(uint vendor, int vendorType, byte[] data)
    {
        if (data.Length > 247) throw new ArgumentException("Vendor attribute value too long (max 247 bytes).");
        var b = new byte[6 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(b, vendor);
        b[4] = (byte)vendorType; b[5] = (byte)(data.Length + 2);
        data.CopyTo(b, 6);
        return new(Attr.VendorSpecific, b);
    }

    /// <summary>Splits a Vendor-Specific attribute into vendor id and its (type, data) sub-attributes.</summary>
    public bool TryReadVsa(out uint vendor, out List<(int Type, byte[] Data)> subs)
    {
        vendor = 0; subs = [];
        if (Type != Attr.VendorSpecific || Value.Length < 6) return false;
        vendor = BinaryPrimitives.ReadUInt32BigEndian(Value);
        int i = 4;
        while (i + 2 <= Value.Length)
        {
            int len = Value[i + 1];
            if (len < 2 || i + len > Value.Length) { subs.Add((-1, Value[i..])); break; }   // malformed (non-standard format)
            subs.Add((Value[i], Value[(i + 2)..(i + len)]));
            i += len;
        }
        return true;
    }
}

public sealed class RadiusPacket
{
    public byte Code { get; set; }
    public byte Identifier { get; set; }
    public byte[] Authenticator { get; set; } = new byte[16];
    public List<RadiusAttribute> Attributes { get; } = [];

    public RadiusAttribute? Find(int type) => Attributes.FirstOrDefault(a => a.Type == type);
    public IEnumerable<RadiusAttribute> FindAll(int type) => Attributes.Where(a => a.Type == type);

    public byte[] Encode()
    {
        int len = 20 + Attributes.Sum(a => 2 + a.Value.Length);
        if (len > 4096) throw new RadiusFormatException("Packet exceeds 4096 bytes.");
        var b = new byte[len];
        b[0] = Code; b[1] = Identifier;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)len);
        Authenticator.CopyTo(b, 4);
        int o = 20;
        foreach (var a in Attributes)
        {
            if (a.Value.Length > 253) throw new RadiusFormatException($"Attribute {a.Type} value is {a.Value.Length} bytes (max 253).");
            b[o] = (byte)a.Type; b[o + 1] = (byte)(a.Value.Length + 2);
            a.Value.CopyTo(b, o + 2);
            o += 2 + a.Value.Length;
        }
        return b;
    }

    public static RadiusPacket Decode(byte[] data)
    {
        if (data.Length < 20) throw new RadiusFormatException($"Packet too short ({data.Length} bytes, minimum 20).");
        int len = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(2));
        if (len < 20 || len > data.Length) throw new RadiusFormatException($"Length field ({len}) does not match the datagram ({data.Length} bytes).");
        var p = new RadiusPacket { Code = data[0], Identifier = data[1], Authenticator = data[4..20] };
        int o = 20;
        while (o < len)
        {
            if (o + 2 > len) throw new RadiusFormatException("Truncated attribute header.");
            int al = data[o + 1];
            if (al < 2 || o + al > len) throw new RadiusFormatException($"Bad attribute length {al} at offset {o}.");
            p.Attributes.Add(new RadiusAttribute(data[o], data[(o + 2)..(o + al)]));
            o += al;
        }
        return p;
    }

    /// <summary>Offset of the first attribute of the given type inside an encoded packet, or -1.</summary>
    public static int FindAttributeOffset(byte[] pkt, int type)
    {
        int len = Math.Min(pkt.Length, BinaryPrimitives.ReadUInt16BigEndian(pkt.AsSpan(2)));
        int o = 20;
        while (o + 2 <= len)
        {
            if (pkt[o] == type) return o;
            if (pkt[o + 1] < 2) return -1;
            o += pkt[o + 1];
        }
        return -1;
    }

    public static byte[] RandomAuthenticator() => RandomNumberGenerator.GetBytes(16);
}
