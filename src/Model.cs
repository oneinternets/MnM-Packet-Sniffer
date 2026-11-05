namespace MnMSniffer;

/// <summary>One captured UDP payload.</summary>
/// <param name="Server">The server end as <c>ip:port</c> ("" when the source does not know it);
/// fragment reassembly is kept separate per server.</param>
public record RawDatagram(DateTime TsUtc, bool FromServer, byte[] Payload, string Server = "");

public record AppPacket(DateTime TsUtc, bool FromServer, byte Channel, byte[] Payload)
{
    // Application opcode = first two body bytes (u16 LE). MnM's PacketRouter dispatches on it
    // (GetPacketTypeFromOpcode); the rest of the body is serialized for that message type.
    public ushort Opcode => Payload.Length >= 2 ? (ushort)(Payload[0] | Payload[1] << 8) : Payload.Length == 1 ? Payload[0] : (ushort)0;
    public string? OpcodeName => OpcodeNames.Get(Opcode);
}

public interface ISink { void Emit(AppPacket p); }

public record DumpRecord(long TsUnixMs, bool FromServer, byte Channel, byte[] Payload)
{
    public ushort Opcode => Payload.Length >= 2 ? (ushort)(Payload[0] | Payload[1] << 8) : Payload.Length == 1 ? Payload[0] : (ushort)0;
}
