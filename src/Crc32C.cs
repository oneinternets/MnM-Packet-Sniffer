namespace MnMSniffer;

/// <summary>
/// CRC-32C (Castagnoli, polynomial 0x1EDC6F41 / reflected 0x82F63B78). LiteNetLib's Crc32cLayer
/// appends these 4 bytes to every MnM datagram. Init 0xFFFFFFFF, reflected, result XORed with
/// 0xFFFFFFFF, written little-endian on the wire.
/// </summary>
public static class Crc32C
{
    const uint Poly = 0x82F63B78;
    static readonly uint[] Table = BuildTable();

    static uint[] BuildTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? Poly ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (var b in data)
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }
}
