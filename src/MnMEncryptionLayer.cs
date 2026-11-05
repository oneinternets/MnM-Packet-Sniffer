using System.Buffers.Binary;
using System.Security.Cryptography;

namespace MnMSniffer;

/// <summary>
/// Inbound decrypt for the MnM packet stack:
/// 4-byte CRC layer, then AES-256-CBC/PKCS7 with the IV in the first 16 bytes after the CRC.
/// HMAC/XOR layers exist in the game but are not wired, so they are not implemented.
/// </summary>
public sealed class MnMEncryptionLayer
{
    // The 4-byte CRC is CRC32C (Castagnoli), TRAILING, computed over IV+ciphertext.
    // That is LiteNetLib's built-in Crc32cLayer.
    // TryDecrypt strips the trailing 4 bytes before AES without re-validating them; HasValidCrc
    // checks them, which is how any-server mode tells MnM datagrams from other programs' UDP.
    private const int CrcOverhead = 4;
    private const bool CrcIsLeading = false;
    private const int IvLength = 16;
    private const int BlockLength = 16;
    private const int MinDatagramLength = CrcOverhead + IvLength + BlockLength;

    private readonly byte[] _key;
    private long _failureCount;

    public MnMEncryptionLayer(byte[] key)
    {
        if (key is null || key.Length != 32)
            throw new ArgumentException("AES-256 key must be exactly 32 bytes.", nameof(key));
        _key = (byte[])key.Clone();
    }

    public long FailureCount => Interlocked.Read(ref _failureCount);

    /// <summary>
    /// True when the datagram is MnM-framed: long enough for IV + one AES block + CRC, and its
    /// CRC32C (over IV + ciphertext) matches. Only checks; never decrypts or counts a failure.
    /// </summary>
    public static bool Framed(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < MinDatagramLength) return false;
        var body = CrcIsLeading ? datagram[CrcOverhead..] : datagram[..^CrcOverhead];
        var crc = CrcIsLeading ? datagram[..CrcOverhead] : datagram[^CrcOverhead..];
        return Crc32C.Compute(body) == BinaryPrimitives.ReadUInt32LittleEndian(crc);
    }

    public bool HasValidCrc(ReadOnlySpan<byte> datagram) => Framed(datagram);

    /// <summary>
    /// Decrypts a raw UDP payload into LiteNetLib packet bytes. The MnM AES layer is symmetric, so
    /// <paramref name="fromServer"/> is intentionally ignored: the same transform decrypts both
    /// directions (confirmed live — client-to-server decrypts with the same key and framing).
    /// Never throws for bad input; returns false (cleartext empty) and increments FailureCount.
    /// </summary>
    public bool TryDecrypt(ReadOnlySpan<byte> datagram, bool fromServer, out byte[] cleartext)
    {
        cleartext = Array.Empty<byte>();
        try
        {
            if (datagram.Length < MinDatagramLength)
                return Fail();

            var body = CrcIsLeading ? datagram[CrcOverhead..] : datagram[..^CrcOverhead];
            var iv = body[..IvLength];
            var ct = body[IvLength..];
            if (ct.Length == 0 || ct.Length % BlockLength != 0)
                return Fail();

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = _key;
            cleartext = aes.DecryptCbc(ct, iv, PaddingMode.PKCS7);
            return true;
        }
        catch (Exception)
        {
            cleartext = Array.Empty<byte>();
            return Fail();
        }
    }

    private bool Fail()
    {
        Interlocked.Increment(ref _failureCount);
        return false;
    }
}
