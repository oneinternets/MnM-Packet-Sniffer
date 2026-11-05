using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MnMSniffer;

/// <summary>
/// Read-only search for this login's AES-256 key in the game process.
/// A hit must decrypt every sample and yield a LiteNetLib property byte.
/// The key is never written to the log.
/// </summary>
static class SessionKey
{
    const uint QueryAndRead = 0x0410; // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

    public static byte[]? Find(int pid, IReadOnlyList<byte[]> payloads, CancellationToken ct, out string? problem)
    {
        problem = null;
        if (payloads.Count < 2) return null;
        var handle = Native.OpenProcess(QueryAndRead, false, pid);
        if (handle == IntPtr.Zero)
        {
            problem = $"Could not read the game process (Win32 {Marshal.GetLastWin32Error()}). The raw dump continues. Start this program as the same user that is running the game.";
            return null;
        }
        try
        {
            var hits = new HashSet<string>(StringComparer.Ordinal);
            Scan(handle, payloads, hits, ct);
            if (ct.IsCancellationRequested) return null;
            if (hits.Count == 1) return Convert.FromHexString(hits.Single());
            if (hits.Count > 1)
                problem = "More than one session key matched the captured packets. Parsing stays off.";
            return null;
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    static void Scan(IntPtr handle, IReadOnlyList<byte[]> payloads, HashSet<string> hits, CancellationToken ct)
    {
        long addr = 0;
        int mbiSize = Marshal.SizeOf<Native.Mbi>();
        while (!ct.IsCancellationRequested &&
               Native.VirtualQueryEx(handle, (IntPtr)addr, out var mbi, (IntPtr)mbiSize) != IntPtr.Zero)
        {
            long size = mbi.RegionSize.ToInt64();
            long next = mbi.BaseAddress.ToInt64() + size;
            if (next <= addr) break;
            addr = next;
            if (mbi.State != 0x1000 || size < 48) continue;          // MEM_COMMIT
            if ((mbi.Protect & 0x101) != 0 || (mbi.Protect & 0xEE) == 0) continue; // guard/no-access, or not readable
            ScanRegion(handle, mbi.BaseAddress.ToInt64(), size, payloads, hits, ct);
        }
    }

    static void ScanRegion(IntPtr handle, long baseAddr, long size, IReadOnlyList<byte[]> payloads, HashSet<string> hits, CancellationToken ct)
    {
        const int Chunk = 4 << 20;
        const int Tail = 64;
        var buf = new byte[Chunk + Tail];
        for (long off = 0; off < size && !ct.IsCancellationRequested; off += Chunk)
        {
            int want = (int)Math.Min(buf.Length, size - off);
            if (!Native.ReadProcessMemory(handle, (IntPtr)(baseAddr + off), buf, (IntPtr)want, out var got)) continue;
            int n = (int)got.ToInt64();
            for (int i = 8; i + 40 <= n; i += 8)
            {
                if (BitConverter.ToUInt64(buf, i - 8) != 0) continue;
                ulong len = BitConverter.ToUInt64(buf, i);
                byte[]? key = null;
                if (len == 32) key = buf.AsSpan(i + 8, 32).ToArray();
                else if (len == 161 && i + 8 + 161 <= n && buf[i + 8] == 0x01) key = buf.AsSpan(i + 8 + 65, 32).ToArray();
                if (key == null || !Plausible(key)) continue;
                if (Works(key, payloads)) hits.Add(Convert.ToHexString(key));
            }
        }
    }

    static bool Plausible(ReadOnlySpan<byte> key)
    {
        Span<int> seen = stackalloc int[256];
        int distinct = 0;
        for (int i = 0; i < key.Length; i++)
            if (seen[key[i]]++ == 0) distinct++;
        return distinct >= 16;
    }

    static bool Works(byte[] key, IReadOnlyList<byte[]> payloads)
    {
        foreach (var payload in payloads)
            if (!One(key, payload)) return false;
        return true;
    }

    static bool One(byte[] key, byte[] datagram)
    {
        int bodyLen = datagram.Length - 4;
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            var clear = aes.DecryptCbc(datagram.AsSpan(16, bodyLen - 16), datagram.AsSpan(0, 16), PaddingMode.PKCS7);
            return clear.Length > 0 && clear[0] <= 12;
        }
        catch (Exception)
        {
            return false;
        }
    }
}

static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Mbi
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualQueryEx(IntPtr handle, IntPtr address, out Mbi mbi, IntPtr length);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr handle, IntPtr address, byte[] buffer, IntPtr size, out IntPtr read);
}
