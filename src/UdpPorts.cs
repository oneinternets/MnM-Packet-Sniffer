using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace MnMSniffer;

readonly record struct UdpBind(IPAddress Address, int Port);

/// <summary>
/// Local UDP ports owned by one process. IPv4 layout was checked against a live socket.
/// A family whose table size does not match the row struct is skipped rather than guessed.
/// </summary>
static class UdpPorts
{
    const uint AfInet = 2;
    const uint AfInet6 = 23;
    const int UdpTableOwnerPid = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, uint family, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    struct Row4
    {
        public uint Addr;
        public uint Port;
        public uint Pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Row6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Addr;
        public uint Scope;
        public uint Port;
        public uint Pid;
    }

    public static int[] ForProcess(int pid, out string? warning)
        => Binds(pid, out warning).Select(b => b.Port).Distinct().OrderBy(p => p).ToArray();

    public static UdpBind[] Binds(int pid, out string? warning)
    {
        warning = null;
        var found = new List<UdpBind>();
        var notes = new List<string>();
        Read(AfInet, pid, found, notes);
        Read(AfInet6, pid, found, notes);
        if (notes.Count > 0) warning = string.Join(" ", notes);
        return found.Where(b => b.Port > 0).ToArray();
    }

    static void Read(uint family, int pid, List<UdpBind> found, List<string> notes)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpTableOwnerPid, 0);
        if (size <= 0) return;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            uint rc = GetExtendedUdpTable(buf, ref size, false, family, UdpTableOwnerPid, 0);
            if (rc != 0) return;
            int count = Marshal.ReadInt32(buf);
            int rowSize = family == AfInet ? Marshal.SizeOf<Row4>() : Marshal.SizeOf<Row6>();
            if (count < 0 || 4L + (long)count * rowSize > size)
            {
                notes.Add(family == AfInet
                    ? "IPv4 UDP table had an unexpected size."
                    : "IPv6 UDP table had an unexpected size; IPv6 sockets were skipped.");
                return;
            }
            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(buf, 4 + i * rowSize);
                uint portRaw, owning;
                IPAddress address;
                if (family == AfInet)
                {
                    var r = Marshal.PtrToStructure<Row4>(row);
                    portRaw = r.Port;
                    owning = r.Pid;
                    // The DWORD is already the network-order address bytes.
                    address = new IPAddress(BitConverter.GetBytes(r.Addr));
                }
                else
                {
                    var r = Marshal.PtrToStructure<Row6>(row);
                    portRaw = r.Port;
                    owning = r.Pid;
                    address = r.Addr is { Length: 16 } bytes ? new IPAddress(bytes) : IPAddress.IPv6Any;
                }
                if (owning == (uint)pid) found.Add(new UdpBind(address, PortOf(portRaw)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>The port is network-order in the low 16 bits of the DWORD.</summary>
    static int PortOf(uint value)
    {
        var b = BitConverter.GetBytes(value);
        return (b[0] << 8) | b[1];
    }
}
