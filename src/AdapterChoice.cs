using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using SharpPcap;
using SharpPcap.LibPcap;

namespace MnMSniffer;

/// <summary>
/// The one local adapter the game client is using. A socket bound to a real address selects
/// that adapter. A socket bound to every adapter follows the PC's route to the internet.
/// </summary>
static class AdapterChoice
{
    [DllImport("iphlpapi.dll")]
    static extern int GetBestInterface(uint destAddress, out uint ifIndex);

    public static ICaptureDevice? Find(int pid, IReadOnlyList<ICaptureDevice> devices, out string? waiting)
    {
        waiting = null;
        if (devices.Count == 0)
        {
            waiting = "No local capture device is available.";
            return null;
        }
        var binds = UdpPorts.Binds(pid, out _);
        if (binds.Length == 0)
        {
            waiting = "Waiting for the Monsters & Memories game client to open its network connection.";
            return null;
        }

        var specific = binds.Select(b => b.Address).Where(IsSpecific).Distinct().ToList();
        if (specific.Count > 0)
        {
            var match = devices.FirstOrDefault(d => specific.Any(ip => Owns(d, ip)));
            if (match != null) return match;
            waiting = "The game client is connected, but that adapter cannot be opened for capture.";
            return null;
        }

        var routed = DefaultRoute(devices);
        if (routed != null) return routed;
        waiting = "The game client is connected, but its adapter could not be identified.";
        return null;
    }

    static bool IsSpecific(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        if (IPAddress.IsLoopback(address)) return false;
        if (address.IsIPv6LinkLocal) return false;
        return true;
    }

    static bool Owns(ICaptureDevice device, IPAddress address)
    {
        if (device is LibPcapLiveDevice live)
        {
            foreach (var entry in live.Addresses)
            {
                var ip = entry.Addr?.ipAddress;
                if (ip == null) continue;
                if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    ip = new IPAddress(ip.GetAddressBytes());
                if (ip.Equals(address)) return true;
            }
        }
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!Same(device, nic)) continue;
            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                if (unicast.Address.Equals(address)) return true;
        }
        return false;
    }

    static ICaptureDevice? DefaultRoute(IReadOnlyList<ICaptureDevice> devices)
    {
        var destination = IPAddress.Parse("1.1.1.1");
        uint dest = BitConverter.ToUInt32(destination.GetAddressBytes(), 0);
        if (GetBestInterface(dest, out uint index) != 0) return null;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            int nicIndex;
            try { nicIndex = nic.GetIPProperties().GetIPv4Properties().Index; }
            catch (Exception) { continue; }
            if ((uint)nicIndex != index) continue;
            var device = devices.FirstOrDefault(d => Same(d, nic));
            if (device != null) return device;
        }
        return null;
    }

    static bool Same(ICaptureDevice device, NetworkInterface nic)
    {
        var id = nic.Id.Trim('{', '}');
        return id.Length > 0 && device.Name.Contains(id, StringComparison.OrdinalIgnoreCase);
    }
}
