using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace MnMSniffer;

/// <summary>
/// Passive UDP capture. Devices are opened read-only and nothing is transmitted.
/// Only datagrams whose source or destination port is owned by the game are kept.
/// </summary>
sealed class GameCapture : IDatagramSource, IDisposable
{
    readonly string? _iface;
    readonly PortTable _ports;
    readonly BlockingCollection<RawDatagram> _queue = new(8192);
    RawPcapWriter? _raw;
    readonly List<ICaptureDevice> _opened = new();
    readonly Dictionary<ulong, long> _seen = new();
    readonly object _seenGate = new();
    HashSet<string> _local = new();
    long _dropped;
    long _lastPrune;

    public long Dropped => Interlocked.Read(ref _dropped);

    public GameCapture(string? iface, PortTable ports)
    {
        _iface = iface;
        _ports = ports;
    }

    public void Use(RawPcapWriter raw) => _raw = raw;

    public void Start()
    {
        if (_raw == null) throw new InvalidOperationException("The raw dump file is not open.");
        foreach (var device in _opened) device.StartCapture();
    }

    public static void ListDevices()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            Console.WriteLine("No capture devices. Install Npcap, then start this program again.");
            return;
        }
        var local = devices.Where(IsLocalAdapter).ToList();
        if (local.Count == 0)
        {
            Console.WriteLine("No local capture devices. Install Npcap, then start this program again.");
            return;
        }
        foreach (var device in local)
            Console.WriteLine($"{device.Description}  {device.Name}");
    }

    /// <summary>Opens only the adapter the game client is using.</summary>
    public LinkLayers Open(ICaptureDevice device)
    {
        try
        {
            device.OnPacketArrival += OnPacket;
            device.Open(DeviceModes.Promiscuous, 100);
            device.Filter = "udp";
            _opened.Add(device);
        }
        catch (Exception ex)
        {
            try { device.Close(); } catch (Exception) { }
            throw new InvalidOperationException($"Could not open {Describe(device)}. {ex.Message}");
        }
        _local = LocalAddresses(_opened);
        return device.LinkType;
    }

    public IEnumerable<RawDatagram> Read(CancellationToken ct)
    {
        try
        {
            while (true)
            {
                if (_queue.TryTake(out var datagram, 200))
                {
                    yield return datagram;
                    continue;
                }
                if (!ct.IsCancellationRequested) continue;
                while (_queue.TryTake(out var rest)) yield return rest;
                yield break;
            }
        }
        finally
        {
            StopDevices();
            _queue.CompleteAdding();
        }
    }

    public void Dispose() => StopDevices();

    public List<ICaptureDevice> Candidates()
        => CaptureDeviceList.Instance.Where(Matches).Cast<ICaptureDevice>().ToList();

    bool Matches(ICaptureDevice device)
    {
        if (!IsLocalAdapter(device)) return false;
        if (_iface == null) return true;
        return device.Name.Contains(_iface, StringComparison.OrdinalIgnoreCase)
            || (device.Description?.Contains(_iface, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    /// <summary>Physical adapters on this PC. Tunnels and other virtual adapters are left out.</summary>
    public static bool IsLocalAdapter(ICaptureDevice device)
    {
        var text = $"{device.Name} {device.Description}";
        string[] skip =
        {
            "Loopback", "Bluetooth", "WAN Miniport", "Kernel Debug",
            "Tunnel", "TAP", "Wintun", "VPN", "Internet Access", "Virtual", "Hyper-V",
            "VMware", "VirtualBox", "vEthernet", "Pseudo"
        };
        return !skip.Any(s => text.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    void OnPacket(object sender, PacketCapture capture)
    {
        try
        {
            var raw = capture.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            var udp = packet.Extract<UdpPacket>();
            if (ip == null || udp == null) return;
            int srcPort = udp.SourcePort, dstPort = udp.DestinationPort;
            bool srcOwned = _ports.Contains(srcPort);
            bool dstOwned = _ports.Contains(dstPort);
            if (!srcOwned && !dstOwned) return;
            string src = ip.SourceAddress.ToString();
            string dst = ip.DestinationAddress.ToString();
            var payload = udp.PayloadData ?? Array.Empty<byte>();
            // The same datagram can show up on two local adapters (Wi-Fi and Ethernet). Collapse copies
            // that arrive within a few milliseconds. A later real resend has a new timestamp gap.
            if (SeenRecently(src, dst, srcPort, dstPort, payload)) return;
            var rawWriter = _raw;
            if (rawWriter == null) return;
            rawWriter.Write(raw);
            var datagram = Classify(raw.Timeval.Date.ToUniversalTime(), src, dst, srcPort, dstPort,
                payload, srcOwned, dstOwned);
            if (datagram != null && !_queue.TryAdd(datagram))
                Interlocked.Increment(ref _dropped);
        }
        catch (Exception)
        {
            /* malformed frame */
        }
    }

    RawDatagram? Classify(DateTime tsUtc, string srcIp, string dstIp, int srcPort, int dstPort,
        byte[] payload, bool srcOwned, bool dstOwned)
    {
        if (srcOwned && !dstOwned)
            return new RawDatagram(tsUtc, false, payload, Endpoint(dstIp, dstPort));
        if (dstOwned && !srcOwned)
            return new RawDatagram(tsUtc, true, payload, Endpoint(srcIp, srcPort));

        bool srcLocal = _local.Contains(srcIp), dstLocal = _local.Contains(dstIp);
        bool fromServer = srcLocal != dstLocal
            ? dstLocal
            : srcPort != dstPort ? srcPort < dstPort : string.CompareOrdinal(srcIp, dstIp) < 0;
        var server = fromServer ? Endpoint(srcIp, srcPort) : Endpoint(dstIp, dstPort);
        return new RawDatagram(tsUtc, fromServer, payload, server);
    }

    static string Endpoint(string ip, int port) => ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";

    bool SeenRecently(string src, string dst, int srcPort, int dstPort, byte[] payload)
    {
        ulong h = 14695981039346656037UL;
        h = Mix(h, src);
        h = Mix(h, dst);
        h = Mix(h, srcPort);
        h = Mix(h, dstPort);
        for (int i = 0; i < payload.Length; i++)
            h = (h ^ payload[i]) * 1099511628211UL;

        long now = Environment.TickCount64;
        lock (_seenGate)
        {
            if (now - _lastPrune > 1000)
            {
                var dead = new List<ulong>();
                foreach (var pair in _seen)
                    if (now - pair.Value > 1000) dead.Add(pair.Key);
                foreach (var key in dead) _seen.Remove(key);
                _lastPrune = now;
            }
            if (_seen.TryGetValue(h, out var seenAt) && now - seenAt < 20)
                return true;
            _seen[h] = now;
            return false;
        }
    }

    static ulong Mix(ulong hash, string text)
    {
        for (int i = 0; i < text.Length; i++)
            hash = (hash ^ (byte)text[i]) * 1099511628211UL;
        return hash;
    }

    static ulong Mix(ulong hash, int value)
    {
        for (int i = 0; i < 4; i++)
        {
            hash = (hash ^ (byte)value) * 1099511628211UL;
            value >>= 8;
        }
        return hash;
    }

    public static string Describe(ICaptureDevice device) =>
        string.IsNullOrWhiteSpace(device.Description) ? device.Name : device.Description;

    static HashSet<string> LocalAddresses(IEnumerable<ICaptureDevice> devices)
    {
        var local = new HashSet<string>(StringComparer.Ordinal);
        foreach (var device in devices.OfType<LibPcapLiveDevice>())
        {
            foreach (var address in device.Addresses)
            {
                var ip = address.Addr?.ipAddress;
                if (ip == null) continue;
                if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                    ip = new IPAddress(ip.GetAddressBytes());
                local.Add(ip.ToString());
            }
        }
        return local;
    }

    void StopDevices()
    {
        foreach (var device in _opened)
        {
            try { device.StopCapture(); } catch (Exception) { }
            try { device.Close(); } catch (Exception) { }
        }
        _opened.Clear();
    }
}
