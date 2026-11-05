using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace MnMSniffer;

/// <summary>Writes the original captured frames to one pcap. Close finalizes the file.</summary>
sealed class RawPcapWriter : IDisposable
{
    readonly CaptureFileWriterDevice _device;
    readonly object _gate = new();
    bool _closed;
    long _count;

    public long Count { get { lock (_gate) return _count; } }

    public RawPcapWriter(string path, LinkLayers link)
    {
        _device = new CaptureFileWriterDevice(path, FileMode.Create);
        _device.Open(new DeviceConfiguration
        {
            LinkLayerType = link,
            Snaplen = 65535
        });
    }

    public void Write(RawCapture packet)
    {
        lock (_gate)
        {
            if (_closed) return;
            _device.Write(packet);
            _count++;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            try { _device.Close(); } catch (Exception) { }
        }
    }
}
