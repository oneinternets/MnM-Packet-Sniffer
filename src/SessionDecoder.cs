namespace MnMSniffer;

/// <summary>Decrypts and emits application messages for one login. The key stays inside the layer.</summary>
sealed class SessionDecoder
{
    readonly MnMEncryptionLayer _layer;
    readonly LiteNetReassembler _reassembler = new();
    readonly ISink _sink;
    readonly HashSet<string> _servers = new();
    public int Count { get; private set; }
    public long FailureCount => _layer.FailureCount;

    public SessionDecoder(byte[] key, ISink sink)
    {
        _layer = new MnMEncryptionLayer(key);
        _sink = sink;
    }

    public void Accept(RawDatagram datagram)
    {
        if (!MnMEncryptionLayer.Framed(datagram.Payload)) return;
        if (!_layer.TryDecrypt(datagram.Payload, datagram.FromServer, out var clear)) return;
        if (datagram.Server.Length > 0 && _servers.Add(datagram.Server))
            Log.Info($"Recording {datagram.Server}");
        foreach (var packet in _reassembler.Accept(datagram.TsUtc, datagram.FromServer, clear, datagram.Server))
        {
            _sink.Emit(packet);
            Count++;
        }
    }
}
