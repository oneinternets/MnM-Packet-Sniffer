namespace MnMSniffer;

public static class Pipeline
{
    /// <summary>capture -> decrypt -> reassemble -> emit; returns count of emitted AppPackets.</summary>
    /// <param name="anyServer">
    /// Any-server mode: the source yields every UDP datagram, so only datagrams whose MnM CRC32C is
    /// valid are MnM traffic. Anything else is dropped silently before decryption: it is not a decrypt
    /// failure, does not trip <paramref name="strict"/>, and never reaches the sink or the log.
    /// </param>
    public static int Run(IDatagramSource source, MnMEncryptionLayer layer, LiteNetReassembler reasm,
        ISink sink, bool strict, CancellationToken ct, bool anyServer = false)
    {
        int count = 0;
        var servers = new HashSet<string>();
        try
        {
            foreach (var d in source.Read(ct))
            {
                if (ct.IsCancellationRequested) break;
                if (anyServer && !layer.HasValidCrc(d.Payload)) continue; // not MnM traffic
                // Both directions: the MnM AES layer is symmetric (same key + [IV][ct][CRC] framing
                // confirmed live for c2s, 690/690 CRC32C match) and the reassembler keys fragment
                // groups by direction, so client->server decodes with the same path as server->client.
                if (!layer.TryDecrypt(d.Payload, d.FromServer, out var clear))
                {
                    if (strict) break;
                    continue;
                }
                if (d.Server.Length > 0 && servers.Add(d.Server)) Log.Info($"Recording {d.Server}");
                foreach (var p in reasm.Accept(d.TsUtc, d.FromServer, clear, d.Server))
                {
                    sink.Emit(p);
                    count++;
                }
            }
        }
        catch (OperationCanceledException) { }
        return count;
    }
}
