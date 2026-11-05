namespace MnMSniffer;

/// <summary>
/// Decodes LiteNetLib packets from decrypted datagrams into application packets, un-merging
/// Merged containers and reassembling fragmented Channeled messages.
///
/// Layout, little-endian:
///   byte 0: low 5 bits = PacketProperty; bits 5-6 = ConnectionNumber; 0x80 = fragmented.
///   Unreliable (prop 0):  header 1 byte (no channel); body at offset 1; channel reported as 0.
///   Channeled  (prop 1):  header 4 bytes — seq (ushort) @1-2, ChannelId @3; body at 4.
///     If fragmented (0x80): fragmentId @4-5, fragmentPart @6-7, fragmentsTotal @8-9, data @10;
///     reassembled by (server, channel, direction, fragmentId), so two servers' fragments never mix.
///   Merged     (prop 12): container of [ushort length][sub-packet]...; each sub-packet is a full
///     LiteNetLib packet, decoded recursively. Carries the bulk of application traffic.
///   Everything else (Ack 2, Ping 3, Pong 4, Connect*, Mtu*, Disconnect, ...): transport, dropped.
/// </summary>
public sealed class LiteNetReassembler
{
    const byte FragmentBit = 0x80;
    const int PropUnreliable = 0;
    const int PropChanneled = 1;
    const int PropMerged = 12;
    const int ChanneledHeader = 4;   // prop, seq(2), channel
    const int FragmentHeader = 10;   // channeled header (4) + fragmentId(2) + part(2) + total(2)
    const int MergedLenSize = 2;
    const int MaxMergedDepth = 4;    // Merged-in-Merged is not expected; bound recursion defensively
    // total is untrusted (0..65535) and sizes a per-group array; real messages fragment into a handful of parts.
    const int MaxFragments = 1024;

    sealed class Group
    {
        public readonly byte[]?[] Parts;
        public int Received;
        public Group(int total) { Parts = new byte[]?[total]; }
    }

    readonly int _max;
    readonly Dictionary<(string, byte, bool, ushort), Group> _groups = new();
    // Insertion order of keys; first node is the oldest group (eviction victim).
    readonly LinkedList<(string, byte, bool, ushort)> _order = new();

    public LiteNetReassembler(int maxPendingGroups = 256) { _max = Math.Max(1, maxPendingGroups); }

    public int PendingGroupCount => _groups.Count;

    /// <param name="server">The server end (<c>ip:port</c>) the datagram belongs to; fragment groups are per server.</param>
    public IEnumerable<AppPacket> Accept(DateTime tsUtc, bool fromServer, byte[] cleartext, string server = "")
    {
        var outp = new List<AppPacket>();
        if (cleartext is not null && cleartext.Length >= 1)
            Decode(tsUtc, fromServer, server, cleartext, 0, outp);
        return outp;
    }

    void Decode(DateTime tsUtc, bool fromServer, string server, ReadOnlySpan<byte> pkt, int depth, List<AppPacket> outp)
    {
        if (pkt.Length < 1) return;
        int prop = pkt[0] & 0x1F;

        if (prop == PropMerged)
        {
            if (depth >= MaxMergedDepth) return;
            int i = 1;
            while (i + MergedLenSize <= pkt.Length)
            {
                int len = pkt[i] | (pkt[i + 1] << 8);
                i += MergedLenSize;
                if (len == 0 || i + len > pkt.Length) break; // zero length or overrun: stop
                Decode(tsUtc, fromServer, server, pkt.Slice(i, len), depth + 1, outp);
                i += len;
            }
            return;
        }

        if (prop == PropUnreliable)
        {
            // header 1 byte, no channel
            outp.Add(new AppPacket(tsUtc, fromServer, 0, pkt[1..].ToArray()));
            return;
        }

        if (prop == PropChanneled)
        {
            if (pkt.Length < ChanneledHeader) return;
            byte channel = pkt[3];
            bool frag = (pkt[0] & FragmentBit) != 0;
            if (!frag)
            {
                outp.Add(new AppPacket(tsUtc, fromServer, channel, pkt[ChanneledHeader..].ToArray()));
                return;
            }
            if (pkt.Length < FragmentHeader) return;
            ushort id = (ushort)(pkt[4] | pkt[5] << 8);
            ushort part = (ushort)(pkt[6] | pkt[7] << 8);
            ushort total = (ushort)(pkt[8] | pkt[9] << 8);
            if (total == 0 || part >= total || total > MaxFragments) return;
            var reassembled = AcceptFragment(server, channel, fromServer, id, part, total, pkt[FragmentHeader..]);
            if (reassembled != null)
                outp.Add(new AppPacket(tsUtc, fromServer, channel, reassembled));
            return;
        }
        // transport/control (Ack, Ping, Pong, Connect*, Mtu*, ...): no application body
    }

    /// <summary>Feeds one fragment; returns the reassembled body once the last part arrives, else null.</summary>
    byte[]? AcceptFragment(string server, byte channel, bool fromServer, ushort id, ushort part, ushort total, ReadOnlySpan<byte> data)
    {
        var key = (server, channel, fromServer, id);
        if (!_groups.TryGetValue(key, out var g) || g.Parts.Length != total)
        {
            if (g != null) { _groups.Remove(key); _order.Remove(key); } // stale group with mismatched total
            while (_groups.Count >= _max)
            {
                var oldest = _order.First!.Value;
                _order.RemoveFirst();
                _groups.Remove(oldest);
            }
            g = new Group(total);
            _groups[key] = g;
            _order.AddLast(key);
        }
        if (g.Parts[part] != null) return null; // duplicate part
        g.Parts[part] = data.ToArray();
        g.Received++;
        if (g.Received < total) return null;

        _groups.Remove(key);
        _order.Remove(key);
        var ms = new MemoryStream();
        foreach (var p in g.Parts) ms.Write(p!);
        return ms.ToArray();
    }
}
