using System.Collections;
using System.Text.Json;

namespace MnMSniffer;

/// <summary>One JSON object for one decoded application packet.</summary>
public static class PacketJson
{
    public static string ToJson(AppPacket p)
    {
        var decoded = PacketDecoder.Decode(p.Opcode, p.Payload, out var full);
        Dictionary<string, object?>? fields = null;
        if (decoded != null)
        {
            fields = new Dictionary<string, object?>(decoded.Count);
            foreach (var kv in decoded)
                fields[kv.Key] = Finite(kv.Value);
        }
        return JsonSerializer.Serialize(new
        {
            ts = new DateTimeOffset(p.TsUtc.ToUniversalTime()).ToUnixTimeMilliseconds(),
            dir = p.FromServer ? "s2c" : "c2s",
            channel = (int)p.Channel,
            opcode = (int)p.Opcode,
            name = p.OpcodeName,
            fields,
            full = decoded != null ? full : (bool?)null,
            len = p.Payload.Length,
            data = Convert.ToBase64String(p.Payload),
        });
    }

    /// <summary>Infinity and NaN are not legal JSON. Those numbers become null; the message is still written.</summary>
    static object? Finite(object? value)
    {
        switch (value)
        {
            case float f:
                return float.IsFinite(f) ? f : null;
            case double d:
                return double.IsFinite(d) ? d : null;
            case Vec3 v:
                return new Dictionary<string, object?>
                {
                    ["x"] = float.IsFinite(v.x) ? v.x : null,
                    ["y"] = float.IsFinite(v.y) ? v.y : null,
                    ["z"] = float.IsFinite(v.z) ? v.z : null,
                };
            case IList list:
                var copy = new List<object?>(list.Count);
                foreach (var item in list)
                    copy.Add(Finite(item));
                return copy;
            default:
                return value;
        }
    }
}
