using System.Buffers.Binary;
using System.Text;

namespace MnMSniffer;

/// <summary>
/// Decodes an application body (u16 opcode + fields) into ordered name->value pairs using the
/// scalar schema for the opcode (<see cref="PacketSchemas"/>). Safe: never throws; on running out
/// of bytes it returns what it read with <paramref name="complete"/>=false. Returns null when no
/// schema exists for the opcode (composite/unmapped packets — consumers keep the raw payload).
/// </summary>
public static class PacketDecoder
{
    public static List<KeyValuePair<string, object>>? Decode(ushort opcode, byte[] body, out bool complete)
    {
        complete = false;
        if (body is null) return null;
        // Hand-written composite decoders (conditionals/quantized/Vector3) take precedence.
        if (CompositeDecoders.Map.TryGetValue(opcode, out var composite))
        {
            var (fields, done) = composite(body);
            complete = done;
            return fields;
        }
        if (!PacketSchemas.Map.TryGetValue(opcode, out var specs)) return null;
        var outp = new List<KeyValuePair<string, object>>(specs.Length);
        int i = 2; // skip the u16 opcode
        foreach (var f in specs)
        {
            if (!TryRead(body, ref i, f.Type, out var val)) return outp; // partial decode
            outp.Add(new(f.Name, val));
        }
        complete = i == body.Length; // exact consume => high confidence
        return outp;
    }

    static bool TryRead(byte[] b, ref int i, FType t, out object val)
    {
        val = null!;
        var s = b.AsSpan();
        switch (t)
        {
            case FType.U8:   if (i + 1 > b.Length) return false; val = b[i]; i += 1; return true;
            case FType.Bool: if (i + 1 > b.Length) return false; val = b[i] != 0; i += 1; return true;
            case FType.I16:  if (i + 2 > b.Length) return false; val = BinaryPrimitives.ReadInt16LittleEndian(s.Slice(i)); i += 2; return true;
            case FType.U16:  if (i + 2 > b.Length) return false; val = BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(i)); i += 2; return true;
            case FType.I32:  if (i + 4 > b.Length) return false; val = BinaryPrimitives.ReadInt32LittleEndian(s.Slice(i)); i += 4; return true;
            case FType.U32:  if (i + 4 > b.Length) return false; val = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(i)); i += 4; return true;
            case FType.I64:  if (i + 8 > b.Length) return false; val = BinaryPrimitives.ReadInt64LittleEndian(s.Slice(i)); i += 8; return true;
            case FType.F32:  if (i + 4 > b.Length) return false; val = Math.Round(BinaryPrimitives.ReadSingleLittleEndian(s.Slice(i)), 3); i += 4; return true;
            case FType.Str:  return TryReadStr(b, ref i, out val);
            case FType.Bytes: // u16-length byte[] -> base64
            {
                if (i + 2 > b.Length) return false;
                int n = b[i] | b[i + 1] << 8; i += 2;
                if (i + n > b.Length) return false;
                val = Convert.ToBase64String(b, i, n); i += n; return true;
            }
            case FType.StrList:
            {
                if (i + 2 > b.Length) return false;
                int n = b[i] | b[i + 1] << 8; i += 2;
                if (n > 4096) return false;
                var list = new List<string>(n);
                for (int k = 0; k < n; k++) { if (!TryReadStr(b, ref i, out var sv)) return false; list.Add((string)sv); }
                val = list; return true;
            }
            default: return false;
        }
    }

    // MnM string: u16 prefix P; P==0 => empty; otherwise the content is P-1 UTF-8 bytes
    // (the client's ReadString reads `length - 1` bytes — see FUN_182381a30).
    static bool TryReadStr(byte[] b, ref int i, out object val)
    {
        val = null!;
        if (i + 2 > b.Length) return false;
        int p = b[i] | b[i + 1] << 8; i += 2;
        if (p == 0) { val = ""; return true; }
        int n = p - 1;
        if (i + n > b.Length) return false;
        val = Encoding.UTF8.GetString(b, i, n); i += n; return true;
    }
}
