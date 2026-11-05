using System.Buffers.Binary;

namespace MnMSniffer;

internal sealed class Cur
{
    readonly byte[] _b;
    public int I;
    public Cur(byte[] b) { _b = b; I = 2; } // skip the u16 opcode
    public bool End => I >= _b.Length;
    bool Need(int n) => I + n <= _b.Length;
    public bool U8(out byte v) { v = 0; if (!Need(1)) return false; v = _b[I++]; return true; }
    public bool Bool(out bool v) { v = false; if (!Need(1)) return false; v = _b[I++] != 0; return true; }
    public bool U16(out ushort v) { v = 0; if (!Need(2)) return false; v = BinaryPrimitives.ReadUInt16LittleEndian(_b.AsSpan(I)); I += 2; return true; }
    public bool I32(out int v) { v = 0; if (!Need(4)) return false; v = BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan(I)); I += 4; return true; }
    public bool I64(out long v) { v = 0; if (!Need(8)) return false; v = BinaryPrimitives.ReadInt64LittleEndian(_b.AsSpan(I)); I += 8; return true; }
    public bool SkipBytes(int n) { if (n < 0 || !Need(n)) return false; I += n; return true; }
    // The unread tail, from I to the end.
    public ReadOnlyMemory<byte> Rest() => _b.AsMemory(Math.Min(I, _b.Length));
    public bool SkipStr() { return Str(out _); }
    // Same bounds rules as Str but only advances the cursor (no string is built, nothing is kept).
    public bool SkipStrNoAlloc()
    {
        if (!Need(2)) return false;
        int p = _b[I] | _b[I + 1] << 8; I += 2;
        if (p == 0) return true;
        return SkipBytes(p - 1);
    }
    // Read an i32 count then run `elem` that many times (bounded against a misaligned huge count).
    public bool List(Func<bool> elem) { if (!I32(out var n) || n < 0 || n > 100000) return false; for (int k = 0; k < n; k++) if (!elem()) return false; return true; }
    // The shared movement blob (PositionSyncGoalData, FUN_1807aec60): i32 serverFrame, u8 flags,
    // Vec3 position, 3 half (facing, moveSpeed, turnSpeed); flags&1 IsMoving adds Vec3 extrapolated
    // position + half extrapolated facing; flags&8 IsOnTransport adds 36 bytes (i32 parentId, Vec3
    // position, 3 half, Vec3 extrapolated position, half extrapolated facing); flags&16 HasPosture adds
    // u8 posture; flags&128 IsClimbing adds half climbPitch. Returns position and facing; when `o` is
    // given every field is appended to it (posture = the flags byte, velocity = extrapolated position).
    public bool Movement(out Vec3 pos, out Vec3 facing, List<KeyValuePair<string, object>>? o = null)
    {
        pos = default; facing = default;
        if (!I32(out var seq) || !U8(out var flags) || !Vec3(out pos) || !Vec3Half(out facing)) return false;
        // Naming: "posture" is the PositionSyncFlags byte, under the field name the decoder has always used (older
        // decoded output keeps the same keys). The EntityPosture itself (0 Stand, 1 Sit, 2 Crouch, 3 Kneel) is
        // "postureState", present only with flags&16 HasPosture.
        o?.Add(new("updateSequence", seq)); o?.Add(new("posture", flags));
        o?.Add(new("position", pos)); o?.Add(new("facing", facing));
        if ((flags & 1) != 0)
        {
            if (!Vec3(out var vel) || !Half(out var va)) return false;
            o?.Add(new("velocity", vel)); o?.Add(new("velocityFacing", va));
        }
        if ((flags & 8) != 0)
        {
            if (!I32(out var pid) || !Vec3(out var ppos) || !Vec3Half(out var pfac)
                || !Vec3(out var pext) || !Half(out var pextFacing)) return false;
            o?.Add(new("parentId", pid)); o?.Add(new("parentPosition", ppos)); o?.Add(new("parentFacing", pfac));
            o?.Add(new("parentExtrapolatedPosition", pext)); o?.Add(new("parentExtrapolatedFacing", pextFacing));
        }
        if ((flags & 16) != 0)
        {
            if (!U8(out var ps)) return false;
            o?.Add(new("postureState", (int)ps));                      // EntityPosture (see "posture" above)
        }
        if ((flags & 128) != 0)
        {
            if (!Half(out var cp)) return false;
            o?.Add(new("climbPitch", cp));
        }
        return true;
    }
    public bool F32(out float v) { v = 0; if (!Need(4)) return false; v = (float)Math.Round(BinaryPrimitives.ReadSingleLittleEndian(_b.AsSpan(I)), 3); I += 4; return true; }
    public bool Half(out float v) { v = 0; if (!Need(2)) return false; v = (float)Math.Round((float)BinaryPrimitives.ReadHalfLittleEndian(_b.AsSpan(I)), 3); I += 2; return true; }
    public bool Vec3(out Vec3 v) { v = default; if (!F32(out var x) || !F32(out var y) || !F32(out var z)) return false; v = new(x, y, z); return true; }
    public bool Vec3Half(out Vec3 v) { v = default; if (!Half(out var x) || !Half(out var y) || !Half(out var z)) return false; v = new(x, y, z); return true; }
    // MnM string: u16 prefix P; 0 => empty; else P-1 UTF-8 bytes.
    public bool Str(out string v)
    {
        v = ""; if (!Need(2)) return false;
        int p = _b[I] | _b[I + 1] << 8; I += 2;
        if (p == 0) return true;
        int n = p - 1; if (I + n > _b.Length) return false;
        v = System.Text.Encoding.UTF8.GetString(_b, I, n); I += n; return true;
    }
}
