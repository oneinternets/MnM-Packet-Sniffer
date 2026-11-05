using System.Buffers.Binary;

namespace MnMSniffer;

public readonly record struct Vec3(float x, float y, float z);

/// <summary>
/// Hand-written decoders for packets whose serialization is not a flat scalar sequence
/// (conditionals, quantized/half-float fields, Vector3, nested blobs). Each was reverse-engineered
/// from the client's Deserialize and validated against the live capture. PacketDecoder consults
/// these before the generic scalar schema.
/// </summary>
public static class CompositeDecoders
{
    public static readonly IReadOnlyDictionary<ushort, Func<byte[], (List<KeyValuePair<string, object>> Fields, bool Complete)>> Map
        = new Dictionary<ushort, Func<byte[], (List<KeyValuePair<string, object>>, bool)>>
        {
            [0x0210] = PositionUpdate, // PositionUpdateNew (server->client); validated on 12,449 packets
            [0x0010] = SelfPosition,   // c2s PositionUpdate — the client's OWN position (id is 0)
            [0x0040] = ChatMessage,    // validated on 16 live packets (trailing 0)
            [0x0020] = SpawnEntity,    // core identity/stats/position fields (prefix before appearance lists)
            [0x0221] = RequestRespawnEntities, // c2s: batch request — a list of entity ids
        };

    // c2s RequestRespawnEntities: i32 count, then that many i32 entity ids.
    static (List<KeyValuePair<string, object>>, bool) RequestRespawnEntities(byte[] body)
    {
        var o = new List<KeyValuePair<string, object>>();
        var c = new Cur(body);
        var ids = new List<int>();
        if (!c.List(() => { if (!c.I32(out var v)) return false; ids.Add(v); return true; })) return (o, false);
        o.Add(new("ids", ids));
        return (o, c.End);
    }

    // SpawnEntity: decodes the leading identity/stats/position fields (validated on the capture:
    // name, class/race/sex, level, health/mana, position). After 'light' come variable-length
    // appearance/pet lists of nested structs (attachments, textures, features, pets) which are not
    // decoded here, so this is intentionally a partial decode (complete=false).
    static (List<KeyValuePair<string, object>>, bool) SpawnEntity(byte[] body)
    {
        var o = new List<KeyValuePair<string, object>>();
        var c = new Cur(body);
        bool R(string name, Func<(bool, object)> f) { var (ok, v) = f(); if (ok) o.Add(new(name, v)); return ok; }
        ushort et = 0;
        if (!R("id", () => (c.I32(out var v), v))) return (o, false);
        if (!c.U16(out et)) return (o, false); o.Add(new("entityType", (int)et));
        if (!R("name", () => (c.Str(out var v), v))) return (o, false);
        if (!R("characterId", () => (c.I32(out var v), v))) return (o, false);
        if (!R("classHID", () => (c.Str(out var v), v))) return (o, false);
        if (!R("raceHID", () => (c.Str(out var v), v))) return (o, false);
        if (!R("sexHID", () => (c.Str(out var v), v))) return (o, false);
        if (!R("skinTone", () => (c.U16(out var v), (int)v))) return (o, false);
        if (!R("level", () => (c.I32(out var v), v))) return (o, false);
        if (!R("health", () => (c.I32(out var v), v))) return (o, false);
        if (!R("maxHealth", () => (c.I32(out var v), v))) return (o, false);
        if (!R("mana", () => (c.I32(out var v), v))) return (o, false);
        if (!R("maxMana", () => (c.I32(out var v), v))) return (o, false);
        if (!c.Movement(out var pos, out var facing)) return (o, false);
        o.Add(new("position", pos)); o.Add(new("facing", facing));
        if (!R("spaceType", () => (c.U8(out var v), (int)v))) return (o, false);
        if (!R("spaceId", () => (c.I32(out var v), v))) return (o, false);
        if (!R("isAttacking", () => (c.Bool(out var v), v))) return (o, false);
        if (!R("targetID", () => (c.I32(out var v), v))) return (o, false);
        if (!R("posture", () => (c.U8(out var v), (int)v))) return (o, false);
        foreach (var fn in new[] { "isCorpse", "isCorpseMine", "isHostile", "isStealth", "isLevitating", "canSee", "hideNameplate" })
            if (!R(fn, () => (c.Bool(out var v), v))) return (o, false);
        if (!R("modelSizeMultiplier", () => (c.F32(out var v), v))) return (o, false);
        if (!R("masterID", () => (c.I32(out var v), v))) return (o, false);
        if (!R("isPlayerPet", () => (c.Bool(out var v), v))) return (o, false);
        if (!R("noCollision", () => (c.Bool(out var v), v))) return (o, false);
        if (!R("light", () => (c.I32(out var v), v))) return (o, false);

        // lightColor(rgb) + animationPresetID + showRangedWeapon
        if (!c.U8(out _) || !c.U8(out _) || !c.U8(out _) || !c.U8(out _) || !c.Bool(out _)) return (o, false);
        // TextureDefinition: u8,str,str,str,str,u16x5
        bool Texture() => c.U8(out _) && c.Str(out _) && c.Str(out _) && c.Str(out _) && c.Str(out _)
                          && c.U16(out _) && c.U16(out _) && c.U16(out _) && c.U16(out _) && c.U16(out _);
        // The part shared by players and NPCs, lightColor .. petLevels.
        bool Shared()
        {
            // attachmentDefinitions (AttachmentDefinition): str slot,str model,i64,bool,list<TextureDefinition>
            if (!c.List(() => c.Str(out _) && c.Str(out _) && c.I64(out _) && c.Bool(out _) && c.List(Texture))) return false;
            if (!c.List(Texture)) return false;              // textureDefinitions
            // features (ModelFeatureRecord): str hid,u16,bool coloured, then f32x3 if coloured else u16
            if (!c.List(() => c.Str(out _) && c.U16(out _) && c.Bool(out var coloured)
                              && (coloured ? c.F32(out _) && c.F32(out _) && c.F32(out _) : c.U16(out _)))) return false;
            if (!c.Str(out _)) return false;                 // materialOverride
            if (!c.Bool(out var hasModel)) return false;
            if (hasModel && !c.Str(out _)) return false;     // modelOverride
            return c.List(() => c.I32(out _))                // pets
                && c.List(() => c.U16(out _))                // petTypes
                && c.List(() => c.U16(out _));               // petLevels
        }
        if (!Shared()) return (o, false);

        if (et == 0)
        {
            // Player tail: i32 anonymousType, str surname, str guildName, i32 guildRank, 7 bools
            // (isHardcore, isLfg, isAfk, isDnd, hasGmNametag, isSelfFound, isPvPFlagged), bool hasDeity,
            // [ClientDeityRecord].
            if (!c.I32(out _)) return (o, false);
            if (!R("surname", () => (c.Str(out var v), v))) return (o, false);
            if (!R("guildName", () => (c.Str(out var v), v))) return (o, false);
            if (!R("guildRank", () => (c.I32(out var v), v))) return (o, false);
            for (int k = 0; k < 7; k++) if (!c.Bool(out _)) return (o, false);
            if (!R("hasDeity", () => (c.Bool(out var v), v))) return (o, false);
            if ((bool)o[^1].Value)
            {
                // ClientDeityRecord: i32 ClientId, str DeityHID, i32 Priority, i32 Devotion, 4 x i64 dates
                if (!c.I32(out _)) return (o, false);
                if (!R("deityHID", () => (c.Str(out var v), v))) return (o, false);
                if (!c.I32(out _) || !c.I32(out _) || !c.I64(out _) || !c.I64(out _) || !c.I64(out _) || !c.I64(out _)) return (o, false);
            }
            if (!c.F32(out _) || !c.I32(out _) || !c.U16(out _)) return (o, false);
            return (o, c.End);
        }

        // Other types (not NPC) have an unknown tail.
        if (et != 1) return (o, false);

        // NPC type block (entityType==1): the flags the map categorises by
        if (!c.Bool(out var isMerchant) || !c.Bool(out var isGuard) || !c.Bool(out var isBanker) || !c.Bool(out var isTrainer))
            return (o, false);
        o.Add(new("isMerchant", isMerchant));
        o.Add(new("isGuard", isGuard));
        o.Add(new("isBanker", isBanker));
        o.Add(new("isTrainer", isTrainer));
        // npcTypeHID + common tail: all must be present for an exact, complete consume
        if (!c.Str(out _) || !c.F32(out _) || !c.I32(out _) || !c.U16(out _)) return (o, false);
        return (o, c.End);
    }

    // ChatMessage: chunkCount(i32, clamped 1..3), that many string chunks concatenated into the
    // message, then channel(u8), language(string), sourceEntityId(i32). Validated on the capture.
    static (List<KeyValuePair<string, object>>, bool) ChatMessage(byte[] body)
    {
        var o = new List<KeyValuePair<string, object>>();
        var c = new Cur(body);
        if (!c.I32(out var count)) return (o, false);
        int n = count < 1 ? 0 : count < 4 ? count : 3;
        var msg = new System.Text.StringBuilder();
        for (int k = 0; k < n; k++) { if (!c.Str(out var part)) return (o, false); msg.Append(part); }
        o.Add(new("message", msg.ToString()));
        if (!c.U8(out var channel)) return (o, false); o.Add(new("channel", channel));
        if (!c.Str(out var lang)) return (o, false); o.Add(new("language", lang));
        if (!c.I32(out var src)) return (o, false); o.Add(new("sourceEntityId", src));
        return (o, c.End);
    }

    // c2s PositionUpdate (0x0010): the client reporting its OWN movement. Layout (46 bytes):
    // i32 id(=0, server infers self), i64, Vec3 position(f32), f32 facing, u16x3, i32, u8 posture,
    // f32, bool. We expose id + position (used by the map as "you").
    static (List<KeyValuePair<string, object>>, bool) SelfPosition(byte[] body)
    {
        var o = new List<KeyValuePair<string, object>>();
        var c = new Cur(body);
        if (!c.I32(out var id)) return (o, false); o.Add(new("id", id));
        if (!c.I64(out _)) return (o, false);
        if (!c.Vec3(out var pos)) return (o, false); o.Add(new("position", pos));
        if (c.F32(out var facing)) o.Add(new("facing", facing));
        return (o, false); // remaining fields not needed
    }

    // PositionUpdate(New): i32 id, then the shared movement blob (Cur.Movement). Validated on all
    // 1,475,269 PositionUpdateNew of dump_20261016_062537; the packet has no trailing 'animate' byte,
    // so any byte left over means the layout is wrong (complete=false).
    static (List<KeyValuePair<string, object>>, bool) PositionUpdate(byte[] body)
    {
        var o = new List<KeyValuePair<string, object>>();
        var c = new Cur(body);
        if (!c.I32(out var id)) return (o, false); o.Add(new("id", id));
        if (!c.Movement(out _, out _, o)) return (o, false);
        return (o, c.End);
    }
}
