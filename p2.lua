-- p2.lua — Siemens APOGEE P2 (Protocol II) Wireshark dissector
-- Version: 2.8  (2026-08-25)  -- the two EQS records decoded in full
--
-- Changelog
--   2.8  The two EQS upload records decoded in full.
--        * 0x0989 mode schedule: eleven fields, not five. entry_enabled, mode,
--          occurrence, scheduled_days (a BITMASK, bit0=Sunday), start/end date,
--          start/stop time, days_spanned, exclusive, state_text_id. The old
--          reading landed on the dates by accident and mislabelled three fields.
--        * 0x0987 zone: the lead u16 is a COUNT OF NAMES. What was called a
--          two-byte separator is the second Team_response's own name_space --
--          and the pair is system-name + user-name, not a duplicate.
--        * The trailing u16 on both is the state-text-table id: constant per
--          zone and identical across both opcodes.
--   2.7  Error table corrected. Eight names were wrong -- three outright and a
--        five-code off-by-one -- and are replaced by the full 0x0001..0x0E17 set.
--        * 0x0E11 was "already_exists"; it is fln_invalid_drop_number. The
--          scanner had been treating it as a success, so a failed FLN point-add
--          reported as having worked.
--        * 0x0E12 was "record_state_rejected (unconfirmed)" / "invalid_point_number";
--          it is fln_device_failed. Invalid point number is 0x0E13.
--        * 0x0009 was unnamed; it is already_exists.
--        * 0x0002 was "out_of_scope"; it is invalid_operation.
--        * 0x0E10-0x0E17 is the FLN error band -- field-level faults, not
--          record-state rejections.
--        * 0x00AC "not_supported" also covers a function code specific to a
--          different firmware revision, so it does not prove an opcode is
--          unimplemented.
--   2.6  Accuracy pass against the corpus.
--        * 0x29 / 0x2A carrier labels corrected. They were named "peer maintenance"
--          and "peer COV-subscribe"; the corpus establishes neither function. They
--          are now "session carrier" and "peer-session carrier (panel<->panel)",
--          matching PROTOCOL.md 6.2. Both carry the EBLN_PING 0x4640 identity
--          exchange.
--        * Error 0x0E12 named "record_state_rejected (unconfirmed)" -- observed a
--          few times, adjacent to already-exists, precise meaning not pinned.
--          (Superseded in 2.7: it is fln_device_failed.)
--        * Opcode 0x0030 AP2_SET_GLOBAL_DATA added.
--        * BUG FIX: the error-tail read guarded on total>=2 and then read
--          tvb(total-2,2). On a truncated dir==0x05 frame whose routing slots run to
--          the end there is no tail, so that lifted two header/slot bytes and
--          rendered a phantom error code (observed: a 13-byte frame reporting
--          "ERROR 0x0105"). Now guards on off+2, matching the tree item.
--   2.5  Response correlation via sequence state. Responses (direction 0x01 success /
--        0x05 error) carry NO opcode on the wire — only the request does — but a response
--        echoes its request's sequence number. The dissector now keeps a per-TCP-stream
--        {sequence -> opcode} map (populated from direction==0x00 frames) and uses it to:
--          * label each response with the operation it answers ("response to
--            POINT_LOG_VALUE", "ERROR not_found — request was POINT_CMD_VALUE"), and
--          * dispatch a response-body decoder by the recovered opcode.
--        Response decoders added (designed against real captured bytes):
--          * CABINET_DISPLAY 0x010C -> firmware banner (rev / platform / build-date TLVs,
--            then node/site/BLN + IP/MAC via the walk) — the richest unauthenticated read.
--          * EBLN_PING 0x4640 -> eBLN_Node (node/site/BLN) via the identity decoder.
--          * Value responses (POINT_LOG_VALUE 0x0220, POINT_LOG_ALARM 0x0221, COV_ENABLE
--            0x0271, UPL_ALL_* 0x0981/0x0982, TREND_DATA_DISPLAY 0x0295): names + EU-units
--            string, and the value block (3F FF FF Fx quality sentinel + sub-type + f32)
--            where present. NOTE: in a plain analog read the f32 is not behind the quality
--            sentinel and its offset varies by point type, so it is left in the raw body
--            rather than guessed (see PROTOCOL.md 10.9 [OPEN]); UPL/sentinel-framed values
--            ARE decoded. Honest over confidently-wrong.
--        seq-state is populated only on the first pass (pinfo.visited guard); requests
--        precede their responses in capture order so the map is ready when the response is
--        seen. Unmatched responses (request not in capture) fall back to the generic walk.
--   2.4  Added wire-verified byte decoders for the most common request/push bodies, all
--        designed against real captured bytes (not metadata):
--        * Addressing family (POINT_LOG_VALUE 0x0220, POINT_LOG_ALARM 0x0221,
--          POINT_CMD_VALUE 0x0240, POINT_CMD_PRIORITY 0x0241, TREND_DATA_DISPLAY 0x0295,
--          UPL_ALL_* 0x0981/0x0982): optional scope tag (SYST/NONE/CC + command priority +
--          3F FF FF FF) then Name_search (name_space u16 + name TLV + suffix TLV + resume
--          cursor). POINT_CMD_VALUE also decodes the trailing f32 commanded value.
--        * COV subscribe (COV_ENABLE 0x0271 / COV_DISABLE 0x0273 / COV_DELETE_STUB 0x0272):
--          name_space + name TLV + suffix TLV + 2-byte trailer (00 FF enable / 00 00 disable).
--        * ALARM_PRINT 0x0508: scope tag, point name + descriptor TLVs, the value block
--          (3F FF FF Fx quality sentinel + point sub-type + f32), and the 8-byte event
--          timestamps. Timestamp helper decodes [yr-1900][mo][day][DOW 1=Mon][hr][min][sec][cs].
--        These run only on dir==0x00 (responses carry no opcode, so they are not per-opcode
--        dispatched). Anything past the known prefix falls through to the generic TLV walk,
--        so an unexpected layout degrades gracefully rather than mis-splitting.
--   2.3  COV_ANNUNCIATE (0x0274) per-point record corrected: each point is a
--        name_response = u16 name_space (00 00) + name TLV + suffix TLV, THEN the
--        f32 value + 10-byte condition block. The prior decoder consumed the first
--        point's name_space as part of the count and lacked per-point name_space
--        handling, so it stopped after the first point in a multi-point push and
--        mislabelled the empty suffix TLV (01 00 00) as a "value marker". Now decodes
--        every point in a multi-point COV and handles non-empty subpoint suffixes.
--        (EBLN_PING baseTime is a Unix-epoch wall-clock, not a tick counter; event
--        timestamps are 8 bytes incl. a day-of-week field — see PROTOCOL.md.)
--   2.2  message-class model corrected from fleet captures
--   2.2  Corrected from multi-panel + command captures:
--        * Message classes are legacy/modern PAIRS chosen by the panel's firmware
--          generation, NOT by direction: data 0x33(legacy)/0x34(modern); 2nd channel
--          0x2E(legacy)/0x2F(modern) carrying identity + DB-change/replication records
--          + alarm prints; peer carriers 0x29/0x2A (panel<->panel, mirror-only).
--          Fingerprint a panel via CABINET_DISPLAY 0x010C and pick the dialect from its
--          firmware generation rather than blind-probing.
--        * COV (0x0274) condition block: byte0 point_priority (0x23=OPER when commanded)
--          and byte1 control_status (0x00/02/03/04/06) now wire-confirmed.
--        * Sequence is per-(peer,channel) with gaps (not one global counter); responses
--          echo the request seq; reconnect resumes (no reset).
--        * UPL_ALL_* continuation is application-layer cursoring (cursor = last object
--          name), not a frame more-follows bit; single frames up to ~1570 B.
--        * Event timestamps are 8 bytes [yr-1900][mo][day][DOW 1=Mon][hr][min][sec][cs].
--        (Candidate future decoders, not yet shipped to avoid offset-fragility: a
--        seq-stateful CABINET_DISPLAY 0x010C banner decode on the response, and an
--        ALARM_PRINT 0x0508 record decode — both currently surface via the TLV walk.)
--   2.1  Per-opcode EXPECTED BODY SCHEMA for every defined function code, derived
--        from the AP2 ASDU type structures and shown as a "[schema: struct-derived,
--        not byte-verified]" note under the body. The actual bytes are still parsed
--        by the wire-verified bespoke decoders (COV / node roster / identity) and a
--        generic TLV/scope/value walk. The schema tells you what fields the body
--        SHOULD contain; byte-level splitting is upgraded per opcode as live captures
--        confirm it. (Field-by-field byte decode is NOT auto-generated, because the
--        struct->wire mapping is non-trivial — TLV framing, scope tags, and unproven
--        enum widths — so a generated split would be confidently wrong for most ops.)
--   2.0  Wire-verified rebuild: the full AP2_Function_Code name set; removed the
--        UDP/10001 233.89.188.1 "presence beacon" (misattribution); opcode read at
--        the variable post-slot offset and only on dir==0x00 (no phantom opcodes);
--        0x29-0x2F session-control band incl. 0x2A; COV/roster/identity decoders;
--        length-prefix reassembly + multi-PDU.
--   1.x  Original public version (behavioral opcode guesses; UDP beacon decoder).
--
-- Frame (big-endian): u32 total_len | u32 msg_type | u32 sequence | u8 direction |
--   four NUL-terminated ASCII routing slots [BLN, dst, BLN, src] |
--   (only when direction==0x00) u16 AP2 function code | body
-- Opcode is at a VARIABLE offset (after the 4 NULs) and present ONLY on dir==0x00.
-- There is NO multicast "presence beacon"; the real optional availability multicast
-- is 234.5.6.7:8 (off by default), not a discovery beacon.

-- Dissector version. Tracks the p2.lua decode surface only; the scanner
-- versions independently (p2_scanner.__version__). History is in the Changelog
-- comment block at the top of this file.
-- ==== P2_DATA BEGIN (generated by gen_embed.py; do not hand-edit) =========
-- Compiled in so this dissector is a single drop-in file with no companion
-- data to ship or lose.  Regenerate in place; edits inside this block are
-- overwritten.
--
--   p2data.opcodes      opcode -> {tag, note};  tag W wire, G grain, X export
--   p2data.point_types  type code -> {mnemonic, name, default_enum}
--   p2data.enum_types   enum id -> {name, apogee, levels}
--   p2data.revisions    revision string -> {level, cab, str}
--   p2data.families     opcode -> {family, param, value}; a run of opcodes
--                       that is one operation with a parameter in the opcode
local p2data = {}
p2data.opcodes = {
  [48] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [52] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [62] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [63] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [65] = {tag="G", note="panel export, body 4-9 B; panel firmware 30/42 images + supervisor sta"},
  [66] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [68] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [70] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [71] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [80] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [81] = {tag="G", note="panel export, body 12-12 B"},
  [88] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [89] = {tag="G", note="panel export, body 3-3 B; panel firmware 30/42 images + supervisor sta"},
  [91] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [92] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [256] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [266] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [268] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [288] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [289] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [291] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [292] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [293] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [294] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [295] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [296] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [297] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [298] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [304] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [305] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [320] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [515] = {tag="W", note="IMPLEMENTED"},
  [516] = {tag="W", note="IMPLEMENTED"},
  [544] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [545] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [546] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [547] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [549] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [550] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [551] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [552] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [553] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [576] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [577] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [578] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [579] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [580] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [581] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [582] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [583] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [584] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [585] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [586] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [587] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [588] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [589] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [608] = {tag="W", note="IMPLEMENTED"},
  [611] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [612] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [625] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [626] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [627] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [628] = {tag="W", note="IMPLEMENTED"},
  [629] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [656] = {tag="X", note="panel export, body 30-59 B; panel firmware 30/42 images + supervisor s"},
  [657] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [660] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [661] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [680] = {tag="W", note="IMPLEMENTED"},
  [736] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [737] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [738] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [770] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [771] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [787] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [788] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [791] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [818] = {tag="G", note="panel export, body 93-159 B"},
  [856] = {tag="G", note="replication grain"},
  [864] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [865] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [866] = {tag="G", note="panel export, body 107-107 B; panel firmware 30/42 images + supervisor"},
  [869] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [870] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [872] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1034] = {tag="W", note="IMPLEMENTED"},
  [1038] = {tag="G", note="replication grain"},
  [1280] = {tag="X", note="panel export, body 41-42 B; panel firmware 30/42 images + supervisor s"},
  [1281] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1288] = {tag="W", note="IMPLEMENTED"},
  [1289] = {tag="W", note="IMPLEMENTED"},
  [1293] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1296] = {tag="W", note="not implemented"},
  [1312] = {tag="W", note="not implemented; panel export, body 33-75 B; panel firmware 30/42 imag"},
  [1318] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1323] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1344] = {tag="W", note="reached handler, refused; panel firmware 30/42 images + supervisor sta"},
  [1345] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1346] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1347] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1348] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1349] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1350] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1351] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1352] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1353] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1354] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1355] = {tag="W", note="reached handler, refused"},
  [1356] = {tag="W", note="not implemented"},
  [1357] = {tag="W", note="IMPLEMENTED; panel export, body 19-19 B"},
  [1376] = {tag="W", note="not implemented"},
  [1377] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1378] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1379] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [1380] = {tag="W", note="not implemented"},
  [1381] = {tag="W", note="not implemented; panel export, body 6-6 B; panel firmware 30/42 images"},
  [1382] = {tag="W", note="not implemented"},
  [1383] = {tag="W", note="not implemented; panel firmware 30/42 images + supervisor stack"},
  [1384] = {tag="W", note="not implemented"},
  [1536] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1537] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1538] = {tag="G", note="panel export, body 27-27 B"},
  [1539] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1541] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1542] = {tag="W", note="IMPLEMENTED"},
  [1552] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1553] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1554] = {tag="G", note="panel export, body 162-162 B"},
  [1555] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [1557] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [2385] = {tag="W", note="IMPLEMENTED"},
  [2388] = {tag="W", note="IMPLEMENTED"},
  [2389] = {tag="W", note="IMPLEMENTED"},
  [2390] = {tag="W", note="IMPLEMENTED"},
  [2393] = {tag="W", note="IMPLEMENTED"},
  [2401] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [2402] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2403] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2404] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [2405] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [2406] = {tag="W", note="not implemented; panel firmware 28/42 images + supervisor stack"},
  [2409] = {tag="W", note="IMPLEMENTED"},
  [2411] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2417] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2418] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2419] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2420] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2421] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2422] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2425] = {tag="W", note="IMPLEMENTED"},
  [2427] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2433] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [2434] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2435] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2436] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2437] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2438] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [2439] = {tag="W", note="IMPLEMENTED"},
  [2440] = {tag="W", note="IMPLEMENTED"},
  [2441] = {tag="W", note="IMPLEMENTED"},
  [2443] = {tag="W", note="not implemented; panel firmware 28/42 images + supervisor stack"},
  [2444] = {tag="W", note="IMPLEMENTED"},
  [2445] = {tag="W", note="IMPLEMENTED"},
  [2446] = {tag="W", note="IMPLEMENTED"},
  [2447] = {tag="W", note="IMPLEMENTED"},
  [2461] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2462] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2463] = {tag="W", note="IMPLEMENTED; panel firmware 28/42 images + supervisor stack"},
  [2465] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2466] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2467] = {tag="W", note="not implemented; panel firmware 28/42 images + supervisor stack"},
  [2471] = {tag="W", note="not implemented"},
  [2473] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2474] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [2475] = {tag="W", note="not implemented; panel firmware 28/42 images + supervisor stack"},
  [2491] = {tag="W", note="reached handler, refused"},
  [2499] = {tag="W", note="reached handler, refused"},
  [3140] = {tag="W", note="inconclusive (never answered)"},
  [16399] = {tag="W", note="reached handler, refused"},
  [16400] = {tag="W", note="reached handler, refused"},
  [16401] = {tag="W", note="reached handler, refused"},
  [16640] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16643] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16644] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16645] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16646] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16647] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16648] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16649] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16654] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16655] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16656] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16657] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16682] = {tag="F", note="panel firmware 28/42 images + supervisor stack"},
  [16691] = {tag="W", note="reached handler, refused"},
  [16692] = {tag="X", note="panel export, body 27-46 B"},
  [16896] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16897] = {tag="X", note="panel export, body 52-121 B; panel firmware 30/42 images + supervisor "},
  [16900] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16912] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16913] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16928] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16929] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16930] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16931] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [16932] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16933] = {tag="W", note="IMPLEMENTED; panel firmware 30/42 images + supervisor stack"},
  [16946] = {tag="F", note="panel firmware 30/42 images + supervisor stack"},
  [17475] = {tag="W", note="inconclusive (never answered)"},
  [17664] = {tag="W", note="reached handler, refused"},
  [17960] = {tag="G", note="panel export, body 58-60 B"},
  [17965] = {tag="G", note="replication grain"},
  [17971] = {tag="W", note="IMPLEMENTED"},
  [17972] = {tag="W", note="IMPLEMENTED"},
  [17973] = {tag="W", note="IMPLEMENTED"},
  [17974] = {tag="W", note="IMPLEMENTED"},
  [17984] = {tag="W", note="IMPLEMENTED"},
  [17985] = {tag="W", note="IMPLEMENTED"},
  [17986] = {tag="W", note="reached handler, refused"},
  [17987] = {tag="W", note="reached handler, refused"},
  [17988] = {tag="W", note="IMPLEMENTED"},
  [17991] = {tag="W", note="inconclusive (never answered)"},
  [17994] = {tag="W", note="IMPLEMENTED"},
  [17995] = {tag="W", note="IMPLEMENTED"},
  [17996] = {tag="W", note="IMPLEMENTED"},
  [17997] = {tag="W", note="IMPLEMENTED"},
  [17998] = {tag="W", note="IMPLEMENTED"},
  [17999] = {tag="W", note="IMPLEMENTED"},
  [18000] = {tag="W", note="IMPLEMENTED"},
  [18469] = {tag="X", note="panel export, body 10-10 B"},
  [18474] = {tag="X", note="panel export, body 2-2 B"},
  [18488] = {tag="X", note="panel export, body 160-197 B"},
  [18528] = {tag="X", note="panel export, body 54-66 B"},
  [18535] = {tag="X", note="panel export, body 18-18 B"},
  [18538] = {tag="X", note="panel export, body 28-28 B"},
  [18541] = {tag="X", note="panel export, body 21-21 B"},
  [18544] = {tag="X", note="panel export, body 39-52 B"},
  [18549] = {tag="X", note="panel export, body 30-36 B"},
  [18560] = {tag="X", note="panel export, body 37-43 B"},
  [18563] = {tag="X", note="panel export, body 16-51 B"},
  [18787] = {tag="X", note="panel export, body 87-107 B"},
  [19201] = {tag="X", note="panel export, body 118-118 B"},
  [20480] = {tag="X", note="panel export, body 47-84 B"},
  [20483] = {tag="W", note="IMPLEMENTED"},
  [20504] = {tag="X", note="panel export, body 42-76 B"},
  [20512] = {tag="W", note="IMPLEMENTED; panel export, body 41-54 B"},
  [20514] = {tag="W", note="IMPLEMENTED"},
  [20520] = {tag="X", note="panel export, body 38-44 B"},
  [20536] = {tag="W", note="IMPLEMENTED"},
  [20538] = {tag="X", note="panel export, body 53-69 B"},
  [20539] = {tag="X", note="panel export, body 100-114 B"},
  [20540] = {tag="X", note="panel export, body 50-64 B"},
  [20541] = {tag="X", note="panel export, body 24-38 B"},
  [21332] = {tag="W", note="not implemented"},
  [21333] = {tag="X", note="panel export, body 34-34 B"},
  [61488] = {tag="X", note="panel export, body 62-68 B"},
  [61490] = {tag="X", note="panel export, body 105-111 B"},
  [61492] = {tag="X", note="panel export, body 55-61 B"},
  [61494] = {tag="X", note="panel export, body 29-35 B"},
}

p2data.families = {
  [288] = {family="set operator-port baud rate", param="port", value="MMI 1"},
  [289] = {family="set operator-port baud rate", param="port", value="MMI 2"},
  [291] = {family="set field-bus baud rate", param="bus", value="FLN 1"},
  [292] = {family="set field-bus baud rate", param="bus", value="FLN 2"},
  [293] = {family="set field-bus baud rate", param="bus", value="FLN 3"},
  [544] = {family="point log", param="filter", value="value"},
  [545] = {family="point log", param="filter", value="in alarm"},
  [546] = {family="point log", param="filter", value="control status"},
  [547] = {family="point log", param="filter", value="failed"},
  [548] = {family="point log", param="filter", value="totalized"},
  [549] = {family="point log", param="filter", value="by priority"},
  [550] = {family="point log", param="filter", value="disabled"},
  [551] = {family="point log", param="filter", value="by type"},
  [552] = {family="point log", param="filter", value="in trouble"},
  [553] = {family="point log", param="filter", value="any"},
  [554] = {family="point log", param="filter", value="ODSB"},
  [555] = {family="point log", param="filter", value="PDSB"},
  [556] = {family="point log", param="filter", value="alarm-commanded"},
  [578] = {family="point command (enable)", param="state", value="enable"},
  [579] = {family="point command (enable)", param="state", value="disable"},
  [580] = {family="point command (alarm state)", param="state", value="alarm"},
  [581] = {family="point command (alarm state)", param="state", value="normal"},
  [582] = {family="point command (alarm enable)", param="state", value="enable"},
  [583] = {family="point command (alarm enable)", param="state", value="disable"},
  [588] = {family="point command (alarm state)", param="state", value="into trouble"},
  [589] = {family="point command (alarm state)", param="state", value="out of trouble"},
  [625] = {family="COV", param="state", value="enable"},
  [627] = {family="COV", param="state", value="disable"},
  [658] = {family="trend", param="state", value="enable"},
  [659] = {family="trend", param="state", value="disable"},
  [736] = {family="point total", param="state", value="enable"},
  [737] = {family="point total", param="state", value="disable"},
  [864] = {family="ems dial", param="state", value="enable"},
  [865] = {family="ems dial", param="state", value="disable"},
  [1348] = {family="category printing", param="state", value="enable"},
  [1350] = {family="category printing", param="state", value="disable"},
  [1353] = {family="category node list", param="action", value="append"},
  [1354] = {family="category node list", param="action", value="remove"},
  [1377] = {family="alarm message", param="state", value="enable"},
  [1378] = {family="alarm message", param="state", value="disable"},
  [2401] = {family="upload point", param="phase", value="deleted"},
  [2402] = {family="upload alarm setup", param="phase", value="deleted"},
  [2403] = {family="upload alarm mode", param="phase", value="deleted"},
  [2404] = {family="upload trend", param="phase", value="deleted"},
  [2405] = {family="upload ppcl", param="phase", value="deleted"},
  [2406] = {family="upload tec", param="phase", value="deleted"},
  [2407] = {family="upload eqs zone", param="phase", value="deleted"},
  [2408] = {family="upload eqs cmd table", param="phase", value="deleted"},
  [2409] = {family="upload eqs mode sched", param="phase", value="deleted"},
  [2410] = {family="upload loop", param="phase", value="deleted"},
  [2411] = {family="upload alarm message", param="phase", value="deleted"},
  [2417] = {family="upload point", param="phase", value="added"},
  [2418] = {family="upload alarm setup", param="phase", value="added"},
  [2419] = {family="upload alarm mode", param="phase", value="added"},
  [2420] = {family="upload trend", param="phase", value="added"},
  [2421] = {family="upload ppcl", param="phase", value="added"},
  [2422] = {family="upload tec", param="phase", value="added"},
  [2423] = {family="upload eqs zone", param="phase", value="added"},
  [2424] = {family="upload eqs cmd table", param="phase", value="added"},
  [2425] = {family="upload eqs mode sched", param="phase", value="added"},
  [2426] = {family="upload loop", param="phase", value="added"},
  [2427] = {family="upload alarm message", param="phase", value="added"},
  [2428] = {family="upload ssto general", param="phase", value="added"},
  [2429] = {family="upload ssto start", param="phase", value="added"},
  [2430] = {family="upload ssto stop", param="phase", value="added"},
  [2431] = {family="upload ssto night", param="phase", value="added"},
  [2433] = {family="upload point", param="phase", value="all"},
  [2434] = {family="upload alarm setup", param="phase", value="all"},
  [2435] = {family="upload alarm mode", param="phase", value="all"},
  [2436] = {family="upload trend", param="phase", value="all"},
  [2437] = {family="upload ppcl", param="phase", value="all"},
  [2438] = {family="upload tec", param="phase", value="all"},
  [2439] = {family="upload eqs zone", param="phase", value="all"},
  [2440] = {family="upload eqs cmd table", param="phase", value="all"},
  [2441] = {family="upload eqs mode sched", param="phase", value="all"},
  [2443] = {family="upload alarm message", param="phase", value="all"},
  [2444] = {family="upload ssto general", param="phase", value="all"},
  [2445] = {family="upload ssto start", param="phase", value="all"},
  [2446] = {family="upload ssto stop", param="phase", value="all"},
  [2447] = {family="upload ssto night", param="phase", value="all"},
  [2461] = {family="upload port", param="phase", value="deleted"},
  [2462] = {family="upload port", param="phase", value="added"},
  [2463] = {family="upload port", param="phase", value="all"},
  [2465] = {family="upload partner", param="phase", value="deleted"},
  [2466] = {family="upload partner", param="phase", value="added"},
  [2467] = {family="upload partner", param="phase", value="all"},
  [2469] = {family="upload eqs override", param="phase", value="deleted"},
  [2470] = {family="upload eqs override", param="phase", value="added"},
  [2471] = {family="upload eqs override", param="phase", value="all"},
  [2473] = {family="upload uc", param="phase", value="deleted"},
  [2474] = {family="upload uc", param="phase", value="added"},
  [2475] = {family="upload uc", param="phase", value="all"},
  [2481] = {family="upload tod point", param="phase", value="deleted"},
  [2482] = {family="upload tod point", param="phase", value="added"},
  [2483] = {family="upload tod point", param="phase", value="all"},
  [2485] = {family="upload tod cmd", param="phase", value="deleted"},
  [2486] = {family="upload tod cmd", param="phase", value="added"},
  [2487] = {family="upload tod cmd", param="phase", value="all"},
  [2489] = {family="upload lon", param="phase", value="deleted"},
  [2490] = {family="upload lon", param="phase", value="added"},
  [2491] = {family="upload lon", param="phase", value="all"},
  [2497] = {family="upload mstp device", param="phase", value="deleted"},
  [2498] = {family="upload mstp device", param="phase", value="added"},
  [2499] = {family="upload mstp device", param="phase", value="all"},
  [14339] = {family="racs partner", param="state", value="disable"},
  [14341] = {family="racs partner", param="state", value="enable"},
  [14355] = {family="racs port", param="state", value="disable"},
  [14357] = {family="racs port", param="state", value="enable"},
  [14371] = {family="racs system", param="state", value="disable"},
  [14373] = {family="racs system", param="state", value="enable"},
  [16644] = {family="PPCL lines", param="state", value="enable"},
  [16645] = {family="PPCL lines", param="state", value="disable"},
  [16654] = {family="report PPCL", param="variant", value="lines"},
  [16682] = {family="report PPCL", param="variant", value="unresolved references"},
  [16689] = {family="upload program", param="phase", value="deleted"},
  [16690] = {family="upload program", param="phase", value="added"},
  [16691] = {family="upload program", param="phase", value="all"},
  [16912] = {family="TEC log", param="log", value="member"},
  [16913] = {family="TEC log", param="log", value="report"},
  [16944] = {family="FLN scan", param="state", value="enable"},
  [16945] = {family="FLN scan", param="state", value="disable"},
  [17168] = {family="LON log", param="log", value="member"},
  [17169] = {family="LON log", param="log", value="report"},
  [17666] = {family="tod point", param="state", value="enable"},
  [17667] = {family="tod point", param="state", value="disable"},
  [17988] = {family="EBLN telnet", param="state", value="enable"},
  [17989] = {family="EBLN telnet", param="state", value="disable"},
  [18466] = {family="upload bbmd", param="phase", value="deleted"},
  [18467] = {family="upload bbmd", param="phase", value="added"},
  [18468] = {family="upload bbmd", param="phase", value="all"},
  [18481] = {family="upload covtab", param="phase", value="deleted"},
  [18482] = {family="upload covtab", param="phase", value="added"},
  [18483] = {family="upload covtab", param="phase", value="all"},
  [18500] = {family="upload bac trend", param="phase", value="deleted"},
  [18501] = {family="upload bac trend", param="phase", value="added"},
  [18502] = {family="upload bac trend", param="phase", value="all"},
  [18552] = {family="upload BACnet object", param="phase", value="added"},
  [18553] = {family="upload BACnet object", param="phase", value="deleted"},
  [20484] = {family="eqs zone", param="state", value="enable"},
  [20485] = {family="eqs zone", param="state", value="disable"},
  [20516] = {family="eqs mode entry", param="state", value="enable"},
  [20517] = {family="eqs mode entry", param="state", value="disable"},
  [20547] = {family="eqs ssto", param="state", value="enable"},
  [20548] = {family="eqs ssto", param="state", value="disable"},
  [21248] = {family="I/O module display", param="scope", value="global"},
  [21253] = {family="I/O module display", param="scope", value="local"},
}

p2data.enum_types = {
  [-1] = {name="Default LDI", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-2] = {name="Default LDO", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-6] = {name="Default L2SL", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-7] = {name="Default LOOAP", apogee=true, levels={[0]="OFF", [1]="ON", [2]="AUTO"}},
  [-12] = {name="Default L2SP", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-13] = {name="Default LOOAL", apogee=true, levels={[0]="OFF", [1]="ON", [2]="AUTO"}},
  [-14] = {name="Default LFSSL", apogee=true, levels={[0]="STOP", [1]="SLOW", [2]="FAST"}},
  [-15] = {name="Default LFSSP", apogee=true, levels={[0]="STOP", [1]="SLOW", [2]="FAST"}},
  [-19] = {name="Default LCTLR", apogee=true, levels={[0]="DAY", [1]="NIGHT"}},
  [-21] = {name="Default LENUM", apogee=true, levels={[0]="NIGHT", [1]="DAY", [2]="SPECIAL2", [3]="SPECIAL3", [4]="SPECIAL4", [5]="SPECIAL5"}},
  [-107] = {name="BACNET OOA", apogee=true, levels={[1]="OFF", [2]="ON", [3]="AUTO"}},
  [-115] = {name="BACNET FSS", apogee=true, levels={[1]="STOP", [2]="SLOW", [3]="FAST"}},
  [-121] = {name="BACNET LENUM", apogee=true, levels={[1]="NIGHT", [2]="DAY", [3]="SPECIAL2", [4]="SPECIAL3", [5]="SPECIAL4", [6]="SPECIAL5"}},
  [-122] = {name="BACNET EVENT ENROLLMENT", apogee=true, levels={[0]="NRML", [1]="FAULT", [2]="OFFNRML", [3]="HIGH", [4]="LOW"}},
  [-1000] = {name="OFF_ON", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-1001] = {name="ON_OFF", apogee=true, levels={[0]="ON", [1]="OFF"}},
  [-1002] = {name="NO_YES", apogee=true, levels={[0]="NO", [1]="YES"}},
  [-1003] = {name="YES_NO", apogee=true, levels={[0]="YES", [1]="NO"}},
  [-1004] = {name="COOL_HEAT", apogee=true, levels={[0]="COOL", [1]="HEAT"}},
  [-1005] = {name="UNOCC_OCC", apogee=true, levels={[0]="UNOCC", [1]="OCC"}},
  [-1006] = {name="OCC_UNOCC", apogee=true, levels={[0]="OCC", [1]="UNOCC"}},
  [-1007] = {name="OPEN_CLOSED", apogee=true, levels={[0]="OPEN", [1]="CLOSED"}},
  [-1008] = {name="CLOSED_OPEN", apogee=true, levels={[0]="CLOSED", [1]="OPEN"}},
  [-1009] = {name="NOPEN_NCLOSE", apogee=true, levels={[0]="NOPEN", [1]="NCLOSE"}},
  [-1010] = {name="CAL_RECAL", apogee=true, levels={[0]="CAL", [1]="RECAL"}},
  [-1011] = {name="RECAL_CAL", apogee=true, levels={[0]="RECAL", [1]="CAL"}},
  [-1012] = {name="ETS_STE", apogee=true, levels={[0]="ETS", [1]="STE"}},
  [-1013] = {name="NTRAL_ACTIVE", apogee=true, levels={[0]="NTRAL", [1]="ACTIVE"}},
  [-1014] = {name="NEG_POS", apogee=true, levels={[0]="NEG", [1]="POS"}},
  [-1015] = {name="STPT_FLOW", apogee=true, levels={[0]="STPT", [1]="FLOW"}},
  [-1016] = {name="NORMAL_ALARM", apogee=true, levels={[0]="NORMAL", [1]="ALARM"}},
  [-1017] = {name="HW_ELEC", apogee=true, levels={[0]="HW", [1]="ELEC"}},
  [-1018] = {name="DAY_NIGHT", apogee=true, levels={[0]="DAY", [1]="NIGHT"}},
  [-1019] = {name="NIGHT_DAY", apogee=true, levels={[0]="NIGHT", [1]="DAY"}},
  [-1020] = {name="CLG_HTG", apogee=true, levels={[0]="CLG", [1]="HTG"}},
  [-1021] = {name="COLD_HOT", apogee=true, levels={[0]="COLD", [1]="HOT"}},
  [-1022] = {name="DISABL_ENABL", apogee=true, levels={[0]="DISABL", [1]="ENABLE"}},
  [-1023] = {name="FLOAT_SPRING", apogee=true, levels={[0]="FLOAT", [1]="SPRING"}},
  [-1024] = {name="VALVE_FBP", apogee=true, levels={[0]="VALVE", [1]="FBP"}},
  [-1025] = {name="NOAUX_AUX", apogee=true, levels={[0]="NOAUX", [1]="AUX"}},
  [-1026] = {name="NOELEC_ELEC", apogee=true, levels={[0]="NOELEC", [1]="ELEC"}},
  [-1027] = {name="FOUR_TWO", apogee=true, levels={[0]="FOUR", [1]="TWO"}},
  [-1028] = {name="ENG_SI", apogee=true, levels={[0]="ENG", [1]="SI"}},
  [-1029] = {name="DONE_READY", apogee=true, levels={[0]="DONE", [1]="READY"}},
  [-1030] = {name="READY_YES", apogee=true, levels={[0]="READY", [1]="YES"}},
  [-1031] = {name="SERIES_PAR", apogee=true, levels={[0]="SERIES", [1]="PAR"}},
  [-1032] = {name="ACTIVE_NTRAL", apogee=true, levels={[0]="ACTIVE", [1]="NTRAL"}},
  [-1033] = {name="ALARM_NORMAL", apogee=true, levels={[0]="ALARM", [1]="NORMAL"}},
  [-1034] = {name="NCLOSE_NOPEN", apogee=true, levels={[0]="NCLOSE", [1]="NOPEN"}},
  [-1035] = {name="SI_ENG", apogee=true, levels={[0]="SI", [1]="ENG"}},
  [-1036] = {name="HOLD_FILL", apogee=true, levels={[0]="HOLD", [1]="FILL"}},
  [-1037] = {name="BLEED_HOLD", apogee=true, levels={[0]="BLEED", [1]="HOLD"}},
  [-1038] = {name="MIN_MAX", apogee=true, levels={[0]="MIN", [1]="MAX"}},
  [-1039] = {name="ONE_TWO", apogee=true, levels={[0]="ONE", [1]="TWO"}},
  [-1040] = {name="AO_DO", apogee=true, levels={[0]="AO", [1]="DO"}},
  [-1041] = {name="CLOSED_ON", apogee=true, levels={[0]="CLOSED", [1]="ON"}},
  [-1042] = {name="OFF_CLOSED", apogee=true, levels={[0]="OFF", [1]="CLOSED"}},
  [-1043] = {name="READY_DONE", apogee=true, levels={[0]="READY", [1]="DONE"}},
  [-1044] = {name="LO_HI", apogee=true, levels={[0]="LO", [1]="HI"}},
  [-1045] = {name="OPEN_CLOSE", apogee=true, levels={[0]="OPEN", [1]="CLOSE"}},
  [-1046] = {name="CAV_VAV", apogee=true, levels={[0]="CAV", [1]="VAV"}},
  [-1047] = {name="PAR_SERIES", apogee=true, levels={[0]="PAR", [1]="SERIES"}},
  [-1048] = {name="AUTO_LEAD", apogee=true, levels={[0]="AUTO", [1]="LEAD"}},
  [-1049] = {name="AUTO_MANUAL", apogee=true, levels={[0]="AUTO", [1]="MANUAL"}},
  [-1050] = {name="AUTO_OFF", apogee=true, levels={[0]="AUTO", [1]="OFF"}},
  [-1051] = {name="AUTO_ON", apogee=true, levels={[0]="AUTO", [1]="ON"}},
  [-1052] = {name="AVERGE_NEARST", apogee=true, levels={[0]="AVERGE", [1]="NEARST"}},
  [-1053] = {name="BRINE_COMFRT", apogee=true, levels={[0]="BRINE", [1]="COMFRT"}},
  [-1054] = {name="CLEAN_DIRTY", apogee=true, levels={[0]="CLEAN", [1]="DIRTY"}},
  [-1055] = {name="CLEAR_LATCH", apogee=true, levels={[0]="CLEAR", [1]="LATCH"}},
  [-1056] = {name="CLEAR_RESET", apogee=true, levels={[0]="CLEAR", [1]="RESET"}},
  [-1057] = {name="CLRBIT_EXTFLT", apogee=true, levels={[0]="CLRBIT", [1]="EXTFLT"}},
  [-1058] = {name="CLRBIT_RESET", apogee=true, levels={[0]="CLRBIT", [1]="RESET"}},
  [-1059] = {name="CNSTNT_VARBLE", apogee=true, levels={[0]="CNSTNT", [1]="VARBLE"}},
  [-1060] = {name="COOLNG_HEATNG", apogee=true, levels={[0]="COOLNG", [1]="HEATNG"}},
  [-1061] = {name="CURENT_DELTPP", apogee=true, levels={[0]="CURENT", [1]="DELTPP"}},
  [-1062] = {name="DIRECT_REVRSE", apogee=true, levels={[0]="DIRECT", [1]="REVRSE"}},
  [-1063] = {name="DISPRS_AMBENT", apogee=true, levels={[0]="DISPRS", [1]="AMBENT"}},
  [-1064] = {name="ECON_VENT", apogee=true, levels={[0]="ECON", [1]="VENT"}},
  [-1065] = {name="ENABLE_DISABL", apogee=true, levels={[0]="ENABLE", [1]="DISABL"}},
  [-1066] = {name="ENGLSH_SI", apogee=true, levels={[0]="ENGLSH", [1]="SI"}},
  [-1067] = {name="EXTRNL_CHLR", apogee=true, levels={[0]="EXTRNL", [1]="CHLR"}},
  [-1068] = {name="FALSE_TRUE", apogee=true, levels={[0]="False", [1]="True"}},
  [-1069] = {name="FAULT_OK", apogee=true, levels={[0]="FAULT", [1]="OK"}},
  [-1070] = {name="FIXED_AUTO", apogee=true, levels={[0]="FIXED", [1]="AUTO"}},
  [-1071] = {name="FIXED_VARBLE", apogee=true, levels={[0]="FIXED", [1]="VARBLE"}},
  [-1072] = {name="FORWRD_REVRSE", apogee=true, levels={[0]="FORWRD", [1]="REVRSE"}},
  [-1073] = {name="FULL_LIMTED", apogee=true, levels={[0]="FULL", [1]="LIMTED"}},
  [-1074] = {name="FWD_REV", apogee=true, levels={[0]="FWD", [1]="REV"}},
  [-1075] = {name="GAUGE_PSI", apogee=true, levels={[0]="GAUGE", [1]="PSI"}},
  [-1076] = {name="GERMAN_ENGLSH", apogee=true, levels={[0]="GERMAN", [1]="ENGLSH"}},
  [-1077] = {name="HAND_AUTO", apogee=true, levels={[0]="HAND", [1]="AUTO"}},
  [-1078] = {name="HIGH_NORMAL", apogee=true, levels={[0]="HIGH", [1]="NORMAL"}},
  [-1079] = {name="HOT_COLD", apogee=true, levels={[0]="HOT", [1]="COLD"}},
  [-1080] = {name="INACTV_ACTIVE", apogee=true, levels={[0]="INACTV", [1]="ACTIVE"}},
  [-1081] = {name="LEAD_AUTO", apogee=true, levels={[0]="LEAD", [1]="AUTO"}},
  [-1082] = {name="LOCAL_NET", apogee=true, levels={[0]="LOCAL", [1]="NET"}},
  [-1083] = {name="LOCAL_REMOTE", apogee=true, levels={[0]="LOCAL", [1]="REMOTE"}},
  [-1084] = {name="LOW_HIGH", apogee=true, levels={[0]="LOW", [1]="HIGH"}},
  [-1085] = {name="LOW_NORMAL", apogee=true, levels={[0]="LOW", [1]="NORMAL"}},
  [-1086] = {name="LOW_STNDRD", apogee=true, levels={[0]="LOW", [1]="STNDRD"}},
  [-1087] = {name="LT_51S_TO255", apogee=true, levels={[0]="LT_51S", [1]="TO255"}},
  [-1088] = {name="LVWTR_RETWTR", apogee=true, levels={[0]="LVWTR", [1]="RETWTR"}},
  [-1089] = {name="MANUAL_AUTO", apogee=true, levels={[0]="MANUAL", [1]="AUTO"}},
  [-1090] = {name="MASTER_SLAVE", apogee=true, levels={[0]="MASTER", [1]="SLAVE"}},
  [-1091] = {name="NO_AUTH", apogee=true, levels={[0]="NO", [1]="AUTH"}},
  [-1092] = {name="NO_ERR_DATA_E", apogee=true, levels={[0]="NO_ERR", [1]="DATA_E"}},
  [-1093] = {name="NO_FLT_FAULT", apogee=true, levels={[0]="NO_FLT", [1]="FAULT"}},
  [-1094] = {name="NO_LIMIT", apogee=true, levels={[0]="NO", [1]="LIMIT"}},
  [-1095] = {name="NO_READY", apogee=true, levels={[0]="NO", [1]="READY"}},
  [-1096] = {name="NO_RESET", apogee=true, levels={[0]="NO", [1]="RESET"}},
  [-1097] = {name="NOFLOW_FLOW", apogee=true, levels={[0]="NOFLOW", [1]="FLOW"}},
  [-1098] = {name="NONLNR_LINEAR", apogee=true, levels={[0]="NONLNR", [1]="LINEAR"}},
  [-1099] = {name="NORMAL_CLEAR", apogee=true, levels={[0]="NORMAL", [1]="CLEAR"}},
  [-1100] = {name="NORMAL_FAIL", apogee=true, levels={[0]="NORMAL", [1]="FAIL"}},
  [-1101] = {name="NORMAL_LIGHT", apogee=true, levels={[0]="NORMAL", [1]="LIGHT"}},
  [-1102] = {name="NORMAL_RESET", apogee=true, levels={[0]="NORMAL", [1]="RESET"}},
  [-1103] = {name="NORMAL_STNDBY", apogee=true, levels={[0]="NORMAL", [1]="STNDBY"}},
  [-1104] = {name="NORMAL_UNFAIL", apogee=true, levels={[0]="NORMAL", [1]="UNFAIL"}},
  [-1105] = {name="NOTRDY_READY", apogee=true, levels={[0]="NOTRDY", [1]="READY"}},
  [-1106] = {name="NTO_ON", apogee=true, levels={[0]="NTO", [1]="ON"}},
  [-1107] = {name="OATEMP_ENTLPY", apogee=true, levels={[0]="OATEMP", [1]="ENTLPY"}},
  [-1108] = {name="OFF_AUTO", apogee=true, levels={[0]="OFF", [1]="AUTO"}},
  [-1109] = {name="OFF_BRAKE", apogee=true, levels={[0]="OFF", [1]="BRAKE"}},
  [-1110] = {name="OFF_BYPASS", apogee=true, levels={[0]="OFF", [1]="BYPASS"}},
  [-1111] = {name="OFF_HEAT", apogee=true, levels={[0]="OFF", [1]="HEAT"}},
  [-1112] = {name="OFF_MNWMUP", apogee=true, levels={[0]="OFF", [1]="MNWMUP"}},
  [-1113] = {name="OK_BAD", apogee=true, levels={[0]="OK", [1]="BAD"}},
  [-1114] = {name="OK_FAULT", apogee=true, levels={[0]="OK", [1]="FAULT"}},
  [-1115] = {name="OK_RESET", apogee=true, levels={[0]="OK", [1]="RESET"}},
  [-1116] = {name="OK_TRIP", apogee=true, levels={[0]="OK", [1]="TRIP"}},
  [-1117] = {name="OK_WARNNG", apogee=true, levels={[0]="OK", [1]="WARNNG"}},
  [-1118] = {name="OPEN_LOCK", apogee=true, levels={[0]="OPEN", [1]="LOCK"}},
  [-1119] = {name="PURGE_RUN", apogee=true, levels={[0]="PURGE", [1]="RUN"}},
  [-1120] = {name="RATEMP_OATEMP", apogee=true, levels={[0]="RATEMP", [1]="OATEMP"}},
  [-1121] = {name="REMOTE_LOCAL", apogee=true, levels={[0]="REMOTE", [1]="LOCAL"}},
  [-1122] = {name="RETURN_SPACE", apogee=true, levels={[0]="RETURN", [1]="SPACE"}},
  [-1123] = {name="REV_FWD", apogee=true, levels={[0]="REV", [1]="FWD"}},
  [-1124] = {name="REVRSE_FORWRD", apogee=true, levels={[0]="REVRSE", [1]="FORWRD"}},
  [-1125] = {name="SHARED_STNDRD", apogee=true, levels={[0]="SHARED", [1]="STNDRD"}},
  [-1126] = {name="SI_ENGLSH", apogee=true, levels={[0]="SI", [1]="ENGLSH"}},
  [-1127] = {name="SLAVE_MASTER", apogee=true, levels={[0]="SLAVE", [1]="MASTER"}},
  [-1128] = {name="SLC_LOCAL", apogee=true, levels={[0]="SLC", [1]="LOCAL"}},
  [-1129] = {name="SOFTWR_TSTAT", apogee=true, levels={[0]="SOFTWR", [1]="TSTAT"}},
  [-1130] = {name="STEAM_GAS", apogee=true, levels={[0]="STEAM", [1]="GAS"}},
  [-1131] = {name="STNDBY_ACT", apogee=true, levels={[0]="STNDBY", [1]="ACT"}},
  [-1132] = {name="STNDRD_LOWTMP", apogee=true, levels={[0]="STNDRD", [1]="LOWTMP"}},
  [-1133] = {name="STOP_ENABLE", apogee=true, levels={[0]="STOP", [1]="ENABLE"}},
  [-1134] = {name="STOP_RUN", apogee=true, levels={[0]="STOP", [1]="RUN"}},
  [-1135] = {name="STOP_START", apogee=true, levels={[0]="STOP", [1]="START"}},
  [-1136] = {name="SURGE_OK", apogee=true, levels={[0]="SURGE", [1]="OK"}},
  [-1137] = {name="TIME_NETWRK", apogee=true, levels={[0]="TIME", [1]="NETWRK"}},
  [-1138] = {name="UNLOCK_LOCK", apogee=true, levels={[0]="UNLOCK", [1]="LOCK"}},
  [-1139] = {name="UNUSED_USE", apogee=true, levels={[0]="UNUSED", [1]="USE"}},
  [-1140] = {name="VH_VECT", apogee=true, levels={[0]="VH", [1]="VECT"}},
  [-1141] = {name="MC_UV_HCMODE", apogee=true, levels={[0]="TEMPOK", [1]="COOLING", [2]="HEATING"}},
  [-1142] = {name="MC_UV_SYSMODE", apogee=true, levels={[0]="UNOCC", [1]="OCC", [2]="OVRD"}},
  [-1143] = {name="MC_RTU_SYSMODE", apogee=true, levels={[0]="RATEMP", [1]="SATEMP", [2]="NETWORK", [3]="OATEMP", [4]="NONE_MAT"}},
  [-1144] = {name="MC_RCH_CHWRSTOPT", apogee=true, levels={[0]="NO_RESET", [1]="RETURN", [2]="mA_4_20", [3]="NETWORK", [4]="ICE", [5]="OATEMP"}},
  [-1145] = {name="MC_SCU_SFANSTATS", apogee=true, levels={[0]="OFF", [1]="LO_SPEED", [2]="HI_SPEED"}},
  [-1146] = {name="MC_SCU_HUMCTRLTP", apogee=true, levels={[0]="NONE", [1]="HUMIDITY", [2]="DEWPOINT"}},
  [-1147] = {name="MC_SCH_OATMETHOD", apogee=true, levels={[1]="LOCAL", [2]="NETWORK"}},
  [-1148] = {name="MC_RMC_TPPRCALC", apogee=true, levels={[0]="MINIMUM", [1]="MAXIMUM", [2]="AVERAGE"}},
  [-1149] = {name="MC_SCA_CLGRESTYP", apogee=true, levels={[0]="NONE", [1]="SATEMP", [2]="RATEMP", [3]="OATEMP", [4]="mA_4_20", [5]="AIR_MAT"}},
  [-1150] = {name="MC_SCA_HTGRESTYP", apogee=true, levels={[0]="NONE", [1]="SATEMP", [2]="RATEMP", [3]="OATEMP", [4]="mA_4_20"}},
  [-1151] = {name="MC_TIMESCHEDULE", apogee=true, levels={[1]="SUNDAY", [2]="MONDAY", [3]="TUESDAY", [4]="WEDNSDAY", [5]="THURSDAY", [6]="FRIDAY", [7]="SATURDAY"}},
  [-1152] = {name="MC_HP_AUTMANMODE", apogee=true, levels={[0]="MANUNOCC", [1]="MANOCC", [5]="MANFAN", [9]="MANOFF", [255]="AUTO"}},
  [-1153] = {name="MC_HP_FAULTS", apogee=true, levels={[187]="LOWDAT1", [188]="LOWRPRS1", [189]="HIRPRS1", [204]="RATSENSR", [205]="LOWDAT2", [206]="LOWRPRS2", [207]="HIRPRS2", [255]="NONE"}},
  [-1154] = {name="MC_CHLR_OPMODE", apogee=true, levels={[0]="STOP", [1]="NETWORK", [2]="IDLE", [3]="RUN"}},
  [-1155] = {name="MC_CHLR_LDLGST", apogee=true, levels={[0]="BOTHOFF", [1]="LEADON", [2]="LAGON", [3]="BOTHON"}},
  [-1156] = {name="MC_CHLR_LDLGSP", apogee=true, levels={[0]="MSTLEAD", [1]="SLVLEAD", [2]="AUTO"}},
  [-1157] = {name="MC_CHLR_LDLGSSP", apogee=true, levels={[1]="SUNDAY", [2]="MONDAY", [3]="TUESDAY", [4]="WEDNSDAY", [5]="THURSDAY", [6]="FRIDAY", [7]="SATURDAY"}},
  [-1158] = {name="CR_RUNSTATUS1", apogee=true, levels={[0]="TIMEOUT", [1]="RECYCLE", [2]="STARTUP", [3]="RAMPING", [4]="RUNNING", [5]="DEMAND", [6]="OVERRIDE", [7]="SHUTDOWN", [8]="ABNORMAL", [9]="PUMPDOWN", [10]="READY", [11]="TRIPOUT", [12]="CONTROL TEST", [13]="LOCKOUT"}},
  [-1159] = {name="CR_RUNSTATUS2", apogee=true, levels={[0]="OFF", [1]="ON", [2]="STOPPING", [3]="DELAY"}},
  [-1160] = {name="CR_RUNSTATUS3", apogee=true, levels={[0]="OFF", [1]="ON", [3]="TEST"}},
  [-1161] = {name="CR_RUNSTATUS4", apogee=true, levels={[1]="RECYCLE", [2]="STARTUP", [3]="RAMPING", [4]="RUNNING", [5]="WARMUP", [6]="OVERRIDE", [7]="DESOLID", [8]="ABNORMAL", [9]="DILUTION", [10]="READY", [11]="TRIPOUT", [12]="CONTROL TEST"}},
  [-1162] = {name="CR_RUNSTATUS5", apogee=true, levels={[0]="SERVICE", [1]="OFF-LOCAL", [2]="OFF-CCN", [3]="OFF-TIME", [4]="EMERGENCY", [5]="ON-LOCAL", [6]="ON-CCN", [7]="ON-TIME"}},
  [-1163] = {name="CR_CONTROLMODE1", apogee=true, levels={[0]="OFF", [2]="LOCAL", [3]="CCN", [15]="RESET"}},
  [-1164] = {name="CR_CONTROLMODE2", apogee=true, levels={[0]="STOP", [2]="LOCAL", [3]="CCN"}},
  [-1165] = {name="CR_CONTROLMODE3", apogee=true, levels={[1]="LOCAL_ON", [2]="EMERGENCY STOP", [3]="CCN_ON", [4]="CLOCK_ON", [5]="DELAY_OFF", [6]="LOCAL_OFF", [7]="CCN_OFF", [8]="CLOCK_OFF"}},
  [-1166] = {name="CR_CONTROLMODE4", apogee=true, levels={[1]="OFF-LOCAL", [2]="OFF-CCN", [3]="TEST", [4]="EMERGENCY STOP", [5]="ON-LOCAL", [6]="ON-CCN", [7]="ON-CLOCK", [8]="OFF-CLOCK"}},
  [-1167] = {name="CR_CURRENTMODE1", apogee=true, levels={[0]="Unit is in Stop Mode", [1]="Unit is Off by CCN Command", [2]="Unit is Off by Time Clock", [3]="Unit in Local Mode", [4]="Unit is On by CCN Command", [5]="Unit is On by Time Clock", [6]="Dual Set Point Configured", [7]="Temperature Reset in Effect", [8]="Demand Limit in Effect", [9]="FSM Controlling Chiller", [10]="Low Source Protection", [11]="Ramp Load Limited", [12]="n Hour Timed Override", [13]="Low Cooler Suction Temperature Warning", [14]="WSM Controlling Chiller", [15]="Slow change Override in Effect", [16]="n Minute Off to On Delay in Effect", [17]="Low Suction Superheat Protection"}},
  [-1168] = {name="CR_CONTROLTYPE1", apogee=true, levels={[1]="REMOTE", [2]="LOCAL", [3]="CCN"}},
  [-1169] = {name="CR_CHILLERSTAT1", apogee=true, levels={[0]="No chiller configured for this number", [1]="Low load recycling", [2]="Off, available for starting", [3]="Restarting after power Fail", [4]="Running normally", [5]="Failed to stop in 5 minutes", [6]="Failed to start, but not faulted", [7]="Safety shutdown", [8]="Unavailable", [9]="CSM cannot communicate with the chiller"}},
  [-1170] = {name="CR_OVRDSTATUS1", apogee=true, levels={[0]="No override of time schedule", [1]="Remote contact forces schedule to be occupied", [2]="Temperature override forces schedule to occupied", [3]="Temperature override forces schedule to unoccupied"}},
  [-1171] = {name="CR_DMDLMTSTAT1", apogee=true, levels={[0]="RAMPING COMPLETE", [1]="CLAMPED", [2]="RAMPING", [3]="REDLINE ACTIVE", [4]="LOADSHED LIMIT EXCEEDED"}},
  [-1172] = {name="CR_LOADSHEDSTAT1", apogee=true, levels={[0]="NORMAL", [1]="REDLINE", [2]="SHED"}},
  [-1173] = {name="CR_ALARMSTATE1", apogee=true, levels={[0]="NORMAL", [1]="PARTIAL", [7]="SHUTDOWN"}},
  [-1174] = {name="CR_CURRENTALARM1", apogee=true, levels={[1]="Circ A, Comp 1 Fail", [2]="Circ A, Comp 2 Fail", [3]="Circ A, Comp 3 Fail", [4]="Circ A, Comp 4 Fail", [5]="Circ B, Comp 1 Fail", [6]="Circ B, Comp 2 Fail", [7]="Circ B, Comp 3 Fail", [8]="Circ B, Comp 4 Fail", [9]="Cooler Leaving Fluid Thermistor Fail", [10]="Cooler Entering Fluid Thermistor Fail", [11]="Condenser Leaving Fluid Thermistor Fail", [12]="Condenser Entering Fluid Thermistor Fail", [13]="Heat Reclaim Entering Fluid Thermistor Fail", [14]="Heat Reclaim Leaving Fluid Thermistor Fail", [15]="Circ A Saturated Cond Temp Thermistor Fail", [16]="Circ B Saturated Cond Temp Thermistor Fail", [17]="Circ A Saturated Suction Temp Thermistor Fail", [18]="Circ B Saturated Suction Temp Thermistor Fail", [19]="Circ A Comp Suction Temp Thermistor Fail", [20]="Circ B Comp Suction Thermistor Fail", [21]="External Reset Temp Thermistor Fail", [22]="Circ A Discharge Pressure Transducer Fail", [23]="Circ B Discharge Pressure Transducer Fail", [24]="Circ A Suction Pressure Transducer Fail", [25]="Circ B Suction Pressure Transducer Fail", [26]="Circ A Oil Pressure Transducer Fail", [27]="Circ B Oil Pressure Transducer Fail", [28]="Transducer Supply Voltage Outside Range", [29]="Local/Stop/CCN Switch Fail", [30]="4 - 20 ma Reset Input Out of Range", [31]="4 - 20 ma Demand Limit Input Out of Range", [32]="Comm Losss with DSIO-1", [33]="Comm Losss with DSIO-2", [34]="Comm Losss with Options Board 1", [35]="Comm Losss with Options Board 2", [36]="Circ A Low Refrigerant Pressure", [37]="Circ B Low Refrigerant Pressure", [38]="Circ A Fail to Pumpdown", [39]="Circ B Fail to Pumpdown", [40]="Circ A Low Oil Pressure", [41]="Circ B Low Oil Pressure", [42]="Cooler Freeze Protection", [43]="Low Cooler Fluid Flow", [44]="Circ A Low Cooler Suction Temp", [45]="Circ B Low Cooler Suction Temp", [46]="Circ A High Suction Superheat", [47]="Circ B High Suction Superheat", [48]="Circ A Low Suction Superheat", [49]="Circ B Low Suction Superheat", [50]="Illegal Configuration", [51]="Initial Configuration Required", [52]="Unit is in Emergency Stop", [53]="Cooler Pump Contacts Fail to Close at Startup", [54]="Cooler Pump Contacts Open in Normal Operation", [55]="Cooler Pump Contacts Close While Relay OFF", [56]="Comm Loss with Water System Manager", [57]="Circ A Disch Press Transducer Requires Cal", [58]="Circ B Disch Press Transducer Requires Cal", [59]="Circ A Suction Press Transducer Requires Cal", [60]="Circ B Suction Press Transducer Requires Cal", [61]="Circ A Oil Pressure Transducer Requires Cal", [62]="Circ B Oil Pressure Transducer Requires Cal", [63]="Circ A and Circ B both off, Unit down", [64]="Circ A Loss of Charge", [65]="Circ B Loss of Charge", [66]="Comm Loss with Flotronic System Manager", [67]="Bad Date Code- No Press Transducer Cal", [68]="Comm Loss with Remote Alarm DSIO #1", [69]="Comm Loss with Remote Alarm DSIO #2", [70]="High Leaving Chilled Water Temp"}},
  [-1175] = {name="CR_CURRENTALARM2", apogee=true, levels={[1]="Circ A1 Compressor Fail", [2]="Circ A1 Compressor Fail", [5]="Circ B1 Compressor Fail", [6]="Circ B2 Compressor Fail", [7]="Circ A Discharge Gas Thermistor Fail", [8]="Circ B Discharge Gas Thermistor Fail", [9]="Cooler Leaving Fluid Thermistor Fail", [10]="Cooler Entering Fluid Thermistor Fail", [11]="Condenser Leaving Fluid Thermistor Fail", [12]="Condenser Entering Fluid Thermistor Fail", [13]="Heat Reclaim Entering Fluid Thermistor Fail", [14]="Heat Reclaim Leaving Fluid Thermistor Fail", [15]="Circ A1 Compressor High Motor Temp", [16]="Circ A2 Compressor High Motor Temp", [17]="Circ B1 Compressor High Motor Temp", [18]="Circ B2 Compressor High Motor Temp", [19]="Circ A Low Oil Temp at Startup", [20]="Circ B Low Oil Temp at Startup", [21]="ExtErnAl Reset Temp Thermistor Fail", [22]="Circ A Discharge Pressure Transducer Fail", [23]="Circ B Discharge Pressure Transducer Fail", [24]="Circ A Suction Pressure Transducer Fail", [25]="Circ B Suction Pressure Transducer Fail", [26]="Circ A1 Comp Oil Pressure Transducer Fail", [27]="Circ A2 Comp Oil Pressure Transducer Fail", [28]="Circ B1 Comp Oil Pressure Transducer Fail", [29]="Circ B2 Comp Oil Pressure Transducer Fail", [30]="Circ A Economizer Transducer Fail", [31]="Circ B Economizer Transducer Fail", [32]="Transducer Supply Outside 4.5 to 5.5 Volts", [34]="4 - 20 ma Reset Input Out of Range", [35]="4 - 20 ma Demand Limit Input Out of Range", [36]="Comm Losss", [37]="Circ A Low Saturated Suction Temp", [38]="Circ B Low Saturated Suction Temp", [40]="Circ A1 Compressor Low Oil Pressure", [41]="Circ A2 Compressor Low Oil Pressure", [42]="Circ B1 Compressor Low Oil Pressure", [43]="Circ B2 Compressor Low Oil Pressure", [44]="Circ A Condenser Freeze Protection", [45]="Circ B Condenser Freeze Protection", [46]="Cooler Freeze Protection", [47]="Circ A High Saturated Suction Temp", [48]="Circ B High Saturated Suction Temp", [49]="Loss of Condenser Flow", [50]="Illegal Configuration", [51]="Initial Configuration Required", [52]="Unit is in Emergency Stop", [53]="Cooler Pump Interlock Failed at Startup", [54]="Cooler Pump Interlock Open Unexpectedly", [55]="Cooler Pump Interlock Close when Pump OFF", [56]="Comm Loss with WSM", [57]="Circ A Liquid Level Sensor Fail", [58]="Circ B Liquid Level Sensor Fail", [59]="Circ A1 Compressor Prestart Oil Pressure", [60]="Circ A2 Compressor Prestart Oil Pressure", [61]="Circ B1 Compressor Prestart Oil Pressure", [62]="Circ B2 Compressor Prestart Oil Pressure", [63]="Circ A and B OFF for Alerts-Unit down", [64]="Circ A Loss of Charge", [65]="Circ B Loss of Charge", [66]="Comm Loss with FSM", [67]="Circ A High Discharge Pressure", [68]="Circ B High Discharge Pressure", [70]="High Leaving Chilled Water Temp", [71]="Circ A Low Oil Level/Flow", [72]="Circ B Low Oil Level/Flow", [73]="Circ A Low Discharge Superheat", [74]="Circ B Low Discharge Superheat", [75]="Circ A1 Comp Max Oil Delta P (check oil line)", [76]="Circ A2 Comp Max Oil Delta P (check oil line)", [77]="Circ B1 Comp Max Oil Delta P (check oil line)", [78]="Circ B2 Comp Max Oil Delta P (check oil line)", [79]="Circ A1 Oil Solenoid Fail", [80]="Circ A2 Oil Solenoid Fail", [81]="Circ B1 Oil Solenoid Fail", [82]="Circ B2 Oil Solenoid Fail"}},
  [-1176] = {name="CR_ERRORCODES", apogee=true, levels={[1]="INVALID COMMAND", [2]="INVALID or NON-EXISTENT TABLE", [3]="COMMUNICATION ERROR", [6]="DEVICE NOT CONFIGURED", [7]="VARIABLE DOES NOT EXIST", [8]="INVALID DATA", [9]="ACCESS RESTRICTED", [10]="LIMITS EXCEEDED", [11]="ALARMS NOT AVAILABLE", [12]="CANNOT FORCE VARIABLE", [13]="PARAMETER NOT FOUND", [14]="COMMUNICATION NACK"}},
  [-1177] = {name="FIRE_EST_STATUS", apogee=true, levels={[0]="Normal", [1]="Maintenance Alert", [2]="Monitor", [3]="Active Under Test", [4]="Trouble", [5]="Supervisory", [6]="Alarm", [10]="Sup. Open, Message Disabled"}},
  [-1178] = {name="FIRE_MXL_STATUS", apogee=true, levels={[0]="Normal", [1]="Trouble", [2]="Supervisory", [4]="Security", [8]="Alarm"}},
  [-1179] = {name="FIRE_SIMPLEX4100", apogee=true, levels={[0]="Normal", [1]="Utility / Monitor", [4]="Supervisory", [5]="Priority 2 Alarm", [6]="Alarm"}},
  [-1180] = {name="SECURITY_STATUS", apogee=true, levels={[0]="Normal", [1]="Secure, message displayed", [4]="Open Circuit", [5]="Short Circuit", [20]="Alarm"}},
  [-1181] = {name="WINTER_SUMMER", apogee=true, levels={[0]="WINTER", [1]="SUMMER"}},
  [-1182] = {name="HIGH_LOW", apogee=true, levels={[0]="HIGH", [1]="LOW"}},
  [-1183] = {name="TREND_EVENT", apogee=true, levels={[0]="OFF", [1]="ON", [2]="ALARM"}},
  [-1184] = {name="MC_LON_HP_ALL", apogee=true, levels={[0]="Unocc", [1]="Occ", [2]="OVRD", [6]="Disable", [9]="Fan Only", [12]="CantHeat", [16]="CantCool", [190]="CondOvrd", [191]="BrownOut", [204]="RSnsFail", [205]="Low Temp", [206]="Low Pres", [207]="Hi Pres", [255]="Normal"}},
  [-1185] = {name="MA_RTU_OPSTAT", apogee=true, levels={[0]="Off", [1]="Shutdown", [2]="Startup", [3]="MWU", [7]="Econ", [8]="Heating", [9]="Cooling"}},
  [-1186] = {name="MA_RTU_ALARM", apogee=true, levels={[0]="None", [1]="Lo SAT", [2]="SAT Fail", [3]="RAT Fail", [4]="EAT Fail", [6]="CWT Fail", [7]="ZAT Fail", [8]="ZAT Fail", [9]="SF1 Fail", [10]="SF2 Fail", [13]="RF1 Fail", [14]="RF2 Fail", [17]="SF1VCone", [18]="SF2VCone", [21]="RF1VCone", [22]="RF2VCone", [25]="Hi SAT", [26]="DrtyFltr", [28]="Comp1Flt", [29]="Comp2Flt", [30]="Comp3Flt", [31]="Comp4Flt", [34]="HTG1Flt", [36]="HiStatic"}},
  [-1187] = {name="MA_RTU_WARNING", apogee=true, levels={[0]="None", [1]="SAT Fail", [2]="RAT Fail", [3]="EAT Fail", [5]="CWT Fail", [6]="ZAT Fail", [8]="SF1 Fail", [9]="SF2 Fail", [12]="RF1 Fail", [13]="RF2 Fail", [16]="SF1VCone", [17]="SF2VCone", [20]="RF1VCone", [21]="RF2VCone", [24]="SysSWOpn", [25]="NoAirFlo", [26]="Lo SAT", [27]="Hi SAT", [28]="CLG Lock", [30]="HTG Lock", [31]="VFDBypas", [32]="BMSStart", [33]="HiStatic"}},
  [-1188] = {name="MA_RTU_OPMODE", apogee=true, levels={[0]="Off", [1]="TimeClok", [2]="RemStart", [3]="Occ", [4]="Unocc", [5]="Cal"}},
  [-1189] = {name="MA_RTU_CTL_RESET", apogee=true, levels={[0]="None", [1]="Sfan", [2]="SFnoEcon", [3]="BMS Al", [4]="OAT", [5]="RAT_MAT", [6]="Zone Air"}},
  [-1190] = {name="YO_BAC_YT_WARN", apogee=true, levels={[1]="None", [2]="ClokFail", [3]="Deflt SP", [4]="TransErr", [5]="LoEvapP", [6]="HiCondP", [11]="PurgHiP", [12]="PurgeSW", [13]="ExessPrg", [15]="HiMtrCur", [16]="VanUnCal", [17]="VanUnCal", [18]="HR Inhib", [19]="HRNoData", [20]="HRFrqOOR", [27]="IO Com"}},
  [-1191] = {name="YO_BAC_YT_OPCODE", apogee=true, levels={[1]="StrtRdy", [2]="LocalSD", [3]="RemoteSD", [4]="Warning", [5]="CycleSD", [6]="SafetySD", [7]="Inhibit", [8]="Start", [9]="Run", [10]="RunWarm", [11]="Unload", [12]="Coastdwn"}},
  [-1192] = {name="YO_BAC_YT_SAFETY", apogee=true, levels={[1]="No Abnormal Condition", [2]="Evap - Low Pressure", [3]="Evap - Leaving Liquid Probe", [4]="Evap - Temp Transducer", [5]="Cond - Hi Pres Contacts Open", [6]="Cond - High Pressure", [7]="Cond - Pres Trans Out Of Range", [8]="Aux Safety - Contacts Closed", [9]="Discharge - Low Temp", [10]="Discharge - High Temp", [11]="Oil - High Temp", [12]="Oil - Low Differential Pressure", [13]="Oil - Hi Differential Pressure", [22]="Control Panel - Power Failure", [24]="Mtr Starter - Current Imbal", [30]="VSD - High Heatsink Temp", [31]="VSD - Motor Current Overlook", [32]="VSD - High Phase A Heatsink Temp", [33]="VSD - High Phase B Heatsink Temp", [34]="VSD - High Phase C Heatsink Temp", [35]="VSD - Hi Converter Heatsink Temp", [36]="VSD - Precharge Lockout", [37]="HarmFltr - High Heatsink Temp", [38]="HarmFltr - Hi Demand Distort", [39]="LCSSSS - Phase Loss", [40]="LCSSSS - Current Imbalance", [41]="LCSSSS - Motor Current Overload", [42]="LCSSSS - High Current", [43]="LCSSSS - Open SCR", [44]="LCSSSS - Shorted Phase A SCR", [45]="LCSSSS - Shorted Phase B SCR", [46]="LCSSSS - Shorted Phase C SCR", [47]="LCSSSS - High Phase A Temp", [48]="LCSSSS - High Phase B Temp", [49]="LCSSSS - High Phase C Temp", [50]="Starter - Invalid Mtr Selection", [52]="Evaporator - Low Pressure", [53]="Evaporator - Smart Freeze"}},
  [-1193] = {name="YO_BAC_YT_CYCLE", apogee=true, levels={[1]="No Abnormal Condition", [2]="MultiUnit Cycling - Contact Open", [3]="System Cycling - Contacts Open", [5]="Oil - Low Temp", [6]="Control Panel - Power Failure", [7]="Low Leaving Chilled Water Temp", [8]="No Chilled Water Flow", [9]="Condenser - Flow Switch", [10]="Motor Cntlr - Contacts Open", [11]="Motor Cntlr - Loss Of Current", [12]="Power Fault", [13]="Control Panel - Schedule", [14]="Starter - Lo Supply Voltage", [15]="Starter - Hi Supply Voltage", [18]="VSD Initialization Failure", [19]="VSD Shutdown", [20]="VSD - High Phase A Current", [21]="VSD - High Phase B Current", [22]="VSD - High Phase C Current", [23]="VSD - Phase A Gate Driver", [24]="VSD - Phase B Gate Driver", [25]="VSD - Phase C Gate Driver", [26]="VSD - Single Phase Input Power", [27]="VSD - High DC Bus Voltage", [28]="VSD - Logic Board Power Supply", [29]="VSD - Low DC Bus Voltage", [30]="VSD - DC Bus Voltage Imbalance", [31]="VSD - High Internal Ambient Temp", [32]="VSD - Invalid Current Scale", [33]="VSD - Low Phase A Heatsink Temp", [34]="VSD - Low Phase B Heatsink Temp", [35]="VSD - Low Phase C Heatsink Temp", [36]="VSD - Lo Converter Heatsink Temp", [37]="VSD - Prechrg - DCBus Volt Imbal", [38]="VSD - Precharge - Lo DC Bus Volt", [39]="VSD - Logic Board Processor", [40]="VSD - Run Signal", [41]="VSD - Serial Communications", [42]="VSD - Stop Contacts Open", [43]="HarmFltr - Communications", [44]="HarmFltr - High DC Bus Voltage", [45]="HarmFltr - High Phase A Current", [46]="HarmFltr - High Phase B Current", [47]="HarmFltr - High Phase C Current", [48]="HarmFltr - Phase Locked Loop", [49]="HarmFltr - Low DC Bus Voltage", [50]="HarmFltr - Low DC Bus Voltage", [51]="HarmFltr - DC Bus Voltage Imbal", [52]="HarmFltr - Input Current Ovrload", [53]="HarmFltr - Logic Board Power Sup", [54]="HarmFltr - Run Signal", [55]="HarmFltr - DC Current Trnsfmr 1", [56]="HarmFltr - DC Current Trnsfmr 2", [57]="LCSSS Initialization Failure", [58]="LCSSS Shutdown", [59]="LCSSS - Low PhaseA Heatsink Temp", [60]="LCSSS - Low PhaseB Heatsink Temp", [61]="LCSSS - Low PhaseC Heatsink Temp", [62]="LCSSS - Phase Locked Loop", [63]="LCSSS - Power Fault", [64]="LCSSS - High Supply Line Voltage", [65]="LCSSS - Low Supply Line Voltage", [66]="LCSSS - Invalid Model Selection", [67]="LCSSS - Run Signal", [68]="LCSSS - Serial Communications", [69]="LCSSS - Stop Contacts Open", [71]="LCSSS - Logic Board Processor", [73]="LCSSS - Power Fail", [74]="VSD - Serial Communications", [75]="LCSSS - Serial Communications", [76]="LCSSS - Phase Loss"}},
  [-2000] = {name="DISABLED_ENABLED", apogee=true, levels={[0]="DISABLED", [1]="ENABLED"}},
  [-2001] = {name="NOTOK_OK", apogee=true, levels={[0]="NOTOK", [1]="OK"}},
  [-2002] = {name="RESTORED", apogee=true, levels={[0]="NOT_REST", [1]="RESTORED"}},
  [-2003] = {name="EQS_OFF_ON", apogee=true, levels={[0]="OFF", [1]="ON"}},
  [-2004] = {name="INACTIVE_ACTIVE", apogee=true, levels={[0]="INACTIVE", [1]="ACTIVE"}},
  [-2005] = {name="ZONE_MODE", apogee=true, levels={[0]="VAC", [1]="OCC1", [2]="OCC2", [3]="OCC3", [4]="OCC4", [5]="OCC5", [6]="WARMUP", [7]="COOLDOWN", [8]="NGHT_HTG", [9]="NGHT_CLG", [10]="STOP_HTG", [11]="STOP_CLG"}},
  [-2006] = {name="SSTO_OPERATION", apogee=true, levels={[0]="NONE", [1]="HEATING", [2]="COOLING", [3]="BOTH"}},
  [-2007] = {name="OPERATION_PHASE", apogee=true, levels={[0]="OFF", [1]="HTDURVAC", [2]="CLDURVAC", [3]="STRT_HTG", [4]="STRT_CLG", [5]="REGULATG", [6]="STOP_HTG", [7]="STOP_CLG", [8]="POST_HTG", [9]="POST_CLG"}},
  [-2008] = {name="START_MODE", apogee=true, levels={[0]="STRT_HTG", [1]="STRT_CLG", [2]="NO_STRT"}},
  [-2009] = {name="STOP_MODE", apogee=true, levels={[0]="STOP_HTG", [1]="STOP_CLG", [2]="STOP_HOC", [3]="NO_STOP"}},
  [-2010] = {name="GAS_STEAM", apogee=true, levels={[0]="GAS", [1]="STEAM"}},
  [-2011] = {name="START_STOP", apogee=true, levels={[0]="START", [1]="STOP"}},
  [-2012] = {name="FAIL_NORMAL", apogee=true, levels={[0]="FAIL", [1]="NORMAL"}},
  [-2013] = {name="FLOW_NOFLOW", apogee=true, levels={[0]="FLOW", [1]="NOFLOW"}},
  [-2014] = {name="POS_NEG", apogee=true, levels={[0]="POS", [1]="NEG"}},
  [-2015] = {name="TRUE_FALSE", apogee=true, levels={[0]="TRUE", [1]="FALSE"}},
  [-2016] = {name="ACTIVE_INACTV", apogee=true, levels={[0]="ACTIVE", [1]="INACTV"}},
  [-2017] = {name="DIRTY_CLEAN", apogee=true, levels={[0]="DIRTY", [1]="CLEAN"}},
  [-2018] = {name="HTG_CLG", apogee=true, levels={[0]="HTG", [1]="CLG"}},
  [-2019] = {name="HEATING_COOLNG", apogee=true, levels={[0]="HEATING", [1]="COOLNG"}},
  [-2020] = {name="VARBLE_CNSTNT", apogee=true, levels={[0]="VARBLE", [1]="CNSTNT"}},
  [-2100] = {name="SMOKE_DETECTOR", apogee=true, levels={[0]="INACTIVE", [1]="ACTIVE", [2]="PREALM", [3]="ALMVER", [4]="MAINT", [5]="DIRTY"}},
  [-2101] = {name="PULL_STATION", apogee=true, levels={[0]="OFF", [1]="ON", [2]="STAGEONE"}},
  [-2102] = {name="SYSTEM_STATUS", apogee=true, levels={[0]="OK", [1]="REMOTE", [2]="DBFAULT", [3]="BLNFAULT", [4]="ALMFAULT", [5]="SHUTDOWN"}},
  [-2103] = {name="PRINTER_STATUS", apogee=true, levels={[0]="OK", [1]="PAPEROUT", [2]="FAULT"}},
  [-2104] = {name="CMDLST_STATUS", apogee=true, levels={[0]="IDLE", [1]="ACTIVATE", [2]="DEACTIV"}},
  [-2105] = {name="XLS LDO", apogee=true, levels={[0]="N/A", [1]="ON", [2]="OFF"}},
  [-2106] = {name="Clear_Alarm", apogee=true, levels={[0]="Clear", [1]="Alarm"}},
  [-2107] = {name="Normal_Fault", apogee=true, levels={[0]="Normal", [1]="Fault"}},
  [-2108] = {name="Fault_Normal", apogee=true, levels={[0]="Fault", [1]="Normal"}},
  [-2109] = {name="FIRE_XLS_STATUS", apogee=true, levels={[0]="Normal", [1]="Status", [2]="Test", [3]="Trouble", [4]="Supvisry", [5]="Security", [6]="Alarm"}},
  [-3000] = {name="days_of_week_t", apogee=true, levels={[0]="SUN", [1]="MON", [2]="TUE", [3]="WED", [4]="THU", [5]="FRI", [6]="SAT", [255]="NUL"}},
  [-3500] = {name="days_of_week_b", apogee=true, levels={[1]="SUN", [2]="MON", [3]="TUE", [4]="WED", [5]="THU", [6]="FRI", [7]="SAT"}},
  [-3001] = {name="discrete_levels_t", apogee=true, levels={[0]="OFF", [1]="LOW", [2]="MED", [3]="HIGH", [4]="ON", [255]="NUL"}},
  [-3501] = {name="discrete_levels_b", apogee=true, levels={[1]="OFF", [2]="LOW", [3]="MED", [4]="HIGH", [5]="ON"}},
  [-3002] = {name="telcom_states_t", apogee=false, levels={[0]="TEL_NOTINUSE", [1]="TEL_OFFHOOK", [2]="TEL_DIALING", [3]="TEL_DIALCOMP", [4]="TEL_RINGBACK", [5]="TEL_INCOMING", [6]="TEL_RINGING", [7]="TEL_ANSWERED", [8]="TEL_CONNECTED", [9]="TEL_TALKING", [10]="TEL_HANGINGUP", [11]="TEL_HUNGUPX", [12]="TEL_HOLD", [13]="TEL_UNHOLD", [14]="TEL_RELEASE", [15]="TEL_FULLDUP", [16]="TEL_BLOCKED", [17]="TEL_CWAIT", [18]="TEL_DESTBUSY", [19]="TEL_NETBUSY", [20]="TEL_ERROR", [255]="TEL_NUL"}},
  [-3003] = {name="config_source_t", apogee=false, levels={[0]="LOCAL", [1]="EXTERNAL", [255]="NUL"}},
  [-3004] = {name="file_request_t", apogee=false, levels={[0]="FR_OPEN_TO_SEND", [1]="FR_OPEN_TO_RECEIVE", [2]="FR_CLOSE_FILE", [3]="FR_CLOSE_DELETE_FILE", [4]="FR_DIRECTORY_LOOKUP", [5]="FR_OPEN_TO_SEND_RA", [6]="FR_OPEN_TO_RECEIVE_RA", [255]="FR_NUL"}},
  [-3005] = {name="file_status_t", apogee=false, levels={[0]="FS_XFER_OK", [1]="FS_LOOKUP_OK", [2]="FS_OPEN_FAIL", [3]="FS_LOOKUP_ERR", [4]="FS_XFER_UNDERWAY", [5]="FS_IO_ERR", [6]="FS_TIMEOUT_ERR", [7]="FS_WINDOW_ERR", [8]="FS_AUTH_ERR", [9]="FS_ACCESS_UNAVAIL", [10]="FS_SEEK_INVALID", [11]="FS_SEEK_WAIT", [255]="FS_NUL"}},
  [-3006] = {name="alarm_type_t", apogee=false, levels={[0]="AL_NO_CONDITION", [1]="AL_ALM_CONDITION", [2]="AL_TOT_SVC_ALM_1", [3]="AL_TOT_SVC_ALM_2", [4]="AL_TOT_SVC_ALM_3", [5]="AL_LOW_LMT_CLR_1", [6]="AL_LOW_LMT_CLR_2", [7]="AL_HIGH_LMT_CLR_1", [8]="AL_HIGH_LMT_CLR_2", [9]="AL_LOW_LMT_ALM_1", [10]="AL_LOW_LMT_ALM_2", [11]="AL_HIGH_LMT_ALM_1", [12]="AL_HIGH_LMT_ALM_2", [13]="AL_FIR_ALM", [14]="AL_FIR_PRE_ALM", [15]="AL_FIR_TRBL", [16]="AL_FIR_SUPV", [17]="AL_FIR_TEST_ALM", [18]="AL_FIR_TEST_PRE_ALM", [19]="AL_FIR_ENVCOMP_MAX", [20]="AL_FIR_MONITOR_COND", [21]="AL_FIR_MAINT_ALERT", [255]="AL_NUL"}},
  [-3007] = {name="priority_level_t", apogee=true, levels={[0]="LEVEL_0", [1]="LEVEL_1", [2]="LEVEL_2", [3]="LEVEL_3", [4]="PR_1", [5]="PR_2", [6]="PR_3", [7]="PR_4", [8]="PR_6", [9]="PR_8", [10]="PR_10", [11]="PR_16", [255]="NUL"}},
  [-3507] = {name="priority_level_b", apogee=true, levels={[1]="LEVEL_0", [2]="LEVEL_1", [3]="LEVEL_2", [4]="LEVEL_3", [5]="PR_1", [6]="PR_2", [7]="PR_3", [8]="PR_4", [9]="PR_6", [10]="PR_8", [11]="PR_10", [12]="PR_16"}},
  [-3008] = {name="currency_t", apogee=false, levels={[0]="CU_ARGENTINA_PESO", [1]="CU_AUSTRALIA_DOLLAR", [2]="CU_AUSTRIA_SCHILLING", [3]="CU_BAHRAIN_DINAR", [4]="CU_BELGIUM_FRANC", [5]="CU_BRAZIL_CRUZEIRO_REAL", [6]="CU_BRITAIN_POUND", [7]="CU_CANADA_DOLLAR", [8]="CU_CZECH_KORUNA", [9]="CU_CHILE_PESO", [10]="CU_CHINA_RENMINBI", [11]="CU_COLOMBIA_PESO", [12]="CU_DENMARK_KRONE", [13]="CU_ECUADOR_SUCRE", [14]="CU_EUROPEAN_CURRENCY_UNIT", [15]="CU_FINLAND_MARKKA", [16]="CU_FRANCE_FRANC", [17]="CU_GERMANY_MARK", [18]="CU_GREECE_DRACHMA", [19]="CU_HONG_KONG_DOLLAR", [20]="CU_HUNGARY_FORINT", [21]="CU_INDIA_RUPEE", [22]="CU_INDONESIA_RUPIAH", [23]="CU_IRELAND_PUNT", [24]="CU_ISRAEL_SHEKEL", [25]="CU_ITALY_LIRA", [26]="CU_JAPAN_YEN", [27]="CU_JORDAN_DINAR", [28]="CU_KUWAIT_DINAR", [29]="CU_LEBANON_POUND", [30]="CU_MALAYSIA_RINGGIT", [31]="CU_MALTA_LIRA", [32]="CU_MEXICO_PESO", [33]="CU_NETHERLANDS_GUILDER", [34]="CU_NEW_ZEALAND_DOLLAR", [35]="CU_NORWAY_KRONE", [36]="CU_PAKISTAN_RUPEE", [37]="CU_PERU_NEW_SOL", [38]="CU_PHILIPPINES_PESO", [39]="CU_POLAND_ZLOTY", [40]="CU_PORTUGAL_ESCUDO", [41]="CU_SAUDI_ARABIA_RIYAL", [42]="CU_SINGAPORE_DOLLAR", [43]="CU_SLOVAK_KORUNA", [44]="CU_SOUTH_AFRICA_RAND", [45]="CU_SOUTH_KOREA_WON", [46]="CU_SPAIN_PESETA", [47]="CU_SPECIAL_DRAWING_RIGHTS", [48]="CU_SWEDEN_KRONA", [49]="CU_SWITZERLAND_FRANC", [50]="CU_TAIWAN_DOLLAR", [51]="CU_THAILAND_BAHT", [52]="CU_TURKEY_LIRA", [53]="CU_UNITED_ARAB_DIRHAM", [54]="CU_UNITED_STATES_DOLLAR", [55]="CU_URUGUAY_NEW_PESO", [56]="CU_VENEZUELA_BOLIVAR", [255]="CU_NUL"}},
  [-3009] = {name="object_request_t", apogee=true, levels={[0]="NORMAL", [1]="DISABLED", [2]="UPDATE_S", [3]="SELFTEST", [4]="UPDATE_A", [5]="RPTMASK", [6]="OVERRIDE", [7]="ENABLE", [8]="REMVOVRD", [9]="CLRSTAT", [10]="CLRALARM", [11]="ALNVYENA", [12]="ALNVYDIS", [13]="MANUAL", [14]="REMOTE", [15]="PROGRAM", [16]="CLRESET", [255]="NUL"}},
  [-3509] = {name="object_request_b", apogee=true, levels={[1]="NORMAL", [2]="DISABLED", [3]="UPDATE_S", [4]="SELFTEST", [5]="UPDATE_A", [6]="RPTMASK", [7]="OVERRIDE", [8]="ENABLE", [9]="REMVOVRD", [10]="CLRSTAT", [11]="CLRALARM", [12]="ALNVYENA", [13]="ALNVYDIS", [14]="MANUAL", [15]="REMOTE", [16]="PROGRAM", [17]="CLRESET"}},
  [-3010] = {name="learn_mode_t", apogee=false, levels={[0]="LN_RECALL", [1]="LN_LEARN_CURRENT", [2]="LN_LEARN_VALUE", [3]="LN_REPORT_VALUE", [255]="LN_NUL"}},
  [-3011] = {name="override_t", apogee=true, levels={[0]="RETAIN", [1]="SPECIFY", [2]="DEFAULT", [255]="NUL"}},
  [-3511] = {name="override_b", apogee=true, levels={[1]="RETAIN", [2]="SPECIFY", [3]="DEFAULT"}},
  [-3012] = {name="emerg_t", apogee=true, levels={[0]="NORMAL", [1]="PRESS", [2]="DEPRESS", [3]="PURGE", [4]="SHUTDOWN", [5]="FIRE", [255]="NUL"}},
  [-3512] = {name="emerg_b", apogee=true, levels={[1]="NORMAL", [2]="PRESS", [3]="DEPRESS", [4]="PURGE", [5]="SHUTDOWN", [6]="FIRE"}},
  [-3013] = {name="hvac_t", apogee=true, levels={[0]="AUTO", [1]="HEAT", [2]="WARMUP", [3]="COOL", [4]="NGT_PURG", [5]="PRE_COOL", [6]="OFF", [7]="TEST", [8]="EMERHEAT", [9]="FAN_ONLY", [10]="FREECOOL", [11]="ICE", [12]="MAX_HEAT", [13]="ECONOMY", [14]="DEHUMID", [255]="NUL"}},
  [-3513] = {name="hvac_b", apogee=true, levels={[1]="AUTO", [2]="HEAT", [3]="WARMUP", [4]="COOL", [5]="NGT_PURG", [6]="PRE_COOL", [7]="OFF", [8]="TEST", [9]="EMERHEAT", [10]="FAN_ONLY", [11]="FREECOOL", [12]="ICE", [13]="MAX_HEAT", [14]="ECONOMY", [15]="DEHUMID"}},
  [-3014] = {name="occup_t", apogee=true, levels={[0]="OCC", [1]="UNOCC", [2]="BYPASS", [3]="STANDBY", [255]="NUL"}},
  [-3514] = {name="occup_b", apogee=true, levels={[1]="OCC", [2]="UNOCC", [3]="BYPASS", [4]="STANDBY"}},
  [-3015] = {name="hvac_overid_t", apogee=true, levels={[0]="OFF", [1]="POSITION", [2]="FLOW_VAL", [3]="FLOW_PCT", [4]="OPEN", [5]="CLOSE", [6]="MINIMUM", [7]="MAXIMUM", [8]="UNUSED8", [9]="UNUSED9", [10]="UNUSED10", [11]="UNUSED11", [12]="UNUSED12", [13]="UNUSED13", [14]="UNUSED14", [15]="UNUSED15", [16]="UNUSED16", [17]="POS_1", [18]="FLOWVAL1", [19]="FLOWPCT1", [20]="OPEN1", [21]="CLOSE1", [22]="MINIMUM1", [23]="MAXIMUM1", [24]="UNUSED24", [25]="UNUSED25", [26]="UNUSED26", [27]="UNUSED27", [28]="UNUSED28", [29]="UNUSED29", [30]="UNUSED30", [31]="UNUSED31", [32]="UNUSED32", [33]="POS_2", [34]="FLOWVAL2", [35]="FLOWPCT2", [36]="OPEN2", [37]="CLOSE2", [38]="MINIMUM2", [39]="MAXIMUM2", [40]="UNUSED40", [41]="UNUSED41", [42]="UNUSED42", [43]="UNUSED43", [44]="UNUSED44", [45]="UNUSED45", [46]="UNUSED46", [47]="UNUSED47", [48]="UNUSED48", [255]="NUL"}},
  [-3515] = {name="hvac_overid_b", apogee=true, levels={[1]="OFF", [2]="POSITION", [3]="FLOW_VAL", [4]="FLOW_PCT", [5]="OPEN", [6]="CLOSE", [7]="MINIMUM", [8]="MAXIMUM", [9]="UNUSED8", [10]="UNUSED9", [11]="UNUSED10", [12]="UNUSED11", [13]="UNUSED12", [14]="UNUSED13", [15]="UNUSED14", [16]="UNUSED15", [17]="UNUSED16", [18]="POS_1", [19]="FLOWVAL1", [20]="FLOWPCT1", [21]="OPEN1", [22]="CLOSE1", [23]="MINIMUM1", [24]="MAXIMUM1", [25]="UNUSED24", [26]="UNUSED25", [27]="UNUSED26", [28]="UNUSED27", [29]="UNUSED28", [30]="UNUSED29", [31]="UNUSED30", [32]="UNUSED31", [33]="UNUSED32", [34]="POS_2", [35]="FLOWVAL2", [36]="FLOWPCT2", [37]="OPEN2", [38]="CLOSE2", [39]="MINIMUM2", [40]="MAXIMUM2", [41]="UNUSED40", [42]="UNUSED41", [43]="UNUSED42", [44]="UNUSED43", [45]="UNUSED44", [46]="UNUSED45", [47]="UNUSED46", [48]="UNUSED47", [49]="UNUSED48"}},
  [-3016] = {name="scene_t", apogee=true, levels={[0]="RECALL", [1]="LEARN", [2]="DISPLAY", [3]="GRP_OFF", [4]="GP_ON", [5]="STAT_OFF", [6]="STAT_ON", [7]="STAT_MIX", [8]="GRP_STAT", [9]="FLICK", [10]="TIMEOUT", [11]="TMO_FLK", [12]="DELAYOFF", [13]="DLA_FLK", [14]="DELAYON", [15]="ENA_GRP", [16]="DIS_GRP", [17]="CLEANON", [18]="CLEANOFF", [19]="WINK", [20]="RESET", [21]="MODE1", [22]="MODE2", [23]="MODE3", [255]="NUL"}},
  [-3516] = {name="scene_b", apogee=true, levels={[1]="RECALL", [2]="LEARN", [3]="DISPLAY", [4]="GRP_OFF", [5]="GP_ON", [6]="STAT_OFF", [7]="STAT_ON", [8]="STAT_MIX", [9]="GRP_STAT", [10]="FLICK", [11]="TIMEOUT", [12]="TMO_FLK", [13]="DELAYOFF", [14]="DLA_FLK", [15]="DELAYON", [16]="ENA_GRP", [17]="DIS_GRP", [18]="CLEANON", [19]="CLEANOFF", [20]="WINK", [21]="RESET", [22]="MODE1", [23]="MODE2", [24]="MODE3"}},
  [-3017] = {name="scene_config_t", apogee=false, levels={[0]="SCF_SAVE", [1]="SCF_CLEAR", [2]="SCF_REPORT", [3]="SCF_SIZE", [4]="SCF_FREE", [255]="SCF_NUL"}},
  [-3018] = {name="setting_t", apogee=true, levels={[0]="OFF", [1]="ON", [2]="DOWN", [3]="UP", [4]="STOP", [5]="STATE", [255]="NUL"}},
  [-3518] = {name="setting_b", apogee=true, levels={[1]="OFF", [2]="ON", [3]="DOWN", [4]="UP", [5]="STOP", [6]="STATE"}},
  [-3019] = {name="evap_t", apogee=true, levels={[0]="NO_CLG", [1]="COOLING", [2]="EMER_CLG", [255]="NUL"}},
  [-3519] = {name="evap_b", apogee=true, levels={[1]="NO_CLG", [2]="COOLING", [3]="EMER_CLG"}},
  [-3020] = {name="therm_mode_t", apogee=true, levels={[0]="NO_CTL", [1]="IN_OUT", [2]="MODULATE", [255]="NUL"}},
  [-3520] = {name="therm_mode_b", apogee=true, levels={[1]="NO_CTL", [2]="IN_OUT", [3]="MODULATE"}},
  [-3021] = {name="defrost_mode_t", apogee=true, levels={[0]="AMBIENT", [1]="FORCED", [2]="SYNC", [255]="NUL"}},
  [-3521] = {name="defrost_mode_b", apogee=true, levels={[1]="AMBIENT", [2]="FORCED", [3]="SYNC"}},
  [-3022] = {name="defrost_term_t", apogee=true, levels={[0]="TEMP", [1]="TIME", [2]="FIRST", [3]="LAST", [255]="NUL"}},
  [-3522] = {name="defrost_term_b", apogee=true, levels={[1]="TEMP", [2]="TIME", [3]="FIRST", [4]="LAST"}},
  [-3023] = {name="defrost_state_t", apogee=true, levels={[0]="STANDBY", [1]="PUMPDOWN", [2]="DEFROST", [3]="DRAINDWN", [4]="INJ_DLY", [255]="NUL"}},
  [-3523] = {name="defrost_state_b", apogee=true, levels={[1]="STANDBY", [2]="PUMPDOWN", [3]="DEFROST", [4]="DRAINDWN", [5]="INJ_DLY"}},
  [-3024] = {name="chiller_t", apogee=true, levels={[0]="OFF", [1]="START", [2]="RUN", [3]="PRESHUTD", [4]="SERVICE", [255]="NUL"}},
  [-3524] = {name="chiller_b", apogee=true, levels={[1]="OFF", [2]="START", [3]="RUN", [4]="PRESHUTD", [5]="SERVICE"}},
  [-3025] = {name="fire_test_t", apogee=true, levels={[0]="NORMAL", [1]="RESET", [2]="TEST", [3]="NOTEST", [255]="NUL"}},
  [-3525] = {name="fire_test_b", apogee=true, levels={[1]="NORMAL", [2]="RESET", [3]="TEST", [4]="NOTEST"}},
  [-3026] = {name="fire_initiator_t", apogee=false, levels={[0]="FI_UNDEFINED", [1]="FI_THERMAL_FIXED", [2]="FI_SMOKE_ION", [3]="FI_MULTI_ION_THERMAL", [4]="FI_SMOKE_PHOTO", [5]="FI_MULTI_PHOTO_THERMAL", [6]="FI_MULTI_PHOTO_ION", [7]="FI_MULTI_PHOTO_ION_THERMAL", [8]="FI_THERMAL_ROR", [9]="FI_MULTI_THERMAL_ROR", [10]="FI_MANUAL_PULL", [11]="FI_WATER_FLOW", [12]="FI_WATER_FLOW_TAMPER", [13]="FI_STATUS_ONLY", [14]="FI_MANUAL_CALL", [15]="FI_FIREMAN_CALL", [16]="FI_UNIVERSAL", [255]="FI_NUL"}},
  [-3027] = {name="fire_indicator_t", apogee=true, levels={[0]="UNDEF", [1]="STROBE_U", [2]="STROBE_S", [3]="HORN", [4]="CHIME", [5]="BELL", [6]="SOUNDER", [7]="SPEAKER", [8]="UNIVERSL", [255]="NUL"}},
  [-3527] = {name="fire_indicator_b", apogee=true, levels={[1]="UNDEF", [2]="STROBE_U", [3]="STROBE_S", [4]="HORN", [5]="CHIME", [6]="BELL", [7]="SOUNDER", [8]="SPEAKER", [9]="UNIVERSL"}},
  [-3028] = {name="calendar_type_t", apogee=false, levels={[0]="CAL_GREG", [1]="CAL_JUL", [2]="CAL_MEU", [255]="CAL_NUL"}},
  [-3029] = {name="reg_val_unit_t", apogee=false, levels={[0]="RVU_NONE", [1]="RVU_W", [2]="RVU_KW", [3]="RVU_MW", [4]="RVU_GW", [5]="RVU_VAR", [6]="RVU_KVAR", [7]="RVU_MVAR", [8]="RVU_GVAR", [9]="RVU_WH", [10]="RVU_KWH", [11]="RVU_MWH", [12]="RVU_GWH", [13]="RVU_VARH", [14]="RVU_KVARH", [15]="RVU_MVARH", [16]="RVU_GVARH", [17]="RVU_V", [18]="RVU_A", [19]="RVU_COSF", [20]="RVU_M3", [21]="RVU_L", [22]="RVU_ML", [23]="RVU_USGAL", [24]="RVU_GJ", [25]="RVU_MJ", [26]="RVU_MCAL", [27]="RVU_KCAL", [28]="RVU_MBTU", [29]="RVU_KBTU", [30]="RVU_MJH", [31]="RVU_MLS", [32]="RVU_LS", [33]="RVU_M3S", [34]="RVU_C", [35]="RVU_LH", [36]="RVU_VA", [37]="RVU_KVA", [38]="RVU_MVA", [39]="RVU_GVA", [40]="RVU_VAH", [41]="RVU_KVAH", [42]="RVU_MVAH", [43]="RVU_GVAH", [255]="RVU_NUL"}},
  [-3030] = {name="hvac_hvt_t", apogee=true, levels={[0]="GENERIC", [1]="FAN_COIL", [2]="VAV", [3]="HEATPUMP", [4]="ROOFTOP", [5]="UNITVENT", [6]="CHILCEIL", [7]="RADIATOR", [8]="AHU", [9]="SELFCONT", [255]="NUL"}},
  [-3530] = {name="hvac_hvt_b", apogee=true, levels={[1]="GENERIC", [2]="FAN_COIL", [3]="VAV", [4]="HEATPUMP", [5]="ROOFTOP", [6]="UNITVENT", [7]="CHILCEIL", [8]="RADIATOR", [9]="AHU", [10]="SELFCONT"}},
  [-3031] = {name="event_mode_type_t", apogee=true, levels={[0]="LIST_END", [1]="SCENE", [2]="MODE", [255]="NUL"}},
  [-3531] = {name="event_mode_type_b", apogee=true, levels={[1]="LIST_END", [2]="SCENE", [3]="MODE"}},
  [-3100] = {name="T_in", apogee=false, levels={[0]="SPACE_TEMP", [1]="SPACE_SETPT_TEMP", [2]="SOURCE_TEMP", [3]="DISCH_TEMP", [4]="OA_TEMP", [5]="MIXED_TEMP", [8]="STAT_SWITCH_DI", [9]="OCC_SENSOR_DI", [10]="WALL_SWITCH_DI", [11]="LOW_TEMP_DI", [12]="FAN_STATUS_DI", [15]="ONBD_PRESSURE_PCT", [16]="EXT_PRESSURE_PCT", [17]="EXT_PRESSURE2_PCT", [19]="SPARE1_TEMP", [20]="SPARE1_DI", [21]="SPARE1_PCT", [255]="IN_UNUSED"}},
  [-3101] = {name="T_out", apogee=false, levels={[0]="TRM_H_COIL_AO", [1]="TRM_H_COIL_FLT_MTR", [2]="TRM_H_COIL_2POS_DO", [3]="TRM_H_STAGE1_DO", [4]="TRM_H_STAGE2_DO", [5]="TRM_H_STAGE3_DO", [6]="TRM_C_COIL_AO", [7]="TRM_C_COIL_FLT_MTR", [8]="TRM_C_COIL_2POS_DO", [9]="PERIM_H_COIL_AO", [10]="PERIM_H_COIL_FLT_MTR", [11]="PERIM_H_STAGE1_DO", [12]="AUX_H_COIL_AO", [13]="AUX_H_COIL_FLT_MTR", [14]="AUX_H_STAGE1_DO", [15]="AUX_H_STAGE2_DO", [16]="AUX_H_STAGE3_DO", [17]="FLOW_DMPR_AO", [18]="FLOW_DMPR_FLT_MTR", [19]="FLOW_DMPR2_AO", [20]="FLOW_DMPR2_FLT_MTR", [21]="OA_DMPR_AO", [22]="OA_DMPR_FLT_MTR", [23]="OA_DMPR_2POS_DO", [24]="FACE_BYPASS_AO", [25]="FACE_BYPASS_FLT_MTR", [26]="DX_STAGE1_DO", [27]="DX_STAGE2_DO", [28]="DX_STAGE3_DO", [29]="H_DX_STAGE1_DO", [30]="H_DX_STAGE2_DO", [31]="H_DX_STAGE3_DO", [32]="REV_RELAY_DO", [33]="TRM_FAN_DO", [34]="SPC_LIGHTS_DO", [35]="SPARE1_AO", [36]="SPARE2_AO", [37]="SPARE1_DO", [38]="SPARE2_DO", [255]="OUT_UNUSED"}},
  [-3102] = {name="T_sparei", apogee=false, levels={[0]="STAT_TEMP", [1]="STAT_SETPT_TEMP", [2]="SPARE1_TEMP", [3]="SPARE2_TEMP", [4]="SPARE3_TEMP", [5]="SPARE4_TEMP", [6]="SPARE5_TEMP", [7]="SPARE6_TEMP", [8]="STAT_OVRD_DI", [9]="SPARE1_DI", [10]="SPARE2_DI", [11]="SPARE3_DI", [12]="SPARE4_DI", [13]="SPARE5_DI", [14]="SPARE6_DI", [15]="SPARE1_PCT", [16]="SPARE2_PCT", [17]="SPARE3_PCT", [18]="SPARE4_PCT", [255]="IN_UNUSED"}},
  [-3103] = {name="T_spareo", apogee=false, levels={[0]="SPARE1_AO", [6]="SPARE2_AO", [9]="SPARE3_AO", [10]="SPARE1_FLT_MTR", [13]="SPARE2_FLT_MTR", [18]="SPARE3_FLT_MTR", [20]="SPARE4_FLT_MTR", [26]="SPARE1_DO", [27]="SPARE2_DO", [28]="SPARE3_DO", [29]="SPARE4_DO", [30]="SPARE5_DO", [31]="SPARE6_DO", [32]="SPARE7_DO", [33]="SPARE8_DO", [255]="OUT_UNUSED"}},
  [-3104] = {name="boolean", apogee=true, levels={[0]="FALSE", [1]="TRUE"}},
  [-3604] = {name="b_boolean", apogee=true, levels={[1]="FALSE", [2]="TRUE"}},
  [-3105] = {name="T_UNVT_device_mode", apogee=true, levels={[0]="MODULATE", [1]="CYCLE", [2]="OFF", [3]="ON"}},
  [-3605] = {name="B_UNVT_device_mode", apogee=true, levels={[1]="MODULATE", [2]="CYCLE", [3]="OFF", [4]="ON"}},
  [-3106] = {name="T_UNVT_coil_control", apogee=true, levels={[0]="VALVE", [1]="BYP_DMPR"}},
  [-3606] = {name="B_UNVT_coil_control", apogee=true, levels={[1]="VALVE", [2]="BYP_DMPR"}},
  [-3107] = {name="T_UNVT_switch_method", apogee=true, levels={[0]="DEADBAND", [1]="PWM"}},
  [-3607] = {name="B_UNVT_switch_method", apogee=true, levels={[1]="DEADBAND", [2]="PWM"}},
  [-3108] = {name="T_UNVT_energy_type", apogee=true, levels={[0]="ELECTRIC", [1]="HOTWATER", [2]="STEAM", [3]="CHILLWTR", [4]="OUT_AIR"}},
  [-3608] = {name="B_UNVT_energy_type", apogee=true, levels={[1]="ELECTRIC", [2]="HOTWATER", [3]="STEAM", [4]="CHILLWTR", [5]="OUT_AIR"}},
  [-3109] = {name="T_UNVT_air_terminal", apogee=true, levels={[0]="NO_FAN", [1]="SERIES", [2]="PARALLEL"}},
  [-3609] = {name="B_UNVT_air_terminal", apogee=true, levels={[1]="NO_FAN", [2]="SERIES", [3]="PARALLEL"}},
  [-3110] = {name="T_contact", apogee=true, levels={[0]="NRM_OPEN", [1]="NRM_CLOS"}},
  [-3610] = {name="B_contact", apogee=true, levels={[1]="NRM_OPEN", [2]="NRM_CLOS"}},
  [-3111] = {name="T_DO_offset", apogee=true, levels={[0]="NRM_OFF", [1]="NRM_ON"}},
  [-3611] = {name="B_DO_offset", apogee=true, levels={[1]="NRM_OFF", [2]="NRM_ON"}},
  [-3112] = {name="aux_dp_loc_t", apogee=true, levels={[0]="HOT_DUCT", [1]="DSCH_DCT"}},
  [-3612] = {name="aux_dp_loc_b", apogee=true, levels={[1]="HOT_DUCT", [2]="DSCH_DCT"}},
  [-3113] = {name="disable_type_t", apogee=true, levels={[0]="NONE", [1]="BYPASS", [2]="DI1", [3]="DI2", [4]="DI3", [5]="DI4", [6]="DI5", [7]="DI6", [8]="DO1", [9]="DO2", [10]="DO3", [11]="DO4", [12]="DO5", [13]="DO6", [14]="DO7", [15]="DO8", [16]="NVI_DIS"}},
  [-3613] = {name="disable_type_b", apogee=true, levels={[1]="NONE", [2]="BYPASS", [3]="DI1", [4]="DI2", [5]="DI3", [6]="DI4", [7]="DI5", [8]="DI6", [9]="DO1", [10]="DO2", [11]="DO3", [12]="DO4", [13]="DO5", [14]="DO6", [15]="DO7", [16]="DO8", [17]="NVI_DIS"}},
  [-3114] = {name="dp_range_t", apogee=true, levels={[0]="DP2_INWC", [1]="DP1_INWC", [2]="DP_HALF"}},
  [-3614] = {name="dp_range_b", apogee=true, levels={[1]="DP2_INWC", [2]="DP1_INWC", [3]="DP_HALF"}},
  [-3115] = {name="econ_control_t", apogee=true, levels={[0]="NONE", [1]="MAT", [2]="DAT", [3]="INTLK"}},
  [-3615] = {name="econ_control_b", apogee=true, levels={[1]="NONE", [2]="MAT", [3]="DAT", [4]="INTLK"}},
  [-3116] = {name="fan_coef_sel_t", apogee=true, levels={[0]="CUSTOM", [1]="TYPE_3", [2]="TYPE_5", [3]="TYPE_7"}},
  [-3616] = {name="fan_coef_sel_b", apogee=true, levels={[1]="CUSTOM", [2]="TYPE_3", [3]="TYPE_5", [4]="TYPE_7"}},
  [-3117] = {name="fnc_select_t", apogee=true, levels={[0]="MINIMUM", [1]="MAXIMUM", [2]="AVERAGE"}},
  [-3617] = {name="fnc_select_b", apogee=true, levels={[1]="MINIMUM", [2]="MAXIMUM", [3]="AVERAGE"}},
  [-3118] = {name="reset_src_t", apogee=true, levels={[0]="NONE", [1]="RETURN", [2]="SPACE", [3]="OA_TEMP", [4]="PERCENT"}},
  [-3618] = {name="reset_src_b", apogee=true, levels={[1]="NONE", [2]="RETURN", [3]="SPACE", [4]="OA_TEMP", [5]="PERCENT"}},
  [-3119] = {name="series_parl_t", apogee=true, levels={[0]="SERIES", [1]="PARALLEL"}},
  [-3619] = {name="series_parl_b", apogee=true, levels={[1]="SERIES", [2]="PARALLEL"}},
  [-3120] = {name="source_type_t", apogee=true, levels={[0]="STAT_TMP", [1]="STAT_SPT", [2]="PVI_TEMP", [3]="PVI_PCT", [4]="NVI_TEMP", [5]="NVI_PCT", [6]="PID", [7]="MAP", [8]="COMPARE", [9]="NCI_TEMP", [10]="NCI_PCT", [11]="AIRFLOW"}},
  [-3620] = {name="source_type_b", apogee=true, levels={[1]="STAT_TMP", [2]="STAT_SPT", [3]="PVI_TEMP", [4]="PVI_PCT", [5]="NVI_TEMP", [6]="NVI_PCT", [7]="PID", [8]="MAP", [9]="COMPARE", [10]="NCI_TEMP", [11]="NCI_PCT", [12]="AIRFLOW"}},
  [-3121] = {name="src_tmp_loc_t", apogee=true, levels={[0]="NONE", [1]="COLD_DCT", [2]="HOT_DUCT"}},
  [-3621] = {name="src_tmp_loc_b", apogee=true, levels={[1]="NONE", [2]="COLD_DCT", [3]="HOT_DUCT"}},
  [-3122] = {name="temp_source_t", apogee=true, levels={[0]="RETURN", [1]="SPACE", [2]="FIXED"}},
  [-3622] = {name="temp_source_b", apogee=true, levels={[1]="RETURN", [2]="SPACE", [3]="FIXED"}},
  [-3123] = {name="UNVT_unit_t", apogee=true, levels={[0]="TEMP", [1]="PERCENT"}},
  [-3623] = {name="UNVT_unit_b", apogee=true, levels={[1]="TEMP", [2]="PERCENT"}},
  [-3200] = {name="T_HP_in", apogee=false, levels={[0]="SPACE_TEMP", [1]="SPACE_SETPT_TEMP", [2]="SOURCE_TEMP", [4]="OA_TEMP", [5]="MIXED_TEMP", [8]="STAT_SWITCH_DI", [9]="OCC_SENSOR_DI", [10]="WALL_SWITCH_DI", [11]="LOW_TEMP_DI", [12]="FAN_STATUS_DI", [19]="SPARE1_TEMP", [20]="SPARE1_DI", [21]="SPARE1_PCT", [255]="IN_UNUSED"}},
  [-3201] = {name="T_HP_out", apogee=false, levels={[9]="PERIM_H_COIL_AO", [10]="PERIM_H_COIL_FLT_MTR", [11]="PERIM_H_STAGE1_DO", [12]="AUX_H_COIL_AO", [13]="AUX_H_COIL_FLT_MTR", [14]="AUX_H_STAGE1_DO", [15]="AUX_H_STAGE2_DO", [16]="AUX_H_STAGE3_DO", [21]="OA_DMPR_AO", [22]="OA_DMPR_FLT_MTR", [23]="OA_DMPR_2POS_DO", [26]="DX_STAGE1_DO", [27]="DX_STAGE2_DO", [28]="DX_STAGE3_DO", [29]="H_DX_STAGE1_DO", [30]="H_DX_STAGE2_DO", [31]="H_DX_STAGE3_DO", [32]="REV_RELAY_DO", [33]="TRM_FAN_DO", [35]="SPARE1_AO", [37]="SPARE1_DO", [255]="OUT_UNUSED"}},
  [-3210] = {name="T_MUX_in", apogee=false, levels={[0]="STAT_TEMP", [1]="STAT_SETPT_TEMP", [2]="SPARE1_TEMP", [3]="SPARE2_TEMP", [4]="SPARE3_TEMP", [5]="SPARE4_TEMP", [6]="SPARE5_TEMP", [7]="SPARE6_TEMP", [8]="STAT_OVRD_DI", [9]="SPARE1_DI", [10]="SPARE2_DI", [11]="SPARE3_DI", [12]="SPARE4_DI", [13]="SPARE5_DI", [14]="SPARE6_DI", [15]="SPARE1_PCT", [16]="SPARE2_PCT", [17]="SPARE3_PCT", [18]="SPARE4_PCT", [255]="IN_UNUSED"}},
  [-3211] = {name="T_MUX_out", apogee=false, levels={[0]="SPARE1_AO", [6]="SPARE2_AO", [9]="SPARE3_AO", [10]="SPARE1_FLT_MTR", [13]="SPARE2_FLT_MTR", [18]="SPARE3_FLT_MTR", [20]="SPARE4_FLT_MTR", [26]="SPARE1_DO", [27]="SPARE2_DO", [28]="SPARE3_DO", [29]="SPARE4_DO", [30]="SPARE5_DO", [31]="SPARE6_DO", [32]="SPARE7_DO", [33]="SPARE8_DO", [255]="OUT_UNUSED"}},
  [-3220] = {name="T_UV_in", apogee=false, levels={[0]="SPACE_TEMP", [1]="SPACE_SETPT_TEMP", [3]="DISCH_TEMP", [4]="OA_TEMP", [8]="STAT_SWITCH_DI", [9]="OCC_SENSOR_DI", [10]="WALL_SWITCH_DI", [11]="LOW_TEMP_DI", [19]="SPARE1_TEMP", [20]="SPARE1_DI", [21]="SPARE1_PCT", [255]="IN_UNUSED"}},
  [-3221] = {name="T_UV_out", apogee=false, levels={[0]="TRM_H_COIL_AO", [1]="TRM_H_COIL_FLT_MTR", [2]="TRM_H_COIL_2POS_DO", [3]="TRM_H_STAGE1_DO", [4]="TRM_H_STAGE2_DO", [5]="TRM_H_STAGE3_DO", [6]="TRM_C_COIL_AO", [7]="TRM_C_COIL_FLT_MTR", [8]="TRM_C_COIL_2POS_DO", [9]="PERIM_H_COIL_AO", [10]="PERIM_H_COIL_FLT_MTR", [11]="PERIM_H_STAGE1_DO", [21]="OA_DMPR_AO", [22]="OA_DMPR_FLT_MTR", [24]="FACE_BYPASS_AO", [25]="FACE_BYPASS_FLT_MTR", [33]="TRM_FAN_DO", [34]="SPC_LIGHTS_DO", [35]="SPARE1_AO", [36]="SPARE2_AO", [37]="SPARE1_DO", [38]="SPARE2_DO", [255]="OUT_UNUSED"}},
  [-3230] = {name="T_FC_in", apogee=false, levels={[0]="SPACE_TEMP", [1]="SPACE_SETPT_TEMP", [2]="SOURCE_TEMP", [8]="STAT_SWITCH_DI", [9]="OCC_SENSOR_DI", [10]="WALL_SWITCH_DI", [19]="SPARE1_TEMP", [20]="SPARE1_DI", [21]="SPARE1_PCT", [255]="IN_UNUSED"}},
  [-3231] = {name="T_FC_out", apogee=false, levels={[0]="TRM_H_COIL_AO", [1]="TRM_H_COIL_FLT_MTR", [3]="TRM_H_STAGE1_DO", [4]="TRM_H_STAGE2_DO", [5]="TRM_H_STAGE3_DO", [6]="TRM_C_COIL_AO", [7]="TRM_C_COIL_FLT_MTR", [9]="PERIM_H_COIL_AO", [10]="PERIM_H_COIL_FLT_MTR", [11]="PERIM_H_STAGE1_DO", [33]="TRM_FAN_DO", [34]="SPC_LIGHTS_DO", [35]="SPARE1_AO", [36]="SPARE2_AO", [37]="SPARE1_DO", [38]="SPARE2_DO", [255]="OUT_UNUSED"}},
  [-3240] = {name="T_VAV_in", apogee=false, levels={[0]="SPACE_TEMP", [1]="SPACE_SETPT_TEMP", [2]="SOURCE_TEMP", [8]="STAT_SWITCH_DI", [9]="OCC_SENSOR_DI", [10]="WALL_SWITCH_DI", [15]="ONBD_PRESSURE_PCT", [20]="SPARE1_DI", [21]="SPARE1_PCT", [255]="IN_UNUSED"}},
  [-3241] = {name="T_VAV_out", apogee=false, levels={[0]="TRM_H_COIL_AO", [1]="TRM_H_COIL_FLT_MTR", [3]="TRM_H_STAGE1_DO", [4]="TRM_H_STAGE2_DO", [5]="TRM_H_STAGE3_DO", [9]="PERIM_H_COIL_AO", [10]="PERIM_H_COIL_FLT_MTR", [11]="PERIM_H_STAGE1_DO", [17]="FLOW_DMPR_AO", [18]="FLOW_DMPR_FLT_MTR", [33]="TRM_FAN_DO", [34]="SPC_LIGHTS_DO", [35]="SPARE1_AO", [37]="SPARE1_DO", [255]="OUT_UNUSED"}},
}

p2data.revisions = {
  ["INT02"] = {level="2.0", cab="INSIGHT", str="RAD50"},
  ["INT03"] = {level="3.0", cab="INSIGHT", str="RAD50"},
  ["INT0310"] = {level="3.1", cab="INSIGHT", str="ASCII"},
  ["INT0320"] = {level="3.2", cab="INSIGHT", str="ASCII"},
  ["INT0330"] = {level="3.3", cab="INSIGHT", str="ASCII"},
  ["INT0340"] = {level="3.4", cab="INSIGHT", str="ASCII"},
  ["INT0350"] = {level="3.5", cab="INSIGHT", str="ASCII"},
  ["INT0351"] = {level="3.51", cab="INSIGHT", str="ASCII"},
  ["INT0360"] = {level="3.6", cab="INSIGHT", str="ASCII"},
  ["INT0370"] = {level="3.7", cab="INSIGHT", str="ASCII"},
  ["INT0380"] = {level="3.8", cab="INSIGHT", str="ASCII"},
  ["INT0381"] = {level="3.81", cab="INSIGHT", str="ASCII"},
  ["INT0390"] = {level="3.9", cab="INSIGHT", str="ASCII"},
  ["INT0391"] = {level="3.91", cab="INSIGHT", str="ASCII"},
  ["INT3100"] = {level="3.10", cab="INSIGHT", str="ASCII"},
  ["INT3110"] = {level="3.11", cab="INSIGHT", str="ASCII"},
  ["INT3120"] = {level="3.12", cab="INSIGHT", str="ASCII"},
  ["INT3130"] = {level="3.13", cab="INSIGHT", str="ASCII"},
  ["INT3140"] = {level="3.14", cab="INSIGHT", str="ASCII"},
  ["INT3150"] = {level="3.15", cab="INSIGHT", str="ASCII"},
  ["INT3160"] = {level="3.16", cab="INSIGHT", str="ASCII"},
  ["2.0"] = {level="2.0", cab="INSIGHT", str="ASCII"},
  ["2.1.1"] = {level="2.1.1", cab="INSIGHT", str="ASCII"},
  ["3.0"] = {level="3.0", cab="INSIGHT", str="ASCII"},
  ["4.0"] = {level="4.0", cab="INSIGHT", str="ASCII"},
  ["5.0"] = {level="5.0", cab="INSIGHT", str="ASCII"},
  ["GMS2.0"] = {level="2.0", cab="INSIGHT", str="ASCII"},
  ["GMS2.1"] = {level="2.1", cab="INSIGHT", str="ASCII"},
  ["GMS3.0"] = {level="3.0", cab="INSIGHT", str="ASCII"},
  ["GMS4.0"] = {level="4.0", cab="INSIGHT", str="ASCII"},
  ["GMS5.0"] = {level="5.0", cab="INSIGHT", str="ASCII"},
  ["SCU0601"] = {level="6.1", cab="SCU", str="RAD50"},
  ["SCU0700"] = {level="7.0", cab="SCU", str="RAD50"},
  ["SCU0701"] = {level="7.1", cab="SCU", str="RAD50"},
  ["SCU0702"] = {level="7.2", cab="SCU", str="RAD50"},
  ["SCU0800"] = {level="8.0", cab="SCU", str="RAD50"},
  ["SCU0900"] = {level="9.0", cab="SCU", str="RAD50"},
  ["SCU0901"] = {level="9.1", cab="SCU", str="RAD50"},
  ["SCU0902"] = {level="9.2", cab="SCU", str="RAD50"},
  ["SCU0903"] = {level="9.3", cab="SCU", str="RAD50"},
  ["SCU1000"] = {level="10.0", cab="SCU", str="RAD50"},
  ["SCU1001"] = {level="10.1", cab="SCU", str="RAD50"},
  ["SCU1100"] = {level="11.0", cab="SCU", str="RAD50"},
  ["SCU1101"] = {level="11.1", cab="SCU", str="RAD50"},
  ["SCU1102"] = {level="11.2", cab="SCU", str="RAD50"},
  ["SCU1103"] = {level="11.3", cab="SCU", str="RAD50"},
  ["SCU1201"] = {level="12.1", cab="SCU", str="RAD50"},
  ["SCU1202"] = {level="12.2", cab="SCU", str="RAD50"},
  ["SCU1203"] = {level="12.3", cab="SCU", str="RAD50"},
  ["SCU1204"] = {level="12.4", cab="SCU", str="RAD50"},
  ["SCU1241"] = {level="12.41", cab="SCU", str="RAD50"},
  ["SCU1205"] = {level="12.5", cab="SCU", str="RAD50"},
  ["SCU1251"] = {level="12.51", cab="SCU", str="RAD50"},
  ["SCU1252"] = {level="12.52", cab="SCU", str="RAD50"},
  ["SCU1253"] = {level="12.53", cab="SCU", str="RAD50"},
  ["SCU1254"] = {level="12.54", cab="SCU", str="RAD50"},
  ["SCU126"] = {level="12.6", cab="SCU", str="RAD50"},
  ["SCU127"] = {level="12.7", cab="SCU", str="RAD50"},
  ["SCU128"] = {level="12.8", cab="SCU", str="RAD50"},
  ["SCU129"] = {level="12.9", cab="SCU", str="RAD50"},
  ["CEC03"] = {level="13.0", cab="MBC", str="ASCII"},
  ["CEC04"] = {level="13.1", cab="MBC", str="ASCII"},
  ["CEC05"] = {level="13.2", cab="MBC", str="ASCII"},
  ["CEC06"] = {level="13.3", cab="MBC", str="ASCII"},
  ["CEC07"] = {level="13.4", cab="MBC", str="ASCII"},
  ["CEC08"] = {level="13.5", cab="MBC", str="ASCII"},
  ["CEC0838"] = {level="13.52", cab="MBC", str="ASCII"},
  ["CEC09"] = {level="13.6", cab="MBC", str="ASCII"},
  ["CEC095"] = {level="13.65", cab="MBC", str="ASCII"},
  ["CEC10"] = {level="13.7", cab="MBC", str="ASCII"},
  ["CEC11"] = {level="13.8", cab="MBC", str="ASCII"},
  ["CEC096"] = {level="14.0", cab="MBC", str="ASCII"},
  ["SV503"] = {level="13.0", cab="SCU", str="ASCII"},
  ["SV504"] = {level="13.1", cab="SCU", str="ASCII"},
  ["SV505"] = {level="13.2", cab="SCU", str="ASCII"},
  ["SV506"] = {level="13.3", cab="SCU", str="ASCII"},
  ["SV507"] = {level="13.4", cab="SCU", str="ASCII"},
  ["SV508"] = {level="13.5", cab="SCU", str="ASCII"},
  ["SV50838"] = {level="13.52", cab="SCU", str="ASCII"},
  ["SV509"] = {level="13.6", cab="SCU", str="ASCII"},
  ["SV5095"] = {level="13.65", cab="SCU", str="ASCII"},
  ["SV510"] = {level="13.7", cab="SCU", str="ASCII"},
  ["SV511"] = {level="13.8", cab="SCU", str="ASCII"},
  ["SV5111"] = {level="13.81", cab="SCU", str="ASCII"},
  ["MEC03"] = {level="13.0", cab="MEC", str="ASCII"},
  ["MEC04"] = {level="13.1", cab="MEC", str="ASCII"},
  ["MEC05"] = {level="13.2", cab="MEC", str="ASCII"},
  ["MEC06"] = {level="13.3", cab="MEC", str="ASCII"},
  ["MEC07"] = {level="13.4", cab="MEC", str="ASCII"},
  ["MEC08"] = {level="13.5", cab="MEC", str="ASCII"},
  ["MEC0838"] = {level="13.52", cab="MEC", str="ASCII"},
  ["MEC09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MEC095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MEC10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MEC11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MEC096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCF07"] = {level="13.4", cab="MEC", str="ASCII"},
  ["MCF08"] = {level="13.5", cab="MEC", str="ASCII"},
  ["MCF0838"] = {level="13.52", cab="MEC", str="ASCII"},
  ["MCF09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCF095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCF10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCF11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCF096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCE08"] = {level="13.53", cab="MEC", str="ASCII"},
  ["MCE09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCE095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCE10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCE11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCE096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCE098"] = {level="13.63", cab="MEC", str="ASCII"},
  ["MCL08"] = {level="13.53", cab="MEC", str="ASCII"},
  ["MCL09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCL095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCL10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCL11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCL096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCL098"] = {level="13.63", cab="MEC", str="ASCII"},
  ["MBN08"] = {level="13.53", cab="MBC", str="ASCII"},
  ["MBN09"] = {level="13.6", cab="MBC", str="ASCII"},
  ["MBN095"] = {level="13.65", cab="MBC", str="ASCII"},
  ["MBN098"] = {level="13.63", cab="MBC", str="ASCII"},
  ["MBN10"] = {level="13.7", cab="MBC", str="ASCII"},
  ["MBN11"] = {level="13.8", cab="MBC", str="ASCII"},
  ["MBN096"] = {level="14.0", cab="MBC", str="ASCII"},
  ["MBS08"] = {level="13.53", cab="MBC", str="ASCII"},
  ["MBS0847"] = {level="13.52", cab="MBC", str="ASCII"},
  ["MBS09"] = {level="13.6", cab="MBC", str="ASCII"},
  ["MBS095"] = {level="13.65", cab="MBC", str="ASCII"},
  ["MBS10"] = {level="13.7", cab="MBC", str="ASCII"},
  ["MBS11"] = {level="13.8", cab="MBC", str="ASCII"},
  ["MBS096"] = {level="14.0", cab="MBC", str="ASCII"},
  ["MCA08"] = {level="13.53", cab="MEC", str="ASCII"},
  ["MCA09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCA095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCA10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCA11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCA096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCP09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCP095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCP10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCP11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCP096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["MCS09"] = {level="13.6", cab="MEC", str="ASCII"},
  ["MCS095"] = {level="13.65", cab="MEC", str="ASCII"},
  ["MCS10"] = {level="13.7", cab="MEC", str="ASCII"},
  ["MCS11"] = {level="13.8", cab="MEC", str="ASCII"},
  ["MCS096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["SCT09"] = {level="13.6", cab="SCT", str="ASCII"},
  ["SCT10"] = {level="13.7", cab="SCT", str="ASCII"},
  ["SCT11"] = {level="13.8", cab="SCT", str="ASCII"},
  ["SCT096"] = {level="14.0", cab="SCT", str="ASCII"},
  ["_M"] = {level="13.0", cab="MXL", str="ASCII"},
  ["_X"] = {level="13.0", cab="XLS", str="ASCII"},
  ["NCC"] = {level="", cab="NCC", str="ASCII"},
  ["BCL096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["BBN096"] = {level="14.0", cab="MBC", str="ASCII"},
  ["BCE096"] = {level="14.0", cab="MEC", str="ASCII"},
  ["BCL1141"] = {level="14.01", cab="MEC", str="ASCII"},
  ["BBN1141"] = {level="14.01", cab="MBC", str="ASCII"},
  ["BCE1141"] = {level="14.01", cab="COMPACT", str="ASCII"},
  ["BME1141"] = {level="14.01", cab="MODULAR", str="ASCII"},
  ["BCL1142"] = {level="14.01", cab="MEC", str="ASCII"},
  ["BBN1142"] = {level="14.01", cab="MBC", str="ASCII"},
  ["BCE1142"] = {level="14.01", cab="COMPACT", str="ASCII"},
  ["BME1142"] = {level="14.01", cab="MODULAR", str="ASCII"},
  ["PCP099"] = {level="13.71", cab="COMPACT", str="ASCII"},
  ["PCE099"] = {level="13.71", cab="COMPACT", str="ASCII"},
  ["PME11"] = {level="13.8", cab="MODULAR", str="ASCII"},
  ["PMP11"] = {level="13.8", cab="MODULAR", str="ASCII"},
  ["PME1120"] = {level="13.81", cab="MODULAR", str="ASCII"},
  ["PMP1120"] = {level="13.81", cab="MODULAR", str="ASCII"},
  ["PCL1120"] = {level="13.81", cab="MODULAR", str="ASCII"},
  ["MCL1121"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MCE1121"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MBN1121"] = {level="13.82", cab="MBC", str="ASCII"},
  ["MBS1121"] = {level="13.82", cab="MBC", str="ASCII"},
  ["MCA1121"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MCP1121"] = {level="13.82", cab="MEC", str="ASCII"},
  ["PCE1121"] = {level="13.82", cab="COMPACT", str="ASCII"},
  ["PCE1168"] = {level="13.83", cab="COMPACT", str="ASCII"},
  ["PCP1121"] = {level="13.82", cab="COMPACT", str="ASCII"},
  ["PCP1168"] = {level="13.83", cab="COMPACT", str="ASCII"},
  ["PXE1168"] = {level="13.83", cab="COMPACT", str="ASCII"},
  ["PXP1168"] = {level="13.83", cab="COMPACT", str="ASCII"},
  ["PME1121"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["PMP1121"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["PCL1121"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["PCP110"] = {level="13.8", cab="COMPACT", str="ASCII"},
  ["MCL1122"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MCE1122"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MBN1122"] = {level="13.82", cab="MBC", str="ASCII"},
  ["MBS1122"] = {level="13.82", cab="MBC", str="ASCII"},
  ["MCA1122"] = {level="13.82", cab="MEC", str="ASCII"},
  ["MCP1122"] = {level="13.82", cab="MEC", str="ASCII"},
  ["PCE1122"] = {level="13.82", cab="COMPACT", str="ASCII"},
  ["PCP1122"] = {level="13.82", cab="COMPACT", str="ASCII"},
  ["PME1122"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["PMP1122"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["PCL1122"] = {level="13.82", cab="MODULAR", str="ASCII"},
  ["OP"] = {level="", cab="MBC", str="ASCII"},
  ["CEC"] = {level="", cab="MBC", str="ASCII"},
  ["FLNC"] = {level="", cab="FLNC", str="ASCII"},
  ["MEC"] = {level="", cab="MEC", str="ASCII"},
  ["MECF"] = {level="", cab="MEC", str="ASCII"},
  ["MECE"] = {level="", cab="MEC", str="ASCII"},
  ["MBCE"] = {level="", cab="MBC", str="ASCII"},
  ["MECL"] = {level="", cab="MEC", str="ASCII"},
  ["SV5"] = {level="", cab="SCU", str="ASCII"},
  ["SCU"] = {level="", cab="SCU", str="RAD50"},
  ["RCU"] = {level="", cab="RCU_P2", str="RAD50"},
  ["ASC"] = {level="", cab="SCU", str="ASCII"},
  ["MBCP"] = {level="", cab="MBC", str="ASCII"},
  ["MCFP"] = {level="", cab="MEC", str="ASCII"},
  ["MCLP"] = {level="", cab="MEC", str="ASCII"},
  ["MCNE"] = {level="", cab="MEC", str="ASCII"},
  ["MEFE"] = {level="", cab="MEC", str="ASCII"},
  ["MCFE"] = {level="", cab="MEC", str="ASCII"},
  ["MCLE"] = {level="", cab="MEC", str="ASCII"},
  ["FFP"] = {level="", cab="MEC", str="ASCII"},
  ["FFE"] = {level="", cab="MEC", str="ASCII"},
  ["FLP"] = {level="", cab="MEC", str="ASCII"},
  ["FLE"] = {level="", cab="MEC", str="ASCII"},
  ["MECP"] = {level="", cab="MEC", str="ASCII"},
  ["MECS"] = {level="", cab="MEC", str="ASCII"},
  ["MCKS"] = {level="", cab="MEC", str="ASCII"},
  ["MCMS"] = {level="", cab="MEC", str="ASCII"},
  ["MCKN"] = {level="", cab="MEC", str="ASCII"},
  ["MCMN"] = {level="", cab="MEC", str="ASCII"},
  ["SCTE"] = {level="", cab="SCT", str="ASCII"},
  ["MXL"] = {level="", cab="MXL", str="ASCII"},
  ["MXL-IQ"] = {level="", cab="MXL-IQ", str="ASCII"},
  ["XLS"] = {level="", cab="XLS", str="ASCII"},
  ["PMI-G"] = {level="", cab="PMI-G", str="ASCII"},
  ["PXCE"] = {level="", cab="COMPACT", str="ASCII"},
  ["PXCP"] = {level="", cab="COMPACT", str="ASCII"},
  ["PPXC"] = {level="", cab="COMPACT", str="ASCII"},
  ["PXME"] = {level="", cab="MODULAR", str="ASCII"},
  ["EPXC"] = {level="", cab="COMPACT", str="ASCII"},
  ["PXMP"] = {level="", cab="MODULAR", str="ASCII"},
  ["PXEE"] = {level="", cab="MODULAR", str="ASCII"},
  ["PXCL"] = {level="", cab="MODULAR", str="ASCII"},
  ["P36E"] = {level="", cab="COMPACT", str="ASCII"},
  ["P36P"] = {level="", cab="COMPACT", str="ASCII"},
  ["E36E"] = {level="", cab="COMPACT", str="ASCII"},
  ["E36L"] = {level="", cab="COMPACT", str="ASCII"},
  ["EX36"] = {level="", cab="COMPACT", str="ASCII"},
  ["PX36"] = {level="", cab="COMPACT", str="ASCII"},
  ["EL36"] = {level="", cab="COMPACT", str="ASCII"},
  ["PL36"] = {level="", cab="COMPACT", str="ASCII"},
  ["PAAC"] = {level="", cab="COMPACT", str="ASCII"},
  ["BCE1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BBN1162"] = {level="14.1", cab="MBC", str="ASCII"},
  ["BCL1162"] = {level="14.1", cab="MEC", str="ASCII"},
  ["BME1162"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["BCP1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BPX1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BCE1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BBN1163"] = {level="14.1", cab="MBC", str="ASCII"},
  ["BCL1163"] = {level="14.1", cab="MEC", str="ASCII"},
  ["BME1163"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["BCP1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BPX1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BCE1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BBN1164"] = {level="14.1", cab="MBC", str="ASCII"},
  ["BCL1164"] = {level="14.1", cab="MEC", str="ASCII"},
  ["BME1164"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["BCP1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["BPX1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TCE1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TBN1162"] = {level="14.1", cab="MBC", str="ASCII"},
  ["TCL1162"] = {level="14.1", cab="MEC", str="ASCII"},
  ["TME1162"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["TCP1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TPX1162"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TCE1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TBN1163"] = {level="14.1", cab="MBC", str="ASCII"},
  ["TCL1163"] = {level="14.1", cab="MEC", str="ASCII"},
  ["TME1163"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["TCP1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TPX1163"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TCE1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TBN1164"] = {level="14.1", cab="MBC", str="ASCII"},
  ["TCL1164"] = {level="14.1", cab="MEC", str="ASCII"},
  ["TME1164"] = {level="14.1", cab="MODULAR", str="ASCII"},
  ["TCP1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["TPX1164"] = {level="14.1", cab="COMPACT", str="ASCII"},
  ["PCP1175"] = {level="13.84", cab="COMPACT", str="ASCII"},
  ["PXE1175"] = {level="13.84", cab="COMPACT", str="ASCII"},
  ["PXP1175"] = {level="13.84", cab="COMPACT", str="ASCII"},
  ["MCL120"] = {level="13.85", cab="MEC", str="ASCII"},
  ["MCE120"] = {level="13.85", cab="MEC", str="ASCII"},
  ["MBN120"] = {level="13.85", cab="MBC", str="ASCII"},
  ["MBS120"] = {level="13.85", cab="MBC", str="ASCII"},
  ["MCA120"] = {level="13.85", cab="MEC", str="ASCII"},
  ["MCP120"] = {level="13.85", cab="MEC", str="ASCII"},
  ["PCE120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["PCP120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["PXE120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["PXP120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["PME120"] = {level="13.85", cab="MODULAR", str="ASCII"},
  ["PMP120"] = {level="13.85", cab="MODULAR", str="ASCII"},
  ["PCL120"] = {level="13.85", cab="MODULAR", str="ASCII"},
  ["P3E120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["P3P120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["36E120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["36P120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["3LE120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["3LP120"] = {level="13.85", cab="COMPACT", str="ASCII"},
  ["BCE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["BBN120"] = {level="14.2", cab="MBC", str="ASCII"},
  ["BCL120"] = {level="14.2", cab="MEC", str="ASCII"},
  ["BME120"] = {level="14.2", cab="MODULAR", str="ASCII"},
  ["BCP120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["BXE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["BXP120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["B3E120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["B6E120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["BLE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TCE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TBN120"] = {level="14.2", cab="MBC", str="ASCII"},
  ["TCL120"] = {level="14.2", cab="MEC", str="ASCII"},
  ["T3E120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TME120"] = {level="14.2", cab="MODULAR", str="ASCII"},
  ["TCP120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TXE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TPX120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TXP120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["T6E120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["TLE120"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["MCL1251"] = {level="13.86", cab="MEC", str="ASCII"},
  ["MCE11251"] = {level="13.86", cab="MEC", str="ASCII"},
  ["MBN1251"] = {level="13.86", cab="MBC", str="ASCII"},
  ["MBS1251"] = {level="13.86", cab="MBC", str="ASCII"},
  ["MCA1251"] = {level="13.86", cab="MEC", str="ASCII"},
  ["MCP1251"] = {level="13.86", cab="MEC", str="ASCII"},
  ["PCE1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["PCP1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["PXE1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["PXP1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["PME1251"] = {level="13.86", cab="MODULAR", str="ASCII"},
  ["PMP1251"] = {level="13.86", cab="MODULAR", str="ASCII"},
  ["PCL1251"] = {level="13.86", cab="MODULAR", str="ASCII"},
  ["P3E1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["P3P1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["36E1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["36P1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["3LE1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["3LP1251"] = {level="13.86", cab="COMPACT", str="ASCII"},
  ["BCE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["BBN1251"] = {level="14.21", cab="MBC", str="ASCII"},
  ["BCL1251"] = {level="14.21", cab="MEC", str="ASCII"},
  ["BME1251"] = {level="14.21", cab="MODULAR", str="ASCII"},
  ["BCP1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["BXE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["BXP1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["B3E1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["B6E1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["BLE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["BUC1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TCE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TBN1251"] = {level="14.21", cab="MBC", str="ASCII"},
  ["TCL1251"] = {level="14.21", cab="MEC", str="ASCII"},
  ["T3E1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TME1251"] = {level="14.21", cab="MODULAR", str="ASCII"},
  ["TCP1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TXE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TPX1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TXP1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["T6E1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TLE1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["TUC1251"] = {level="14.21", cab="COMPACT", str="ASCII"},
  ["MCL122"] = {level="13.87", cab="MEC", str="ASCII"},
  ["MCE122"] = {level="13.87", cab="MEC", str="ASCII"},
  ["MBN122"] = {level="13.87", cab="MBC", str="ASCII"},
  ["MBS122"] = {level="13.87", cab="MBC", str="ASCII"},
  ["MCA122"] = {level="13.87", cab="MEC", str="ASCII"},
  ["MCP122"] = {level="13.87", cab="MEC", str="ASCII"},
  ["PCE122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["PCP122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["PXE122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["PXP122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["PME122"] = {level="13.87", cab="MODULAR", str="ASCII"},
  ["PMP122"] = {level="13.87", cab="MODULAR", str="ASCII"},
  ["PCL122"] = {level="13.87", cab="MODULAR", str="ASCII"},
  ["P3E122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["P3P122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["36E122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["36P122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["3LE122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["3LP122"] = {level="13.87", cab="COMPACT", str="ASCII"},
  ["BCE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["BBN122"] = {level="14.22", cab="MBC", str="ASCII"},
  ["BCL122"] = {level="14.22", cab="MEC", str="ASCII"},
  ["BME122"] = {level="14.22", cab="MODULAR", str="ASCII"},
  ["BCP122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["BXE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["BXP122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["B3E122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["B6E122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["BLE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["BUC122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TCE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TBN122"] = {level="14.22", cab="MBC", str="ASCII"},
  ["TCL122"] = {level="14.22", cab="MEC", str="ASCII"},
  ["T3E122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TME122"] = {level="14.22", cab="MODULAR", str="ASCII"},
  ["TCP122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TXE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TPX122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TXP122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["T6E122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TLE122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["TUC122"] = {level="14.22", cab="COMPACT", str="ASCII"},
  ["MCL123"] = {level="13.88", cab="MEC", str="ASCII"},
  ["MCE123"] = {level="13.88", cab="MEC", str="ASCII"},
  ["MBN123"] = {level="13.88", cab="MBC", str="ASCII"},
  ["MBS123"] = {level="13.88", cab="MBC", str="ASCII"},
  ["MCA123"] = {level="13.88", cab="MEC", str="ASCII"},
  ["MCP123"] = {level="13.88", cab="MEC", str="ASCII"},
  ["PCE123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["PCP123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["PXE123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["PXP123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["PME123"] = {level="13.88", cab="MODULAR", str="ASCII"},
  ["PMP123"] = {level="13.88", cab="MODULAR", str="ASCII"},
  ["PCL123"] = {level="13.88", cab="MODULAR", str="ASCII"},
  ["P3E123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["P3P123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["36E123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["36P123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["3LE123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["3LP123"] = {level="13.88", cab="COMPACT", str="ASCII"},
  ["BCE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["BBN123"] = {level="14.23", cab="MBC", str="ASCII"},
  ["BCL123"] = {level="14.23", cab="MEC", str="ASCII"},
  ["BME123"] = {level="14.23", cab="MODULAR", str="ASCII"},
  ["BCP123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["BXE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["BXP123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["B3E123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["B6E123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["BLE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["BUC123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TCE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TBN123"] = {level="14.23", cab="MBC", str="ASCII"},
  ["TCL123"] = {level="14.23", cab="MEC", str="ASCII"},
  ["T3E123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TME123"] = {level="14.23", cab="MODULAR", str="ASCII"},
  ["TCP123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TXE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TPX123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TXP123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["T6E123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TLE123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["TUC123"] = {level="14.23", cab="COMPACT", str="ASCII"},
  ["MCL1240"] = {level="13.89", cab="MEC", str="ASCII"},
  ["MCE1240"] = {level="13.89", cab="MEC", str="ASCII"},
  ["MBN1240"] = {level="13.89", cab="MBC", str="ASCII"},
  ["MBS1240"] = {level="13.89", cab="MBC", str="ASCII"},
  ["MCA1240"] = {level="13.89", cab="MEC", str="ASCII"},
  ["MCP1240"] = {level="13.89", cab="MEC", str="ASCII"},
  ["PCE1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["PCP1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["PXE1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["PXP1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["PME1240"] = {level="13.89", cab="MODULAR", str="ASCII"},
  ["PMP1240"] = {level="13.89", cab="MODULAR", str="ASCII"},
  ["PCL1240"] = {level="13.89", cab="MODULAR", str="ASCII"},
  ["P3E1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["P3P1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["36E1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["36P1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["3LE1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["3LP1240"] = {level="13.89", cab="COMPACT", str="ASCII"},
  ["BCE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["BBN1240"] = {level="14.24", cab="MBC", str="ASCII"},
  ["BCL1240"] = {level="14.24", cab="MEC", str="ASCII"},
  ["BME1240"] = {level="14.24", cab="MODULAR", str="ASCII"},
  ["BCP1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["BXE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["BXP1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["B3E1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["B6E1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["BLE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["BUC1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TCE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TBN1240"] = {level="14.24", cab="MBC", str="ASCII"},
  ["TCL1240"] = {level="14.24", cab="MEC", str="ASCII"},
  ["T3E1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TME1240"] = {level="14.24", cab="MODULAR", str="ASCII"},
  ["TCP1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TXE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TPX1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TXP1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["T6E1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TLE1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["TUC1240"] = {level="14.24", cab="COMPACT", str="ASCII"},
  ["MCL1252"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MCE1252"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MBN1252"] = {level="13.811", cab="MBC", str="ASCII"},
  ["MBS1252"] = {level="13.811", cab="MBC", str="ASCII"},
  ["MCA1252"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MCP1252"] = {level="13.811", cab="MEC", str="ASCII"},
  ["PCE1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PCP1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PXE1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PXP1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PME1252"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["PMP1252"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["PCL1252"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["P3E1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["P3P1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["36E1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["36P1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["3LE1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["3LP1252"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["BCE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["BBN1252"] = {level="14.25", cab="MBC", str="ASCII"},
  ["BCL1252"] = {level="14.25", cab="MEC", str="ASCII"},
  ["BME1252"] = {level="14.25", cab="MODULAR", str="ASCII"},
  ["BCP1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["BXE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["BXP1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["B3E1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["B6E1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["BLE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["BUC1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TCE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TBN1252"] = {level="14.25", cab="MBC", str="ASCII"},
  ["TCL1252"] = {level="14.25", cab="MEC", str="ASCII"},
  ["T3E1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TME1252"] = {level="14.25", cab="MODULAR", str="ASCII"},
  ["TCP1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TXE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TPX1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TXP1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["T6E1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TLE1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["TUC1252"] = {level="14.25", cab="COMPACT", str="ASCII"},
  ["MCL1261"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MCE1261"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MBN1261"] = {level="13.811", cab="MBC", str="ASCII"},
  ["MBS1261"] = {level="13.811", cab="MBC", str="ASCII"},
  ["MCA1261"] = {level="13.811", cab="MEC", str="ASCII"},
  ["MCP1261"] = {level="13.811", cab="MEC", str="ASCII"},
  ["PCE1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PCP1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PXE1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PXP1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["PME1261"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["PMP1261"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["PCL1261"] = {level="13.811", cab="MODULAR", str="ASCII"},
  ["P3E1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["P3P1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["36E1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["36P1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["3LE1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["3LP1261"] = {level="13.811", cab="COMPACT", str="ASCII"},
  ["BCE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["BBN1261"] = {level="14.3", cab="MBC", str="ASCII"},
  ["BCL1261"] = {level="14.3", cab="MEC", str="ASCII"},
  ["BME1261"] = {level="14.3", cab="MODULAR", str="ASCII"},
  ["BCP1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["BXE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["BXP1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["B3E1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["B6E1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["BLE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["BUC1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TCE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TBN1261"] = {level="14.3", cab="MBC", str="ASCII"},
  ["TCL1261"] = {level="14.3", cab="MEC", str="ASCII"},
  ["T3E1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TME1261"] = {level="14.3", cab="MODULAR", str="ASCII"},
  ["TCP1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TXE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TPX1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TXP1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["T6E1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TLE1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["TUC1261"] = {level="14.3", cab="COMPACT", str="ASCII"},
  ["MCL1262"] = {level="13.812", cab="MEC", str="ASCII"},
  ["MCE1262"] = {level="13.812", cab="MEC", str="ASCII"},
  ["MBN1262"] = {level="13.812", cab="MBC", str="ASCII"},
  ["MBS1262"] = {level="13.812", cab="MBC", str="ASCII"},
  ["MCA1262"] = {level="13.812", cab="MEC", str="ASCII"},
  ["MCP1262"] = {level="13.812", cab="MEC", str="ASCII"},
  ["PCE1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["PCP1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["PXE1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["PXP1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["PME1262"] = {level="13.812", cab="MODULAR", str="ASCII"},
  ["PMP1262"] = {level="13.812", cab="MODULAR", str="ASCII"},
  ["PCL1262"] = {level="13.812", cab="MODULAR", str="ASCII"},
  ["P3E1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["P3P1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["36E1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["36P1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["3LE1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["3LP1262"] = {level="13.812", cab="COMPACT", str="ASCII"},
  ["BCE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["BBN1262"] = {level="14.31", cab="MBC", str="ASCII"},
  ["BCL1262"] = {level="14.31", cab="MEC", str="ASCII"},
  ["BME1262"] = {level="14.31", cab="MODULAR", str="ASCII"},
  ["BCP1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["BXE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["BXP1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["B3E1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["B6E1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["BLE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["BUC1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TCE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TBN1262"] = {level="14.31", cab="MBC", str="ASCII"},
  ["TCL1262"] = {level="14.31", cab="MEC", str="ASCII"},
  ["T3E1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TME1262"] = {level="14.31", cab="MODULAR", str="ASCII"},
  ["TCP1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TXE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TPX1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TXP1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["T6E1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TLE1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["TUC1262"] = {level="14.31", cab="COMPACT", str="ASCII"},
  ["MCL1265"] = {level="13.813", cab="MEC", str="ASCII"},
  ["MCE1265"] = {level="13.813", cab="MEC", str="ASCII"},
  ["MBN1265"] = {level="13.813", cab="MBC", str="ASCII"},
  ["MBS1265"] = {level="13.813", cab="MBC", str="ASCII"},
  ["MCA1265"] = {level="13.813", cab="MEC", str="ASCII"},
  ["MCP1265"] = {level="13.813", cab="MEC", str="ASCII"},
  ["PCE1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["PCP1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["PXE1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["PXP1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["PME1265"] = {level="13.813", cab="MODULAR", str="ASCII"},
  ["PMP1265"] = {level="13.813", cab="MODULAR", str="ASCII"},
  ["PCL1265"] = {level="13.813", cab="MODULAR", str="ASCII"},
  ["P3E1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["P3P1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["36E1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["36P1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["3LE1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["3LP1265"] = {level="13.813", cab="COMPACT", str="ASCII"},
  ["BCE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["BBN1265"] = {level="14.4", cab="MBC", str="ASCII"},
  ["BCL1265"] = {level="14.4", cab="MEC", str="ASCII"},
  ["BME1265"] = {level="14.4", cab="MODULAR", str="ASCII"},
  ["BCP1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["BXE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["BXP1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["B3E1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["B6E1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["BLE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["BUC1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TCE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TBN1265"] = {level="14.4", cab="MBC", str="ASCII"},
  ["TCL1265"] = {level="14.4", cab="MEC", str="ASCII"},
  ["T3E1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TME1265"] = {level="14.4", cab="MODULAR", str="ASCII"},
  ["TCP1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TXE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TPX1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TXP1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["T6E1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TLE1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["TUC1265"] = {level="14.4", cab="COMPACT", str="ASCII"},
  ["MCL1270"] = {level="13.815", cab="MEC", str="ASCII"},
  ["MCE1270"] = {level="13.815", cab="MEC", str="ASCII"},
  ["MBN1270"] = {level="13.815", cab="MBC", str="ASCII"},
  ["MBS1270"] = {level="13.815", cab="MBC", str="ASCII"},
  ["MCA1270"] = {level="13.815", cab="MEC", str="ASCII"},
  ["MCP1270"] = {level="13.815", cab="MEC", str="ASCII"},
  ["PCE1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["PCP1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["PXE1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["PXP1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["PME1270"] = {level="13.815", cab="MODULAR", str="ASCII"},
  ["PMP1270"] = {level="13.815", cab="MODULAR", str="ASCII"},
  ["PCL1270"] = {level="13.815", cab="MODULAR", str="ASCII"},
  ["P3E1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["P3P1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["36E1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["36P1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["3LE1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["3LP1270"] = {level="13.815", cab="COMPACT", str="ASCII"},
  ["BCE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BBN1270"] = {level="14.5", cab="MBC", str="ASCII"},
  ["BCL1270"] = {level="14.5", cab="MEC", str="ASCII"},
  ["BME1270"] = {level="14.5", cab="MODULAR", str="ASCII"},
  ["BCP1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BXE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BXP1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["B3E1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["B6E1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BLE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BUC1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TCE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TBN1270"] = {level="14.5", cab="MBC", str="ASCII"},
  ["TCL1270"] = {level="14.5", cab="MEC", str="ASCII"},
  ["T3E1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TME1270"] = {level="14.5", cab="MODULAR", str="ASCII"},
  ["TCP1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TXE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TPX1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TXP1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["T6E1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TLE1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["TUC1270"] = {level="14.5", cab="COMPACT", str="ASCII"},
  ["BCE1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["BME1280"] = {level="14.51", cab="MODULAR", str="ASCII"},
  ["BCP1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["BXE1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["BXP1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["B3E1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["B6E1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["BUC1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TCE1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["T3E1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TME1280"] = {level="14.51", cab="MODULAR", str="ASCII"},
  ["TCP1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TXE1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TPX1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TXP1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["T6E1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["TUC1280"] = {level="14.51", cab="COMPACT", str="ASCII"},
  ["BCE1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["BME1290"] = {level="14.52", cab="MODULAR", str="ASCII"},
  ["BCP1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["BXE1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["BXP1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["B3E1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["B6E1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["BUC1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TCE1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["T3E1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TME1290"] = {level="14.52", cab="MODULAR", str="ASCII"},
  ["TCP1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TXE1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TPX1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TXP1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["T6E1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["TUC1290"] = {level="14.52", cab="COMPACT", str="ASCII"},
  ["MCL1300"] = {level="13.818", cab="MEC", str="ASCII"},
  ["MCE1300"] = {level="13.818", cab="MEC", str="ASCII"},
  ["MBN1300"] = {level="13.818", cab="MBC", str="ASCII"},
  ["MBS1300"] = {level="13.818", cab="MBC", str="ASCII"},
  ["MCA1300"] = {level="13.818", cab="MEC", str="ASCII"},
  ["MCP1300"] = {level="13.818", cab="MEC", str="ASCII"},
  ["PCE1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["PCP1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["PXE1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["PXP1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["PME1300"] = {level="13.818", cab="MODULAR", str="ASCII"},
  ["PMP1300"] = {level="13.818", cab="MODULAR", str="ASCII"},
  ["PCL1300"] = {level="13.818", cab="MODULAR", str="ASCII"},
  ["P3E1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["P3P1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["36E1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["36P1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["3LE1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["3LP1300"] = {level="13.818", cab="COMPACT", str="ASCII"},
  ["B6E1164"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["T6E1164"] = {level="14.2", cab="COMPACT", str="ASCII"},
  ["BCE1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["BME1300"] = {level="14.53", cab="MODULAR", str="ASCII"},
  ["BCP1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["BXE1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["BXP1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["B3E1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["B6E1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["BUC1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TCE1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["T3E1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TME1300"] = {level="14.53", cab="MODULAR", str="ASCII"},
  ["TCP1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TXE1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TPX1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TXP1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["T6E1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["TUC1300"] = {level="14.53", cab="COMPACT", str="ASCII"},
  ["BCE1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["BME1310"] = {level="14.54", cab="MODULAR", str="ASCII"},
  ["BCP1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["BXE1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["BXP1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["B3E1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["B6E1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["BUC1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TCE1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["T3E1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TME1310"] = {level="14.54", cab="MODULAR", str="ASCII"},
  ["TCP1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TXE1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TPX1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TXP1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["T6E1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["TUC1310"] = {level="14.54", cab="COMPACT", str="ASCII"},
  ["MCL1310"] = {level="13.819", cab="MEC", str="ASCII"},
  ["MCE1310"] = {level="13.819", cab="MEC", str="ASCII"},
  ["MBN1310"] = {level="13.819", cab="MBC", str="ASCII"},
  ["MBS1310"] = {level="13.819", cab="MBC", str="ASCII"},
  ["MCA1310"] = {level="13.819", cab="MEC", str="ASCII"},
  ["MCP1310"] = {level="13.819", cab="MEC", str="ASCII"},
  ["PCE1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["PCP1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["PXE1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["PXP1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["PME1310"] = {level="13.819", cab="MODULAR", str="ASCII"},
  ["PMP1310"] = {level="13.819", cab="MODULAR", str="ASCII"},
  ["PCL1310"] = {level="13.819", cab="MODULAR", str="ASCII"},
  ["P3E1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["P3P1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["36E1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["36P1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["3LE1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["3LP1310"] = {level="13.819", cab="COMPACT", str="ASCII"},
  ["BCE1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["BME1320"] = {level="14.55", cab="MODULAR", str="ASCII"},
  ["BCP1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["BXE1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["BXP1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["B3E1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["B6E1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["BUC1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TCE1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["T3E1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TME1320"] = {level="14.55", cab="MODULAR", str="ASCII"},
  ["TCP1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TXE1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TPX1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TXP1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["T6E1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["TUC1320"] = {level="14.55", cab="COMPACT", str="ASCII"},
  ["MCL1320"] = {level="13.820", cab="MEC", str="ASCII"},
  ["MCE1320"] = {level="13.820", cab="MEC", str="ASCII"},
  ["MBN1320"] = {level="13.820", cab="MBC", str="ASCII"},
  ["MBS1320"] = {level="13.820", cab="MBC", str="ASCII"},
  ["MCA1320"] = {level="13.820", cab="MEC", str="ASCII"},
  ["MCP1320"] = {level="13.820", cab="MEC", str="ASCII"},
  ["PCE1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["PCP1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["PXE1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["PXP1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["PME1320"] = {level="13.820", cab="MODULAR", str="ASCII"},
  ["PMP1320"] = {level="13.820", cab="MODULAR", str="ASCII"},
  ["PCL1320"] = {level="13.820", cab="MODULAR", str="ASCII"},
  ["P3E1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["P3P1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["36E1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["36P1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["3LE1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["3LP1320"] = {level="13.820", cab="COMPACT", str="ASCII"},
  ["BCE1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["BME1330"] = {level="14.56", cab="MODULAR", str="ASCII"},
  ["BCP1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["BXE1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["BXP1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["B3E1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["B6E1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["BUC1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TCE1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["T3E1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TME1330"] = {level="14.56", cab="MODULAR", str="ASCII"},
  ["TCP1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TXE1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TPX1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TXP1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["T6E1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
  ["TUC1330"] = {level="14.56", cab="COMPACT", str="ASCII"},
}

p2data.point_types = {
  [1] = {mnemonic="LDI", name="Logical Digital Input", default_enum=-1},
  [2] = {mnemonic="LDO", name="Logical Digital Output", default_enum=-2},
  [3] = {mnemonic="LAI", name="Logical Analog Input", default_enum=nil},
  [4] = {mnemonic="LAO", name="Logical Analog Output", default_enum=nil},
  [6] = {mnemonic="L2SL", name="Logical Two-State Latched", default_enum=-6},
  [7] = {mnemonic="LOOAP", name="Logical On/Off/Auto Pulsed", default_enum=-7},
  [11] = {mnemonic="LPACI", name="Logical Pulse Accumulator (Counter) Input", default_enum=nil},
  [12] = {mnemonic="L2SP", name="Logical Two-State Pulsed", default_enum=-12},
  [13] = {mnemonic="LOOAL", name="Logical On/Off/Auto Latched", default_enum=-13},
  [14] = {mnemonic="LFSSL", name="Logical Fast/Slow/Stop Latched", default_enum=-14},
  [15] = {mnemonic="LFSSP", name="Logical Fast/Slow/Stop Pulsed", default_enum=-15},
  [19] = {mnemonic="LCTLR", name="Logical Controller (control loop)", default_enum=-19},
  [20] = {mnemonic="LDAO", name="Logical Digital-Actuated Analog Output", default_enum=nil},
  [21] = {mnemonic="LENUM", name="Logical Enumerated (multistate)", default_enum=-21},
  [22] = {mnemonic="LFMSSL", name="Logical Fast/Medium/Slow/Stop Latched", default_enum=nil},
  [23] = {mnemonic="LFMSSP", name="Logical Fast/Medium/Slow/Stop Pulsed", default_enum=nil},
  [24] = {mnemonic="PPCL_LAI", name="PPCL-referenced analog input", default_enum=nil},
}

-- A point type's default state-text set is the enum whose id is the
-- negation of its type code. Resolve an explicit reference first; fall
-- back to the default when the point carries none.
function p2data.default_enum_for(point_type)
  local t = p2data.point_types[point_type]
  return t and t.default_enum or nil
end

-- Render an enumerated point value as text, or nil.
-- A point may carry an explicit enum reference; when it does not, its type's
-- DEFAULT enumeration applies -- the enum whose id is the negation of the
-- type code.  Analog types have no default and correctly return nil.
function p2data.state_text(value, point_type, enum_id)
  local eid = enum_id or p2data.default_enum_for(point_type)
  if not eid then return nil end
  local t = p2data.enum_types[eid]
  if not t then return nil end
  return t.levels[math.floor(tonumber(value or 0) + 0.5)]
end
-- ==== P2_DATA END =========================================================

local P2_DISSECTOR_VERSION = "2.6"

local p2 = Proto("p2", "Siemens APOGEE P2 (Protocol II)")

-- seq-state: responses carry no opcode, only an echoed sequence number. Map
-- {tcp.stream : sequence} -> request opcode so responses can be correlated + decoded.
local f_tcp_stream = Field.new("tcp.stream")
local resp_op = {}

------------------------------------------------------------------------ value strings
-- Message classes are legacy/modern PAIRS chosen by the panel's firmware generation
-- (fingerprint via CABINET_DISPLAY 0x010C), NOT by direction:
--   data channel:    0x33 legacy / 0x34 modern  (same opcodes + same f32 encoding)
--   2nd channel:     0x2E legacy / 0x2F modern  (identity + DB-change/replication records + alarm prints)
--   peer (mirror-only): 0x29 maintenance / 0x2A panel<->panel COV-subscribe
local MSG_CLASS = {
  [0x33]="data (legacy panel)", [0x34]="data (modern panel)",
  -- Labels follow PROTOCOL.md §6.2. 0x29 is the low-volume session carrier seen
  -- only at connection start at low sequence numbers; 0x2A is the peer-to-peer
  -- (panel<->panel) session carrier. Both carry the EBLN_PING 0x4640 identity
  -- exchange. Earlier labels ("maintenance" / "COV-subscribe") asserted a
  -- function the corpus does not establish.
  [0x29]="session carrier", [0x2A]="peer-session carrier (panel<->panel)",
  [0x2E]="2nd channel (legacy: announce/DB-sync)", [0x2F]="2nd channel (modern: announce/DB-sync)",
}
local DIR = { [0x00]="request / push", [0x01]="success response", [0x05]="error response" }
local ERRORS = {
  [0x0001]="no_memory_available",
  [0x0002]="invalid_command",
  [0x0003]="not_found",
  [0x0004]="priority_too_low",
  [0x0005]="no_change",
  [0x0007]="point_failed",
  [0x0008]="out_of_service",
  [0x0009]="already_exists",
  [0x000A]="trend_already_exists",
  [0x000B]="value_unchanged",
  [0x000C]="value_out_of_range",
  [0x000D]="not_hostcaller_node",
  [0x0016]="line_not_traced",
  [0x0028]="invalid_dst_pair",
  [0x0040]="invalid_report_id",
  [0x0065]="command_not_supported",
  [0x0080]="invalid_user_id",
  [0x0081]="invalid_password",
  [0x0082]="user_accounts_database_full",
  [0x00AB]="coldstart_required",
  [0x00AC]="not_supported",
  [0x00B7]="too_many_framing_errors",
  [0x00B8]="scu_no_answer",
  [0x00F9]="invalid_point_address",
  [0x00FA]="failed_io_device",
  [0x00FE]="io_timeout",
  [0x0200]="monitor_list_full",
  [0x0202]="flt_transfer_in_progress",
  [0x0203]="flt_transfer_killed",
  [0x0205]="tec_not_added",
  [0x0206]="connection_lost",
  [0x0207]="warm_started",
  [0x0209]="protocol_error",
  [0x0210]="timeout",
  [0x0E10]="fln_invalid_fln_number",
  [0x0E11]="fln_invalid_drop_number",
  [0x0E12]="fln_device_failed",
  [0x0E13]="fln_invalid_point_number",
  [0x0E14]="fln_physical_point_failed",
  [0x0E15]="physical_point_not_commandable",
  [0x0E16]="fln_value_out_of_range",
  [0x0E17]="fln_application_invalid_for_device",
}
local PRIORITY = {
  [0x00]="NONE (read)", [0x01]="tec_ovrd", [0x05]="PDL", [0x0A]="host_2",
  [0x0F]="host_3", [0x14]="host_4", [0x19]="host_5", [0x1E]="host_6",
  [0x20]="EMER", [0x22]="SMOKE", [0x23]="OPER",
}
local OPCODES = {
  [0x0030] = "AP2_SET_GLOBAL_DATA",
  [0x0031] = "AP2_GET_GLOBAL_DATA",
  [0x0032] = "AP2_REMOTE_NODE_CHECK",
  [0x0033] = "AP2_GET_COMPLETE_NODE_STATE",
  [0x0034] = "AP2_SET_NODE_STATE",
  [0x0035] = "AP2_SET_COMPLETE_NODE_STATE",
  [0x003E] = "AP2_CABINET_TIMEOUT_NORMAL",
  [0x003F] = "AP2_CABINET_TIMEOUT_EXTENDED",
  [0x0041] = "AP2_CABINET_ADD",
  [0x0042] = "AP2_CABINET_REMOVE",
  [0x0044] = "AP2_CABINET_MAKE_READY",
  [0x0046] = "AP2_CABINET_ONLINE",
  [0x0047] = "AP2_CABINET_OFFLINE",
  [0x0050] = "AP2_DISK_LOG",
  [0x0051] = "AP2_DISK_ADD",
  [0x0058] = "AP2_REPORT_PRINTER_LOG",
  [0x0059] = "AP2_REPORT_PRINTER_ADD",
  [0x005B] = "AP2_BLN_DIAGNOSTICS_DISPLAY",
  [0x005C] = "AP2_RESET_BLN_DIAGNOSTIC_COUNTERS",
  [0x0100] = "AP2_DUMMY_CMD / AP2_REV_STRING",
  [0x0108] = "AP2_CABINET_BOOT_MONITOR",
  [0x010A] = "AP2_CABINET_COLDSTART",
  [0x010B] = "AP2_CABINET_WARMSTART",
  [0x010C] = "AP2_CABINET_DISPLAY",
  [0x010D] = "AP2_SERVICES_RENDERED",
  [0x010E] = "AP2_SERVICES_RENDERED_CHANGED",
  [0x010F] = "AP2_LICENSE_MANAGER_DISPLAY",
  [0x0110] = "AP2_LICENSE_MANAGER_ADD",
  [0x0111] = "AP2_LICENSE_MANAGER_DELETE",
  [0x0112] = "AP2_LICENSE_MANAGER_DELETE_ALL",
  [0x0113] = "AP2_LICENSE_MANAGER_DBCHANGE",
  [0x0114] = "AP2_LICENSE_MANAGER_DISPLAY_LICENSE",
  [0x0116] = "AP2_LICENSE_MANAGER_MESSAGE_SEND",
  [0x0120] = "AP2_CABINET_SET_MMI1_BAUDRATE",
  [0x0121] = "AP2_CABINET_SET_MMI2_BAUDRATE",
  [0x0123] = "AP2_CABINET_SET_FLN1_BAUDRATE",
  [0x0124] = "AP2_CABINET_SET_FLN2_BAUDRATE",
  [0x0125] = "AP2_CABINET_SET_FLN3_BAUDRATE",
  [0x0126] = "AP2_CABINET_SET_BLN_BAUDRATE",
  [0x0127] = "AP2_CABINET_SET_PBUS_STATE",
  [0x0128] = "AP2_CABINET_SET_BLN_ADDRESS",
  [0x0129] = "AP2_CABINET_SET_MODEM_STATE",
  [0x012A] = "AP2_CABINET_COLDSTART_DISPLAY",
  [0x012B] = "AP2_CABINET_COLDSTART_CLEAR_HISTORY",
  [0x012F] = "AP2_CABINET_MEMORY_MODIFY",
  [0x0130] = "AP2_CABINET_MEMORY_DISPLAY",
  [0x0131] = "AP2_CABINET_MEMORY_AVAILABLE",
  [0x0136] = "AP2_P2_ROUTE",
  [0x0140] = "AP2_PBUS_MODULE_DISPLAY",
  [0x0142] = "AP2_PBUS_DIAGS_RESET",
  [0x0143] = "AP2_PBUS_LINETEST",
  [0x0200] = "AP2_POINT_ADD",
  [0x0201] = "AP2_POINT_ADD_LDO",
  [0x0202] = "AP2_POINT_ADD_LDI",
  [0x0203] = "AP2_POINT_ADD_LAO",
  [0x0204] = "AP2_POINT_ADD_LAI",
  [0x0205] = "AP2_POINT_ADD_L2SL",
  [0x0206] = "AP2_POINT_ADD_L2SP",
  [0x0207] = "AP2_POINT_ADD_LFSSL",
  [0x0208] = "AP2_POINT_ADD_LFSSP",
  [0x0209] = "AP2_POINT_ADD_LOOAL",
  [0x020A] = "AP2_POINT_ADD_LOOAP",
  [0x020B] = "AP2_POINT_ADD_LPACI",
  [0x020C] = "AP2_POINT_ADD_LDAO",
  [0x020D] = "AP2_POINT_ADD_LFMSSL",
  [0x020E] = "AP2_POINT_ADD_LFMSSP",
  [0x020F] = "AP2_POINT_ADD_LENUM",
  [0x0220] = "AP2_POINT_LOG_VALUE",
  [0x0221] = "AP2_POINT_LOG_ALARM",
  [0x0222] = "AP2_POINT_LOG_CTRL_STAT",
  [0x0223] = "AP2_POINT_LOG_FAILED",
  [0x0224] = "AP2_POINT_LOG_TOTAL",
  [0x0225] = "AP2_POINT_LOG_PRIORITY",
  [0x0226] = "AP2_POINT_LOG_DISABLED",
  [0x0227] = "AP2_POINT_LOG_TYPE",
  [0x0228] = "AP2_POINT_LOG_TROUBLE",
  [0x0229] = "AP2_POINT_LOG_ANY",
  [0x022A] = "AP2_POINT_LOG_ODSB",
  [0x022B] = "AP2_POINT_LOG_PDSB",
  [0x022C] = "AP2_POINT_LOG_ALARM_CMD",
  [0x0240] = "AP2_POINT_CMD_VALUE",
  [0x0241] = "AP2_POINT_CMD_PRIORITY",
  [0x0242] = "AP2_POINT_CMD_ENABLE",
  [0x0243] = "AP2_POINT_CMD_DISABLE",
  [0x0244] = "AP2_POINT_CMD_ALARM",
  [0x0245] = "AP2_POINT_CMD_NORMAL",
  [0x0246] = "AP2_POINT_CMD_ALARM_ENABLE",
  [0x0247] = "AP2_POINT_CMD_ALARM_DISABLE",
  [0x0248] = "AP2_POINT_CMD_INIT_LPACI",
  [0x0249] = "AP2_POINT_CMD_LOWLIMIT",
  [0x024A] = "AP2_POINT_CMD_HIGHLIMIT",
  [0x024B] = "AP2_POINT_CMD_TOTALIZER",
  [0x024C] = "AP2_POINT_CMD_INTO_TROUBLE",
  [0x024D] = "AP2_POINT_CMD_OUTOF_TROUBLE",
  [0x024E] = "AP2_POINT_CMD_RELEASE",
  [0x0260] = "AP2_POINT_MODIFY",
  [0x0261] = "AP2_POINT_LOOK",
  [0x0262] = "AP2_POINT_DEFINITION_DISPLAY",
  [0x0263] = "AP2_POINT_REMOVE",
  [0x0264] = "AP2_POINT_DEFINITION_BYADDR_DISPLAY",
  [0x0265] = "AP2_POINT_QUERY_NAME",
  [0x0271] = "AP2_COV_ENABLE",
  [0x0272] = "AP2_COV_DELETE_STUB",
  [0x0273] = "AP2_COV_DISABLE",
  [0x0274] = "AP2_COV_ANNUNCIATE",
  [0x0275] = "AP2_XREF_COV_DISPLAY",
  [0x0280] = "AP2_MONITOR_ADD_NAME",
  [0x0281] = "AP2_MONITOR_REMOVE_NAME",
  [0x0282] = "AP2_MONITOR_START",
  [0x0290] = "AP2_TREND_SETUP_ADD",
  [0x0291] = "AP2_TREND_SETUP_DELETE",
  [0x0292] = "AP2_TREND_ENABLE",
  [0x0293] = "AP2_TREND_DISABLE",
  [0x0294] = "AP2_TREND_SETUP_LOG",
  [0x0295] = "AP2_TREND_DATA_DISPLAY",
  [0x0296] = "AP2_TREND_DEFINITION_DISPLAY",
  [0x0297] = "AP2_TREND_MULTIPOINT_DISPLAY",
  [0x0298] = "AP2_TREND_SETUP_MODIFY",
  [0x0299] = "AP2_TREND_MODIFY",
  [0x029A] = "AP2_TREND_SETUP_COPY",
  [0x029B] = "AP2_TREND_COPY",
  [0x029C] = "AP2_TREND_LOOK",
  [0x029D] = "AP2_TREND_QUERY_SINGLE_NAME",
  [0x029E] = "AP2_TREND_QUERY_NAMES",
  [0x029F] = "AP2_TREND_QUERY_TRENDS",
  [0x02A0] = "AP2_TREND_ARC_SETUP",
  [0x02A1] = "AP2_TREND_ARC_DATA_UPLOAD",
  [0x02A2] = "AP2_TREND_ARC_UPLOAD_ME",
  [0x02A5] = "AP2_TREND_EVENT_SETUP_ADD",
  [0x02A6] = "AP2_TREND_EVENT_MODIFY",
  [0x02A7] = "AP2_TREND_EVENT_COPY",
  [0x02A8] = "AP2_TREND_EVENT_ARC_SETUP",
  [0x02A9] = "AP2_TREND_EVENT_ARC_ENABLE",
  [0x02E0] = "AP2_POINT_TOTAL_ENABLE",
  [0x02E1] = "AP2_POINT_TOTAL_DISABLE",
  [0x02E2] = "AP2_POINT_TOTAL_DISPLAY",
  [0x0300] = "AP2_POINT_SET_PREFIX",
  [0x0301] = "AP2_TIME_DISPLAY / AP2_TIME_SOFTWARE",
  [0x0302] = "AP2_TIME_DISPLAY_CLOCK / AP2_TIME_SET",
  [0x0303] = "AP2_MESSAGE_SEND / AP2_MESSAGE",
  [0x0304] = "AP2_LOGON_CEC",
  [0x0305] = "AP2_LOGOFF_CEC",
  [0x0306] = "AP2_QUICK_KEYS",
  [0x0307] = "AP2_LOAD_DATABASE",
  [0x0308] = "AP2_SAVE_DATABASE",
  [0x0309] = "AP2_POINT_SAVE",
  [0x030A] = "AP2_PPCL_SAVE",
  [0x030B] = "AP2_TAPE_TRAILER",
  [0x030C] = "AP2_TOGGLE_DEVELOPMENT",
  [0x030D] = "AP2_COLBAS_TEST",
  [0x030E] = "AP2_ROUTE_OBJECT",
  [0x030F] = "AP2_P1_POLL",
  [0x0310] = "AP2_PB_POLL",
  [0x0311] = "AP2_PRINT_ERROR",
  [0x0313] = "AP2_P1_ROUTE",
  [0x0314] = "AP2_P1_LINETEST",
  [0x0316] = "AP2_OPEN_ENVELOPE",
  [0x0317] = "AP2_P1_RESET_COUNTERS",
  [0x031B] = "AP2_ENVELOPE_OPEN_DEST",
  [0x031C] = "AP2_ENVELOPE_CLOSE_DEST",
  [0x031D] = "AP2_ENVELOPE_OPEN_TEXT",
  [0x031E] = "AP2_ENVELOPE_CLOSE_TEXT",
  [0x031F] = "AP2_ENVELOPE_OPEN_USERS",
  [0x0320] = "AP2_ENVELOPE_CLOSE_USERS",
  [0x0325] = "AP2_SETUP_LOGGER",
  [0x0326] = "AP2_GET_LOGGER_STATE",
  [0x0327] = "AP2_SETUP_BUFFERALARM",
  [0x0328] = "AP2_GET_BUFFERALARM_STATE",
  [0x0330] = "AP2_USER_ACCT_LOG",
  [0x0331] = "AP2_USER_ACCT_DISPLAY",
  [0x0332] = "AP2_USER_ACCT_ADD",
  [0x0333] = "AP2_USER_ACCT_MODIFY",
  [0x0334] = "AP2_USER_ACCT_COPY",
  [0x0335] = "AP2_USER_ACCT_DELETE",
  [0x0336] = "AP2_USER_ACCT_LOOK",
  [0x0337] = "AP2_USER_ACCT_DB_GET",
  [0x0338] = "AP2_USER_ACCT_DB_REPLACE",
  [0x0350] = "AP2_ACCESS_GROUPS_LOG",
  [0x0353] = "AP2_ACCESS_GROUPS_MODIFY",
  [0x0357] = "AP2_ACCESS_GROUPS_DB_GET",
  [0x0358] = "AP2_ACCESS_GROUPS_DB_REPLACE",
  [0x0360] = "AP2_EMS_DIAL_ENABLE",
  [0x0361] = "AP2_EMS_DIAL_DISABLE",
  [0x0362] = "AP2_EMS_DB_REPLACE",
  [0x0363] = "AP2_EMS_DB_GET",
  [0x0364] = "AP2_EMS_DB_DISPLAY",
  [0x0365] = "AP2_EMS_ENTRY_REPLACE",
  [0x0366] = "AP2_EMS_DB_GET_DIALFLAGS",
  [0x0367] = "AP2_EMS_DB_GET_DESTINATIONS",
  [0x0368] = "AP2_EMS_PRINT",
  [0x0401] = "AP2_ENUM_TYPE_ADD",
  [0x0402] = "AP2_ENUM_TYPE_DELETE",
  [0x0403] = "AP2_ENUM_TYPE_DB_DELETE",
  [0x0404] = "AP2_ENUM_TYPE_DISPLAY",
  [0x0405] = "AP2_ENUM_TYPE_LOOK",
  [0x0406] = "AP2_ENUM_TYPE_LOG",
  [0x0407] = "AP2_ENUM_ELEMENT_ADD",
  [0x0408] = "AP2_ENUM_ELEMENT_DELETE",
  [0x0409] = "AP2_ENUM_ELEMENT_MODIFY",
  [0x040A] = "AP2_ENUM_TYPE_DB_GET",
  [0x040B] = "AP2_ENUM_TYPE_DB_REPLACE",
  [0x040E] = "AP2_ENUM_TYPE_REPLACE",
  [0x0500] = "AP2_ALARM_SETUP",
  [0x0501] = "AP2_ALARM_REMOVE",
  [0x0502] = "AP2_ALARM_POINT_QUERY_LIST_EALARMABLE",
  [0x0503] = "AP2_ALARM_POINT_QUERY_REC_EALARMABLE",
  [0x0504] = "AP2_ALARM_POINT_SETUP_QUERY_LIST",
  [0x0505] = "AP2_ALARM_POINT_SETUP_QUERY_RECORD",
  [0x0506] = "AP2_ALARM_SETUP_COPY",
  [0x0507] = "AP2_ALARM_SETUP_MODIFY",
  [0x0508] = "AP2_ALARM_PRINT",
  [0x0509] = "AP2_ALARM_ACK",
  [0x050A] = "AP2_ALARM_ACK_PENDING_QUERY_LIST",
  [0x050B] = "AP2_ALARM_SETUP_DISPLAY_BY_MODE",
  [0x050C] = "AP2_ALARM_SETUP_DISPLAY_BY_CATEGORY",
  [0x050D] = "AP2_ALARM_SETUP_DISPLAY",
  [0x0520] = "AP2_ALARM_MODE_ADD",
  [0x0521] = "AP2_ALARM_MODE_COPY",
  [0x0522] = "AP2_ALARM_MODE_LISTBY_SETPOINT_NAME",
  [0x0523] = "AP2_ALARM_MODE_LISTBY_PRIORITY",
  [0x0524] = "AP2_ALARM_MODE_LISTBY_SETPOINT_VALUE",
  [0x0525] = "AP2_ALARM_MODE_DEFINITION_DISPLAY",
  [0x0526] = "AP2_ALARM_MODE_LOOK",
  [0x0528] = "AP2_ALARM_MODE_MODIFY",
  [0x0529] = "AP2_ALARM_MODE_QUERY_RECORD",
  [0x052B] = "AP2_ALARM_MODE_DELETE",
  [0x052C] = "AP2_ALARM_MODE_LISTBY_CATEGORY",
  [0x052D] = "AP2_ALARM_MODE_LISTBY_MESSAGE",
  [0x0530] = "AP2_ALARM_MODE_QUERY_LIST",
  [0x0540] = "AP2_CATEGORY_ADD",
  [0x0541] = "AP2_CATEGORY_REMOVE",
  [0x0542] = "AP2_CATEGORY_DESCRIPTOR",
  [0x0543] = "AP2_CATEGORY_ENABLE_DIAL",
  [0x0544] = "AP2_CATEGORY_ENABLE_PRINT",
  [0x0545] = "AP2_CATEGORY_DIAL_DISABLE",
  [0x0546] = "AP2_CATEGORY_PRINT_DISABLE",
  [0x0547] = "AP2_CATEGORY_DB_GET",
  [0x0548] = "AP2_CATEGORY_LOG",
  [0x0549] = "AP2_CATEGORY_NODES_APPEND",
  [0x054A] = "AP2_CATEGORY_NODES_REMOVE",
  [0x054B] = "AP2_CATEGORY_QUERY_LIST",
  [0x054C] = "AP2_CATEGORY_DEFAULT_DB_GET",
  [0x054D] = "AP2_CATEGORY_REPLACE",
  [0x0560] = "AP2_ALARM_MESSAGE_LOOK",
  [0x0561] = "AP2_ALARM_MESSAGE_ENABLE",
  [0x0562] = "AP2_ALARM_MESSAGE_DISABLE",
  [0x0563] = "AP2_ALARM_MESSAGE_DELETE",
  [0x0564] = "AP2_ALARM_MESSAGE_COPY",
  [0x0565] = "AP2_ALARM_MESSAGE_ADD",
  [0x0566] = "AP2_ALARM_MESSAGE_QUERY_RECORD",
  [0x0567] = "AP2_ALARM_MESSAGE_LOG",
  [0x0568] = "AP2_ALARM_MESSAGE_QUERY_LIST",
  [0x056A] = "AP2_ALARM_MESSAGE_MODIFY",
  [0x0600] = "AP2_CAL_DATE_ADD",
  [0x0601] = "AP2_CAL_DATE_RESET",
  [0x0602] = "AP2_CAL_DB_ADD",
  [0x0603] = "AP2_CAL_DB_RESET",
  [0x0604] = "AP2_CAL_DB_DISPLAY",
  [0x0605] = "AP2_CAL_DB_GET_HOL_SPEC",
  [0x0606] = "AP2_CAL_DB_GET_OTHER",
  [0x0610] = "AP2_DST_YEAR_ADD",
  [0x0611] = "AP2_DST_YEAR_DELETE",
  [0x0612] = "AP2_DST_DB_ADD",
  [0x0613] = "AP2_DST_DB_DELETE",
  [0x0614] = "AP2_DST_DB_DISPLAY",
  [0x0615] = "AP2_DST_DB_GET",
  [0x0900] = "AP2_LANGUAGE_GET_STRING",
  [0x0901] = "AP2_LANGUAGE_GET_PROMPT",
  [0x0902] = "AP2_LANGUAGE_REPORT_DATA",
  [0x0950] = "AP2_DOWNLOAD_ME",
  [0x0951] = "AP2_DBCHANGE_POINT",
  [0x0952] = "AP2_DBCHANGE_ALARM_SETUP",
  [0x0953] = "AP2_DBCHANGE_ALARM_MODE",
  [0x0954] = "AP2_DBCHANGE_TREND",
  [0x0955] = "AP2_DBCHANGE_PPCL",
  [0x0956] = "AP2_DBCHANGE_CONTROLLER",
  [0x0957] = "AP2_DBCHANGE_EQS_ZONE",
  [0x0958] = "AP2_DBCHANGE_EQS_CMD_TABLE",
  [0x0959] = "AP2_DBCHANGE_EQS_MODE_SCHED",
  [0x095A] = "AP2_DBCHANGE_LOOP",
  [0x095B] = "AP2_DBCHANGE_ALARM_MESSAGE",
  [0x095C] = "AP2_DBCHANGE_SSTO_GENERAL",
  [0x095D] = "AP2_DBCHANGE_SSTO_START",
  [0x095E] = "AP2_DBCHANGE_SSTO_STOP",
  [0x095F] = "AP2_DBCHANGE_SSTO_NIGHT",
  [0x0961] = "AP2_UPL_DEL_POINT",
  [0x0962] = "AP2_UPL_DEL_ALARM_SETUP",
  [0x0963] = "AP2_UPL_DEL_ALARM_MODE",
  [0x0964] = "AP2_UPL_DEL_TREND",
  [0x0965] = "AP2_UPL_DEL_PPCL",
  [0x0966] = "AP2_UPL_DEL_TEC",
  [0x0967] = "AP2_UPL_DEL_EQS_ZONE",
  [0x0968] = "AP2_UPL_DEL_EQS_CMD_TABLE",
  [0x0969] = "AP2_UPL_DEL_EQS_MODE_SCHED",
  [0x096A] = "AP2_UPL_DEL_LOOP",
  [0x096B] = "AP2_UPL_DEL_ALARM_MESSAGE",
  [0x0971] = "AP2_UPL_ADDED_POINT",
  [0x0972] = "AP2_UPL_ADDED_ALARM_SETUP",
  [0x0973] = "AP2_UPL_ADDED_ALARM_MODE",
  [0x0974] = "AP2_UPL_ADDED_TREND",
  [0x0975] = "AP2_UPL_ADDED_PPCL",
  [0x0976] = "AP2_UPL_ADDED_TEC",
  [0x0977] = "AP2_UPL_ADDED_EQS_ZONE",
  [0x0978] = "AP2_UPL_ADDED_EQS_CMD_TABLE",
  [0x0979] = "AP2_UPL_ADDED_EQS_MODE_SCHED",
  [0x097A] = "AP2_UPL_ADDED_LOOP",
  [0x097B] = "AP2_UPL_ADDED_ALARM_MESSAGE",
  [0x097C] = "AP2_UPL_ADDED_SSTO_GENERAL",
  [0x097D] = "AP2_UPL_ADDED_SSTO_START",
  [0x097E] = "AP2_UPL_ADDED_SSTO_STOP",
  [0x097F] = "AP2_UPL_ADDED_SSTO_NIGHT",
  [0x0981] = "AP2_UPL_ALL_POINT",
  [0x0982] = "AP2_UPL_ALL_ALARM_SETUP",
  [0x0983] = "AP2_UPL_ALL_ALARM_MODE",
  [0x0984] = "AP2_UPL_ALL_TREND",
  [0x0985] = "AP2_UPL_ALL_PPCL",
  [0x0986] = "AP2_UPL_ALL_TEC",
  [0x0987] = "AP2_UPL_ALL_EQS_ZONE",
  [0x0988] = "AP2_UPL_ALL_EQS_CMD_TABLE",
  [0x0989] = "AP2_UPL_ALL_EQS_MODE_SCHED",
  [0x098B] = "AP2_UPL_ALL_ALARM_MESSAGE",
  [0x098C] = "AP2_UPL_ALL_SSTO_GENERAL",
  [0x098D] = "AP2_UPL_ALL_SSTO_START",
  [0x098E] = "AP2_UPL_ALL_SSTO_STOP",
  [0x098F] = "AP2_UPL_ALL_SSTO_NIGHT",
  [0x099C] = "AP2_DBCHANGE_PORT",
  [0x099D] = "AP2_UPL_DEL_PORT",
  [0x099E] = "AP2_UPL_ADDED_PORT",
  [0x099F] = "AP2_UPL_ALL_PORT",
  [0x09A0] = "AP2_DBCHANGE_PARTNER",
  [0x09A1] = "AP2_UPL_DEL_PARTNER",
  [0x09A2] = "AP2_UPL_ADDED_PARTNER",
  [0x09A3] = "AP2_UPL_ALL_PARTNER",
  [0x09A4] = "AP2_DBCHANGE_EQS_OVERRIDE",
  [0x09A5] = "AP2_UPL_DEL_EQS_OVERRIDE",
  [0x09A6] = "AP2_UPL_ADDED_EQS_OVERRIDE",
  [0x09A7] = "AP2_UPL_ALL_EQS_OVERRIDE",
  [0x09A8] = "AP2_DBCHANGE_UC",
  [0x09A9] = "AP2_UPL_DEL_UC",
  [0x09AA] = "AP2_UPL_ADDED_UC",
  [0x09AB] = "AP2_UPL_ALL_UC",
  [0x09B0] = "AP2_DBCHANGE_TOD_POINT",
  [0x09B1] = "AP2_UPL_DEL_TOD_POINT",
  [0x09B2] = "AP2_UPL_ADDED_TOD_POINT",
  [0x09B3] = "AP2_UPL_ALL_TOD_POINT",
  [0x09B4] = "AP2_DBCHANGE_TOD_CMD",
  [0x09B5] = "AP2_UPL_DEL_TOD_CMD",
  [0x09B6] = "AP2_UPL_ADDED_TOD_CMD",
  [0x09B7] = "AP2_UPL_ALL_TOD_CMD",
  [0x09B8] = "AP2_DBCHANGE_LON",
  [0x09B9] = "AP2_UPL_DEL_LON",
  [0x09BA] = "AP2_UPL_ADDED_LON",
  [0x09BB] = "AP2_UPL_ALL_LON",
  [0x09BC] = "AP2_DBCHANGE_COMMAND_REPORT",
  [0x09BD] = "AP2_UPLD_COMND_REPORT",
  [0x09BE] = "AP2_DBCHANGE_MISCDATA_REPORT",
  [0x09BF] = "AP2_UPLD_MISCDATA_REPORT",
  [0x09C0] = "AP2_DBCHANGE_MSTP_DEVICE",
  [0x09C1] = "AP2_UPL_DEL_MSTP_DEVICE",
  [0x09C2] = "AP2_UPL_ADDED_MSTP_DEVICE",
  [0x09C3] = "AP2_UPL_ALL_MSTP_DEVICE",
  [0x2824] = "AP2_RACS_SYSTEM_DISPLAY",
  [0x3800] = "AP2_RACS_PARTNER_ADD",
  [0x3801] = "AP2_RACS_PARTNER_COPY",
  [0x3802] = "AP2_RACS_PARTNER_DELETE",
  [0x3803] = "AP2_RACS_PARTNER_DISABLE",
  [0x3804] = "AP2_RACS_PARTNER_DISPLAY",
  [0x3805] = "AP2_RACS_PARTNER_ENABLE",
  [0x3806] = "AP2_RACS_PARTNER_LOG",
  [0x3807] = "AP2_RACS_PARTNER_LOOK",
  [0x3808] = "AP2_RACS_PARTNER_MODIFY",
  [0x3809] = "AP2_RACS_PARTNER_STATLOG",
  [0x380A] = "AP2_RACS_PARTNER_STATLOG_RESET",
  [0x3810] = "AP2_RACS_PORT_ADD",
  [0x3811] = "AP2_RACS_PORT_COPY",
  [0x3812] = "AP2_RACS_PORT_DELETE",
  [0x3813] = "AP2_RACS_PORT_DISABLE",
  [0x3814] = "AP2_RACS_PORT_DISPLAY",
  [0x3815] = "AP2_RACS_PORT_ENABLE",
  [0x3816] = "AP2_RACS_PORT_LOG",
  [0x3817] = "AP2_RACS_PORT_LOOK",
  [0x3818] = "AP2_RACS_PORT_MODIFY",
  [0x3819] = "AP2_RACS_PORT_STATLOG",
  [0x381A] = "AP2_RACS_PORT_STATLOG_RESET",
  [0x3820] = "AP2_RACS_SYSTEM_ADD",
  [0x3821] = "AP2_RACS_SYSTEM_COPY",
  [0x3822] = "AP2_RACS_SYSTEM_DELETE",
  [0x3823] = "AP2_RACS_SYSTEM_DISABLE",
  [0x3825] = "AP2_RACS_SYSTEM_ENABLE",
  [0x3826] = "AP2_RACS_SYSTEM_LOG",
  [0x3827] = "AP2_RACS_SYSTEM_LOOK",
  [0x3828] = "AP2_RACS_SYSTEM_MODIFY",
  [0x3829] = "AP2_RACS_SYSTEM_STATLOG",
  [0x382A] = "AP2_RACS_SYSTEM_STATLOG_RESET",
  [0x4000] = "AP2_TEAM_LOG / AP2_APPLICATION_LOG",
  [0x4001] = "AP2_TEAM_DESC_ADD / AP2_APPLICATION_DISPLAY",
  [0x4002] = "AP2_MEMBER_DESC_ADD_ANALOG",
  [0x4003] = "AP2_MEMBER_DESC_ADD_DIGITAL",
  [0x4004] = "AP2_MEMBER_DESC_ADD_ENUM",
  [0x4005] = "AP2_MEMBER_DESC_ADD_LPACI",
  [0x4006] = "AP2_MEMBER_DESC_ADD_L2SL",
  [0x400B] = "AP2_TEAM_MEMBER_LOG",
  [0x400C] = "AP2_TEAM_REPORT_LOG",
  [0x400D] = "AP2_TEAM_REPORT_LIST",
  [0x400E] = "AP2_REPORT_DESC_ADD",
  [0x400F] = "AP2_TEAM_DESC_UPLOAD",
  [0x4010] = "AP2_MEMBER_DESC_UPLOAD",
  [0x4011] = "AP2_REPORT_DESC_UPLOAD",
  [0x4015] = "AP2_TEAM_DESC_DB_CHANGE",
  [0x4016] = "AP2_TEAM_MEMBER_DB_CHANGE",
  [0x4017] = "AP2_TEAM_DESC_UPLOAD_ADDED",
  [0x4018] = "AP2_TEAM_MEMBER_UPLOAD_ADDED",
  [0x4100] = "AP2_PPCL_ADD_LINE",
  [0x4101] = "AP2_PPCL_EDIT_LINE",
  [0x4103] = "AP2_PPCL_REMOVE_LINES",
  [0x4104] = "AP2_PPCL_ENABLE_LINES",
  [0x4105] = "AP2_PPCL_DISABLE_LINES",
  [0x4106] = "AP2_PPCL_CLEAR_TRACE",
  [0x4107] = "AP2_PPCL_PROGRAM_LOG",
  [0x4108] = "AP2_PPCL_SEARCH_NAME_TYPE",
  [0x4109] = "AP2_PPCL_QUERY_PROGRAM",
  [0x410A] = "AP2_PPCL_PROGRAM_DISPLAY",
  [0x410B] = "AP2_PPCL_MODIFY_LINE",
  [0x410C] = "AP2_PPCL_COPY_LINE",
  [0x410D] = "AP2_PPCL_SETUP_MODIFY_LINE",
  [0x410E] = "AP2_PPCL_LOOK_LINES",
  [0x410F] = "AP2_PPCL_PDL_RESET",
  [0x4110] = "AP2_PPCL_PDL_INIT",
  [0x4111] = "AP2_PPCL_PDL_DISPLAY",
  [0x412A] = "AP2_PPCL_PROGRAM_DISPLAY_UNRESOLVED",
  [0x4130] = "AP2_DBCHANGE_PROGRAM",
  [0x4131] = "AP2_UPL_DEL_PROGRAM",
  [0x4132] = "AP2_UPL_ADDED_PROGRAM",
  [0x4133] = "AP2_UPL_ALL_PROGRAM",
  [0x4134] = "AP2_PROGRAM_ADD",
  [0x4135] = "AP2_PROGRAM_REMOVE",
  [0x4137] = "AP2_PROGRAM_LOG",
  [0x4138] = "AP2_PROGRAM_MODIFY",
  [0x4200] = "AP2_CONTROLLER_LOG / AP2_TEC_LOG",
  [0x4201] = "AP2_TEC_ADD",
  [0x4202] = "AP2_TEC_COPY",
  [0x4203] = "AP2_TEC_MODIFY / AP2_CONTROLLER_MODIFY",
  [0x4204] = "AP2_CONTROLLER_REMOVE / AP2_TEC_REMOVE",
  [0x4205] = "AP2_TEC_LOOK / AP2_CONTROLLER_LOOK",
  [0x4206] = "AP2_TEC_QUERY_RECORD / AP2_CONTROLLER_QUERY",
  [0x4207] = "AP2_TEC_QUERY_LIST",
  [0x4208] = "AP2_TEC_DEFINITION",
  [0x4210] = "AP2_TEC_MEMBER_LOG",
  [0x4211] = "AP2_TEC_REPORT_LOG",
  [0x4212] = "AP2_TEC_REPORT_QUERY_LIST",
  [0x4220] = "AP2_TEC_LOCAL_INIT_VALUE_LOG",
  [0x4221] = "AP2_TEC_REMOTE_INIT_VALUE_LOG",
  [0x4222] = "AP2_TEC_SET_INIT_VALUE",
  [0x4223] = "AP2_TEC_RESTORE_INIT_VALUE",
  [0x4224] = "AP2_TEC_INITIALIZE",
  [0x4225] = "AP2_TEC_UPDATE_LOCAL_INIT_VALUES",
  [0x4230] = "AP2_FLN_SCAN_ENABLE",
  [0x4231] = "AP2_FLN_SCAN_DISABLE",
  [0x4232] = "AP2_P1_DIAGNOSTICS_LOG",
  [0x4241] = "AP2_UC_ADD",
  [0x4244] = "AP2_UC_REMOVE",
  [0x4245] = "AP2_UC_LOOK",
  [0x4249] = "AP2_UC_MEMBER_LOG",
  [0x4300] = "AP2_LON_LOG",
  [0x4301] = "AP2_LON_ADD",
  [0x4303] = "AP2_LON_MODIFY",
  [0x4304] = "AP2_LON_REMOVE",
  [0x4310] = "AP2_LON_MEMBER_LOG",
  [0x4311] = "AP2_LON_REPORT_LOG",
  [0x4320] = "AP2_LON_LOCAL_INIT_VALUE_LOG",
  [0x4321] = "AP2_LON_REMOTE_INIT_VALUE_LOG",
  [0x4322] = "AP2_LON_SET_INIT_VALUE",
  [0x4323] = "AP2_LON_RESTORE_INIT_VALUE",
  [0x4324] = "AP2_LON_INITIALIZE",
  [0x4325] = "AP2_LON_UPDATE_LOCAL_INIT_VALUES",
  [0x4332] = "AP2_LON_DIAGNOSTICS_LOG",
  [0x4401] = "AP2_LON_SEND_SERVICE_PIN",
  [0x4402] = "AP2_LON_GET_DOMAIN",
  [0x4403] = "AP2_LON_SET_DOMAIN",
  [0x4404] = "AP2_LON_REQUEST_WINK",
  [0x440B] = "AP2_LON_STATUS_CLEAR",
  [0x4450] = "AP2_LON_PKCMSAGTSRVDBEXPORT",
  [0x4451] = "AP2_LON_PKCMSAGTSRVDBIMPORT",
  [0x4452] = "AP2_LON_PEAK_DB_CLEAR",
  [0x4500] = "AP2_TOD_POINT_ADD",
  [0x4501] = "AP2_TOD_POINT_REMOVE",
  [0x4502] = "AP2_TOD_POINT_ENABLE",
  [0x4503] = "AP2_TOD_POINT_DISABLE",
  [0x4504] = "AP2_TOD_CMD_ADD",
  [0x4505] = "AP2_TOD_CMD_REMOVE",
  [0x4506] = "AP2_TOD_CMD_DISABLE",
  [0x450E] = "AP2_TOD_POINT_DISPLAY",
  [0x450F] = "AP2_TOD_CMD_DISPLAY",
  [0x461F] = "AP2_EBLN_FP_NAMES_DISPLAY",
  [0x4620] = "AP2_EBLN_FP_NAME_SET",

  -- EBLN management/replication set, 0x4620-0x4642.
  -- Names recovered from the command string pool of a shipped EBLN
  -- diagnostic binary, ordered by opcode; validated against five
  -- independently wire-established bindings (0x4640, 0x4636, 0x4634,
  -- 0x462E, 0x462D), which all agree on one base. Read/write kind is
  -- from the command name. 0x4633-0x4636 and 0x4640 are wire-observed;
  -- the rest have never been seen in captured traffic, so any
  -- occurrence is anomalous by construction (see PROTOCOL.md 17).
  [0x4623] = "AP2_EBLN_FP_DISPLAY",   -- read
  [0x4624] = "AP2_EBLN_STORAGE_NODES_REPLACE",   -- write
  [0x4625] = "AP2_EBLN_STORAGE_NODES_DISPLAY",   -- read
  [0x4626] = "AP2_EBLN_REPORT_PRINTER_REPLACE",   -- write
  [0x4627] = "AP2_EBLN_REPORT_PRINTER_DISPLAY",   -- read
  [0x4630] = "AP2_EBLN_NODE_ADD",   -- write
  [0x4631] = "AP2_EBLN_NODE_REMOVE",   -- write
  [0x4632] = "AP2_EBLN_NODE_LIST_DISPLAY",   -- read
  [0x4621] = "AP2_EBLN_FP_IP_CONFIGURE",
  [0x4622] = "AP2_EBLN_FP_TCP_PORTS_CONFIGURE",
  [0x4628] = "AP2_EBLN_TRUNK_SETTINGS_REPLACE",
  [0x4629] = "AP2_EBLN_TRUNK_SETTINGS_DISPLAY",
  [0x462A] = "AP2_EBLN_FP_SITE_NAME_SET",
  [0x462B] = "AP2_EBLN_FP_BLN_NAME_SET",
  [0x462C] = "AP2_EBLN_FP_MULTICAST_CONFIGURE",
  [0x462D] = "AP2_EBLN_HOSTTABLE_ENTRY_ADD",
  [0x462E] = "AP2_EBLN_HOSTTABLE_ENTRY_REMOVE",
  [0x462F] = "AP2_EBLN_HOSTTABLE_DISPLAY",
  [0x4633] = "AP2_EBLN_REPL_NOTIFY",
  [0x4634] = "AP2_EBLN_REPL_PULL",
  [0x4635] = "AP2_EBLN_REPL_PULL_MORE",
  [0x4636] = "AP2_EBLN_REPL_CHANGES",
  [0x4637] = "AP2_EBLN_POINT_LOCATION_GET",
  [0x4638] = "AP2_EBLN_MAC_ADDRESS_SET",
  [0x4639] = "AP2_EBLN_MII_CONFIGURE",
  [0x463A] = "AP2_EBLN_MII_DISPLAY",
  [0x463B] = "AP2_EBLN_IP_DISPLAY",
  [0x463C] = "AP2_EBLN_PORTS_DISPLAY",
  [0x463D] = "AP2_EBLN_MULTICAST_DISPLAY",
  [0x463E] = "AP2_EBLN_MAC_ADDRESS_DISPLAY",
  [0x4640] = "AP2_EBLN_PING",
  [0x4644] = "AP2_EBLN_TELNET_ENABLE",
  [0x4645] = "AP2_EBLN_TELNET_DISABLE",
  [0x464C] = "AP2_EBLN_REPL_DIAG_NODELIST",
  [0x465D] = "AP2_WEBSERVER_GET_STATE",
  [0x4821] = "AP2_BAC_DBCHANGE_BBMD",
  [0x4822] = "AP2_BAC_UPL_DEL_BBMD",
  [0x4823] = "AP2_BAC_UPL_ADDED_BBMD",
  [0x4824] = "AP2_BAC_UPL_ALL_BBMD",
  [0x4825] = "AP2_BAC_BBMD_ADD",
  [0x4826] = "AP2_BAC_BBMD_REMOVE",
  [0x4827] = "AP2_BAC_BBMD_DISPLAY",
  [0x4828] = "AP2_BAC_BBMD_REMOVE_ALL",
  [0x4829] = "AP2_BAC_OBJECT_ID_LOG",
  [0x482A] = "AP2_BAC_APPLICATION_PRIORITY_REPLACE",
  [0x482B] = "AP2_BAC_APPLICATION_PRIORITY_REMOVE",
  [0x482C] = "AP2_BAC_APPLICATION_PRIORITY_DISPLAY",
  [0x482E] = "AP2_BAC_DEVICE_NAME_REPLACE",
  [0x482F] = "AP2_BAC_DEVICE_NAME_REMOVE",
  [0x4830] = "AP2_BAC_DBCHANGE_COVTAB",
  [0x4831] = "AP2_BAC_UPL_DEL_COVTAB",
  [0x4832] = "AP2_BAC_UPL_ADDED_COVTAB",
  [0x4833] = "AP2_BAC_UPL_ALL_COVTAB",
  [0x4834] = "AP2_BAC_COVTAB_ADD",
  [0x4835] = "AP2_BAC_COVTAB_REMOVE",
  [0x4837] = "AP2_BAC_COVTAB_REMOVE_ALL",
  [0x4838] = "AP2_BAC_TREND_LOG_ADD",
  [0x4839] = "AP2_BAC_TREND_LOG_DELETE",
  [0x483A] = "AP2_BAC_TREND_LOG_MODIFY",
  [0x4842] = "AP2_BAC_TREND_LOG_LOG",
  [0x4843] = "AP2_BAC_TREND_DBCHANGE",
  [0x4844] = "AP2_BAC_TREND_UPL_DELETED",
  [0x4845] = "AP2_BAC_TREND_UPL_ADDED",
  [0x4846] = "AP2_BAC_TREND_UPL_ALL",
  [0x4877] = "AP2_BAC_DBCHANGE",
  [0x4878] = "AP2_BAC_UPLOAD_ADDED",
  [0x4879] = "AP2_BAC_UPLOAD_DELETED",
  [0x4960] = "AP2_BACNET_SET_MSTP",
  [0x4961] = "AP2_BACNET_SET_FLN_TYPE",
  [0x4963] = "AP2_BNMSTP_ADD",
  [0x4965] = "AP2_BNMSTP_MODIFY",
  [0x4966] = "AP2_BNMSTP_REMOVE",
  [0x4967] = "AP2_BNMSTP_LOOK",
  [0x496B] = "AP2_BNMSTP_MEMBER_LOG",
  [0x496E] = "AP2_BNMSTP_LOCAL_INIT_VALUE_LOG",
  [0x4970] = "AP2_BNMSTP_SET_INIT_VALUE",
  [0x4971] = "AP2_BNMSTP_RESTORE_INIT_VALUE",
  [0x4972] = "AP2_BNMSTP_INITIALIZE",
  [0x4973] = "AP2_BNMSTP_UPDATE_LOCAL_INIT_VALUES",
  [0x4A00] = "AP2_COLBAS_IMMEDIATE",
  [0x4A01] = "AP2_COLBAS_CONNECT",
  [0x4A02] = "AP2_COLBAS_DISCONNECT",
  [0x4A03] = "AP2_COLBAS_WRITE",
  [0x4A04] = "AP2_COLBAS_ABORT",
  [0x4A05] = "AP2_COLBAS_UPLOAD_BEGIN",
  [0x4A06] = "AP2_COLBAS_UPLOAD_CONTINUE",
  [0x4B01] = "AP2_BNEEO_ADD",
  [0x4B02] = "AP2_BNEEO_REMOVE",
  [0x4B03] = "AP2_BNEEO_LOOK",
  [0x5000] = "AP2_EQS_ZONE_ADD",
  [0x5001] = "AP2_EQS_ZONE_REMOVE",
  [0x5002] = "AP2_EQS_ZONE_MODIFY",
  [0x5003] = "AP2_EQS_ZONE_LOOK",
  [0x5004] = "AP2_EQS_ZONE_ENABLE",
  [0x5005] = "AP2_EQS_ZONE_DISABLE",
  [0x5018] = "AP2_EQS_CMD_TABLE_ENTRY_ADD",
  [0x5019] = "AP2_EQS_CMD_TABLE_ENTRY_MODIFY",
  [0x501A] = "AP2_EQS_CMD_TABLE_ENTRY_REMOVE",
  [0x501B] = "AP2_EQS_CMD_TABLE_ENTRY_LOOK",
  [0x5020] = "AP2_EQS_MODE_ENTRY_ADD",
  [0x5021] = "AP2_EQS_MODE_ENTRY_MODIFY",
  [0x5022] = "AP2_EQS_MODE_ENTRY_REMOVE",
  [0x5023] = "AP2_EQS_MODE_ENTRY_LOOK",
  [0x5024] = "AP2_EQS_MODE_ENTRY_ENABLE",
  [0x5025] = "AP2_EQS_MODE_ENTRY_DISABLE",
  [0x5028] = "AP2_EQS_OVERRIDE_ADD",
  [0x5029] = "AP2_EQS_OVERRIDE_MODIFY",
  [0x502A] = "AP2_EQS_OVERRIDE_REMOVE",
  [0x502B] = "AP2_EQS_OVERRIDE_LOOK",
  [0x5035] = "AP2_EQS_DISPLAY_ZONE",
  [0x5036] = "AP2_EQS_DISPLAY_MODE_ENTRY",
  [0x5037] = "AP2_EQS_DISPLAY_CMD_TABLE",
  [0x5038] = "AP2_EQS_ZONE_LOG",
  [0x5039] = "AP2_EQS_DISPLAY_OVERRIDES",
  [0x503A] = "AP2_EQS_SSTO_SETUP_GENERAL",
  [0x503B] = "AP2_EQS_SSTO_SETUP_START",
  [0x503C] = "AP2_EQS_SSTO_SETUP_STOP",
  [0x503D] = "AP2_EQS_SSTO_SETUP_NIGHT",
  [0x503E] = "AP2_EQS_SSTO_LOOK_GENERAL",
  [0x503F] = "AP2_EQS_SSTO_LOOK_START",
  [0x5040] = "AP2_EQS_SSTO_LOOK_STOP",
  [0x5041] = "AP2_EQS_SSTO_LOOK_NIGHT",
  [0x5042] = "AP2_EQS_SSTO_RESET",
  [0x5043] = "AP2_EQS_SSTO_ENABLE",
  [0x5044] = "AP2_EQS_SSTO_DISABLE",
  [0x5050] = "AP2_EQS_SSTO_DISPLAY_GENERAL",
  [0x5051] = "AP2_EQS_SSTO_DISPLAY_START",
  [0x5052] = "AP2_EQS_SSTO_DISPLAY_STOP",
  [0x5053] = "AP2_EQS_SSTO_DISPLAY_NIGHT",
  [0x5054] = "AP2_EQS_MEMBER_LOG",
  [0x5300] = "AP2_GLOBAL_IO_MODULE_DISPLAY",
  [0x5301] = "AP2_GET_FLN_TOPOLOGY",
  [0x5303] = "AP2_GLOBAL_IO_MODULE_DISPLAY_MEC_EXPBUS",
  [0x5304] = "AP2_GET_MEC_EXPBUS_TOPOLOGY",
  [0x5305] = "AP2_LOCAL_IO_MODULE_DISPLAY",
  [0x5330] = "AP2_BACKUP_FLASH_DBASE",
  [0x5331] = "AP2_RESTORE_FLASH_DBASE",
  [0x5332] = "AP2_CLEAR_FLASH_DBASE",
  [0x5351] = "AP2_HOA_MAP_MODIFY",
  [0x5354] = "AP2_HOA_MAP_LOOK",
  [0x5355] = "AP2_HOA_MAP_ADD",
  [0x5356] = "AP2_DBCHANGE_HOA_MAP",
  [0x700C] = "AP2_WS_APOGEEEDIT_GET_STATE",
}
-- Per-opcode expected body schema (struct-derived from the AP2 ASDU type set).
-- NOT a byte-level layout: it is the field list the request body SHOULD contain.
local OPSCHEMA = {
  [0x0032] = "ownNodeNr:u8, coldstarted:bool",
  [0x0034] = "node_changed:u8, node_table_event:Node_table_event, node_complete_state:Node_complete_state",
  [0x0035] = "nrOfnode_table:u16, node_table:Node_complete_state[]",
  [0x003E] = "change_node:u8",
  [0x003F] = "change_node:u8",
  [0x0041] = "new_node_address:u8, node_complete_state:Node_complete_state",
  [0x0042] = "removed_node_address:u8, cold_start_removed_node:bool, scu_rev_8_filler:u8",
  [0x0046] = "change_node:u8",
  [0x0047] = "change_node:u8",
  [0x005B] = "start_node:u16, end_node:u16, last_node:u16",
  [0x010F] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0110] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, license_text:str",
  [0x0111] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, app_name:str",
  [0x0112] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0113] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0114] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0116] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, message:str",
  [0x0120] = "baud_rate:Baud_rate",
  [0x0121] = "baud_rate:Baud_rate",
  [0x0123] = "baud_rate:Baud_rate",
  [0x0124] = "baud_rate:Baud_rate",
  [0x0125] = "baud_rate:Baud_rate",
  [0x0126] = "baud_rate:Baud_rate",
  [0x0127] = "pbus_enabled:bool",
  [0x0128] = "new_address:u16",
  [0x0129] = "modem_present:bool",
  [0x012A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x012F] = "start_address:u32, nrOfnew_bytes:u16, new_bytes:Bytes_to_write[]",
  [0x0130] = "start_address:u32, end_address:u32, last_address:u32",
  [0x0136] = "nrOfp2_bytes:u16, p2_bytes:P2_bytes[]",
  [0x0200] = "point:{tag_:u8,ldi:ldi_,ldo:ldo_,lai:lai_,lao:lao_,l2sl:l2sl_,looap:looap_,lpaci:lpaci_,l2sp:l2sp_,looal:looal_,lfssl:lfssl_,lfssp:lfssp_,ldao:ldao_,lenum:lenum_,lfmsl:lfmsl_,lfmsp:lfmsp_,ppcl_lai:ppcl_lai_}, lenum_address:{tag_:u8,not_present:-,present:present_}, user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, point_extension2:Point_extension2",
  [0x0201] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0202] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0203] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0204] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0205] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0206] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0207] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0208] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0209] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020A] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020B] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020C] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020D] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020E] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x020F] = "point_base:{point_type:Point_type,nrOfnames:u16,names:{name_space:Name_space,name:str,suffix:str}[],point_descriptor:Point_descriptor,access_class:Access_class,out_of_service:bool,failed:bool,control_status:Control_status,point_value:Point_value,point_priority:Point_priority,point_totalizer:{tag_:u8,disabled:-,enabled:enabled_},alarm_object:{tag_:u8,no_alarming:-,std_digital:std_digital_,std_single_analog:std_single_analog_,std_analog:std_analog_,enhanced_digital:enhanced_digital_,enhanced_analog:enhanced_analog_,enhanced_lenum:enhanced_lenum_,bacnet_alarm_analog:bacnet_alarm_analog_,bacnet...",
  [0x0220] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0221] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, alarm_level:Alarm_levels",
  [0x0222] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, control_status:Control_status",
  [0x0223] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0224] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0225] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, point_priority:Point_priority",
  [0x0226] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0227] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, point_type:Point_type",
  [0x0228] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0229] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x022A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x022B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x022C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0240] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, point_value:Point_value, point_priority:Point_priority",
  [0x0241] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, point_priority:Point_priority",
  [0x0242] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0243] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0244] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0245] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0246] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0247] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0248] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, point_value:Point_value, point_priority:Point_priority",
  [0x0249] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, low_alarm_limit:f32",
  [0x024A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, high_alarm_limit:f32",
  [0x024B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, reset_what:reset_what_",
  [0x024C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x024D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x024E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0261] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0262] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0263] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0264] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lan_choice:lan_choice_, drop_choice:drop_choice_, point_choice:point_choice_, bSubpoints:bool, last_lan:u8, last_drop:u8, last_point:u16, last_name:{name_space:Name_space,name:str,suffix:str}",
  [0x0265] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0271] = "name_response:{name_space:Name_space,name:str,suffix:str}, cov_mask:Cov_mask",
  [0x0272] = "name_response:{name_space:Name_space,name:str,suffix:str}",
  [0x0273] = "name_response:{name_space:Name_space,name:str,suffix:str}, cov_mask:Cov_mask",
  [0x0274] = "nrOfannunciate_request:u16, annunciate_request:{name_response:{name_space:Name_space,name:str,suffix:str},value:f32,point_priority:Point_priority,control_status:Control_status,out_of_service:bool,failed:bool,proof_on:bool,operator_disabled:bool,program_disabled:bool,commanded_to_alarm:bool,alarm_state:Alarm_state,alarm_priority:Alarm_priority}[]",
  [0x0275] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0280] = "name_response:{name_space:Name_space,name:str,suffix:str}",
  [0x0281] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0290] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, nrOftrend_setups:u16, trend_setups:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}[]",
  [0x0291] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, which_trend:which_trend_",
  [0x0292] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0293] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0294] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0295] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}, last_sequence_number:u32, last_date_time:datetime, max_samples:u16",
  [0x0299] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}, new_trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}",
  [0x029B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, nrOftrend_setups:u16, trend_setups:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}[]",
  [0x029C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x02A0] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, nrOftrend_setups:u16, trend_setups:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}[]",
  [0x02A1] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}, max_samples:u16",
  [0x02A5] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, nrOftrend_setups:u16, trend_setups:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}[], nrOftrend_event_setups:u16, trend_event_setups:{using_trend_archive:bool,highwater_level:u16,trend_by_event:{tag_:u8,no_trigger:-,event_trigger:event_trigger_}}[]",
  [0x02A6] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}, new_trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}, trend_by_event:{using_trend_archive:bool,highwater_level:u16,trend_by_event:{tag_:u8,no_trigger:-,event_trigger:event_trigger_}}, new_trend_by_event:{using_trend_ar...",
  [0x02A8] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, nrOftrend_setups:u16, trend_setups:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}[], nrOftrend_event_setups:u16, trend_event_setups:{using_trend_archive:bool,highwater_level:u16,trend_by_event:{tag_:u8,no_trigger:-,event_trigger:event_trigger_}}[]",
  [0x02E0] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, total_rate:Total_rate",
  [0x02E1] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x02E2] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0301] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0302] = "bln_network_time:{year:u8,month:u8,dayofmonth:u8,dayofweek:u8,hours:u8,minutes:u8,seconds:u8,tics:u8}, tics_per_second:u16",
  [0x0303] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, message:str",
  [0x030F] = "lan:u8, drop:u16, nrOftx_buffer:u16, tx_buffer:Data_byte[]",
  [0x0313] = "name:str, p1_command:u8, nrOftx_buffer:u16, tx_buffer:Data_byte[]",
  [0x0314] = "lan:u8, drop:u8, p1_command:u8, nrOftx_buffer:u16, tx_buffer:Data_byte[]",
  [0x0317] = "lan_number:u8, drop_number:u8, all_drops:bool",
  [0x0325] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, logger_state:bool",
  [0x0327] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, buffer_state:bool",
  [0x0330] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, initials_pattern:str, last_initials:str",
  [0x0331] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, initials_pattern:str, last_initials:str",
  [0x0332] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, user_account:{initials:str,long_name:str,password:str,autologoff_enabled:bool,autologoff_delay:u16,language_ID:Language_ID,date_format:str,time_format:str,user_command_priority:User_command_priority,name_space:Name_space,access_class:BITSTRING32,nrOffunctional_accesses:u16,functional_accesses:{user_access_functions:User_access_functions,user_access_priority:User_access_priority}[]}, password_expire_ext:{strike_count:u8,expire_limit:u16,expire_date:datetime}, is_pxm10tiny_autologin_acct:bool",
  [0x0333] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, user_account:{initials:str,long_name:str,password:str,autologoff_enabled:bool,autologoff_delay:u16,language_ID:Language_ID,date_format:str,time_format:str,user_command_priority:User_command_priority,name_space:Name_space,access_class:BITSTRING32,nrOffunctional_accesses:u16,functional_accesses:{user_access_functions:User_access_functions,user_access_priority:User_access_priority}[]}, password_expire_ext:{strike_count:u8,expire_limit:u16,expire_date:datetime}, is_pxm10tiny_autologin_acct:bool",
  [0x0335] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, initials_pattern:str, last_initials:str",
  [0x0336] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, initials_pattern:str, last_initials:str",
  [0x0338] = "user_Account_DB:{nrOfuser_accounts:u16,user_accounts:{initials:str,long_name:str,password:str,autologoff_enabled:bool,autologoff_delay:u16,language_ID:Language_ID,date_format:str,time_format:str,user_command_priority:User_command_priority,name_space:Name_space,access_class:BITSTRING32,nrOffunctional_accesses:u16,functional_accesses:Functional_access[]}[]}, nrOfpassword_expire_db_ext:u16, password_expire_db_ext:{initials:str,password_expire_ext:{strike_count:u8,expire_limit:u16,expire_date:datetime}}[]",
  [0x0350] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0353] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, access_group:{access_class_num:u8,description:str}",
  [0x0358] = "access_group_DB:{nrOfaccess_groups:u16,access_groups:{access_class_num:u8,description:str}[]}",
  [0x0360] = "ems_range_req:{begin_EMS_number:u16,end_EMS_number:u16}",
  [0x0361] = "ems_range_req:{begin_EMS_number:u16,end_EMS_number:u16}",
  [0x0362] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, ems_database:{nrOfems_entries:u16,ems_entries:{message_number:u16,category:u16,bring_on_remote:bool}[]}",
  [0x0364] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0365] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, ems_entry:{message_number:u16,category:u16,bring_on_remote:bool}",
  [0x0401] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type:{type_id:i16,type_name:str,nrOfelements:u16,elements:{value:i16,value_text:str}[]}",
  [0x0402] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type_id:i16",
  [0x0403] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0404] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_pattern:str, last_pattern:str",
  [0x0405] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type_name:str",
  [0x0406] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_pattern:str, last_pattern:str",
  [0x0407] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type_id:i16, nrOfenum_elements:u16, enum_elements:{value:i16,value_text:str}[]",
  [0x0408] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type_id:i16, value:i16",
  [0x0409] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type_id:i16, value:i16, new_value_text:str",
  [0x040A] = "last_enum_type_id:i16",
  [0x040B] = "begin_type_id:i16, end_type_id:i16, enum_type:{type_id:i16,type_name:str,nrOfelements:u16,elements:{value:i16,value_text:str}[]}",
  [0x040E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, enum_type:{type_id:i16,type_name:str,nrOfelements:u16,elements:{value:i16,value_text:str}[]}",
  [0x0500] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_response:{name_space:Name_space,name:str,suffix:str}, mode_name:str, mode_suffix:str, normal_acks:bool, alarmcnt2:bool, level_delay:u16, mode_delay:u16, differential:f32, category0:u8, category1:u8, category2:u8, category3:u8",
  [0x0501] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_response:{name_space:Name_space,name:str,suffix:str}",
  [0x0504] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0505] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0506] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_response:{name_space:Name_space,name:str,suffix:str}, mode_name:str, mode_suffix:str, normal_acks:bool, alarmcnt2:bool, level_delay:u16, mode_delay:u16, differential:f32, category0:u8, category1:u8, category2:u8, category3:u8",
  [0x0507] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_response:{name_space:Name_space,name:str,suffix:str}, mode_name:str, mode_suffix:str, normal_acks:bool, alarmcnt2:bool, level_delay:u16, mode_delay:u16, differential:f32, category0:u8, category1:u8, category2:u8, category3:u8",
  [0x0508] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, point:{tag_:u8,ldi:ldi_,ldo:ldo_,lai:lai_,lao:lao_,l2sl:l2sl_,looap:looap_,lpaci:lpaci_,l2sp:l2sp_,looal:looal_,lfssl:lfssl_,lfssp:lfssp_,ldao:ldao_,lenum:lenum_,lfmsl:lfmsl_,lfmsp:lfmsp_,ppcl_lai:ppcl_lai_}, alarm_message_node:u8, alarm_message_number:u16, alarm_message:str, lenum_address:{tag_:u8,not_present:-,present:present_}, nrOfalarm_buffer:u16, alarm_buffer:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},point:{tag_:u8,ldi:ldi_,ldo:ldo_,lai:lai_,lao:lao_,l2sl...",
  [0x0509] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x050A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x050B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, mode_name:str",
  [0x050C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, category:u16",
  [0x050D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0520] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_single:{name_space:Name_space,name:str,suffix:str}, setpoint_name:str, setpoint_suffix:str, alarm_mode:{mode_number:u8,set_point:f32,nrOflevels:u16,levels:{offset:f32,alarm_priority:Alarm_priority,category:u8,msg_number:u16}[]}",
  [0x0521] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_single:{name_space:Name_space,name:str,suffix:str}, setpoint_name:str, setpoint_suffix:str, alarm_mode:{mode_number:u8,set_point:f32,nrOflevels:u16,levels:{offset:f32,alarm_priority:Alarm_priority,category:u8,msg_number:u16}[]}",
  [0x0522] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16, alarm_priority:Alarm_priority",
  [0x0523] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16, alarm_priority:Alarm_priority",
  [0x0524] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16, setpoint_value:f32",
  [0x0525] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16",
  [0x0526] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u8",
  [0x0528] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_single:{name_space:Name_space,name:str,suffix:str}, setpoint_name:str, setpoint_suffix:str, alarm_mode:{mode_number:u8,set_point:f32,nrOflevels:u16,levels:{offset:f32,alarm_priority:Alarm_priority,category:u8,msg_number:u16}[]}",
  [0x0529] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, current_mode:u16",
  [0x052B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_single:{name_space:Name_space,name:str,suffix:str}, alarm_mode_type:Alarm_mode_type",
  [0x052C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16, category:u8",
  [0x052D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16, message_number:u8",
  [0x0530] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u16",
  [0x0540] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, category:{category_id:u8,description:str,dial_enabled:bool,printing_enabled:bool,nrOfnodes_bits:u16,nodes_bits:Node_bits[]}",
  [0x0541] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, first_category_id:u8, last_category_id:u8",
  [0x0542] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, category_id:u8, new_description:str",
  [0x0543] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, first_category:u8, last_category:u8",
  [0x0544] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, first_category:u8, last_category:u8",
  [0x0545] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, first_category:u8, last_category:u8",
  [0x0546] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, first_category:u8, last_category:u8",
  [0x0547] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_category:u8, end_category:u8, last_category:u8",
  [0x0548] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_category:u8, end_category:u8, last_category:u8",
  [0x0549] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, category_id:u8, nrOfnode_bits:u16, node_bits:Node_bits[]",
  [0x054A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, category_id:u8, nrOfnode_bits:u16, node_bits:Node_bits[]",
  [0x054B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_category:u8, end_category:u8, last_category:u8",
  [0x054C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_category:u8, end_category:u8, last_category:u8",
  [0x054D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, category:{category_id:u8,description:str,dial_enabled:bool,printing_enabled:bool,nrOfnodes_bits:u16,nodes_bits:Node_bits[]}",
  [0x0560] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16, last_message_id:u16",
  [0x0561] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16",
  [0x0562] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16",
  [0x0563] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16",
  [0x0564] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, alarm_message:{enabled:bool,msg_number:u16,message:str}",
  [0x0565] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, alarm_message:{enabled:bool,msg_number:u16,message:str}",
  [0x0566] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, message_id:u16",
  [0x0567] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16, last_message_id:u16",
  [0x0568] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, begin_message_id:u16, end_message_id:u16, last_message_id:u16",
  [0x056A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, alarm_message:{enabled:bool,msg_number:u16,message:str}",
  [0x0600] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, calendar_entry:{date_type:Date_type,the_date:date}",
  [0x0601] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, date_to_reset:date",
  [0x0602] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, nrOfcalendar_db:u16, calendar_db:{date_type:Date_type,the_date:date}[]",
  [0x0603] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0604] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0605] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0606] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0610] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, dst_entry:{spring_date:datetime,fall_date:datetime}",
  [0x0611] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, reset_year:date",
  [0x0612] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, nrOfdst_pairs:u16, dst_pairs:{spring_date:datetime,fall_date:datetime}[]",
  [0x0613] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0614] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x0961] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0962] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0963] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u8",
  [0x0964] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, trend_specifier:{number_of_samples:u16,trend_type:{tag_:u8,point_cov:-,trend_cov:trend_cov_,time:time_}}",
  [0x0965] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_line_returned:u16",
  [0x0966] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0967] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0968] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, eqs_start_where:{tag_:u8,beginning:-,last_mode:i16}",
  [0x0969] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_entry_id:i32",
  [0x096B] = "last_alarm_msg_id:u16",
  [0x0971] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0972] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0973] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u8",
  [0x0974] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0975] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_line_returned:u16",
  [0x0976] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0977] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0978] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, eqs_start_where:{tag_:u8,beginning:-,last_mode:i16}",
  [0x0979] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, entry_ID:i32, last_entry_ID:i32, state_text_ID:i16",
  [0x097B] = "begin_message_id:u16, end_message_id:u16, last_message_id:u16",
  [0x097C] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x097D] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x097E] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x097F] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0981] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0982] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0983] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_mode:u8",
  [0x0984] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x0985] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_line_returned:u16",
  [0x0986] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0987] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x0988] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, eqs_start_where:{tag_:u8,beginning:-,last_mode:i16}",
  [0x0989] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, entry_ID:i32, last_entry_ID:i32, state_text_ID:i16",
  [0x098B] = "begin_message_id:u16, end_message_id:u16, last_message_id:u16",
  [0x098C] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x098D] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x098E] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x098F] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x099E] = "port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x099F] = "port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x09A1] = "last_partner_id:u16",
  [0x09A2] = "partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x09A3] = "partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x09A5] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_xoverride_entry_id:i32",
  [0x09A6] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_xoverride_ID:i32",
  [0x09A7] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_xoverride_ID:i32",
  [0x09A9] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09AA] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09AB] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09B9] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09BA] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09BB] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09C1] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09C2] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x09C3] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x3800] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_record:{partner_log:{number:u16,enabled:bool,device_type:Device_type,descriptor:str,insight_node_number:u16},host_id:str,nrOfpartner_numbers:u16,partner_numbers:{phone_number:str}[],flex_string:str,full_flex_string:str}",
  [0x3802] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3803] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3804] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3805] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3806] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3807] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3808] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_record:{partner_log:{number:u16,enabled:bool,device_type:Device_type,descriptor:str,insight_node_number:u16},host_id:str,nrOfpartner_numbers:u16,partner_numbers:{phone_number:str}[],flex_string:str,full_flex_string:str}",
  [0x3809] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x380A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, partner_request:{begin_partner_number:u16,end_partner_number:u16,last_partner_number:u16}",
  [0x3814] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x3817] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x3818] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, port_log:{port_number:Port_number,port_status:{descriptor:str,baud_rate:Baud_rate,highlight_enabled:bool,autobye_enabled:bool,alarm_printing_enabled:bool,report_printing_enabled:bool,port_type:Port_type,my_site_id:str,AdvancedPortString:str,AdvancedSystemString:str,DiagPortString:str,DiagSystemString:str,PortName:str}}",
  [0x3819] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x381A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, port_request:{begin_port_number:u8,end_port_number:u8,last_port_number:u8}",
  [0x4000] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4001] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, description:str, default_member:u16, default_report:u16, member_count:u16, report_count:u16, dynamic:bool, extended_team_desc:{tag_:u8,no_extension:-,LON_extension:LON_extension_,MSTP_extension:-}",
  [0x4002] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, def_analog_add:{member_desc_base:{member_number:u16,nrOfteam_suffix:u16,team_suffix:Team_Suffix[],member_desc:str,point_type:Point_type,virtual_pt:bool,alarmable:bool,reference_type:Reference_Type,totalize:bool,print_alarms:bool,total_scale:Total_rate,includeInCount2:bool},english_units:str,english_init_val:f32,english_low_alarm:f32,english_high_alarm:f32,si_units:str,si_init_val:f32,si_low_alarm:f32,si_high_alarm:f32,representation:Representation}, analog_team_scale:{scale:scale_}, extended_team_member:{tag_:u...",
  [0x4003] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, def_digital_add:{member_desc_base:{member_number:u16,nrOfteam_suffix:u16,team_suffix:Team_Suffix[],member_desc:str,point_type:Point_type,virtual_pt:bool,alarmable:bool,reference_type:Reference_Type,totalize:bool,print_alarms:bool,total_scale:Total_rate,includeInCount2:bool},initial_value:f32,state_text_table:State_text_table}, inverted:bool, extended_team_member:{tag_:u8,no_extension:-,LON_extension:LON_extension_,MSTP_extension:MSTP_extension_}",
  [0x4004] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, def_enum_add:{member_desc_base:{member_number:u16,nrOfteam_suffix:u16,team_suffix:Team_Suffix[],member_desc:str,point_type:Point_type,virtual_pt:bool,alarmable:bool,reference_type:Reference_Type,totalize:bool,print_alarms:bool,total_scale:Total_rate,includeInCount2:bool},initial_value:f32,state_text_table:State_text_table}, extended_team_member:{tag_:u8,no_extension:-,LON_extension:LON_extension_,MSTP_extension:MSTP_extension_}",
  [0x4005] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, def_analog_add:{member_desc_base:{member_number:u16,nrOfteam_suffix:u16,team_suffix:Team_Suffix[],member_desc:str,point_type:Point_type,virtual_pt:bool,alarmable:bool,reference_type:Reference_Type,totalize:bool,print_alarms:bool,total_scale:Total_rate,includeInCount2:bool},english_units:str,english_init_val:f32,english_low_alarm:f32,english_high_alarm:f32,si_units:str,si_init_val:f32,si_low_alarm:f32,si_high_alarm:f32,representation:Representation}, count_both_edges:bool, si_gain:f32, si_cov_limit:f32, english_...",
  [0x4006] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, def_digital_add:{member_desc_base:{member_number:u16,nrOfteam_suffix:u16,team_suffix:Team_Suffix[],member_desc:str,point_type:Point_type,virtual_pt:bool,alarmable:bool,reference_type:Reference_Type,totalize:bool,print_alarms:bool,total_scale:Total_rate,includeInCount2:bool},initial_value:f32,state_text_table:State_text_table}, inverted:bool, proof_delay:u16, slavenumber:i16, slaveinverted:bool, extended_team_member:{tag_:u8,no_extension:-,LON_extension:LON_extension_,MSTP_extension:MSTP_extension_}",
  [0x400B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x400C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x400D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, report_name_pattern:str, last_report_name:str",
  [0x400F] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, last_team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}",
  [0x4010] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, member_number:u16, last_member_number:u16",
  [0x4017] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, last_team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}",
  [0x4018] = "team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16}, member_number:u16, last_member_number:u16",
  [0x4100] = "ppcl_data:{name_space:Name_space,name:str,line_status:str,line_text:str,line_number:u16,line_enabled:bool,line_traced:bool,line_unresolved:bool,line_failed:bool,line_looped:bool}, user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x4101] = "program_name:str",
  [0x4103] = "ppcl_range:{name_space:Name_space,name:str,first_line:u16,last_line:u16}, user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x4104] = "ppcl_range:{name_space:Name_space,name:str,first_line:u16,last_line:u16}",
  [0x4105] = "ppcl_range:{name_space:Name_space,name:str,first_line:u16,last_line:u16}",
  [0x4106] = "ppcl_range:{name_space:Name_space,name:str,first_line:u16,last_line:u16}",
  [0x4107] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4108] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, begin_line_number:u16, end_line_number:u16, last_line_returned:u16, point_name:str, nrOfStatement_types:u16, Statement_types:PPCL_statement_type[]",
  [0x4109] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x410A] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, begin_line_number:u16, end_line_number:u16, last_line_returned:u16",
  [0x410B] = "ppcl_data:{name_space:Name_space,name:str,line_status:str,line_text:str,line_number:u16,line_enabled:bool,line_traced:bool,line_unresolved:bool,line_failed:bool,line_looped:bool}, old_line_number:u16, user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x410E] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, begin_line_number:u16, end_line_number:u16, last_line_returned:u16",
  [0x410F] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, meter_area:u16",
  [0x4110] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, meter_area:u16",
  [0x4111] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, meter_area:u16, last_state:Last_state",
  [0x412A] = "team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, begin_line_number:u16, end_line_number:u16, last_line_returned:u16",
  [0x4131] = "program_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4132] = "program_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4133] = "program_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4134] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, program:{name_space:Name_space,program_name:str,base_instance_number:u32,instance_range:u32,priority_for_writing:u32}",
  [0x4135] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_space:Name_space, program_name:str",
  [0x4137] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, program_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4200] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:i16",
  [0x4201] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, tec_body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:Access_class,si_units:bool,lan:u8,drop:u8,duct_available:{tag_:u8,no_duct:-,use_duct:use_duct_},nightOverride:u8,added_to_database:bool,initialized:bool,is_valid:TEC_valid,failed_status:Failed_status,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32}[],nrOfrechar_values:u16,rechar_values:{member_number:u16,logi...",
  [0x4202] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, tec_body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:Access_class,si_units:bool,lan:u8,drop:u8,duct_available:{tag_:u8,no_duct:-,use_duct:use_duct_},nightOverride:u8,added_to_database:bool,initialized:bool,is_valid:TEC_valid,failed_status:Failed_status,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32}[],nrOfrechar_values:u16,rechar_values:{member_number:u16,logi...",
  [0x4203] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, tec_body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:Access_class,si_units:bool,lan:u8,drop:u8,duct_available:{tag_:u8,no_duct:-,use_duct:use_duct_},nightOverride:u8,added_to_database:bool,initialized:bool,is_valid:TEC_valid,failed_status:Failed_status,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32}[],nrOfrechar_values:u16,rechar_values:{member_number:u16,logi...",
  [0x4204] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4205] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4206] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4208] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4210] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, suffix_is_number:bool, member_number:u16",
  [0x4211] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, suffix_is_number:bool, report_number:u16",
  [0x4212] = "query:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str},last_suffix:str,application_number:u16}",
  [0x4220] = "def_TEC_app:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},application_family:Application_family,team_type:u16,name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},all_init_values:bool}",
  [0x4221] = "def_TEC_app:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},application_family:Application_family,team_type:u16,name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},all_init_values:bool}",
  [0x4222] = "set:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},application_number:u16,suffix_is_number:bool}, member_number:u16, initial_value:f32",
  [0x4223] = "restore:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},application_number:u16,suffix_is_number:bool}, member_number:u16",
  [0x4224] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16, clear_panel_initvals:bool, clear_device_initvals:bool",
  [0x4225] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16",
  [0x4230] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lan_or_device:{tag_:u8,one_device:one_device_,whole_lan:whole_lan_}",
  [0x4231] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lan_or_device:{tag_:u8,one_device:one_device_,whole_lan:whole_lan_}",
  [0x4232] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, which_lan:{tag_:u8,all_lans:-,one_lan:one_lan_}, which_drop:{tag_:u8,all_drops:-,one_drop:one_drop_}, last_lan:u8, last_drop:u8",
  [0x4241] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, uc_body:{team_description_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:BITSTRING32,lan:u8,drop:u8,added_to_database:bool,initialized:bool,is_valid:Uc_is_valid,failed_status:Uc_failed_status,nrOfrechar_values:u16,rechar_values:{member_number:u16,logical_value:f32,point_priority:Point_priority,control_status:Control_status}[],is_bacnet:{tag_:u8,BACnetNo:-,BACnetYes:BACnetYes_}}",
  [0x4244] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4245] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x4249] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x4300] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:i16",
  [0x4301] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lon_body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:BITSTRING32,si_units:bool,lan:u8,drop:u8,added_to_database:bool,initialized:bool,is_valid:TEC_valid,failed_status:Failed_status,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32}[],nrOfrechar_values:u16,rechar_values:{member_number:u16,logical_value:f32,point_priority:Point_priority,control_status:Control_statu...",
  [0x4303] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lon_body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:BITSTRING32,si_units:bool,lan:u8,drop:u8,added_to_database:bool,initialized:bool,is_valid:TEC_valid,failed_status:Failed_status,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32}[],nrOfrechar_values:u16,rechar_values:{member_number:u16,logical_value:f32,point_priority:Point_priority,control_status:Control_statu...",
  [0x4304] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:i16",
  [0x4310] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, suffix_is_number:bool, member_number:u16",
  [0x4311] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, suffix_is_number:bool, report_number:u16",
  [0x4320] = "def_LON_app:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},application_family:Application_family,team_type:u16,name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},all_init_values:bool}",
  [0x4321] = "def_LON_app:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},application_family:Application_family,team_type:u16,name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},all_init_values:bool}",
  [0x4322] = "set:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},application_number:u16,suffix_is_number:bool}, member_number:u16, initial_value:f32",
  [0x4323] = "restore:{user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class},name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str},application_number:u16,suffix_is_number:bool}, member_number:u16",
  [0x4324] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16, clear_panel_initvals:bool, clear_device_initvals:bool",
  [0x4325] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16",
  [0x4332] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, subnet_choice:{tag_:u8,all_subnets:-,single_subnet:u8}, node_choice:{tag_:u8,all_nodes:-,single_node:u8}, last_subnet:u8, last_node:u8",
  [0x4402] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, m_local:{tag_:u8,remote_is_set:remote_is_set_,local_is_set:-}",
  [0x4403] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, nrOflon_domain:u16, lon_domain:{domain_index:u8,nrOfdomain_id:u16,domain_id:{data:u8}[],subnet:u8,node:u8}[]",
  [0x4452] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x4621] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, node_name:str, site_name:str, bln_name:str, ip_addr_settings:{dhcp:dhcp_,dns:dns_,nrOfapp_ports:u16,app_ports:u16[],nrOfmulticast:u16,multicast:{mc_addr:u32,mc_port:u16}[],smtp_server:smtp_server_,telnet_enabled:bool,dynamic_dns:dynamic_dns_}, bacnetSettings:{tag_:u8,noBacnet:-,yesBacnet:yesBacnet_}, bacnet_ip_aln_choice:bool, bacnet_ip_network_number:u16, BACnetMSTPALNSettings:{tag_:u8,noMSTPALN:-,yesMSTPALN:yesMSTPALN_}, BACnetMSTPFLNSettings:{tag_:u8,noBACnetFLNs:-,yesBACnetFLNs:yesBACnetFLNs_}",
  [0x4628] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, bln_name:str, intrasite_eping_period:u32, intrasite_eping_timeout:u32, intersite_eping_period:u32, intersite_eping_timeout:u32, intrasite_notif_repl_period:u32, intrasite_poll_repl_period:u32, intrasite_repl_cycle_timeout:u32, intersite_notif_repl_period:u32, intersite_poll_repl_period:u32, intersite_repl_cycl_timeout:u32, tombstone_lifetime:u32, holdback_delay:u32",
  [0x4629] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x462A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, site_name:str",
  [0x462B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, bln_name:str",
  [0x462D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, hosttable_entry:{node_name:str,ip_address:u32}",
  [0x462E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, node_name:str",
  [0x462F] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, last_name:str",
  [0x4634] = "reconciliation:u16, high_watermark:u32, nrOfutdv_array:u16, utdv_array:{originating_node:str,originating_usn:u32}[], changes_max_size:u32",
  [0x4635] = "changes_max_size:u32, srce_cycle_number:u16, srce_cycle_pdu_number:u16",
  [0x4636] = "reconciliation:u16, boc_usn_changed:u32, more_data:bool, srce_cycle_number:u16, srce_cycle_pdu_number:u16, nrOfutdv_array:u16, utdv_array:{originating_node:str,originating_usn:u32}[], nrOfgrain_array:u16, grain_array:{repl_guid:str,usn_changed:u32,repl_cmd_type:Repl_Cmd_Type,grain_type:Grain_Type,entry_id:str,nrOfblob:u16,blob:{<Value>k__BackingField:SByte}[],grain_version:u32,orig_time:u32,orig_node:str,orig_usn:u32}[]",
  [0x4637] = "name_single:{name_space:Name_space,name:str,suffix:str}",
  [0x4640] = "enode:{node_name:str,site_name:str,bln_name:str,failed:bool,ready:bool,replication_online:bool,reresolve_all:bool,reresolve_unresolved:bool,spare1:u32,baseTime:u32,offset:u16,dst_flag:bool}",
  [0x4644] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x4645] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x482A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_priority_entry:{app_id:u8,bacnet_priority:u8}",
  [0x482B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, app_id:u8",
  [0x482C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, last_app_id:u8",
  [0x482E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, device_id:str, object_id:str, device_name:str, object_name:str, mac_address:str, option_string:str",
  [0x482F] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, device_id:str, object_id:str",
  [0x4838] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, point_name:{name_space:Name_space,name:str,suffix:str}, log_object:{object_Identifier:u32,object_Name:str,object_Type:u16,description:str,log_Enabled:bool,start_Time:datetime,stop_Time:datetime,log_deviceObjectProperty:{objectIdentifier:u32,propertyIdentifier:u32,propertyArrayIndex:u32,deviceIdentifer:u32},log_interval:u32,COV_Resubscription_Interval:u32,client_COV_Increment:client_COV_Increment_,stop_When_Full:bool,buffer_Size:u32,record_Count:u32,total_Record_Count:u32,notification_Threshold:u32,records...",
  [0x4839] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, object_Identifier:u32",
  [0x483A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, point_name:{name_space:Name_space,name:str,suffix:str}, log_object:{object_Identifier:u32,object_Name:str,object_Type:u16,description:str,log_Enabled:bool,start_Time:datetime,stop_Time:datetime,log_deviceObjectProperty:{objectIdentifier:u32,propertyIdentifier:u32,propertyArrayIndex:u32,deviceIdentifer:u32},log_interval:u32,COV_Resubscription_Interval:u32,client_COV_Increment:client_COV_Increment_,stop_When_Full:bool,buffer_Size:u32,record_Count:u32,total_Record_Count:u32,notification_Threshold:u32,records...",
  [0x4842] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_Object_Identifer:u32",
  [0x4844] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_Object_Identifer:u32",
  [0x4845] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_Object_Identifer:u32",
  [0x4846] = "name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, last_Object_Identifer:u32",
  [0x4878] = "last_object_id:u32",
  [0x4879] = "last_object_id:u32",
  [0x4960] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, baud_rate:BAC_Baud_rate, mstp_network_number:u16, mstp_node_number:u8, keep_alive_poll_rate:u16, discovery_poll_rate:u16",
  [0x4961] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, BACnet_MSTP_LAN:BACnet_MSTP_LAN_",
  [0x4963] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:Access_class,is_master:{is_master:bool},device:{instance_number:u32,network_number:u16,mac_address:Mac_Address,failed:bool},added_to_database:bool,initialized:bool,is_valid:TEC_valid,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32,xoverride:bool}[],initial_value_priority:u8,save_relinquish_default:bool,bacnet_pas...",
  [0x4965] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, body:{team_desc_base:{team_family:Application_family,team_type:u16,team_revision:u16},nrOfnames:u16,names:{name_space:Name_space,name:str}[],descriptor:str,access_class:Access_class,is_master:{is_master:bool},device:{instance_number:u32,network_number:u16,mac_address:Mac_Address,failed:bool},added_to_database:bool,initialized:bool,is_valid:TEC_valid,nrOfinitial_values:u16,initial_values:{member_number:u16,initial_value:f32,xoverride:bool}[],initial_value_priority:u8,save_relinquish_default:bool,bacnet_pas...",
  [0x4966] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:i16",
  [0x4967] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:i16",
  [0x496B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x496E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x4970] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, application_number:u16, initial_value:f32",
  [0x4971] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, application_number:u16",
  [0x4972] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16, clear_panel_initvals:bool, clear_device_initvals:bool",
  [0x4973] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, application_number:u16",
  [0x4B01] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, log_object:{object_instance_number:u32,object_Type:u16,object_Name:str,description:str,log_deviceObjectProperty:{object_instance_number:u32,object_Type:u16,propertyIdentifier:u8,propertyArrayIndex:u8,device_present:bool,device_instance_number:u32,device_type:u16},eventType:u8,eventState:u16,notification_Class:u32,eventEnable:u8,ackedTransitions:u8,notifyType:u8,alarmmessage_Number:u16,eventresolved:u16,event_Time_Stamps:{AlarmTimeStamp:datetime,FaultTimeStamp:datetime,NormalTimeStamp:datetime},event_param...",
  [0x4B02] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, searchbyname:bool, objectIDbegin:u32, objectIDend:u32, objectIDlast:u32",
  [0x4B03] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, objectIDbegin:u32",
  [0x5000] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_zone_definition:{nrOfnames:u16,names:{name_space:Name_space,name:str}[],eqs_zone_data:{zone_enabled:bool,description:str,access_class:Access_class,min_off_time:u16,recmd_after_warmstart:bool,warmstart_delay:u16,state_text_table:State_text_table,default_mode:i16,english_units:bool,optimization_osv:bool},nrOfrecharacterization_values:u16,recharacterization_values:{member_number:u16,logical_value:f32,point_priority:Point_priority,control_status:Control_status}[]}",
  [0x5001] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5002] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_zone_definition:{nrOfnames:u16,names:{name_space:Name_space,name:str}[],eqs_zone_data:{zone_enabled:bool,description:str,access_class:Access_class,min_off_time:u16,recmd_after_warmstart:bool,warmstart_delay:u16,state_text_table:State_text_table,default_mode:i16,english_units:bool,optimization_osv:bool},nrOfrecharacterization_values:u16,recharacterization_values:{member_number:u16,logical_value:f32,point_priority:Point_priority,control_status:Control_status}[]}",
  [0x5003] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5004] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5005] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5018] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_cmd_table_sequence:{name_team:{name_space:Name_space,name:str},name_name:{name_space:Name_space,name:str,suffix:str},nrOfcmd_table_entries:u16,cmd_table_entries:{mode:i16,command_value:f32,command_offset:u16}[]}",
  [0x5019] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_cmd_table_entry:{name_team:{name_space:Name_space,name:str},name_name:{name_space:Name_space,name:str,suffix:str},eqs_cmd_table_data:{mode:i16,command_value:f32,command_offset:u16}}",
  [0x501A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, mode:{tag_:u8,all_modes:-,one_mode:i16}",
  [0x501B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}, eqs_start_where:{tag_:u8,beginning:-,last_mode:i16}",
  [0x5020] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_mode_entry:{name:{name_space:Name_space,name:str},eqs_mode_data:{entry_ID:i32,entry_enabled:bool,mode:i16,occurrence:Occurrence,scheduled_days:Schedule_days,start_date:date,end_date:date,start_time:time,stop_time:time,days_spanned:u8,exclusive:bool}}",
  [0x5021] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, eqs_mode_entry:{name:{name_space:Name_space,name:str},eqs_mode_data:{entry_ID:i32,entry_enabled:bool,mode:i16,occurrence:Occurrence,scheduled_days:Schedule_days,start_date:date,end_date:date,start_time:time,stop_time:time,days_spanned:u8,exclusive:bool}}",
  [0x5022] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, which_mode_entry:{tag_:u8,all_mode_entries:-,entry_ID:i32}",
  [0x5023] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, entry_ID:i32, last_entry_ID:i32",
  [0x5024] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, eqs_which_mode_entry:{tag_:u8,all_mode_entries:-,entry_ID:i32}",
  [0x5025] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, eqs_which_mode_entry:{tag_:u8,all_mode_entries:-,entry_ID:i32}",
  [0x5028] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, eqs_xoverride:{entry_ID_to_xoverride:i32,my_entry_ID:i32,disable:bool,xoverride_date:date,ovr_start_time:time,ovr_stop_time:time,ovr_day_span:u8}",
  [0x5029] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, eqs_xoverride:{entry_ID_to_xoverride:i32,my_entry_ID:i32,disable:bool,xoverride_date:date,ovr_start_time:time,ovr_stop_time:time,ovr_day_span:u8}",
  [0x502A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_response:{name_space:Name_space,name:str}, entry_ID:i32",
  [0x502B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, xoverride_entry_ID:i32, last_entry_ID:i32",
  [0x5035] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5036] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, scheduled_days:Schedule_days, last_entry_ID:i32, last_schedule_day:Schedule_days",
  [0x5037] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x5038] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5039] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, last_entry_id:i32, last_xoverride_entry_ID:i32",
  [0x503A] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, ssto_general_setup:{osv:bool,eopst:bool,eopsp:bool,eoocnt:bool,ssto_amd:Ssto_amd,ssto_desop:{tag_:u8,value:Ssto_desop_value,name_suffix:name_suffix_},to:{tag_:u8,value:f32,name_suffix:name_suffix_},ti:{tag_:u8,value:f32,name_suffix:name_suffix_},sph:{tag_:u8,value:f32,name_suffix:name_suffix_},sphd:{tag_:u8,value:f32,name_suffix:name_suffix_},spc:{tag_:u8,value:f32,name_suffix:name_suffix_},spcd:{tag_:u8,value:f...",
  [0x503B] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, ssto_start_setup:{stmht:u16,occ_early_st_ht:bool,mod_early_st_ht:u16,occ_late_st_ht:bool,mod_late_st_ht:u16,ssto_zo_mod_ht:Ssto_zo_mod_ht,aosvstht:bool,hlo:f32,hdi:f32,min_st_dur_ht:f32,max_st_dur_ht:f32,to_min_st_dur_ht:f32,to_max_st_dur_ht:f32,cdtht:f32,dspht:f32,stmcl:u16,occ_early_st_cl:bool,mod_early_st_cl:u16,occ_late_st_cl:bool,mod_late_st_cl:u16,ssto_zo_mod_cl:Ssto_zo_mod_cl,aosvstcl:bool,clo:f32,cdi:f32...",
  [0x503C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, ssto_stop_setup:{apmht:u16,sk1_ht:f32,tdht:f32,dt_max_ht:f32,max_sp_dur_ht:f32,a_osv_sp_ht:bool,spmcl:u16,sk1_cl:f32,dt_max_cl:f32,max_sp_dur_cl:f32,a_osv_sp_cl:bool}",
  [0x503D] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, ssto_night_setup:{ntmht:u16,ntmcl:u16,ihys:f32}",
  [0x503E] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x503F] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5040] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5041] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5042] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, reset_settings:Ssto_reset_settings",
  [0x5043] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, enable_settings:SSTO_enable_settings",
  [0x5044] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}, disable_settings:SSTO_disable_settings",
  [0x5050] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5051] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5052] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5053] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, team_search:{name_space:Name_space,name_pattern:str,last_name_space:Name_space,last_name:str}",
  [0x5054] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, application_family:Application_family, team_type:u16, name_search:{name_space:Name_space,name_pattern:str,suffix_pattern:str,last_name_space:Name_space,last_name:str,last_suffix:str}",
  [0x5300] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, bim_lan_number:u8, bim_drop_number:u8",
  [0x5301] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lan_number:u8",
  [0x5303] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, bim_lan_number:u8, bim_drop_number:u8",
  [0x5304] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, lan_number:u8",
  [0x5330] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x5331] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x5332] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x5351] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, hoa_map:{nrOfhoa_map_entries:u16,hoa_map_entries:{switch_number:u8,point_number:CHAR_}[]}",
  [0x5354] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
  [0x5355] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}, hoa_map:{nrOfhoa_map_entries:u16,hoa_map_entries:{switch_number:u8,point_number:CHAR_}[]}",
  [0x700C] = "user_profile:{user_logon:str,point_priority:Point_priority,access_class:Access_class}",
}

------------------------------------------------------------------------ fields
local f = {}
f.total_len = ProtoField.uint32("p2.total_len","Total Length",base.DEC)
f.msg_type  = ProtoField.uint32("p2.msg_type","Message Type (raw)",base.HEX)
f.msg_class = ProtoField.uint8 ("p2.msg_class","Message Class",base.HEX,MSG_CLASS)
f.seq       = ProtoField.uint32("p2.seq","Sequence",base.DEC)
f.dir       = ProtoField.uint8 ("p2.dir","Direction",base.HEX,DIR)
f.bln1      = ProtoField.string("p2.bln1","BLN Name (slot 0)")
f.dst       = ProtoField.string("p2.dst","Dest/Peer Node (slot 1)")
f.bln2      = ProtoField.string("p2.bln2","BLN Name (slot 2)")
f.src       = ProtoField.string("p2.src","Source/Self Node (slot 3)")
f.opcode    = ProtoField.uint16("p2.opcode","AP2 Function Code",base.HEX,OPCODES)
f.err       = ProtoField.uint16("p2.err","Error Code",base.HEX,ERRORS)
f.schema    = ProtoField.string("p2.schema","Expected body fields [struct-derived]")
f.operand   = ProtoField.string("p2.operand","Operation operand [opcode-encoded]")
f.date      = ProtoField.string("p2.date","Date (y/m/d + weekday)")
f.modept    = ProtoField.string("p2.mode_point","Mode Point")
f.setpoint  = ProtoField.float ("p2.setpoint","Set Point")
f.lvl_off   = ProtoField.float ("p2.alarm_offset","Alarm Level Offset")
f.lvl_pri   = ProtoField.uint8 ("p2.alarm_priority","Alarm Priority",base.DEC)
f.lvl_cat   = ProtoField.uint8 ("p2.alarm_category","Alarm Category",base.DEC)
f.lvl_msg   = ProtoField.uint16("p2.alarm_message","Alarm Message Number",base.DEC)
f.eqs_mode  = ProtoField.uint16("p2.eqs_mode","EQS Mode Index",base.DEC)
f.eqs_val   = ProtoField.float ("p2.eqs_value","Commanded Value")
f.eqs_time  = ProtoField.string("p2.eqs_time","Scheduled Time")
f.rec_index = ProtoField.uint32("p2.record_index","Record Index (resume key)",base.DEC)
f.eqs_en    = ProtoField.uint8 ("p2.eqs_enabled","Entry Enabled",base.DEC,{[0]="no",[1]="yes"})
f.eqs_occ   = ProtoField.uint8 ("p2.eqs_occurrence","Occurrence",base.DEC,
                { [0]="one_time", [1]="weekly", [2]="replacement" })
f.eqs_days  = ProtoField.uint32("p2.eqs_days","Scheduled Days (bitmask)",base.HEX)
f.eqs_dayst = ProtoField.string("p2.eqs_days_text","Scheduled Days")
f.eqs_span  = ProtoField.uint8 ("p2.eqs_days_spanned","Days Spanned",base.DEC)
f.eqs_excl  = ProtoField.uint8 ("p2.eqs_exclusive","Exclusive",base.DEC,{[0]="no",[1]="yes"})
f.eqs_stt   = ProtoField.uint16("p2.eqs_state_text_id","State-Text Table Id",base.HEX)
f.tlv       = ProtoField.string("p2.tlv","TLV String")
f.scope     = ProtoField.string("p2.scope","User Logon (User_profile)")
f.access    = ProtoField.uint32("p2.access_class","Access Class (BITSTRING32)",base.HEX)
f.ems_code  = ProtoField.uint8 ("p2.ems_code","Session Event",base.HEX,
                { [0x07]="logon", [0x08]="logoff", [0x09]="attempt (no account resolved)" })
f.ems_user  = ProtoField.string("p2.ems_user","Operator Account")
f.ems_desc  = ProtoField.string("p2.ems_desc","Account Description")
f.priority  = ProtoField.uint8 ("p2.priority","Command Priority",base.HEX,PRIORITY)
f.value     = ProtoField.float ("p2.value","Value (f32 BE)")
f.cov_count = ProtoField.uint16("p2.cov.count","COV point count",base.DEC)
f.cov_point = ProtoField.string("p2.cov.point","COV Point Name")
f.cov_cond  = ProtoField.bytes ("p2.cov.cond","COV condition/priority block (10B)")
-- 10-byte condition block, field order from the ASDU schema (1 byte each fits the 10B exactly).
-- byte0 point_priority and byte1 control_status are now WIRE-CONFIRMED (point_priority=0x23 OPER
-- when commanded; control_status observed 0x00/02/03/04/06). A failed sensor asserts the
-- oos/failed bytes. alarm_state(+8)/alarm_priority(+9) still need a limit-alarmed capture.
f.cov_pri    = ProtoField.uint8("p2.cov.point_priority","point_priority",base.HEX,PRIORITY)
f.cov_ctrl   = ProtoField.uint8("p2.cov.control_status","control_status",base.HEX)
f.cov_oos    = ProtoField.uint8("p2.cov.out_of_service","out_of_service",base.DEC)
f.cov_fail   = ProtoField.uint8("p2.cov.failed","failed",base.DEC)
f.cov_proof  = ProtoField.uint8("p2.cov.proof_on","proof_on",base.DEC)
f.cov_opdis  = ProtoField.uint8("p2.cov.operator_disabled","operator_disabled",base.DEC)
f.cov_pgmdis = ProtoField.uint8("p2.cov.program_disabled","program_disabled",base.DEC)
f.cov_cmdal  = ProtoField.uint8("p2.cov.commanded_to_alarm","commanded_to_alarm",base.DEC)
f.cov_astate = ProtoField.uint8("p2.cov.alarm_state","alarm_state",base.DEC)
f.cov_apri   = ProtoField.uint8("p2.cov.alarm_priority","alarm_priority",base.DEC)
f.r_name    = ProtoField.string("p2.roster.name","Node Name")
f.r_ver     = ProtoField.uint32("p2.roster.ver","Node Version (change generation)")
f.r_tabver  = ProtoField.uint16("p2.roster.tabver","Table Version")
f.r_count   = ProtoField.uint16("p2.roster.count","Entry Count")
f.id_node   = ProtoField.string("p2.id.node","Node Name")
f.id_site   = ProtoField.string("p2.id.site","Site Name")
f.id_bln    = ProtoField.string("p2.id.bln","BLN Name")
-- request-family decoders (2.4)
local NAME_SPACE = { [0x0000]="system", [0x0001]="user", [0xFFFF]="any" }
local COV_SUB = { [0x00FF]="enable", [0x0000]="disable" }
f.ns        = ProtoField.uint16("p2.namespace","Name Space",base.HEX,NAME_SPACE)
f.pt_name   = ProtoField.string("p2.point.name","Point / Object Name")
f.pt_suffix = ProtoField.string("p2.point.suffix","Name Suffix")
f.resume    = ProtoField.string("p2.resume","Resume Cursor (last object)")
f.cov_sub   = ProtoField.uint16("p2.cov.subscribe","COV Subscribe",base.HEX,COV_SUB)
f.cmd_value = ProtoField.float ("p2.cmd.value","Commanded Value (f32 BE)")
f.ts        = ProtoField.string("p2.timestamp","Event Timestamp")
f.qual      = ProtoField.uint32("p2.quality","Value Quality Sentinel",base.HEX)
f.subtype   = ProtoField.uint8 ("p2.point.subtype","Point Sub-type",base.HEX)
f.al_value  = ProtoField.float ("p2.alarm.value","Alarm Value (f32 BE)")
-- seq-state response correlation (2.5)
f.resp_op   = ProtoField.string("p2.response_to","Response to (opcode recovered via seq)")
f.fw_rev    = ProtoField.string("p2.fw.rev","Firmware Revision")
f.fw_plat   = ProtoField.string("p2.fw.platform","Hardware Platform / Firmware Version")
f.fw_build  = ProtoField.string("p2.fw.build","Firmware Build Date")
f.eu        = ProtoField.string("p2.eu","Engineering Units")
f.body      = ProtoField.bytes ("p2.body","Body")
p2.fields = {
  f.total_len,f.msg_type,f.msg_class,f.seq,f.dir,f.bln1,f.dst,f.bln2,f.src,
  f.opcode,f.err,f.schema,f.operand,f.tlv,f.scope,f.priority,f.value,
  f.access,f.ems_code,f.ems_user,f.ems_desc,f.date,f.modept,f.setpoint,f.lvl_off,f.lvl_pri,f.lvl_cat,f.lvl_msg,
  f.eqs_mode,f.eqs_val,f.eqs_time,f.rec_index,
  f.eqs_en,f.eqs_occ,f.eqs_days,f.eqs_dayst,f.eqs_span,f.eqs_excl,f.eqs_stt,
  f.cov_count,f.cov_point,f.cov_cond,
  f.cov_pri,f.cov_ctrl,f.cov_oos,f.cov_fail,f.cov_proof,f.cov_opdis,f.cov_pgmdis,f.cov_cmdal,f.cov_astate,f.cov_apri,
  f.r_name,f.r_ver,f.r_tabver,f.r_count,
  f.id_node,f.id_site,f.id_bln,
  f.ns,f.pt_name,f.pt_suffix,f.resume,f.cov_sub,f.cmd_value,f.ts,f.qual,f.subtype,f.al_value,
  f.resp_op,f.fw_rev,f.fw_plat,f.fw_build,f.eu,
  f.body,
}

------------------------------------------------------------------------ helpers
local function cstr(tvb, off)
  local n = tvb:len(); if off >= n then return nil end
  for i = off, n-1 do if tvb(i,1):uint()==0 then return tvb(off,i-off):string(),(i-off+1) end end
  return nil
end
-- The prologue on most addressable requests is a User_profile:
--   TLV(user_logon) | u8 point_priority | BITSTRING32 access_class
-- SYST/NONE/CC are the logons the stack presents for system-originated work;
-- an operator driving a panel session puts their own login here instead, so
-- an unknown name in this position is a person, not a parse failure.
-- The system logons the stack presents for its own work.  A *person* driving a
-- session puts their own account name here instead, so this table is a label
-- hint only -- recognition is by shape (see profile_at), never by name list:
-- hardcoding site account names would neither generalise nor be ours to ship.
local SYSTEM_LOGON = { SYST=true, NONE=true, CC=true }
-- A User_profile prologue: TLV(user_logon) + u8 point_priority +
-- BITSTRING32 access_class, whose low three bytes are all ones in every
-- observed frame.  Returns the logon and the offset past the block, or nil.
local function profile_at(tvb, off, last)
  local s, l, no = read_tlv(tvb, off, last)
  if not s or l < 2 or l > 8 or no + 5 > last then return nil end
  if not s:match("^[%w%-%._]+$") then return nil end
  if tvb(no+2,3):uint() ~= 0xFFFFFF then return nil end
  return s, l, no
end
local function tlv_walk(tvb, off, last, tree)
  local i = off
  while i + 3 <= last do
    if tvb(i,1):uint()==0x01 and tvb(i+1,1):uint()==0x00 then
      local l = tvb(i+2,1):uint()
      if l > 0 and i+3+l <= last then
        local s = tvb(i+3,l):string()
        if SYSTEM_LOGON[s] then
          tree:add(f.scope, tvb(i,3+l), s)
          if i+3+l < last then tree:add(f.priority, tvb(i+3+l,1)) end
        else tree:add(f.tlv, tvb(i,3+l), s) end
        i = i + 3 + l
      else i = i + 1 end
    else i = i + 1 end
  end
end
local function dissect_cov(tvb, off, last, tree)
  -- COV_ANNUNCIATE body: u16 count, then per point a name_response
  -- (u16 name_space + name TLV + suffix TLV) + f32 value + 10-byte condition block.
  if off+2 > last then return end
  tree:add(f.cov_count, tvb(off,2)); off = off + 2
  while off + 9 <= last do
    local rec = off
    off = off + 2                              -- name_space (u16; observed 00 00 = system)
    if not (tvb(off,1):uint()==0x01 and tvb(off+1,1):uint()==0x00) then break end
    local l = tvb(off+2,1):uint(); if off+3+l > last then break end
    local pt = tree:add(p2, tvb(rec,0), "COV point")
    pt:add(f.cov_point, tvb(off+3,l)); off = off + 3 + l
    -- suffix TLV: empty (01 00 00) for top-level points; non-empty for FLN subpoints
    if off+3 <= last and tvb(off,1):uint()==0x01 and tvb(off+1,1):uint()==0x00 then
      local sl = tvb(off+2,1):uint()
      if off+3+sl <= last then
        if sl > 0 then pt:add(f.cov_point, tvb(off+3,sl)) end
        off = off + 3 + sl
      else break end
    end
    if off+4 <= last then pt:add(f.value, tvb(off,4)); off = off + 4 else break end
    if off+10 <= last then
      local cb = pt:add(f.cov_cond, tvb(off,10))
      cb:set_text("condition/priority block (10B) [byte0/1 wire-confirmed; alarm bytes need limit-alarm capture]")
      cb:add(f.cov_pri,   tvb(off,1));   cb:add(f.cov_ctrl,  tvb(off+1,1))
      cb:add(f.cov_oos,   tvb(off+2,1)); cb:add(f.cov_fail,  tvb(off+3,1))
      cb:add(f.cov_proof, tvb(off+4,1)); cb:add(f.cov_opdis, tvb(off+5,1))
      cb:add(f.cov_pgmdis,tvb(off+6,1)); cb:add(f.cov_cmdal, tvb(off+7,1))
      cb:add(f.cov_astate,tvb(off+8,1)); cb:add(f.cov_apri,  tvb(off+9,1))
      off = off + 10
    else break end
  end
end
local function dissect_roster(tvb, off, last, tree)
  if off+8 > last then return end
  tree:add(f.r_tabver, tvb(off+4,2)); tree:add(f.r_count, tvb(off+6,2)); off = off + 8
  while off + 3 <= last do
    if not (tvb(off,1):uint()==0x01 and tvb(off+1,1):uint()==0x00) then break end
    local l = tvb(off+2,1):uint(); if off+3+l > last then break end
    local e = tree:add(p2, tvb(off,0), "Node entry")
    e:add(f.r_name, tvb(off+3,l)); off = off + 3 + l
    if off+4 <= last then e:add(f.r_ver, tvb(off,4)); off = off + 4 end
  end
end
local function dissect_identity(tvb, off, last, tree)
  local fl = { f.id_node, f.id_site, f.id_bln }; local idx = 1
  while off + 3 <= last and idx <= 3 do
    if not (tvb(off,1):uint()==0x01 and tvb(off+1,1):uint()==0x00) then break end
    local l = tvb(off+2,1):uint(); if off+3+l > last then break end
    tree:add(fl[idx], tvb(off+3,l)); off = off + 3 + l; idx = idx + 1
  end
  if off < last then tlv_walk(tvb, off, last, tree) end
end

-- ---- request-family helpers/decoders (2.4; designed against captured bytes) ----
-- read a string TLV (01 00 <len> <bytes>); returns (string, len, next_off) or nil
local function read_tlv(tvb, off, last)
  if off + 3 > last then return nil end
  if tvb(off,1):uint() ~= 0x01 or tvb(off+1,1):uint() ~= 0x00 then return nil end
  local l = tvb(off+2,1):uint()
  if off + 3 + l > last then return nil end
  return tvb(off+3,l):string(), l, off + 3 + l
end
-- decode an 8-byte event timestamp [yr-1900][mo][day][DOW 1=Mon][hr][min][sec][centisec]
local DOW = { "Mon","Tue","Wed","Thu","Fri","Sat","Sun" }
local function ts8(tvb, off, last)
  if off + 8 > last then return nil end
  local yr=tvb(off,1):uint();   local mo=tvb(off+1,1):uint(); local dy=tvb(off+2,1):uint()
  local dw=tvb(off+3,1):uint(); local hh=tvb(off+4,1):uint(); local mm=tvb(off+5,1):uint()
  local ss=tvb(off+6,1):uint(); local cs=tvb(off+7,1):uint()
  -- year>=2000 excludes the all-zero "null/never" sentinel (epoch base 1900) and most
  -- non-timestamp trailing bytes; cs<=99 (centiseconds). Tightened to avoid false matches.
  if yr<100 or yr>199 or mo<1 or mo>12 or dy<1 or dy>31 or dw<1 or dw>7
     or hh>23 or mm>59 or ss>59 or cs>99 then return nil end
  return string.format("%04d-%02d-%02d %s %02d:%02d:%02d.%02d", 1900+yr, mo, dy, DOW[dw] or "?", hh, mm, ss, cs)
end
-- 4-byte calendar date [yr-1900][mo][day][DOW 1=Mon..7=Sun] -- the same encoding
-- as ts8 above, truncated before the time.  The weekday is redundant with the
-- date, which makes it a free alignment check: every date in the reference
-- corpus carries the correct weekday, so a mismatch means the parse has drifted.
local function date4(tvb, off, last)
  if off + 4 > last then return nil end
  local yr=tvb(off,1):uint(); local mo=tvb(off+1,1):uint()
  local dy=tvb(off+2,1):uint(); local dw=tvb(off+3,1):uint()
  if mo == 0 and dy == 0 then return "(none)" end
  if yr<100 or yr>199 or mo>12 or dy>31 or dw<1 or dw>7 then return nil end
  -- Sakamoto: weekday of a Gregorian date, 0=Sunday
  local y = 1900 + yr
  local t = {0,3,2,5,0,3,5,1,4,6,2,4}
  local yy = (mo < 3) and (y - 1) or y
  local w = (yy + math.floor(yy/4) - math.floor(yy/100) + math.floor(yy/400)
             + t[mo] + dy) % 7
  local iso = (w == 0) and 7 or w                        -- 1=Mon .. 7=Sun
  return string.format("%04d-%02d-%02d %s%s", y, mo, dy, DOW[dw] or "?",
                       (iso == dw) and "" or string.format(" [weekday byte %d, date is %s]",
                                                           dw, DOW[iso] or "?"))
end
-- consume an optional scope tag: 01 00 <len> <SCOPE> <command-priority:1> <3F FF FF FF>; returns next_off
local function scope_tag(tvb, off, last, tree)
  local s, l, no = profile_at(tvb, off, last)
  if s then
    local sc = tree:add(p2, tvb(off, (no+5)-off), "User_profile: "..s)
    sc:add(f.scope, tvb(off,3+l), s)
    sc:add(f.priority, tvb(no,1))     -- point_priority (wire-confirmed: 0x23 oper on commands)
    if no + 5 <= last then sc:add(f.access, tvb(no+1,4)) end   -- access_class bit string
    return no + 5
  end
  return off
end
-- Name_search: name_space u16 + name TLV + suffix TLV [+ last_name_space u16 + last_name TLV + last_suffix TLV]
local function dissect_namesearch(tvb, off, last, tree, has_resume)
  if off + 2 > last then return off end
  tree:add(f.ns, tvb(off,2)); off = off + 2
  local nm, nl, no = read_tlv(tvb, off, last); if not nm then return off end
  tree:add(f.pt_name, tvb(off+3,nl)); off = no
  local sf, sl, so = read_tlv(tvb, off, last)
  if sf ~= nil then if sl > 0 then tree:add(f.pt_suffix, tvb(off+3,sl)) end; off = so end
  if has_resume and off + 2 <= last then
    off = off + 2                                   -- last_name_space
    local rn, rl, rno = read_tlv(tvb, off, last)
    if rn ~= nil then
      if rl > 0 then tree:add(f.resume, tvb(off+3,rl)) end; off = rno
      local rs, rsl, rso = read_tlv(tvb, off, last)
      if rs ~= nil then off = rso end
    end
  end
  return off
end
-- addressing-family request: [scope] + Name_search + opcode tail
local function dissect_addr(tvb, off, last, tree, has_resume, tail)
  off = scope_tag(tvb, off, last, tree)
  off = dissect_namesearch(tvb, off, last, tree, has_resume)
  if tail == "cov" then
    if off + 2 <= last then tree:add(f.cov_sub, tvb(off,2)); off = off + 2 end
  elseif tail == "value" then
    if off + 4 <= last then tree:add(f.cmd_value, tvb(off,4)); off = off + 4 end
  end
  if off < last then tlv_walk(tvb, off, last, tree) end
end
-- ALARM_PRINT 0x0508 push: scope + name/descriptor TLVs + value block + dual timestamps
local function dissect_alarm(tvb, off, last, tree)
  off = scope_tag(tvb, off, last, tree)
  local nts = 0                                  -- alarm records carry up to 3 timestamps
  while off < last do
    local b0 = tvb(off,1):uint()
    if off + 3 <= last and b0 == 0x01 and tvb(off+1,1):uint() == 0x00 then
      local l = tvb(off+2,1):uint()
      if off + 3 + l <= last then
        if l > 0 then tree:add(f.tlv, tvb(off,3+l), tvb(off+3,l):string()) end
        off = off + 3 + l
      else off = off + 1 end
    elseif off + 4 <= last and b0 == 0x3F and tvb(off+1,1):uint() == 0xFF and tvb(off+2,1):uint() == 0xFF then
      tree:add(f.qual, tvb(off,4)); off = off + 4               -- quality sentinel 3F FF FF Fx
      if off + 3 <= last then tree:add(f.subtype, tvb(off+2,1)); off = off + 3 end  -- 00 comm subtype
      if off + 4 <= last then tree:add(f.al_value, tvb(off,4)); off = off + 4 end   -- f32 value
    else
      local t = (nts < 3) and ts8(tvb, off, last) or nil       -- report / onset / last-normal
      if t then tree:add(f.ts, tvb(off,8), t); off = off + 8; nts = nts + 1
      else off = off + 1 end
    end
  end
end
-- EMS_PRINT 0x0368: the panel announcing an operator session on its own console.
-- Body: u8 event code | 01 00 00 | TLV(node) | TLV(account) | TLV(description).
-- The account name arrives as typed on logon and in its canonical case on logoff,
-- and the description is the account's own text -- all in clear.
local function dissect_ems(tvb, off, last, tree)
  if off >= last then return end
  tree:add(f.ems_code, tvb(off,1)); off = off + 4        -- code + 01 00 00
  local labels = { f.pt_name, f.ems_user, f.ems_desc }
  for i = 1, 3 do
    local v, l, no = read_tlv(tvb, off, last); if not v then break end
    if l > 0 then tree:add(labels[i], tvb(off+3,l)) end
    off = no
  end
  if off < last then tlv_walk(tvb, off, last, tree) end
end
-- opcodes whose request body is scope?+Name_search (point reads, trend read, bulk uploads)
local ADDR_OPS = {
  [0x0220]=true, [0x0221]=true, [0x0295]=true,
  [0x0981]=true, [0x0982]=true,
}

-- ---- response-body decoders (2.5; reached via seq-state, never an on-wire opcode) ----
-- CABINET_DISPLAY 0x010C response: firmware banner = rev / platform / build TLVs, then
-- (after a binary config block) node/site/BLN + IP/MAC TLVs surfaced by the walk.
local function dissect_banner(tvb, off, last, tree)
  local labels = { f.fw_rev, f.fw_plat, f.fw_build }
  for i = 1, 3 do
    local s, l, no = read_tlv(tvb, off, last)
    if s then if l > 0 then tree:add(labels[i], tvb(off+3,l)) end; off = no else break end
  end
  if off < last then tlv_walk(tvb, off, last, tree) end
end
-- Value responses (read / COV-enable / UPL / trend): names + EU-units string + the value
-- block at the 3F FF FF Fx quality-sentinel anchor. The f32 in a plain analog read is NOT
-- sentinel-framed and its offset varies by point type, so it is intentionally left raw.
local EU_HINT = { ["DEG F"]=1,["DEG C"]=1,["PCT"]=1,["IN H2O"]=1,["PSI"]=1,["GPM"]=1,
                  ["CFM"]=1,["KW"]=1,["KWH"]=1,["VOLTS"]=1,["AMPS"]=1,["HZ"]=1,["RPM"]=1,["FPM"]=1 }
local function dissect_value_resp(tvb, off, last, tree)
  while off < last do
    local b0 = tvb(off,1):uint()
    if off + 3 <= last and b0 == 0x01 and tvb(off+1,1):uint() == 0x00 then
      local l = tvb(off+2,1):uint()
      if off + 3 + l <= last then
        if l > 0 then
          local s = tvb(off+3,l):string()
          tree:add(EU_HINT[s] and f.eu or f.tlv, tvb(off,3+l), s)
        end
        off = off + 3 + l
      else off = off + 1 end
    elseif off + 11 <= last and b0 == 0x3F and tvb(off+1,1):uint() == 0xFF and tvb(off+2,1):uint() == 0xFF then
      tree:add(f.qual, tvb(off,4)); off = off + 4          -- quality sentinel
      tree:add(f.subtype, tvb(off+2,1)); off = off + 3     -- 00 comm sub-type
      tree:add(f.value, tvb(off,4)); off = off + 4         -- f32 value
    else off = off + 1 end
  end
end
-- UPL_ALL_ALARM_MODE 0x0983 response: an enhanced-alarm definition.  The tail is
-- self-validating -- a u16 count followed by exactly count*8 bytes of Alarm_level --
-- so it is located from the end and the middle block is left as a raw block rather
-- than guessed at (its field offsets shift between records).
local function dissect_alarmmode(tvb, off, last, tree)
  if off + 2 > last then return end
  tree:add(f.ns, tvb(off,2)); off = off + 2
  local labels = { f.pt_name, f.pt_suffix, f.modept, f.pt_suffix, f.eu }
  for i = 1, 5 do
    local v, l, no = read_tlv(tvb, off, last); if not v then break end
    if l > 0 then tree:add(labels[i], tvb(off+3,l)) end
    off = no
  end
  off = off + 5                                     -- flag + four category bytes
  for _ = 1, 3 do                                   -- changed / reference / changed
    local t = ts8(tvb, off, last)
    if not t then break end
    tree:add(f.ts, tvb(off,8), t); off = off + 8
  end
  -- find the count: the only position where count*8 consumes the rest exactly
  local cut = nil
  for j = off, last - 2 do
    local n = tvb(j,2):uint()
    if n > 0 and (last - (j + 2)) == n * 8 then cut = j; break end
    end
  if not cut then if off < last then tlv_walk(tvb, off, last, tree) end; return end
  if cut - 4 >= off then tree:add(f.setpoint, tvb(cut-4,4)) end
  if cut - 4 > off then tree:add(p2, tvb(off, (cut-4)-off), "Setup block (delays, differential)") end
  local n = tvb(cut,2):uint()
  local lt = tree:add(p2, tvb(cut, last-cut), "Alarm levels ("..n..")")
  for k = 0, n - 1 do
    local b = cut + 2 + k * 8
    local e = lt:add(p2, tvb(b,8), string.format("Level %d", k + 1))
    e:add(f.lvl_off, tvb(b,4)); e:add(f.lvl_pri, tvb(b+4,1))
    e:add(f.lvl_cat, tvb(b+5,1)); e:add(f.lvl_msg, tvb(b+6,2))
  end
end
-- UPL_ALL_EQS_CMD_TABLE 0x0988: zone, commanded point, mode index, value
local function dissect_eqs_cmd(tvb, off, last, tree)
  if off + 2 > last then return end
  tree:add(f.ns, tvb(off,2)); off = off + 2
  local z, zl, zo = read_tlv(tvb, off, last); if not z then return end
  tree:add(f.pt_name, tvb(off+3,zl)); off = zo + 2                 -- + second name space
  local p, pl, po = read_tlv(tvb, off, last); if not p then return end
  tree:add(f.pt_name, tvb(off+3,pl)); off = po
  local sf, sl, so = read_tlv(tvb, off, last)
  if sf then if sl > 0 then tree:add(f.pt_suffix, tvb(off+3,sl)) end; off = so end
  if off + 6 <= last then
    tree:add(f.eqs_mode, tvb(off,2)); tree:add(f.eqs_val, tvb(off+2,4)); off = off + 6
  end
end
-- UPL_ALL_EQS_MODE_SCHED 0x0989: zone, record index (the resume key), mode,
-- effective-from / effective-until dates, and the time the mode starts
-- 0x0989 UPL_ALL_EQS_MODE_SCHED. Eleven fields (PROTOCOL.md 10.8), validated on
-- every captured record: both dates carry a weekday byte that must match their
-- own date, both times must be real, the booleans must be 0/1, and the record
-- must consume the body exactly.
local DAYNAME = { "Su","Mo","Tu","We","Th","Fr","Sa" }
local function days_text(mask)
  if mask == 0 then return "(none)" end
  local out = {}
  for b = 0, 6 do
    if bit.band(bit.rshift(mask, b), 1) == 1 then out[#out+1] = DAYNAME[b+1] end
  end
  for b = 7, 13 do
    if bit.band(bit.rshift(mask, b), 1) == 1 then out[#out+1] = "Repl"..(b-6) end
  end
  return #out > 0 and table.concat(out, "+") or string.format("0x%X", mask)
end
local function time4(tvb, off, last)
  if off + 4 > last then return nil end
  local h, m, s = tvb(off,1):uint(), tvb(off+1,1):uint(), tvb(off+2,1):uint()
  if h > 23 or m > 59 or s > 59 then return nil end
  return string.format("%02d:%02d:%02d", h, m, s)
end
local function dissect_eqs_sched(tvb, off, last, tree)
  if off + 2 > last then return end
  tree:add(f.ns, tvb(off,2)); off = off + 2
  local z, zl, zo = read_tlv(tvb, off, last); if not z then return end
  tree:add(f.pt_name, tvb(off+3,zl)); off = zo
  if off + 12 > last then return end
  tree:add(f.rec_index, tvb(off,4)); off = off + 4
  tree:add(f.eqs_en,   tvb(off,1)); off = off + 1
  tree:add(f.eqs_mode, tvb(off,2)); off = off + 2
  tree:add(f.eqs_occ,  tvb(off,1)); off = off + 1
  local mask = tvb(off,4):uint()
  tree:add(f.eqs_days,  tvb(off,4))
  tree:add(f.eqs_dayst, tvb(off,4), days_text(mask)); off = off + 4
  for _, lab in ipairs({ "Start date", "End date" }) do
    local d = date4(tvb, off, last); if not d then return end
    tree:add(f.date, tvb(off,4), lab..": "..d); off = off + 4
  end
  for _, lab in ipairs({ "Start time", "Stop time" }) do
    local v = time4(tvb, off, last); if not v then return end
    tree:add(f.eqs_time, tvb(off,4), lab..": "..v); off = off + 4
  end
  if off + 2 > last then return end
  tree:add(f.eqs_span, tvb(off,1)); off = off + 1
  tree:add(f.eqs_excl, tvb(off,1)); off = off + 1
  if off + 2 <= last then tree:add(f.eqs_stt, tvb(off,2)) end
end
-- UPL_ALL_EQS_ZONE 0x0987: zone name, its schedule point, and a descriptor
-- 0x0987 UPL_ALL_EQS_ZONE. The lead u16 is a COUNT OF NAMES, not a marker: it
-- predicts exactly that many Team_response entries (u16 name_space + TLV), and
-- the second entry's own name_space is what an earlier reading called a
-- "two-byte separator". Then Eqs_zone_data. PROTOCOL.md 10.8.
local function dissect_eqs_zone(tvb, off, last, tree)
  if off + 2 > last then return end
  local n = tvb(off,2):uint()
  tree:add(f.r_count, tvb(off,2)); off = off + 2
  if n < 1 or n > 8 then return end            -- not the shape we know
  for _ = 1, n do
    if off + 2 > last then return end
    tree:add(f.ns, tvb(off,2)); off = off + 2
    local s, sl, no = read_tlv(tvb, off, last); if not s then return end
    if sl > 0 then tree:add(f.pt_name, tvb(off+3,sl)) end
    off = no
  end
  if off >= last then return end
  tree:add(f.eqs_en, tvb(off,1)); off = off + 1        -- zone_enabled
  local d, dl, dno = read_tlv(tvb, off, last); if not d then return end
  if dl > 0 then tree:add(f.tlv, tvb(off+3,dl)) end
  off = dno
  if off + 11 > last then return end
  tree:add(f.access, tvb(off,4)); off = off + 4        -- access_class
  off = off + 2                                        -- min_off_time
  off = off + 1                                        -- recmd_after_warmstart
  off = off + 2                                        -- warmstart_delay
  tree:add(f.eqs_stt, tvb(off,2))                      -- state_text_table
end
-- opcodes whose response carries a value/Point_base-style body
local VALUE_RESP = {
  [0x0220]=true, [0x0221]=true, [0x0271]=true, [0x0295]=true, [0x0981]=true, [0x0982]=true,
}

------------------------------------------------------------------------ one PDU
local function dissect_one(tvb, pinfo, tree)
  local total = tvb(0,4):uint()
  local mclass = tvb(7,1):uint()
  local dir = tvb(12,1):uint()
  local st = tree:add(p2, tvb(0,total), "Siemens P2")
  st:add(f.total_len, tvb(0,4)); st:add(f.msg_type, tvb(4,4)); st:add(f.msg_class, tvb(7,1))
  st:add(f.seq, tvb(8,4)); st:add(f.dir, tvb(12,1))
  local off = 13
  local sfields = { f.bln1, f.dst, f.bln2, f.src }; local slots = {}
  for s = 1, 4 do
    local val, adv = cstr(tvb, off); if not val then break end
    st:add(sfields[s], tvb(off, adv-1), val); slots[s] = val; off = off + adv
  end
  -- seq-state key: per TCP stream + the (echoed) sequence number
  local seq = tvb(8,4):uint()
  local sinfo = f_tcp_stream()
  local skey = (sinfo and tostring(sinfo.value) or "?") .. ":" .. seq
  local opname, rop = nil, nil
  -- A run of opcodes is often one operation with a parameter encoded in the
  -- opcode rather than the body, so name the operand alongside the mnemonic.
  local function rlabel(o)
    local n = OPCODES[o] or string.format("0x%04X", o)
    local fm = p2data.families[o]
    return fm and (n .. string.format(" (%s=%s)", fm.param, fm.value)) or n
  end
  if dir == 0x00 then
    if off + 2 <= total then
      local op = tvb(off,2):uint(); st:add(f.opcode, tvb(off,2))
      opname = OPCODES[op] or string.format("unknown_0x%04X", op)
      local fam = p2data.families[op]
      if fam then
        st:add(f.operand, tvb(off,2), string.format("%s - %s: %s",
               fam.family, fam.param, fam.value)):set_generated()
        opname = opname .. string.format(" (%s=%s)", fam.param, fam.value)
      end
      if not pinfo.visited then resp_op[skey] = op end   -- remember for the matching response
      off = off + 2
      if off < total then
        local bt = st:add(p2, tvb(off, total-off), "Body ("..(total-off).." B)")
        if OPSCHEMA[op] then bt:add(f.schema, tvb(off,0), OPSCHEMA[op]) end
        local ok = pcall(function()
          if op==0x0274 then dissect_cov(tvb,off,total,bt)
          elseif op==0x4634 or op==0x4636 then dissect_roster(tvb,off,total,bt)
          elseif op==0x4640 then dissect_identity(tvb,off,total,bt)
          elseif op==0x0508 then dissect_alarm(tvb,off,total,bt)
          elseif op==0x0368 then dissect_ems(tvb,off,total,bt)
          elseif op==0x0271 or op==0x0272 or op==0x0273 then dissect_addr(tvb,off,total,bt,false,"cov")
          elseif op==0x0240 then dissect_addr(tvb,off,total,bt,true,"value")
          elseif op==0x0241 then dissect_addr(tvb,off,total,bt,true,"none")
          elseif ADDR_OPS[op] then dissect_addr(tvb,off,total,bt,true,"none")
          else tlv_walk(tvb,off,total,bt) end
        end)
        if not ok then tlv_walk(tvb,off,total,bt) end
      end
    end
  elseif dir == 0x05 then
    rop = resp_op[skey]
    if total >= off+2 then st:add(f.err, tvb(total-2,2)) end
    if rop then st:add(f.resp_op, tvb(0,0), rlabel(rop)):set_generated() end
    if off < total-2 then tlv_walk(tvb, off, total-2, st:add(p2, tvb(off,total-2-off), "Body")) end
  else
    rop = resp_op[skey]
    if off < total then
      local hdr = rop and ("Body ("..(total-off).." B) -- response to "..rlabel(rop))
                  or ("Body ("..(total-off).." B)")
      local bt = st:add(p2, tvb(off,total-off), hdr)
      if rop then bt:add(f.resp_op, tvb(0,0), rlabel(rop)):set_generated() end
      pcall(function()
        if rop==0x010C then dissect_banner(tvb,off,total,bt)
        elseif rop==0x4640 then dissect_identity(tvb,off,total,bt)
        elseif rop==0x0983 then dissect_alarmmode(tvb,off,total,bt)
        elseif rop==0x0987 then dissect_eqs_zone(tvb,off,total,bt)
        elseif rop==0x0988 then dissect_eqs_cmd(tvb,off,total,bt)
        elseif rop==0x0989 then dissect_eqs_sched(tvb,off,total,bt)
        elseif rop and VALUE_RESP[rop] then dissect_value_resp(tvb,off,total,bt)
        else tlv_walk(tvb,off,total,bt) end
      end)
    elseif rop then
      st:add(f.resp_op, tvb(0,0), rlabel(rop)):set_generated()   -- 0-byte ACK (e.g. write)
    end
  end
  local cls = MSG_CLASS[mclass] or string.format("0x%02X", mclass)
  local who = (slots[4] or "?").."->"..(slots[2] or "?")
  if dir == 0x00 then pinfo.cols.info:set(cls.."  "..(opname or "?").."  "..who)
  elseif dir == 0x05 then
    -- Guard on off+2, not total>=2. The error tail lives after the four routing
    -- slots; on a truncated frame whose slots run to the end there is no tail,
    -- and reading tvb(total-2,2) would lift two header/slot bytes and render
    -- them as a phantom error code (observed: a 13-byte dir-0x05 frame reported
    -- "ERROR 0x0105"). Matches the guard already used on the tree item above.
    if total >= off+2 then
      local ec = tvb(total-2,2):uint()
      pinfo.cols.info:set("ERROR "..(ERRORS[ec] or string.format("0x%04X",ec)).."  seq="..seq
                          ..(rop and ("  ["..rlabel(rop).."]") or ""))
    else
      pinfo.cols.info:set("ERROR (truncated - no code)  seq="..seq
                          ..(rop and ("  ["..rlabel(rop).."]") or ""))
    end
  else
    pinfo.cols.info:set("success"..(rop and ("  "..rlabel(rop).." resp") or "").."  seq="..seq.."  "..who)
  end
end

------------------------------------------------------------------------ top-level (reassembly)
function p2.dissector(tvb, pinfo, tree)
  pinfo.cols.protocol = "P2"
  local len = tvb:len(); local offset = 0
  while offset < len do
    -- Fewer than a full 13-byte header (4 len + 4 class + 4 seq + 1 dir) in hand:
    -- ask TCP for one more segment rather than dropping the tail. The old guard
    -- (`offset + 4 > len` inside a `offset + 13 <= len` loop) could never fire, so
    -- a segment ending mid-header silently desynced the rest of the stream.
    if offset + 13 > len then
      pinfo.desegment_offset = offset
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      return
    end
    local total = tvb(offset,4):uint()
    if total < 13 or total > 65536 then return end
    if offset + total > len then
      pinfo.desegment_offset = offset; pinfo.desegment_len = (offset+total)-len; return
    end
    dissect_one(tvb(offset,total):tvb(), pinfo, tree)
    offset = offset + total
  end
end

local tcp = DissectorTable.get("tcp.port")
tcp:add(5033, p2)
tcp:add(5034, p2)
