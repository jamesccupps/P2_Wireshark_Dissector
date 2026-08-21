-- p2.lua — Siemens APOGEE P2 (Protocol II) Wireshark dissector
-- Version: 2.6  (2026-08-19)  -- carrier-label correction, error/opcode names, tail-guard fix
--
-- Changelog
--   2.6  Accuracy pass against the corpus.
--        * 0x29 / 0x2A carrier labels corrected. They were named "peer maintenance"
--          and "peer COV-subscribe"; the corpus establishes neither function. They
--          are now "session carrier" and "peer-session carrier (panel<->panel)",
--          matching PROTOCOL.md 6.2. Both carry the EBLN_PING 0x4640 identity
--          exchange.
--        * Error 0x0E12 named "record_state_rejected (unconfirmed)" -- observed a
--          few times, adjacent to already-exists, precise meaning not pinned.
--          Rendering it as a known-but-unpinned code beats bare hex.
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
  [0x0003]="not_found", [0x00AC]="not_supported (E172)", [0x0002]="out_of_scope",
  [0x0E11]="already_exists", [0x0E15]="not_commandable", [0x0009]="error_0009",
  -- 0x0E12: observed a few times in the corpus; an already-exists-adjacent
  -- record-state rejection whose precise meaning is not established
  -- (PROTOCOL.md §7.2.2, Appendix D item 3). Named here so it renders as a
  -- known-but-unpinned code rather than bare hex.
  [0x0E12]="record_state_rejected (unconfirmed)",
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
f.tlv       = ProtoField.string("p2.tlv","TLV String")
f.scope     = ProtoField.string("p2.scope","Scope Tag")
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
  f.opcode,f.err,f.schema,f.tlv,f.scope,f.priority,f.value,
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
local SCOPE = { SYST=true, NONE=true, CC=true }
local function tlv_walk(tvb, off, last, tree)
  local i = off
  while i + 3 <= last do
    if tvb(i,1):uint()==0x01 and tvb(i+1,1):uint()==0x00 then
      local l = tvb(i+2,1):uint()
      if l > 0 and i+3+l <= last then
        local s = tvb(i+3,l):string()
        if SCOPE[s] then
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
-- consume an optional scope tag: 01 00 <len> <SCOPE> <command-priority:1> <3F FF FF FF>; returns next_off
local function scope_tag(tvb, off, last, tree)
  local s, l, no = read_tlv(tvb, off, last)
  if s and SCOPE[s] and no + 5 <= last and tvb(no+1,4):uint() == 0x3FFFFFFF then
    local sc = tree:add(p2, tvb(off, (no+5)-off), "Scope: "..s)
    sc:add(f.scope, tvb(off,3+l), s)
    sc:add(f.priority, tvb(no,1))     -- command priority byte (wire-confirmed: 0x23 OPER on commands)
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
  local function rlabel(o) return OPCODES[o] or string.format("0x%04X", o) end
  if dir == 0x00 then
    if off + 2 <= total then
      local op = tvb(off,2):uint(); st:add(f.opcode, tvb(off,2))
      opname = OPCODES[op] or string.format("unknown_0x%04X", op)
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
