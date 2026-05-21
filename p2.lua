-- p2.lua — Wireshark dissector for Siemens APOGEE P2 (Apogee Ethernet)
--
-- Decodes TCP/5033 (Siemens-default P2 port per white paper 149-1006)
-- and the UDP/10001 multicast presence beacon into a navigable protocol
-- tree: routing header, opcode, and (for reads/COVs) device / point /
-- value broken out.
--
-- Non-default port: use Wireshark's Decode As... to map your site's
-- port to the P2 dissector. See README for details.
--
-- Plugin folder location:
--   Help -> About Wireshark -> Folders -> "Personal Lua Plugins"
--   Typical paths:
--     Windows: %APPDATA%\Wireshark\plugins\
--     Linux:   ~/.local/lib/wireshark/plugins/
--     macOS:   ~/.local/lib/wireshark/plugins/
--
-- Reload without restarting: Analyze -> Reload Lua Plugins (Ctrl+Shift+L)
--
-- Coverage notes:
--   * Mode C connections — operational opcodes carried inside 0x2E/0x2F
--     framing (no transition to 0x33/0x34 ever) are dispatched to the
--     opcode handler. Detection rule: first 2 bytes after routing header
--     != 0x4640 -> operational opcode; else -> IdentifyBlock.
--   * Routing-header name ordering is destination-first across ALL message
--     types (DATA, HEARTBEAT, CONNECT, ANNOUNCE). Field labels reflect
--     that.
--   * Comm-status byte (live vs stale-cache) and data-type byte are
--     surfaced from the value block — the 0x00/0x01 byte at value-block
--     offset +6 is the device-comm-fault flag.
--   * Multicast presence beacon decoder bound to UDP/10001 — payload
--     should always be 4 bytes 01 00 00 00. Dual-emitted to multicast
--     233.89.188.1 and broadcast 255.255.255.255 (sub-millisecond delta);
--     cadence ~10.5s.
--   * Schedule operations (0x098C-F, 0x5020/22), PPCL editor opcodes
--     (0x4100/03/04/06), property-write split (0x0240/0x4222 with
--     0x0E15 wrong-write-opcode error), and alarm pair (0x0508/0x0509)
--     all dispatched and decoded.
--
-- Anything tagged "unknown_opcode" in the dissector output is a candidate
-- for further protocol analysis. Add new opcodes to OPCODES below as
-- they're identified.

local p2  = Proto("p2",        "Siemens P2 (Apogee Ethernet)")
local p2b = Proto("p2_beacon", "Siemens P2 Multicast Beacon")

------------------------------------------------------------------------
-- Constants
------------------------------------------------------------------------

local MSG_TYPES = {
    [0x29] = "ANNOUNCE-inter-panel (inter-panel post-restart BLN re-establishment)",
    [0x2E] = "CONNECT (legacy handshake; carries Mode C ops)",
    [0x2F] = "ANNOUNCE (modern dialect; supervisor-bound)",
    [0x33] = "DATA (legacy dialect)",
    [0x34] = "HEARTBEAT (modern dialect / session maintenance)",
}

local DIR_BYTES = {
    [0x00] = "Request",
    [0x01] = "Success Response",
    [0x05] = "Error Response (typically body `00 00 03` for unrecognized opcode)",
}

-- Big-endian u16 opcode that follows the routing header in DATA/HEARTBEAT
-- frames (and Mode C 0x2E/0x2F frames carrying operational ops).
local OPCODES = {
    -- System info / identity
    [0x0100] = "GetRevString (legacy sysinfo)",
    [0x010C] = "SysInfoCompact (model/firmware/build-date)",
    [0x4640] = "Identify (handshake or 10s mid-session refresh)",
    [0x4634] = "RoutingTable (BLN topology announce; legitimate replication-table operation)",

    -- 0x46xx replication-ops range. The opcodes in this range carry the
    -- supervisor's BLN-wide peer-table push and related topology
    -- operations. Most have minimal public documentation; the
    -- annotations below reflect observed wire-level behavior only.
    [0x462D] = "RecordSet (sub-opcode observed inside 0x4636 ReplChanges body — wraps each <peer-name, peer-IP> entry with SYST-scope sentinel)",
    [0x4633] = "Undocumented success-response (body 51B-several-hundred B; content not fully decoded)",
    [0x4635] = "Undocumented success-response (body 51B-several-hundred B; content not fully decoded)",
    [0x4636] = "ReplChanges (CPI 0x1604) — supervisor->panel BLN-wide peer-table push; body carries <name TLV, IP> records using sub-opcode 0x462D",
    [0x4641] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4642] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4643] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4644] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4645] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4646] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4647] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4648] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x4649] = "0x46xx — undocumented (semantics not publicly documented)",
    [0x464A] = "Replication op (peer-name write to BLN peer table)",
    [0x464B] = "Replication op (same class as 0x464A)",
    [0x464C] = "Replication op (same class as 0x464A)",
    [0x464D] = "Topology query (response carries BLN peer inventory)",
    [0x464E] = "Undocumented success-response",
    [0x464F] = "Undocumented success-response",
    [0x4650] = "Undocumented success-response",

    -- Status / system probes. 0x0050 / 0x0606 / 0x5354 / 0x098B all have
    -- constant body bytes.
    [0x0050] = "StatusQuery (14B fixed body; response includes a system identity string after the SYST scope footer)",
    [0x0606] = "Ping (14B body; panel name appears in routing header)",
    [0x5354] = "Status probe (14B constant body; always errors 0x0003; semantics unknown)",

    -- Reads
    [0x0220] = "ReadShort (modern dialect, compact; small + 273B preallocated descriptor-fetch)",
    [0x0271] = "ReadExtended (legacy dialect)",
    [0x0272] = "ReadExtended-MetaOnly (no value sentinel)",
    [0x0273] = "WriteNoValue / PointExistenceProbe (Desigo UI browse — 500x more common than alarm-ack use)",
    [0x0274] = "ValuePush (5033 push-write / 5034 COV — direction-dependent)",

    -- Bare-opcode session pings (PXC->DCC, 2 bytes total, panel-specific)
    [0x0951] = "BarePing 0951 (panel-specific 2-byte keepalive)",
    [0x0954] = "BarePing 0954 (panel-specific 2-byte keepalive)",
    [0x0955] = "BarePing 0955 (panel-specific 2-byte keepalive)",
    [0x0956] = "BarePing 0956 (panel-specific 2-byte keepalive)",
    [0x0959] = "BarePing 0959 (panel-specific 2-byte keepalive)",

    -- Writes / SYST property ops
    [0x0240] = "WriteWithQuality — 5034 NONE-device virtual writes; 5033 SYST attempts error 0x0E15 (Desigo retries with 0x4222)",
    [0x0241] = "PropertyEcho / DefaultPropertyResolve (SYST) — echoes (dev,pt) for fully-qualified targets; fills MODE/etc. into empty 2nd-TLV for object-only probes",
    [0x0244] = "ScopedQuery (SYST-restricted read variant; returns 0x0002 out-of-scope)",
    [0x0245] = "TestProbe (always errors; not a real op)",
    [0x0291] = "SYST property op (probable write — 01 00 c8 [type] [f32] value marker)",
    [0x0294] = "SYST read variant — small (53B sep=0x00) and large (222B preallocated sep=0x01) forms",
    [0x0295] = "SYST-scoped read (sibling of 0x0294; plant-equipment status registers)",
    [0x02A8] = "SYST property op (probable write w/ priority trailer 50 00; otherwise like 0x0291)",

    -- Object lifecycle (02xx)
    [0x0203] = "ObjectLifecycle 0x0203 (probe; carries name + initial-value f32)",
    [0x0204] = "CreateObject (returns 0x0E11 if exists; carries name + initial-value f32)",
    [0x0260] = "ObjectLifecycle 0x0260 (probe variant; carries f32=1.0 default-value)",
    [0x0263] = "ObjectLifecycle 0x0263 (probable delete; ACK-only response, no per-object data)",

    -- Routing / node queries
    [0x0368] = "NodeRoutingQuery",

    -- Multi-state label catalog
    [0x040A] = "MultiStateLabelCatalog (state-set fetch)",

    -- Alarms
    [0x0508] = "AlarmReport (PXC->DCC, full alarm record)",
    [0x0509] = "AlarmAck (DCC->PXC, acknowledge alarm)",
    [0x0541] = "Probable working opcode (62B dir=1 response with `55 AA FF` sentinel body on bare invocation; state-dependent — subsequent calls from same peer session return 0x0003; probable pollable / get-next pattern)",
    [0x0549] = "Probable SetActiveSupervisor (appears in normal Desigo-CC-to-panel mid-session traffic; embeds supervisor canonical name in SYST-scoped body; not in spec opcode tables)",
    [0x0561] = "Undocumented success-response cluster",
    [0x0562] = "Undocumented success-response (same class as 0x0561)",
    [0x0563] = "Undocumented success-response (same class as 0x0561)",

    -- Point enumeration (09xx — three distinct request shapes)
    [0x0981] = "EnumeratePoints (cursor-based, all panel points)",
    [0x0982] = "EnumerateTrended (cursor-based + timestamps)",
    [0x0983] = "EnumerateVariant (mostly 0x00AC)",
    [0x0984] = "EnumerateVariant (mostly 0x00AC)",
    [0x0985] = "EnumeratePrograms (PPCL source dump)",
    [0x0986] = "EnumerateFLN (FLN device list, two cursor formats)",
    [0x0987] = "EnumerateVariant (mostly 0x00AC)",
    [0x0988] = "EnumerateMulti (multi-string filter)",
    [0x0989] = "EnumerateVariant (mostly 0x00AC)",
    [0x099F] = "GetPortConfig (5B body 09 9F 00 04 XX; 6 indices walked: 0xFF, 0x00..0x04)",

    -- Schedule operations (09xx — Mode C)
    [0x0961] = "AnalogPointQuery (legacy)",
    [0x0964] = "TitleAnalogQuery (value + units + limits)",
    [0x0965] = "NodeDiscoveryEnumerate",
    [0x0966] = "ShortQuery (probe; mostly errors)",
    [0x0969] = "ScheduleObjectList",
    [0x0971] = "EnhancedPointRead (desc + value + units + min/max + type)",
    [0x0974] = "MultistatePointEnumerate (state-set-aware)",
    [0x0975] = "NodeDiscoveryWithLines",
    [0x0976] = "DeviceAllSubpointsRead (per-device f32 dump; observed Mode-C requests went unanswered)",
    [0x0979] = "ShortVariant (cross-opcode lookup)",
    [0x098B] = "Enumerate (newer-firmware probe; constant body 09 8B 00 01 00 FA 00 00; always errors 0x0003 on observed firmware)",
    [0x098C] = "ScheduleSetpointTable",
    [0x098D] = "ScheduleEntries (weekly schedule with BACnet dates)",
    [0x098E] = "ScheduleGainConfig (PID/gain rows)",
    [0x098F] = "ScheduleDeadband (single f32)",

    -- Newer-firmware / capability probes (mostly errors on legacy)
    [0x09A3] = "Newer-firmware enumerate (often 0x00AC)",
    [0x09A7] = "Newer-firmware enumerate (often 0x00AC)",
    [0x09AB] = "Newer-firmware enumerate (often 0x00AC)",
    [0x09BB] = "Newer-firmware enumerate (often 0x00AC)",
    [0x09C3] = "Newer-firmware enumerate (often 0x00AC)",
    [0x400F] = "Capability probe (0x00AC on this firmware)",
    [0x4010] = "Capability probe (0x00AC on this firmware)",
    [0x4011] = "Capability probe (0x00AC on this firmware)",
    [0x4133] = "Capability probe (0x00AC on this firmware)",
    [0x4500] = "TestProbe (always errors)",

    -- PPCL editor. 0x4100 / 0x4103 request bodies append a 9-byte SYST scope
    -- footer (`01 00 04 SYST 23 3F FF FF FF`) after their opcode-specific
    -- payload — strip it and the panel rejects the request.
    [0x4100] = "PPCL LineWrite/Create (5-byte zero gap before SYST footer)",
    [0x4103] = "PPCL ProgramEnableHint (00 01 7F FF mode/scope; SYST footer adjacent)",
    [0x4104] = "PPCL LineRead/Delete (line-number + length/mode u16s)",
    [0x4106] = "PPCL ClearTracebits (refresh; modifies runtime state)",

    -- Bulk property
    [0x4200] = "PropertyQuery (small ~30-40B browse OR 222B preallocated deep-read)",
    [0x4220] = "BulkProperty variant (222B preallocated; '00 10' selector at sentinel — single corpus sample)",
    [0x4221] = "BulkPropertyRead (constant 273-byte preallocated request)",
    [0x4222] = "BulkPropertyWrite (canonical SYST setpoint write opcode)",

    -- Schedule property writes
    [0x5003] = "ScheduleObjectInfoQuery",
    [0x5020] = "ScheduleEntryWrite",
    [0x5022] = "ScheduleSlotInit (allocate-then-write pair)",
    [0x5038] = "ObjectDisplayLabels (cursor enumerate name->label)",
}

-- Status / error code catalog. Codes flagged * are the ones observed in
-- normal operation; the rest are vendor-documented (Siemens BACnet ALN
-- Manual 125-3020 Appendix C) and surface mostly on writes, firmware-
-- update flows, and PPCL ops.
local STATUS_ERRORS = {
    -- Common
    [0x0002] = "object_unknown (E2; out-of-scope for scope-restricted op)",
    [0x0003] = "not_found (E3; *dominant* error in normal operation)",
    [0x00AC] = "not_supported (E172; opcode not on this firmware)",
    [0x0E11] = "already_exists (E3601; CreateObject — treat as success)",
    [0x0E15] = "physical_point_not_commandable (E3605; 0x0240 vs SYST — retry as 0x4222)",
    -- Vendor-documented
    [0x0001] = "no_memory_available (E1)",
    [0x0004] = "priority_too_low (E4)",
    [0x0005] = "failed_no_change (E5)",
    [0x0007] = "out_of_service (E7)",
    [0x0008] = "field_panel_general_error (E8)",
    [0x0009] = "already_exists_v2 (E9; sibling of E3601)",
    [0x000A] = "trend_already_exists / value_unchanged (E10)",
    [0x000B] = "value_out_of_range (E11; also see E3606)",
    [0x000C] = "line_not_traced (E12; PPCL)",
    [0x000D] = "line_state_mismatch (E13; PPCL)",
    [0x0016] = "has_unresolved_points (E22; PPCL/zone)",
    [0x0028] = "line_accessed_not_traced (E40; PPCL tracebit)",
    [0x0040] = "tiu_busy (E64)",
    [0x0065] = "command_not_supported (E101; sibling of E172)",
    [0x0080] = "point_in_hand_mode (E128)",
    [0x0081] = "invalid_password (E129)",
    [0x0082] = "user_accounts_database_full (E130)",
    [0x00AB] = "coldstart_required (E171)",
    [0x00B7] = "operation_aborted_warmstart (E183)",
    [0x00B8] = "too_many_framing_errors (E184)",
    [0x00F9] = "invalid_point_address (E249)",
    [0x00FA] = "failed_io_device (E250)",
    [0x00FE] = "monitor_list_full (E254; COV)",
    [0x0200] = "flt_transfer_in_progress (E512; firmware loader)",
    [0x0202] = "flt_transfer_killed (E514)",
    [0x0203] = "tec_not_added (E515)",
    [0x0205] = "connection_lost (E517)",
    [0x0206] = "warm_started (E518)",
    [0x0207] = "protocol_error (E519)",
    [0x0209] = "timeout (E521)",
    [0x0210] = "invalid_fln_number (E528)",
    [0x0E10] = "invalid_drop_number (E3600)",
    [0x0E12] = "invalid_point_number (E3602)",
    [0x0E13] = "physical_point_failed (E3603)",
    [0x0E14] = "physical_point_not_commandable_v2 (E3604; sibling of E3605)",
    [0x0E16] = "value_out_of_range_v2 (E3606; sibling of E11)",
    [0x0E17] = "application_invalid_for_device (E3607)",
}

-- Data-type codes seen in value-block 7-byte metadata (last byte). Empirical
-- distribution from ~575 R3 responses across 5 captures.
local DATA_TYPE_CODES = {
    [0x00] = "digital/binary/enum",
    [0x01] = "rare (semantics not pinned)",
    [0x02] = "small int (likely int16)",
    [0x03] = "analog (dominant)",
    [0x04] = "(unobserved; speculative)",
    [0x05] = "(unobserved; speculative)",
    [0x06] = "analog32 / extended numeric",
}

-- Comm-status byte (value-block metadata offset +1 after the 01 00 00 marker).
-- This is the device-level comm-fault flag — distinct from the response-level
-- direction byte (0x01 success / 0x05 error). PXCs return cached values
-- indefinitely from comm-faulted devices; this byte is the only way to spot it.
local COMM_STATUS = {
    [0x00] = "live (device online)",
    [0x01] = "STALE (device comm-faulted; cached value)",
}

-- 4-byte BLN multicast beacon payload — invariant across the corpus.
local BEACON_PAYLOAD_HEX = "01000000"

------------------------------------------------------------------------
-- ProtoFields
------------------------------------------------------------------------

local f = {}

-- Frame header (12 bytes, big-endian)
f.total_len = ProtoField.uint32("p2.total_len", "Total Length", base.DEC)
f.msg_type  = ProtoField.uint32("p2.msg_type",  "Message Type", base.HEX, MSG_TYPES)
f.sequence  = ProtoField.uint32("p2.seq",       "Sequence",     base.DEC)

-- Routing header
f.dir_byte    = ProtoField.uint8 ("p2.dir",       "Direction",       base.HEX, DIR_BYTES)
f.bln1        = ProtoField.string("p2.bln1",     "BLN Network (1)")
f.node_a      = ProtoField.string("p2.node_a",   "Node A (slot 2)")
f.bln2        = ProtoField.string("p2.bln2",     "BLN Network (2)")
f.node_b      = ProtoField.string("p2.node_b",   "Node B (slot 4)")
f.dst_node    = ProtoField.string("p2.dst",      "Destination Node")
f.src_node    = ProtoField.string("p2.src",      "Source Node")
f.sender      = ProtoField.string("p2.sender",   "Sender (self)")
f.recipient   = ProtoField.string("p2.recipient","Recipient (peer)")

-- Body
f.opcode      = ProtoField.uint16("p2.opcode",   "Opcode",     base.HEX, OPCODES)
f.error_code  = ProtoField.uint16("p2.err_code", "Error Code", base.HEX, STATUS_ERRORS)

-- Read / COV / write decoded fields
f.device_name  = ProtoField.string("p2.device", "Device Name")
f.point_name   = ProtoField.string("p2.point",  "Point Name")
f.float_value  = ProtoField.float ("p2.value",  "Value (float, BE)")
f.units        = ProtoField.string("p2.units",  "Units")

-- Value block sub-fields
f.value_marker      = ProtoField.bytes ("p2.vb.marker",       "Value-block Marker (01 00 00)")
f.value_sentinel    = ProtoField.bytes ("p2.vb.sentinel",     "Property-state Sentinel (4 bytes)")
f.value_comm_status = ProtoField.uint8 ("p2.vb.comm_status",  "Comm Status",          base.HEX, COMM_STATUS)
f.value_err_code    = ProtoField.uint8 ("p2.vb.err_code",     "Per-device Err Code",  base.HEX)
f.value_dtype       = ProtoField.uint8 ("p2.vb.dtype",        "Data Type",            base.HEX, DATA_TYPE_CODES)

-- Identity-block strings (handshake / 0x4640)
f.scanner_name = ProtoField.string("p2.scanner", "Scanner Name")
f.site_name    = ProtoField.string("p2.site",    "Site Name")
f.network_name = ProtoField.string("p2.network", "Network Name")
f.id_timestamp = ProtoField.absolute_time("p2.id.timestamp",
                                          "Embedded Unix epoch", base.UTC)

-- Sysinfo response decode (0x010C)
f.sysinfo_model    = ProtoField.string("p2.sys.model",    "Panel Model")
f.sysinfo_firmware = ProtoField.string("p2.sys.firmware", "Firmware")
f.sysinfo_build    = ProtoField.string("p2.sys.build",    "Build Date")

-- Port config (0x099F)
f.port_index = ProtoField.uint8 ("p2.port.index", "Port Index", base.HEX)
f.port_label = ProtoField.string("p2.port.label", "Port Label")

-- Routing table entry (0x4634)
f.rt_peer = ProtoField.string("p2.rt.peer", "Peer Name")
f.rt_cost = ProtoField.uint32("p2.rt.cost", "Cost", base.DEC)

-- Alarm-record fields (0x0508 / 0x0509)
f.alarm_class       = ProtoField.string("p2.alarm.class",       "Alarm Class")
f.alarm_point       = ProtoField.string("p2.alarm.point",       "Alarmed Point")
f.alarm_description = ProtoField.string("p2.alarm.description", "Alarm Description")
f.alarm_marker      = ProtoField.string("p2.alarm.marker",      "Internal Marker (4-char)")
f.alarm_time_raised = ProtoField.string("p2.alarm.t_raised",    "Time Alarm First Raised")
f.alarm_time_now    = ProtoField.string("p2.alarm.t_now",       "Time of Report (now)")
f.alarm_time_last   = ProtoField.string("p2.alarm.t_last",      "Time of Last Transition")
f.alarm_value       = ProtoField.float ("p2.alarm.value",       "Alarm-time Value")

-- Schedule fields (0x098D / 0x5020)
f.sched_name      = ProtoField.string("p2.sched.name",      "Schedule Name")
f.sched_date      = ProtoField.string("p2.sched.date",      "BACnet Date (4B)")
f.sched_setpoint  = ProtoField.float ("p2.sched.setpoint",  "Setpoint (f32 BE)")

-- Beacon
f.beacon_payload = ProtoField.bytes("p2.beacon.payload", "Beacon Payload")

-- Generic LP-strings collected from elsewhere in the body
f.lp_strings = ProtoField.string("p2.strings", "Decoded Strings")

p2.fields = {
    f.total_len, f.msg_type, f.sequence,
    f.dir_byte, f.bln1, f.bln2,
    f.node_a, f.node_b, f.dst_node, f.src_node, f.sender, f.recipient,
    f.opcode, f.error_code,
    f.device_name, f.point_name, f.float_value, f.units,
    f.value_marker, f.value_sentinel, f.value_comm_status,
    f.value_err_code, f.value_dtype,
    f.scanner_name, f.site_name, f.network_name, f.id_timestamp,
    f.sysinfo_model, f.sysinfo_firmware, f.sysinfo_build,
    f.port_index, f.port_label,
    f.rt_peer, f.rt_cost,
    f.alarm_class, f.alarm_point, f.alarm_description, f.alarm_marker,
    f.alarm_time_raised, f.alarm_time_now, f.alarm_time_last, f.alarm_value,
    f.sched_name, f.sched_date, f.sched_setpoint,
    f.lp_strings,
}

p2b.fields = { f.beacon_payload }

------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------

-- Read a null-terminated ASCII string starting at `offset` in tvb. Returns
-- (string_value, length_including_null). Returns nil on missing terminator.
local function read_cstring(tvb, offset)
    local len = tvb:len()
    if offset >= len then return nil end
    for i = offset, len - 1 do
        if tvb(i, 1):uint() == 0 then
            local s = (i > offset) and tvb(offset, i - offset):string() or ""
            return s, (i - offset + 1)
        end
    end
    return nil
end

-- Pull all `01 00 LL [ASCII]` style LP-strings from a TvbRange. Mirrors
-- _extract_lp_strings in the scanner. Returns a list of {offset, length, value}.
--
-- Important: validate the raw bytes are printable ASCII directly — do NOT
-- rely on `:string()` to filter, because Wireshark's TvbRange:string()
-- truncates at the first NUL byte. A "\0\0" payload would otherwise round-
-- trip as an empty string and pass a pattern-based check, polluting results
-- with phantom empty entries (the alarm-header `01 00 02 00 00` padding TLV
-- exhibits this).
local function extract_lp_strings(tvb)
    local out = {}
    local len = tvb:len()
    local i = 0
    while i < len - 3 do
        -- TLV header: tag 0x01 + u16 BE length (spec §9.2).
        -- High byte is 0x00 for all observed TEC names (capped at 30 chars
        -- per §2.4), but read the full u16 to match spec.
        if tvb(i, 1):uint() == 0x01 then
            local slen = tvb(i+1, 2):uint()
            if slen > 0 and slen < 100 and (i + 3 + slen) <= len then
                local ok = true
                for j = i + 3, i + 2 + slen do
                    local b = tvb(j, 1):uint()
                    if b < 0x20 or b > 0x7E then ok = false; break end
                end
                if ok then
                    table.insert(out, {
                        offset = i,
                        length = 3 + slen,
                        value  = tvb(i+3, slen):string(),
                    })
                    i = i + 3 + slen
                else
                    i = i + 1
                end
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    return out
end

-- Extract u16-BE-prefixed strings (the format used in some sysinfo bodies).
local function extract_u16lp_strings(tvb)
    local out = {}
    local len = tvb:len()
    local i = 0
    while i < len - 2 do
        local slen = tvb(i, 2):uint()
        if slen > 0 and slen < 1024 and (i + 2 + slen) <= len then
            local ok = true
            for j = i + 2, i + 1 + slen do
                local b = tvb(j, 1):uint()
                if b < 0x20 or b > 0x7E then ok = false; break end
            end
            if ok then
                table.insert(out, {
                    offset = i, length = 2 + slen, value = tvb(i+2, slen):string()
                })
                i = i + 2 + slen
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    return out
end

-- Decode an 8-byte BACnet date+time block. Format from the protocol spec's
-- alarm section: year-1900 / month / day / day-of-week / hour / min / sec / hund.
local function decode_bacnet_datetime(tvb, off)
    if off + 8 > tvb:len() then return nil end
    local y   = tvb(off,     1):uint()
    local mo  = tvb(off + 1, 1):uint()
    local d   = tvb(off + 2, 1):uint()
    local dow = tvb(off + 3, 1):uint()
    local h   = tvb(off + 4, 1):uint()
    local mi  = tvb(off + 5, 1):uint()
    local s   = tvb(off + 6, 1):uint()
    local hu  = tvb(off + 7, 1):uint()
    if y < 0x70 then return nil end                   -- year < 2012: implausible
    if mo < 1 or mo > 12 then return nil end
    if d  < 1 or d  > 31 then return nil end
    if dow > 7 then return nil end
    if h > 23 or mi > 59 or s > 59 or hu > 99 then return nil end
    local dows = {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}
    local dows_label = (dow >= 1 and dow <= 7) and dows[dow] or "?"
    return string.format("%04d-%02d-%02d %s %02d:%02d:%02d.%02d",
        y + 1900, mo, d, dows_label, h, mi, s, hu)
end

-- Decode a 4-byte BACnet date — used inside 0x098D schedule entries and
-- 0x5020 schedule writes. Format: [year-1900][month][day][day-of-week].
local function decode_bacnet_date4(tvb, off)
    if off + 4 > tvb:len() then return nil end
    local y   = tvb(off,     1):uint()
    local mo  = tvb(off + 1, 1):uint()
    local d   = tvb(off + 2, 1):uint()
    local dow = tvb(off + 3, 1):uint()
    if y < 0x70 then return nil end
    if mo < 1 or mo > 12 then return nil end
    if d  < 1 or d  > 31 then return nil end
    if dow < 1 or dow > 7 then return nil end
    local dows = {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}
    return string.format("%04d-%02d-%02d (%s)", y + 1900, mo, d, dows[dow])
end

------------------------------------------------------------------------
-- Value-block detection + decode
-- See spec §14 (Response Parsing — Point Reads) and
-- "Comm status (the stale-cache trick)".
------------------------------------------------------------------------

-- Returns offset of [01 00 00] value-block marker, or nil. Mirrors the
-- scanner's _parse_read_response with the documented off-by-one fix:
-- bound is `len - 13` so payload[i..i+13] is fully addressable.
--
-- The predicate must be tight: 0x0981 enumerate responses contain `01 00 00`
-- bytes embedded in the per-entry metadata block (e.g. `01 00 00 04 00 02 00 00`
-- right after the device-name TLV) whose preceding byte is the last ASCII
-- char of the device name. Without sentinel-shape and reserved-byte checks,
-- those false-match and the dissector decodes garbage floats and a phantom
-- "comm STALE" tag pulled from whatever bytes happen to follow. Verified
-- against an enumerate-response capture, where SHAPE A enumerate metadata produces
-- exactly this confusion.
local function find_value_block(tvb)
    local len = tvb:len()
    for i = 1, len - 14 do
        if  tvb(i, 1):uint()   == 0x01
        and tvb(i+1, 1):uint() == 0x00
        and tvb(i+2, 1):uint() == 0x00
        then
            -- Sentinel shapes: see spec §14.3.
            -- Real value blocks have one of these patterns at +3..+6:
            --   `3F FF FF XX` — R1 ("quality flags" register), where XX
            --                   varies. The protocol spec documents
            --                   `3F FF FF FF` but the F7 variant — and
            --                   probably others — is real and common in
            --                   the field. Lock only the 3-byte prefix.
            --   `00 00 00 00` — R2/R3 (explicit "all flags clear" /
            --                   modern compact form).
            -- The 09xx enumerate-response per-entry metadata block has
            -- shapes like `04 00 02 00`, `03 00 02 00`, etc. that
            -- false-match a permissive scan; either the `3F FF FF`
            -- prefix or the all-zero check filters them out.
            local s0 = tvb(i+3, 1):uint()
            local s1 = tvb(i+4, 1):uint()
            local s2 = tvb(i+5, 1):uint()
            local s3 = tvb(i+6, 1):uint()
            local sentinel_3fff = (s0 == 0x3F and s1 == 0xFF and s2 == 0xFF)
            local sentinel_zero = (s0 == 0x00 and s1 == 0x00 and s2 == 0x00 and s3 == 0x00)
            -- Byte +7 is the "reserved" byte of the 3-byte status group
            -- (sentinel:4 + reserved:1 + comm_status:1 + err/dtype:1).
            -- Always 0x00 across all observed read responses — including
            -- STALE responses, where it's byte +8 (comm_status) that flips
            -- to 0x01, never +7.
            local reserved_ok = (tvb(i+7, 1):uint() == 0x00)
            if (sentinel_3fff or sentinel_zero) and reserved_ok then
                local prev = tvb(i-1, 1):uint()
                local is_ascii_end = (prev >= 0x41 and prev <= 0x5A)
                                  or (prev >= 0x61 and prev <= 0x7A)
                                  or (prev >= 0x30 and prev <= 0x39)
                                  or prev == 0x20 or prev == 0x2E
                                  or prev == 0x5F or prev == 0x2D
                if is_ascii_end then
                    -- Cheap float-leading-byte sanity check
                    local first = tvb(i+10, 1):uint()
                    if first <= 0x48
                       or first == 0xBF or first == 0xC0 or first == 0xC1
                       or first == 0xC2 or first == 0xC3 or first == 0xC4
                       or first == 0xC5
                    then
                        return i
                    end
                end
            end
        end
    end
    return nil
end

-- Decode value block at offset `vb`. Adds a sub-tree with marker, sentinel,
-- comm-status, error-code, data-type, and value. Returns the float value.
local function dissect_value_block(tvb, vb, parent, pinfo)
    local vtree = parent:add(p2, tvb(vb, 14), "Value Block")
    vtree:add(f.value_marker,      tvb(vb,     3))
    vtree:add(f.value_sentinel,    tvb(vb + 3, 4))
    -- 7-byte metadata at offsets +3..+9, broken into:
    --   +3..+6: sentinel (4 bytes; documented separately)
    --   +7    : reserved (always 0x00 observed)
    --   +8    : comm_status — 0x00 live / 0x01 STALE (PROTOCOL "Comm status")
    --             this is the "second byte of the metadata block" the doc
    --             refers to, counting from the start of the 3-byte trailer
    --   +9    : err_code in R1/R2 (legacy dialect; 0x06 = typical comm err)
    --             OR data-type code in R3 (modern dialect / SHAPE B). The
    --             role depends on whether the sentinel at +3..+6 is non-zero
    --             (R1, then +9 is err_code) or zero (R2/R3, then +9 may be
    --             a data-type code).
    vtree:add(f.value_comm_status, tvb(vb + 8, 1))
    vtree:add(f.value_err_code,    tvb(vb + 9, 1))
    vtree:add(f.value_dtype,       tvb(vb + 9, 1))
    vtree:add(f.float_value,       tvb(vb + 10, 4))
    local val = tvb(vb + 10, 4):float()

    -- If the device is comm-faulted, flag it loudly in the info column.
    if tvb(vb + 8, 1):uint() == 0x01 then
        pinfo.cols.info:append(" [#COM stale]")
    end
    return val
end

------------------------------------------------------------------------
-- Routing header
-- spec §4.6 (Routing Header — Name Slot Ordering): slot 2 is the
-- destination, slot 4 is the source, for ALL message types. Verified
-- across a large corpus. The IdentifyBlock body's
-- first TLV agrees with slot 4 (sender's self-name).
------------------------------------------------------------------------

-- Parses [dir][BLN\0][slot2\0][BLN\0][slot4\0]. Returns body offset.
local function dissect_routing(tvb, tree, msg_type)
    local rtree = tree:add(p2, tvb, "Routing Header")
    rtree:add(f.dir_byte, tvb(0, 1))
    local fields = { f.bln1, f.dst_node, f.bln2, f.src_node }
    local off = 1
    for _, field in ipairs(fields) do
        local s, n = read_cstring(tvb, off)
        if not s then return nil end
        rtree:add(field, tvb(off, n - 1), s)
        if field == f.dst_node then
            rtree:add(f.node_a, tvb(off, n - 1), s)
        elseif field == f.src_node then
            rtree:add(f.node_b, tvb(off, n - 1), s)
        end
        off = off + n
    end
    rtree:set_len(off)
    return off
end

------------------------------------------------------------------------
-- Identity block (0x4640) — also the body of CONNECT/ANNOUNCE handshakes
-- and mid-session identity refreshes inside any msg type.
------------------------------------------------------------------------

local function dissect_identify(tvb, tree, pinfo)
    local strings = extract_lp_strings(tvb)
    local labels = { f.scanner_name, f.site_name, f.network_name }
    for i, s in ipairs(strings) do
        if i <= #labels then
            tree:add(labels[i], tvb(s.offset + 3, s.length - 3), s.value)
        end
    end
    if #strings >= 1 then
        pinfo.cols.info:append(" scanner=" .. strings[1].value)
    end

    -- Embedded Unix epoch timestamp lives at offset (len-7..len-4) of the
    -- identity payload — see spec §9.9. The byte
    -- before is always 0x00 padding. PXC may validate this; scanners send
    -- int(time.time()) here.
    local len = tvb:len()
    if len >= 7 then
        local ts_off = len - 7
        -- Sanity: leading pad byte must be 0x00 and the resulting epoch
        -- must look plausible (after 2010, before 2070).
        if tvb(ts_off, 1):uint() == 0x00 then
            local epoch = tvb(ts_off + 1, 4):uint()
            if epoch >= 1262304000 and epoch <= 3155760000 then
                local ts = NSTime.new(epoch, 0)
                tree:add(f.id_timestamp, tvb(ts_off + 1, 4), ts)
            end
        end
    end
end

------------------------------------------------------------------------
-- Alarm-record dissector for 0x0508 (PXC->DCC) and 0x0509 (DCC->PXC).
------------------------------------------------------------------------

local function dissect_alarm_record(body, tree, pinfo)
    if body:len() < 10 then return end

    local strings = extract_lp_strings(body)
    if #strings >= 1 then
        tree:add(f.alarm_class,
            body(strings[1].offset + 3, strings[1].length - 3),
            strings[1].value)
    end

    -- Subsequent LP-strings: typically [point_name][point_name][description]
    local data_strings = {}
    for i = 2, #strings do
        table.insert(data_strings, strings[i])
    end
    if #data_strings >= 1 then
        tree:add(f.alarm_point,
            body(data_strings[1].offset + 3, data_strings[1].length - 3),
            data_strings[1].value)
        pinfo.cols.info:append(string.format(" point=%s", data_strings[1].value))
    end
    if #data_strings >= 3 then
        tree:add(f.alarm_description,
            body(data_strings[3].offset + 3, data_strings[3].length - 3),
            data_strings[3].value)
    end

    -- Optional 4-char ASCII marker between two zero-pad runs (only in 0x0508)
    for i = 4, body:len() - 4 do
        local b1, b2, b3, b4 = body(i,1):uint(), body(i+1,1):uint(),
                               body(i+2,1):uint(), body(i+3,1):uint()
        if b1 >= 0x41 and b1 <= 0x7A
           and b2 >= 0x41 and b2 <= 0x7A
           and b3 >= 0x41 and b3 <= 0x7A
           and b4 >= 0x41 and b4 <= 0x7A
           and body(i-4, 4):uint() == 0
        then
            tree:add(f.alarm_marker, body(i, 4), body(i, 4):string())
            break
        end
    end

    -- Hunt for BACnet datetime blocks (8 bytes each); first three are
    -- typically raise / current / last-transition.
    local dt_count = 0
    local dt_labels = { f.alarm_time_raised, f.alarm_time_now, f.alarm_time_last }
    local i = 0
    while i + 8 <= body:len() and dt_count < #dt_labels do
        local ts = decode_bacnet_datetime(body, i)
        if ts then
            tree:add(dt_labels[dt_count + 1], body(i, 8), ts)
            dt_count = dt_count + 1
            i = i + 8
        else
            i = i + 1
        end
    end
end

------------------------------------------------------------------------
-- 0x010C SystemInfo response decoder
------------------------------------------------------------------------

local function dissect_sysinfo_response(tvb, tree, pinfo)
    -- Strings here are typically u16-BE-prefixed (per scanner code paths).
    -- Fall back to LP-strings if u16 fails.
    local strings = extract_u16lp_strings(tvb)
    if #strings == 0 then
        strings = extract_lp_strings(tvb)
    end
    local fields = { f.sysinfo_model, f.sysinfo_firmware, f.sysinfo_build }
    for i, s in ipairs(strings) do
        if i <= #fields then
            local val_off = (s.length == 2 + #s.value) and (s.offset + 2)
                                                       or  (s.offset + 3)
            tree:add(fields[i], tvb(val_off, #s.value), s.value)
        end
    end
    if #strings >= 1 then
        pinfo.cols.info:append(" model=" .. strings[1].value)
    end
    if #strings >= 2 then
        pinfo.cols.info:append(" fw=" .. strings[2].value)
    end
end

------------------------------------------------------------------------
-- 0x099F GetPortConfig
-- Request body: 09 9F 00 04 XX  (5 bytes total; XX = port index)
-- Response: TLV strings — three dot-separated config rows + a port label.
------------------------------------------------------------------------

local function dissect_port_config(tvb, tree, pinfo, is_request)
    if is_request and tvb:len() >= 3 then
        -- Request: skip 2-byte separator, then port index byte
        tree:add(f.port_index, tvb(2, 1))
        pinfo.cols.info:append(string.format(" port=0x%02X", tvb(2, 1):uint()))
    else
        local strings = extract_lp_strings(tvb)
        for _, s in ipairs(strings) do
            -- Last string in a typical response is the human label
            -- ("USB Modem port", "HMI port"); earlier ones are config rows.
            if not s.value:find(";") and #s.value > 2 then
                tree:add(f.port_label, tvb(s.offset + 3, s.length - 3), s.value)
                pinfo.cols.info:append(" label=\"" .. s.value .. "\"")
            else
                tree:add(p2, tvb(s.offset, s.length), "Config: " .. s.value)
            end
        end
    end
end

------------------------------------------------------------------------
-- 0x4634 RoutingTable — list of {LP-name, u32 BE cost} entries.
------------------------------------------------------------------------

local function dissect_routing_table(tvb, tree, pinfo)
    local stree = tree:add(p2, tvb, "Routing Table Entries")
    local i = 0
    local count = 0
    local len = tvb:len()
    while i + 7 < len do
        -- TLV header: tag 0x01 + u16 BE length (spec §9.2).
        if tvb(i, 1):uint() == 0x01 then
            local slen = tvb(i+1, 2):uint()
            if slen > 0 and slen < 64 and (i + 3 + slen + 4) <= len then
                local s = tvb(i+3, slen):string()
                if s:match("^[%w%p%s|]*$") then
                    local cost = tvb(i + 3 + slen, 4):uint()
                    -- First-TLV invariant per spec §12.10:
                    -- the first entry MUST be $paneldefault. Flag and
                    -- bail on anything else so a malformed/forged frame
                    -- doesn't get rendered as if it were valid topology.
                    if count == 0 and s ~= "$paneldefault" then
                        stree:add_expert_info(PI_PROTOCOL, PI_WARN,
                            "First routing-table TLV is not $paneldefault — "
                            .. "frame is malformed (spec §12.10)")
                        return
                    end
                    local etree = stree:add(p2, tvb(i, 3 + slen + 4),
                        string.format("%s = %u", s, cost))
                    etree:add(f.rt_peer, tvb(i + 3, slen), s)
                    etree:add(f.rt_cost, tvb(i + 3 + slen, 4), cost)
                    i = i + 3 + slen + 4
                    count = count + 1
                else
                    i = i + 1
                end
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    if count > 0 then
        pinfo.cols.info:append(string.format(" (%d peers)", count))
    end
end

------------------------------------------------------------------------
-- Schedule-write decoder (0x098D / 0x5020) — best-effort surface of the
-- schedule name, BACnet date entries, and f32 setpoints. Full structure
-- per spec §12.17 (Schedule Operations).
------------------------------------------------------------------------

local function dissect_schedule_payload(tvb, tree, pinfo)
    local strings = extract_lp_strings(tvb)
    if #strings >= 1 then
        local s = strings[1]
        tree:add(f.sched_name, tvb(s.offset + 3, s.length - 3), s.value)
        pinfo.cols.info:append(" sched=" .. s.value)
    end
    -- Walk for plausible 4-byte BACnet dates and f32-shaped setpoints.
    local i = 0
    local len = tvb:len()
    while i + 4 <= len do
        local d = decode_bacnet_date4(tvb, i)
        if d then
            tree:add(f.sched_date, tvb(i, 4), d)
            i = i + 4
        else
            i = i + 1
        end
    end
end

------------------------------------------------------------------------
-- Generic name/point extractor used by simple read-shaped requests
------------------------------------------------------------------------

local function dissect_name_pair(rest, tree, pinfo)
    local strings = extract_lp_strings(rest)
    if #strings >= 2 then
        tree:add(f.device_name,
            rest(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
        tree:add(f.point_name,
            rest(strings[2].offset + 3, strings[2].length - 3), strings[2].value)
        pinfo.cols.info:append(string.format(" %s/%s",
            strings[1].value, strings[2].value))
    elseif #strings == 1 then
        tree:add(f.point_name,
            rest(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
        pinfo.cols.info:append(string.format(" (BLN virtual) %s", strings[1].value))
    end
end

------------------------------------------------------------------------
-- Value-update opcodes (0x0274 ValuePush, 0x0240 WriteWithQuality).
-- Empirically validated against this capture's 5033 / 5034 traffic:
--
-- 0x0274 PXC->DCC (5034): 02 74 [00 01 00 00] [LP device] [LP point] [f32 BE]
-- 0x0274 DCC->PXC (5033): 02 74 [00 01 00 00] [LP point] [01 00 00] [f32 BE]
-- 0x0240 PXC->DCC (5034): 02 40 [LP "NONE"] 00 [3FFFFFFF] 00 00 [LP point]
--                         01 00 00 00 00 01 00 00 01 00 00 [f32 BE]
--
-- For 0x0274 we can place the float at the byte after the last LP-string.
-- For 0x0240 we walk forward to find a `01 00 00` marker preceded by ASCII
-- and read 4 bytes at marker+11 (slightly different layout from R1/R2/R3
-- read responses).
------------------------------------------------------------------------

local function dissect_value_update(rest, tree, pinfo, opcode, src_port)
    local strings = extract_lp_strings(rest)
    if #strings == 0 then return end

    if opcode == 0x0274 then
        -- Branch on the wire shape rather than the port: PXC->DCC carries
        -- two LP-strings (device + point); DCC->PXC carries one (point
        -- only). This is more reliable than port-checking — Mode C flows
        -- can put DCC->5033 PXC traffic on either side.
        if #strings >= 2 then
            tree:add(f.device_name,
                rest(strings[1].offset + 3, strings[1].length - 3),
                strings[1].value)
            tree:add(f.point_name,
                rest(strings[2].offset + 3, strings[2].length - 3),
                strings[2].value)
            local foff = strings[2].offset + strings[2].length
            if foff + 4 <= rest:len() then
                tree:add(f.float_value, rest(foff, 4))
                pinfo.cols.info:append(string.format(" %s/%s = %g",
                    strings[1].value, strings[2].value, rest(foff, 4):float()))
            else
                pinfo.cols.info:append(string.format(" %s/%s",
                    strings[1].value, strings[2].value))
            end
        else
            -- DCC->PXC push-write: just a point name; float sits 3 bytes
            -- past the LP-string end (skipping the `01 00 00` empty TLV).
            tree:add(f.point_name,
                rest(strings[1].offset + 3, strings[1].length - 3),
                strings[1].value)
            local foff = strings[1].offset + strings[1].length + 3
            if foff + 4 <= rest:len() then
                tree:add(f.float_value, rest(foff, 4))
                pinfo.cols.info:append(string.format(" (BLN-push) %s = %g",
                    strings[1].value, rest(foff, 4):float()))
            else
                pinfo.cols.info:append(string.format(" (BLN-push) %s",
                    strings[1].value))
            end
        end

    elseif opcode == 0x0240 then
        -- Device is literally "NONE" for panel-globals; point follows.
        if #strings >= 2 then
            tree:add(f.device_name,
                rest(strings[1].offset + 3, strings[1].length - 3),
                strings[1].value)
            tree:add(f.point_name,
                rest(strings[2].offset + 3, strings[2].length - 3),
                strings[2].value)
            -- Look for the value-block marker after the point name. Per
            -- spec §12.6, the f32
            -- sits 11 bytes past the FIRST `01 00 00` marker that follows
            -- the point TLV — different from the R1/R2/R3 read-response
            -- shape, so don't reuse find_value_block here.
            local scan_from = strings[2].offset + strings[2].length
            local found = nil
            for j = scan_from, rest:len() - 14 do
                if  rest(j, 1):uint()   == 0x01
                and rest(j+1, 1):uint() == 0x00
                and rest(j+2, 1):uint() == 0x00 then
                    found = j
                    break
                end
            end
            if found and found + 15 <= rest:len() then
                tree:add(f.float_value, rest(found + 11, 4))
                pinfo.cols.info:append(string.format(" %s/%s = %g",
                    strings[1].value, strings[2].value,
                    rest(found + 11, 4):float()))
            else
                pinfo.cols.info:append(string.format(" %s/%s",
                    strings[1].value, strings[2].value))
            end
        end
    end
end

------------------------------------------------------------------------
-- Body dispatcher: dispatches operational opcodes regardless of which
-- msg type carries them (0x33, 0x34, or Mode C 0x2E/0x2F).
------------------------------------------------------------------------

local function dispatch_request(opcode, rest, btree, pinfo, src_port)
    if opcode == 0x0271 or opcode == 0x0220 or opcode == 0x0272
            or opcode == 0x0273 or opcode == 0x0241 or opcode == 0x0244 then
        dissect_name_pair(rest, btree, pinfo)

    elseif opcode == 0x4640 then
        dissect_identify(rest, btree, pinfo)

    elseif opcode == 0x0508 or opcode == 0x0509 then
        dissect_alarm_record(rest, btree, pinfo)

    elseif opcode == 0x010C then
        -- Empty-body request (`01 0C` only). Nothing to decode here.

    elseif opcode == 0x099F then
        dissect_port_config(rest, btree, pinfo, true)

    elseif opcode == 0x4634 then
        dissect_routing_table(rest, btree, pinfo)

    elseif opcode == 0x4636 or opcode == 0x4647 then
        -- Two body shapes observed for this opcode-class:
        --   1) SYST-wildcard pattern body `01 00 04 'SYST' 23 3F FF FF FF`.
        --      Flagged inline so analysts can spot it.
        --   2) ReplChanges body containing <name, IP> records wrapped
        --      in sub-opcode 0x462D. Decoded record-by-record below.
        if rest:len() >= 9 then
            local first9 = rest(0, 9):bytes():tohex()
            local SYST_WILDCARD = "010004535953542333FFFFFF"
            if string.find(string.upper(first9 .. (rest:len() >= 12 and rest(9, 3):bytes():tohex() or "")),
                           SYST_WILDCARD, 1, true) then
                btree:add(p2, rest(0, math.min(12, rest:len())),
                    string.format("SYST-wildcard pattern body on opcode 0x%04X", opcode))
                pinfo.cols.info:append(string.format(" [SYST-wildcard 0x%04X]", opcode))
            else
                -- Look for ReplChanges body marker: sub-opcode 0x462D appearing
                -- within first ~50 bytes. If present, the body is a
                -- peer-table push containing <name, IP> records.
                if rest:len() >= 30 then
                    local scan_end = math.min(80, rest:len() - 2)
                    local found_462d = false
                    for scan_i = 0, scan_end do
                        if rest(scan_i, 2):uint() == 0x462D then
                            found_462d = true
                            break
                        end
                    end
                    if found_462d then
                        btree:add(p2, rest(0, math.min(40, rest:len())),
                            "0x4636 ReplChanges: BLN-wide peer-table push (body carries <name, IP> records via sub-opcode 0x462D)")
                        pinfo.cols.info:append(" [ReplChanges push]")
                        -- Surface any name strings found in the body
                        local strings = extract_lp_strings(rest)
                        if #strings >= 1 then
                            local raw = ""
                            for idx, s in ipairs(strings) do
                                if idx > 8 then raw = raw .. ", ..."; break end
                                if idx > 1 then raw = raw .. ", " end
                                raw = raw .. s.value
                            end
                            btree:add(f.lp_strings, rest, raw)
                        end
                    end
                end
            end
        end

    elseif opcode == 0x464A or opcode == 0x464B or opcode == 0x464C then
        -- Peer-table write opcodes. Surface the peer-name string from the
        -- body so the analyst can see what's being written.
        btree:add(p2, rest(0, math.min(16, rest:len())),
            "Peer-table write — registers peer-name in BLN peer table via replication")
        pinfo.cols.info:append(string.format(" [peer-write 0x%04X]", opcode))
        local strings = extract_lp_strings(rest)
        if #strings >= 1 then
            btree:add(f.lp_strings, rest, strings[1].value)
            pinfo.cols.info:append(string.format(" name=%s", strings[1].value))
        end

    elseif opcode == 0x464D then
        -- BLN topology query. Empty body in the request; the response is
        -- a ~2KB body containing the BLN peer inventory.
        btree:add(p2, rest(0, math.min(2, rest:len())),
            "BLN topology query (response carries peer inventory)")
        pinfo.cols.info:append(" [topology-query]")

    elseif opcode == 0x0274 or opcode == 0x0240 then
        dissect_value_update(rest, btree, pinfo, opcode, src_port)

    elseif opcode == 0x4222 or opcode == 0x4221 or opcode == 0x4220
            or opcode == 0x4200 or opcode == 0x02A8 or opcode == 0x0291
            or opcode == 0x0294 or opcode == 0x0295 then
        -- SYST/device/point read or write — surface strings; value
        -- breakout differs across these and isn't fully byte-mapped yet.
        local strings = extract_lp_strings(rest)
        if #strings >= 1 then
            local raw = ""
            for i, s in ipairs(strings) do
                if i > 1 then raw = raw .. ", " end
                raw = raw .. s.value
            end
            btree:add(f.lp_strings, rest, raw)
            pinfo.cols.info:append(" " .. raw)
        end

    elseif opcode == 0x098C or opcode == 0x098D
            or opcode == 0x098E or opcode == 0x098F
            or opcode == 0x5020 or opcode == 0x5022 or opcode == 0x5003 then
        dissect_schedule_payload(rest, btree, pinfo)

    elseif opcode == 0x4100 or opcode == 0x4103
            or opcode == 0x4104 or opcode == 0x4106 then
        -- PPCL editor: first LP-string is the program name
        local strings = extract_lp_strings(rest)
        if #strings >= 1 then
            btree:add(f.point_name,
                rest(strings[1].offset + 3, strings[1].length - 3),
                strings[1].value)
            pinfo.cols.info:append(string.format(" prog=%s", strings[1].value))
        end

    else
        -- Generic: dump strings for analysis
        local strings = extract_lp_strings(rest)
        if #strings > 0 then
            local raw = ""
            for i, s in ipairs(strings) do
                if i > 1 then raw = raw .. ", " end
                raw = raw .. s.value
            end
            btree:add(f.lp_strings, rest, raw)
        end
    end
end

------------------------------------------------------------------------
-- Per-frame dissector
------------------------------------------------------------------------

-- Helper: does the body start with an 0x4640 IdentifyBlock marker? Used
-- to distinguish CONNECT/ANNOUNCE handshake (or mid-session identity
-- refresh) from Mode C operational opcode framing — see the protocol spec
-- "Three connection modes" / "Implementation note".
local function body_is_identify(body)
    return body:len() >= 2
       and body(0, 1):uint() == 0x46
       and body(1, 1):uint() == 0x40
end

local function dissect_one_frame(tvb, pinfo, root)
    local total_len = tvb(0, 4):uint()
    local msg_type  = tvb(4, 4):uint()
    local sequence  = tvb(8, 4):uint()

    -- src_port lets value-update opcodes branch on the listening port
    -- (0x0274 has direction-dependent wire format; see the protocol spec).
    local src_port = pinfo.src_port or 0

    local tree = root:add(p2, tvb(0, total_len), "Siemens P2")

    local htree = tree:add(p2, tvb(0, 12), "Frame Header")
    htree:add(f.total_len, tvb(0, 4))
    htree:add(f.msg_type,  tvb(4, 4))
    htree:add(f.sequence,  tvb(8, 4))

    pinfo.cols.protocol = "P2"
    local mt_label = MSG_TYPES[msg_type] or string.format("0x%X", msg_type)
    pinfo.cols.info:set(string.format("seq=%d %s", sequence, mt_label))

    if total_len <= 12 then
        return total_len
    end

    local payload = tvb(12, total_len - 12)
    if payload:len() < 1 then
        return total_len
    end

    local dir_byte = payload(0, 1):uint()

    -- Routing header (always present in DATA/HEARTBEAT/CONNECT/ANNOUNCE)
    local body_off = dissect_routing(payload, tree, msg_type)
    if not body_off then return total_len end

    local is_op_carrier = (msg_type == 0x33) or (msg_type == 0x34)
    local is_handshake_carrier = (msg_type == 0x2E) or (msg_type == 0x2F)

    if not is_op_carrier and not is_handshake_carrier then
        pinfo.cols.info:append(" [" .. (DIR_BYTES[dir_byte] or "?") .. "]")
        return total_len
    end

    if payload:len() <= body_off + 2 then
        -- Bare-opcode session ping or pure ACK; nothing further to parse.
        return total_len
    end

    local body = payload(body_off, payload:len() - body_off)

    -- For CONNECT/ANNOUNCE, the body is normally a 0x4640 IdentifyBlock —
    -- but in Mode C headless flows it can be an operational opcode instead.
    -- Discriminate on the first 2 bytes after the routing header.
    if is_handshake_carrier and body_is_identify(body) then
        local btree = tree:add(p2, body, "IdentifyBlock (handshake/refresh)")
        btree:add(f.opcode, body(0, 2))
        local rest = body(2, body:len() - 2)
        dissect_identify(rest, btree, pinfo)
        pinfo.cols.info:append(" [Identify]")
        return total_len
    end

    -- Mode C tag for non-identify 0x2E/0x2F frames so the user can see at a
    -- glance that operational ops are riding inside CONNECT/ANNOUNCE framing.
    if is_handshake_carrier then
        pinfo.cols.info:append(" [Mode C]")
    end

    -- Unified opcode dispatcher (handles both 0x33/0x34 DATA/HEARTBEAT and
    -- Mode C operational frames). Opcodes appear on requests (dir=0x00);
    -- responses are matched to requests by sequence number, so we dispatch
    -- on the direction byte for response decoding.
    if dir_byte == 0x00 then
        local opcode = body(0, 2):uint()
        local op_name = OPCODES[opcode] or string.format("unknown_0x%04X", opcode)
        local btree = tree:add(p2, body, "Request — " .. op_name)
        btree:add(f.opcode, body(0, 2))
        pinfo.cols.info:append(string.format(" %s [Request]", op_name))

        local rest = body(2, body:len() - 2)
        dispatch_request(opcode, rest, btree, pinfo, src_port)

    elseif dir_byte == 0x05 then
        -- Error response: u16 BE error code immediately after routing
        local btree = tree:add(p2, body, "Error Response")
        if body:len() >= 2 then
            btree:add(f.error_code, body(0, 2))
            local code = body(0, 2):uint()
            local name = STATUS_ERRORS[code] or string.format("unknown_0x%04X", code)
            pinfo.cols.info:append(" [ERROR " .. name .. "]")
        end

    else
        -- Success response (dir=0x01). No opcode echo; shape depends on
        -- which request it answers. Heuristics:
        --   * find_value_block hit -> ReadProperty response
        --   * else                 -> identify echo / sysinfo / generic
        local btree = tree:add(p2, body, "Success Response")
        local vb = find_value_block(payload)
        if vb then
            local pre = payload(0, vb)
            local strings = extract_lp_strings(pre)
            if #strings >= 2 then
                local sd = strings[#strings - 1]
                local sp = strings[#strings]
                btree:add(f.device_name, payload(sd.offset + 3, sd.length - 3), sd.value)
                btree:add(f.point_name,  payload(sp.offset + 3, sp.length - 3), sp.value)
                pinfo.cols.info:append(string.format(" %s/%s", sd.value, sp.value))
            end
            local val = dissect_value_block(payload, vb, btree, pinfo)
            pinfo.cols.info:append(string.format(" = %g", val))
            -- Units after value block
            if payload:len() > vb + 14 then
                local after = payload(vb + 14, payload:len() - vb - 14)
                local units_strings = extract_lp_strings(after)
                if #units_strings >= 1 then
                    local u = units_strings[1]
                    btree:add(f.units, after(u.offset + 3, u.length - 3), u.value)
                    pinfo.cols.info:append(" " .. u.value)
                end
            end
        else
            -- No value block — try LP-strings first, fall back to u16-LL.
            -- Special-case: if it looks like a sysinfo response (carries a
            -- recognizable model string), break it out properly.
            local strings = extract_lp_strings(body)
            if #strings == 0 then
                strings = extract_u16lp_strings(body)
            end
            local looks_sysinfo = false
            for _, s in ipairs(strings) do
                if s.value:find("PME%d") or s.value:find("APOGEE")
                        or s.value:find("PXME") then
                    looks_sysinfo = true
                    break
                end
            end
            if looks_sysinfo then
                dissect_sysinfo_response(body, btree, pinfo)
            elseif #strings > 0 then
                local raw = ""
                for i, s in ipairs(strings) do
                    if i > 1 then raw = raw .. ", " end
                    raw = raw .. s.value
                end
                btree:add(f.lp_strings, body, raw)
                pinfo.cols.info:append(" [" .. raw .. "]")
            end
        end
    end

    return total_len
end

------------------------------------------------------------------------
-- Top-level TCP dissector with reassembly
------------------------------------------------------------------------

function p2.dissector(tvb, pinfo, tree)
    local offset = 0
    local len = tvb:len()
    if len < 12 then
        pinfo.desegment_offset = 0
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    while offset + 12 <= len do
        local total_len = tvb(offset, 4):uint()
        if total_len < 12 or total_len > 65536 then
            return
        end
        if offset + total_len > len then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = (offset + total_len) - len
            return
        end
        dissect_one_frame(tvb(offset, total_len), pinfo, tree)
        offset = offset + total_len
    end
end

------------------------------------------------------------------------
-- UDP/10001 multicast presence beacon
-- spec §3.2.2 (Multicast Presence Beacon).
-- Payload is invariant across the corpus: 4 bytes 01 00 00 00.
-- Dual-emitted to both 233.89.188.1 and 255.255.255.255 with sub-millisecond
-- delta. Cadence ~10.5s. Carries no node/site/BLN info — pure presence.
------------------------------------------------------------------------

function p2b.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len ~= 4 then
        return 0  -- not our beacon
    end
    local hex = tvb(0, 4):bytes():tohex():lower()

    pinfo.cols.protocol = "P2-Beacon"
    local subtree = tree:add(p2b, tvb(0, len), "Siemens P2 BLN Presence Beacon")
    subtree:add(f.beacon_payload, tvb(0, 4))

    if hex == BEACON_PAYLOAD_HEX then
        pinfo.cols.info:set("BLN presence beacon (01 00 00 00)")
    else
        pinfo.cols.info:set("BLN beacon (unexpected payload " .. hex .. ")")
        subtree:add_expert_info(PI_PROTOCOL, PI_NOTE,
            "Unexpected beacon payload — corpus has zero variation in 1040 samples")
    end
    return len
end

------------------------------------------------------------------------
-- Bind to the known P2 ports
------------------------------------------------------------------------

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(5033, p2)
tcp_table:add(5034, p2)

local udp_table = DissectorTable.get("udp.port")
udp_table:add(10001, p2b)
