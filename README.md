# Siemens APOGEE P2 Wireshark Dissector

A Lua dissector for Wireshark that decodes the Siemens APOGEE P2 building-automation protocol — the management/data protocol spoken between Desigo CC or Insight supervisors and APOGEE PXC field panels. Decodes TCP/5033 into a navigable protocol tree with routing-header breakouts, opcode-level dispatch, and per-opcode value/string extraction.

## What it does

Click a packet on TCP/5033 and get:

- **Frame header** — total length, message type (DATA / HEARTBEAT / CONNECT / ANNOUNCE / inter-panel ANNOUNCE), sequence counter
- **Routing header** — direction byte, BLN (Building Local Network) name, destination panel name, source panel name
- **Opcode** — labelled against a catalog of 100+ known opcodes covering reads, writes, point enumerates, PPCL editor ops, schedule operations, alarm pair, system info, and replication ops
- **Per-opcode body decode** — depending on opcode:
  - Point reads → device name / point name / float value / units / comm-status (live vs stale-cache) / data-type
  - Alarms → alarm class, point, description, three BACnet datetime stamps, marker, alarm-time value
  - Schedules → schedule name, BACnet date entries, f32 setpoints
  - Identify (0x4640) → scanner name, site name, BLN name, embedded Unix epoch timestamp
  - Sysinfo (0x010C) → panel model, firmware string, build date
  - Routing table (0x4634) → peer list with costs, with `$paneldefault` first-entry invariant check
  - Replication ops (0x46xx) → ReplChanges body decode (per-record name surfacing via sub-opcode 0x462D), peer-table-write opcode name surfacing, topology-query labelling, SYST-wildcard body-pattern flagging
  - Value updates (0x0274 / 0x0240) → direction-aware decode (PXC→DCC carries device+point, DCC→PXC carries point only)
- **Multicast beacon** — UDP/10001 presence beacon, payload sanity-checked against the corpus invariant `01 00 00 00`

## Installation

1. Open Wireshark
2. **Help → About Wireshark → Folders → "Personal Lua Plugins"**. Common paths:
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux: `~/.local/lib/wireshark/plugins/`
   - macOS: `~/.local/lib/wireshark/plugins/`
3. Drop `p2.lua` into that folder
4. **Analyze → Reload Lua Plugins** (`Ctrl+Shift+L`) or restart Wireshark

Verify by opening any capture containing TCP/5033 traffic — the Protocol column should show `P2` and the packet detail pane should show the Siemens P2 tree.

## Port bindings

| Port | Protocol | Direction | Description |
|---|---|---|---|
| TCP/5033 | P2 (DATA / HEARTBEAT / CONNECT / ANNOUNCE) | supervisor ↔ panel | Main control channel |

If your environment uses non-standard ports, edit the `DissectorTable.get("tcp.port"):add(...)` calls at the bottom of `p2.lua` and reload.

## Coverage summary

### Message types (header byte 4–7)

| Code | Meaning |
|---|---|
| `0x29` | Inter-panel ANNOUNCE (post-restart BLN re-establishment) |
| `0x2E` | CONNECT (legacy handshake; carries Mode C operational ops) |
| `0x2F` | ANNOUNCE (modern dialect; supervisor-bound) |
| `0x33` | DATA (legacy dialect, dominant on TCP/5033) |
| `0x34` | HEARTBEAT (modern dialect / session maintenance) |

### Opcode categories decoded

- **System info / identity:** `0x0100`, `0x010C`, `0x4640`, `0x4634`, `0x0050`
- **Replication ops (0x46xx range):** `0x4633`, `0x4635`, `0x4636`, `0x4641`–`0x464D`, `0x464E`, `0x464F`, `0x4650` (ReplChanges push decode, peer-table-write surfacing, topology query)
- **Reads:** `0x0220`, `0x0271`–`0x0274` (with direction-aware decode)
- **Property writes:** `0x0240`, `0x0241`, `0x0291`, `0x02A8`, `0x4200`, `0x4220`–`0x4222`
- **Object lifecycle:** `0x0203`, `0x0204`, `0x0260`, `0x0263`
- **Point enumeration:** `0x0981`–`0x0989`, `0x099F`
- **Schedule operations:** `0x098C`–`0x098F`, `0x5003`, `0x5020`, `0x5022`, `0x5038`
- **PPCL editor:** `0x4100`, `0x4103`, `0x4104`, `0x4106`
- **Alarm pair:** `0x0508` (PXC→DCC), `0x0509` (DCC→PXC)
- **BarePings:** `0x0951`, `0x0954`–`0x0956`, `0x0959`
- **Error codes:** 37-entry catalog covering common (`0x0002` not_found, `0x0003` E3, `0x00AC` not_supported, `0x0E11` already_exists, etc.)

### Value-block decode

Read responses contain a 14-byte value block at a discoverable offset. The dissector decodes:

- `01 00 00` marker
- 4-byte sentinel (R1 quality flags `3F FF FF XX` or R2/R3 explicit `00 00 00 00`)
- Reserved byte (always `0x00` observed)
- Comm-status byte (`0x00` live, `0x01` STALE — flagged in Info column as `[#COM stale]`)
- Per-device error code OR data-type code (role depends on dialect)
- Big-endian f32 value
- Units string following the value block

The `[#COM stale]` flag is the device-level comm-fault indicator. PXCs return cached values indefinitely from comm-faulted devices; this byte is the only way to spot it without out-of-band knowledge.

## Notes on the protocol

Some observations that may be useful when reading captures or extending the dissector:

- **Routing-header name ordering is destination-first** across all message types (slot 2 = destination, slot 4 = source). The IdentifyBlock body's first TLV agrees with slot 4.
- **Node names are case-insensitive on the wire** but display is case-preserving — same name can appear as `NODE99` from one client and `node99` from another.
- **Mode C connections** carry operational opcodes inside `0x2E`/`0x2F` framing without ever transitioning to `0x33`/`0x34`. The dissector detects this by checking whether the first two bytes after the routing header are `0x4640` (IdentifyBlock — handshake) or something else (operational opcode riding inside handshake framing).
- **PPCL editor opcodes** (`0x4100`/`0x4103`/`0x4104`/`0x4106`) append a 9-byte SYST scope footer (`01 00 04 SYST 23 3F FF FF FF`) after the opcode-specific payload. Stripping the footer causes the panel to reject the request.
- **The 0x46xx replication-ops range** is a mixed bag: `0x4634` is the documented routing-table announce, `0x4636` is `ReplChanges` (BLN-wide peer-table push using sub-opcode `0x462D` records), and the gap opcodes `0x4641`–`0x464C` carry replication-related operations whose exact semantics are not all publicly documented. The dissector surfaces name strings from bodies where it can and labels what it knows.

## Unknowns and limitations

This dissector was built from observed traffic, not from a vendor-provided protocol specification. Several behaviors are best-effort:

- Some opcodes are labelled `Undocumented success-response` because the panel returns data but the body structure hasn't been fully decoded. Contributions welcome.
- The msg_type `0x29` semantics (inter-panel post-restart re-establishment) are inferred from observed flow patterns, not confirmed against documentation.
- Several `0x09xx` enumeration variants (`0x0983`, `0x0984`, `0x0987`, `0x0989`) return error `0x00AC` ("not supported") on the firmware versions observed; their request format is documented but their response format isn't.
- The 7-byte metadata block inside the value block has bytes at offset +9 whose role depends on dialect (legacy R1/R2 → error code; modern R3 → data-type code). The dissector adds both fields and lets you read whichever applies to the trace you're looking at.
- The dissector relies on heuristics (sentinel-shape checks, reserved-byte checks, ASCII-end-of-name checks) to discriminate real value blocks from `01 00 00` byte sequences embedded inside enumerate-response metadata. Edge cases may misclassify.

When the dissector labels an opcode `unknown_0xNNNN`, that's a candidate for further analysis. Add it to the `OPCODES` table in `p2.lua` and submit a PR with a brief description.

## Contributing

Pull requests welcome. If you have:

- A capture showing a new opcode that the dissector currently labels `unknown_0xNNNN`
- A correction to a current opcode label
- A better body-decode for an opcode currently using the generic LP-string fallback
- A capture exhibiting behavior the comments don't cover

…open an issue with the capture (or a relevant excerpt with site identifiers redacted) and what you observed. If you can share a one-paragraph description of the wire-format pattern, that's enough to extend the dissector.

When extending opcode coverage, please:

- Keep opcode entries in their existing category groupings in the `OPCODES` table
- Add a brief comment describing the wire-format pattern at the dissector logic site, not just the lookup entry
- If the opcode has direction-dependent behavior, branch on payload shape rather than on TCP port (Mode C flows can put either direction on either port)

## License

MIT. See `LICENSE`.

## Acknowledgments

Built from observed traffic captures. Opcode coverage cross-checked against publicly available Siemens product literature (BACnet ALN Manual 125-3020, public SSA disclosures, vendor data sheets). The Siemens APOGEE protocol family is proprietary to Siemens; this dissector is a third-party analytical tool and is not affiliated with or endorsed by Siemens.
