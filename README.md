# Siemens APOGEE P2 (Protocol II) Wireshark Dissector

A Lua dissector for Wireshark that decodes the Siemens APOGEE **P2** (Protocol II)
building-automation protocol over TCP. Built and validated from wire captures; the
opcode names are the protocol's authoritative AP2 function-code vocabulary.

> **v2.5 — response correlation + more body decoders.** Responses carry no opcode on the
> wire (only requests do) but echo their request's sequence; the dissector now keeps a
> per-TCP-stream `{sequence → opcode}` map and **labels and decodes responses** — the
> `CABINET_DISPLAY` firmware banner (revision / platform / build date / node-site-BLN), the
> value responses (point name + engineering-units + value), and the identity exchange. New
> request decoders too: the addressing family — point read/command, COV enable/disable,
> trend, bulk upload (scope tag + name + suffix + commanded value) — and `ALARM_PRINT`
> (`0x0508`) with its value block and three 8-byte event timestamps. Validated with zero
> Lua errors across a ~530k-frame corpus.
>
> **v2.2 — message-class model corrected from fleet captures.** The message classes are
> legacy/modern **pairs chosen by a panel's firmware generation, not by direction**:
> data `0x33` (legacy) / `0x34` (modern); second channel `0x2E` / `0x2F` (identity +
> DB-change/replication records + alarm prints); peer carriers `0x29` / `0x2A`
> (panel↔panel, visible only from a panel-side mirror). Fingerprint a panel with
> `CABINET_DISPLAY` (`0x010C`) and pick the dialect from its firmware. Also: COV
> condition byte0/byte1 (priority/control-status) wire-confirmed; sequence is
> per-(peer,channel) with gaps (not one global counter); `UPL_ALL_*` continuation is
> application-layer cursoring, not a frame more-follows bit; event timestamps are 8 bytes
> (`yr-1900, mo, day, day-of-week, hr, min, sec, cs`).
>
> **v2.1 — wire-verified rebuild.** Opcode names corrected to the full authoritative
> set; the framing model fixed (the opcode is read only on request frames, at its true
> variable offset); accurate body decoders for the common operations; per-opcode
> *expected-body schema* notes; and the old UDP/10001 "multicast presence beacon"
> decoder **removed** (it was a misattribution of unrelated gateway traffic — see
> *Correctness notes*).

## What it does

Click a P2 packet and get:

- **Frame header** — total length, message class, sequence, direction
- **Routing slots** — the four NUL-terminated ASCII slots `[BLN, dst-node, BLN, src-node]`
- **Opcode** — the 2-byte AP2 function code, labelled against the full authoritative
  name set; an opcode that isn't a defined function code shows as `unknown_0x….`
- **Per-opcode body** — wire-verified decoders for the common operations:
  - **COV value push** (`0x0274`) — point name, present value (`f32` BE), and the
    10-byte condition/priority block split into its named fields
    (priority, control status, out-of-service / failed / proof / disabled / commanded
    flags, alarm state, alarm priority)
  - **Node-name-table replication** (`0x4634`) — the roster digest: each node name
    plus its version (change generation)
  - **Identity / keepalive exchange** (`0x4640`, `EBLN_PING`) — node / site / BLN identity,
    on session-establish and on the ~10-second heartbeat
  - **Addressing-family requests** — point read/command (`0x0220`/`0x0240`/`0x0241`), COV
    enable/disable (`0x0271`/`0x0273`), trend and bulk upload: scope tag + command priority,
    name + suffix, and (for commands) the `f32` value
  - **Alarm reports** (`0x0508`) — point + descriptor, the value block, and the event
    timestamps
  - **Responses** — correlated to their request by sequence and decoded: the
    `CABINET_DISPLAY` firmware banner, value/read results, and the identity block
  - **Scope tag + command priority**, **error codes**, and a generic TLV / value walk
    for everything else
- **Expected-body schema** — for ~440 opcodes, a `[struct-derived]` note listing the
  fields the body is expected to contain (see *Schema notes* below)

## Install

1. **Help → About Wireshark → Folders → "Personal Lua Plugins"**
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux / macOS: `~/.local/lib/wireshark/plugins/`
2. Drop `p2.lua` into that folder
3. **Analyze → Reload Lua Plugins** (`Ctrl+Shift+L`) or restart Wireshark

The Protocol column shows `P2` on TCP/5033 and TCP/5034 traffic. You can also load it
ad hoc: `tshark -X lua_script:p2.lua -r capture.pcapng`.

## Ports

- **TCP/5033** is the canonical, default P2 port — every field panel (and the
  supervisor) listens here for inbound P2.
- **TCP/5034** is, in some deployments, a second supervisor-side listener carrying the
  panel→supervisor push/announce (reverse) channel. It is optional and
  deployment-specific; the protocol on it is identical to 5033.

The dissector binds both. For any other port, use **Analyze → Decode As…** to map it to
`P2`. Frame semantics derive from the frame's contents and direction, never from the TCP
port it arrived on.

## Coverage at a glance

- **Message classes** — a session / second-channel band: `0x29` / `0x2A` (peer carriers,
  panel↔panel), `0x2E` / `0x2F` (legacy / modern second channel — identity +
  DB-change/replication records + alarm prints), all carrying the `EBLN_PING 0x4640`
  identity exchange; and a data band, `0x33` (legacy) / `0x34` (modern). The pairs are
  chosen by a panel's firmware generation, not by direction.
- **Opcodes** — the complete authoritative AP2 function-code set is named. The common
  operations are byte-decoded; the rest show their name + expected-body schema + a
  generic body walk.
- **Errors** — `0x0003` not_found, `0x00AC` not_supported, `0x0E15` not_commandable,
  `0x0002` out_of_scope, `0x0E11` already_exists, `0x0E12`.
- **Values** — big-endian `f32`; the COV condition/priority block decoded field by field.

## Correctness notes

- **The opcode is present only on request/push frames (direction `0x00`)**, and it sits
  at a *variable* offset (immediately after the four NUL-terminated routing slots). The
  dissector scans the four NULs rather than assuming a fixed offset — reading the
  post-slot bytes off a success/error response would fabricate phantom opcodes.
- **There is no multicast "presence beacon."** Earlier versions decoded UDP/10001 to
  `233.89.188.1` as a Siemens P2 beacon; that traffic is actually unrelated
  gateway/heartbeat multicast, not P2. The real, *optional* Ethernet-BLN availability
  multicast is `234.5.6.7:8` and is **disabled by default** — a peer-liveness heartbeat,
  not a discovery mechanism. The decoder has been removed to avoid false positives.
- Routing-slot ordering is destination-first within the request direction; the BLN-name
  slot is the membership/admission key.

## Schema notes

For opcodes whose request body is defined by the AP2 type system, the dissector shows
an **expected-body schema** — the field list the body *should* contain. This is a
struct-derived aid, **not** a guaranteed byte layout: P2's body encoding uses TLV
framing, scope tags, and field widths that are only fully pinned for the wire-verified
opcodes. As live captures confirm an opcode's exact layout, its schema note is upgraded
to a real, byte-level field decode (as already done for COV, the replication roster, and
the identity exchange). Treat un-upgraded schema fields as expectations, not decoded
bytes.

## Useful tshark one-liner

Heuristic to spot Siemens PXC field panels in a capture without decoding payloads — PXCs
(Nucleus NET RTOS) characteristically emit `TTL=64` with a small fixed TCP window:

```bash
tshark -r capture.pcapng -Y "tcp.flags.syn==1" \
    -T fields -e ip.src -e ip.ttl -e tcp.window_size_value | sort -u
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests welcome — especially captures that
let an expected-body schema be promoted to a verified byte decoder (a point in alarm or
held under command, a node-name-table change, a large upload), new bespoke body
decoders, and edge-case fixes.

## License

MIT. See `LICENSE`.

This dissector is a third-party analytical tool built from observed traffic for owner-
operators of their own equipment. It is not affiliated with or endorsed by Siemens.
