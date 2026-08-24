# Changelog

Release notes for the P2 dissector, scanner and protocol reference.
The current release is summarised at the top of [README.md](README.md).

> Entries below v2.7 are kept as written at the time. Figures in them reflect
> what was believed then; where a later release corrected one, the correction is
> in that release's entry and in `PROTOCOL.md`.

## v2.7 — the operand, the paging model, and four decoded records

- **Opcodes carry operands.** A run of consecutive opcodes is usually one
  operation with a small parameter (filter, state, phase, bus number,
  boolean) encoded in the opcode instead of the body. 55 families covering
  146 opcodes are named by the dissector (`p2.operand`) and the scanner.
- **Range-and-resume paging** documented for every bulk read (§10.2.3), with
  the four selector encodings and the out-of-range resume sentinel.
- **Four record types decoded and dissected**: the enhanced-alarm definition
  (`0x0983`) and the three equipment-scheduling records (`0x0987`, `0x0988`,
  `0x0989`), including the ISO-numbered weekday byte the dissector uses as an
  alignment self-check.
- **The CPI tier corrected**: the wire opcode is chosen while the request is
  encoded, so no 1:1 operation↔opcode map exists; the object field at `+0x06`
  is the CPI function code, closing a standing open item.
- **Accuracy audit of `PROTOCOL.md`**: the §9.5 catalog is generated from the
  data the tools ship, every corpus figure derives from one reproducible
  census (206,050 trusted frames, 104,752 requests, 125 wire-observed
  opcodes across 85 captures), and the table of contents is complete.

## v2.6 — accuracy pass

The `0x29` / `0x2A` carrier labels are corrected: they were
named "peer maintenance" and "peer COV-subscribe," and the corpus establishes neither
function. They are now **session carrier** and **peer-session carrier (panel↔panel)**,
matching PROTOCOL.md §6.2; both carry the `EBLN_PING` (`0x4640`) identity exchange.
Error code `0x0E12` is named `record_state_rejected (unconfirmed)` — observed a handful
of times, adjacent to already-exists, precise meaning not pinned — and opcode `0x0030`
`AP2_SET_GLOBAL_DATA` is added. **Bug fix:** the error-tail read guarded on frame
length rather than on the post-slot offset, so a truncated `dir==0x05` frame could
render two header bytes as a phantom error code (observed: a 13-byte frame reporting
"ERROR 0x0105"). It now guards on the slot offset.


## v2.5 — response correlation + more body decoders

Responses carry no opcode on the
wire (only requests do) but echo their request's sequence; the dissector now keeps a
per-TCP-stream `{sequence → opcode}` map and **labels and decodes responses** — the
`CABINET_DISPLAY` firmware banner (revision / platform / build date / node-site-BLN), the
value responses (point name + engineering-units + value), and the identity exchange. New
request decoders too: the addressing family — point read/command, COV enable/disable,
trend, bulk upload (scope tag + name + suffix + commanded value) — and `ALARM_PRINT`
(`0x0508`) with its value block and three 8-byte event timestamps. Validated with zero
Lua errors across a ~530k-frame corpus.


## v2.2 — message-class model corrected from fleet captures

The message classes are
legacy/modern **pairs chosen by a panel's firmware generation, not by direction**:
data `0x33` (legacy) / `0x34` (modern); second channel `0x2E` / `0x2F` (identity +
DB-change/replication records + alarm prints); peer carriers `0x29` / `0x2A`
(panel↔panel, visible only from a panel-side mirror). Fingerprint a panel with
`CABINET_DISPLAY` (`0x010C`) and pick the dialect from its firmware. Also: COV
condition byte0/byte1 (priority/control-status) wire-confirmed; sequence is
per-(peer,channel) with gaps (not one global counter); `UPL_ALL_*` continuation is
application-layer cursoring, not a frame more-follows bit; event timestamps are 8 bytes
(`yr-1900, mo, day, day-of-week, hr, min, sec, cs`).


## v2.1 — wire-verified rebuild

Opcode names corrected to the full
set; the framing model fixed (the opcode is read only on request frames, at its true
variable offset); accurate body decoders for the common operations; per-opcode
*expected-body schema* notes; and the old UDP/10001 "multicast presence beacon"
decoder **removed** (it was a misattribution of unrelated gateway traffic — see
*Correctness notes*).
