# Changelog

Release notes for the P2 dissector, scanner and protocol reference.
The current release is summarised at the top of [README.md](README.md).

> Entries below v2.7 are kept as written at the time. Figures in them reflect
> what was believed then; where a later release corrected one, the correction is
> in that release's entry and in `PROTOCOL.md`.

## v2.8.2 — the decode side

- **A request may carry a zero-length body**, and 220 in the corpus do — `0x010C`
  (163x), `0x4633 EBLN_REPL_NOTIFY` (22x), `0x0951 DBCHANGE_POINT` (11x) and the
  rest of the `DBCHANGE` family. It is the natural encoding of a parameterless
  operation: the `u16` opcode is the whole message. An encoder must be willing to
  emit an ASDU of length zero and a decoder must accept it as complete rather
  than truncated.
- **The family band is structural, not descriptive.** §9.4 said the opcode's high
  byte "loosely tracks" the family. The supervisor's command factory selects a
  subclass by switching on `opcode & 0xFF00`, so the band is a real
  classification in the implementation.
- Decode confirmed as the mirror of encode: the decoder is handed `buf+2` and
  `total-2`, so the two reserved opcode bytes of v2.8.1 are established from the
  receive direction too.

## v2.8.1 — the segmentation ceiling

- **A segment is 16,384 bytes; the encoder may fill 16,382.** The two bytes held
  back at the head are the `u16` function code, written after the body is
  encoded — which is why the wire carries the opcode immediately before the body
  and why `total_length` counts it. An implementer reading a body is reading the
  encoder's `buf+2`.
- **Reassembly is a cursor against a declared total**, not a negotiation: each
  mapped segment copies `n` bytes and advances the cursor, and the last segment's
  length is `total - cursor`. The sender knows the total before it begins.
- **The ceiling is not exercised by anything captured.** No body in the corpus
  exceeds 16,382 B — largest complete 1,570 B, largest declared 12,073 B — so a
  client may size a receive buffer at 16 KB with confidence, while the on-wire
  form of a *multi-segment* exchange remains unobserved and stays `[OPEN]`.
- §4's segmentation open item goes from "not pinned" to "pinned in the encoder,
  unobserved on the wire".

## v2.8.0 — the two EQS records, decoded in full

- **`0x0989` mode schedule: eleven fields, not five.** `entry_ID`,
  `entry_enabled`, `mode`, `occurrence`, `scheduled_days`, `start_date`,
  `end_date`, `start_time`, `stop_time`, `days_spanned`, `exclusive`, and a
  trailing `state_text_id`. Validated on every captured record: both dates carry
  a weekday byte that must match their own date, both times must be real, the
  booleans must be 0/1, and the record must consume the body exactly.
- **`scheduled_days` is a bitmask**, bit 0 = Sunday. `0x3E` is Mon–Fri, `0x41` is
  Sun+Sat, `0x7E` is Mon–Sat.
- **`0x0987` zone: the lead `u16` is a count of names.** What an earlier edition
  called "the name again after a two-byte separator" is the second
  `Team_response` entry, whose own `name_space` supplies those two bytes — and
  the pair is the zone's **system name and user name**, not a duplicate.
- **The trailing `u16` on both records is a state-text-table id.** It had been
  an unexplained two-valued field through four wrong readings. It is constant
  per zone and identical across both opcodes.
- **A third point-type numbering**, and the most dangerous: a current supervisor
  product ships a dense 1..16 renumbering of the L-type mnemonics beside the
  sparse wire codes, spelled identically. Six of fifteen disagree.
- **How the `0x09xx` bank is organised** — section × transfer direction × record
  state — and why an opcode cannot be computed from a section index.

## v2.7.1 — the error table, corrected

- **26 of the 42 error names were wrong, and it was one defect.** The table was
  **shifted by one entry** against the vendor's field-panel error catalog, from
  `0x0007` through `0x0210` and again across the FLN band, so each code carried
  the name belonging to the next code up. The `_v2` suffixes the old table used
  (`already_exists_v2`, `value_out_of_range_v2`) are the tell: the duplicate
  names the shift produced were suffixed rather than investigated.
- **One consequence was behavioural, not cosmetic.** `0x0E11` was named
  `already_exists` and `p2_scanner` treated it as a **success**, so a failed FLN
  point-add was reported as having worked. `0x0E11` is *FLN invalid drop number*;
  the code that means already-exists is `0x0009`, which had been left unnamed.
- **`0x0E10`–`0x0E17` is the FLN error band** — field-level faults, not the
  record-state rejections the old table implied.
- **`not_supported` (`0x00AC`) is revision-dependent.** It also covers a function
  code that is specific to a different firmware revision, so a panel answering it
  does not prove the opcode is unimplemented.
- The table is now **generated** rather than hand-maintained, and `PROTOCOL.md`
  §7.2.2 records the correction rather than quietly replacing it.

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
