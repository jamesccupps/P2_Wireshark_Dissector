# Contributing

Thanks for considering a contribution to the Siemens APOGEE P2 (Protocol II) dissector.

## Reporting issues

When opening an issue:

- Describe what you saw vs. what you expected.
- For a wrong decode, include the relevant packet excerpt (hex bytes) with site
  identifiers redacted.
- For an opcode shown as `unknown_0xNNNN`, note the opcode value, message class,
  direction, and any visible pattern in the body bytes. (Some values are not real
  function codes — e.g. malformed-frame artifacts or scanner-probe noise — so an
  `unknown_` label is sometimes correct.)
- Wireshark version and OS help.

## How the dissector is organized

- The frame model is in `dissect_one`: fixed header → four NUL-terminated routing slots
  → (only on direction `0x00`) the 2-byte AP2 opcode → body. The opcode is parsed at a
  *variable* offset by scanning the four NULs — never at a fixed offset.
- `OPCODES` (name table) and `OPSCHEMA` (expected-body field lists) are **machine-
  generated** from the protocol's authoritative function-code set and its ASDU type
  definitions. **Don't hand-edit opcode names or schemas** — if a name is wrong or
  missing, open an issue. Contributions are body *decoders*, not names.
- Bespoke body decoders (`dissect_cov`, `dissect_roster`, `dissect_identity`) are the
  wire-verified, byte-level ones; everything else falls back to the generic
  `tlv_walk`. The per-opcode schema note is an *expectation*, not a decoded layout.

## Pull requests

For new or improved body decodes:

- Add a branch in `dissect_one`'s direction-`0x00` handler that calls a new
  `dissect_<operation>()` helper, modeled on `dissect_cov` / `dissect_roster` /
  `dissect_identity`, and add any new `ProtoField`s to the `f` table and `p2.fields`.
- **Promote a struct-derived schema to a real byte decoder only when a capture confirms
  the byte layout** (especially field widths, which the schema does not pin). Note in a
  comment which capture/condition verified it.
- Branch on payload shape / direction, not TCP port — the opcode exists only on
  direction `0x00`, and either side may use either port.
- Verify it loads and runs clean:
  `lua5.4 -e 'assert(loadfile("p2.lua"))'` and
  `tshark -X lua_script:p2.lua -r your.pcapng -Y p2` (expect zero Lua errors).
- Test against your own capture; include before/after Info-column screenshots if the
  change affects what users see.

## Style

- Match the existing Lua style in `p2.lua` (lowercase_with_underscores function names,
  bounds-checked field reads, `pcall`-guarded sub-dissectors so a malformed body can
  never break the whole dissection).
- Annotate non-obvious heuristics and tag any inferred (not wire-confirmed) layout.

## What's in scope

- Promoting expected-body schemas to verified byte decoders, backed by a capture.
- New bespoke body decoders and new `ProtoField`s for surfaces currently shown only via
  the generic TLV walk.
- A malformed-routing-header guard (so slot-walk artifacts are flagged as malformed
  rather than decoded as phantom opcodes).
- Multi-frame reassembly / edge-case fixes.

## What's out of scope

- Active probing / packet-crafting tools — this is a passive dissector.
- Anything that ties the dissector to specific deployments, sites, or product
  configurations (no hardcoded names, IPs, or labels in code, comments, or test data).
