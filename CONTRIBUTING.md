# Contributing

Thanks for considering a contribution to the Siemens APOGEE P2 (Protocol II) tooling.

This repository holds **three things with different contribution rules**, so start by
identifying which one you're touching:

| Component | Files | Nature |
|---|---|---|
| Wire-level reference | `PROTOCOL.md` | Documentation — evidence-tagged |
| Dissector | `p2.lua` | **Passive.** Decodes captures; sends nothing. |
| Scanner | `p2_scanner.py`, `p2_gui.py`, `firmware_registry.py`, `analyze_pcap.py` | **Active.** Connects to panels and reads from them. |

## Reporting issues

When opening an issue:

- Describe what you saw vs. what you expected.
- For a wrong decode, include the relevant packet excerpt (hex bytes) with site
  identifiers redacted.
- For an opcode shown as `unknown_0xNNNN`, note the opcode value, message class,
  direction, and any visible pattern in the body bytes. (Some values are not real
  function codes — e.g. malformed-frame artifacts or scanner-probe noise — so an
  `unknown_` label is sometimes correct.)
- Wireshark version and OS help. For scanner issues, include the Python version and
  the panel's firmware build tag (`--sysinfo-compact`) where you can.

## The dissector (`p2.lua`)

### How it's organized

- The frame model is in `dissect_one`: fixed header → four NUL-terminated routing slots
  → (only on direction `0x00`) the 2-byte AP2 opcode → body. The opcode is parsed at a
  *variable* offset by scanning the four NULs — never at a fixed offset.
- `OPCODES` (name table) and `OPSCHEMA` (expected-body field lists) are **machine-
  generated** from the protocol's function-code set and its ASDU type
  definitions. **Don't hand-edit opcode names or schemas** — if a name is wrong or
  missing, open an issue. Contributions are body *decoders*, not names.
- Bespoke body decoders are the wire-verified, byte-level ones. Request-side:
  `dissect_cov`, `dissect_roster`, `dissect_identity`, `dissect_alarm`, `dissect_addr`,
  `dissect_namesearch`. Response-side (reached through the per-stream
  `{sequence → opcode}` map, since responses carry no opcode): `dissect_banner`,
  `dissect_value_resp`. Everything else falls back to the generic `tlv_walk`.
- The per-opcode schema note is an *expectation*, not a decoded layout.

### Pull requests

- Add a branch in `dissect_one`'s direction-`0x00` handler that calls a new
  `dissect_<operation>()` helper, modeled on the existing ones, and add any new
  `ProtoField`s to the `f` table and `p2.fields`.
- **Promote a struct-derived schema to a real byte decoder only when a capture confirms
  the byte layout** (especially field widths, which the schema does not pin). Note in a
  comment which capture/condition verified it.
- Branch on payload shape / direction, not TCP port — the opcode exists only on
  direction `0x00`, and either side may use either port.
- Verify it loads and runs clean:
  `lua5.3 -e 'assert(loadfile("p2.lua"))'` (or `lua5.4`) and
  `tshark -X lua_script:p2.lua -r your.pcapng -Y p2` (expect zero Lua errors).
- Exercise segmentation, not just whole frames. A capture where one PDU spans several
  TCP segments — and where a segment ends mid-header — is the case that regresses most
  easily. `editcap -C` or a crafted pcap both work.
- Test against your own capture; include before/after Info-column screenshots if the
  change affects what users see.

### Style

- Match the existing Lua style (lowercase_with_underscores function names,
  bounds-checked field reads, `pcall`-guarded sub-dissectors so a malformed body can
  never break the whole dissection).
- Annotate non-obvious heuristics and tag any inferred (not wire-confirmed) layout.

## The scanner (`p2_scanner.py` / `p2_gui.py`)

The scanner is an **active** tool for owner-operators inventorying their own plant. It
is in scope for this repository, but under tighter rules than the dissector.

- **Read-only stays read-only.** The scanner implements reads, browse, and enumeration.
  Panel-destructive operations (cold/warm start, flash erase, node eviction) are
  documented in `PROTOCOL.md` §16.6 / §17.4 but **not implemented**, and PRs adding them
  will be declined — including behind a flag or a confirmation prompt.
- **Every new opcode you transmit must be justified in the PR description**: what it
  reads, what footprint it leaves, and why the passive path can't get the same answer.
- **Respect the footprint contract.** A correct-BLN handshake writes a permanent
  node-table entry. Anything that increases that footprint (more identities, more
  entries, entries that don't clean up) needs to be called out and documented in the
  user-facing output, as the cold-discovery path already does.
- **Validate before you encode.** Strings bound for the wire go through `_wire_name()`,
  which rejects embedded NULs, non-ASCII, and over-long names by raising
  `ScannerInputError`. Don't call `.encode('ascii')` directly on user-supplied names.
- **Parsers must not trust the panel.** Every field length, count, and offset in a
  response is peer-controlled. Bound your loops, check `off + N <= len(body)` before
  slicing, and return `None` rather than raising on malformed input.
- Keep the GUI's worker-thread discipline: scanner calls run on the `TaskRunner`
  thread and communicate back through the queues. Don't touch Tk widgets off the main
  thread.

## What's out of scope

- **Weaponization.** Exploit code, denial-of-service triggers, credential harvesting, or
  anything whose primary use is against equipment you don't own. The split in this
  repository — a passive dissector plus a read-oriented scanner, with destructive
  operations documented but not shipped runnable — is deliberate, and PRs that erode it
  will be declined.
- Anything that ties either tool to specific deployments, sites, or product
  configurations (no hardcoded names, IPs, or labels in code, comments, or test data).
  Sanitize captures before attaching them.

## Documentation (`PROTOCOL.md`)

- Every non-trivial claim carries an evidence tag — `[W]` wire-observed, `[S]`
  struct-derived, `[D]` vendor-doc, `[I]` inferred, `[OPEN]` unconfirmed. New claims need
  one. See Appendix E for the legend and the precedence rule.
- Upgrading a claim's tag (e.g. `[S]` → `[W]` because you captured it) is one of the most
  valuable contributions here. Say what the capture showed.
- If you close an Appendix D open question, update both the inline `[OPEN]` and the
  register entry.
- Section cross-references are `§N.N` and are expected to resolve; if you add or
  renumber a section, check the references still point somewhere.
