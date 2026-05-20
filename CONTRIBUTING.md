# Contributing

Thanks for considering a contribution to the Siemens APOGEE P2 dissector.

## Reporting issues

When opening an issue:

- Describe what you saw vs. what you expected
- If reporting a wrong decode, include a relevant packet excerpt (hex bytes) with site identifiers redacted
- If reporting a new opcode (`unknown_0xNNNN` in the Info column), note the opcode value, message type, direction, and any visible pattern in the body bytes
- Wireshark version and OS help

## Pull requests

For new opcode support or improved decodes:

- Keep opcode entries grouped under their existing category headers in the `OPCODES` table
- Add a brief comment at the dispatch site (in `dispatch_request` or a per-opcode helper) describing the wire-format pattern
- For direction-dependent opcodes, branch on payload shape rather than TCP port — Mode C flows can put either direction on either port
- Verify the dissector still parses cleanly with `lua5.4 -e 'loadfile("p2.lua")'` after your changes
- Test against your own capture and include before/after Info-column screenshots if the change affects what users see

## Style

- Match existing Lua style in `p2.lua` (4-space indent, lowercase_with_underscores function names, descriptive comment blocks)
- Annotate non-obvious heuristics — future-you and future-others will thank you
- Avoid hardcoding deployment-specific names, IPs, or labels in test data or comments

## What's in scope

- Opcode dispatch additions and improvements
- Better body-decode for opcodes currently using the generic LP-string fallback
- Edge-case fixes in `find_value_block` (false matches on enumerate-response metadata are a known sensitivity)
- Multi-frame reassembly improvements
- New ProtoFields for surfaces that are currently dumped as raw bytes

## What's out of scope

- Active probing / packet-crafting tools — this is a passive dissector
- Modifications that would tie the dissector to specific deployments, sites, or product configurations
