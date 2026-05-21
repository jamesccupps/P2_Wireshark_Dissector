# Siemens APOGEE P2 Wireshark Dissector

A Lua dissector for Wireshark that decodes the Siemens APOGEE P2 building-automation protocol over TCP/5033 and the UDP/10001 multicast presence beacon.

## What it does

Click a P2 packet and get:

- **Frame header** — total length, message type (DATA / HEARTBEAT / CONNECT / ANNOUNCE / inter-panel ANNOUNCE), sequence counter
- **Routing header** — direction byte, BLN name, destination panel, source panel
- **Opcode** — labelled against a catalog of 100+ known opcodes
- **Per-opcode body decode** — point reads (device / point / float / units / comm-status), alarms, schedules, identify, sysinfo, routing table, replication ops, value updates
- **Multicast beacon** — UDP/10001 payload sanity-check against the invariant `01 00 00 00`

## Install

1. **Help → About Wireshark → Folders → "Personal Lua Plugins"**
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux / macOS: `~/.local/lib/wireshark/plugins/`
2. Drop `p2.lua` into that folder
3. **Analyze → Reload Lua Plugins** (`Ctrl+Shift+L`) or restart Wireshark

The Protocol column should show `P2` on any TCP/5033 traffic.

## Port

P2's default transport is **TCP/5033** (Siemens white paper 149-1006). The port is configurable per site; if your captures use a different port, use Wireshark's **Analyze → Decode As...** to map it to the `P2` dissector.

## Useful tshark one-liner

Identify Siemens PXC field panels in any capture without decoding payloads — PXCs (Nucleus NET RTOS) emit `TTL=64` with `window=16000` exactly; everything else looks different:

```bash
tshark -r capture.pcapng -Y "tcp.flags.syn==1" \
    -T fields -e ip.src -e ip.ttl -e tcp.window_size_value | sort -u
```

## Coverage at a glance

- **Message types:** `0x29` inter-panel ANNOUNCE, `0x2E` CONNECT, `0x2F` ANNOUNCE, `0x33` DATA, `0x34` HEARTBEAT
- **Opcodes** (categories): system info / identity, replication ops (0x46xx), reads, property writes, object lifecycle, point enumeration, schedule ops, PPCL editor, alarm pair, BarePings
- **Errors:** 37-entry catalog from Siemens BACnet ALN Manual 125-3020 Appendix C
- **Value blocks:** marker, sentinel, comm-status (live vs `[#COM stale]`), data-type, big-endian f32, units

## Notes

- Routing-header name ordering is destination-first across all message types.
- BLN names are case-sensitive ASCII; node names are case-insensitive on the wire (display preserves case).
- Mode C connections carry operational opcodes inside `0x2E` / `0x2F` framing without ever transitioning to `0x33` / `0x34`.
- Multicast beacon (UDP/10001) is dual-emitted to `233.89.188.1` and `255.255.255.255` at ~10.5 s cadence; payload invariant.
- Opcodes labelled `unknown_0xNNNN` are candidates for further analysis — see CONTRIBUTING.md.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests for new opcode coverage, body-decode improvements, and edge-case fixes welcome.

## License

MIT. See `LICENSE`.

This dissector is a third-party analytical tool built from observed traffic. It is not affiliated with or endorsed by Siemens.
