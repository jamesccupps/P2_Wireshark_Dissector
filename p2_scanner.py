#!/usr/bin/env python3
"""
Siemens P2 Protocol Scanner
============================
Universal scanner for Siemens PXC field panels participating in the Apogee
Ethernet variant of the P2 protocol. Discovers panels, enumerates FLN
devices, reads point values, and queries firmware/system information — all
over the P2-over-Ethernet transport (default TCP/5033).

Quick Start:
    python p2_scanner.py --pcap capture.pcapng                              # Learn BLN name
    python p2_scanner.py --discover --range 192.0.2.0/24 --network MYBLN     # Find everything
    python p2_scanner.py -n 192.0.2.50 -d DEVICE1 -p "ROOM TEMP" --network MYBLN  # Read a point

Protocol context (Siemens canonical vocabulary)
-----------------------------------------------
Siemens describes the APOGEE / Desigo system as three tiers:

  * MLN — Management Level Network (Insight / Desigo CC management
          stations on Ethernet TCP/IP). Optional Datamate Advanced (DMA).
  * BLN/ALN — Building-Level Network (legacy term) / Automation Level
          Network (current term). Field panels (PXC, PXC Modular, PXC
          Compact, MEC, MBC) AND the management station participate here
          as peer nodes. Wire format slot 1 = BLN identifier (case-
          sensitive ASCII). Siemens uses BLN and ALN interchangeably;
          firmware prompts still display "BLN".
  * FLN — Floor Level Network (TECs, UCs, VFDs). P1 over RS-485 or
          BACnet MS/TP. Not addressed by this scanner.

This scanner targets the BLN/ALN tier on the Apogee Ethernet (TCP-based)
variant. Robert Old (Siemens BT system architect, 2001) named the four
P2 variants: Pre-APOGEE (RAD-50/RS-485), APOGEE (ASCII/RS-485), APOGEE
Ethernet (this scanner's target), APOGEE BACnet. Per Siemens spec sheets
149-487 and 553-104 an Ethernet ALN is capped at 100 nodes per BLN.

A P2 EBLN is a full-mesh of long-lived TCP sessions: every peer node
listens on the configured port AND opens outbound client sockets to
every other peer (N participants → up to N(N-1) TCP sessions). PurpleSwift
documents this for their BACnetP2 gateway; Siemens 149-1006 confirms
"Traffic must be allowed at both the field panels and the computer
hosting the ALN for proper communication."

Port assignment
---------------
P2_PORT below defaults to 5033, the Siemens-documented value per the
white paper 149-1006 ("Configuring an APOGEE System on an IT
Infrastructure", June 2016). The port is CONFIGURABLE via Desigo CC's
"Our Server Port" setting; both the management station and every panel
must agree. The only Siemens-documented reason to deviate from 5033 is
a Datamate Advanced (DMA) co-installation collision. Override P2_PORT
(or use --port) on sites where the configured P2 ALN port is not 5033.

Terminology in this codebase
----------------------------
We use SCANNER_NAME and references to "supervisor" colloquially for the
Desigo CC / Insight management station. In Siemens' formal vocabulary
the management station is a peer node with an "Our Node" drop number
(1-99), not architecturally distinct from a field panel. We use
"supervisor" because operators recognize it; the BLN tier has no formal
"supervisor" in Siemens' model.

Wire format derived from protocol analysis of network captures plus
Siemens-published documents 125-3019 (APOGEE P2 ALN Field Panel User's
Manual), 149-1006 (Configuring an APOGEE System on an IT Infrastructure),
149-487 (PXC Modular for BACnet Networks spec), and 553-104 (PXC Compact
Series Owner's Manual). No reverse engineering of Siemens binaries was
performed.
"""

import socket
import struct
import time
import sys
import os
import argparse
import json
import csv
import re
import secrets
from datetime import datetime
from collections import Counter, OrderedDict
from typing import Optional, Dict, List, Tuple, Any, Callable

import firmware_registry  # APOGEE_P2_SPEC.md §30 — fast-path dialect lookup
import p2_data            # compiled-in opcode / point-type / enum tables

# ─────────────────────────────────────────────────────────────────────────────
# A note on `APOGEE_P2_SPEC.md §N` citations throughout this file.
#
# APOGEE_P2_SPEC.md is the internal working spec this tooling was built against.
# It is NOT shipped in this repository, and its section numbering does NOT
# correspond to the published PROTOCOL.md. Treat those citations as provenance
# markers ("this constant came from a specific documented observation"), not as
# links a reader can follow. The same applies to the occasional reference to
# OPCODES.md (an internal opcode audit, since folded into PROTOCOL.md 9) and to
# PUNCHLIST_REPO_HEALTH.md (an internal tracking document). Neither ships here.
#
# The published, self-contained reference is PROTOCOL.md in this repo. Where a
# claim here matters to a reader, the equivalent PROTOCOL.md section is:
#   frame layout / framing over TCP ......... §6.1
#   message classes & dialects .............. §6.2
#   direction byte .......................... §6.3
#   routing slots ........................... §6.4
#   sequence & request/response pairing ..... §6.5
#   success vs error responses, error codes . §7.2
#   connection & session model .............. §7.3
#   string TLV / scope tag / value fields ... §8.1-§8.3
#   date/time stamp ......................... §8.3.4
#   opcode catalog .......................... §9.5
#   COV body & condition block .............. §12.3
#   alarm report / ack opcodes .............. §13.6
#   firmware & revision identity ............ §16.5
#   destructive opcodes (documented, not implemented) §16.6, §17.4
# ─────────────────────────────────────────────────────────────────────────────

# Single source of truth for the scanner library version. Keep in sync
# with pyproject.toml's [project].version. `import p2_scanner` users can
# inspect `p2_scanner.__version__` rather than parsing pyproject metadata.
__version__ = "1.3.0"

# Console output uses Unicode formatting chars (✓ ✗ ⚠ ── → ═) for readability.
# Windows defaults to cp1252 in cmd.exe / PowerShell, which crashes on these.
# Reconfigure stdout/stderr to UTF-8 so the script works on stock Windows
# without requiring users to set PYTHONIOENCODING themselves. Python 3.7+.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, OSError):
    pass  # already UTF-8, or stdout was redirected to something that can't be reconfigured

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION — Defaults are auto-learned when possible
# ═══════════════════════════════════════════════════════════════════════════════

P2_PORT = 5033                   # Siemens-documented default per white paper 149-1006.
                                 # CONFIGURABLE — "Our Server Port" in Desigo CC; both the
                                 # management station and every panel must agree. The only
                                 # Siemens-documented reason to deviate is a Datamate
                                 # Advanced (DMA) co-installation collision. Override via
                                 # --port on sites where the configured P2 ALN port is
                                 # not 5033.
P2_NETWORK = ""                  # BLN name (slot 1 of every P2 frame). Case-sensitive
                                 # ASCII per Siemens Desigo CC Engineering Help.
                                 # Auto-learned from first connection.
P2_SITE = ""                     # Site name (free text, spaces allowed in Siemens HMI;
                                 # used as the SYST scope footer in some opcode responses).
                                 # Auto-learned from first connection.

# Honest, obviously-a-scanner identity placed in slot 4 of the handshake.
# The tool announces itself AS a scanner — it does NOT impersonate the
# supervisor. A connecting node must register an identity to read anything
# (that is simply how P2 works); making that identity clearly read "a
# scanner was here" in the panel's NODE NAME TABLE is the read-only-by-
# default, leave-an-audit-trail posture. The port suffix is the conventional
# `<host>|<listen-port>` form; effective_scanner_name() derives it from the
# active port. An operator who must present a specific identity can override
# with --scanner-name. See APOGEE_P2_SPEC.md §9.3 for the slot-4 identity.
_GENERIC_SCANNER_NAME = "P2SCAN-LAP|5033"
SCANNER_NAME = _GENERIC_SCANNER_NAME

DEBUG_READS = False              # When True, print raw hex on parse failures
CONNECT_TIMEOUT = 5              # TCP connect timeout (seconds)
READ_TIMEOUT = 10                # Read response timeout (seconds)
HANDSHAKE_PROBE_TIMEOUT = 2.0    # First-dialect probe timeout — see _handshake(). A PXC speaking the legacy dialect
                                 # responds well under a second; a PXC speaking the modern dialect stays silent.
                                 # Setting this too long makes modern-dialect panels slow to connect; too short and
                                 # a congested network falsely fails the first attempt.

# Known nodes (optional — populated by discovery or site config file)
# Format: {"NODE_NAME": "IP_ADDRESS", ...}
KNOWN_NODES = {}


def _set_network(name: str):
    global P2_NETWORK
    P2_NETWORK = name

def _set_scanner_name(name: str):
    global SCANNER_NAME
    SCANNER_NAME = name


def effective_scanner_name() -> str:
    """Return the identity to put in slot 4 of the handshake.

    Honest-by-default: the scanner announces itself as an obviously-a-scanner
    node, NOT as the supervisor. A clearly-labeled entry is what a colleague
    sees in the panel's NODE NAME TABLE — it should read "a scanner was here",
    not impersonate Desigo CC.

    Resolution order:
      1. If SCANNER_NAME was explicitly set (--scanner-name, _set_scanner_name,
         or a scanner_name field in site.json), use it verbatim — the escape
         hatch for an operator who must present a specific identity.
      2. Otherwise the honest generic `P2SCAN-LAP|<active-port>`.

    Acceptance note: on the firmware tested here a panel accepts any slot-4
    identity of >=15 characters paired with the correct BLN; `P2SCAN-LAP|5033`
    is 15 chars and the port suffix is the conventional `<host>|<listen-port>`
    form. This is a wire-observed behavior, not a documented guarantee.
    """
    if SCANNER_NAME and SCANNER_NAME != _GENERIC_SCANNER_NAME:
        return SCANNER_NAME
    return f"P2SCAN-LAP|{P2_PORT}"


# Status-byte error code lookup (see P2Connection._parse_read_response).
# These are the u16 BE codes that follow the direction byte 0x05 in error
# responses. Full catalog of 37 codes per APOGEE_P2_SPEC.md §10.2; codes
# observed on the wire most often (0x0003, 0x00AC, 0x0E15) are commented.
_P2_STATUS_ERRORS = {
    # Common codes
    0x0002: 'object_unknown',                # E2 — scope-restricted op out of scope
    0x0003: 'not_found',                     # E3 — dominant error in normal operation
    0x00AC: 'not_supported',                 # E172 — opcode not on this firmware
    0x0E11: 'already_exists',                # E3601 — CreateObject; treat as success
    0x0E15: 'physical_point_not_commandable',# E3605 — 0x0240 vs SYST; retry as 0x4222

    # Vendor-documented (BACnet ALN Manual 125-3020 Appendix C; spec §10.2)
    0x0001: 'no_memory_available',           # E1
    0x0004: 'priority_too_low',              # E4
    0x0005: 'failed_no_change',              # E5
    0x0007: 'out_of_service',                # E7
    0x0008: 'field_panel_general_error',     # E8
    0x0009: 'already_exists_v2',             # E9 — sibling of 0x0E11
    0x000A: 'trend_already_exists',          # E10 — also value_unchanged
    0x000B: 'value_out_of_range',            # E11 — also see 0x0E16
    0x000C: 'line_not_traced',               # E12 — PPCL trace
    0x000D: 'line_state_mismatch',           # E13 — PPCL enable/exists
    0x0016: 'has_unresolved_points',         # E22 — PPCL or zone
    0x0028: 'line_accessed_not_traced',      # E40 — PPCL tracebit
    0x0040: 'tiu_busy',                      # E64
    0x0065: 'command_not_supported',         # E101 — sibling of E172
    0x0080: 'point_in_hand_mode',            # E128
    0x0081: 'invalid_password',              # E129
    0x0082: 'user_accounts_database_full',   # E130
    0x00AB: 'coldstart_required',            # E171
    0x00B7: 'operation_aborted_warmstart',   # E183
    0x00B8: 'too_many_framing_errors',       # E184
    0x00F9: 'invalid_point_address',         # E249
    0x00FA: 'failed_io_device',              # E250
    0x00FE: 'monitor_list_full',             # E254 — COV
    0x0200: 'flt_transfer_in_progress',      # E512 — Firmware Loading Tool
    0x0202: 'flt_transfer_killed',           # E514
    0x0203: 'tec_not_added',                 # E515
    0x0205: 'connection_lost',               # E517
    0x0206: 'warm_started',                  # E518
    0x0207: 'protocol_error',                # E519
    0x0209: 'timeout',                       # E521
    0x0210: 'invalid_fln_number',            # E528
    0x0E10: 'invalid_drop_number',           # E3600
    0x0E12: 'invalid_point_number',          # E3602
    0x0E13: 'physical_point_failed',         # E3603
    0x0E14: 'physical_point_not_commandable_v2', # E3604 — sibling of E3605
    0x0E16: 'value_out_of_range_v2',         # E3606 — sibling of E11
    0x0E17: 'application_invalid_for_device',# E3607
}


class ScannerInputError(ValueError):
    """Raised when the scanner is asked to do something the DBF or protocol
    rules say is invalid — e.g. reading an out-of-range slot, or reading a
    slot that isn't defined in the device's application (without --force-slot).

    The CLI catches this and exits with code 2 so shell scripts and parent
    processes can distinguish 'bad input' from 'ran fine but found nothing'.
    Library callers who want to handle input errors themselves can catch it
    directly; those who don't care will get a normal Python traceback.
    """
    pass


# Sanity bound for any string that lands in a NUL-terminated routing slot.
# Not a protocol constant — the true panel-side field width isn't pinned in
# PROTOCOL.md. 64 is comfortably above every observed identity (the
# conventional form is 15 chars, e.g. `P2SCAN-LAP|5033`) while still catching
# a config typo or a pasted blob before it reaches the wire.
MAX_WIRE_NAME = 64


def _wire_name(value: Optional[str], field: str,
               max_len: int = MAX_WIRE_NAME) -> bytes:
    """Validate and ASCII-encode a name bound for a NUL-terminated P2 slot.

    The four routing slots are delimited by NUL bytes, so a name that itself
    contains a NUL emits an extra delimiter and desynchronizes the panel's
    four-slot parse — the frame is then misrouted or dropped, with no error
    surfaced to us. Non-ASCII raises UnicodeEncodeError deep in the payload
    builder, which escapes the ScannerInputError contract the CLI relies on
    for its exit-code-2 behavior. Both are caught here, at the one boundary
    where a Python string becomes wire bytes.

    Empty is permitted: P2_NETWORK/P2_SITE are legitimately empty before a
    site config is loaded, and an empty slot is a valid frame.

    Raises ScannerInputError on any violation.
    """
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise ScannerInputError(
            f"{field} must be a string, got {type(value).__name__}")
    if '\x00' in value:
        raise ScannerInputError(
            f"{field} contains an embedded NUL byte at index "
            f"{value.index(chr(0))}; NUL is the routing-slot delimiter and "
            f"cannot appear inside a name")
    try:
        encoded = value.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ScannerInputError(
            f"{field} must be ASCII; {value!r} contains a non-ASCII "
            f"character at index {exc.start}") from exc
    if len(encoded) > max_len:
        raise ScannerInputError(
            f"{field} is {len(encoded)} bytes; the limit is {max_len}")
    return encoded


def save_config(filepath: str):
    """Save learned P2 network config to a JSON file.

    Also persists the firmware_registry build-tag cache under
    ``known_builds`` so the next process can skip the §11.2 dialect probe
    on first contact to known panels.
    """
    config = {
        'p2_network': P2_NETWORK,
        'p2_site': P2_SITE,
        'scanner_name': SCANNER_NAME,
        'known_nodes': KNOWN_NODES,
        'known_builds': firmware_registry.all_cached_build_tags(),
    }
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"  Config saved to {filepath}")


def load_config(filepath: str) -> bool:
    """Load P2 network config from a JSON file.

    Populates the firmware_registry build-tag cache from ``known_builds``
    when present; this enables the §30.4 fast-path on first contact.
    Unknown fields are tolerated (forward compat).
    """
    global P2_NETWORK, P2_SITE, SCANNER_NAME, KNOWN_NODES
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)
        if config.get('p2_network'):
            P2_NETWORK = config['p2_network']
        if config.get('p2_site'):
            P2_SITE = config['p2_site']
        if config.get('scanner_name'):
            SCANNER_NAME = config['scanner_name']
        if config.get('known_nodes'):
            KNOWN_NODES.update(config['known_nodes'])
        firmware_registry.load_build_tags(config.get('known_builds'))
        # No scanner_name pinned → keep the honest, obviously-a-scanner
        # default (`P2SCAN-LAP|<port>`, via effective_scanner_name()). The
        # tool does not auto-impersonate the supervisor; set scanner_name in
        # the config or pass --scanner-name to present a specific identity.
        print(f"  Config loaded from {filepath}")
        print(f"  Network: {P2_NETWORK}  |  Site: {P2_SITE}  |  "
              f"Nodes: {len(KNOWN_NODES)}  |  "
              f"Builds cached: {len(firmware_registry.all_cached_build_tags())}")
        return True
    except FileNotFoundError:
        print(f"  [ERROR] Config file not found: {filepath}")
        return False
    except json.JSONDecodeError:
        print(f"  [ERROR] Invalid config file: {filepath}")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# TEC APPLICATION POINT DEFINITIONS — LEGACY HARDCODED FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════
# These tables (COMMON_POINTS / HEATING_POINTS / REHEAT_POINTS / HW_VALVE_POINTS
# / FAN_POINTS / SUPPLY_TEMP_POINT) are the **legacy fallback** point catalog,
# used by `get_point_table` ONLY when the full catalog cannot be loaded at all.
# In practice that never happens: the complete 1024-application catalog is
# EMBEDDED IN THIS FILE as a gzip+base64 blob (`_TECPOINTS_GZ_B64`, ~386 KB
# encoded, ~8.7 MB expanded) and is the last entry in the loader's search
# order, so a bare copy of p2_scanner.py with no data files beside it still
# resolves every application. That is deliberate: one file, nothing to install,
# nothing to forget to copy. An external tecpoints.json still overrides it.
#
# Kept on disk for:
#   - resilience when running an out-of-tree script without the data package
#   - documenting which slots define the "common-TEC" lineage these tables grew
#     out of (apps 2020-2027 are the historical VAV cooling/heating family)
#
# DO NOT add new applications here. New apps go in tecpoints.json upstream
# (see PUNCHLIST_REPO_HEALTH.md H-32 for retirement rationale).
#
# Each TEC has up to 99 subpoints. Slot 0 is reserved; 1-99 are subpoints.
# Format: address -> (name, description, units, read_only)

# Common points present in ALL applications (2020-2027)
COMMON_POINTS = {
    1:  ("CTLR ADDRESS",   "Controller FLN address",              "",      False),
    2:  ("APPLICATION",    "Application number",                   "",      True),
    3:  ("CTL TEMP",       "Control temperature",                  "DEG F", True),
    4:  ("ROOM TEMP",      "Room temperature sensor reading",      "DEG F", True),
    6:  ("DAY CLG STPT",   "Day cooling setpoint",                 "DEG F", False),
    8:  ("NGT CLG STPT",   "Night cooling setpoint",               "DEG F", False),
    11: ("RM STPT MIN",    "Room setpoint dial minimum",           "DEG F", False),
    12: ("RM STPT MAX",    "Room setpoint dial maximum",           "DEG F", False),
    13: ("RM STPT DIAL",   "Room setpoint dial reading",           "DEG F", True),
    14: ("STPT DIAL",      "Setpoint dial enabled",                "",      False),
    18: ("WALL SWITCH",    "Wall switch monitoring enabled",       "",      False),
    19: ("DI OVRD SW",     "Override switch status",               "",      True),
    20: ("OVRD TIME",      "Override duration (hours)",            "",      False),
    21: ("NGT OVRD",       "Night override active",                "",      True),
    24: ("DI 2",           "Digital input 2 status",               "",      True),
    29: ("DAY.NGT",        "Day/Night mode",                       "",      True),
    31: ("CLG FLOW MIN",   "Cooling minimum airflow",              "",      False),
    32: ("CLG FLOW MAX",   "Cooling maximum airflow",              "",      False),
    35: ("CTL STPT",       "Active control setpoint",              "DEG F", True),
    36: ("CTL FLOW MIN",   "Active control flow minimum",          "",      True),
    37: ("CTL FLOW MAX",   "Active control flow maximum",          "",      True),
    38: ("FLOW STPT",      "Flow setpoint",                        "PCT",   True),
    39: ("FLOW",           "Actual airflow percentage",            "PCT",   True),
    40: ("AIR VOLUME",     "Air volume (CFM)",                     "",      True),
    41: ("DMPR POS",       "Damper position",                      "PCT",   True),
    42: ("DMPR COMD",      "Damper command",                       "PCT",   True),
    43: ("DMPR STATUS",    "Damper status",                        "",      True),
    44: ("DMPR ROT ANG",   "Damper rotation angle",                "",      False),
    45: ("DUCT AREA",      "Duct cross-sectional area (sq ft)",    "",      False),
    46: ("FLOW COEFF",     "Flow coefficient",                     "",      True),
    47: ("CLG LOOPOUT",    "Cooling loop output",                  "PCT",   True),
    48: ("CLG BIAS",       "Cooling bias",                         "PCT",   False),
    49: ("CLG P GAIN",     "Cooling proportional gain",            "",      False),
    50: ("CLG I GAIN",     "Cooling integral gain",                "",      False),
    51: ("CLG D GAIN",     "Cooling derivative gain",              "",      False),
    52: ("FLOW P GAIN",    "Flow proportional gain",               "",      False),
    53: ("FLOW I GAIN",    "Flow integral gain",                   "",      False),
    54: ("FLOW D GAIN",    "Flow derivative gain",                 "",      False),
    55: ("FLOW BIAS",      "Flow bias",                            "PCT",   False),
    58: ("SWITCH LIMIT",   "Switch limit",                         "PCT",   False),
    59: ("SWITCH DBAND",   "Switch deadband",                      "DEG F", False),
    60: ("SWITCH TIME",    "Switch time (minutes)",                "",      False),
    70: ("DO 1",           "Digital output 1",                     "",      True),
    71: ("DO 2",           "Digital output 2",                     "",      True),
    75: ("DO 6",           "Digital output 6",                     "",      True),
    80: ("CAL SETUP",      "Calibration setup",                    "",      False),
    81: ("CAL MODULE",     "Calibration module",                   "",      True),
    82: ("CAL TIMER",      "Calibration timer",                    "",      True),
    83: ("CAL AIR",        "Calibration air",                      "",      True),
    84: ("MTR SETUP",      "Motor setup",                          "",      False),
    85: ("MTR1 TIMING",    "Motor 1 timing",                       "SEC",   False),
    86: ("MTR2 TIMING",    "Motor 2 timing",                       "SEC",   False),
    87: ("MTR3 TIMING",    "Motor 3 timing",                       "SEC",   False),
    90: ("LOOP TIME",      "Control loop time",                    "SEC",   False),
    91: ("ERROR STATUS",   "Error status",                         "",      True),
    92: ("DO DIR. REV",    "DO direction reverse",                 "",      False),
    93: ("VALVE COUNT",    "Number of valve actuators",            "",      False),
    95: ("DO 3",           "Digital output 3",                     "",      True),
    96: ("DO 4",           "Digital output 4",                     "",      True),
    97: ("DO 5",           "Digital output 5",                     "",      True),
    98: ("TOTAL VOLUME",   "Totalized air volume",                 "",      True),
}

# Points specific to heating applications (2021-2027)
HEATING_POINTS = {
    5:  ("HEAT.COOL",      "Current heating/cooling mode",         "",      True),
    7:  ("DAY HTG STPT",   "Day heating setpoint",                 "DEG F", False),
    9:  ("NGT HTG STPT",   "Night heating setpoint",               "DEG F", False),
    25: ("DI 3",           "Digital input 3 status",               "",      True),
    33: ("HTG FLOW MIN",   "Heating minimum airflow",              "",      False),
    34: ("HTG FLOW MAX",   "Heating maximum airflow",              "",      False),
    56: ("HTG LOOPOUT",    "Heating loop output",                  "PCT",   True),
    57: ("HTG BIAS",       "Heating bias",                         "PCT",   False),
    61: ("HTG P GAIN",     "Heating proportional gain",            "",      False),
    62: ("HTG I GAIN",     "Heating integral gain",                "",      False),
    63: ("HTG D GAIN",     "Heating derivative gain",              "",      False),
}

# Points for reheat applications (2022-2027)
REHEAT_POINTS = {
    15: ("AUX TEMP",       "Auxiliary temperature sensor",         "DEG F", True),
    16: ("FLOW START",     "Heating flow start threshold",         "PCT",   False),
    17: ("FLOW END",       "Heating flow end threshold",           "PCT",   False),
    22: ("REHEAT START",   "Reheat start threshold",               "PCT",   False),
    23: ("REHEAT END",     "Reheat end threshold",                 "PCT",   False),
}

# Hot water valve points (2023, 2025, 2027)
HW_VALVE_POINTS = {
    64: ("VLV1 POS",       "Valve 1 position",                    "PCT",   True),
    65: ("VLV1 COMD",      "Valve 1 command",                     "PCT",   True),
    66: ("VLV2 POS",       "Valve 2 position",                    "PCT",   True),
    67: ("VLV2 COMD",      "Valve 2 command",                     "PCT",   True),
}

# Fan points (2024-2027)
FAN_POINTS = {
    26: ("SERIES ON",      "Series fan ON threshold",              "",      False),
    27: ("SERIES OFF",     "Series fan OFF threshold",             "",      False),
    28: ("PARALLEL ON",    "Parallel fan ON threshold",            "",      False),
    30: ("PARALLEL OFF",   "Parallel fan OFF threshold",           "",      False),
}

# Supply temp for 2021
SUPPLY_TEMP_POINT = {
    15: ("SUPPLY TEMP",    "Supply air temperature",               "DEG F", True),
}


def get_point_table(application: int) -> Dict[int, tuple]:
    """Build the complete point table for a given TEC application number.

    First tries to load from tecpoints.json (rich format with
    1024 apps — PTYPE / slope / intercept / state labels / per-app _meta).
    Falls back to legacy tecpnts.json (name/units/dtype tuples).
    Falls back to the hardcoded COMMON_POINTS / HEATING_POINTS / ... tables
    above for apps 2020-2027 only if neither JSON catalog is reachable; that
    path is dead for normal installs (the data package always ships).

    Return format: {addr: (name, desc, units, read_only)} — same tuple shape
    as before for backwards compatibility with all call sites.
    Rich metadata is also available via get_point_info() for the output path.
    """
    global _TECPNTS_DB

    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()

    if _TECPNTS_DB and str(application) in _TECPNTS_DB:
        app_data = _TECPNTS_DB[str(application)]
        points = {}
        for addr_str, info in app_data.items():
            try:
                addr = int(addr_str)
            except (ValueError, TypeError):
                continue
            # Support both rich dict format and legacy list format
            if isinstance(info, dict):
                name = info.get('name', '')
                units = info.get('units', '')
                ptype = info.get('ptype', 4)
                # ptype 1,10 = digital RW; ptype 2 = digital RO (mostly);
                # ptype 3 = analog RO (input); ptype 4 = analog RW.
                # Use 'rw' field when present, else fall back to ptype mapping.
                rw_flag = info.get('rw')
                if rw_flag is None:
                    rw_flag = ptype not in (2, 3)
                ro = not rw_flag
            else:  # legacy list format: [name, units, dtype_str]
                name = info[0]
                units = info[1] if len(info) > 1 else ""
                dtype = info[2] if len(info) > 2 else "AO"
                ro = dtype in ('AI', 'BI')
            points[addr] = (name, name, units, ro)
        return OrderedDict(sorted(points.items()))

    # Fallback to hardcoded tables
    points = dict(COMMON_POINTS)

    if application == 2020:
        points[25] = ("DI 3", "Digital input 3 status", "", True)
    elif application == 2021:
        points.update(HEATING_POINTS)
        points.update(SUPPLY_TEMP_POINT)
    elif application == 2022:
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
    elif application == 2023:
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(HW_VALVE_POINTS)
    elif application in (2024, 2025):
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(FAN_POINTS)
        if application == 2025:
            points.update(HW_VALVE_POINTS)
    elif application in (2026, 2027):
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(FAN_POINTS)
        if application == 2027:
            points.update(HW_VALVE_POINTS)

    return OrderedDict(sorted(points.items()))


def get_point_info(application: int, point_name: str) -> Optional[Dict]:
    """Get the rich metadata entry for a specific (app, point name).
    Returns a dict with keys like 'name', 'ptype', 'type', 'units', 'slope',
    'intercept', 'on_label', 'off_label', 'rw'. Returns None if not found.

    Only works when tecpoints.json (rich format) is loaded.
    """
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    # Scan entries for a name match (point_name is the lookup key from live data)
    for addr_str, info in app_data.items():
        if isinstance(info, dict) and info.get('name') == point_name:
            return info
    return None


def resolve_slot_to_name(application: int, slot: int) -> Optional[str]:
    """Look up the point name registered at a specific slot number for an app.
    Returns None if the slot isn't defined in the app's point table.

    This is what lets '-p 29' mean 'read whatever's at slot 29 for this device.'
    """
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    entry = app_data.get(str(slot))
    if isinstance(entry, dict):
        return entry.get('name')
    elif isinstance(entry, (list, tuple)) and entry:
        # Legacy format support
        return entry[0]
    return None


def get_point_slot(application: int, point_name: str) -> Optional[int]:
    """Reverse lookup: find the slot number for a point name within an app.
    Used for display — shows the Desigo-style '(29) DAY.NGT' prefix."""
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    for addr_str, info in app_data.items():
        name_in_db = None
        if isinstance(info, dict):
            name_in_db = info.get('name')
        elif isinstance(info, (list, tuple)) and info:
            name_in_db = info[0]
        if name_in_db == point_name:
            try:
                return int(addr_str)
            except (ValueError, TypeError):
                return None
    return None


def get_app_meta(application: int) -> Optional[Dict[str, Any]]:
    """Return the per-application `_meta` block from tecpoints.json (v2+).

    The v2 catalog format carries application-level metadata at the
    `_meta` key inside each app entry:

        {"descr": "VAV Cooling Only", "cab_type": "TEC", "type": "ELECTRIC",
         "rev": "VV11", "transport": "p1_fln", "has_point_data": true}

    Returns None when the catalog is older (v1), the application is unknown,
    or no `_meta` block is present. Loader-safe — auto-loads the catalog on
    first call.
    """
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not isinstance(app_data, dict):
        return None
    meta = app_data.get('_meta')
    return meta if isinstance(meta, dict) else None


def format_app_label(application: int, prefix: str = "APP ") -> str:
    """Format an application number with its catalog description (v2+).

    Returns a display-ready string like:
        "APP 2020 — VAV Cooling Only"        (v2 catalog with descr)
        "APP 2020"                            (v1 catalog or unknown app)
        ""                                    (when application is 0)

    The prefix is configurable for callers that already have an existing
    label format (e.g. `prefix="[APP "` produces `"[APP 2020 — VAV ..."`,
    suitable for inline-bracket use).
    """
    if not application:
        return ""
    meta = get_app_meta(application)
    base = f"{prefix}{application}"
    if meta and isinstance(meta.get('descr'), str) and meta['descr']:
        return f"{base} — {meta['descr']}"
    return base


def app_supports_p2(application: int) -> Optional[bool]:
    """Whether this TEC application is reachable over the P2 protocol.

    Apogee's TEC catalog spans two transports: `p1_fln` (Apogee P1 FLN bus,
    P2 reachable via 0x0986 enumerate + 0x0271/0x0220 reads) and
    `bacnet_mstp` (BACnet MSTP — addressable over BACnet/IP only when the
    panel acts as a BACnet router, NOT reachable through this protocol's
    wire opcodes). The catalog's `_meta.transport` field distinguishes
    them; `has_point_data` is False for every bacnet_mstp entry because
    the P2 catalog can't enumerate slot layouts the wire protocol doesn't
    own.

    Returns:
        True   — application is on a `p1_fln` transport (P2-reachable).
        False  — application is `bacnet_mstp` (not reachable via P2; the
                 scanner / bridge should route via BACnet).
        None   — catalog is v1 (no transport metadata) or app is unknown.
                 Callers should treat None as "assume reachable, try anyway."
    """
    meta = get_app_meta(application)
    if meta is None:
        return None
    transport = meta.get('transport')
    if transport == 'p1_fln':
        return True
    if transport == 'bacnet_mstp':
        return False
    # Unknown transport string — be conservative, return None to fall back
    # to "try anyway" behavior.
    return None


def render_point_value(value: float, info: Optional[Dict]) -> Tuple[str, str]:
    """Convert a raw float value into (display_str, value_text) using point info.

    display_str: what to show in a table cell (e.g. '74.0', 'NIGHT', '1 (ON)')
    value_text: just the label portion for digital points ('NIGHT'), empty string
                for analog points.

    If info is None or lacks labels, falls back to formatting the float.
    """
    if value is None:
        return ("—", "")

    # Digital points with on/off labels
    if info and 'on_label' in info and 'off_label' in info:
        # Siemens convention: 1 = ON/first-label, 0 = OFF/second-label
        label = info['on_label'] if value >= 0.5 else info['off_label']
        return (label, label)

    # Analog — format cleanly
    if value == int(value) and abs(value) < 100000:
        return (str(int(value)), "")
    return (f"{value:.2f}", "")


# Global cache for the full TEC point definitions
_TECPNTS_DB = None

def _load_tecpnts_db() -> Optional[Dict]:
    """Load the TEC point definitions.

    Search order:
      1. **`importlib.resources.files('p2_scanner_data') / 'tecpoints.json'`** —
         the canonical location when installed via `pip install p2_scanner`.
         The catalog lives in a data-only sibling package (see H-8 in the
         repo-health punch list) so setuptools `package-data` carries it
         to site-packages.
      2. Module-sibling `tecpoints.json` (repo-clone-and-run-in-place).
      3. CWD `tecpoints.json` (legacy convenience for users who copied the
         file into their working directory).
      4. Legacy `tecpnts.json` at the same locations.
      5. **The catalog embedded in this module** (`_TECPOINTS_GZ_B64`). This is
         the one that actually serves nearly every install: it makes the
         scanner a single self-contained file. Anything found above overrides
         it, so a site can ship a newer or trimmed catalog without editing
         this module.

    Returns the parsed catalog. In practice never None, because step 5 is
    always available; None is reserved for a corrupted embedded blob.
    """
    import os

    # Path 1: installed package data via importlib.resources. Available on
    # Python 3.9+; the package itself is created by the `p2_scanner_data`
    # sibling directory in the repo.
    try:
        import importlib.resources
        ref = importlib.resources.files('p2_scanner_data') / 'tecpoints.json'
        if ref.is_file():
            with ref.open('r', encoding='utf-8') as f:
                return json.load(f)
    except (ImportError, ModuleNotFoundError, FileNotFoundError, AttributeError):
        # ImportError/ModuleNotFoundError: package not installed (running
        # from a non-package layout, e.g. repo clone before round 7).
        # FileNotFoundError: package installed but bundle missing.
        # AttributeError: Python < 3.9's importlib.resources lacked .files().
        pass

    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    # Path 2-4: filesystem search for repo-clone-and-run-in-place workflows
    # and legacy filenames. Belt-and-suspenders — covers cases where:
    #   - importlib.resources can't find p2_scanner_data because of an
    #     unusual sys.path setup
    #   - Bridge has the catalog as a flat file (not in p2_scanner_data/)
    #   - Older repo state still has tecpoints.json at the repo root
    #   - User dropped tecpoints.json into their CWD manually
    search_paths = []
    # New canonical layout (H-8 / round 7) — sibling data package
    for base in (here, cwd):
        search_paths.append(os.path.join(base, 'p2_scanner_data', 'tecpoints.json'))
    # Pre-H-8 flat layout at module-sibling / CWD / unqualified path
    for base in (here, cwd, ''):
        search_paths.append(os.path.join(base, 'tecpoints.json'))
    # Legacy filename
    for base in (here, cwd, ''):
        search_paths.append(os.path.join(base, 'tecpnts.json'))
    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
    # Path 5: the catalog embedded in this file — makes the scanner a
    # self-contained single file (no external tecpoints.json required). An
    # external file found above still overrides this embedded copy.
    try:
        import gzip as _gz, base64 as _b64
        return json.loads(_gz.decompress(_b64.b64decode(_TECPOINTS_GZ_B64)))
    except Exception:
        return None


# List of key points to read first (quick scan)
QUICK_SCAN_POINTS = [
    "APPLICATION", "ROOM TEMP", "CTL STPT", "CTL TEMP",
    "DAY CLG STPT", "NGT CLG STPT", "DAY HTG STPT", "NGT HTG STPT",
    "HEAT.COOL", "DAY.NGT", "FLOW", "AIR VOLUME",
    "DMPR POS", "VLV1 POS", "VLV2 POS",
    "HTG LOOPOUT", "CLG LOOPOUT", "ERROR STATUS",
]


# ═══════════════════════════════════════════════════════════════════════════════
# P2 PROTOCOL IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

class P2Message:
    """Represents a single P2 protocol message."""
    # Message types
    TYPE_CONNECT   = 0x2E   # legacy 2nd channel (announce + DB-change/replication); name kept for compat
    TYPE_ANNOUNCE  = 0x2F   # modern 2nd channel (same role as 0x2E, by firmware generation)
    TYPE_DATA      = 0x33
    TYPE_HEARTBEAT = 0x34

    # Response direction byte (first byte of S2C payload)
    DIR_REQUEST   = 0x00   # C2S
    DIR_SUCCESS   = 0x01   # S2C success
    DIR_ERROR     = 0x05   # S2C error (followed by u16 BE error code)

    # Opcode / marker constants (big-endian 16-bit opcodes live inside 0x33/0x34 payloads)
    OP_IDENTIFY        = 0x4640  # mid-session identity refresh
    OP_READ_EXTENDED   = 0x0271  # point read (legacy-dialect clients)
    OP_READ_SHORT      = 0x0220  # point read (modern-dialect clients)
    OP_WRITE_NOVALUE   = 0x0273  # Desigo's UI point-existence probe (dominant use, 500x more common than alarm-ack); also AlarmAckTrigger before 0x0509
    OP_VALUE_PUSH      = 0x0274  # bidirectional: DCC->PXC virtual-write, or PXC->DCC COV
    OP_WRITE_QUALITY   = 0x0240  # WriteWithQuality. 5034 PXC->DCC NONE/sep=0x00 (ACK'd) vs 5033 DCC->PXC SYST/sep=0x23 (errors 0x0E15 — Desigo retries with 0x4222)
    OP_ENUM_FLN        = 0x0986  # enumerate FLN devices
    OP_ENUM_POINTS     = 0x0981  # enumerate all points (cursor-based)
    OP_ENUM_PROGRAMS   = 0x0985  # enumerate PPCL programs — response carries source text
    OP_SYSINFO         = 0x0100  # firmware / model (legacy). Also the CONNECT-response opcode on PME1252 V2.8.10 — panels echo this in 0x2E body instead of 0x4640.
    OP_SYSINFO_COMPACT = 0x010C  # firmware / model (newer; 2-byte request)
    OP_ROUTING_TABLE   = 0x4634  # BLN routing-table announce/push (port-agnostic — observed on both 5033 and 5034)
    OP_BULK_READ       = 0x4221  # bulk property read (constant 273-byte preallocated request body — see APOGEE_P2_SPEC.md §12.7 / §29.10. Distinct from 0x4220's 222-byte form.)
    OP_BULK_WRITE      = 0x4222  # BulkPropertyWrite — the canonical opcode for SYST setpoint writes; 0x0240 against SYST returns 0x0E15
    OP_PROPERTY_ECHO   = 0x0241  # SYST-scoped PropertyEcho / DefaultPropertyResolve — see OPCODES.md (May 2026 paired-response audit)
    OP_STATUS_QUERY    = 0x0050  # leaks supervisor name (bare form) without authentication; useful cold-discovery primitive
    # ---- EBLN management set, 0x4620-0x4642 ------------------------------
    # Validated span 0x4620-0x4640. Names from the AP2 function enumeration,
    # corroborated by the command
    # string pool of a shipped EBLN diagnostic binary (ordered by opcode and
    # validated against five independently wire-established bindings).
    #
    # Only 0x4633-0x4636 and 0x4640 have ever been seen in captured traffic.
    # The rest do not occur in normal operation at all, which cuts two ways:
    # any occurrence is anomalous and worth alerting on, and nothing in the
    # protocol restricts them to a supervisor -- the identity check is the
    # same for every caller, so "supervisor-only" is a property of which tool
    # ships them, not an enforced one.
    OP_EBLN_FP_NAME_SET          = 0x4620
    OP_EBLN_FP_IP_CONFIGURE      = 0x4621
    OP_EBLN_FP_TCP_PORTS_CONFIG  = 0x4622
    OP_EBLN_FP_DISPLAY           = 0x4623
    OP_EBLN_STORAGE_NODES_REPL   = 0x4624
    OP_EBLN_STORAGE_NODES_DISP   = 0x4625
    OP_EBLN_REPORT_PRINTER_REPL  = 0x4626
    OP_EBLN_REPORT_PRINTER_DISP  = 0x4627
    OP_EBLN_TRUNK_SETTINGS_REPL  = 0x4628
    OP_EBLN_TRUNK_SETTINGS_DISP  = 0x4629   # yields the TRUNK_SETTINGS report
    OP_EBLN_FP_SITE_NAME_SET     = 0x462A
    OP_EBLN_FP_BLN_NAME_SET      = 0x462B   # sets the BLN name -- the only gate
    OP_EBLN_FP_MULTICAST_CONFIG  = 0x462C
    OP_EBLN_HOSTTABLE_ADD        = 0x462D
    OP_EBLN_HOSTTABLE_REMOVE     = 0x462E
    OP_EBLN_HOSTTABLE_DISPLAY    = 0x462F   # the (Permanent) name->IP table
    OP_EBLN_NODE_ADD             = 0x4630
    OP_EBLN_NODE_REMOVE          = 0x4631
    OP_EBLN_NODE_LIST_DISPLAY    = 0x4632
    OP_EBLN_REPL_NOTIFY          = 0x4633
    OP_EBLN_REPL_PULL            = 0x4634   # == OP_ROUTING_TABLE above; see note
    OP_EBLN_REPL_PULL_MORE       = 0x4635
    OP_EBLN_REPL_CHANGES         = 0x4636
    OP_EBLN_POINT_LOCATION_GET   = 0x4637
    OP_EBLN_MAC_ADDRESS_SET      = 0x4638
    OP_EBLN_MII_CONFIGURE        = 0x4639
    OP_EBLN_MII_DISPLAY          = 0x463A
    OP_EBLN_IP_DISPLAY           = 0x463B
    OP_EBLN_PORTS_DISPLAY        = 0x463C
    OP_EBLN_MULTICAST_DISPLAY    = 0x463D
    OP_EBLN_MAC_ADDRESS_DISPLAY  = 0x463E
    OP_EBLN_REPL_DIAG_NODELIST   = 0x464C   # AP2 enum + firmware report
                                            # name + captured body all agree
    OP_EBLN_TELNET_ENABLE        = 0x4644   # AP2 enum; NOT 0x4641
    OP_EBLN_TELNET_DISABLE       = 0x4645   # AP2 enum; NOT 0x4642
    #
    # Naming note: OP_ROUTING_TABLE (0x4634) above was named from observed
    # behaviour ("BLN routing-table announce/push"). The AP2 name for the same
    # opcode is Repl Pull, which fits the traffic -- 1,267 requests, 59% of them
    # panel-initiated, pulling replication changes. Both constants are kept; the
    # older one is not renamed because callers depend on it.

    OP_PROPERTY_QUERY  = 0x4200  # PropertyQuery (small ~30-40B browse form OR 222B preallocated deep-read form)

    # Byte-sequence markers used by pcap/stream scanners looking for these opcodes.
    # Kept as raw bytes for fast substring search.
    MARKER_KEEPALIVE    = b'\x46\x40'
    MARKER_VALUE_PUSH   = b'\x02\x74'
    MARKER_WRITE_QUAL   = b'\x02\x40'
    MARKER_ROUTING_TBL  = b'\x46\x34'
    MARKER_ALARM_REPORT = b'\x05\x08'  # 0x0508 ALARM_PRINT (panel->supervisor alarm push)
    MARKER_READ         = b'\x02\x71'
    MARKER_BROWSE       = b'\x42'

    # Back-compat alias — original doc called 0x0274 "COV notification".
    # Reality (confirmed from dual-port captures): 0x0274 is bidirectional.
    # On 5033 (DCC->PXC) it's a virtual-point write into the panel's model.
    # On the supervisor port (panel->supervisor direction) it's the genuine unsolicited COV. Same opcode,
    # direction-dependent semantic. Prefer MARKER_VALUE_PUSH for new code.
    MARKER_COV = MARKER_VALUE_PUSH

    # Bare-opcode session keepalives (APOGEE_P2_SPEC.md §9.13, §28.6).
    # Panels emit these as 2-byte payloads with no direction byte and no
    # body — the opcode IS the payload. Distinct from request/response
    # framing; an in-flight read should not pair with these.
    BARE_PING_OPCODES = frozenset({0x0951, 0x0954, 0x0955, 0x0956, 0x0959})

    def __init__(self, msg_type: int, sequence: int, payload: bytes):
        self.msg_type = msg_type
        self.sequence = sequence
        self.payload = payload
        # is_response covers both success (0x01) and error (0x05) per
        # APOGEE_P2_SPEC.md §8.3. Direction byte 0x00 is a request from
        # the peer or our own request; anything else is a response that
        # _recv_response should pair to the in-flight request. An earlier
        # version checked == 0x01 only, which silently filtered out error
        # responses and made the error-handling code in _parse_*_response
        # unreachable (errors looked like timeouts to the caller).
        self.is_response = payload[0] in (0x01, 0x05) if payload else False
        # Bare-opcode keepalive ping: exactly 2 bytes, opcode in the set
        # documented in §9.13. Non-matching 2-byte payloads (e.g. an
        # error reply truncated to direction+code) are NOT bare pings —
        # the opcode-set test discriminates.
        self.is_bare_ping = (
            len(payload) == 2
            and struct.unpack('>H', payload)[0] in self.BARE_PING_OPCODES
        ) if payload else False

    def to_bytes(self) -> bytes:
        total_len = 12 + len(self.payload)
        header = struct.pack('>III', total_len, self.msg_type, self.sequence)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['P2Message']:
        if len(data) < 12:
            return None
        total_len, msg_type, sequence = struct.unpack('>III', data[:12])
        payload = data[12:total_len]
        return cls(msg_type, sequence, payload)



# ---------------------------------------------------------------------------
# EBLN read/write split, and the operations this tool will not emit.
#
# This is an ALLOWLIST, not a blocklist. A blocklist cannot protect against an
# opcode nobody has named yet: a May 2026 sweep sent 0x4641 blind and the panel
# returned success -- that opcode is Telnet Enable, and the same sweep walked a
# range containing BLN Name Set and MAC Address Set; 0x4644 Telnet Enable was
# sent and returned success. Naming them afterwards is what made the risk
# visible, so the guard is expressed positively.

EBLN_READS = frozenset({
    P2Message.OP_EBLN_FP_DISPLAY,            P2Message.OP_EBLN_STORAGE_NODES_DISP,
    P2Message.OP_EBLN_REPORT_PRINTER_DISP,   P2Message.OP_EBLN_TRUNK_SETTINGS_DISP,
    P2Message.OP_EBLN_HOSTTABLE_DISPLAY,     P2Message.OP_EBLN_NODE_LIST_DISPLAY,
    P2Message.OP_EBLN_POINT_LOCATION_GET,    P2Message.OP_EBLN_MII_DISPLAY,
    P2Message.OP_EBLN_IP_DISPLAY,            P2Message.OP_EBLN_PORTS_DISPLAY,
    P2Message.OP_EBLN_MULTICAST_DISPLAY,     P2Message.OP_EBLN_MAC_ADDRESS_DISPLAY,
    P2Message.OP_EBLN_REPL_DIAG_NODELIST,
})

EBLN_WRITES = frozenset({
    P2Message.OP_EBLN_FP_NAME_SET,           P2Message.OP_EBLN_FP_IP_CONFIGURE,
    P2Message.OP_EBLN_FP_TCP_PORTS_CONFIG,   P2Message.OP_EBLN_STORAGE_NODES_REPL,
    P2Message.OP_EBLN_REPORT_PRINTER_REPL,   P2Message.OP_EBLN_TRUNK_SETTINGS_REPL,
    P2Message.OP_EBLN_FP_SITE_NAME_SET,      P2Message.OP_EBLN_FP_BLN_NAME_SET,
    P2Message.OP_EBLN_FP_MULTICAST_CONFIG,   P2Message.OP_EBLN_HOSTTABLE_ADD,
    P2Message.OP_EBLN_HOSTTABLE_REMOVE,      P2Message.OP_EBLN_NODE_ADD,
    P2Message.OP_EBLN_NODE_REMOVE,           P2Message.OP_EBLN_MAC_ADDRESS_SET,
    P2Message.OP_EBLN_MII_CONFIGURE,         P2Message.OP_EBLN_TELNET_ENABLE,
    P2Message.OP_EBLN_TELNET_DISABLE,
})

# Deliberately NOT in EBLN_READS: 0x464A, 0x464B, 0x464D, 0x464E, 0x464F and
# 0x4650. Every one of them answered success with a structured body when
# probed, so it is tempting to call them reads. Do not.
#
# The panel firmware names six EBLN replication reports, and two of them are
# "Add Data Store" and "Delete Data Store". Which opcode emits which report
# is unknown -- six names against seven responding opcodes, over a range
# whose gaps are unknown. Guessing a positional mapping across an opcode
# range with unknown gaps is exactly what produced a wrong Telnet binding
# earlier in this project. If the guess is wrong here the cost is not a
# mislabelled constant, it is emitting a data-store mutation at a customer
# site. 0x464C is in the allowlist because three independent sources agree
# on it; the rest wait for evidence.
#
# Note also that "returned data and appeared to change nothing" is not proof
# of being side-effect-free. It is proof of nothing observed from outside.

# Denial-of-service risk, independent of read/write: a single well-formed
# 0x4636 carrying the standard SYST scope body has been observed to take a
# panel's P2 task out for ~18 s -- longer than a real power cycle of the same
# panel. 0x4647 shows the same signature.
EBLN_STALL_RISK = frozenset({0x4636, 0x4647})

REFUSED_OPCODES = EBLN_WRITES | EBLN_STALL_RISK

# The EBLN replication diagnostic block. Every value here answered success with
# a structured body when probed, and all but 0x464C are unidentified: the panel
# firmware names six replication reports, two of which are "Add Data Store" and
# "Delete Data Store". Until a specific opcode is tied to a specific report,
# this range is closed rather than open -- an allowlist, because the failure
# mode of guessing wrong is a data-store mutation on someone's panel.
EBLN_DIAGNOSTIC_RANGE = range(0x4646, 0x4651)


def check_emit_allowed(opcode: int) -> None:
    """Raise if an opcode must never be emitted by this tool.

    Called from P2Connection._send_message on every outbound frame.
    Deliberately not overridable by a flag: a determined caller can edit the
    source, but nobody does that by accident.

    Coverage, stated honestly: a few standalone helpers (dialect probe, cold
    discovery) build raw frames and call sock.sendall directly, bypassing this
    check. Audited at the time of writing -- the only EBLN opcodes any of them
    emit are 0x4634 REPL_PULL and 0x4640 PING, both permitted. If you add a
    raw-frame path, route it through here.
    """
    if opcode is None:
        return
    if opcode in EBLN_STALL_RISK:
        raise PermissionError(
            f"0x{opcode:04X} is a denial-of-service risk (observed ~18 s panel "
            f"outage) and is never emitted by this tool.")
    if opcode in EBLN_WRITES:
        raise PermissionError(
            f"0x{opcode:04X} is an EBLN write/configuration operation and is "
            f"never emitted by this tool. Use the panel console if you intend "
            f"to change configuration.")
    if opcode in EBLN_DIAGNOSTIC_RANGE and opcode not in EBLN_READS:
        raise PermissionError(
            f"0x{opcode:04X} is in the EBLN replication diagnostic block and "
            f"has not been identified. Two of the six reports this family "
            f"produces are 'Add Data Store' and 'Delete Data Store', and the "
            f"opcode-to-report mapping is unknown, so this tool will not send "
            f"it. 0x464C is permitted because three independent sources agree "
            f"it is the read-only NodeList report.")

class P2Connection:
    """Manages a TCP connection to a PXC controller using the P2 protocol."""

    def __init__(self, host: str, port: Optional[int] = None,
                 network: Optional[str] = None,
                 scanner_name: Optional[str] = None):
        # Defaults resolve at CALL time, not definition time. This avoids the
        # module-load-capture gotcha where a caller like P2Connection(ip) would
        # otherwise bake in whatever the globals happened to be when Python
        # first parsed this class — even if load_config() later updated them.
        self.host = host
        self.port = port if port is not None else P2_PORT
        self.network = network if network is not None else P2_NETWORK
        # Honor an explicit per-connection scanner_name argument; else
        # delegate to effective_scanner_name() which auto-builds the
        # canonical `<SITE>DCC-SVR|5033` form when site is known.
        self.scanner_name = scanner_name if scanner_name is not None else effective_scanner_name()
        self.sock: Optional[socket.socket] = None
        # Start sequence at a random 24-bit value matching real Desigo behavior.
        # APOGEE_P2_SPEC.md §5.2 / §8.4 + corpus analysis show real DCC
        # uses session-monotonic seqs in the millions; seq=0 / seq=1 is a clear
        # scanner fingerprint and may be rejected by stricter future firmware.
        self.sequence = secrets.randbits(24)
        self.node_name = None      # Learned from responses
        self._recv_buffer = b""
        # Dialect detection — see _handshake() for why this matters.
        # Initialized to TYPE_DATA (legacy PME1252 and earlier). If the target
        # turns out to speak the PME1300 dialect, _handshake() flips this to
        # TYPE_HEARTBEAT and every subsequent message uses the new type.
        self.op_msg_type = P2Message.TYPE_DATA
        # Optional event hook for frames _recv_response chooses not to pair
        # with the in-flight request — bare-opcode keepalives (§9.13),
        # out-of-window sequence numbers, async COV pushes on the same
        # socket, etc. Default is None (silently discard, matching prior
        # behavior). Callers can attach a hook to surface what's being
        # dropped:
        #     conn.on_discarded_frame = lambda msg, reason: ...
        # `reason` is one of: "bare_ping", "stale_seq", "unmatched".
        self.on_discarded_frame: Optional[Callable[[P2Message, str], None]] = None

    def connect(self, node_name: str = "node") -> bool:
        """Establish TCP connection and P2 session with the PXC controller."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(CONNECT_TIMEOUT)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(READ_TIMEOUT)
        except (socket.error, socket.timeout) as e:
            print(f"  [ERROR] Connection to {self.host}:{self.port} failed: {e}")
            return False

        # P2 session handshake: send a keepalive/heartbeat to establish the session
        # The PXC won't respond to read requests until it sees this.
        if not self._handshake(node_name):
            print(f"  [ERROR] P2 handshake failed — controller did not respond")
            self.close()
            return False

        return True

    def _handshake(self, node_name: str) -> bool:
        """Establish a P2 session, auto-detecting the PXC's message-type dialect.

        Two dialects are in use across Siemens PXC firmware:
          - **Legacy (PME1252 and earlier)**: operational traffic uses TYPE_DATA (0x33).
            The handshake exchange itself is 0x33-in, 0x33-out.
          - **Modern (firmware build PME1300, PXME hardware platform)**:
            operational traffic uses TYPE_HEARTBEAT (0x34). The handshake
            is 0x34-in, 0x34-out, and the panel typically initiates with
            a 0x2F ANNOUNCE to the supervisor.

        A PXC speaking the modern dialect will silently drop our 0x33 handshake
        (not RST, not respond — just ignore). So the detection logic is: try 0x33
        first with a short timeout; if nothing comes back, retry as 0x34. Whichever
        wins is locked in on self.op_msg_type for every subsequent message this
        connection sends.

        Result is cached in _DIALECT_CACHE keyed by host IP, so repeated connects
        to the same PXC within one process skip the probe.

        Important: we must rebuild and re-send the identity block with a fresh seq
        on retry. The PXC ties its response to the seq of the request that reached
        it, so reusing the original seq after a timeout is fine for our own tracking
        but pointless — the first seq's response will never come.
        """
        net = _wire_name(self.network, 'BLN name (network)')
        src = _wire_name(node_name, 'node name')
        scanner = _wire_name(self.scanner_name, 'scanner name')
        site = _wire_name(P2_SITE, 'site name')

        routing = (
            b'\x00' +
            net + b'\x00' +
            src + b'\x00' +
            net + b'\x00' +
            scanner + b'\x00'
        )

        def build_identity():
            # Fresh timestamp on every attempt. PXCs may reject handshakes with
            # suspiciously old timestamps from the same scanner — rebuilding it
            # per attempt keeps the retry clean.
            #
            # Trailer layout (16 bytes total) per APOGEE_P2_SPEC.md Connection-handshake
            # section, verified against the corpus:
            #   1 byte   separator (0x00)
            #   3 bytes  flags (0x01 0x01 0x00)  — third byte is the role flag;
            #            0x00 = "configured peer" (DCC-style), what we want
            #   5 bytes  reserved zeros
            #   4 bytes  timestamp (BE u32, Unix epoch seconds)
            #   2 bytes  session id (0x00 0x00 = panel-style; bouncer accepts;
            #            real DCC uses per-session non-zero values but copying
            #            one risks colliding with an active session)
            #   1 byte   trailing null
            return (
                b'\x46\x40' +
                b'\x01' + struct.pack('>H', len(scanner)) + scanner +
                b'\x01' + struct.pack('>H', len(site)) + site +
                b'\x01' + struct.pack('>H', len(net)) + net +
                b'\x00\x01\x01\x00' +                  # separator + 3 flag bytes
                b'\x00\x00\x00\x00\x00' +              # 5 reserved zeros
                struct.pack('>I', int(time.time())) + # 4-byte timestamp
                b'\x00\x00' +                          # 2-byte session id
                b'\x00'                                # trailing null
            )

        # ── Fast path A — registry lookup by cached firmware build tag.
        # APOGEE_P2_SPEC.md §30.4. Survives process restart via
        # site.json's known_builds field; can also fast-fail BACnet panels
        # (BME####) without paying the §11.2 dialect-probe wait.
        build_tag = firmware_registry.get_cached_build_tag(self.host)
        if build_tag is not None:
            negotiated = firmware_registry.negotiate_dialect(build_tag)
            if negotiated is not None:
                dialect, _read_family = negotiated
                if dialect == 'n/a':
                    print(f"  [INFO] {self.host} build {build_tag} is "
                          "BACnet firmware; unreachable via P2.")
                    return False
                seq = self._next_seq()
                mt = (P2Message.TYPE_HEARTBEAT if dialect == 'modern'
                      else P2Message.TYPE_DATA)
                msg = P2Message(mt, seq, routing + build_identity())
                if self._send_message(msg):
                    resp = self._recv_response(seq, max_attempts=5)
                    if resp is not None:
                        self.op_msg_type = mt
                        _DIALECT_CACHE[self.host] = (
                            0x33 if mt == P2Message.TYPE_DATA else 0x34)
                        return True
                # Tag is stale (firmware upgrade, panel swap, etc.).
                # Evict and fall through to the probe path.
                firmware_registry.evict_build_tag(self.host)
                self._recv_buffer = b""

        # ── Fast path B — process-local dialect cache.
        # Skip the probe if we've talked to this panel before this run.
        cached_dialect = _DIALECT_CACHE.get(self.host)
        if cached_dialect is not None:
            seq = self._next_seq()
            mt = P2Message.TYPE_DATA if cached_dialect == 0x33 else P2Message.TYPE_HEARTBEAT
            msg = P2Message(mt, seq, routing + build_identity())
            if not self._send_message(msg):
                return False
            resp = self._recv_response(seq, max_attempts=5)
            if resp is not None:
                self.op_msg_type = mt
                return True
            # Cached value didn't work — maybe firmware upgraded or cache stale.
            # Fall through to full probe, but evict the bad cache entry first.
            _DIALECT_CACHE.pop(self.host, None)
            self._recv_buffer = b""

        # Attempt 1: legacy TYPE_DATA (0x33) dialect.
        seq = self._next_seq()
        msg = P2Message(P2Message.TYPE_DATA, seq, routing + build_identity())
        if not self._send_message(msg):
            return False

        # Short first timeout — if the target speaks the legacy dialect, it
        # responds in well under a second. Waiting the full READ_TIMEOUT here
        # would make every modern-dialect PXC painfully slow to detect.
        original_timeout = self.sock.gettimeout() if self.sock else READ_TIMEOUT
        try:
            if self.sock:
                self.sock.settimeout(HANDSHAKE_PROBE_TIMEOUT)
            resp = self._recv_response(seq, max_attempts=3)
        finally:
            if self.sock:
                try: self.sock.settimeout(original_timeout)
                except Exception: pass

        if resp is not None:
            # Confirm the response msg_type — this is what the panel wants us
            # to speak. The common case (PME1252) will be TYPE_DATA; odd panels
            # that respond with TYPE_HEARTBEAT to a TYPE_DATA probe are rare
            # but handled correctly here.
            self.op_msg_type = resp.msg_type if resp.msg_type in (
                P2Message.TYPE_DATA, P2Message.TYPE_HEARTBEAT
            ) else P2Message.TYPE_DATA
            _DIALECT_CACHE[self.host] = 0x33 if self.op_msg_type == P2Message.TYPE_DATA else 0x34
            return True

        # Attempt 2: modern TYPE_HEARTBEAT (0x34) dialect.
        # Before retrying we need to drain any stale bytes in our recv buffer —
        # a late response from attempt 1 would otherwise confuse the next read.
        self._recv_buffer = b""
        seq = self._next_seq()
        msg = P2Message(P2Message.TYPE_HEARTBEAT, seq, routing + build_identity())
        if not self._send_message(msg):
            return False

        resp = self._recv_response(seq, max_attempts=5)
        if resp is not None:
            self.op_msg_type = P2Message.TYPE_HEARTBEAT
            _DIALECT_CACHE[self.host] = 0x34
            return True

        return False

    def close(self):
        """Close the TCP connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _next_seq(self) -> int:
        seq = self.sequence
        self.sequence += 1
        return seq

    def _build_routing(self, dest_node: str, is_request: bool = True) -> bytes:
        """Build the P2 routing header. P2 puts destination first, then source."""
        flag = b'\x00' if is_request else b'\x01'
        src = _wire_name(self.scanner_name, 'scanner name')
        dst = _wire_name(dest_node, 'destination node name')
        net = _wire_name(self.network, 'BLN name (network)')
        return flag + net + b'\x00' + dst + b'\x00' + net + b'\x00' + src + b'\x00'

    def _send_message(self, msg: P2Message) -> bool:
        """Send a P2 message over the TCP connection.

        Every outbound frame passes check_emit_allowed() first. The check
        lived here unenforced for one release -- defined, documented in the
        commit message, and called from nowhere. A safety guard that is not
        on the path is not a safety guard.
        """
        if not self.sock:
            return False
        check_emit_allowed(getattr(msg, "opcode", None))
        try:
            self.sock.sendall(msg.to_bytes())
            return True
        except socket.error as e:
            print(f"  [ERROR] Send failed: {e}")
            return False

    def _recv_message(self) -> Optional[P2Message]:
        """Receive a single P2 message from the connection."""
        if not self.sock:
            return None

        try:
            # Read until we have at least 12 bytes for the header
            while len(self._recv_buffer) < 12:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            # Parse the total length from the header
            total_len = struct.unpack('>I', self._recv_buffer[:4])[0]

            # Sanity-check the length. P2 frames are bounded; an unbounded
            # value here means either framing desync or a hostile peer sending
            # a forged length field. Either way, refusing to read 4GB into
            # memory is the right move. Same threshold as the supervisor-port listener.
            if total_len < 12 or total_len > 65536:
                self._recv_buffer = b''
                return None

            # Read until we have the full message
            while len(self._recv_buffer) < total_len:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            # Extract the message and advance the buffer
            msg_data = self._recv_buffer[:total_len]
            self._recv_buffer = self._recv_buffer[total_len:]
            return P2Message.from_bytes(msg_data)

        except socket.timeout:
            return None
        except socket.error as e:
            print(f"  [ERROR] Receive failed: {e}")
            return None

    def _recv_response(self, expected_seq: int, max_attempts: int = 10) -> Optional[P2Message]:
        """Receive a response paired to the expected request sequence.

        Pairs with a sliding-window tolerance, not strict equality, per
        APOGEE_P2_SPEC.md §5.2 / §24.5. In busy sessions about 10% of
        request/response pairs show the panel's response sequence running
        1-17 behind the request sequence (never ahead) due to panel-side
        pipelining lag. Strict equality treats those as unrelated traffic
        and silently loses ~10% of responses.

        Accepts any success response whose sequence is within the last 20
        frames of the expected sequence. Modular subtraction handles the
        rare 2^32 wrap case correctly (lag is always >= 0 per spec, so a
        "negative" raw difference wraps to a large positive value and
        gets rejected by the window check).
        """
        SEQ_WINDOW = 20
        for _ in range(max_attempts):
            msg = self._recv_message()
            if msg is None:
                return None
            if msg.is_response:
                lag = (expected_seq - msg.sequence) & 0xFFFFFFFF
                if lag <= SEQ_WINDOW:
                    return msg
                # Response from the same peer but outside the pairing window
                # — almost certainly a stale reply for a prior request.
                self._discard_frame(msg, "stale_seq")
                continue
            # Bare-opcode session keepalive — explicitly recognized so the
            # discard reason is accurate (was previously routed through the
            # generic "unmatched" path).
            if msg.is_bare_ping:
                self._discard_frame(msg, "bare_ping")
                continue
            # Any other frame: peer-initiated traffic on the same socket
            # — async COV, alarm report, identity refresh, etc.
            self._discard_frame(msg, "unmatched")
        return None

    def _discard_frame(self, msg: 'P2Message', reason: str) -> None:
        """Route a frame that won't pair with the in-flight request to the
        optional event hook. No-op when no hook is attached. Used to surface
        bare pings and async pushes that _recv_response would otherwise drop
        silently."""
        hook = getattr(self, 'on_discarded_frame', None)
        if hook is None:
            return
        try:
            hook(msg, reason)
        except Exception:
            # Hook errors must not affect protocol flow. Best-effort logging
            # only when DEBUG_READS is set.
            if DEBUG_READS:
                import traceback
                print(f"    [DEBUG] on_discarded_frame hook raised: "
                      f"{traceback.format_exc().strip()}")

    def read_point(self, device: str, point_name: str,
                   node_name: str = "node") -> Optional[Dict[str, Any]]:
        """
        Read a single point value from a TEC device.

        Args:
            device: TEC device name (e.g., "DEVICE1")
            point_name: Subpoint name (e.g., "ROOM TEMP")
            node_name: P2 node name in lowercase (e.g., "node1")

        Returns:
            Dict with 'value', 'units', 'description', or None on failure.
        """
        seq = self._next_seq()

        # Build routing header
        routing = self._build_routing(node_name)

        # Build read request payload
        # Format: [routing] 02 71 00 00 01 00 [dev_len] [device] 01 00 [pt_len] [point] 00 FF
        dev_bytes = device.encode('ascii')
        pt_bytes = point_name.encode('ascii')

        read_payload = (
            routing +
            b'\x02\x71\x00\x00' +
            b'\x01' + struct.pack('>H', len(dev_bytes)) + dev_bytes +
            b'\x01' + struct.pack('>H', len(pt_bytes)) + pt_bytes +
            b'\x00\xff'
        )

        msg = P2Message(self.op_msg_type, seq, read_payload)
        if not self._send_message(msg):
            return None

        # Wait for response
        resp = self._recv_response(seq)
        if resp is None:
            # No response at all — surface last_error if we have structured info
            if getattr(self, 'last_error', None):
                name, desc = self.last_error
                if DEBUG_READS:
                    print(f"    [DEBUG] {device}/{point_name}: AP2 error {name} ({desc})")
            elif DEBUG_READS:
                print(f"    [DEBUG] {device}/{point_name}: no response from PXC")
            return None

        parsed = self._parse_read_response(resp)
        if parsed is None and DEBUG_READS:
            print(f"    [DEBUG] {device}/{point_name}: parse failed")
            print(f"    [DEBUG]   response payload ({len(resp.payload)}B): {resp.payload.hex()}")
        return parsed

    def _parse_read_response(self, msg: P2Message) -> Optional[Dict[str, Any]]:
        """Parse a point read response message."""
        payload = msg.payload
        result = {
            'value': None,
            'units': '',
            'description': '',
            'point_name': '',
            'device_name': '',
            'data_type': 'unknown',
        }

        # ─── Status-byte error path (direction byte 0x05 + u16 BE error code after routing header)
        # This handles the common "object not found" case that reads hit on BLN-sourced
        # virtual points that don't exist on the target panel. Without this branch, the
        # response falls through to the value-block scan below and returns None, which loses
        # the distinction between "no response from PXC" and "PXC said no such point."
        if payload and payload[0] == P2Message.DIR_ERROR:
            # Advance past the 4 null-terminated routing-header strings
            i = 1
            nulls = 0
            while i < len(payload) and nulls < 4:
                if payload[i] == 0:
                    nulls += 1
                i += 1
            if i + 2 <= len(payload):
                err_code = struct.unpack('>H', payload[i:i+2])[0]
                err_name = _P2_STATUS_ERRORS.get(err_code, f'unknown_0x{err_code:04X}')
                result['error'] = {'code': err_code, 'name': err_name}
                if hasattr(self, 'last_error'):
                    self.last_error = (err_name, f'response status-byte error 0x{err_code:04X}')
                if DEBUG_READS:
                    print(f"    [DEBUG] PXC returned status-byte error: {err_name} (0x{err_code:04X})")
            # Keep the existing "return None on error" contract — callers check for None.
            return None

        # Find the value block. Confirmed from protocol analysis:
        #
        # ALL valid responses have this layout in the value block region:
        #   [last point_name LP-string] [01 00 00] [7 metadata bytes] [4-byte float]
        #                                                              ^^ float at +10
        #
        # Four observed shapes of the 7 metadata bytes:
        #   Shape A  (0x0271 resp, 3FFFFFFF case): 3f ff ff ff 00 00 00
        #   Shape B1 (0x0271 resp, zero-sentinel): 00 00 00 00 00 00 00
        #   Shape B2 (0x0220 resp, explicit type): 00 00 00 00 00 00 XX
        #            where XX = data-type code (0x03 = analog, etc.)
        #   Shape C  (app-2500-ish negative values): same as B1/B2 but float
        #            starts 0xbf (negative floats)
        #
        # Critical: the payload also has a TRAILING metadata block (min/max limits,
        # resolution) that looks almost identical to [01 00 00][zeros][float]. A
        # pure structural scan false-positives on it. The trailing block is always
        # preceded by bytes from the VALUE block itself (the float); the real
        # value block is always preceded by an ASCII character (last byte of a
        # length-prefixed point name string).
        #
        # So: scan FORWARD for [01 00 00] whose position-1 byte is an ASCII
        # character from A-Z, 0-9, space, or common punctuation. That's the
        # point-name tail, and the next 10 bytes are our value block.

        flags_idx = -1
        # Predicate must be tight: 0x0981 enumerate responses contain `01 00 00`
        # bytes embedded in per-entry metadata (e.g. `01 00 00 04 00 02 00 00`
        # right after the device-name TLV) whose preceding byte is ASCII —
        # those false-match a permissive scan. The sentinel at +3..+6 must be
        # one of the two known shapes (3F FF FF FF wildcard OR all-zero
        # explicit-flags), and byte +7 (the "reserved" byte of the 3-byte
        # status group) must be 0x00. Byte +8 (comm_status) is INTENTIONALLY
        # NOT constrained — it's 0x00 for live and 0x01 for STALE, and an
        # earlier version of this predicate that required +8 == 0x00 silently
        # filtered out every comm-faulted response (see APOGEE_P2_SPEC.md §15).
        #
        # Loop bound: marker (3 bytes) + 7-byte metadata + 4-byte float = 14 bytes,
        # so the highest valid `i` is len(payload) - 14, i.e. range stop = len - 13.
        # Off-by-one trap (APOGEE_P2_SPEC.md §14.5):
        # `len(payload) - 14` (one too small) misses the case where the float sits
        # at the very end of the payload with no trailing data — symptom is digital
        # points without a units TLV silently failing to parse.
        for i in range(1, len(payload) - 13):
            if not (payload[i]   == 0x01 and payload[i+1] == 0x00
                    and payload[i+2] == 0x00):
                continue
            # Sentinel shapes: see APOGEE_P2_SPEC.md §14.3.
            # Real value blocks have one of these patterns at +3..+6:
            #   `3F FF FF XX` — R1 ("quality flags" register), where XX
            #                   varies on the wire. APOGEE_P2_SPEC.md
            #                   documents `3F FF FF FF` but the F7 variant
            #                   (and possibly others — the bit pattern of
            #                   byte +6 encodes quality flags) is also
            #                   real and very common in the field.
            #   `00 00 00 00` — R2/R3 (explicit "all flags clear" / modern
            #                   compact form).
            # The 09xx enumerate response's per-entry metadata block
            # (`04 00 02 00`, `03 00 02 00`, etc. — fixed second byte 0x00,
            # third byte 0x02) shapes false-match a permissive scan; the
            # `3F FF FF` prefix check or the all-zero check filters those
            # out cleanly.
            sentinel_3fff = (payload[i+3] == 0x3F
                             and payload[i+4] == 0xFF
                             and payload[i+5] == 0xFF)
            sentinel_zero = payload[i+3:i+7] == b'\x00\x00\x00\x00'
            if not (sentinel_3fff or sentinel_zero):
                continue
            if payload[i+7] != 0x00:
                continue
            prev = payload[i-1]
            # Previous byte must be printable ASCII (end of point name string)
            # Accepted chars: A-Z, a-z, 0-9, space, period, underscore, hyphen
            is_asciiend = (
                (0x41 <= prev <= 0x5A) or   # A-Z
                (0x61 <= prev <= 0x7A) or   # a-z
                (0x30 <= prev <= 0x39) or   # 0-9
                prev in (0x20, 0x2E, 0x5F, 0x2D)  # space . _ -
            )
            if not is_asciiend:
                continue
            # Sanity: float byte should look plausible
            first_byte = payload[i + 10]
            # Accept positive floats 0..~2e5, negative floats, zero, and
            # digital-point raw bytes (0x00-0x01 range).
            if first_byte <= 0x48 or first_byte in (0xBF, 0xC0, 0xC1, 0xC2,
                                                    0xC3, 0xC4, 0xC5):
                flags_idx = i + 3
                break

        if flags_idx < 0:
            # No value block found — probably an error response, a device-summary
            # bulk read, or a characterization read (different opcode). Safe to
            # return None; --debug-reads will surface the raw hex for inspection.
            return None

        # Extract device name and point name from length-prefixed strings before flags
        pre_flags = payload[:flags_idx]
        lp_strings = self._extract_lp_strings(pre_flags)

        routing_names = {self.network, self.scanner_name, P2_SITE,
                        P2_NETWORK} | {s.split('|')[0] for s in [self.scanner_name] if '|' in s}
        data_strs = [s for s in lp_strings
                     if s.upper() not in {n.upper() for n in routing_names}
                     and not s.upper().startswith('NODE')]
        if len(data_strs) >= 2:
            result['device_name'] = data_strs[0]
            result['point_name'] = data_strs[1]
            if len(data_strs) >= 3:
                result['description'] = data_strs[2]

        # Extract value after flags
        # [3F FF FF F7] [00 XX YY] [4-byte float]
        # XX = comm status: 00=online, 01=comm fault (offline)
        # YY = error code (06 = typical comm error)
        after_flags = payload[flags_idx + 3:]
        if len(after_flags) >= 8:
            # Check comm status flag (byte +2 after 3FFFFF)
            comm_status = after_flags[2] if len(after_flags) > 2 else 0
            result['comm_status'] = 'online' if comm_status == 0 else 'comm_fault'
            result['comm_error_code'] = after_flags[3] if len(after_flags) > 3 else 0

            # Surface the 4-byte property-state slot — adjacent to (not part of)
            # the float value. In decomp this appears to be a sentinel: 3FFFFFFF
            # means "no specific quality flags set"; 00000000 means "explicit
            # quality flags, all cleared." Unverified whether 00000000 implies
            # a cached/stale value vs a fresh poll. Surfacing so users can spot
            # patterns across devices.
            result['property_state_hex'] = payload[flags_idx:flags_idx + 4].hex()

            val_offset = 4  # skip flag tail byte + status bytes
            raw_val = after_flags[val_offset:val_offset + 4]
            if len(raw_val) == 4:
                result['value'] = struct.unpack('>f', raw_val)[0]
                result['value_raw_hex'] = raw_val.hex()

                # Determine data type from byte before value
                dtype_byte = after_flags[3] if len(after_flags) > 3 else 0
                if dtype_byte == 0x03:
                    result['data_type'] = 'analog'
                elif dtype_byte == 0x00:
                    result['data_type'] = 'binary' if result['value'] in (0.0, 1.0) else 'analog'

        # Extract units from after the value. Units arrive as length-prefixed
        # strings; some devices pad with a leading space (e.g. " CFM"), so we
        # strip before matching.
        after_val = payload[flags_idx + 3 + 8:]
        unit_whitelist = {
            'DEG F', 'DEG C', 'DEGF', 'DEGC',
            'PCT', '%', 'PERCENT',
            'SEC', 'MIN', 'HRS', 'HR', 'MS',
            'CFM', 'FPM', 'CF', 'FT3/MIN',
            'GPM', 'LPM', 'LPS',
            'PSI', 'KPA', 'INHG', 'IN WC', 'IN.WC', 'PA',
            'AMPS', 'VOLTS', 'V', 'A', 'MA', 'MV',
            'KW', 'KWH', 'BTU', 'BTUH', 'W', 'WH',
            'PPM', 'PPB',
            'RPM', 'HZ', 'KHZ',
            'FT', 'IN', 'M', 'MM', 'CM',
        }
        for s in self._extract_lp_strings(after_val):
            s_clean = s.strip().upper()
            if s_clean in unit_whitelist:
                result['units'] = s.strip()  # preserve original casing minus padding
                break

        return result

    @staticmethod
    def _extract_lp_strings(data: bytes) -> List[str]:
        """Extract length-prefixed strings (01 00 [len] [str] or 00 01 00 [len] [str])."""
        strings = []
        i = 0
        while i < len(data) - 3:
            # Pattern: 01 00 [len] [string]
            if data[i] == 0x01 and data[i+1] == 0x00 and 0 < data[i+2] < 100:
                slen = data[i+2]
                if i + 3 + slen <= len(data):
                    try:
                        s = data[i+3:i+3+slen].decode('ascii')
                        if s.isprintable():
                            strings.append(s)
                            i += 3 + slen
                            continue
                    except Exception:
                        pass
            # Pattern: 00 01 00 [len] [string]
            if (i < len(data) - 4 and data[i] == 0x00 and data[i+1] == 0x01
                    and data[i+2] == 0x00 and 0 < data[i+3] < 100):
                slen = data[i+3]
                if i + 4 + slen <= len(data):
                    try:
                        s = data[i+4:i+4+slen].decode('ascii')
                        if s.isprintable():
                            strings.append(s)
                            i += 4 + slen
                            continue
                    except Exception:
                        pass
            i += 1
        return strings

    # ── Additional opcodes identified from multi-panel packet captures ──

    def read_system_info_compact(self, node_name: str = "node") -> Optional[Dict[str, Any]]:
        """Read panel model/firmware/build via opcode 0x010C (2-byte request).

        Works on newer PXC firmware (PME1300 / V2.8.18-era). Falls back to the
        legacy 0x0100 GetRevString externally via `get_node_info()` if this returns
        None. Response carries three TLV strings followed by ~16 bytes of feature
        flags, an embedded IdentifyBlock, and panel state fields.

        Returns dict with 'model', 'firmware', 'build_date', 'node_number',
        'raw_strings' — or None on failure.
        """
        seq = self._next_seq()
        routing = self._build_routing(node_name)
        body = struct.pack('>H', P2Message.OP_SYSINFO_COMPACT)
        msg = P2Message(self.op_msg_type, seq, routing + body)
        if not self._send_message(msg):
            return None
        resp = self._recv_response(seq)
        if resp is None or not resp.payload or resp.payload[0] == P2Message.DIR_ERROR:
            return None
        strings = self._extract_lp_strings(resp.payload)
        # Drop anything that looks like a routing-header name
        routing_set = {self.network, self.scanner_name, P2_SITE,
                       node_name.upper(), node_name.lower()}
        data_strings = [s for s in strings if s not in routing_set]
        result = {
            'model': data_strings[0].strip() if len(data_strings) > 0 else '?',
            'firmware': data_strings[1] if len(data_strings) > 1 else '?',
            'build_date': data_strings[2] if len(data_strings) > 2 else '',
            'raw_strings': data_strings,
        }
        # Cache the firmware-build tag for the §30.4 dialect fast-path.
        # The "model" TLV (Siemens-internally labeled) actually holds the
        # build identifier like "PME1300 ". Subsequent connects to this
        # host will skip the §11.2 dialect probe via firmware_registry.
        build_tag = firmware_registry.parse_build_tag(result['model'])
        if build_tag:
            firmware_registry.cache_build_tag(self.host, build_tag)
            result['build_tag'] = build_tag
            if build_tag not in firmware_registry.KNOWN_BUILDS:
                # Spec §30.5 limitation 4 — log unknown builds with full
                # context so the registry can be extended.
                print(f"  [INFO] Unknown firmware build {build_tag} on "
                      f"{self.host} — full revstring: model={result['model']!r}, "
                      f"firmware={result['firmware']!r}, "
                      f"build_date={result['build_date']!r}. Heuristic "
                      f"classification: "
                      f"{firmware_registry.classify_unknown_build(build_tag)}.")
        # Byte at offset ~0x68 of the response payload encodes the node number.
        # Offset varies slightly by firmware; search for the NODE name TLV and
        # back up 3 bytes.
        # For now, caller can inspect raw_strings for reliability.
        return result

    def enumerate_all_points(self, node_name: str = "node",
                             max_points: int = 10000) -> List[Dict[str, Any]]:
        """Walk every point on the panel using opcode 0x0981 with cursor pagination.

        0x0981 is more complete than 0x0986 (EnumerateFLN): it returns panel-internal
        points (PPCL variables, scheduled points, global analogs) in addition to
        TEC-device points.

        Request body framing (empirically verified from packet captures):
            09 81                   opcode
            00 00                   2-byte header
            01 00 01 2a             TLV: first filter, always "*"
            01 00 01 2a             TLV: second filter, always "*"
            00 00                   separator
            01 00 LL <cursor>       TLV: cursor = previous response's device name,
                                          or empty (len=0) on the first call
            01 00 00                empty TLV trailer

        Cursor advancement strategy:
            Normally the panel returns the next point alphabetically after the
            cursor. When the cursor matches a point name that has a compound
            identity (device + subkey, e.g. "BCCW" + "DAY.NGT"), the panel
            sometimes returns the same record again because its internal index
            uses the compound key and our single-name cursor doesn't advance
            past it. Detection: if we get the same device name back, try
            incrementing the last byte of the cursor (e.g. "BCCW" → "BCCX"),
            which forces the panel to skip past the stuck entry and return
            whatever comes next alphabetically. Give up after several such
            retries to avoid infinite loops on genuinely-empty panels.
        """
        results = []
        cursor = b''   # empty on first call
        seen_devices = set()

        def send_and_parse(cur: bytes):
            """Send one enumerate request and return (parsed_dict or None)."""
            seq = self._next_seq()
            routing = self._build_routing(node_name)
            body = (struct.pack('>H', P2Message.OP_ENUM_POINTS) +
                    b'\x00\x00' +
                    b'\x01\x00\x01\x2a' +   # first filter = "*"
                    b'\x01\x00\x01\x2a' +   # second filter = "*"
                    b'\x00\x00' +
                    b'\x01' + struct.pack('>H', len(cur)) + cur +
                    b'\x01\x00\x00')
            msg = P2Message(self.op_msg_type, seq, routing + body)
            if not self._send_message(msg):
                return None
            resp = self._recv_response(seq)
            if resp is None:
                return None
            if resp.payload and resp.payload[0] == P2Message.DIR_ERROR:
                return None
            return self._parse_enum_points_response(resp.payload)

        def build_advance_cursors(cur: bytes):
            """Yield successively more aggressive cursor mutations to force
            advance past a stuck entry.

            Strategy order (minimal advance first to preserve adjacent points):
              1. Append 0x01 — `cur + \\x01` is the smallest string > cur.
                 Example: "DIVV1" → "DIVV1\\x01"
                 Returns the next entry after "DIVV1", which could be
                 "DIVV10.STPT", "DIVV1T", or any longer prefix match.
              2. Append ' ' (0x20) — space, first printable byte.
              3. Append '0' (0x30) — matches numeric-suffix points.
              4. Append 'A' (0x41) — matches alpha-suffix points.
              5. Append 'a' (0x61) — matches lowercase-suffix points.
              6. Append '~' (0x7E) — jumps past all printable-suffix entries
                 that start with cur.
              7. Byte-increment last character — "DIVV1" → "DIVV2".
                 This is a big jump that skips everything with prefix "DIVV1".
                 Only used as a last resort when all appends stall.
              8. Increment + append space — last-ditch attempt.

            Each mutation is strictly > cur in memcmp-with-length-tiebreak order.
            """
            if not cur:
                yield b'\x01'
                return
            # Append mutations from smallest to largest suffix
            for suffix in (b'\x01', b' ', b'0', b'A', b'a', b'~'):
                yield cur + suffix
            # Byte-increment the last character
            last = cur[-1]
            if last < 0x7E:
                yield cur[:-1] + bytes([last + 1])
                # And increment + space suffix
                yield cur[:-1] + bytes([last + 1]) + b' '
            else:
                yield cur + b'\x01' + b'\x01'

        for _ in range(max_points):
            parsed = send_and_parse(cursor)
            if parsed is None:
                break

            dev_name = parsed['device']

            if dev_name in seen_devices:
                # Cursor stalled — panel returned a record we've already seen.
                # This commonly happens on compound-identity points (e.g. BCCW
                # with subkey DAY.NGT) where our single-name cursor can't
                # advance past the compound record.
                #
                # Try a sequence of cursor mutations starting with the minimal
                # advance (append \x01, which gives the smallest string > cur)
                # so we don't accidentally skip over adjacent entries with the
                # same prefix. Fall back to byte-increment only as last resort.
                advanced = False
                for candidate in build_advance_cursors(cursor):
                    cursor = candidate
                    retry = send_and_parse(cursor)
                    if retry is None:
                        break
                    if retry['device'] not in seen_devices:
                        # Escaped the stall — accept this record
                        parsed = retry
                        dev_name = parsed['device']
                        advanced = True
                        break
                if not advanced:
                    # Either the panel genuinely has no more points or we
                    # couldn't find a cursor mutation that gets past the stuck
                    # entry. Either way, terminate.
                    break

            seen_devices.add(dev_name)
            results.append(parsed)

            # Advance cursor with the DEVICE name from this response
            cursor = dev_name.encode('ascii', errors='replace')

        return results

    @staticmethod
    def _parse_enum_points_response(payload: bytes) -> Optional[Dict[str, Any]]:
        """Extract {device, point, value, units} from a 0x0981 response payload.

        Three response shapes observed. The shape the panel picks depends on
        (a) firmware dialect (PME1252 vs PME1300) and (b) point type (physical
        sensor with a quality register vs PPCL-computed variable vs Title-only
        panel entry).

        SHAPE A — physical point with quality sentinel (real sensor value):
            [routing header]
            00 00
            01 00 LL <dev>              device name (often repeated 3x)
            01 00 LL <point>            point name
            01 00 LL <description>      description
            3F FF FF Fx 00 00 04        quality sentinel + marker
            <f32 value>
            01 00 LL <units>            units

        SHAPE B — PPCL-computed variable with value, no quality register
                  (e.g. a computed setpoint returning a float in engineering units):
            [routing header]
            00 00
            01 00 LL <name>             point name (repeated 3x)
            01 00 LL <description>      description
            00 00 00 00 00 00 02        7-byte zero-ish metadata (last byte = data-type code)
            <f32 value>
            00 00 00                    3-byte pad
            01 00 LL <units>            units

        SHAPE C — "Title"-only panel entry (label-only, no value, no units):
            [routing header]
            00 00
            01 00 LL <fullname>         full point name (repeated)
            01 00 LL <description>      human description
            <metadata — NO quality sentinel, NO float, NO units TLV>

        The disambiguator: scan forward from after the description TLV looking for
        a units TLV. If found, there's a value between description and units —
        extract it as f32 from the 4 bytes immediately before the units TLV header.
        The presence of a `3F FF FF F?` sentinel is a useful hint for SHAPE A but
        isn't required; SHAPE B points have real values with no sentinel.

        Returns {'device', 'point', 'value', 'units', 'description'}. For SHAPE C,
        device == point, value is None, units is empty, description carries the
        label.
        """
        # Skip routing header (4 null-terminated strings)
        i = 1
        nulls = 0
        while i < len(payload) and nulls < 4:
            if payload[i] == 0:
                nulls += 1
            i += 1
        if i >= len(payload):
            return None
        body = payload[i:]

        # Collect all TLVs (tag=0x01, u16 BE length, value)
        tlvs = []
        p = 0
        while p + 3 <= len(body):
            if body[p] == 0x01:
                L = struct.unpack('>H', body[p+1:p+3])[0]
                if 0 <= L < 256 and p + 3 + L <= len(body):
                    tlvs.append((p, L, body[p+3:p+3+L]))
                    p += 3 + L
                    continue
            p += 1

        # First non-empty printable ASCII TLV is the device/primary name
        dev = None
        dev_positions = []
        for pos, L, val in tlvs:
            if L == 0:
                continue
            try:
                s = val.decode('ascii')
            except UnicodeDecodeError:
                continue
            if not s.isprintable():
                continue
            if dev is None:
                dev = s
            if s == dev:
                dev_positions.append(pos)
        if dev is None:
            return None

        # Compound-name detection. Some panels return entries with TWO ASCII
        # name TLVs in a row at the top of the body (instead of one name + an
        # empty-TLV separator). Example:
        #     01 00 04 ZN01  01 00 07 DAY.SCH  02 00 02 00 00 ...
        # vs normal:
        #     01 00 07 RM TEMP  01 00 00  02 00 02 00 00 ...
        # The second name is a sub-key (some kind of subfield — schedule slot,
        # point group, etc.). It's NOT units and NOT description — treating it
        # as units (as earlier parser versions did) mangles display and can
        # misalign value extraction. Detect it and set it aside so the rest of
        # the parser ignores it.
        #
        # Detection: if the FIRST ASCII TLV after the first device occurrence
        # (still within the "header" region, before the metadata bytes) is a
        # non-empty ASCII TLV different from dev, we have a compound name.
        subkey = ''
        subkey_positions = set()
        if dev_positions:
            first_dev_end = dev_positions[0] + 3 + len(dev)
            # Look at the very next TLV
            for pos, L, val in tlvs:
                if pos < first_dev_end:
                    continue
                # The first TLV we see after the dev must be either empty
                # (normal case) or a non-empty ASCII TLV (compound case).
                if L == 0:
                    break  # normal — no subkey
                try:
                    s = val.decode('ascii')
                except UnicodeDecodeError:
                    break
                if not s.isprintable() or s == dev:
                    break
                # Found a compound subkey
                subkey = s
                # Find all positions where this subkey appears — we'll
                # exclude them from units/description candidates
                for p2, L2, val2 in tlvs:
                    if L2 == 0:
                        continue
                    try:
                        s2 = val2.decode('ascii')
                    except UnicodeDecodeError:
                        continue
                    if s2 == subkey:
                        subkey_positions.add(p2)
                break

        # Next ASCII TLV after the last device repetition is either:
        #   - a point name (SHAPE A with separate dev/point, rare)
        #   - a description (SHAPE B or C — dev == point, description is distinct)
        # We'll collect all ASCII TLVs past the last device repetition so we can
        # distinguish SHAPE A (where there's typically a point name BEFORE the
        # description, differing from dev) from SHAPE B/C.
        after_last_dev = (dev_positions[-1] + 3 + len(dev)) if dev_positions else 0
        subsequent = []
        for pos, L, val in tlvs:
            if pos <= after_last_dev or L == 0:
                continue
            if pos in subkey_positions:
                # Don't let a compound-name subkey be mistaken for units or desc
                continue
            try:
                s = val.decode('ascii')
            except UnicodeDecodeError:
                continue
            if s.isprintable() and s != subkey:
                subsequent.append((pos, L, s))

        if not subsequent:
            # No description or units found — return dev-only
            return {'device': dev, 'point': dev, 'value': None,
                    'units': '', 'description': '', 'subkey': subkey}

        # Quality sentinel hint for SHAPE A
        q_idx = -1
        for p in range(len(body) - 4):
            if body[p] == 0x3F and body[p+1] == 0xFF and body[p+2] == 0xFF:
                q_idx = p
                break

        # Find a units TLV. Real engineering units are narrow: short, no internal
        # multi-word spaces (except known patterns like "DEG F", "IN H20"). Multi-
        # word strings like "BLR 2 ALM" are descriptions, not units, even when short.
        #
        # Heuristic: a units string is <= 8 chars and either has no spaces OR
        # starts with "DEG " / "IN " (the only two space-containing unit patterns
        # we've seen). Also accept single-char units like "%".
        def looks_like_units(s: str) -> bool:
            s = s.strip()
            if not s: return False
            if len(s) > 8: return False
            # Single char / no-space units: "%", "MA", "PSI", "CFM", "PPM", etc.
            if ' ' not in s: return True
            # Space-containing patterns we accept as units
            if s.startswith('DEG ') or s.startswith('deg '): return True
            if s.startswith('IN '): return True
            return False

        units_candidates = []
        for (pos, L, s) in subsequent:
            if s == dev:
                continue
            if L <= 10 and L > 0 and looks_like_units(s):
                units_candidates.append((pos, L, s.strip()))

        # The units TLV, if present, is typically the LAST ASCII TLV in the body
        # (before trailing binary metadata). Pick the last candidate.
        units_pos = None
        units_str = ''
        if units_candidates:
            units_pos, units_L, units_str = units_candidates[-1]

        # Description: first ASCII TLV after the last device repetition that isn't units
        description = ''
        point_name = dev
        for (pos, L, s) in subsequent:
            if s == dev:
                continue
            if units_pos is not None and pos == units_pos:
                continue
            # In SHAPE A, there's sometimes a distinct point name before the description.
            # Detect this: if we see a non-dev ASCII TLV that's followed by another
            # ASCII TLV (the description) before the quality sentinel or units, then
            # this first one is the point name.
            description = s
            break

        # Try to extract a float value. Three sources in order of reliability:
        #   1. If quality sentinel present (SHAPE A), offset +7/+4/+8 past it.
        #      Physical points with a quality register use this.
        #   2. SHAPE B marker: `00 00 00 00 00 00 XX` (6 zeros + data-type byte)
        #      immediately after the description TLV, followed by an f32.
        #      Covers all PME1300 computed/binary points — with or without units.
        #   3. Fall back to offset-relative-to-units-TLV for edge cases.
        #   4. Otherwise no value.
        value = None

        if q_idx >= 0:
            # SHAPE A: value lives past the quality sentinel
            for offset in (7, 4, 8):
                if q_idx + offset + 4 <= len(body):
                    try:
                        candidate = struct.unpack('>f', body[q_idx+offset:q_idx+offset+4])[0]
                        if candidate == candidate and -1e10 < candidate < 1e10:
                            value = candidate
                            break
                    except struct.error:
                        continue

        if value is None:
            # SHAPE B marker scan — 6 zero bytes followed by a small data-type
            # code (observed: 01, 02, 03, 04, 05, 06), then the f32 in the next
            # 4 bytes.
            #
            # The SHAPE B layout is:
            #     [description TLV] [7-byte meta] [f32] [3-byte pad] [units TLV]
            # So the value sits BETWEEN the description TLV and the units TLV.
            # Scan in that window, not after the last ASCII TLV (which would
            # typically be units, already past the value).
            #
            # Start scan: immediately after the FIRST non-dev ASCII TLV
            # (which is the description). Stop scan: before the units TLV
            # if present, else to end of body.
            scan_start = 0
            scan_end = len(body) - 11
            if subsequent:
                first_pos, first_L, _ = subsequent[0]
                scan_start = first_pos + 3 + first_L
                if units_pos is not None and units_pos > scan_start:
                    scan_end = units_pos
            for p in range(scan_start, min(scan_end, len(body) - 11)):
                if (body[p] == 0 and body[p+1] == 0 and body[p+2] == 0 and
                    body[p+3] == 0 and body[p+4] == 0 and body[p+5] == 0 and
                    body[p+6] in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06)):
                    try:
                        candidate = struct.unpack('>f', body[p+7:p+11])[0]
                        if candidate == candidate and -1e10 < candidate < 1e10:
                            value = candidate
                            break
                    except struct.error:
                        continue

        if value is None and units_pos is not None and units_pos >= 4:
            # SHAPE B extraction: f32 sits before the units TLV header.
            # Layout: [7-byte meta][f32][3-byte pad][01 00 LL units]
            # So the float is at units_pos - 3 - 4 = units_pos - 7.
            # SHAPE A may also have a units TLV but the bytes before are
            # structural (00 00 04 [f32]); that float is 4 before units_pos
            # in the A layout. Try -7 first (B), then -4 (A), then -8.
            for back in (7, 4, 8):
                if units_pos - back >= 0:
                    try:
                        candidate = struct.unpack('>f', body[units_pos-back:units_pos-back+4])[0]
                        if candidate == candidate and -1e10 < candidate < 1e10:
                            # Sanity check: reject tiny non-zero "noise" values that
                            # come from misaligned reads of zero bytes. Values in the
                            # range of sub-picovolt (|x| < 1e-6) with nonzero bits are
                            # almost certainly misaligned interpretations.
                            if abs(candidate) < 1e-6 and candidate != 0.0:
                                continue
                            value = candidate
                            break
                    except struct.error:
                        continue

        if value is None and q_idx >= 0:
            # SHAPE A fallback: value lives past the quality sentinel
            for offset in (7, 4, 8):
                if q_idx + offset + 4 <= len(body):
                    try:
                        candidate = struct.unpack('>f', body[q_idx+offset:q_idx+offset+4])[0]
                        if candidate == candidate and -1e10 < candidate < 1e10:
                            value = candidate
                            break
                    except struct.error:
                        continue

        # Final classification:
        # - If we found a value OR a units TLV OR a sentinel → valued point (A or B)
        # - Otherwise → SHAPE C (Title-only, device==point, description only)
        if value is not None or units_pos is not None or q_idx >= 0:
            return {'device': dev, 'point': point_name or dev,
                    'value': value, 'units': units_str,
                    'description': description if description != dev else '',
                    'subkey': subkey}
        else:
            # SHAPE C — title-only, no value
            return {'device': dev, 'point': dev, 'value': None,
                    'units': '', 'description': description.strip(),
                    'subkey': subkey}

    def read_programs(self, node_name: str = "node",
                      max_requests: int = 5000) -> List[Dict[str, Any]]:
        """Enumerate PPCL programs via opcode 0x0985 — response carries source text.

        The cursor protocol for 0x0985 is two-level:
          1. Program name cursor (advances when a program is exhausted)
          2. Line number cursor (advances within a program, 10 lines per chunk)

        Request body format (different from 0x0981 — only ONE filter TLV):
            09 85                   opcode
            00 00                   2-byte header
            01 00 01 2a             filter TLV = "*" (single, not double)
            00 00                   separator
            01 00 LL <program>      program name (empty string on first call)
            NN NN                   u16 BE line number to fetch (0 on first call)

        Response body format:
            00 00                   separator
            01 00 LL <program>      program name (PXC's current position)
            01 00 06 <module_tag>   6-char module type (e.g. "ET    " "D     " "DT    ")
            01 00 LL <source_chunk> PPCL source code chunk (one or more lines)
            NN NN                   u16 BE next-line hint (where to resume)
            HH                      has-more flag: 0x01=more of this program, 0x00=done
            01 00 00 00             4-byte trailer

        Termination: when we ask for a line past the end of the LAST program,
        the PXC returns a 2-byte error body `00 03` (DIR_ERROR + code 0x0003).

        Returns list of {'name': ..., 'module': ..., 'code': ...} with full source
        text per program.
        """
        # Accumulate chunks per program name
        by_program: Dict[str, Dict[str, Any]] = {}
        prog_order: List[str] = []

        current_name = b''   # empty on first call — PXC treats as "start"
        current_line = 0
        requests_made = 0
        seen_states = set()

        while requests_made < max_requests:
            requests_made += 1
            seq = self._next_seq()
            routing = self._build_routing(node_name)
            body = (struct.pack('>H', P2Message.OP_ENUM_PROGRAMS) +
                    b'\x00\x00' +
                    b'\x01\x00\x01\x2a' +                         # single filter "*"
                    b'\x00\x00' +
                    b'\x01' + struct.pack('>H', len(current_name)) + current_name +
                    struct.pack('>H', current_line))              # u16 BE line number
            msg = P2Message(self.op_msg_type, seq, routing + body)
            if not self._send_message(msg):
                break
            resp = self._recv_response(seq)
            if resp is None:
                break
            if resp.payload and resp.payload[0] == P2Message.DIR_ERROR:
                # PXC says no more programs — normal end-of-list termination.
                break

            parsed = self._parse_program_response(resp.payload)
            if parsed is None:
                break

            prog = parsed['program']
            module = parsed['module']
            code_chunk = parsed['code']
            next_line = parsed['next_line']

            # Accumulate the code chunk into the program record
            if prog not in by_program:
                by_program[prog] = {'name': prog, 'module': module, 'code': ''}
                prog_order.append(prog)
            if code_chunk:
                existing = by_program[prog]['code']
                by_program[prog]['code'] = (existing + '\n' + code_chunk) if existing else code_chunk

            # Always advance using what the PXC returned. The has_more flag's exact
            # semantic was unreliable in captures (it can be 0 mid-program too), so
            # we rely on the PXC returning 0x0003 to signal end-of-list.
            next_name = prog.encode('ascii')

            # Loop guard: if we've been at this exact (name, line) before, bail.
            # Protects against a PXC that parks on a line without advancing.
            state_key = (next_name, next_line)
            if state_key in seen_states:
                break
            seen_states.add(state_key)

            current_name = next_name
            current_line = next_line

        return [by_program[name] for name in prog_order]

    @staticmethod
    def _parse_program_response(payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse a 0x0985 response payload.

        Returns {program, module, code, next_line, has_more} or None.
        """
        # Skip routing header
        i = 1
        nulls = 0
        while i < len(payload) and nulls < 4:
            if payload[i] == 0:
                nulls += 1
            i += 1
        if i >= len(payload):
            return None
        body = payload[i:]

        # Expect: 00 00, then 3 TLVs, then next_line(u16) + has_more(u8) + trailer
        if len(body) < 2 or body[0:2] != b'\x00\x00':
            return None

        # Walk TLVs starting at offset 2
        tlvs = []
        p = 2
        while p + 3 <= len(body):
            if body[p] == 0x01:
                L = struct.unpack('>H', body[p+1:p+3])[0]
                if 0 <= L < 8192 and p + 3 + L <= len(body):
                    tlvs.append((p, L, body[p+3:p+3+L]))
                    p += 3 + L
                    continue
            break  # TLV section ended

        if len(tlvs) < 3:
            return None

        try:
            program = tlvs[0][2].decode('ascii').rstrip()
            module = tlvs[1][2].decode('ascii').rstrip()
            code = tlvs[2][2].decode('ascii', errors='replace').rstrip()
        except UnicodeDecodeError:
            return None

        # Next 3 bytes after the 3 TLVs: next_line (u16 BE) + has_more (u8)
        tail_start = p
        if tail_start + 3 > len(body):
            return None
        next_line = struct.unpack('>H', body[tail_start:tail_start+2])[0]
        has_more = body[tail_start+2] == 0x01

        return {
            'program': program,
            'module': module,
            'code': code,
            'next_line': next_line,
            'has_more': has_more,
        }

    def browse_device(self, device: str, node_name: str = "node") -> Optional[Dict[str, Any]]:
        """
        Send a device browse request to enumerate device info.

        Args:
            device: TEC device name (e.g., "DEVICE1")
            node_name: P2 node name in lowercase

        Returns:
            Dict with device info, or None on failure.
        """
        seq = self._next_seq()
        routing = self._build_routing(node_name)

        dev_bytes = device.encode('ascii')

        browse_payload = (
            routing +
            b'\x42\x00' +
            b'\x01\x00\x04SYST' +
            b'\x23\x3f\xff\xff\xff' +
            b'\x00\x00' +
            b'\x01' + struct.pack('>H', len(dev_bytes)) + dev_bytes +
            b'\x00\x00\x01\x00\x00\xff\xff'
        )

        msg = P2Message(self.op_msg_type, seq, browse_payload)
        if not self._send_message(msg):
            return None

        resp = self._recv_response(seq)
        if resp is None:
            return None

        # Parse browse response for device description and metadata
        strings = self._extract_lp_strings(resp.payload)
        routing_names = {SCANNER_NAME, P2_NETWORK, P2_SITE} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
        data_strs = [s for s in strings
                     if s.upper() not in {n.upper() for n in routing_names}
                     and not s.upper().startswith('NODE')]

        result = {'device': device, 'strings': data_strs}
        if len(data_strs) >= 2:
            result['description'] = data_strs[1]
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_node_name(host: str) -> str:
    """Look up or auto-learn the P2 node name for a given IP address."""
    # Check known nodes first
    for name, ip in KNOWN_NODES.items():
        if ip == host:
            return name.lower()
    # Auto-probe the host to learn its name
    result = probe_p2_host(host)
    if result and 'node_name' in result:
        # Cache it for future use
        KNOWN_NODES[result['node_name']] = host
        return result['node_name'].lower()
    return "node"  # generic fallback


def scan_device(host: str, device: str, points: Optional[List[str]] = None,
                quick: bool = False, output_format: str = "table",
                force_slot: bool = False,
                inter_read_delay_s: float = 0.05) -> List[Dict]:
    """
    Scan all (or selected) points on a TEC device.

    Args:
        host: PXC controller IP address
        device: TEC device name
        points: Optional list of specific point names OR slot numbers (as
                strings like "29" or "DAY.NGT"). Numeric strings trigger
                slot → name resolution via the app's point table.
        quick: If True, only read key operational points
        output_format: "table", "json", or "csv"
        force_slot: When a numeric slot isn't defined in the app's point
                    table, normally the scanner refuses with a clear error.
                    Setting force_slot=True attempts the read anyway using
                    a synthesized name (useful for protocol troubleshooting).
        inter_read_delay_s: Seconds to wait between consecutive point reads
                    on the same device. Default 0.05. Sites with slow or
                    busy controllers can raise this (CLI: --read-delay).

    Returns:
        List of point result dicts
    """
    # Pre-flight validation: check slot-range inputs BEFORE we touch the network.
    # Doesn't catch "slot not defined in app" since we don't know the app yet,
    # but range violations are purely syntactic and can be rejected up front.
    if points:
        for p in points:
            p_str = str(p).strip()
            if p_str.isdigit():
                slot = int(p_str)
                if not (1 <= slot <= 99):
                    raise ScannerInputError(
                        f"Slot {slot} out of range — TEC subpoints are 1-99")

    node_name = resolve_node_name(host)
    # P2Connection needs the current (possibly auto-learned) network name
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)

    # When output_format="none", we're running as a step inside a larger
    # sweep (e.g. building-wide room-temp read). Suppress per-device banners
    # and progress chatter so the sweep can render a single combined table.
    suppress_output = (output_format == "none")

    if not suppress_output:
        print(f"\n{'═' * 70}")
        print(f"  P2 SCANNER — {device} on {node_name.upper()} ({host})")
        if P2_NETWORK:
            print(f"  Network: {P2_NETWORK}  |  Site: {P2_SITE or '?'}")
        print(f"{'═' * 70}")

    if not conn.connect(node_name):
        return []

    # Determine which points to scan. When using the point table, we also
    # remember the app_num so we can attach rich metadata (type, labels,
    # scaling, etc.) to each read result — this drives pretty-printing and
    # gives downstream callers the context they need.
    scan_app_num = None
    if points or quick:
        # Explicit point list or quick mode — still read APPLICATION so we
        # can (a) render labels on the output, and (b) resolve numeric slots
        # against the app's point table.
        try:
            app_result = conn.read_point(device, "APPLICATION", node_name)
            if app_result and app_result.get('value') is not None:
                scan_app_num = int(app_result['value'])
        except Exception:
            pass  # app lookup is a nice-to-have, don't fail the scan over it

        if quick:
            scan_list = list(QUICK_SCAN_POINTS)
        else:
            # User gave explicit points. Each entry can be either a name
            # ('ROOM TEMP') or a slot number ('29'). Resolve numbers here
            # BEFORE hitting the wire so we can error cleanly on undefined
            # slots rather than sending garbage to the PXC.
            scan_list = []
            for p in points:
                p_stripped = str(p).strip()
                if p_stripped.isdigit():
                    slot = int(p_stripped)
                    if not (1 <= slot <= 99):
                        conn.close()
                        raise ScannerInputError(
                            f"Slot {slot} out of range — TEC subpoints are 1-99")
                    if scan_app_num is None:
                        conn.close()
                        raise ScannerInputError(
                            f"Can't resolve slot {slot} — failed to read "
                            f"APPLICATION from {device}. Try a named point first, "
                            f"or pass force_slot=True to attempt the read anyway.")
                    resolved = resolve_slot_to_name(scan_app_num, slot)
                    if resolved:
                        print(f"  Slot {slot} on app {scan_app_num} = {resolved!r}")
                        scan_list.append(resolved)
                    elif force_slot:
                        # Forced read of undefined slot. The PXC probably
                        # won't return anything useful, but this is a
                        # protocol-troubleshooting escape hatch.
                        synth = f"POINT_{slot}"
                        print(f"  [WARN] Slot {slot} not defined in app {scan_app_num} — "
                              f"forcing read as {synth!r} (likely to fail)")
                        scan_list.append(synth)
                    else:
                        conn.close()
                        raise ScannerInputError(
                            f"Slot {slot} is not defined in app {scan_app_num}. "
                            f"Use --force-slot (CLI) or force_slot=True (library) "
                            f"to try anyway.")
                else:
                    scan_list.append(p_stripped)
    else:
        # First, read APPLICATION to get the right point table
        print(f"  Reading APPLICATION number...")
        app_result = conn.read_point(device, "APPLICATION", node_name)
        app_num = None
        if app_result and app_result.get('value') is not None:
            app_num = int(app_result['value'])
            comm = app_result.get('comm_status', 'online')
            if comm == 'comm_fault':
                print(f"  ⚠ Device has #COM — values will be stale cached data")
            print(f"  Application: {app_num}")
        scan_app_num = app_num

        pt_table = get_point_table(app_num) if app_num else {}

        if pt_table:
            # Use the point table for this application
            scan_list = [info[0] for addr, info in sorted(pt_table.items())]
            print(f"  Scanning {len(scan_list)} points for app {app_num}")
        else:
            # No point table at all — try ALL known point names as last resort
            all_names = set()
            for app in range(2020, 2028):
                for addr, info in get_point_table(app).items():
                    all_names.add(info[0])
            scan_list = sorted(all_names)
            print(f"  No point table for app {app_num} — trying {len(scan_list)} common names")

    # F-4: warn (don't block) when the device's application is a BACnet/MSTP
    # transport — those are TEC devices that talk BACnet to the panel, not P2
    # FLN bus protocol. Reads via P2 wire opcodes will return 0x0003 not_found
    # or similar errors. The catalog flags this via `_meta.transport`. We
    # surface the warning but still attempt the scan (the scanner is read-only;
    # the failed reads are diagnostic rather than destructive).
    if scan_app_num is not None and app_supports_p2(scan_app_num) is False:
        meta = get_app_meta(scan_app_num) or {}
        print(f"  ⚠ App {scan_app_num} ({meta.get('descr', 'unknown')}) is a "
              f"BACnet/MSTP transport — P2 reads will likely fail. This device "
              f"should be reached via BACnet/IP if the panel acts as a router.")

    results = []
    total = len(scan_list)
    success = 0
    failed = 0

    for i, pt_name in enumerate(scan_list):
        if not suppress_output:
            sys.stdout.write(f"\r  Scanning: {i+1}/{total} — {pt_name:<25s}")
            sys.stdout.flush()

        result = conn.read_point(device, pt_name, node_name)
        if result and result['value'] is not None:
            result['point_name'] = pt_name
            # Attach rich metadata if we have the app number. This lets the
            # output formatters show "NIGHT" instead of "1.0" for digital
            # points, correct units even when the wire response lacks them,
            # etc.
            if scan_app_num is not None:
                info = get_point_info(scan_app_num, pt_name)
                if info:
                    result['point_info'] = info
                    # Fill in units if parser didn't get them from the wire
                    if not result.get('units') and info.get('units'):
                        result['units'] = info['units']
                    # Compute a rendered value_text for digital points
                    if 'on_label' in info and 'off_label' in info:
                        val = result['value']
                        result['value_text'] = info['on_label'] if val >= 0.5 else info['off_label']
                    result['point_type'] = info.get('type', 'unknown')
                # Panel-level points are not in the TEC library. Fall back
                # to the compiled-in tables: a point type implies a default
                # enumeration (the enum whose id is the negation of the type
                # code), so a digital point renders as OFF/ON rather than
                # 0.0/1.0 even with no application number to look up.
                if not result.get('value_text'):
                    txt = p2_data.resolve_state_text(
                        result.get('value'),
                        point_type=result.get('point_type_code'),
                        enum_id=result.get('enum_id'))
                    if txt:
                        result['value_text'] = txt
                if not result.get('point_type'):
                    mn = p2_data.point_type_name(result.get('point_type_code'))
                    if mn:
                        result['point_type'] = mn
                # Attach the subpoint slot number for Desigo-style '(29)'
                # display. Handled even when point_info is missing, in case
                # someone's scanning with only the legacy JSON.
                slot = get_point_slot(scan_app_num, pt_name)
                if slot is not None:
                    result['point_slot'] = slot
            results.append(result)
            success += 1
        else:
            failed += 1

        # Small delay to avoid overwhelming the controller
        if inter_read_delay_s > 0:
            time.sleep(inter_read_delay_s)

    conn.close()
    if not suppress_output:
        print(f"\r  Scan complete: {success} points read, {failed} failed{'':30s}")

        # Output results
        if output_format == "table":
            print_results_table(device, results)
        elif output_format == "json":
            print(json.dumps(results, indent=2))
        elif output_format == "csv":
            print_results_csv(results)

    return results


def scan_network(quick: bool = False) -> Dict[str, List[Dict]]:
    """Scan all known PXC nodes on the P2 network."""
    print(f"\n{'═' * 70}")
    print(f"  P2 NETWORK SCAN — {P2_NETWORK}")
    print(f"  {len(KNOWN_NODES)} known nodes")
    print(f"{'═' * 70}")

    all_results = {}
    for name, ip in sorted(KNOWN_NODES.items()):
        node_name = name.lower()
        conn = P2Connection(ip)

        print(f"\n  Probing {name} ({ip})...", end=" ")
        if conn.connect(node_name):
            print("CONNECTED")
            # Try reading a common point to verify the node is responsive
            result = conn.read_point("OATEMP", "OATEMP", node_name)
            if result:
                print(f"    OATEMP = {result['value']}")
            conn.close()
            all_results[name] = [result] if result else []
        else:
            print("FAILED")
            all_results[name] = []

    return all_results


# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE SNIFFER (PCAP ANALYSIS)
# ═══════════════════════════════════════════════════════════════════════════════

def sniff_pcap(pcap_file: str, output_format: str = "table") -> List[Dict]:
    """
    Parse a pcap/pcapng file and decode all P2 point data from both 5033 and 5034.
    Surfaces:
      - Point reads and COV notifications (0x0274) — as list of events
      - BLN routing-table topology (0x4634) — printed as summary
      - Unique panel list derived from routing headers
    Requires tshark to be installed.
    """
    import subprocess

    print(f"\n{'═' * 70}")
    print(f"  P2 PCAP DECODER — {pcap_file}")
    print(f"{'═' * 70}")

    # Use tcp.payload, not data.data. The `data.data` field is only populated
    # when Wireshark fails to classify TCP data with any protocol — and on
    # systems where the p2.lua dissector is loaded (or any other handler
    # claims TCP/5033) it stays empty. tcp.payload is the raw bytes after
    # the TCP header, always populated, regardless of dissector chain.
    result = subprocess.run([
        'tshark', '-r', pcap_file,
        '-Y', '(tcp.port==5033 || tcp.port==5034) && tcp.payload',
        '-T', 'fields',
        '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'tcp.srcport', '-e', 'tcp.dstport',
        '-e', 'tcp.payload'
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  [ERROR] tshark failed: {result.stderr}")
        return []

    ip_node = {}
    all_points = []
    # Cross-panel topology observations — populated from 0x4634 routing tables
    routing_tables = []  # [{'src_panel': ..., 'peers': [{'name': ..., 'cost': ...}]}]
    cov_sources: 'Counter[str]' = Counter()

    def _inc(d, k):
        d[k] += 1

    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) < 6:
            continue

        fnum, src, dst = int(parts[0]), parts[1], parts[2]
        try:
            sport, dport = int(parts[3]), int(parts[4])
        except ValueError:
            continue
        port_on_wire = 5033 if (dport == 5033 or sport == 5033) else 5034
        try:
            raw = bytes.fromhex(parts[5])
        except Exception:
            continue

        # Parse potentially multiple P2 messages in one TCP segment
        pos = 0
        while pos < len(raw) - 12:
            remaining = len(raw) - pos
            if remaining < 12:
                break
            total_len = struct.unpack('>I', raw[pos:pos+4])[0]
            # Malformed frame (length under 12 = invalid; over remaining =
            # truncated/forged). Stop parsing this segment rather than
            # consuming whatever's left as one giant fake frame — that would
            # corrupt subsequent iteration state and could panic the parser.
            if total_len < 12 or total_len > remaining:
                break
            msg = raw[pos:pos+total_len]
            pos += total_len

            if len(msg) <= 12:
                continue

            resp_flag = msg[12]

            # Map node names from routing headers
            lp = P2Connection._extract_lp_strings(msg[12:])
            routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
            for s in lp:
                if s.upper().startswith('NODE') and s.upper() not in routing_set:
                    remote_ip = dst if src != dst else src
                    ip_node[remote_ip] = s.upper()

            # ── 0x4634 routing-table push: extract BLN topology
            rt_idx = msg.find(b'\x46\x34')
            if rt_idx >= 14 and rt_idx < len(msg) - 20:
                # Only process if it looks like a real routing-table body (not inside a float)
                # Heuristic: preceded by end-of-routing-header null terminator within a few bytes
                if b'\x00' in msg[max(12, rt_idx-2):rt_idx]:
                    body = msg[rt_idx:]
                    parsed = parse_routing_table(body)
                    if parsed and parsed.get('entries'):
                        src_panel = '?'
                        # The source panel for a PXC->DCC routing push is in routing slot 4
                        rh = _parse_routing_header(msg[12:])
                        if rh:
                            _, names, _ = rh
                            src_panel = names[3] if len(names) >= 4 else '?'
                        routing_tables.append({
                            'src_panel': src_panel,
                            'port': port_on_wire,
                            'frame': fnum,
                            'entries': parsed['entries'],
                        })

            # ── 0x0274 COV / value-push
            marker_idx = msg.find(b'\x02\x74')
            if marker_idx >= 0:
                after = msg[marker_idx + 2:]
                if len(after) >= 7 and after[0:6] == b'\x00\x01\x00\x00\x01\x00':
                    name_len = after[6]
                    if name_len > 0 and len(after) >= 7 + name_len + 7:
                        try:
                            pt_name = after[7:7+name_len].decode('ascii')
                        except Exception:
                            pt_name = None
                        if pt_name and pt_name.isprintable():
                            val_area = after[7+name_len:]
                            value = None
                            # Two value-block shapes: (a) immediate TLV marker with f32,
                            # (b) second TLV string (device first) then f32 — PXC->DCC form.
                            if len(val_area) >= 7 and val_area[0:3] == b'\x01\x00\x00':
                                try:
                                    value = struct.unpack('>f', val_area[3:7])[0]
                                except struct.error:
                                    pass
                            elif len(val_area) >= 3 and val_area[0] == 0x01:
                                # Skip the second TLV string, then read f32
                                L2 = struct.unpack('>H', val_area[1:3])[0]
                                if 3 + L2 + 4 <= len(val_area):
                                    try:
                                        value = struct.unpack('>f', val_area[3+L2:3+L2+4])[0]
                                    except struct.error:
                                        pass

                            remote_ip = dst if src != dst else src
                            node = ip_node.get(remote_ip, remote_ip)
                            # A 0x0274 ValuePush is a panel->supervisor COV or a
                            # supervisor->panel virtual write; the protocol does NOT
                            # tie that distinction to a port number. In a passive
                            # capture we infer it from the listener port in play:
                            # only the supervisor runs a second (push) listener, so a
                            # frame on a non-canonical port is a panel->supervisor
                            # COV, while 5033 frames default to a virtual write. This
                            # is a heuristic, not a protocol rule — the opcode is
                            # identical on any port.
                            direction = 'pxc_to_dcc' if port_on_wire != 5033 else 'dcc_to_pxc'
                            all_points.append({
                                'frame': fnum,
                                'node': node,
                                'point_name': pt_name,
                                'value': value,
                                'type': 'COV_PUSH' if direction == 'pxc_to_dcc' else 'VIRTUAL_WRITE',
                                'direction': direction,
                            })
                            _inc(cov_sources, node)

            # ── Read responses (flag=1, has 3FFFFFxx value-block signature)
            if resp_flag == 1:
                flags_idx = -1
                for i in range(12, len(msg) - 3):
                    if msg[i] == 0x3F and msg[i+1] == 0xFF and msg[i+2] == 0xFF:
                        flags_idx = i
                        break
                if flags_idx >= 0:
                    pre = msg[12:flags_idx]
                    data_strs = [s for s in P2Connection._extract_lp_strings(pre)
                                 if s not in routing_set and not s.upper().startswith('NODE')]
                    after_flags = msg[flags_idx + 3:]
                    if len(after_flags) >= 8 and len(data_strs) >= 2:
                        raw_val = after_flags[4:8]
                        try:
                            value = struct.unpack('>f', raw_val)[0]
                        except struct.error:
                            value = None
                        # Extract units
                        units = ''
                        for s in P2Connection._extract_lp_strings(after_flags[8:]):
                            if s in ('DEG F', 'PCT', 'SEC', 'CFM', 'PSI'):
                                units = s
                                break

                        remote_ip = dst if src != dst else src
                        node = ip_node.get(remote_ip, remote_ip)
                        all_points.append({
                            'frame': fnum,
                            'node': node,
                            'device_name': data_strs[0],
                            'point_name': data_strs[1],
                            'value': value,
                            'units': units,
                            'description': data_strs[2] if len(data_strs) >= 3 else '',
                            'type': 'READ',
                        })

    print(f"  Decoded {len(all_points)} point values")

    # ── Topology summary from observed 0x4634 messages
    if routing_tables:
        # Merge all observed routing tables into a single unique peer list
        all_peers = {}
        for rt in routing_tables:
            for entry in rt['entries']:
                n = entry['name']
                if n and n not in all_peers:
                    all_peers[n] = entry['cost']
        print(f"\n  ── BLN topology (from {len(routing_tables)} routing-table pushes) ──")
        print(f"  {'Peer':<24} {'Cost':>8}")
        for name, cost in sorted(all_peers.items()):
            print(f"  {name:<24} {cost:>8}")

    if cov_sources:
        # Sort — works for Counter.most_common() or plain dict fallback
        try:
            top = cov_sources.most_common(10)
        except AttributeError:
            top = sorted(cov_sources.items(), key=lambda kv: -kv[1])[:10]
        if top:
            print(f"\n  ── COV / value pushes by source node ──")
            for node, n in top:
                print(f"  {node:<24} {n:>6} events")

    if output_format == "table" and all_points:
        # Group by node and device
        from itertools import groupby
        keyfunc = lambda p: (p.get('node', '?'), p.get('device_name', p.get('point_name', '?')))
        sorted_pts = sorted(all_points, key=keyfunc)
        for key, group in groupby(sorted_pts, key=keyfunc):
            pts = list(group)
            print(f"\n  {key[0]} / {key[1]}:")
            seen = set()
            for p in pts:
                pt_key = p['point_name']
                if pt_key in seen:
                    continue
                seen.add(pt_key)
                val = p['value']
                units = p.get('units', '')
                if val is not None:
                    print(f"    {pt_key:<30s} = {val:>10.2f} {units}")

    return all_points


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

def print_results_table(device: str, results: List[Dict]):
    """Print point results in a formatted table."""
    if not results:
        print("  No results.")
        return

    # Check if device is genuinely offline vs just a few unconnected inputs
    comm_fault_count = sum(1 for r in results if r.get('comm_status') == 'comm_fault')
    total_with_status = sum(1 for r in results if r.get('comm_status'))

    if total_with_status > 0 and comm_fault_count == total_with_status:
        print(f"\n  ⚠ WARNING: Device {device} has #COM (communication fault)")
        print(f"  Values shown are STALE cached data — device is offline!")
    elif comm_fault_count > total_with_status * 0.5:
        print(f"\n  ⚠ WARNING: {comm_fault_count}/{total_with_status} points show #COM")
        print(f"  Device may be offline — some values could be stale")
    elif comm_fault_count > 0:
        print(f"\n  Note: {comm_fault_count} point(s) show #COM (unconnected inputs)")

    # Column widths: Point column holds "(##) POINT_NAME_WITH_SPACES". With
    # slot numbers up to 99 that's "(##) " = 5 chars of prefix + up to 25
    # chars of name = 30. Digital labels ("NIGHT"/"COOL"/"OFF") fit in the
    # Value column without truncation while numeric values stay clean.
    print(f"\n  {'Point':<31s} {'Value':>14s} {'Units':<8s} {'Type':<12s}")
    print(f"  {'─' * 31} {'─' * 14} {'─' * 8} {'─' * 12}")

    for r in results:
        val = r.get('value')
        units = r.get('units', '')
        name = r.get('point_name', '?')
        slot = r.get('point_slot')
        comm = r.get('comm_status', '')
        info = r.get('point_info')

        # Desigo-style '(29) DAY.NGT' prefix when slot is known
        if slot is not None:
            name_display = f"({slot}) {name}"
        else:
            name_display = name

        # Type column: prefer rich 'point_type' over raw 'data_type'
        type_display = r.get('point_type') or r.get('data_type', '') or ''
        type_short = {
            'analog_ro':  'AI',
            'analog_rw':  'AO',
            'digital_ro': 'BI',
            'digital_rw': 'BO',
        }.get(type_display, type_display)

        if val is not None:
            if r.get('value_text'):
                label = r['value_text']
                raw_int = int(round(val))
                val_str = f"{label} ({raw_int})"
            else:
                if val == int(val) and abs(val) < 100000:
                    val_str = f"{int(val)}"
                else:
                    val_str = f"{val:.2f}"
            if comm == 'comm_fault':
                val_str += " #COM"
        else:
            val_str = "—"

        print(f"  {name_display:<31s} {val_str:>14s} {units:<8s} {type_short:<12s}")


def print_results_csv(results: List[Dict]):
    """Print results in CSV format."""
    writer = csv.writer(sys.stdout)
    writer.writerow(['point_slot', 'point_name', 'value', 'value_text', 'units',
                     'point_type', 'data_type', 'comm_status', 'description'])
    for r in results:
        writer.writerow([
            r.get('point_slot', ''),
            r.get('point_name', ''),
            r.get('value', ''),
            r.get('value_text', ''),
            r.get('units', ''),
            r.get('point_type', ''),
            r.get('data_type', ''),
            r.get('comm_status', ''),
            r.get('description', ''),
        ])


def _print_sweep_results(sweep_results: List[Dict], read_points: List,
                         output_format: str = "table"):
    """Render building-wide sweep output — results are flat, one row per
    (node, device, point). Prints a single combined table/CSV/JSON.
    Each result dict has '_node' and '_device' set from discover_network."""
    if not sweep_results:
        print("  No devices responded.")
        return

    if output_format == "json":
        # JSON: pass through as-is for programmatic use
        print(json.dumps(sweep_results, indent=2, default=str))
        return

    if output_format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(['node', 'device', 'description', 'point_slot',
                         'point_name', 'value', 'value_text', 'units',
                         'point_type', 'comm_status', 'error'])
        for r in sweep_results:
            writer.writerow([
                r.get('_node', r.get('node', '')),
                r.get('_device', r.get('device', '')),
                r.get('_description', r.get('description', '')),
                r.get('point_slot', ''),
                r.get('point_name', ''),
                r.get('value', ''),
                r.get('value_text', ''),
                r.get('units', ''),
                r.get('point_type', ''),
                r.get('comm_status', ''),
                r.get('error', ''),
            ])
        return

    # Table: grouped by node, then device
    print(f"\n  {'Node':<8s} {'Device':<12s} {'Point':<22s} {'Value':>14s} {'Units':<8s}")
    print(f"  {'─' * 8} {'─' * 12} {'─' * 22} {'─' * 14} {'─' * 8}")

    prev_node = None
    for r in sweep_results:
        node = r.get('_node', r.get('node', '?'))
        dev = r.get('_device', r.get('device', '?'))

        # Insert blank line between nodes for readability
        if prev_node and node != prev_node:
            print()
        prev_node = node

        if 'error' in r:
            print(f"  {node:<8s} {dev:<12s} {'(' + r['error'] + ')':<22s} "
                  f"{'—':>14s} {'':<8s}")
            continue

        name = r.get('point_name', '?')
        slot = r.get('point_slot')
        if slot is not None:
            name_display = f"({slot}) {name}"
        else:
            name_display = name

        # Clip for width
        if len(name_display) > 22:
            name_display = name_display[:21] + "…"

        val = r.get('value')
        units = r.get('units', '') or ''

        if val is None:
            val_str = "—"
        elif r.get('value_text'):
            val_str = f"{r['value_text']} ({int(round(val))})"
        elif val == int(val) and abs(val) < 100000:
            val_str = f"{int(val)}"
        else:
            val_str = f"{val:.2f}"

        if r.get('comm_status') == 'comm_fault':
            val_str += " #COM"

        print(f"  {node:<8s} {dev:<12s} {name_display:<22s} {val_str:>14s} {units:<8s}")


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

# Common TEC device name patterns to try during brute-force discovery.
# This is a generic starter set covering naming conventions seen broadly
# across commercial BAS installations. It is deliberately conservative;
# many sites use site-specific prefixes (e.g. perimeter-VAV series, suite
# numbering, tenant-prefixed devices) that the integrator established at
# commissioning time. Edit this list to add your site's naming conventions
# for faster discovery — the more accurate the seed list, the faster cold
# discovery converges.
DISCOVERY_DEVICE_PATTERNS = [
    # AC/AH series (AHUs) — common Siemens factory naming
    *[f"AC{n:02d}" for n in range(1, 20)],
    *[f"AH{n:02d}" for n in range(1, 20)],
    *[f"AH{n:02d}T1" for n in range(1, 20)],
    *[f"AC{n:02d}T1" for n in range(1, 20)],
    # BLR series — generic boiler patterns
    *[f"BLR{n}" for n in range(1, 6)],
    "BLRST", "BLRSTPT",                    # boiler status / setpoint (generic)
    # Add site-specific abbreviations here as you encounter them. Common
    # patterns to watch for: interior-VAV prefixes, perimeter-zone series,
    # custom boiler-plant abbreviations (valve outputs, OA-enable flags),
    # tenant-prefixed devices.
    # Exhaust / supply fans
    *[f"EF{n}" for n in range(1, 25)],
    *[f"SF{n}" for n in range(1, 10)],
    *[f"EF{n:02d}" for n in range(1, 25)],
    # Common generic points
    "OATEMP", "OAT",
    # Floor-based naming patterns
    *[f"FLR{n}VAV{v}" for n in range(1, 16) for v in range(1, 6)],
    # Common VAV naming: V followed by numbers
    *[f"V{n}" for n in range(1, 51)],
    *[f"VAV{n}" for n in range(1, 51)],
    *[f"VAV-{n}" for n in range(1, 21)],
    # Zone controllers
    *[f"ZN{n}" for n in range(1, 31)],
    *[f"ZONE{n}" for n in range(1, 21)],
    # Room-based naming (generic step-100 series)
    *[f"RM{n}" for n in range(100, 500, 100)],
    # Suite-based
    *[f"STE{n}" for n in range(100, 500, 100)],
    *[f"SUITE{n}" for n in range(1, 21)],
    # Heat pump / FCU
    *[f"HP{n}" for n in range(1, 21)],
    *[f"FCU{n}" for n in range(1, 21)],
    *[f"FCU-{n}" for n in range(1, 21)],
    # CW/HW/CHW
    *[f"CWP{n}" for n in range(1, 6)],
    *[f"HWP{n}" for n in range(1, 6)],
    *[f"CHWP{n}" for n in range(1, 6)],
    # Misc
    *[f"UH{n}" for n in range(1, 11)],  # Unit heaters
    *[f"RTU{n}" for n in range(1, 11)],  # Rooftop units
    *[f"MAU{n}" for n in range(1, 6)],   # Makeup air
    *[f"CT{n}" for n in range(1, 6)],    # Cooling towers
    *[f"CH{n}" for n in range(1, 6)],    # Chillers
    *[f"P{n}" for n in range(1, 11)],    # Pumps
]

# Panel-level point names (not TECs, but readable from nodes).
# Conservative starter set covering Siemens factory defaults and broadly-
# common BAS conventions. Many panels expose site-specific custom points
# (zone-prefixed, tenant-prefixed, integrator-specific PPCL globals, lighting
# schedules) that vary per deployment. Missing point names are harmless —
# the scanner just gets no data for them. Edit this list to add the custom
# panel points used at your site for richer panel-level discovery results.
PANEL_POINT_NAMES = [
    # Outside air / weather (common Siemens-default naming)
    "OATEMP", "OAT", "OUTSIDE_AIR_TEMP",
    # Boiler common patterns (BLR{n} alarm/enable/status)
    "BLRST", "BLRSTPT",
    *[f"BLR{n}ALM" for n in range(1, 5)],
    *[f"BLR{n}ENB" for n in range(1, 5)],
    *[f"BLR{n}ST"  for n in range(1, 5)],
    # Chiller common patterns
    *[f"CH{n}ALM"  for n in range(1, 5)],
    *[f"CH{n}ENB"  for n in range(1, 5)],
    *[f"CH{n}ST"   for n in range(1, 5)],
    # Exhaust fan enables / statuses
    *[f"EF{n}_ENABLE" for n in range(1, 21)],
    *[f"EF{n}_STATUS" for n in range(1, 21)],
    *[f"EF{n}.ENABLE" for n in range(1, 21)],
    # Add site-specific panel-internal points here. Common shapes to watch
    # for: legacy/replacement weather-feed mirrors, site-aggregated enthalpy,
    # system-mode globals (heat-lockout / cool-release style), chilled-water
    # differential-pressure points, tenant-prefixed lighting schedules.
    # The .BN suffix indicates BLN-virtual (mirrored from another panel).
]


def parse_ip_range(range_str: str) -> List[str]:
    """
    Parse flexible IP range formats into a list of IPs.

    Supported formats:
        192.0.2.50              Single IP
        192.0.2.1-254            Last octet range
        192.0.2.0/24             CIDR notation
        192.0.2                 Shorthand for .1-.254
        192.0.2.0/24,198.51.100.0/24   Comma-separated multiple ranges
    """
    ips = []
    for part in range_str.split(','):
        part = part.strip()

        if '/' in part:
            # CIDR notation
            base, prefix_len = part.split('/')
            prefix_len = int(prefix_len)
            octets = [int(o) for o in base.split('.')]
            if prefix_len == 24:
                for i in range(1, 255):
                    ips.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{i}")
            elif prefix_len == 16:
                for s3 in range(0, 256):
                    for s4 in range(1, 255):
                        ips.append(f"{octets[0]}.{octets[1]}.{s3}.{s4}")
            else:
                # Just do /24 from the base
                for i in range(1, 255):
                    ips.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{i}")

        elif '-' in part.split('.')[-1]:
            # Range in last octet: 192.0.2.1-254
            base = '.'.join(part.split('.')[:-1])
            range_part = part.split('.')[-1]
            start, end = range_part.split('-')
            for i in range(int(start), int(end) + 1):
                ips.append(f"{base}.{i}")

        elif part.count('.') == 2:
            # Shorthand subnet: 192.0.2 → 192.0.2.1-254
            for i in range(1, 255):
                ips.append(f"{part}.{i}")

        elif part.count('.') == 3:
            # Single IP
            ips.append(part)

    return ips


def port_scan_p2(ip_list: List[str], timeout: float = 0.5) -> List[str]:
    """Scan a list of IPs for TCP/5033 open."""
    found = []
    total = len(ip_list)

    for i, ip in enumerate(ip_list):
        sys.stdout.write(f"\r  Scanning {ip} ({i+1}/{total})...   ")
        sys.stdout.flush()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, P2_PORT))
            s.close()
            if result == 0:
                found.append(ip)
                sys.stdout.write(f"\r  {ip} — P2 OPEN                    \n")
                sys.stdout.flush()
        except Exception:
            pass

    sys.stdout.write(f"\r  Scan complete: {len(found)} P2 hosts found{'':30s}\n")
    return found


def learn_network_name(hosts: List[str]) -> Optional[str]:
    """
    Try to auto-learn the P2 network name.
    Strategy 1: If P2_NETWORK is already set, return it.
    Strategy 2: Try a live tshark capture to sniff P2 traffic.
    Strategy 3: PXCs won't respond without the name, so prompt user.
    """
    if P2_NETWORK:
        return P2_NETWORK

    # Try live capture with tshark
    name = sniff_network_name(duration=10)
    if name:
        return name

    return None


def sniff_network_name(duration: int = 10, interface: str = None) -> Optional[str]:
    """
    Use tshark to do a live capture and extract the P2 network name
    from any P2 traffic on the wire. Requires Wireshark/tshark installed.

    Args:
        duration: Seconds to capture (default 10)
        interface: Network interface to capture on (auto-detected if None)

    Returns:
        P2 network name string, or None if not found
    """
    global P2_NETWORK, P2_SITE
    import subprocess
    import shutil
    import tempfile
    import os

    # Find tshark
    tshark = shutil.which('tshark')
    if not tshark:
        # Check common Windows install paths
        for path in [
            r'C:\Program Files\Wireshark\tshark.exe',
            r'C:\Program Files (x86)\Wireshark\tshark.exe',
        ]:
            if os.path.exists(path):
                tshark = path
                break

    if not tshark:
        return None

    print(f"    Found tshark: {tshark}")
    print(f"    Capturing P2 traffic for {duration} seconds...")

    # Create temp file for capture. NamedTemporaryFile(delete=False) creates
    # the file atomically with secure permissions and returns its name, avoiding
    # the TOCTOU race in the deprecated tempfile.mktemp(). The file is closed
    # on context exit so tshark can reopen it; cleanup happens in the finally
    # block below.
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcapng') as _tf:
        tmpfile = _tf.name

    try:
        # Build tshark command
        cmd = [tshark, '-a', f'duration:{duration}',
               '-f', 'tcp port 5033', '-w', tmpfile, '-q']
        if interface:
            cmd.extend(['-i', interface])

        result = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=duration + 10)

        if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) < 100:
            print(f"    No P2 traffic captured")
            return None

        # Parse the capture for network name
        print(f"    Captured {os.path.getsize(tmpfile)} bytes, parsing...")
        try:
            sniff_pcap(tmpfile, "table")
        except Exception:
            pass

        if P2_NETWORK:
            print(f"    Learned network name: {P2_NETWORK}")
            return P2_NETWORK

        # Manual parse if sniff_pcap didn't set it
        try:
            with open(tmpfile, 'rb') as f:
                raw = f.read()
            # Look for P2 routing strings (null-terminated after msg type 0x33)
            for i in range(len(raw) - 20):
                if raw[i:i+4] == b'\x00\x00\x003':  # msg type 0x33
                    # Skip header, look for null-terminated strings
                    buf = b""
                    for j in range(i + 12, min(i + 100, len(raw))):
                        if raw[j] == 0 and buf:
                            try:
                                s = buf.decode('ascii')
                                if s.isprintable() and len(s) >= 3 and '|' not in s:
                                    P2_NETWORK = s
                                    print(f"    Learned network name: {P2_NETWORK}")
                                    return P2_NETWORK
                            except Exception:
                                pass
                            buf = b""
                        elif 32 <= raw[j] < 127:
                            buf += bytes([raw[j]])
                        else:
                            buf = b""
        except Exception:
            pass

        return None

    except subprocess.TimeoutExpired:
        print(f"    Capture timed out")
        return None
    except FileNotFoundError:
        print(f"    tshark not found or cannot execute")
        return None
    except PermissionError:
        print(f"    Permission denied — try running as Administrator")
        return None
    finally:
        try:
            os.unlink(tmpfile)
        except Exception:
            pass


def probe_p2_host(host: str) -> Optional[Dict[str, str]]:
    """
    Connect to a P2 host, blast heartbeats with many node names on a single
    connection, and learn its identity from whichever one it responds to.
    Returns dict with 'node_name', 'network', 'site' — or None on failure.
    Auto-learns and sets P2_NETWORK and P2_SITE globals on first success.
    """
    global P2_NETWORK, P2_SITE

    # Common PXC node naming patterns to try
    probe_names = (
        [f"node{i}" for i in range(1, 21)] +
        [f"NODE{i}" for i in range(1, 21)] +
        [f"PXC{i}" for i in range(1, 11)] +
        [f"MEC{i}" for i in range(1, 11)] +
        [f"MBC{i}" for i in range(1, 6)] +
        [f"AHU{i}" for i in range(1, 11)] +
        [f"BLR{i}" for i in range(1, 6)] +
        [f"FLR{i}" for i in range(1, 16)] +
        ["PANEL1", "PANEL2", "PANEL3", "MAIN", "LOBBY", "PENT",
         "PENTHOUSE", "BOILER", "CHILLER", "COOLING"]
    )

    net = P2_NETWORK.encode('ascii') if P2_NETWORK else b'P2NET'
    scanner = effective_scanner_name().encode('ascii')
    site = P2_SITE.encode('ascii') if P2_SITE else b'SITE'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))

        # Blast all heartbeats on this one connection
        for seq, target_name in enumerate(probe_names, start=100):
            target = target_name.encode('ascii')
            routing = b'\x00' + net + b'\x00' + target + b'\x00' + net + b'\x00' + scanner + b'\x00'
            # Trailer per APOGEE_P2_SPEC.md §9 — see _handshake()
            # in P2Connection for the byte layout.
            identity = (
                b'\x46\x40' +
                b'\x01' + struct.pack('>H', len(scanner)) + scanner +
                b'\x01' + struct.pack('>H', len(site)) + site +
                b'\x01' + struct.pack('>H', len(net)) + net +
                b'\x00\x01\x01\x00' +                  # separator + 3 flag bytes
                b'\x00\x00\x00\x00\x00' +              # 5 reserved zeros
                struct.pack('>I', int(time.time())) + # 4-byte timestamp
                b'\x00\x00' +                          # 2-byte session id
                b'\x00'                                # trailing null
            )
            payload = routing + identity
            msg = struct.pack('>III', 12 + len(payload), 0x33, seq) + payload
            try:
                s.sendall(msg)
            except (BrokenPipeError, ConnectionResetError, OSError):
                break
            time.sleep(0.01)  # 10ms between sends

        # Now read any response — the PXC responds only to the matching name
        s.settimeout(3)
        data = b""
        try:
            while len(data) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                s.settimeout(0.5)  # short timeout for additional data
        except socket.timeout:
            pass

        s.close()

        if not data or len(data) < 20:
            return None

        # Parse the response
        resp_payload = data[12:]
        if not resp_payload or resp_payload[0] != 0x01:
            return None

        # Extract routing strings
        null_strings = []
        buf = b""
        for b in resp_payload[1:]:
            if b == 0:
                if buf:
                    try:
                        null_strings.append(buf.decode('ascii'))
                    except Exception:
                        null_strings.append("")
                    buf = b""
                    if len(null_strings) >= 4:
                        break
            else:
                buf += bytes([b])

        result = {}

        # Learn network name
        if len(null_strings) >= 1:
            learned_net = null_strings[0]
            if learned_net and learned_net != SCANNER_NAME:
                result['network'] = learned_net
                if not P2_NETWORK:
                    P2_NETWORK = learned_net

        # Learn node name (4th routing string)
        if len(null_strings) >= 4:
            node_name = null_strings[3]
            our_names = {SCANNER_NAME} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
            if node_name and node_name not in our_names:
                result['node_name'] = node_name.upper()

        # Fallback: figure out which name matched from the sequence number
        if 'node_name' not in result and len(data) >= 12:
            resp_seq = struct.unpack('>I', data[8:12])[0]
            idx = resp_seq - 100
            if 0 <= idx < len(probe_names):
                result['node_name'] = probe_names[idx].upper()

        # Learn site from length-prefixed identity block
        lp_strings = []
        i = 0
        while i < len(resp_payload) - 3:
            if resp_payload[i] == 0x01 and resp_payload[i+1] == 0x00 and 0 < resp_payload[i+2] < 30:
                slen = resp_payload[i+2]
                if i + 3 + slen <= len(resp_payload):
                    try:
                        st = resp_payload[i+3:i+3+slen].decode('ascii')
                        if st.isprintable():
                            lp_strings.append(st)
                    except Exception:
                        pass
                    i += 3 + slen
                    continue
            i += 1

        known = {result.get('network', ''), result.get('node_name', ''),
                 SCANNER_NAME, P2_NETWORK}
        for st in lp_strings:
            if st not in known and 2 <= len(st) <= 10:
                result['site'] = st
                if not P2_SITE:
                    P2_SITE = st
                break

        return result if 'node_name' in result else None

    except (socket.error, socket.timeout, OSError):
        return None


def discover_node_name(host: str) -> Optional[str]:
    """Connect to a PXC and learn its P2 node name. Wrapper for probe_p2_host."""
    result = probe_p2_host(host)
    return result['node_name'] if result else None


# Per-host dialect cache. Keyed by host IP string. Values are 0x33 or 0x34.
# Saves a ~2-second probe on every subsequent connection to the same PXC within
# a single process lifetime — notable for building-wide sweeps that hit each
# panel multiple times (discover, then verify, then read_all).
_DIALECT_CACHE: Dict[str, int] = {}


def _recv_one_frame(sock: socket.socket, max_payload: int = 65536,
                    overall_timeout: float = 3.0) -> Optional[bytes]:
    """Read exactly one P2 frame from sock and return total bytes.

    Replaces the older "recv-until-timeout" pattern in raw-socket call
    sites like get_node_info and enumerate_fln_devices. The frame layout
    (APOGEE_P2_SPEC.md §4.4) puts a u32 BE total_length at offset 0, so we
    can buffer to the exact length and avoid both truncation (slow links)
    and over-reading (multiple frames piggybacked from the panel).

    Returns the complete frame bytes (header+payload) on success, or None
    on EOF, timeout before the frame is complete, or a malformed length
    prefix.
    """
    sock.settimeout(overall_timeout)
    buf = bytearray()
    # Step 1: read the 4-byte length prefix.
    while len(buf) < 4:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    total_len = struct.unpack('>I', bytes(buf[:4]))[0]
    # Sanity-check: spec §4.4 minimum frame is 12 bytes (header only); maximum
    # is bounded by max_payload + 12. A length outside this window is a
    # framing failure — bail rather than try to recover.
    if total_len < 12 or total_len > max_payload + 12:
        return None
    # Step 2: top up to total_len.
    while len(buf) < total_len:
        try:
            chunk = sock.recv(min(4096, total_len - len(buf)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf[:total_len])


def _probe_dialect(sock: socket.socket, handshake_msg_0x33: bytes,
                   handshake_msg_0x34: bytes,
                   host: Optional[str] = None) -> Optional[int]:
    """Send a handshake probe and detect which message-type dialect the PXC speaks.

    PXC firmware splits into two dialects:
      - Legacy (PME1252 and earlier): operational traffic uses msg_type 0x33 DATA.
        Handshake is 0x33-in, 0x33-out.
      - Modern (firmware build PME1300 on PXME hardware): operational traffic uses msg_type 0x34 HEARTBEAT.
        Handshake is 0x34-in, 0x34-out.

    A PXC silently drops handshakes sent with the wrong msg_type. The detection
    strategy: try 0x33 first with a short timeout; if nothing comes back, retry
    as 0x34. Returns the confirmed msg_type (0x33 or 0x34) on success, or None on
    total failure.

    Both handshake payloads should be pre-built by the caller with identical
    routing + identity bodies but different msg_type bytes in the 12-byte header.

    If `host` is provided, the detected dialect is cached for subsequent calls
    against the same host. The cache is process-local — site.json doesn't
    persist it, so a fresh process pays the probe cost once per panel.
    """
    # Check cache first. If we've seen this host before, skip the probe.
    if host is not None and host in _DIALECT_CACHE:
        cached = _DIALECT_CACHE[host]
        msg = handshake_msg_0x33 if cached == 0x33 else handshake_msg_0x34
        try:
            sock.sendall(msg)
            sock.settimeout(3.0)
            data = sock.recv(4096)
            if data:
                return cached
            # Cache hit produced no response — panel may have flipped dialect
            # (firmware upgrade?) or the cache entry is stale. Fall through to
            # full probe to rediscover.
            del _DIALECT_CACHE[host]
        except socket.error:
            # Socket died mid-cache-check. Caller has to deal with this.
            return None

    try:
        sock.sendall(handshake_msg_0x33)
        sock.settimeout(HANDSHAKE_PROBE_TIMEOUT)
        data = sock.recv(4096)
        if data:
            # Legacy dialect confirmed — use 0x33 for the rest of the session
            if host is not None:
                _DIALECT_CACHE[host] = 0x33
            return 0x33
    except socket.timeout:
        pass
    except socket.error:
        return None

    # No response on 0x33. Try 0x34.
    try:
        sock.sendall(handshake_msg_0x34)
        sock.settimeout(3.0)
        data = sock.recv(4096)
        if data:
            if host is not None:
                _DIALECT_CACHE[host] = 0x34
            return 0x34
    except (socket.timeout, socket.error):
        return None

    return None


def get_node_info(host: str, node_name: str) -> Optional[Dict]:
    """
    Query firmware version and panel info from a PXC node using opcode 0x0100.
    Returns dict with revision strings, or None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except Exception:
        return None

    net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
    scanner = effective_scanner_name().encode('ascii')
    site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
    node_lower = node_name.lower().encode('ascii')

    # Build the handshake payload once. We'll wrap it with two different msg_type
    # bytes and try each in turn via _probe_dialect().
    routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    identity = (
        b'\x46\x40' +
        b'\x01' + struct.pack('>H', len(scanner)) + scanner +
        b'\x01' + struct.pack('>H', len(site)) + site +
        b'\x01' + struct.pack('>H', len(net)) + net +
        # Trailer: separator + 3 flags + 5 reserved + 4-byte timestamp +
        # 2-byte session id (00 00 = panel-style) + trailing null = 16 bytes.
        # See APOGEE_P2_SPEC.md §9 for the documented format.
        b'\x00\x01\x01\x00\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\x00\x00'
    )
    # Random 24-bit seq matches real Desigo behavior — see APOGEE_P2_SPEC.md
    # "Sequence number field". Both dialect probes share the seq so they
    # look like alternative attempts of one handshake.
    _hs_seq = secrets.randbits(24)
    hs_0x33 = struct.pack('>III', 12 + len(routing) + len(identity), 0x33, _hs_seq) + routing + identity
    hs_0x34 = struct.pack('>III', 12 + len(routing) + len(identity), 0x34, _hs_seq) + routing + identity

    dialect = _probe_dialect(s, hs_0x33, hs_0x34, host=host)
    if dialect is None:
        s.close()
        return None

    # Send opcode 0x0100 (GetRevString) — try with empty data
    info_routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    info_data = struct.pack('>H', 0x0100)
    # Random 24-bit seq avoids the seq=0/1/10 "scanner fingerprint" that
    # stricter future firmware may reject; matches the P2Connection
    # convention (see APOGEE_P2_SPEC.md §5.2 / §8.4).
    _info_seq = secrets.randbits(24)
    msg = struct.pack('>III', 12 + len(info_routing) + len(info_data), dialect, _info_seq) + info_routing + info_data

    try:
        s.sendall(msg)
        # Buffer to the frame's exact total_length per APOGEE_P2_SPEC.md §4.4
        # instead of the older "read until timeout" pattern. The old pattern
        # truncated on slow links (fragmented frames could time out mid-read)
        # and over-read when the panel piggybacked a push frame onto the
        # response.
        data = _recv_one_frame(s, overall_timeout=3.0)
        s.close()

        if not data or len(data) <= 55 or data[12] == 0x05:
            return None

        # Extract strings from response
        payload = data[12:]
        pos = 1
        nulls = 0
        while pos < len(payload) and nulls < 4:
            if payload[pos] == 0: nulls += 1
            pos += 1

        data_area = payload[pos:]
        strings = []
        i = 0
        while i < len(data_area) - 2:
            slen = struct.unpack('>H', data_area[i:i+2])[0]
            if 0 < slen < 60 and i + 2 + slen <= len(data_area):
                try:
                    st = data_area[i+2:i+2+slen].decode('ascii')
                    if st.isprintable():
                        strings.append(st)
                        i += 2 + slen
                        continue
                except Exception: pass
            i += 1

        routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE, node_name.upper(), node_name.lower()}
        info_strings = [st for st in strings if st not in routing_set]

        return {
            'firmware': info_strings[0] if len(info_strings) > 0 else '?',
            'model': info_strings[1] if len(info_strings) > 1 else '?',
            'extra': info_strings[2] if len(info_strings) > 2 else '',
            'raw_strings': info_strings,
        }
    except Exception:
        s.close()
        return None


def get_device_application(host: str, node_name: str, device_name: str) -> Optional[int]:
    """Read the APPLICATION number from a specific device."""
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        return None
    result = conn.read_point(device_name, "APPLICATION", node_name.lower())
    conn.close()
    if result and result.get('value') is not None:
        return int(result['value'])
    return None


def enumerate_fln_devices(host: str, node_name: str) -> List[Dict]:
    """
    Enumerate all FLN devices on a PXC node using opcode 0x0986.
    No brute force — asks the PXC to list every device on its FLN bus.
    
    Returns list of dicts with 'device', 'description', 'application'.
    """
    found = []
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except (socket.error, socket.timeout) as e:
        print(f"    [ERROR] Connection failed: {e}")
        return []

    try:

        net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
        scanner = effective_scanner_name().encode('ascii')
        site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
        node_lower = node_name.lower().encode('ascii')

        # Build both dialect variants of the handshake and probe to see which the
        # PXC wants. See _probe_dialect() for why this exists.
        routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
        identity = (
            b'\x46\x40' +
            b'\x01' + struct.pack('>H', len(scanner)) + scanner +
            b'\x01' + struct.pack('>H', len(site)) + site +
            b'\x01' + struct.pack('>H', len(net)) + net +
            # Trailer: separator + 3 flags + 5 reserved + 4-byte timestamp +
            # 2-byte session id (00 00 = panel-style) + trailing null = 16 bytes.
            # See APOGEE_P2_SPEC.md §9 for the documented format.
            b'\x00\x01\x01\x00\x00\x00\x00\x00\x00' +
            struct.pack('>I', int(time.time())) + b'\x00\x00\x00'
        )
        # Random 24-bit seq matches real Desigo behavior — see APOGEE_P2_SPEC.md
        # "Sequence number field". Both dialect probes share the seq so they
        # look like alternative attempts of one handshake.
        _hs_seq = secrets.randbits(24)
        hs_0x33 = struct.pack('>III', 12 + len(routing) + len(identity), 0x33, _hs_seq) + routing + identity
        hs_0x34 = struct.pack('>III', 12 + len(routing) + len(identity), 0x34, _hs_seq) + routing + identity

        dialect = _probe_dialect(s, hs_0x33, hs_0x34, host=host)
        if dialect is None:
            s.close()
            print(f"    [ERROR] Handshake failed")
            return []

        cursor = "*"
        # Random 24-bit seq base avoids the scanner-fingerprint pattern
        # (low constant values) — APOGEE_P2_SPEC.md §5.2 / §8.4. We still
        # increment monotonically; only the starting point is randomized.
        seq = secrets.randbits(24)

        for iteration in range(200):
            seq += 1
            cb = cursor.encode('ascii')
            enum_data = (struct.pack('>H', 0x0986) +
                         b'\x00\x00\x00' + struct.pack('>H', 1) + b'*' +
                         b'\x00\x00\x00' + struct.pack('>H', len(cb)) + cb)
            enum_routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
            msg = struct.pack('>III', 12 + len(enum_routing) + len(enum_data), dialect, seq) + enum_routing + enum_data
        
            try:
                s.sendall(msg)
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

            # Buffer to exact frame length per APOGEE_P2_SPEC.md §4.4. The
            # previous "recv until short timeout" pattern truncated on slow
            # links (large enumerate responses can fragment across TCP
            # segments) and over-read when the panel piggybacked a push
            # frame onto the response.
            data = _recv_one_frame(s, overall_timeout=3.0)
            if not data or len(data) <= 55:
                break
            if data[12] == 0x05:
                break
        
            # Parse: skip P2 header + routing, extract length-prefixed strings
            payload = data[12:]
            pos = 1
            nulls = 0
            while pos < len(payload) and nulls < 4:
                if payload[pos] == 0: nulls += 1
                pos += 1
        
            if pos >= len(payload): break
            data_area = payload[pos:]
        
            # Extract all length-prefixed strings from data area
            strings = []
            i = 0
            while i < len(data_area) - 2:
                slen = struct.unpack('>H', data_area[i:i+2])[0]
                if 0 < slen < 60 and i + 2 + slen <= len(data_area):
                    try:
                        st = data_area[i+2:i+2+slen].decode('ascii')
                        if st.isprintable():
                            strings.append(st)
                            i += 2 + slen
                            continue
                    except Exception: pass
                i += 1
        
            routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE, node_name.upper(), node_name.lower()}
            device_strings = [st for st in strings if st not in routing_set]
        
            if not device_strings:
                break
        
            dev_name = device_strings[0]
            # Description is the last unique string that differs from device name
            # Response contains: [device_name, device_name, internal_name, display_name]
            # We want the display name (last one)
            desc = ''
            for st in device_strings[1:]:
                if st != dev_name:
                    desc = st  # keep overwriting — last one wins
        
            if dev_name == cursor:
                break  # End of list
        
            found.append({
                'device': dev_name,
                'description': desc,
                'application': 0,
            })
            sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  {desc}\n")
            sys.stdout.flush()
        
            cursor = dev_name
    
    finally:
        s.close()
    sys.stdout.write(f"\r    Enumerate complete: {len(found)} devices found{'':20s}\n")
    return found


def _app_has_room_temp(application: int) -> Optional[bool]:
    """
    Check whether a given TEC application defines a ROOM TEMP point. Returns
    True/False from the app's point table, or None when the application is
    unknown (app=0 or not in tecpoints.json). Callers should treat None as
    "try ROOM TEMP anyway" to preserve the legacy behavior.
    """
    if not application:
        return None
    try:
        tbl = get_point_table(application)
    except Exception:
        return None
    if not tbl:
        return None
    for _addr, (name, _desc, _units, _ro) in tbl.items():
        if isinstance(name, str) and name.upper() == 'ROOM TEMP':
            return True
    return False


def verify_devices(host: str, node_name: str, devices: List[Dict],
                   show_filter: str = "all") -> List[Dict]:
    """
    Verify which enumerated devices are actually online.

    Strategy: prefer ROOM TEMP for the liveness probe — its comm_status flag
    is the authoritative live-FLN signal. For apps that don't define ROOM TEMP
    (chillers, boilers, fan coils with different point naming), we skip the
    wasted ROOM TEMP read and fall straight through to the APPLICATION-based
    fallback path.

    Args:
        host: PXC controller IP
        node_name: P2 node name
        devices: List of device dicts from enumerate
        show_filter: "all", "online", or "offline"

    Returns:
        Updated device list with 'status' field added ('online'/'offline')
    """
    if not devices:
        return devices

    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        print(f"    [ERROR] Could not connect for verification")
        return devices

    total = len(devices)
    online = 0
    offline = 0

    for i, dev in enumerate(devices):
        dev_name = dev['device']
        sys.stdout.write(f"\r    Verifying: {i+1}/{total} — {dev_name:<20s}")
        sys.stdout.flush()

        # Read ROOM TEMP first. ROOM TEMP is live FLN data, so the
        # comm_status flag in the response is the authoritative signal
        # for whether the device is online right now:
        #   comm_status=='online'      → live FLN read succeeded → ONLINE
        #   comm_status=='comm_fault'  → PXC handed back a stale-cached
        #                                value because the device is
        #                                FLN-faulted. This matches
        #                                Desigo's own "#COM" indicator
        #                                on the same point. → OFFLINE
        #   None (no ROOM TEMP point)  → device doesn't have a ROOM TEMP
        #                                point at all (some non-VAV apps).
        #                                Fall through to APPLICATION as a
        #                                last-resort registration probe.
        #
        # NOTE: an earlier version of this routine fell back to
        # APPLICATION whenever ROOM TEMP came back stale. APPLICATION is
        # panel-cached metadata (configured app number), not live FLN
        # data — it returns successfully even for #COM-faulted devices,
        # so falling back to it converts true offlines into false
        # onlines. Cross-checked against Desigo CC's own status display
        # (which shows ROOM TEMP=#COM and APPLICATION=2090 for the same
        # device): the live signal is comm_status, not APPLICATION
        # responsiveness.
        #
        # Per-app optimization: when the app catalog explicitly says this
        # device's application doesn't define ROOM TEMP (chillers/boilers
        # /non-VAV), skip the wasted probe and go straight to the
        # APPLICATION fallback. _app_has_room_temp returns None for
        # unknown apps, in which case we preserve the legacy "try ROOM
        # TEMP anyway" behavior.
        has_rt = _app_has_room_temp(dev.get('application', 0))
        if has_rt is False:
            result = None
        else:
            result = conn.read_point(dev_name, "ROOM TEMP", node_name.lower())

        dev['status'] = 'offline'

        # Surface comm_status on the dev dict regardless of classification.
        room_temp_comm = result.get('comm_status') if result else None
        if room_temp_comm:
            dev['comm_status'] = room_temp_comm

        if result and result.get('comm_status') == 'online':
            # Live ROOM TEMP read.
            dev['status'] = 'online'
            dev['room_temp'] = result.get('value')
            dev['units'] = result.get('units', '')
            if dev.get('application', 0) == 0:
                app_result = conn.read_point(dev_name, "APPLICATION", node_name.lower())
                if app_result and app_result.get('value') is not None:
                    dev['application'] = int(app_result['value'])
            online += 1
            continue

        if result and result.get('comm_status') == 'comm_fault':
            # PXC explicitly reports the device as FLN-faulted. Record
            # the stale value (useful for diagnostics — "last seen at...")
            # but DO NOT mark online. APPLICATION would lie here.
            dev['stale_temp'] = result.get('value')
            # Best-effort: if the panel still has APPLICATION cached,
            # surface it so the GUI can still show what the device is
            # configured as — but the device stays offline.
            if dev.get('application', 0) == 0:
                app_result = conn.read_point(dev_name, "APPLICATION", node_name.lower())
                if app_result and app_result.get('value') is not None:
                    dev['application'] = int(app_result['value'])
                    dev['application_cached'] = True
            offline += 1
            continue

        # No ROOM TEMP response at all (point doesn't exist, parse failed,
        # or the panel returned an error). Fall through to APPLICATION as
        # a last-resort probe — for devices without a ROOM TEMP point
        # this is the only way to confirm they exist. We treat success
        # here as "online" but flag it as a soft signal.
        result2 = conn.read_point(dev_name, "APPLICATION", node_name.lower())
        if result2 and result2.get('value') is not None:
            app_comm = result2.get('comm_status')
            if app_comm == 'comm_fault':
                # Even APPLICATION came back stale — definitely offline.
                dev['status'] = 'offline'
                dev['comm_status'] = 'comm_fault'
                if dev.get('application', 0) == 0:
                    dev['application'] = int(result2['value'])
                    dev['application_cached'] = True
                offline += 1
            else:
                dev['status'] = 'online'
                if dev.get('application', 0) == 0:
                    dev['application'] = int(result2['value'])
                online += 1
        else:
            offline += 1

    conn.close()

    # Print results based on filter
    sys.stdout.write(f"\r{'':60s}\r")
    print(f"    Verified: {online} online, {offline} offline, {total} total")
    print()

    for dev in devices:
        status = dev.get('status', '?')
        dev_name = dev['device']
        desc = dev.get('description', '')
        app = dev.get('application', 0)

        if show_filter == "online" and status != "online":
            continue
        if show_filter == "offline" and status != "offline":
            continue

        if status == 'online':
            temp = dev.get('room_temp')
            units = dev.get('units', '')
            app_str = f"APP {app}" if app else ""
            if temp is not None:
                print(f"    ✓ {dev_name:<20s} {app_str:>8s}  {temp:>6.1f}{units:<5s} {desc}")
            else:
                print(f"    ✓ {dev_name:<20s} {app_str:>8s}  {'':>11s} {desc}")
        else:
            # Offline: distinguish "FLN comm-faulted (PXC has stale cache)"
            # from "completely unreachable" so the user can tell whether
            # the device is wired up but failing or genuinely gone.
            stale = dev.get('stale_temp')
            app_str = f"APP {app}" if app else ""
            if dev.get('comm_status') == 'comm_fault':
                if stale is not None:
                    label = f"#COM (cached {stale:.0f}{dev.get('units', '')})"
                else:
                    label = "#COM"
                print(f"    ✗ {dev_name:<20s} {app_str:>8s}  {label:<24s} {desc}")
            else:
                print(f"    ✗ {dev_name:<20s} {app_str:>8s}  {'(no response)':<24s} {desc}")

    return devices


def discover_devices_on_node(host: str, node_name: str,
                             device_list: Optional[List[str]] = None,
                             use_enumerate: bool = True) -> List[Dict]:
    """
    Discover TEC devices on a PXC node.
    First tries FLN enumerate (opcode 0x0986) for a complete device list.
    Falls back to batched APPLICATION reads if enumerate fails.
    """
    # Try FLN enumerate first (fast, complete, no brute force)
    if use_enumerate and device_list is None:
        print(f"    Trying FLN enumerate...")
        devs = enumerate_fln_devices(host, node_name)
        if devs:
            return devs
        print(f"    Enumerate returned no devices, falling back to brute force...")

    candidates = device_list or DISCOVERY_DEVICE_PATTERNS
    found = []
    BATCH_SIZE = 25

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except (socket.error, socket.timeout) as e:
        print(f"    [ERROR] Connection failed: {e}")
        return []

    try:

        net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
        scanner = effective_scanner_name().encode('ascii')
        site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
        node_lower = node_name.lower().encode('ascii')

        # Build both dialect variants for probe.
        routing_hb = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
        identity = (
            b'\x46\x40' +
            b'\x01' + struct.pack('>H', len(scanner)) + scanner +
            b'\x01' + struct.pack('>H', len(site)) + site +
            b'\x01' + struct.pack('>H', len(net)) + net +
            # Trailer: separator + 3 flags + 5 reserved + 4-byte timestamp +
            # 2-byte session id (00 00 = panel-style) + trailing null = 16 bytes.
            # See APOGEE_P2_SPEC.md §9 for the documented format.
            b'\x00\x01\x01\x00\x00\x00\x00\x00\x00' +
            struct.pack('>I', int(time.time())) + b'\x00\x00\x00'
        )
        hb_payload = routing_hb + identity
        _hs_seq = secrets.randbits(24)  # See APOGEE_P2_SPEC.md §5.2 / §8.4
        hs_0x33 = struct.pack('>III', 12 + len(hb_payload), 0x33, _hs_seq) + hb_payload
        hs_0x34 = struct.pack('>III', 12 + len(hb_payload), 0x34, _hs_seq) + hb_payload

        dialect = _probe_dialect(s, hs_0x33, hs_0x34, host=host)
        if dialect is None:
            s.close()
            print(f"    [ERROR] Handshake failed")
            return []

        total = len(candidates)
        base_seq = 5000
        num_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

        for batch_num in range(num_batches):
            batch_start = batch_num * BATCH_SIZE
            batch_end = min(batch_start + BATCH_SIZE, total)
            batch = candidates[batch_start:batch_end]

            sys.stdout.write(f"\r    Probing: {batch_end}/{total}{'':20s}")
            sys.stdout.flush()

            # Build and send this batch
            seq_map = {}
            batch_msgs = b""
            for i, dev in enumerate(batch):
                seq = base_seq + batch_start + i
                seq_map[seq] = dev
                dev_bytes = dev.encode('ascii')
                routing = (b'\x00' + net + b'\x00' + node_lower + b'\x00' +
                           net + b'\x00' + scanner + b'\x00')
                read_data = (
                    b'\x02\x71\x00\x00' +
                    b'\x01' + struct.pack('>H', len(dev_bytes)) + dev_bytes +
                    b'\x01\x00\x0bAPPLICATION' +
                    b'\x00\xff'
                )
                payload = routing + read_data
                msg = struct.pack('>III', 12 + len(payload), dialect, seq) + payload
                batch_msgs += msg

            try:
                s.sendall(batch_msgs)
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

            # Collect responses for this batch
            all_data = b""
            s.settimeout(2)
            try:
                while True:
                    chunk = s.recv(16384)
                    if not chunk:
                        break
                    all_data += chunk
                    s.settimeout(0.3)
            except socket.timeout:
                pass
            except (ConnectionResetError, OSError):
                break

            # Parse responses
            pos = 0
            while pos < len(all_data) - 12:
                if len(all_data) - pos < 12:
                    break
                msg_len = struct.unpack('>I', all_data[pos:pos+4])[0]
                if msg_len < 12 or msg_len > len(all_data) - pos:
                    pos += 1
                    continue
                msg_data = all_data[pos:pos+msg_len]
                pos += msg_len
                if len(msg_data) < 13:
                    continue
                resp_seq = struct.unpack('>I', msg_data[8:12])[0]
                resp_flag = msg_data[12]
                if resp_flag != 1 or resp_seq not in seq_map:
                    continue
                dev_name = seq_map[resp_seq]
                if len(msg_data) <= 55:
                    continue

                # Try standard parser (3FFFFF flags)
                flags_idx = -1
                for fi in range(12, len(msg_data) - 3):
                    if msg_data[fi] == 0x3F and msg_data[fi+1] == 0xFF and msg_data[fi+2] == 0xFF:
                        flags_idx = fi
                        break
                if flags_idx >= 0:
                    after_flags = msg_data[flags_idx + 3:]
                    if len(after_flags) >= 8:
                        raw_val = after_flags[4:8]
                        app_num = int(struct.unpack('>f', raw_val)[0])
                        desc = ''
                        lp_strings = P2Connection._extract_lp_strings(msg_data[12:flags_idx])
                        routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE,
                                      node_name.upper(), node_name.lower()}
                        data_strs = [st for st in lp_strings if st not in routing_set
                                   and st.upper() != 'APPLICATION']
                        if len(data_strs) >= 2:
                            desc = data_strs[1]
                        found.append({
                            'device': dev_name,
                            'application': app_num,
                            'description': desc,
                        })
                        sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  APP={app_num}  {desc}\n")
                        sys.stdout.flush()
                else:
                    # Fallback: device responded but different format (UC, PTEC, etc)
                    # Extract description from any length-prefixed strings
                    lp_strings = P2Connection._extract_lp_strings(msg_data[12:])
                    routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE,
                                  node_name.upper(), node_name.lower(), 'APPLICATION'}
                    data_strs = [st for st in lp_strings if st not in routing_set
                               and st != dev_name]
                    desc = data_strs[0] if data_strs else ''
                    found.append({
                        'device': dev_name,
                        'application': 0,
                        'description': desc,
                    })
                    sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  (non-TEC)  {desc}\n")
                    sys.stdout.flush()

    finally:
        s.close()
    sys.stdout.write(f"\r    Device scan complete: {len(found)} TECs found{'':30s}\n")
    return found

def discover_panel_points(host: str, node_name: str) -> List[Dict]:
    """Try reading known panel-level points from a node."""
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET", scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        return []

    found = []
    total = len(PANEL_POINT_NAMES)

    for i, pt_name in enumerate(PANEL_POINT_NAMES):
        sys.stdout.write(f"\r    Panel points: {i+1}/{total} — {pt_name:<30s}")
        sys.stdout.flush()

        # Panel points use the point name as both device and point
        result = conn.read_point(pt_name, pt_name, node_name.lower())
        if result and result.get('value') is not None:
            found.append({
                'point': pt_name,
                'value': result['value'],
                'units': result.get('units', ''),
            })

        time.sleep(0.03)

    conn.close()
    sys.stdout.write(f"\r    Panel point scan complete: {len(found)} points found{'':30s}\n")
    return found


def discover_network(ip_ranges: str = "192.0.2", scan_ports: bool = True,
                     scan_devices: bool = True, scan_panel: bool = False,
                     scan_info: bool = False, verify: str = None,
                     read_all: bool = False, output_format: str = "table",
                     read_points: Optional[List[str]] = None,
                     inter_read_delay_s: float = 0.05):
    """
    Full network discovery:
    1. Port scan for P2 hosts (or use known nodes)
    2. Handshake each to learn node names
    3. Brute-force TEC device discovery on each node
    4. Optionally read all points on every discovered device (read_all=True)
       OR read specific points across all devices (read_points=["ROOM TEMP"])
    """
    print(f"\n{'═' * 70}")
    print(f"  P2 NETWORK DISCOVERY")
    print(f"{'═' * 70}")

    # Step 1: Find P2 hosts
    if scan_ports:
        ip_list = parse_ip_range(ip_ranges)
        print(f"\n  [1/3] Port scanning {len(ip_list)} IPs for TCP/{P2_PORT}...")
        print(f"        Range: {ip_ranges}")
        hosts = port_scan_p2(ip_list)
    else:
        print(f"\n  [1/3] Using known node list ({len(KNOWN_NODES)} nodes)")
        hosts = list(KNOWN_NODES.values())

    if not hosts:
        print("  No P2 hosts found.")
        return

    # Auto-learn the P2 network name if not already known
    if not P2_NETWORK:
        print(f"\n  Auto-learning P2 network name...")
        learned = learn_network_name(hosts)
        if learned:
            print(f"  Learned network: {learned}")
        else:
            print(f"\n  ⚠ Could not auto-learn the P2 network name.")
            print(f"    PXC controllers require the correct network name to respond.")
            print(f"    Use --network <NAME> to specify it.")
            print(f"    Find it in your BAS front-end (often listed under Field Networks).")
            print(f"    Common formats: SITEBLN, SITEEBLN, SITE_BLN")
            print(f"\n    Example: p2_scanner.py --discover --range {ip_ranges} --network MYBLN")
            return

    # Step 2: Identify each node
    print(f"\n  [2/3] Identifying {len(hosts)} P2 nodes...")
    print(f"        (trying common node names — this may take a moment)")
    node_map = {}  # ip -> node_name
    for ip in hosts:
        # Check known_nodes first (from config file)
        known_name = None
        for kname, kip in KNOWN_NODES.items():
            if kip == ip:
                known_name = kname
                break
        if known_name:
            node_map[ip] = known_name
            print(f"    {ip}... {known_name}  (from config)")
            continue

        sys.stdout.write(f"    {ip}... probing ")
        sys.stdout.flush()
        info = probe_p2_host(ip)
        if info and 'node_name' in info:
            node_map[ip] = info['node_name']
            KNOWN_NODES[info['node_name']] = ip
            extras = []
            if info.get('network'):
                extras.append(f"net={info['network']}")
            if info.get('site'):
                extras.append(f"site={info['site']}")
            extra_str = f"  ({', '.join(extras)})" if extras else ""
            sys.stdout.write(f"\r    {ip}... {info['node_name']}{extra_str}{'':20s}\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"\r    {ip}... not a PXC (DCC server or unresponsive){'':20s}\n")
            sys.stdout.flush()
            node_map[ip] = f"UNKNOWN_{ip.split('.')[-1]}"

    if P2_NETWORK:
        print(f"\n  P2 Network: {P2_NETWORK}  |  Site: {P2_SITE or '?'}")

    # Step 3: Discover devices on each node
    all_devices = {}
    if scan_devices:
        # Filter to only identified nodes (skip UNKNOWN — those are servers, not PXCs)
        pxc_nodes = {ip: name for ip, name in node_map.items()
                     if not name.startswith('UNKNOWN')}
        skipped = len(node_map) - len(pxc_nodes)
        if skipped:
            print(f"\n  Skipping {skipped} unidentified hosts (likely DCC servers)")
        print(f"\n  [3/3] Discovering TEC devices on {len(pxc_nodes)} PXC nodes...")

        for ip, name in sorted(pxc_nodes.items(), key=lambda x: x[1]):
            print(f"\n  {'─' * 60}")
            print(f"  {name} ({ip})", end="")

            # Get node firmware info if requested
            if scan_info:
                info = get_node_info(ip, name)
                if info:
                    print(f"  — {info['firmware']} / {info['model']}", end="")
                    all_devices.setdefault(name, {})['node_info'] = info

            print(f"\n  {'─' * 60}")

            devs = discover_devices_on_node(ip, name)
            all_devices[name] = {'ip': ip, 'devices': devs}

            # Verify online status if requested
            if verify and devs:
                verify_devices(ip, name, devs, show_filter=verify)

            if scan_panel:
                print(f"    Scanning panel-level points...")
                panel_pts = discover_panel_points(ip, name)
                all_devices[name]['panel_points'] = panel_pts
                if panel_pts:
                    for pt in panel_pts[:10]:
                        val = pt['value']
                        units = pt.get('units', '')
                        print(f"      {pt['point']:<35s} = {val:>10.2f} {units}")
                    if len(panel_pts) > 10:
                        print(f"      ... and {len(panel_pts) - 10} more")

    # Step 4: Optionally read all points on discovered devices
    if read_all and all_devices:
        print(f"\n{'═' * 70}")
        print(f"  READING ALL POINTS ON DISCOVERED DEVICES")
        print(f"{'═' * 70}")

        for name in sorted(all_devices.keys()):
            node_info = all_devices[name]
            ip = node_info['ip']
            devs = node_info['devices']

            for dev_info in devs:
                dev = dev_info['device']
                app = dev_info.get('application', 2023)
                desc = dev_info.get('description', '')

                app_label = format_app_label(app, prefix="[APP ") + "]"
                print(f"\n  {'━' * 60}")
                print(f"  {name} / {dev}", end="")
                if desc:
                    print(f"  ({desc})", end="")
                print(f"  {app_label}")
                print(f"  {'━' * 60}")

                results = scan_device(ip, dev, quick=False, output_format=output_format,
                                       inter_read_delay_s=inter_read_delay_s)
                all_devices[name].setdefault('point_data', {})[dev] = results

    # Step 4b: Selective point read across every discovered device.
    # This is the "quick building health check" mode — read specific points
    # (by name or slot number) from every device without doing a full scan.
    # Output is a single combined table sorted by node/device.
    elif read_points and all_devices:
        print(f"\n{'═' * 70}")
        print(f"  BUILDING-WIDE READ — points: {', '.join(str(p) for p in read_points)}")
        print(f"{'═' * 70}")

        sweep_results = []  # flat list: one entry per (node, device, point)
        total_devs = sum(len(ni['devices']) for ni in all_devices.values())
        done = 0

        for name in sorted(all_devices.keys()):
            node_info = all_devices[name]
            ip = node_info['ip']
            devs = node_info['devices']

            for dev_info in devs:
                dev = dev_info['device']
                desc = dev_info.get('description', '')
                done += 1
                sys.stdout.write(f"\r  Reading {done}/{total_devs} — {name}/{dev}           ")
                sys.stdout.flush()

                try:
                    # output_format="none" suppresses per-device tables; we'll
                    # render a single combined table at the end.
                    dev_results = scan_device(ip, dev, points=list(read_points),
                                              output_format="none",
                                              inter_read_delay_s=inter_read_delay_s)
                except ScannerInputError as e:
                    # Bad input stops the whole sweep — the user gave us a
                    # slot/name that's invalid. Fail fast, same contract as
                    # single-device scans.
                    print(f"\n  [ERROR] {e}")
                    return
                except Exception as e:
                    # Per-device exceptions (timeouts, auth) are logged and
                    # skipped so one bad device doesn't kill the sweep.
                    sweep_results.append({'node': name, 'device': dev,
                                          'description': desc, 'error': str(e)})
                    continue

                if dev_results:
                    for r in dev_results:
                        r['_node'] = name
                        r['_device'] = dev
                        r['_description'] = desc
                        sweep_results.append(r)
                else:
                    # Device unreachable or point not readable — record the miss
                    sweep_results.append({'node': name, 'device': dev,
                                          'description': desc,
                                          'error': 'no data'})

        # Clear progress line
        sys.stdout.write("\r" + " " * 70 + "\r")

        # Render combined output
        _print_sweep_results(sweep_results, read_points, output_format)

    # Summary
    print(f"\n{'═' * 70}")
    print(f"  DISCOVERY RESULTS")
    print(f"{'═' * 70}")

    print(f"\n  P2 NODES:")
    for name in sorted(all_devices.keys()):
        info = all_devices[name]
        devs = info.get('devices', [])
        dev_count = len(devs)
        panel_count = len(info.get('panel_points', []))
        # Count online/offline if verified
        online = sum(1 for d in devs if d.get('status') == 'online')
        offline = sum(1 for d in devs if d.get('status') == 'offline')
        extra_parts = []
        if panel_count:
            extra_parts.append(f"{panel_count} panel points")
        if online or offline:
            extra_parts.append(f"{online} online, {offline} offline")
        extra = f"  ({', '.join(extra_parts)})" if extra_parts else ""
        print(f"    {name:<12s}  {info['ip']:<16s}  {dev_count} devices{extra}")

    total_devs = 0
    total_online = 0
    total_offline = 0
    for name in sorted(all_devices.keys()):
        devs = all_devices[name].get('devices', [])
        if devs:
            # Don't re-print device list if verify already printed it
            if not verify:
                print(f"\n  {name} DEVICES:")
                for d in devs:
                    desc = d.get('description', '')
                    desc_str = f"  ({desc})" if desc else ""
                    app_label = format_app_label(d['application'])
                    print(f"    {d['device']:<20s}  {app_label}{desc_str}")
            total_devs += len(devs)
            total_online += sum(1 for d in devs if d.get('status') == 'online')
            total_offline += sum(1 for d in devs if d.get('status') == 'offline')

    summary = f"\n  TOTAL: {len(node_map)} nodes, {total_devs} devices discovered"
    if total_online or total_offline:
        summary += f" ({total_online} online, {total_offline} offline)"
    print(summary)
    print(f"{'═' * 70}")

    # JSON output
    if output_format == "json":
        print(json.dumps(all_devices, indent=2, default=str))


# ═══════════════════════════════════════════════════════════════════════════════
# Cold-site onboarding — discover BLN/scanner/node names on an unknown site.
#
# Pure addition to the original scanner — does NOT modify any existing code
# paths. Builds its own heartbeats independently via _cold_probe(), uses the
# existing port_scan_p2() helper, and populates KNOWN_NODES at the end via
# direct dict mutation (which save_config respects).
#
# Empirically validated: PXCs validate (BLN name, scanner name, node name)
# on handshake; wrong BLN → TCP RST; wrong scanner/node → silent drop;
# site and trailer fields are decorative.
# ═══════════════════════════════════════════════════════════════════════════════

_COLD_VENDOR_OUIS = {
    '00:c0:e4': 'Siemens Building Technologies',
    '00:a0:03': 'Siemens AG Automation',
    '00:12:ea': 'Trane',
    '00:50:db': 'Contemporary Controls',
    '00:50:7f': 'Distech Controls',
}
_COLD_SIEMENS_OUIS = {o for o, v in _COLD_VENDOR_OUIS.items() if 'Siemens' in v}
_COLD_BACNET_PORT = 47808
_COLD_FALSE_POSITIVE_PREFIXES = {
    'RM', 'VAV', 'AHU', 'FAN', 'FLR', 'CAB', 'BACNET',
    'DEVICE', 'ROOT', 'SYS', 'OBJECT', 'NET', 'SITE',
    'NODE', 'PANEL', 'ETHER', 'BVLC',
}


def _cold_extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    results, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                results.append(''.join(cur))
            cur = []
    if len(cur) >= min_len:
        results.append(''.join(cur))
    return results


def _cold_get_arp_mac(ip: str) -> Optional[str]:
    import subprocess
    try:
        if sys.platform.startswith('win'):
            result = subprocess.run(['arp', '-a', ip], capture_output=True,
                                    text=True, timeout=3)
        else:
            result = subprocess.run(['arp', '-n', ip], capture_output=True,
                                    text=True, timeout=3)
        for line in result.stdout.splitlines():
            if ip in line:
                m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                if m:
                    return m.group(0).replace('-', ':').lower()
    except Exception:
        pass
    return None


def _cold_classify_vendor(mac: Optional[str]) -> str:
    if not mac:
        return 'Unknown (no MAC)'
    return _COLD_VENDOR_OUIS.get(mac[:8].lower(), f'Unknown OUI {mac[:8]}')


def _cold_passive_bacnet(duration: int = 30, interface: str = '0.0.0.0',
                         verbose: bool = False) -> Dict[str, dict]:
    from collections import defaultdict
    print(f"\n{'─' * 70}")
    print(f"  COLD-DISCOVER PHASE 1: Passive BACnet recon ({duration}s)")
    print(f"{'─' * 70}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind((interface, _COLD_BACNET_PORT))
    except OSError as e:
        print(f"  [FAIL] Could not bind UDP/{_COLD_BACNET_PORT}: {e}")
        sock.close()
        return {}

    discoveries: Dict[str, dict] = defaultdict(
        lambda: {'strings': set(), 'packet_count': 0, 'first_seen': None}
    )
    start = time.time()
    try:
        while time.time() - start < duration:
            sock.settimeout(1.0)
            try:
                data, (src, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) < 4 or data[0] != 0x81:
                continue
            d = discoveries[src]
            if d['first_seen'] is None:
                d['first_seen'] = time.time()
                if verbose:
                    print(f"  new BACnet source: {src}")
            d['packet_count'] += 1
            for s in _cold_extract_strings(data, min_len=4):
                d['strings'].add(s)
    except KeyboardInterrupt:
        print(f"  Interrupted.")
    finally:
        sock.close()
    print(f"  Captured from {len(discoveries)} unique BACnet source(s)")
    return dict(discoveries)


def _cold_infer_prefix(discoveries: Dict[str, dict]) -> List[str]:
    from collections import Counter
    scores: Counter = Counter()
    for info in discoveries.values():
        for s in info['strings']:
            if len(s) < 3 or s.lower() in ('bacnet', 'utf-8'):
                continue
            m = re.match(r'^([A-Za-z]{2,10})[_\-]', s)
            if m: scores[m.group(1).upper()] += 2
            m = re.match(r'^([A-Za-z]{3,8})\d', s)
            if m: scores[m.group(1).upper()] += 1
            m = re.match(r'^([A-Z][a-z]*[A-Z]+)', s)
            if m: scores[m.group(1).upper()] += 1
    ranked = [(p, c) for p, c in scores.most_common()
              if p not in _COLD_FALSE_POSITIVE_PREFIXES]
    if not ranked:
        return []
    top_score = ranked[0][1]
    return [p for p, c in ranked if c == top_score]


def _cold_generate_bln_candidates(prefixes: List[str]) -> List[str]:
    patterns = ["{p}EBLN", "{p}BLN", "{p}_BLN", "{p}-BLN",
                "{p}_EBLN", "{p}-EBLN", "{p}", "{p}NET"]
    candidates = []
    for pat in patterns:
        for p in [x.upper() for x in prefixes]:
            candidates.append(pat.format(p=p))
    candidates.extend(["APOGEE", "APOGEEBLN", "SIEMENS", "MAIN",
                       "DEFAULT", "NETWORK", "BLN1", "P2NET"])
    seen, result = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_generate_scanner_candidates(prefixes: List[str]) -> List[str]:
    patterns = [
        "{p}DCC-SVR|5033", "{p}DCC-SVR",
        "{p}-DCC-SVR|5033", "{p}-DCC-SVR",
        "{p}DCC|5033", "{p}DCC",
    ]
    candidates = []
    for pat in patterns:
        for p in [x.upper() for x in prefixes]:
            candidates.append(pat.format(p=p))
    candidates.extend([
        "DCC-SVR|5033", "DCC-SVR",
        "INSIGHT-SVR", "INSIGHT",
        "DESIGO-CC", "DESIGO", "DESIGOCC", "APOGEE-SVR",
    ])
    seen, result = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_generate_node_candidates(limit: int = 10) -> List[str]:
    candidates = []
    for i in range(1, limit + 1):
        candidates.append(f"node{i}")
        candidates.append(f"NODE{i}")
    candidates.extend(["MAIN", "LOBBY", "PENT", "BOILER", "CHILLER"])
    seen, result = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_probe(host: str, bln: str, scanner: str, node: str,
                site: str = 'DIAGSITE', timeout: float = 3.0) -> Dict:
    """Independent heartbeat probe — builds its own frame, doesn't touch
    any module globals or the P2Connection class."""
    bln_b = bln.encode('ascii')
    scanner_b = scanner.encode('ascii')
    site_b = site.encode('ascii')
    node_b = node.encode('ascii')

    routing = (b'\x00' + bln_b + b'\x00' + node_b + b'\x00' +
               bln_b + b'\x00' + scanner_b + b'\x00')
    identity = (
        b'\x46\x40' +
        b'\x01' + struct.pack('>H', len(scanner_b)) + scanner_b +
        b'\x01' + struct.pack('>H', len(site_b)) + site_b +
        b'\x01' + struct.pack('>H', len(bln_b)) + bln_b +
        # Trailer: separator + 3 flags + 5 reserved + 4-byte timestamp +
        # 2-byte session id (00 00 = panel-style) + trailing null = 16 bytes.
        # See APOGEE_P2_SPEC.md §9 for the documented format.
        b'\x00\x01\x01\x00\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\x00\x00'
    )
    payload = routing + identity
    frame = struct.pack('>III', 12 + len(payload), 0x33, secrets.randbits(24)) + payload

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, P2_PORT))
    except (ConnectionRefusedError, socket.timeout):
        return {'verdict': 'port_closed'}
    except Exception as e:
        return {'verdict': 'error', 'reason': str(e)}

    try:
        sock.sendall(frame)
    except Exception as e:
        sock.close()
        return {'verdict': 'error', 'reason': str(e)}

    sock.settimeout(2.0)
    data, reset = b"", False
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            sock.settimeout(0.5)
    except ConnectionResetError:
        reset = True
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass

    if data:
        return {'verdict': 'got_response', 'data': data}
    return {'verdict': 'rejected_rst' if reset else 'rejected_silent'}


# ─────────────────────────────────────────────────────────────────────
# Optimized cold-discovery primitive
#
# The panel's IdentifyBlock response (91 bytes) and SysInfoCompact
# response (281 bytes) both echo the panel's configured BLN, site code,
# and panel name in their TLV block, regardless of what the request
# claimed in those fields. Combined with the observation that a 15-
# character placeholder is accepted in slot 4 by the panel's bouncer,
# this reduces cold-discovery from a 3-dimensional Cartesian sweep
# (BLN × scanner × node) to a 2-dimensional sweep (BLN × node).
#
# Tradeoff: a placeholder scanner identity is treated as a new peer by
# the panel, which generates outbound callbacks at ~16s cadence to the
# requesting IP. To avoid those callbacks on subsequent probes, the
# optimized flow learns the canonical supervisor identity from the
# first successful response and uses that identity in slot 4 for all
# later probes. The panel treats a second session claiming the same
# identity as a parallel session and does not re-bind the supervisor
# IP, which suppresses the callbacks because the original supervisor
# IP remains the bound destination.
# ─────────────────────────────────────────────────────────────────────

WILDCARD_15CHAR_PLACEHOLDER = "RANDOM15CHARSXY"


def _parse_handshake_response(data: bytes) -> Optional[Dict]:
    """Parse a panel's IdentifyBlock response to extract canonical names.

    Empirically-verified response wire format (legacy-firmware PXC,
    derived from packet-capture analysis of the actual 91-byte response):

        [4B length BE] [4B msg_type=0x33/0x34] [4B seq] [01=success]
        [slot1 BLN \\0] [slot2 DEST \\0] [slot3 BLN \\0] [slot4 SOURCE \\0]
        [TLV: panel name] [TLV: site code] [TLV: BLN] [trailer]

    Response slot 4 is the panel itself (the source). Response slot 2 is
    the DEST = whoever the requester claimed to be in REQUEST slot 4.
    That means slot 2 of the response is the requester's claimed
    identity ECHOED BACK, NOT the panel's real supervisor canonical
    name. **The real supervisor canonical name is NOT in this response.**

    To learn the real supervisor name, use _cold_status_query_probe
    (opcode 0x0050 — already implemented elsewhere in this module) or
    sniff the supervisor port (default TCP/5033) for panel→supervisor callbacks.

    The TLV block echoes the panel's REAL configured site code, panel
    name, and BLN. The supervisor's canonical name is NOT in this
    response — it appears in the 0x0050 StatusQuery response instead.

    Returns dict with:
        bln                       — real BLN (from slot 1)
        panel_name                — real panel name (from slot 4)
        site                      — real site code (from TLV)
        claimed_supervisor_echo   — what the requester claimed to be
                                    (slot 2 echoed back; NOT the real
                                    supervisor canonical name)

    Returns None if the response doesn't match the expected shape.
    """
    if len(data) < 50:
        return None
    if data[12] not in (0x00, 0x01):  # request or success-response
        return None

    body = data[13:]
    fields = body.split(b'\x00', 4)
    if len(fields) < 5:
        return None

    bln1, claimed_sup_b, bln2, panel_name_b, rest = fields[:5]
    if bln1 != bln2 or not bln1:
        return None

    # TLV block follows the routing slots. In the response there is NO
    # explicit 0x4640 marker before the TLVs (request frames include it;
    # responses observed without). Walk TLVs to find the site code.
    site = None
    pos = 0
    # Tolerate an optional leading 0x4640 marker for robustness
    if rest[:2] == b'\x46\x40':
        pos = 2
    while pos + 3 < len(rest):
        if rest[pos] != 0x01 or rest[pos+1] != 0x00:
            break
        length = rest[pos+2]
        if pos + 3 + length > len(rest):
            break
        tlv_value = rest[pos+3:pos+3+length].rstrip(b'\x00')
        # Site code is typically the shortest distinct TLV string
        # (3-5 chars), differs from panel name, BLN, and claimed
        # supervisor echo.
        if (2 <= len(tlv_value) <= 10
                and tlv_value != panel_name_b
                and tlv_value != bln1
                and tlv_value != claimed_sup_b):
            site = tlv_value
            break
        pos += 3 + length

    def _safe_decode(b):
        try:
            return b.decode('ascii') if b else None
        except UnicodeDecodeError:
            return None

    return {
        'bln': _safe_decode(bln1),
        'site': _safe_decode(site) if site else None,
        'panel_name': _safe_decode(panel_name_b),
        'claimed_supervisor_echo': _safe_decode(claimed_sup_b),
        # NOTE: real supervisor_name is intentionally NOT returned here.
        # Use _cold_status_query_probe (opcode 0x0050) to learn it.
    }


def _cold_placeholder_probe(host: str, bln: str, node: str,
                    scanner_name: str = WILDCARD_15CHAR_PLACEHOLDER,
                    site: str = 'DIAGSITE',
                    timeout: float = 3.0) -> Dict:
    """Cold-probe using a 15-character ASCII placeholder for slot 4.
    Wraps `_cold_probe` with a known-accepting scanner identity,
    reducing the Cartesian search dimension from 3D to 2D (BLN × node).

    First-call note: a placeholder scanner identity triggers outbound
    callbacks at ~16 s cadence from the panel. Subsequent probes
    should use the learned supervisor canonical name as `scanner_name`
    to activate the panel's parallel-session-no-rebind protection,
    which suppresses callbacks silently.
    """
    if scanner_name == WILDCARD_15CHAR_PLACEHOLDER and len(scanner_name) != 15:
        raise ValueError(
            f"WILDCARD_15CHAR_PLACEHOLDER must be exactly 15 chars; got {len(scanner_name)}"
        )
    return _cold_probe(host, bln, scanner_name, node, site=site, timeout=timeout)


def cold_discover_v0_14(host: str,
                        bln_candidates: List[str],
                        node_candidates: List[str],
                        delay: float = 1.0,
                        verbose: bool = True,
                        chain_status_query: bool = True) -> Optional[Dict]:
    """Optimized two-stage cold-discovery primitive.

    Stage 1 — placeholder-wildcard handshake (this function's main loop):
        Probes BLN × node combinations until one is accepted. Parses
        the 91-byte IdentifyBlock response for real BLN, panel name,
        and site code. Reduces the search space from
        O(BLN × scanner × node) to O(BLN × node).

        Note: this stage does NOT learn the real supervisor canonical
        name — the response's slot 2 is the requester's claimed
        identity echoed back, not the panel's configured supervisor.

    Stage 2 — 0x0050 StatusQuery (chain_status_query=True, default):
        Calls _cold_status_query_probe with the learned BLN+panel and
        a permissive scanner identity. Per APOGEE_P2_SPEC.md §22.6 the
        0x0050 response includes the real supervisor canonical name
        in the body after the SYST scope footer. This is the existing
        scanner primitive — `cold_discover_v0_14` simply chains to it.

    Returns dict with:
        host, bln, site, panel_name,
        claimed_supervisor_echo,  — from Stage 1 (slot-2 echo)
        supervisor_name,          — from Stage 2 (real, if chain_status_query=True)
        first_probe_combo         — BLN, node pair that hit Stage 1
        status_query_msg_type     — present if Stage 2 succeeded

    or None if Stage 1 found no acceptance.

    Stage 2 failure is non-fatal: the function still returns the
    Stage 1 result without supervisor_name (caller can decide).

    Use the returned supervisor_name as scanner_name in subsequent
    probes (via _cold_probe / cold_discover_silent_sysinfo) to avoid
    additional outbound-callback traces — the panel's parallel-session
    protection suppresses callbacks when the second session claims
    the active supervisor identity.
    """
    if verbose:
        print(f"  cold_discover_v0_14 Stage 1: probing {host} "
              f"({len(bln_candidates)} BLN × {len(node_candidates)} node = "
              f"{len(bln_candidates) * len(node_candidates)} max probes)")

    discovery: Optional[Dict] = None
    for bln in bln_candidates:
        if discovery:
            break
        for node in node_candidates:
            r = _cold_placeholder_probe(host, bln, node, timeout=3.0)
            v = r['verdict']
            if v == 'got_response':
                parsed = _parse_handshake_response(r['data'])
                if parsed and parsed.get('bln') and parsed.get('panel_name'):
                    discovery = {
                        'host': host,
                        'first_probe_combo': {'bln': bln, 'node': node},
                        **parsed,
                    }
                    if verbose:
                        print(f"    HIT bln={bln!r} node={node!r}")
                        print(f"      -> real bln              = {parsed.get('bln')!r}")
                        print(f"      -> real panel name       = {parsed.get('panel_name')!r}")
                        print(f"      -> real site code        = {parsed.get('site')!r}")
                        print(f"      -> claimed supervisor    = "
                              f"{parsed.get('claimed_supervisor_echo')!r}  "
                              f"(this is the placeholder echoed back, NOT real)")
                    break
            elif v == 'port_closed':
                if verbose:
                    print(f"    {host}: port closed - aborting")
                return None
            time.sleep(delay)

    if not discovery:
        if verbose:
            print(f"  cold_discover_v0_14 Stage 1: no acceptance found across "
                  f"{len(bln_candidates) * len(node_candidates)} combos")
        return None

    if not chain_status_query:
        return discovery

    # Stage 2 — 0x0050 StatusQuery for real supervisor canonical name
    if verbose:
        print(f"  cold_discover_v0_14 Stage 2: 0x0050 StatusQuery for supervisor name")

    sq = _cold_status_query_probe(
        host,
        scanner_name=WILDCARD_15CHAR_PLACEHOLDER,
        bln_hint=discovery['bln'],
        panel_hint=discovery['panel_name'],
        timeout=3.0,
    )
    if sq:
        sup_bare = sq.get('supervisor')
        discovery['supervisor_name'] = sup_bare
        discovery['status_query_msg_type'] = sq.get('msg_type')

        # The 0x0050 StatusQuery returns the BARE form of the supervisor
        # name (e.g. "SITEDCC-SVR" without the port suffix). The
        # active-session-bound identity that Desigo CC uses on the wire
        # is the PORT-SUFFIXED form (e.g. "SITEDCC-SVR|5033"). Using
        # the bare form in slot 4 of a follow-up probe is typically
        # silent-dropped or rejected with a 0x05 error; the port-
        # suffixed form is accepted as a parallel session and does
        # not generate callbacks.
        #
        # Heuristic: if the bare form doesn't already contain |, append
        # the conventional Desigo CC port |5033. The caller can override
        # by providing supervisor_name_with_port directly. Some sites
        # use non-standard ports — if |5033 doesn't get the silent
        # parallel-session accept, the active port can be discovered by
        # sniffing supervisor-port callbacks or by the 0x464D topology query.
        if sup_bare and '|' not in sup_bare:
            discovery['supervisor_name_with_port'] = f"{sup_bare}|5033"
        else:
            discovery['supervisor_name_with_port'] = sup_bare

        if verbose:
            print(f"    HIT 0x0050 StatusQuery")
            print(f"      -> real supervisor name (bare)         = {sup_bare!r}")
            print(f"      -> canonical form (with default |5033) = "
                  f"{discovery['supervisor_name_with_port']!r}")
            print(f"         (use this form in slot 4 of follow-up probes for")
            print(f"          silent parallel-session accept)")
    else:
        if verbose:
            print(f"    0x0050 StatusQuery did not return supervisor name")
            print(f"    (panel may be on strict-peer-list firmware; falling back to "
                  f"passive supervisor-port sniff or manual lookup)")

    return discovery


def cold_discover_silent_sysinfo(host: str, discovery: Dict,
                                 timeout: float = 3.0) -> Optional[bytes]:
    """Follow-up 0x010C sysinfo probe using the learned supervisor name
    in slot 4. Silent (no callbacks) because the panel treats the
    second session as a parallel session and does not rebind the
    supervisor IP.

    Returns the raw response bytes (typically ~281 B) or None.
    Use _parse_handshake_response on the result to extract panel-side
    canonical names; sysinfo also returns model / firmware / build-date
    inline (decoded by the standard sysinfo helpers).

    Prefers `supervisor_name_with_port` from the discovery dict over
    `supervisor_name`. The bare form returned by 0x0050 StatusQuery is
    NOT the active-session-bound identity — using it in slot 4 typically
    causes silent-drop or a 0x05 rejection. The port-suffixed form
    (e.g. `<bare>|5033`) is what Desigo CC uses for the active session
    and is what the parallel-session protection covers.
    """
    bln = discovery.get('bln')
    panel_name = discovery.get('panel_name')
    # Prefer port-suffixed form (active-session-bound); fall back to bare
    supervisor_name = (discovery.get('supervisor_name_with_port')
                       or discovery.get('supervisor_name'))
    site = discovery.get('site') or 'DIAGSITE'

    if not all([bln, panel_name, supervisor_name]):
        return None

    bln_b = bln.encode('ascii')
    sv_b = supervisor_name.encode('ascii')
    site_b = site.encode('ascii')
    node_b = panel_name.lower().encode('ascii')

    routing = (b'\x00' + bln_b + b'\x00' + node_b + b'\x00' +
               bln_b + b'\x00' + sv_b + b'\x00')
    body = b'\x01\x0C'   # 0x010C SysInfoCompact request, empty body
    payload = routing + body
    frame = struct.pack('>III', 12 + len(payload), 0x33,
                        secrets.randbits(24)) + payload

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, P2_PORT))
        sock.sendall(frame)
        sock.settimeout(2.0)
        data = b''
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            sock.settimeout(0.5)
        return data if data else None
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _cold_status_query_probe(host: str, scanner_name: str,
                             bln_hint: str = "", panel_hint: str = "",
                             timeout: float = 3.0
                             ) -> Optional[Dict[str, Any]]:
    """`0x0050` StatusQuery one-round-trip bootstrap (APOGEE_P2_SPEC.md §22.6).

    Sends a Status Query and parses the response for the panel's identity.
    The panel echoes its own BLN in slot 0 and its node name in slot 3 of
    the role-swapped routing header, plus the supervisor identity it
    expects as an LP-string in the body after the SYST scope footer.

    Far cheaper than the Cartesian attack (§22.1) — one request gives us
    BLN + panel name + supervisor name. Strict-peer-list panels reject
    this the same way they reject IdentifyBlock; in that case the caller
    falls through to Cartesian.

    Args:
        host: Panel IP.
        scanner_name: Slot 4 source identifier. Use `<SITE>DCC-SVR|5033` when
            site is known; generic forms get silent-dropped on strict sites
            but work on permissive ones.
        bln_hint: Optional slot 0 value. Empty is safest for true cold
            discovery — the panel ignores empty routing slots on this opcode
            on permissive firmware.
        panel_hint: Optional slot 1 value (destination node name). Empty
            works on permissive sites; strict sites may require a guess.
        timeout: Per-attempt timeout in seconds.

    Returns:
        {'bln': str, 'panel': str, 'supervisor': str, 'msg_type': int} on
        success; None on no-response / RST / parse-fail.
    """
    bln_b = bln_hint.encode('ascii')
    panel_b = panel_hint.encode('ascii')
    scanner_b = scanner_name.encode('ascii')

    routing = (b'\x00'
               + bln_b + b'\x00'
               + panel_b + b'\x00'
               + bln_b + b'\x00'
               + scanner_b + b'\x00')

    # 0x0050 body per §22.6: opcode + 1-byte TLV "SYST" + SYST separator + wildcard.
    body = b'\x00\x50\x01\x00\x04SYST\x23\x3f\xff\xff\xff'
    payload = routing + body
    seq = secrets.randbits(24)

    for msg_type in (P2Message.TYPE_DATA, P2Message.TYPE_HEARTBEAT):
        frame = struct.pack('>III', 12 + len(payload), msg_type, seq) + payload
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, P2_PORT))
            sock.sendall(frame)
            data = _recv_one_frame(sock, overall_timeout=timeout)
        except (socket.error, socket.timeout):
            data = None
        finally:
            if sock is not None:
                try: sock.close()
                except Exception: pass

        if data is None or len(data) < 14:
            continue
        # Reject error-direction responses; spec §8.3.
        if data[12] == P2Message.DIR_ERROR:
            continue

        rh = _parse_routing_header(data[12:])
        if rh is None:
            continue
        _dir, names, body_after = rh
        if len(names) < 4:
            continue
        bln_resp = names[0]
        us_resp = names[1]
        panel_resp = names[3]

        # Sanity: panel must have filled in something useful. An echo of
        # our empty slots without any identity content is not a usable
        # response.
        if not bln_resp or not panel_resp:
            continue

        # Supervisor identity comes back as an LP-string in the body, after
        # the echoed scope footer. _extract_tlv_strings will find both
        # "SYST" (from the echoed scope) and the supervisor name; filter
        # "SYST" out and take the first remaining string. If parsing fails
        # we fall back to slot-1 ("us" position after role swap), which is
        # what the panel thinks our identity should be.
        sup_strings = _extract_tlv_strings(body_after)
        supervisor = next((s for s in sup_strings if s != "SYST"), us_resp)

        return {
            'bln': bln_resp,
            'panel': panel_resp,
            'supervisor': supervisor,
            'msg_type': msg_type,
        }

    return None


def _cold_cartesian_attack(host: str, bln_list: List[str],
                           scanner_list: List[str], node_list: List[str],
                           delay: float = 0.3, inter_tier_pause: float = 5.0,
                           force_full: bool = False
                           ) -> Optional[Tuple[str, str, str, bytes]]:
    tiers = [
        ("Tier 1 (high-probability)", 2, 3, 3),
        ("Tier 2 (plausible)",        4, 4, 5),
    ]
    if force_full:
        tiers.append(("Tier 3 (exhaustive)",
                      len(scanner_list), len(bln_list), len(node_list)))

    attempted: set = set()
    attempt_num = 0

    for idx, (label, s_n, b_n, n_n) in enumerate(tiers):
        scanners = scanner_list[:s_n]
        blns = bln_list[:b_n]
        nodes = node_list[:n_n]
        new_combos = [(sc, bl, nd)
                      for sc in scanners for bl in blns for nd in nodes
                      if (sc, bl, nd) not in attempted]
        for combo in new_combos:
            attempted.add(combo)
        if not new_combos:
            continue

        print(f"\n  {label}: {len(new_combos)} combo(s)")
        if idx > 0:
            print(f"  Pausing {inter_tier_pause}s (lockout safety)...")
            time.sleep(inter_tier_pause)

        for sc, bl, nd in new_combos:
            attempt_num += 1
            print(f"  [{attempt_num:3d}] scanner={sc!r:<25} BLN={bl!r:<12} "
                  f"node={nd!r:<8}", end=" ", flush=True)
            result = _cold_probe(host, bl, sc, nd)
            v = result['verdict']
            if v == 'got_response':
                print(f"ACCEPTED ({len(result['data'])} bytes)")
                return (sc, bl, nd, result['data'])
            elif v == 'rejected_rst':
                print(f"RST (wrong BLN)")
            elif v == 'rejected_silent':
                print(f"silent (wrong scanner/node)")
            elif v == 'port_closed':
                print(f"port closed — aborting")
                return None
            else:
                print(f"{v}")
            time.sleep(delay)
    return None


def _cold_parse_node_name(data: bytes, our_scanner: str,
                          our_bln: str) -> Optional[str]:
    if len(data) < 14 or data[12] != 0x01:
        return None
    payload = data[13:]
    strings, cur = [], bytearray()
    for b in payload:
        if b == 0:
            if cur:
                try:
                    sv = cur.decode('ascii')
                    if sv.isprintable():
                        strings.append(sv)
                except UnicodeDecodeError:
                    pass
                cur = bytearray()
            if len(strings) >= 4:
                break
        else:
            cur.append(b)
    excluded = {our_scanner, our_bln}
    for sv in strings:
        if sv not in excluded and (sv.upper().startswith('NODE')
                                   or sv.upper().startswith('PXC')):
            return sv
    return strings[3] if len(strings) >= 4 else None


def cold_discover_site(ranges: Optional[List[str]] = None,
                       pxc_ips: Optional[List[str]] = None,
                       site_hint: Optional[str] = None,
                       bacnet_duration: int = 30,
                       bacnet_interface: str = '0.0.0.0',
                       skip_bacnet: bool = False,
                       force_full: bool = False,
                       delay: float = 0.3,
                       verbose: bool = False) -> Optional[Dict]:
    """Discover BLN name, scanner name, and at least one node name on a site
    where nothing is preconfigured. Returns a dict suitable for site.json,
    or None on failure."""
    print(f"\n{'═' * 70}")
    print(f"  COLD-SITE DISCOVERY")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 70}")

    discoveries: Dict[str, dict] = {}
    inferred_prefixes: List[str] = []
    siemens_ips_from_bacnet: List[str] = []

    # Phase 1: BACnet recon
    if not skip_bacnet and not pxc_ips:
        discoveries = _cold_passive_bacnet(
            duration=bacnet_duration, interface=bacnet_interface,
            verbose=verbose)
        if discoveries:
            print(f"\n  BACnet devices:")
            for ip in sorted(discoveries, key=lambda s: tuple(int(o) for o in s.split('.'))):
                mac = _cold_get_arp_mac(ip)
                vendor = _cold_classify_vendor(mac)
                is_siemens = mac and mac[:8].lower() in _COLD_SIEMENS_OUIS
                marker = " ← SIEMENS" if is_siemens else ""
                print(f"    {ip:<16} {mac or '(unknown)':<20} "
                      f"{vendor:<32} pkts={discoveries[ip]['packet_count']}{marker}")
                if is_siemens:
                    siemens_ips_from_bacnet.append(ip)
        inferred_prefixes = _cold_infer_prefix(discoveries)
        if inferred_prefixes:
            print(f"\n  Inferred site prefix(es): {', '.join(inferred_prefixes)}")

    if site_hint:
        prefixes = [site_hint]
        print(f"\n  Using user-provided site hint: {site_hint}")
    elif inferred_prefixes:
        prefixes = inferred_prefixes
    else:
        prefixes = []
        print(f"\n  No site prefix — falling back to universal candidates")

    # Phase 2: PXC discovery and fingerprint
    if pxc_ips:
        candidate_ips = list(pxc_ips)
        print(f"\n  Using {len(candidate_ips)} provided PXC IP(s)")
    else:
        from ipaddress import ip_network
        scan_ips: set = set()
        for r in (ranges or []):
            try:
                net = ip_network(r, strict=False)
                hosts = net.hosts() if net.prefixlen <= 30 else net
                scan_ips.update(str(ip) for ip in hosts)
            except ValueError:
                scan_ips.add(r)
        scan_ips.update(siemens_ips_from_bacnet)
        if not scan_ips:
            print(f"\n  No scan targets. Provide --range or --pxc.")
            return None
        print(f"\n  PHASE 2: Port scan {len(scan_ips)} IPs for TCP/{P2_PORT}")
        candidate_ips = port_scan_p2(sorted(scan_ips,
                                     key=lambda s: tuple(int(o) for o in s.split('.'))))

    if not candidate_ips:
        print(f"  No hosts with TCP/{P2_PORT} open.")
        return None

    print(f"\n  PHASE 2b: Fingerprint {len(candidate_ips)} host(s)")
    siemens_pxcs = []
    for host in candidate_ips:
        r = _cold_probe(host, "DIAGTEST", "DIAGPROBE|5033", "node1")
        if r['verdict'] == 'rejected_rst':
            print(f"    {host:<16} SIEMENS PXC (rejected wrong BLN)")
            siemens_pxcs.append(host)
        elif r['verdict'] == 'rejected_silent':
            print(f"    {host:<16} Siemens-maybe (silent drop)")
            siemens_pxcs.append(host)
        elif r['verdict'] == 'got_response':
            print(f"    {host:<16} RESPONDED to junk — not-Siemens")
        else:
            print(f"    {host:<16} {r['verdict']}")

    if not siemens_pxcs:
        print(f"\n  No Siemens PXCs identified.")
        return None

    # Phase 2c: 0x0050 StatusQuery bootstrap (APOGEE_P2_SPEC.md §22.6).
    # One round-trip per panel returns BLN + node name + supervisor identity
    # — far cheaper than the Cartesian attack in Phase 3. Strict-peer-list
    # panels reject this the same way they reject IdentifyBlock; we fall
    # through to Phase 3 if every host silent-drops.
    print(f"\n  PHASE 2c: 0x0050 status-query bootstrap (§22.6)")
    bootstrap_scanner = (f"{prefixes[0].upper()}DCC-SVR|5033" if prefixes
                         else "P2SCAN-LAP|5033")
    bootstrap_hits: Dict[str, Dict[str, Any]] = {}
    for host in siemens_pxcs:
        print(f"    {host:<16} scanner={bootstrap_scanner!r}", end=" ", flush=True)
        result = _cold_status_query_probe(host, bootstrap_scanner)
        if result:
            print(f"BLN={result['bln']!r} node={result['panel']!r}")
            bootstrap_hits[host] = result
        else:
            print("(no response)")
        time.sleep(delay)

    if bootstrap_hits:
        # Short-circuit Phase 3 — we have everything we need.
        first_ip = next(iter(bootstrap_hits))
        first = bootstrap_hits[first_ip]
        bln = first['bln']
        scanner = first['supervisor']
        print(f"\n{'═' * 70}")
        print(f"  COLD DISCOVERY COMPLETE (via 0x0050 bootstrap)")
        print(f"{'═' * 70}")
        print(f"  BLN name:     {bln}")
        print(f"  Scanner name: {scanner}")
        print(f"  Hosts with bootstrap hits: {len(bootstrap_hits)}/{len(siemens_pxcs)}")

        site_name = prefixes[0].upper() if prefixes else "SITE"
        site_config = {
            "p2_network": bln,
            "p2_site": site_name,
            "scanner_name": scanner,
            "known_nodes": {},
        }
        for ip in siemens_pxcs:
            if ip in bootstrap_hits:
                site_config["known_nodes"][bootstrap_hits[ip]['panel']] = ip
            else:
                site_config["known_nodes"][f"UNKNOWN_{ip.split('.')[-1]}"] = ip

        print(f"\n  site.json content:")
        for line in json.dumps(site_config, indent=2).splitlines():
            print(f"  {line}")
        return site_config

    # Phase 3: Cartesian attack (fallback when bootstrap got zero hits)
    bln_candidates = _cold_generate_bln_candidates(prefixes)
    scanner_candidates = _cold_generate_scanner_candidates(prefixes)
    node_candidates = _cold_generate_node_candidates()
    target = siemens_pxcs[0]
    print(f"\n  PHASE 3: Cartesian attack against {target}")
    hit = _cold_cartesian_attack(target, bln_candidates, scanner_candidates,
                                  node_candidates, delay=delay,
                                  force_full=force_full)

    if not hit:
        print(f"\n{'═' * 70}")
        print(f"  INCOMPLETE — no working combo found")
        print(f"{'═' * 70}")
        print(f"  Siemens PXCs: {', '.join(siemens_pxcs)}")
        if not force_full:
            print(f"  Retry with --force-full for exhaustive sweep.")
        return None

    scanner, bln, node_guess, data = hit
    extracted = _cold_parse_node_name(data, scanner, bln)
    node = extracted or node_guess

    print(f"\n{'═' * 70}")
    print(f"  COLD DISCOVERY COMPLETE")
    print(f"{'═' * 70}")
    print(f"  BLN name:     {bln}")
    print(f"  Scanner name: {scanner}")
    print(f"  Node (for {target}): {node}")
    print(f"  All Siemens PXCs: {', '.join(siemens_pxcs)}")

    site_name = prefixes[0].upper() if prefixes else "SITE"
    site_config = {
        "p2_network": bln,
        "p2_site": site_name,
        "scanner_name": scanner,
        "known_nodes": {},
    }
    for ip in siemens_pxcs:
        label = node if ip == target else f"UNKNOWN_{ip.split('.')[-1]}"
        site_config["known_nodes"][label] = ip

    print(f"\n  site.json content:")
    for line in json.dumps(site_config, indent=2).splitlines():
        print(f"  {line}")
    return site_config


# ─────────────────────────────────────────────────────────────────────────────
# Polished one-shot cold discovery (added 2026-05-20)
#
# Higher-level wrapper around cold_discover_site() that adds:
#   * Automatic local-subnet detection — no --range required
#   * Per-panel name backfill via 0x0050 follow-up against any host that the
#     first-pass bootstrap left labeled UNKNOWN_<last-octet>
#   * Atomic site.json write that preserves arbitrary extra keys (e.g.
#     known_builds, _comment) the caller may have already written
#
# Entry point for users: run with no arguments — `polished_cold_discover()`.
# This is also what the GUI's "Cold Discover (Auto)" menu item drives.
# ─────────────────────────────────────────────────────────────────────────────

# Common telnet service port. Insight/Desigo CC's "Field Network" view
# surfaces the same telnet-availability indicator per panel — knowing
# which PXCs have telnet open is the difference between "I can SSH/telnet
# in and run `nodeNametable Remove` cleanup" vs "I have to drive to the
# physical panel for service-port access."
TELNET_PORT = 23


def probe_telnet_status(host: str, timeout: float = 1.0,
                        read_banner: bool = True
                        ) -> Dict[str, Any]:
    """Probe TCP/23 reachability on `host`. Pure-stdlib, read-only.

    A successful TCP connect on port 23 means the panel's telnet service
    is accepting connections — the panel can be reached for operator
    cleanup tooling like `Fieldpanels dElete <name>` and
    `nodeNametable Remove <name>`. A refused / timed-out connect means
    telnet is disabled (operator policy), blocked by an upstream ACL,
    or the panel is unreachable at the IP layer.

    Args:
        host: Panel IPv4 address.
        timeout: Per-attempt connect timeout in seconds.
        read_banner: If True, attempt to read a short banner (up to
            128 bytes / 1 s) for diagnostic display. Most PXC telnet
            stacks send a banner immediately; some don't until input
            arrives.

    Returns:
        {
            'host':           '<ip>',
            'open':           True / False,
            'banner':         '<first-line>' or None,
            'error':          str  (only set on connect failure)
        }
    """
    out: Dict[str, Any] = {'host': host, 'open': False,
                           'banner': None, 'error': None}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # Use connect() (raising form) instead of connect_ex() — the
        # latter returns WSAEWOULDBLOCK (10035) on Windows when the
        # timeout elapses with the syscall still pending, which is
        # indistinguishable from a real WOULDBLOCK in non-blocking mode
        # and bites every cross-platform probe written this way. The
        # raising form gives us socket.timeout for "no answer in time"
        # and ConnectionRefusedError for "panel said no", which is what
        # we want to distinguish.
        sock.connect((host, TELNET_PORT))
        out['open'] = True
        if read_banner:
            try:
                sock.settimeout(1.0)
                data = sock.recv(128)
                if data:
                    # First printable line, stripped. Telnet IAC bytes
                    # (0xFF…) appear early in some banners — keep only
                    # printable ASCII so the GUI doesn't try to render
                    # control sequences.
                    line = data.split(b'\n', 1)[0]
                    text = ''.join(chr(b) for b in line
                                   if 32 <= b < 127).strip()
                    if text:
                        out['banner'] = text
            except (socket.timeout, OSError):
                pass  # banner is optional diagnostic
        return out
    except socket.timeout:
        out['error'] = 'timeout'
        return out
    except ConnectionRefusedError:
        out['error'] = 'connection refused'
        return out
    except OSError as e:
        # Unreachable host, no route, DNS failure, etc.
        out['error'] = f"{type(e).__name__}: {e}"
        return out
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_telnet_status_bulk(hosts: List[str], timeout: float = 1.0,
                             verbose: bool = False
                             ) -> Dict[str, Dict[str, Any]]:
    """Run `probe_telnet_status` against many hosts sequentially.

    Returns: {host: probe_result_dict}. Sequential (not parallel) on
    purpose — same rationale as the cold-discovery delays, plus most
    fleets are <50 panels and a 1-s-per-host probe finishes in under
    a minute. If you need parallel, wrap this with a ThreadPoolExecutor.
    """
    results: Dict[str, Dict[str, Any]] = {}
    for i, host in enumerate(hosts, start=1):
        if verbose:
            print(f"    [{i}/{len(hosts)}] {host:<16} telnet probe...",
                  end=" ", flush=True)
        r = probe_telnet_status(host, timeout=timeout)
        results[host] = r
        if verbose:
            if r['open']:
                banner = f" banner={r['banner']!r}" if r['banner'] else ""
                print(f"OPEN{banner}")
            else:
                print(f"closed ({r['error']})")
    return results


def get_primary_local_ipv4() -> Optional[str]:
    """Return the IPv4 of the interface used to reach the default gateway.

    Pure stdlib. The connect-to-UDP trick doesn't actually send a packet —
    it just causes the kernel to populate the local source address as if
    it were going to. Works on Windows / Linux / macOS without admin or
    external deps. Returns None on failure.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 8.8.8.8 is the canonical "any reachable internet host" placeholder.
        # Anything routable works; nothing is actually transmitted.
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def auto_detect_local_subnets(assume_prefix: int = 24) -> List[str]:
    """Detect local IPv4 subnet(s) the machine is connected to (CIDR list).

    Pure stdlib. Returns a list of CIDR strings, primary interface first.
    Loopback and link-local are excluded. `assume_prefix` is the netmask
    bits to apply (default /24 — overwhelmingly the most common LAN size
    for BAS subnets). Multihomed machines (e.g. a separate NIC into a BAS
    VLAN) may surface additional candidates via socket.getaddrinfo on the
    hostname, though that path is OS-dependent and not all platforms list
    every interface.

    Example return values:
        ['192.168.1.0/24']
        ['192.0.2.0/24', '192.168.1.0/24']
        []   # neither path worked — caller should prompt for a range
    """
    from ipaddress import IPv4Address, IPv4Network

    found: List[str] = []
    seen_networks: set = set()

    # Primary: gateway-route trick. Most reliable single answer.
    primary = get_primary_local_ipv4()
    if primary:
        try:
            net = IPv4Network(f"{primary}/{assume_prefix}", strict=False)
            if not net.is_loopback and not net.is_link_local:
                cidr = str(net)
                if cidr not in seen_networks:
                    found.append(cidr)
                    seen_networks.add(cidr)
        except ValueError:
            pass

    # Secondary: enumerate any other IPv4 the OS reports for the hostname.
    # Catches some multihomed setups (a BAS VLAN bound to a second NIC)
    # but is OS-dependent — Windows may surface every adapter, Linux
    # often only surfaces /etc/hosts entries.
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip_str = info[4][0]
            try:
                ip = IPv4Address(ip_str)
                if ip.is_loopback or ip.is_link_local:
                    continue
                net = IPv4Network(f"{ip_str}/{assume_prefix}", strict=False)
                cidr = str(net)
                if cidr not in seen_networks:
                    found.append(cidr)
                    seen_networks.add(cidr)
            except ValueError:
                continue
    except (socket.gaierror, OSError):
        pass

    return found


def _atomic_write_site_json(path: str, site_config: Dict) -> bool:
    """Write `site_config` (canonical site.json keys) to `path` atomically,
    preserving any extra keys (e.g. known_builds, _comment) that already
    exist in the file. Returns True on success, False on OSError.

    Atomic semantics: writes to `path + '.tmp'` then os.replace's it in,
    so a crash mid-write doesn't corrupt the existing file.
    """
    try:
        existing: Dict = {}
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
                if not isinstance(existing, dict):
                    existing = {}
            except (json.JSONDecodeError, OSError):
                existing = {}
        # Overlay the discovery-side keys; everything else is preserved.
        # node_telnet is the per-node telnet-port-open map produced by
        # the polished cold-discovery flow (Phase 5). Backward compat:
        # absence is treated as "unknown" by the GUI, not "closed."
        for key in ('p2_network', 'p2_site', 'scanner_name',
                    'known_nodes', 'node_telnet'):
            if key in site_config:
                existing[key] = site_config[key]
        tmp_path = path + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2)
            f.write('\n')
        os.replace(tmp_path, path)
        return True
    except OSError:
        return False


def passive_sniff_bln(duration: int = 10,
                      interface: Optional[str] = None,
                      verbose: bool = True) -> Optional[str]:
    """Passively sniff TCP/5033 for `duration` seconds and extract the BLN
    name from the first valid P2 frame seen.

    Pure-passive: no packets sent, no NODE NAME TABLE writes, no impact on
    the BAS network. Works because the Desigo CC supervisor pushes to each
    PXC constantly (heartbeats, COVs, replication) and every routing header
    on TCP/5033 carries the BLN in slot 1.

    Requires `tshark` (Wireshark CLI) to be installed and on PATH or in one
    of the standard Windows install locations.

    Does NOT depend on or modify the module-level P2_NETWORK global — this
    is a fresh capture+parse that returns ONLY what was actually seen in
    the window. (The older `sniff_network_name` has a side-effect bug where
    it returns the pre-existing P2_NETWORK without actually sniffing if the
    global was previously set by a config load. This function avoids that.)

    Returns the BLN string on success, None on:
      - tshark not installed
      - no TCP/5033 traffic in the capture window
      - parse failure
      - PermissionError (need admin / wireshark group on Linux)
    """
    import subprocess
    import shutil
    import tempfile

    # Find tshark
    tshark = shutil.which('tshark')
    if not tshark:
        for path in [r'C:\Program Files\Wireshark\tshark.exe',
                     r'C:\Program Files (x86)\Wireshark\tshark.exe']:
            if os.path.exists(path):
                tshark = path
                break
    if not tshark:
        if verbose:
            print(f"  tshark not found — cannot passive-sniff BLN.")
        return None

    if verbose:
        print(f"  Passive BLN sniff: tshark capturing TCP/5033 for "
              f"{duration} s (no probes sent)...")

    # NamedTemporaryFile(delete=False) creates the file atomically and avoids
    # the TOCTOU race in the deprecated tempfile.mktemp(). Cleanup in finally.
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcapng') as _tf:
        tmpfile = _tf.name
    try:
        cmd = [tshark, '-a', f'duration:{duration}',
               '-f', 'tcp port 5033', '-w', tmpfile, '-q']
        if interface:
            cmd.extend(['-i', interface])
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 10)
        except subprocess.TimeoutExpired:
            if verbose:
                print(f"  Sniff timed out.")
            return None
        except (FileNotFoundError, PermissionError) as e:
            if verbose:
                print(f"  Sniff failed: {e}")
            return None

        if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) < 100:
            if verbose:
                print(f"  No TCP/5033 traffic captured in {duration} s "
                      f"window (supervisor may be quiet, or interface may "
                      f"not see BAS traffic).")
            return None

        # Parse the pcapng — find the first valid P2 frame and extract
        # slot 1. The P2 header signature is bytes 4-7 = 0x00000033 (DATA)
        # or 0x00000034 (HEARTBEAT). We scan for these byte patterns, then
        # validate the surrounding frame structure before trusting the
        # slot extraction.
        with open(tmpfile, 'rb') as f:
            raw = f.read()
        bln = _parse_first_bln_from_capture(raw)
        if bln:
            if verbose:
                print(f"  BLN learned from wire: {bln!r}")
            return bln
        if verbose:
            print(f"  TCP/5033 traffic captured but no parseable P2 frame "
                  f"found.")
        return None
    finally:
        try:
            os.unlink(tmpfile)
        except OSError:
            pass


def _parse_first_bln_from_capture(raw: bytes) -> Optional[str]:
    """Scan raw pcapng bytes for the first valid P2 frame and return slot 1
    (the BLN name). Returns None if no valid frame is found.

    Validation rules (must all pass):
      * msg_type field (bytes 4-7 of candidate frame) is 0x00000033 (DATA)
        or 0x00000034 (HEARTBEAT)
      * total_len field (bytes 0-3) is in [20, 16384]
      * direction byte (byte 12) is 0x00 (request) or 0x01 (response)
      * slot 1 ends with a null within 32 bytes of frame start + 13
      * slot 1 is 3-32 printable ASCII characters with no pipe `|`
        (pipe is the supervisor-port separator like `<SITE>DCC-SVR|5033`,
        which never appears in the BLN field)
    """
    for sig in (b'\x00\x00\x00\x33', b'\x00\x00\x00\x34'):
        i = 0
        while True:
            i = raw.find(sig, i)
            if i < 0:
                break
            # Candidate P2 frame starts 4 bytes before the msg_type match
            if i < 4:
                i += 1
                continue
            frame_start = i - 4
            if frame_start + 13 > len(raw):
                break
            total_len = int.from_bytes(
                raw[frame_start:frame_start + 4], 'big')
            if not (20 <= total_len <= 16384):
                i += 1
                continue
            dir_byte = raw[frame_start + 12]
            if dir_byte not in (0x00, 0x01):
                i += 1
                continue
            # Slot 1 starts at offset 13 and is null-terminated
            end = raw.find(
                b'\x00',
                frame_start + 13,
                min(frame_start + 13 + 32, len(raw))
            )
            if end < 0 or end == frame_start + 13:
                i += 1
                continue
            slot1 = raw[frame_start + 13:end]
            if not (3 <= len(slot1) <= 32):
                i += 1
                continue
            try:
                bln = slot1.decode('ascii')
            except UnicodeDecodeError:
                i += 1
                continue
            if not bln.isprintable() or '|' in bln:
                i += 1
                continue
            return bln
    return None


def _discover_bln_via_probe(host: str,
                            bln_candidates: List[str],
                            node_candidate: str = 'node1',
                            delay: float = 0.3,
                            stop_event: Optional[Any] = None,
                            verbose: bool = True) -> Optional[str]:
    """Active BLN discovery against a single PXC. Iterates BLN candidates
    using the 15-character placeholder in slot 4 + a single node-name
    candidate in slot 2.

    Per-candidate behavior:
      * Wrong BLN → panel TCP-RSTs (verdict='rejected_rst'). NO write to
        NODE NAME TABLE — the RST happens before any application-layer
        processing.
      * Right BLN + wrong node → silent drop (verdict='rejected_silent').
        ONE write to NODE NAME TABLE on this panel under the placeholder
        name. We've still learned the BLN.
      * Right BLN + right node → response (verdict='got_response'). One
        write. We've learned both BLN and a valid node name.

    Worst-case NODE NAME TABLE footprint: 1 entry on this single panel
    under WILDCARD_15CHAR_PLACEHOLDER. Propagates BLN-wide via replication ⇒
    1 BLN-wide entry total. Cleanup is a single `nodeNametable Remove
    RANDOM15CHARSXY` afterward.

    Returns the first BLN that produced a non-RST response, or None if
    every candidate TCP-RST'd. Honors stop_event between candidates.
    """
    for bln in bln_candidates:
        if stop_event is not None and stop_event.is_set():
            if verbose:
                print(f"      Cancelled during BLN discovery.")
            return None
        if verbose:
            print(f"      BLN guess: {bln!r:<14}", end=" ", flush=True)
        r = _cold_probe(host, bln, WILDCARD_15CHAR_PLACEHOLDER, node_candidate,
                        timeout=2.0)
        v = r['verdict']
        if v in ('got_response', 'rejected_silent'):
            if verbose:
                print(f"HIT (verdict={v}) — BLN learned: {bln!r}")
            return bln
        if v == 'port_closed':
            if verbose:
                print(f"port closed (cannot continue against this host)")
            return None
        if verbose:
            print(f"miss ({v})")
        time.sleep(delay)
    return None


def _default_bln_candidate_list(site_hint: Optional[str] = None) -> List[str]:
    """Build a BLN candidate list. If `site_hint` is provided (e.g. 'ACME'),
    generates targeted candidates from the existing pattern list. Always
    falls back to generic common-pattern candidates so the list is useful
    even with no hint.
    """
    candidates: List[str] = []
    if site_hint:
        candidates.extend(_cold_generate_bln_candidates([site_hint]))
    else:
        # No hint — provide common patterns most BAS sites land on.
        # APOGEEBLN, SIEMENS, MAIN are vendor-default-ish; BLN1, BLN, NET,
        # P2NET cover short common names.
        candidates.extend(["APOGEEBLN", "APOGEE", "SIEMENS", "MAIN",
                           "MAINBLN", "BLN1", "BLN", "DEFAULTBLN",
                           "DEFAULT", "NETWORK", "P2NET", "NET"])
    # Dedup preserving order
    seen, out = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def auto_detect_site_prefixes(duration: int = 15,
                              interface: str = '0.0.0.0',
                              verbose: bool = True) -> List[str]:
    """Passive BACnet/IP recon — listen UDP/47808 for `duration` seconds,
    capture I-Am / Who-Is and unsolicited COV broadcasts, extract device-
    name strings, infer the dominant site prefix(es) from naming patterns.

    Pure-passive: binds to UDP/47808 read-only, sends nothing, makes no
    NODE NAME TABLE writes anywhere. Works on switched networks because
    BACnet/IP broadcasts are visible to every host on the subnet (unlike
    unicast TCP traffic which the laptop can't see without a SPAN port).

    Why this works for BLN discovery: in a typical Siemens BAS deployment
    the Desigo CC supervisor speaks BACnet/IP heavily, and its device-
    object name typically encodes the site prefix (e.g. 'ACMEBAS-Server',
    'MAINBacnetGW', etc.). Third-party BACnet controllers on the same
    network often use the same prefix as their object names. The
    `_cold_infer_prefix` heuristic identifies the dominant prefix across
    all observed device names and returns it (e.g. 'ACME').

    Returns a list of inferred prefixes ordered by confidence (most-likely
    first). Empty list if no BACnet traffic or no parseable prefix
    discovered. Caller can feed the result to `_default_bln_candidate_list`
    or pass each prefix as `site_hint` to `cold_discover_minimal`.

    Args:
        duration: seconds to listen (default 15 — usually enough for a
            handful of I-Am broadcasts + unsolicited COVs on an active
            BAS network).
        interface: bind address (default 0.0.0.0 = all interfaces).
        verbose: print progress to stdout.

    Returns:
        e.g. ['ACME']  or  ['MAIN', 'BAS']  or  []
    """
    discoveries = _cold_passive_bacnet(
        duration=duration, interface=interface, verbose=verbose)
    if not discoveries:
        if verbose:
            print(f"  No BACnet/IP devices observed in {duration} s.")
        return []
    prefixes = _cold_infer_prefix(discoveries)
    if verbose:
        if prefixes:
            print(f"  Inferred site prefix(es): {prefixes}")
        else:
            print(f"  Captured {len(discoveries)} BACnet device(s) but "
                  f"could not infer a dominant site prefix from device "
                  f"names.")
    return prefixes


def cold_discover_minimal(network: str,
                          bln: Optional[str] = None,
                          node_candidates: Optional[List[str]] = None,
                          site_hint: Optional[str] = None,
                          probe_delay: float = 0.5,
                          port_scan_timeout: float = 0.5,
                          stop_event: Optional[Any] = None,
                          verbose: bool = True) -> Optional[Dict]:
    """Cold discovery via the 2-packet primitive: IdentifyBlock handshake
    (Packet A) + 0x0050 StatusQuery chain (Packet B).

    Requires the BLN as input — the handshake's bouncer TCP-RSTs any
    wrong-BLN frame so we cannot discover the BLN by probing. Supply
    `bln` from prior site.json, from Desigo CC's Field Networks view,
    or from a passive sniff of supervisor-port (TCP/5033) traffic.

    Per-panel NODE NAME TABLE footprint:
      ONE entry under WILDCARD_15CHAR_PLACEHOLDER (= "RANDOM15CHARSXY") mapped
      to this machine's IP. Even though the function tries multiple
      `node_candidates` per panel and most are silent-dropped, every
      probe uses the SAME slot-4 placeholder, so the silent-drop writes
      are idempotent. Across all panels: ONE BLN-wide entry under
      RANDOM15CHARSXY (BLN replication collapses identical name+IP
      writes).

      Cleanup: telnet into any one panel and run
          nodeNametable Remove RANDOM15CHARSXY
      The removal propagates BLN-wide within ~2 minutes.

    Returns the standard site_config dict on success, None on failure.

    Args:
        network: CIDR to scan (e.g. '192.168.1.0/24').
        bln: REQUIRED. The BLN (Building Local Network) name. Wrong
            BLN → TCP RST from every panel, function returns None.
        node_candidates: Optional list of lowercase node-name candidates
            to try in slot 2. Defaults to ['node1', 'node2', ...,
            'node20'] which covers most field-panel naming conventions.
            For sites with unusual naming, provide an explicit list.
        probe_delay: Inter-probe delay (seconds). Default 0.5.
        port_scan_timeout: Per-host TCP/5033 connect timeout.
        verbose: Print progress to stdout.

    What this function does NOT do (intentionally):
      * BACnet recon
      * Siemens fingerprint probe (wrong-BLN write attempt — TCP RSTs
        anyway so no write happens, but no value either)
      * Multiple scanner identities (Cartesian dictionary attack) —
        every probe uses the same placeholder, so writes are idempotent
      * Fallback to anything that would write DIFFERENT names
    """
    from ipaddress import ip_network
    if node_candidates is None:
        node_candidates = [f'node{i}' for i in range(1, 21)]

    if verbose:
        print(f"\n{'═' * 70}")
        print(f"  COLD-DISCOVER (MINIMAL) — 2-packet primitive")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  network={network}  bln={bln!r}")
        print(f"  scanner identity (slot 4) = {WILDCARD_15CHAR_PLACEHOLDER!r}")
        print(f"  node candidates: {len(node_candidates)} "
              f"({node_candidates[0]}..{node_candidates[-1]})")
        print(f"{'═' * 70}")

    # Phase A — Port scan TCP/5033
    try:
        net = ip_network(network, strict=False)
        scan_ips = sorted(
            (str(ip) for ip in (net.hosts() if net.prefixlen <= 30 else net)),
            key=lambda s: tuple(int(o) for o in s.split('.'))
        )
    except ValueError as e:
        if verbose:
            print(f"  ERROR: invalid network {network!r}: {e}")
        return None

    if verbose:
        print(f"\n  Phase A: port scan {len(scan_ips)} IPs on TCP/{P2_PORT}")
    pxcs = port_scan_p2(scan_ips, timeout=port_scan_timeout)
    if not pxcs:
        if verbose:
            print(f"  No hosts with TCP/{P2_PORT} open.")
        return None
    if verbose:
        print(f"  Found {len(pxcs)} PXC(s) on TCP/{P2_PORT}: {', '.join(pxcs)}")

    # Cooperative cancel: if the caller passed a threading.Event-like
    # object (anything with `is_set()`), poll it between phases and at
    # every per-host iteration. The GUI's Cancel button sets this; the
    # function returns whatever results have been collected so far.
    def _cancelled() -> bool:
        try:
            return stop_event is not None and stop_event.is_set()
        except Exception:
            return False

    if _cancelled():
        if verbose:
            print(f"  Cancelled after port scan.")
        return None

    # Phase A.5 — BLN auto-discovery (only when caller didn't supply one).
    #
    # On a switched BAS network the laptop can't see unicast supervisor↔
    # panel TCP traffic, so passive TCP/5033 sniff is unreliable. But
    # BACnet/IP UDP broadcasts ARE visible to every host on the subnet,
    # and the Desigo CC supervisor's BACnet device-object name typically
    # encodes the site prefix (e.g. 'ACMEBAS-Server'). So:
    #
    #   1. If site_hint not provided: 15 s passive BACnet recon →
    #      infer prefix(es) from device names (pure-passive, no writes)
    #   2. Generate BLN candidates from prefix(es)
    #   3. Active BLN-guess attack against first PXC with the placeholder
    #      identity in slot 4: wrong-BLN frames TCP-RST (no writes),
    #      correct BLN gets accepted/silent-dropped (1 placeholder
    #      write under WILDCARD_15CHAR_PLACEHOLDER)
    #
    # Worst case for the full chain: 1 NODE NAME TABLE entry on a single
    # panel under the placeholder, replicates BLN-wide as 1 entry total.
    if not bln:
        # Step 1: if no site_hint, try BACnet recon first
        inferred_prefixes: List[str] = []
        if not site_hint:
            if verbose:
                print(f"\n  Phase A.4: passive BACnet recon (15 s) — no "
                      f"site hint provided, listening for supervisor "
                      f"device-name broadcasts to infer prefix")
            inferred_prefixes = auto_detect_site_prefixes(
                duration=15, verbose=verbose)
            if inferred_prefixes:
                site_hint = inferred_prefixes[0]
                if verbose:
                    print(f"  Using inferred prefix as site_hint: "
                          f"{site_hint!r}")
                    if len(inferred_prefixes) > 1:
                        print(f"  (Other candidates if first fails: "
                              f"{inferred_prefixes[1:]})")

        if _cancelled():
            if verbose:
                print(f"  Cancelled after BACnet recon.")
            return None

        # Step 2: build candidate list (uses site_hint if we have one,
        # else generic patterns)
        bln_candidates = _default_bln_candidate_list(site_hint)
        # If multiple prefixes were inferred, generate candidates from
        # each and append. First-prefix candidates already at the front.
        if not site_hint or len(inferred_prefixes) > 1:
            for extra in inferred_prefixes[1:]:
                extra_candidates = _default_bln_candidate_list(extra)
                for c in extra_candidates:
                    if c not in bln_candidates:
                        bln_candidates.append(c)

        if verbose:
            print(f"\n  Phase A.5: active BLN auto-discovery against "
                  f"{pxcs[0]} (wrong-BLN guesses TCP-RST without writes)")
            print(f"    Trying {len(bln_candidates)} candidates...")
        bln = _discover_bln_via_probe(
            pxcs[0], bln_candidates,
            node_candidate='node1',
            delay=probe_delay,
            stop_event=stop_event,
            verbose=verbose,
        )
        if not bln:
            if verbose:
                print(f"\n  No BLN candidate accepted. Options:")
                print(f"    1. Provide bln='<YOUR-BLN>' explicitly")
                print(f"    2. Provide site_hint='<PREFIX>' (e.g. 'ACME' → "
                      f"tries ACMEEBLN, ACMEBLN, ACME_BLN, etc.)")
                print(f"    3. Look up BLN in Desigo CC > System Browser >")
                print(f"       Field Networks")
            return None
        if verbose:
            print(f"\n  BLN auto-discovered: {bln!r}")

    if _cancelled():
        if verbose:
            print(f"  Cancelled after BLN discovery.")
        return None

    # Phase B — Per-PXC 2-packet primitive (Identify handshake + 0x0050
    # chain). cold_discover_v0_14() iterates bln_candidates × node_
    # candidates until one accepts. We pass [single_node] at a time so
    # we can honour cancel between candidates (otherwise a per-host
    # call could run the full 20-candidate list before returning).
    if verbose:
        print(f"\n  Phase B: Identify handshake + 0x0050 chain per PXC "
              f"(2-packet primitive — single placeholder, idempotent writes)")

    discoveries: Dict[str, Dict[str, Any]] = {}
    supervisor_name: Optional[str] = None
    for host in pxcs:
        if _cancelled():
            if verbose:
                print(f"\n  Cancelled before probing {host}.")
            break
        if verbose:
            print(f"\n    {host}:")
        d = None
        for node in node_candidates:
            if _cancelled():
                if verbose:
                    print(f"      Cancelled mid-host {host}.")
                break
            r = cold_discover_v0_14(
                host=host,
                bln_candidates=[bln],
                node_candidates=[node],
                delay=probe_delay,
                verbose=False,  # quiet inner loop; we print per-host above
                chain_status_query=True,
            )
            if r:
                d = r
                if verbose:
                    print(f"      HIT node={node!r} "
                          f"bln={r.get('bln')!r} "
                          f"panel={r.get('panel_name')!r}")
                break
        if d:
            discoveries[host] = d
            if supervisor_name is None and d.get('supervisor_name_with_port'):
                supervisor_name = d['supervisor_name_with_port']
        elif verbose and not _cancelled():
            print(f"      no candidate accepted "
                  f"(tried {len(node_candidates)} node names)")

    if not discoveries:
        if verbose:
            print(f"\n  No panels responded to the Identify handshake. "
                  f"Verify the BLN name ({bln!r}) is correct — wrong BLN "
                  f"causes every panel to TCP-RST without responding.")
        return None

    # Phase C — Synthesize site_config from per-panel discoveries.
    # All panels on the same BLN return the same BLN + supervisor; use
    # the first one as canonical.
    first = discoveries[next(iter(discoveries))]
    canonical_bln = first.get('bln', bln)
    canonical_site = first.get('site') or re.sub(
        r'(_?E?BLN|NET)$', '', canonical_bln) or canonical_bln
    canonical_sup = (supervisor_name
                     or first.get('supervisor_name_with_port')
                     or first.get('supervisor_name')
                     or _GENERIC_SCANNER_NAME)

    site_config: Dict[str, Any] = {
        'p2_network': canonical_bln,
        'p2_site': canonical_site,
        'scanner_name': canonical_sup,
        'known_nodes': {},
    }
    for ip, d in discoveries.items():
        panel_name = d.get('panel_name')
        if panel_name:
            site_config['known_nodes'][panel_name] = ip

    if verbose:
        print(f"\n{'═' * 70}")
        print(f"  COLD-DISCOVER COMPLETE")
        print(f"{'═' * 70}")
        print(f"  BLN:              {canonical_bln}")
        print(f"  Site (guessed):   {canonical_site}")
        print(f"  Supervisor name:  {canonical_sup}")
        print(f"  Panels resolved:  {len(site_config['known_nodes'])}/"
              f"{len(pxcs)}")
        print()
        print(f"  Cleanup (one entry to remove BLN-wide):")
        print(f"    telnet into any panel, then:")
        print(f"      Fieldpanels dElete {WILDCARD_15CHAR_PLACEHOLDER}")
        print(f"      nodeNametable Remove {WILDCARD_15CHAR_PLACEHOLDER}")
        print(f"    (Fieldpanels dElete FIRST, then nodeNametable Remove —")
        print(f"     reverse order strands the field-panel entry)")
    return site_config


def polished_cold_discover(network: Optional[str] = None,
                           bln: Optional[str] = None,
                           node_candidates: Optional[List[str]] = None,
                           site_hint: Optional[str] = None,
                           save_to: Optional[str] = None,
                           bacnet_duration: int = 15,  # unused — kept for API stability
                           skip_bacnet: bool = False,   # unused — kept for API stability
                           probe_delay: float = 0.5,
                           backfill_unknown_names: bool = True,
                           probe_telnet: bool = True,
                           telnet_timeout: float = 1.0,
                           scanner_identity: Optional[str] = None,  # unused; placeholder is used
                           stop_event: Optional[Any] = None,
                           verbose: bool = True) -> Optional[Dict]:
    """One-shot cold discovery — no arguments needed for the common case.

    Auto-detects the local subnet, port-scans it for PXCs on TCP/5033,
    sends ONE 0x0050 StatusQuery per discovered PXC with a single
    consistent scanner identity (the minimum-write primitive), then
    probes each discovered panel's telnet availability and optionally
    writes the result to site.json.

    Per-panel NODE NAME TABLE footprint: ONE entry under the
    `scanner_identity` label, mapped to this machine's IP. Because
    every probe uses the same name and the same source IP, the
    panels' BLN-wide replication mechanism collapses these into a
    single BLN-wide entry. Cleanup is one `nodeNametable Remove
    <scanner_identity>` on any panel — propagates BLN-wide within
    ~2 minutes.

    Returns the discovered site_config dict on success, None on failure.
    The dict has the standard site.json shape:
        {
            'p2_network':  '<BLN>',
            'p2_site':     '<SITE>',
            'scanner_name':'<SUPERVISOR>|5033',
            'known_nodes': {'NODE1': '192.0.2.1', ...},
            'node_telnet': {'NODE1': True, ...},
        }

    Args:
        network: CIDR to scan (e.g. '192.168.1.0/24'). None = auto-detect
            the primary local /24.
        save_to: Path to write site.json on success (atomic, preserves
            arbitrary extra keys). None = dry-run, just return the dict.
        bacnet_duration: IGNORED. Kept for API stability. The polished
            flow does not run BACnet recon — it's not needed for the
            minimum-write primitive and adds ~15 s wall-clock.
        skip_bacnet: IGNORED. Kept for API stability.
        probe_delay: Inter-probe delay during the 0x0050 phase.
        backfill_unknown_names: IGNORED. Kept for API stability.
            cold_discover_minimal only records panels that resolved
            cleanly, so there are no UNKNOWN_* placeholders to backfill.
        probe_telnet: If True, probe TCP/23 on each discovered panel
            and record reachability in the returned dict's 'node_telnet'
            key (mapping node_name -> bool). Default True.
        telnet_timeout: Per-host telnet TCP-connect timeout (seconds).
        scanner_identity: The slot-4 value used for every 0x0050 probe.
            Default 'P2SCAN-LAP|5033' — clean, identifiable label so the
            NODE NAME TABLE cleanup-target is obvious.
        verbose: Print progress to stdout.

    What this function does NOT do (intentionally):
      * BACnet recon
      * Wrong-BLN Siemens fingerprint probe
      * Cartesian dictionary attack of (BLN, scanner, node) candidates
      * Anything that would dump multiple distinct names into the
        panels' NODE NAME TABLEs

    If the 0x0050 bootstrap returns zero hits, the function returns
    None and prints a hint about supplying a BLN sniff or running
    `cold_discover_site()` directly (which has the dictionary fallback)
    if the user genuinely wants it.

    Example:
        >>> result = polished_cold_discover(save_to='site.json')
        >>> result['p2_network']
        'MYSITEBLN'
        >>> result['known_nodes']
        {'NODE1': '192.0.2.1', 'NODE2': '192.0.2.2', ...}
        >>> result['node_telnet']
        {'NODE1': True, 'NODE2': False}
    """
    # Auto-detect network if caller didn't pin one down.
    if network is None:
        subnets = auto_detect_local_subnets()
        if not subnets:
            if verbose:
                print("  ERROR: could not auto-detect a local subnet.")
                print("         Provide network='X.X.X.X/24' explicitly.")
            return None
        network = subnets[0]
        if verbose:
            print(f"  Auto-detected local network: {network}")
            if len(subnets) > 1:
                print(f"  (Additional candidates not scanned: "
                      f"{', '.join(subnets[1:])})")

    # If BLN not provided, cold_discover_minimal will auto-discover via
    # active BLN-guess attack against the first port-scanned PXC (Phase
    # A.5 — wrong-BLN candidates TCP-RST without writing, only the
    # correct one accepts and writes 1 placeholder entry). This works
    # without a SPAN port. If you DO have a SPAN port, you can call
    # passive_sniff_bln() first and pass the result as `bln=` here to
    # skip the active probe phase entirely.

    # Strict minimum-write path: per-PXC IdentifyBlock handshake (with
    # the configured BLN + small node-name candidate list) chained to
    # 0x0050 StatusQuery for the supervisor name. cold_discover_minimal
    # uses a single placeholder scanner identity across all probes so
    # silent-drop writes are idempotent — total NODE NAME TABLE
    # footprint is ONE BLN-wide entry under WILDCARD_15CHAR_PLACEHOLDER.
    site_config = cold_discover_minimal(
        network=network,
        bln=bln,
        node_candidates=node_candidates,
        site_hint=site_hint,
        probe_delay=probe_delay,
        stop_event=stop_event,
        verbose=verbose,
    )
    if not site_config:
        return None
    # `backfill_unknown_names` is now a no-op — cold_discover_minimal
    # only records panels that the IdentifyBlock handshake actually
    # resolved, so there are no UNKNOWN_* placeholders to backfill.
    # Argument `scanner_identity` is also unused — the 15-character
    # placeholder is always used (matches the wildcard accept length).
    # Both kept in the signature for API stability.
    _ = backfill_unknown_names
    _ = scanner_identity

    # Phase 5 — Telnet-availability probe.
    # Same indicator Insight/Desigo CC's "Field Network" view surfaces:
    # a green dot means the panel's telnet service is accepting
    # connections (operator can run `Fieldpanels dElete` / `nodeNametable
    # Remove` from there), a gray/red dot means it isn't. Recorded into
    # site.json as 'node_telnet': {node_name: bool} so the GUI can render
    # the status without re-probing on every reload.
    if probe_telnet:
        nodes_for_probe = site_config.get('known_nodes', {})
        if nodes_for_probe:
            if verbose:
                print(f"\n  PHASE 5: Telnet (TCP/23) availability probe "
                      f"({len(nodes_for_probe)} panel(s))")
            telnet_status: Dict[str, bool] = {}
            for name, ip in sorted(nodes_for_probe.items()):
                if verbose:
                    print(f"    {name:<14} {ip:<16}", end=" ",
                          flush=True)
                r = probe_telnet_status(ip, timeout=telnet_timeout,
                                        read_banner=False)
                telnet_status[name] = bool(r['open'])
                if verbose:
                    print("OPEN" if r['open']
                          else f"closed ({r['error']})")
            site_config['node_telnet'] = telnet_status
            if verbose:
                open_count = sum(1 for v in telnet_status.values() if v)
                print(f"    Telnet open on {open_count}/"
                      f"{len(telnet_status)} panel(s)")

    # Optional: persist to site.json.
    if save_to:
        ok = _atomic_write_site_json(save_to, site_config)
        if verbose:
            if ok:
                print(f"\n  Saved site config to {save_to}")
            else:
                print(f"\n  WARNING: could not write {save_to} "
                      f"(returning discovery anyway)")

    return site_config


# ═══════════════════════════════════════════════════════════════════════════════
# Passive push-channel listener (default TCP 5033, configurable) + related parsers
# ═══════════════════════════════════════════════════════════════════════════════
#
# A P2 ALN is a full-mesh of TCP/5033 by default. PXCs also open an outbound
# TCP session to the supervisor port at boot (default 5033 per Siemens 149-1006;
# some sites run that listener on a non-5033 port — e.g. a Datamate Advanced
# co-install bumps it off 5033 — so the port is configurable) and push
# asynchronous notifications there:
#   0x0274 — COV notification (value changed on a TEC-device point)
#   0x0240 — BLN-sourced virtual-point value report (device name is literally "NONE")
#   0x4634 — BLN routing-table announcement
# Supervisor's only job on the push channel is to ACK with a 39-byte routing-header reply.
# Running this listener alongside a real DCC server will work, but expect the
# real DCC to retry to panels that get confused by duplicate ACKs — use only on
# a dedicated IP or during a maintenance window for passive reconnaissance.

def _parse_routing_header(payload: bytes) -> Optional[Tuple[bytes, List[str], bytes]]:
    """Split P2 routing header off the payload.

    Returns ``(direction_byte, [name1, name2, name3, name4], remaining_body)``
    or None on parse failure. The four names are:
        [BLN, destination, BLN, source]  for DATA/HEARTBEAT messages
        [BLN, sender, BLN, recipient]    for CONNECT/ANNOUNCE (order reversed)
    Caller needs to know the message type to interpret which slot is which.
    """
    if not payload:
        return None
    dir_byte = payload[0:1]
    names = []
    i = 1
    for _ in range(4):
        j = payload.find(b'\x00', i)
        if j < 0:
            return None
        try:
            names.append(payload[i:j].decode('ascii'))
        except UnicodeDecodeError:
            return None
        i = j + 1
    return dir_byte, names, payload[i:]


def _extract_tlv_strings(data: bytes) -> List[str]:
    """Pull out TLV strings (tag=0x01, u16 BE length, ASCII value)."""
    out = []
    i = 0
    while i + 3 <= len(data):
        if data[i] == 0x01:
            L = struct.unpack('>H', data[i + 1:i + 3])[0]
            if 0 < L < 1024 and i + 3 + L <= len(data):
                val = data[i + 3:i + 3 + L]
                if all(32 <= b < 127 for b in val):
                    try:
                        out.append(val.decode('ascii'))
                        i += 3 + L
                        continue
                    except UnicodeDecodeError:
                        pass
        i += 1
    return out


_COV_COND_FIELDS = ('point_priority', 'control_status', 'out_of_service', 'failed',
                    'proof_on', 'operator_disabled', 'program_disabled',
                    'commanded_to_alarm', 'alarm_state', 'alarm_priority')


def _read_tlv(body: bytes, off: int):
    """Read a string TLV `01 00 <len> <bytes>` at off. Returns (text, next_off) or
    (None, off) if there is no TLV there."""
    if off + 3 > len(body) or body[off] != 0x01 or body[off + 1] != 0x00:
        return None, off
    ln = body[off + 2]
    if off + 3 + ln > len(body):
        return None, off
    return body[off + 3:off + 3 + ln].decode('latin-1', 'replace'), off + 3 + ln


def _consume_scope_tag(body: bytes, off: int) -> int:
    """Skip an optional scope tag `01 00 <len> <SCOPE> <priority:1> <3F FF FF FF>`."""
    s_, no = _read_tlv(body, off)
    if s_ in ('SYST', 'NONE', 'CC') and no + 5 <= len(body) \
            and body[no + 1:no + 5] == b'\x3f\xff\xff\xff':
        return no + 5
    return off


def _decode_event_timestamp(body: bytes, off: int):
    """Decode an 8-byte event timestamp [yr-1900][mo][day][DOW 1=Mon][hr][min][sec][cs].
    Returns (iso_string, next_off) or (None, off) if the 8 bytes are not a plausible
    timestamp (year>=2000 guard rejects the null/sentinel and most non-timestamp bytes)."""
    if off + 8 > len(body):
        return None, off
    yr, mo, dy, dw, hh, mm, ss, cs = body[off:off + 8]
    if not (100 <= yr <= 199 and 1 <= mo <= 12 and 1 <= dy <= 31 and 1 <= dw <= 7
            and hh <= 23 and mm <= 59 and ss <= 59 and cs <= 99):
        return None, off
    dow = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')[dw - 1]
    return (f"{1900 + yr:04d}-{mo:02d}-{dy:02d} {dow} "
            f"{hh:02d}:{mm:02d}:{ss:02d}.{cs:02d}"), off + 8


def parse_cov_notification(body: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 0x0274 COV_ANNUNCIATE body (payload INCLUDING the 2-byte opcode).

    Wire layout (matches the p2.lua dissector): `02 74` + `count` (u16), then per point:
        name_space (u16, observed 00 00)
        name TLV   (01 00 LL <name>)
        suffix TLV (01 00 LL <suffix>, empty for top-level points)
        value      (f32 BE)
        condition  (10 bytes: point_priority, control_status, out_of_service, failed,
                    proof_on, operator_disabled, program_disabled, commanded_to_alarm,
                    alarm_state, alarm_priority)

    Returns {device, point, value, direction='cov', condition, points}. `points` is the
    full list of decoded points; device/point/value reflect the first point for
    backward-compatible display.
    """
    if len(body) < 6 or body[0:2] != b'\x02\x74':
        return None
    count = struct.unpack('>H', body[2:4])[0]
    off = 4
    points: List[Dict[str, Any]] = []
    for _ in range(min(count, 256)):           # cap guards against a bogus count
        if off + 2 > len(body):
            break
        ns = struct.unpack('>H', body[off:off + 2])[0]
        off += 2
        name, off = _read_tlv(body, off)
        if name is None:
            break
        suffix, no = _read_tlv(body, off)
        if suffix is None:
            suffix = ''
        else:
            off = no
        value = None
        if off + 4 <= len(body):
            try:
                value = struct.unpack('>f', body[off:off + 4])[0]
            except struct.error:
                pass
            off += 4
        cond: Dict[str, int] = {}
        if off + 10 <= len(body):
            for i, fn in enumerate(_COV_COND_FIELDS):
                cond[fn] = body[off + i]
            off += 10
        points.append({'name': name, 'suffix': suffix, 'value': value,
                       'name_space': ns, 'condition': cond})
    if not points:
        return None
    p0 = points[0]
    return {'device': p0['name'], 'point': p0['suffix'] or p0['name'],
            'value': p0['value'], 'direction': 'cov',
            'condition': p0['condition'], 'points': points}


def parse_alarm_report(body: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 0x0508 ALARM_PRINT push body (payload INCLUDING the 2-byte opcode).

    Best-effort, matching the dissector's alarm decode: an optional scope tag, then the
    point and descriptor name TLVs, a value block (`3F FF FF Fx` quality sentinel +
    sub-type + f32), and up to three 8-byte event timestamps (event / reference /
    last-normal). Returns {point, descriptor, value, timestamps, direction='alarm'}.
    """
    if len(body) < 4 or body[0:2] != b'\x05\x08':
        return None
    off = _consume_scope_tag(body, 2)
    n = len(body)
    names: List[str] = []
    value = None
    timestamps: List[str] = []
    while off < n:
        b0 = body[off]
        tlv, no = _read_tlv(body, off)
        if tlv is not None:
            if tlv and tlv not in ('SYST', 'NONE', 'CC'):
                names.append(tlv)
            off = no
            continue
        if value is None and off + 11 <= n and b0 == 0x3F \
                and body[off + 1] == 0xFF and body[off + 2] == 0xFF:
            off += 7                            # quality sentinel (4) + group (3)
            try:
                value = struct.unpack('>f', body[off:off + 4])[0]
            except struct.error:
                pass
            off += 4
            continue
        if len(timestamps) < 3:
            ts, no = _decode_event_timestamp(body, off)
            if ts is not None:
                timestamps.append(ts)
                off = no
                continue
        off += 1
    return {'point': names[0] if names else None,
            'descriptor': names[-1] if len(names) > 1 else None,
            'value': value, 'timestamps': timestamps, 'direction': 'alarm'}


def parse_write_with_quality(body: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 0x0240 WriteWithQuality body.

    APOGEE_P2_SPEC.md §12.6 documents two distinct wire shapes selected
    by the scope byte at offset +7 (the separator after the scope-tag
    TLV). The scanner only generates reads, so this is parse-only for
    observed traffic.

    NONE-scope form (PXC -> supervisor on push channel — BLN-virtual report):
        02 40
        01 00 04 "NONE"
        00                          separator (0x00 = NONE scope)
        3F FF FF FF                 wildcard / quality-default sentinel
        00 00
        01 00 LL <point>
        01 00 00 00 00 01 00 00 01 00 00   marker pattern
        XX XX XX XX                 f32 BE value
        00                          trailer

    SYST-scope form (supervisor -> PXC on 5033 — fails with 0x0E15;
    supervisor retries via 0x4222 BulkPropertyWrite):
        02 40
        01 00 04 "SYST"
        23                          separator (0x23 = SYST scope)
        ... addressing fields ...
        ... value bytes ...
        00                          quality byte

    Returns {'device', 'point', 'value', 'scope'} where scope is 'NONE'
    or 'SYST'. SYST-form value extraction is best-effort because the
    addressing-field layout varies by request flavor.
    """
    if len(body) < 20 or body[0:2] != b'\x02\x40':
        return None
    strings = _extract_tlv_strings(body)
    if len(strings) < 2:
        return None
    device, point = strings[0], strings[1]

    # Disambiguate by the scope-separator byte at body[9]: 0x00 = NONE,
    # 0x23 = SYST. Offset 9 = 2-byte opcode + 3-byte TLV header + 4-byte
    # scope-string value ("NONE"/"SYST").
    scope = 'NONE'
    if len(body) >= 10 and body[9] == 0x23:
        scope = 'SYST'

    # Float-search heuristic — same as before. For NONE the f32 sits
    # in the well-defined post-marker slot; for SYST the layout is
    # less stable across firmware revs and the heuristic catches it.
    value = None
    for i in range(len(body) - 5, max(0, len(body) - 20), -1):
        try:
            v = struct.unpack('>f', body[i:i + 4])[0]
            if -1e9 < v < 1e9 and v == v:
                if abs(v) > 1e-6:
                    value = v
                    break
        except struct.error:
            continue
    if value is None:
        for i in range(max(0, len(body) - 20), len(body) - 3):
            try:
                v = struct.unpack('>f', body[i:i + 4])[0]
                if v == 0.0:
                    value = v
                    break
            except struct.error:
                continue
    return {'device': device, 'point': point, 'value': value, 'scope': scope}


def parse_routing_table(body: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 0x4634 BLN routing-table push.

    Wire format:
        46 34 00 00 00 00 <u16 count?> 00 0E   ~10-byte header
        (01 00 LL <name> 00 00 <u32 BE cost>)+
        00 00 00 00                     terminator

    Per APOGEE_P2_SPEC.md §12.10, the first TLV MUST be `$paneldefault`
    (cost always 12) — it's the internal fallback/default-route anchor.
    A body whose first TLV is not `$paneldefault` is malformed and
    parsers SHOULD reject it rather than continue. Returns None on
    malformed input; {'entries': [...]} on success.
    """
    if len(body) < 10 or body[0:2] != b'\x46\x34':
        return None
    entries = []
    i = 10  # skip 10-byte header; exact structure varies slightly by firmware
    while i + 5 < len(body):
        if body[i] == 0x01:
            L = struct.unpack('>H', body[i + 1:i + 3])[0]
            if 0 < L < 64 and i + 3 + L + 4 <= len(body):
                name_bytes = body[i + 3:i + 3 + L]
                try:
                    name = name_bytes.decode('ascii')
                except UnicodeDecodeError:
                    i += 1
                    continue
                cost = struct.unpack('>I', body[i + 3 + L:i + 3 + L + 4])[0]
                # First-TLV invariant — must be $paneldefault per spec §12.10.
                # Reject malformed frames rather than parse them as topology.
                if not entries and name != '$paneldefault':
                    return None
                entries.append({'name': name, 'cost': cost})
                i += 3 + L + 4
                continue
        i += 1
    # An empty entry list means we never found a TLV at the expected
    # 10-byte offset — also malformed.
    if not entries:
        return None
    return {'entries': entries}


def _build_ack_response(msg_type: int, seq: int, req_payload: bytes,
                       supervisor_name: str, site_name: str) -> bytes:
    """Build a 39-byte routing-header-only ACK (direction byte 0x01).

    The ACK echoes the request's seq and swaps the destination/source names.
    """
    rh = _parse_routing_header(req_payload)
    if rh is None:
        return b''
    _, names, _ = rh
    # Slot 0=BLN, slot 1=dest(=us), slot 2=BLN, slot 3=src(=panel)
    # For response: slot 1 becomes the panel (was src), slot 3 becomes us (was dest)
    bln = names[0]
    panel = names[3]
    us = names[1]
    body = (
        b'\x01' +
        bln.encode('ascii') + b'\x00' +
        panel.encode('ascii') + b'\x00' +
        bln.encode('ascii') + b'\x00' +
        us.encode('ascii') + b'\x00'
    )
    return struct.pack('>III', 12 + len(body), msg_type, seq) + body


def listen_for_push_notifications(port: int = 5033, duration: Optional[int] = None,
                                  output_format: str = 'table',
                                  output_file: Optional[str] = None,
                                  ack_enabled: bool = True,
                                  verbose: bool = False,
                                  bind_address: str = '0.0.0.0') -> None:  # noqa: S104 - explicit back-compat default, warned at runtime, overridable via --listen-bind
    """Bind to TCP port (default 5033 — Siemens-canonical supervisor port
    per white paper 149-1006) and passively collect PXC push notifications.

    Decodes:
      - 0x0274 COV notifications → device/point/value events
      - 0x0240 WriteWithQuality  → BLN virtual updates (device="NONE")
      - 0x4634 Routing tables    → BLN topology dumps

    Sends routing-header-only ACKs back to keep panels happy. Handles multiple
    concurrent inbound connections via threading.

    Args:
        port: TCP port to bind (default 5033 — Siemens-canonical supervisor port per white paper 149-1006; override if your site uses a different port, e.g. 5034 when Datamate Advanced occupies 5033).
        duration: Seconds to listen; None runs until KeyboardInterrupt.
        output_format: 'table' (human) or 'json' (one object per line, JSONL).
        output_file: Path to write events; stdout if None.
        ack_enabled: If False, don't ACK — useful if a real DCC is also listening
                     and you want to avoid confusing panels. Panels may drop the
                     connection after ~30s without ACKs.
        verbose: Print connection/disconnection events.
    """
    import threading
    import json as _json
    from concurrent.futures import ThreadPoolExecutor

    # Cap concurrent peer connections so a misconfigured supervisor or a
    # flood from a hostile peer can't spawn unbounded threads. 32 is well
    # above any realistic site (a typical BLN has 5–20 panels feeding the
    # supervisor on the configured supervisor port); excess connections queue in the executor and
    # are handled as workers free up.
    MAX_PEER_THREADS = 32

    out_lock = threading.Lock()
    out_stream = open(output_file, 'a', buffering=1) if output_file else None
    # In-flight connection counter, guarded by its own lock. A single-element
    # list so the nested handler can mutate it without a `nonlocal`.
    _inflight = [0]
    _inflight_lock = threading.Lock()

    def emit(event: Dict):
        line = (_json.dumps(event) if output_format == 'json'
                else _format_event_line(event))
        with out_lock:
            if out_stream:
                out_stream.write(line + '\n')
            else:
                print(line)

    def handle_connection(csock: socket.socket, peer: Tuple[str, int]):
        if verbose:
            print(f"  [{port}] connection from {peer[0]}:{peer[1]}")
        buf = b''
        try:
            csock.settimeout(45)  # heartbeat interval is ~30s; give 45s before we give up
            while True:
                chunk = csock.recv(8192)
                if not chunk:
                    break
                buf += chunk
                # Parse as many complete P2 messages as we have
                while len(buf) >= 12:
                    total_len, msg_type, seq = struct.unpack('>III', buf[:12])
                    if total_len < 12 or total_len > 65536:
                        # Framing desync — discard and move on
                        buf = b''
                        break
                    if len(buf) < total_len:
                        break   # wait for more bytes
                    raw_payload = buf[12:total_len]
                    buf = buf[total_len:]

                    event = {
                        'peer': f'{peer[0]}:{peer[1]}',
                        'msg_type': f'0x{msg_type:02X}',
                        'seq': seq,
                    }

                    rh = _parse_routing_header(raw_payload)
                    if rh:
                        dir_byte, names, body = rh
                        event['src_node'] = names[3] if len(names) > 3 else '?'
                        event['bln'] = names[0] if names else '?'

                        if msg_type in (P2Message.TYPE_DATA, P2Message.TYPE_HEARTBEAT) and body:
                            # The 2-byte opcode is meaningful ONLY in dir==0x00 frames
                            # (requests / panel pushes). In a 0x01 success response the
                            # post-routing bytes are payload, and in a 0x05 error they are
                            # a 2-byte status code — reading an "opcode" off either would
                            # fabricate opcodes. (Verified against raw captures.)
                            if dir_byte == 0x00:
                                op_bytes = body[:2]
                                op = struct.unpack('>H', op_bytes)[0] if len(op_bytes) == 2 else None
                                event['opcode'] = f'0x{op:04X}' if op is not None else '?'
                                if op_bytes == P2Message.MARKER_VALUE_PUSH:
                                    parsed = parse_cov_notification(body)
                                    if parsed:
                                        event['event'] = 'cov'
                                        event.update(parsed)
                                elif op_bytes == P2Message.MARKER_WRITE_QUAL:
                                    parsed = parse_write_with_quality(body)
                                    if parsed:
                                        event['event'] = 'virtual_push'
                                        event.update(parsed)
                                elif op_bytes == P2Message.MARKER_ROUTING_TBL:
                                    parsed = parse_routing_table(body)
                                    if parsed:
                                        event['event'] = 'routing_table'
                                        event['peer_count'] = len(parsed.get('entries', []))
                                        event['entries'] = parsed['entries']
                                elif op_bytes == P2Message.MARKER_ALARM_REPORT:
                                    parsed = parse_alarm_report(body)
                                    if parsed:
                                        event['event'] = 'alarm'
                                        event.update(parsed)
                                else:
                                    event['event'] = 'unknown_opcode'
                            elif dir_byte == 0x05:
                                # Panel error response — 2-byte status code, not an opcode.
                                err = struct.unpack('>H', body[:2])[0] if len(body) >= 2 else None
                                event['event'] = 'error_response'
                                if err is not None:
                                    event['error'] = _P2_STATUS_ERRORS.get(err, f'0x{err:04X}')
                            else:
                                # dir_byte == 0x01 — success response; payload, no opcode.
                                event['event'] = 'response'
                        elif msg_type in (P2Message.TYPE_CONNECT, P2Message.TYPE_ANNOUNCE):
                            event['event'] = '2ndch_legacy' if msg_type == P2Message.TYPE_CONNECT else '2ndch_modern'

                    if 'event' in event:
                        emit(event)

                    # Send ACK
                    if ack_enabled:
                        ack = _build_ack_response(msg_type, seq, raw_payload,
                                                   SCANNER_NAME, P2_SITE)
                        if ack:
                            try:
                                csock.sendall(ack)
                            except socket.error:
                                pass
        except (socket.timeout, socket.error, ConnectionResetError):
            pass
        finally:
            try:
                csock.close()
            except Exception:
                pass
            with _inflight_lock:
                _inflight[0] -= 1
            if verbose:
                print(f"  [{port}] disconnect {peer[0]}:{peer[1]}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind to the operator-selected interface. Defaults to 0.0.0.0 for
    # backward compatibility, but a scanner host is routinely dual-homed
    # (corporate LAN on one NIC, automation VLAN on the other) and this
    # listener answers P2 — it should not be reachable from the corporate
    # side just because that is where the default route lives. Pass the
    # automation-VLAN address via --listen-bind to pin it.
    try:
        srv.bind((bind_address, port))
    except OSError as exc:
        srv.close()
        raise ScannerInputError(
            f"cannot bind {bind_address}:{port} — {exc}") from exc
    srv.listen(32)
    srv.settimeout(1.0)

    print(f"  Listening on {bind_address}:{port} for P2 push notifications...")
    if bind_address == '0.0.0.0':  # noqa: S104 - comparison, not a bind
        print("  [WARN] bound to all interfaces; use --listen-bind <ip> to "
              "restrict to the automation VLAN")
    print(f"  Scanner identity: {SCANNER_NAME}  |  BLN: {P2_NETWORK or '(not set)'}")
    print(f"  {'Press Ctrl+C to stop' if duration is None else f'Running for {duration}s'}")
    print()

    start = time.time()
    executor = ThreadPoolExecutor(max_workers=MAX_PEER_THREADS,
                                   thread_name_prefix='p2-listener')
    try:
        while True:
            if duration is not None and (time.time() - start) >= duration:
                break
            try:
                csock, peer = srv.accept()
            except socket.timeout:
                continue
            # Bound in-flight connections. accept() will happily keep taking
            # sockets past MAX_PEER_THREADS; without this they queue inside the
            # executor holding an open fd each, so a flood exhausts the process
            # fd limit even though only 32 are ever serviced. Refusing past the
            # cap is the honest signal to the peer.
            with _inflight_lock:
                at_capacity = _inflight[0] >= MAX_PEER_THREADS
            if at_capacity:
                if verbose:
                    print(f"  [{port}] refusing {peer[0]}:{peer[1]} — "
                          f"{MAX_PEER_THREADS} connections already in flight")
                try:
                    csock.close()
                except OSError:
                    pass
                continue
            with _inflight_lock:
                _inflight[0] += 1
            executor.submit(handle_connection, csock, peer)
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        srv.close()
        # Don't wait — handle_connection's per-peer reads have their own
        # timeouts and any in-flight work will exit on its own. wait=False
        # gives Ctrl-C its expected snappy behavior.
        executor.shutdown(wait=False)
        if out_stream:
            out_stream.close()


def _format_event_line(event: Dict) -> str:
    """One-line human-readable rendering of a push event."""
    ts = time.strftime('%H:%M:%S')
    src = event.get('src_node', '?')
    ev = event.get('event', 'unknown')
    if ev == 'cov':
        return (f"{ts}  COV    {src:<12}  {event.get('device', ''):<14}  "
                f"{event.get('point', ''):<20}  "
                f"{event.get('value', '?'):>10}")
    if ev == 'virtual_push':
        return (f"{ts}  VIRT   {src:<12}  {'(panel)':<14}  "
                f"{event.get('point', ''):<20}  "
                f"{event.get('value', '?'):>10}")
    if ev == 'routing_table':
        names = [e['name'] for e in event.get('entries', [])]
        return (f"{ts}  ROUTE  {src:<12}  peers={event.get('peer_count', 0)}  "
                f"[{', '.join(names[:5])}" +
                (f", +{len(names)-5} more]" if len(names) > 5 else ']'))
    if ev == 'alarm':
        tslist = event.get('timestamps') or []
        return (f"{ts}  ALARM  {src:<12}  {event.get('point', ''):<20}  "
                f"val={event.get('value', '?')}  {tslist[0] if tslist else ''}")
    if ev in ('2ndch_legacy', '2ndch_modern'):
        return f"{ts}  2NDCH  {src:<12}  (2nd-channel identity)"
    return (f"{ts}  {ev:<6} {src:<12}  "
            f"msg_type={event.get('msg_type', '?')} op={event.get('opcode', '?')}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Siemens P2 Protocol Scanner — Read TEC/FLN points from PXC controllers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # FIRST TIME — Learn network name from a pcap
  %(prog)s --pcap capture.pcapng --save site.json

  # FIRST TIME — Discover with known network name, save config
  %(prog)s --discover --range 192.0.2.0/24 --network MYBLN --save site.json

  # AFTER SETUP — Use saved config (no --network needed)
  %(prog)s --config site.json --discover --skip-portscan
  %(prog)s --config site.json -n NODE1 -d DEVICE1 --quick

  # OR — Just use --network directly every time
  %(prog)s --discover --range 192.0.2.0/24 --network MYBLN
  %(prog)s -n 192.0.2.50 -d DEVICE1 -p "ROOM TEMP" --network MYBLN

  # Discover + read every point on every device
  %(prog)s --network MYBLN --discover --range 192.0.2.0/24 --read-all

  # Get node firmware info
  %(prog)s --config site.json -n NODE1 --info

  # Discovery with firmware info for each node
  %(prog)s --config site.json --discover --skip-portscan --info

  # Multiple subnets (multiple buildings)
  %(prog)s --discover --range 192.0.2.0/24 --range 198.51.100.0/24 --network MYBLN

  # Decode a pcap file
  %(prog)s --pcap capture.pcapng

  # Show point table for an application
  %(prog)s --show-app 2023

Known nodes: """ + ', '.join(f"{n}={ip}" for n, ip in sorted(KNOWN_NODES.items()))
    )

    parser.add_argument('--node', '-n', help='PXC controller IP or node name')
    parser.add_argument('--device', '-d', help='TEC device name (e.g., DEVICE1)')
    parser.add_argument('--point', '-p', action='append',
                       help='Specific point(s) to read. Accepts point names '
                            '("ROOM TEMP") or slot numbers ("29"). Can be '
                            'passed multiple times.')
    parser.add_argument('--force-slot', action='store_true',
                       help='When reading by slot number, attempt the read '
                            'even if the slot is undefined in the app\'s '
                            'point table (for protocol troubleshooting).')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick scan (key points only)')
    parser.add_argument('--read-delay', type=float, default=0.05, metavar='SECONDS',
                       help='Inter-read delay during a device scan (default: 0.05). '
                            'Raise on slow controllers or where you want to throttle '
                            'probe rate.')
    parser.add_argument('--discover', action='store_true', help='Discover nodes and devices')
    parser.add_argument('--range', '-r', action='append',
                       help='IP range to scan. Formats: 192.0.2.0/24, 192.0.2.1-254, '
                            '192.0.2, or single IP. Can specify multiple times.')
    parser.add_argument('--skip-portscan', action='store_true',
                       help='Skip port scan during discovery (use known nodes)')
    parser.add_argument('--with-panel', action='store_true',
                       help='Also scan panel-level points during discovery')
    parser.add_argument('--read-all', action='store_true',
                       help='Read all points on every discovered device')
    parser.add_argument('--network', help='P2 network name (auto-learned if not set)')
    parser.add_argument('--scanner-name', default=None,
                       help=f'Scanner identity on P2 network (overrides config; default from config or {SCANNER_NAME!r})')
    parser.add_argument('--config', help='Load site config from JSON file')
    parser.add_argument('--save', help='Save learned config to JSON file')
    parser.add_argument('--browse', '-b', action='store_true', help='Browse devices on a node')
    parser.add_argument('--info', action='store_true',
                       help='Show node firmware/revision info during discovery')
    parser.add_argument('--verify', action='store_true',
                       help='Verify which devices are actually online after discovery')
    parser.add_argument('--online', action='store_true',
                       help='Only show devices confirmed online (implies --verify)')
    parser.add_argument('--offline', action='store_true',
                       help='Only show devices confirmed offline (implies --verify)')
    parser.add_argument('--pcap', help='Decode a pcap/pcapng file')
    parser.add_argument('--sniff', nargs='?', const=10, type=int, metavar='SECONDS',
                       help='Live capture P2 traffic to learn network name (requires tshark/Wireshark, default 10s)')
    parser.add_argument('--scan-network', action='store_true', help='Probe all known nodes')
    parser.add_argument('--cold-discover', action='store_true',
                       help='Discover BLN/scanner/node names on an unknown site. '
                            'Uses BACnet recon + Cartesian dictionary attack.')
    parser.add_argument('--auto-discover', action='store_true',
                       help='Polished one-shot cold discovery: auto-detects '
                            'local subnet (if --range omitted), port-scans '
                            'TCP/5033, bootstraps BLN + supervisor + per-panel '
                            'names via 0x0050, then writes site.json (use '
                            '--save PATH; defaults to ./site.json).')
    parser.add_argument('--pxc', action='append', default=[],
                       help='For --cold-discover: known PXC IP (skips port scan)')
    parser.add_argument('--site-hint',
                       help='For --cold-discover: override BACnet-inferred prefix')
    parser.add_argument('--bacnet-duration', type=int, default=30,
                       help='For --cold-discover: BACnet listen seconds (default 30)')
    parser.add_argument('--bacnet-interface', default='0.0.0.0',
                       help='For --cold-discover: bind interface (default 0.0.0.0)')
    parser.add_argument('--skip-bacnet', action='store_true',
                       help='For --cold-discover: skip BACnet phase')
    parser.add_argument('--force-full', action='store_true',
                       help='For --cold-discover: enable exhaustive tier 3 sweep')
    parser.add_argument('--cold-delay', type=float, default=0.3,
                       help='For --cold-discover: delay between probes (default 0.3)')
    parser.add_argument('--debug-reads', action='store_true',
                       help='Print raw hex when a point-read fails to parse '
                            '(helpful for diagnosing unusual response shapes)')
    parser.add_argument('--format', '-f', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--list-nodes', action='store_true', help='List known PXC nodes')
    parser.add_argument('--show-app', type=int, help='Show point table for TEC application')
    parser.add_argument('--port', type=int, default=None, help='P2 ALN port (default: 5033). Override only where the configured P2 port is not 5033 — e.g. a site where a Datamate Advanced co-install bumped the supervisor listener to another port.')

    # ── New capabilities (supervisor-port listener, 0x010C/0x0981/0x0985 opcodes) ──
    parser.add_argument('--listen-push', nargs='?', const=0, type=int, metavar='SECONDS',
                        help='Bind to the supervisor port (default 5033) and collect PXC push notifications '
                             '(COV events, BLN virtual updates, routing tables). '
                             'No SECONDS = run until Ctrl+C.')
    parser.add_argument('--listen-port', type=int, default=5033,
                        help='Port for --listen-push (default: 5033 — Siemens-canonical supervisor port per 149-1006; override if your site uses a different port, e.g. 5034 for DMA-collision installs)')
    parser.add_argument('--listen-bind', metavar='IP', default='0.0.0.0',  # noqa: S104 - documented default; see listen_for_push_notifications
                        help='Local interface address for --listen-push '
                             '(default: 0.0.0.0, all interfaces). Set this to '
                             'the automation-VLAN address on a dual-homed host '
                             'so the listener is not exposed on the corporate side.')
    parser.add_argument('--listen-output', metavar='FILE',
                        help='Write captured events to FILE (default: stdout)')
    parser.add_argument('--listen-no-ack', action='store_true',
                        help="Don't ACK incoming pushes (safer if a real DCC is "
                             "also on the network)")
    parser.add_argument('--walk-points', action='store_true',
                        help='Use opcode 0x0981 to enumerate every point on a '
                             'panel (more complete than 0x0986 FLN enumerate). '
                             'Requires -n NODE.')
    parser.add_argument('--dump-programs', action='store_true',
                        help='Use opcode 0x0985 to read PPCL program source from a '
                             'panel. Requires -n NODE.')
    parser.add_argument('--sysinfo-compact', action='store_true',
                        help='Use opcode 0x010C (newer firmware) for panel info. '
                             'Complements --info which uses legacy 0x0100. '
                             'Requires -n NODE.')

    args = parser.parse_args()

    # Hoist all module-globals this function reassigns into a single
    # declaration at the top — Python disallows `global X` after the same
    # function has already assigned X, so per-branch globals would race.
    global P2_SITE, DEBUG_READS, P2_PORT

    # Load site config if specified (optional — file doesn't need to exist yet)
    if args.config:
        if os.path.exists(args.config):
            load_config(args.config)
        else:
            print(f"  Config file {args.config} not found — will create after discovery")

    # Apply CLI overrides (take precedence over config file)
    if args.network:
        _set_network(args.network)
    if args.scanner_name:
        _set_scanner_name(args.scanner_name)
    if args.debug_reads:
        DEBUG_READS = True
    if args.port is not None:        # CLI --port overrides the 5033 default (and any config)
        P2_PORT = args.port

    # ─── Polished auto-discovery — validated 2-packet primitive.
    #     Auto-detects the local subnet if --range omitted. Requires the
    #     BLN name as input (--network) since wrong-BLN handshakes
    #     TCP-RST without giving us anything to learn from. Prefers an
    #     explicit --network flag, falls back to the BLN loaded from
    #     --config site.json, and errors out if neither is set.
    if args.auto_discover:
        save_target = args.save or os.path.join(os.getcwd(), 'site.json')
        network = args.range[0] if args.range else None
        bln_for_discover = args.network or P2_NETWORK
        if not bln_for_discover or bln_for_discover == 'MYBLN':
            print(f"\n  ERROR: --auto-discover requires the BLN name.")
            print(f"  Pass --network <YOUR-BLN> (or have it set in your "
                  f"loaded site.json's p2_network key).")
            print(f"  Look it up in Desigo CC > System Browser > Field "
                  f"Networks, or sniff a supervisor-port frame.")
            sys.exit(1)
        result = polished_cold_discover(
            network=network,
            bln=bln_for_discover,
            save_to=save_target,
            probe_delay=args.cold_delay,
            verbose=True,
        )
        if not result:
            return
        # Also propagate into in-process globals so any downstream flags
        # in the same invocation (e.g. --auto-discover --read-all) work.
        _set_network(result.get('p2_network', ''))
        _set_scanner_name(result.get('scanner_name', _GENERIC_SCANNER_NAME))
        P2_SITE = result.get('p2_site', '')
        KNOWN_NODES.clear()
        KNOWN_NODES.update(result.get('known_nodes', {}))
        return

    # ─── Cold-site discovery — runs before the network-name check since
    #     the whole point is to discover the network name.
    if args.cold_discover:
        result = cold_discover_site(
            ranges=args.range,
            pxc_ips=args.pxc if args.pxc else None,
            site_hint=args.site_hint,
            bacnet_duration=args.bacnet_duration,
            bacnet_interface=args.bacnet_interface,
            skip_bacnet=args.skip_bacnet,
            force_full=args.force_full,
            delay=args.cold_delay,
            verbose=False,
        )
        if result and args.save:
            # Apply discovered values to globals, then save
            _set_network(result['p2_network'])
            _set_scanner_name(result['scanner_name'])
            P2_SITE = result['p2_site']
            KNOWN_NODES.update(result['known_nodes'])
            save_config(args.save)
            print(f"\n  Saved to {args.save}")
        elif result:
            print(f"\n  To save: rerun with --save site.json")
        return

    # ─── Passive supervisor-port listener — doesn't need the network name; extracts identity
    #     from incoming packets. Runs in its own event loop until Ctrl+C or duration.
    if args.listen_push is not None:
        listen_for_push_notifications(
            port=args.listen_port,
            bind_address=args.listen_bind,
            duration=args.listen_push if args.listen_push > 0 else None,
            output_format='json' if args.format == 'json' else 'table',
            output_file=args.listen_output,
            ack_enabled=not args.listen_no_ack,
            verbose=args.debug_reads,
        )
        return

    # Check if we have what we need for P2 communication
    if not P2_NETWORK and not args.pcap and not args.show_app and not args.list_nodes:
        # Try sniffing if requested or if we need the network name
        if hasattr(args, 'sniff') and args.sniff:
            print(f"\n  Sniffing for P2 traffic...")
            name = sniff_network_name(duration=args.sniff)
            if name:
                print(f"  Learned network: {P2_NETWORK}  |  Site: {P2_SITE}")
                if args.save:
                    save_config(args.save)
                elif args.config:
                    save_config(args.config)
            else:
                print(f"  Could not learn network name from live traffic.")
                print(f"  Make sure this machine can see P2 traffic (same VLAN as BAS).")
                if not (args.range or args.node):
                    return

        # Still no network name?
        if not P2_NETWORK and (args.range or args.node):
            # Try auto-sniff before giving up
            if not (hasattr(args, 'sniff') and args.sniff):
                print(f"\n  Attempting to sniff P2 traffic for network name...")
                name = sniff_network_name(duration=5)
                if name:
                    print(f"  Learned network: {P2_NETWORK}")
                    
            if not P2_NETWORK:
                print(f"\n  ⚠ P2 network name required.")
                print(f"    PXC controllers won't respond without the correct network name.")
                print(f"")
                print(f"    Options:")
                print(f"      --network NAME         Specify it directly (e.g. --network MYBLN)")
                print(f"      --pcap FILE            Learn it from a Wireshark capture")
                print(f"      --sniff [SECONDS]      Live capture to auto-learn (needs tshark)")
                print(f"      --config FILE          Load from a saved config")
                print(f"")
                print(f"    To get the network name:")
                print(f"      1. Check Desigo CC → Field Networks → BLN name")
                print(f"      2. Or: grab a 5-second Wireshark capture on the BAS server,")
                print(f"         then: p2_scanner.py --pcap capture.pcapng")
                print(f"      3. Or: run on the BAS server: p2_scanner.py --sniff 10")
                return

    # List nodes
    if args.list_nodes:
        print(f"\nKnown P2 nodes on {P2_NETWORK}:")
        for name, ip in sorted(KNOWN_NODES.items()):
            print(f"  {name:<10s} {ip}")
        return

    # Show application point table
    if args.show_app:
        pt_table = get_point_table(args.show_app)
        print(f"\nTEC Application {args.show_app} — {len(pt_table)} subpoints:")
        print(f"  {'Addr':>4s}  {'Name':<25s} {'Units':<8s} {'RO':<4s} Description")
        print(f"  {'─' * 4}  {'─' * 25} {'─' * 8} {'─' * 4} {'─' * 30}")
        for addr, (name, desc, units, ro) in pt_table.items():
            ro_str = "RO" if ro else "RW"
            print(f"  {addr:>4d}  {name:<25s} {units:<8s} {ro_str:<4s} {desc}")
        return

    # Decode pcap
    if args.pcap:
        sniff_pcap(args.pcap, args.format)
        if args.save and P2_NETWORK:
            save_config(args.save)
        elif P2_NETWORK and not args.save:
            print(f"\n  Learned network: {P2_NETWORK}  |  Site: {P2_SITE}")
            print(f"  Tip: use --save site.json to save this for future scans")
        return

    # Standalone sniff mode
    if hasattr(args, 'sniff') and args.sniff and not args.discover and not args.node:
        print(f"\n  Sniffing for P2 traffic ({args.sniff} seconds)...")
        name = sniff_network_name(duration=args.sniff)
        if name:
            print(f"\n  Network: {P2_NETWORK}  |  Site: {P2_SITE}")
            if args.save:
                save_config(args.save)
            else:
                print(f"  Use --save site.json to save for future scans")
        else:
            print(f"\n  No P2 traffic detected.")
            print(f"  Make sure this machine is on the BAS VLAN and tshark is installed.")
        return

    # Discovery mode
    if args.discover:
        if args.node and not args.range:
            # Discover devices on a single node
            host = KNOWN_NODES.get(args.node.upper(), args.node)
            node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else None
            if not node_name:
                print(f"  Identifying node at {host}...")
                node_name = discover_node_name(host)
                if not node_name:
                    node_name = "UNKNOWN"
            print(f"\n{'═' * 70}")
            print(f"  DISCOVERING DEVICES ON {node_name} ({host})")

            if args.info:
                info = get_node_info(host, node_name)
                if info:
                    print(f"  Firmware: {info['firmware']}  Model: {info['model']}")
                    if info['extra']:
                        print(f"  Extra: {info['extra']}")

            print(f"{'═' * 70}")
            devs = discover_devices_on_node(host, node_name)
            if args.with_panel:
                print(f"\n  Scanning panel-level points...")
                panel_pts = discover_panel_points(host, node_name)
                for pt in panel_pts:
                    print(f"    {pt['point']:<35s} = {pt['value']:>10.2f} {pt.get('units', '')}")
            print(f"\n  Found {len(devs)} configured devices on {node_name}")

            # Verify online status if requested
            should_verify = args.verify or args.online or args.offline
            if should_verify and devs:
                show_filter = "online" if args.online else ("offline" if args.offline else "all")
                verify_devices(host, node_name, devs, show_filter=show_filter)
            else:
                for d in devs:
                    desc = d.get('description', '')
                    desc_str = f"  ({desc})" if desc else ""
                    app_label = format_app_label(d['application'])
                    print(f"    {d['device']:<20s}  {app_label}{desc_str}")

            # If --read-all, scan every discovered device
            if args.read_all and devs:
                print(f"\n{'═' * 70}")
                print(f"  READING ALL POINTS")
                print(f"{'═' * 70}")
                # If verified, only read online devices
                for d in devs:
                    if should_verify and d.get('status') == 'offline':
                        continue
                    scan_device(host, d['device'], output_format=args.format,
                                inter_read_delay_s=args.read_delay)
        else:
            # Full network discovery
            if not args.range:
                print("ERROR: full-network discovery requires --range. "
                      "Example: --range 192.0.2.0/24 (or comma-separated CIDRs).")
                return 1
            ip_ranges = ','.join(args.range)
            # Determine verify filter
            verify_filter = None
            if args.online:
                verify_filter = "online"
            elif args.offline:
                verify_filter = "offline"
            elif args.verify:
                verify_filter = "all"

            discover_network(
                ip_ranges=ip_ranges,
                scan_ports=not args.skip_portscan,
                scan_devices=True,
                scan_panel=args.with_panel,
                scan_info=args.info,
                verify=verify_filter,
                read_all=args.read_all,
                output_format=args.format,
                read_points=args.point,
                inter_read_delay_s=args.read_delay,
            )
        if args.save and P2_NETWORK:
            save_config(args.save)
        elif args.config and P2_NETWORK:
            save_config(args.config)  # Auto-save back to config file
        return

    # Network scan (legacy, simpler than discover)
    if args.scan_network:
        scan_network(args.quick)
        return

    # Resolve node name to IP
    if args.node:
        host = KNOWN_NODES.get(args.node.upper(), args.node)
    else:
        parser.print_help()
        return

    # ── New opcode-based operations (require -n NODE) ──
    if args.sysinfo_compact:
        node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else args.node
        print(f"\n  Compact sysinfo for {node_name} ({host}) via opcode 0x010C...")
        conn = P2Connection(host)
        if conn.connect(node_name.lower()):
            info = conn.read_system_info_compact(node_name.lower())
            conn.close()
            if info:
                print(f"  Model:      {info['model']}")
                print(f"  Firmware:   {info['firmware']}")
                print(f"  Build date: {info['build_date']}")
                if args.format == 'json':
                    print(json.dumps(info, indent=2))
            else:
                print(f"  No response (panel may not support 0x010C — try --info for legacy 0x0100)")
        else:
            print(f"  Could not connect to {host}")
        return

    if args.walk_points:
        node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else args.node
        print(f"\n  Walking all points on {node_name} ({host}) via opcode 0x0981...")
        conn = P2Connection(host)
        if not conn.connect(node_name.lower()):
            print(f"  Could not connect to {host}")
            return
        points = conn.enumerate_all_points(node_name.lower())
        conn.close()
        print(f"  Found {len(points)} points")
        if args.format == 'json':
            print(json.dumps(points, indent=2, default=str))
        elif args.format == 'csv':
            print("device,point,value,units,description")
            for p in points:
                v = '' if p.get('value') is None else f"{p['value']:g}"
                desc = p.get('description', '').replace(',', ';')
                print(f"{p['device']},{p['point']},{v},{p.get('units', '')},{desc}")
        else:
            print(f"\n  {'Device':<28} {'Point':<22} {'Value':>10} {'Units':<8} {'Description':<24}")
            print(f"  {'-'*28} {'-'*22} {'-'*10} {'-'*8} {'-'*24}")
            for p in points:
                v = '' if p.get('value') is None else f"{p['value']:g}"
                desc = p.get('description', '')
                print(f"  {p['device']:<28.28} {p['point']:<22.22} {v:>10} "
                      f"{p.get('units', ''):<8.8} {desc:<24.24}")
        return

    if args.dump_programs:
        node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else args.node
        print(f"\n  Reading PPCL programs from {node_name} ({host}) via opcode 0x0985...")
        conn = P2Connection(host)
        if not conn.connect(node_name.lower()):
            print(f"  Could not connect to {host}")
            return
        programs = conn.read_programs(node_name.lower())
        conn.close()
        total_lines = sum(p['code'].count('\n') + 1 for p in programs if p.get('code'))
        print(f"  Found {len(programs)} programs, ~{total_lines} total source lines\n")
        if args.format == 'json':
            print(json.dumps(programs, indent=2))
        else:
            for p in programs:
                print(f"  {'='*72}")
                module_str = f" [{p['module']}]" if p.get('module') else ''
                print(f"  PROGRAM: {p['name']}{module_str}")
                print(f"  {'='*72}")
                # Indent the code two spaces for readability; preserve blank lines
                for line in p.get('code', '').split('\n'):
                    print(f"    {line}")
                print()
        return

    # Device scan
    if args.device:
        try:
            results = scan_device(host, args.device, args.point, args.quick,
                                  args.format, force_slot=args.force_slot,
                                  inter_read_delay_s=args.read_delay)
        except ScannerInputError as e:
            print(f"\n  [ERROR] {e}")
            sys.exit(2)
        # Exit 1 if the scan completed but yielded no successful reads —
        # lets cron jobs and parent processes detect "I ran but found nothing"
        # without having to parse stdout.
        if not results:
            sys.exit(1)
    elif args.info:
        # Standalone node info query
        node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else None
        if not node_name:
            node_name = discover_node_name(host)
            if not node_name:
                node_name = "UNKNOWN"
        print(f"\n  Querying {node_name} ({host})...")
        info = get_node_info(host, node_name)
        if info:
            print(f"  Firmware: {info['firmware']}")
            print(f"  Model:    {info['model']}")
            if info['extra']:
                print(f"  Extra:    {info['extra']}")
            if info.get('raw_strings'):
                print(f"  Raw:      {info['raw_strings']}")
        else:
            print(f"  Could not get info (node may not support opcode 0x0100)")
    elif args.browse:
        print(f"  Use --discover instead: p2_scanner.py --node {args.node} --discover")
    else:
        parser.print_help()


# ── Embedded FLN/TEC application point catalog ─────────────────────────
# gzip+base64 of the FLN/TEC point-table database, decoded on demand by
# _load_tecpnts_db(). Lets the scanner run as one self-contained file; an external
# p2_scanner_data/tecpoints.json (or tecpnts.json) found at runtime overrides it.
_TECPOINTS_GZ_B64 = (
    "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"
    "xGTiOnkdPIaeT0ecpp5UgfqpPFm2kusYTf2TpkOw6W1Yfcx3SLY0U2Q227jxE27YiwYft2ZGroHX6/2pIQUuPv5TjKkVoTZFsdpL9YjM2vCgHU"
    "AeoAdYB6KUBdzJfTPELpDifzQBNMfzLsJYTqQj6geYQT/ZWa794wxYVXvzyvnj5EtDpaHa2OVrdZq6vXTOXCRnb1rJHwC6vmclh4VSjt2JGzaf"
    "yu7cQ/Vi3TATZ/MbS3jQf4i6G9YzzAXwztMsloOkLl2B4u/FIwQsEIBSMUjFAwQsEIBSMUjFAwkvrNZHfBSHTgxWSciyJIIRArUnrRVo6jk25X"
    "dvCS2MFodrTd1sR2tRzLf+byVdXVqZDjX3EaT0d3rq7lt0tgVnJ2aupEty3hWVbio1brEgVcHW1AHjfX6XGe3V3RDyk7ouyIsqOLLTt6wn9+UX"
    "bUW8pvpO5k9HqSb4lRixIjSowoMaLEiBIjSowoMaLEiBIjSowoMaLEKCZBR/0O9TvU71C/Q/0O9TvU71C/Q/0O9TvU71C/Q/0O9TvU71C/Q/0O"
    "9TvU71C/Q/0O9TvU75xl/Y7alUc8Ka9sSiieNGdsPhjfyJ2OKSmipIiSIkqKKCmipIiSIkqKKCmipIiSIkqKKCmipOhyS4q8RCVFnz9uRH+/fy"
    "f8T5+E3P5IfH212uwOn+/vxH+J7fr+/UY8rB8+iI/rw4d8So28GqVGlBpRakSpEaVGlBpRakSpEaVGlBqdZ6lRBWt7wgXTVTBeLGeDcrmzeq+g"
    "0Fj2Ar/32h/3jE7F1YVG385UNGPL494KP+R0pWNydfdFgsqi8ALKW305DMpd9qKK6LyriBx1Xn3hvx4GYpol3+oph8njgVMX/hRTuuLpI3wG4E"
    "3xb6q8qPKiyitBfB3by3ErU4dWcqmVtv7M/1fJK4La4jMxWv5JAdo5FaCFfSHsKO+iBI0SNErQKEHLJ0DKxCgTo0yMMrFLKhOLPpQoE6NMjDKx"
    "ksvEHH1NlmNHyZOrj7BpR4TUtVHXRl0bdW3UtVHXdqZ1bdb3cqXyjso7Ku+ovKPyjso7Ku+ovFNX3tUTbuYlwnIy0ak15FZeoje4vhY/1lCPs4"
    "m5uuRu6L9Ot7tXm5I7Su4ouaPkjpI7Su4ouaPkjpI7Su7Y3YvdvTTplqFw7UhnqIsCowg9SyJsaCOsWxJhUxthw44I2T2Luirqqi5496w9u2ex"
    "exbFS+yedeGlS5QGURpkaWnQMKAwyOrCIHVVRj67irHtDvUU1FPYU08BZLcdslvvxM8bYu8rB7GVj/Toz3AItOKGsY16wiphlbDKS2KVjZSssg"
    "WrhFXCKmGVsEpYJawSVgmrhFXCKmGVsEpYJawSVgmrhFXCKmGVsEpYJaySjvB0hId9wj5hn7BP2CfsE/ZpHfukBTQtoJGzdFgG9la9w/IR9lrS"
    "1Nh2elyVrssQaYg0RBoibYxIP0kWxRDp7n73cFjvDmK1337+uBGvhPtyun+4O9ztd+I6/Df9/f6dmkgvgm4aIv2n51w6kQYiA5GTGzm0L9oX7Y"
    "v2rb72tUrTajPlvcDvvfbHPaNf/Dg9nB5O77ed3nBiSYyZrN7XClq9GBx3ZHzlWr0UIAioB9QD6iWBetHYmg9q6etWi4fPBq6G8rmYyIfi2xpt"
    "LtD46Xh/miAKy6sS4Cg5XvyqFCv5rnLh+q6OPQ+uwi+YBBYqPEUmrpdFHMrTfidAliBL2aJs60+kXAaz4yNUvZ2phKa5LAAEY//1UFeeIQdn+d"
    "MX1dshNPwGHYxDD65a6kp/lsanSenTiBRfxmRqtZlakqEkQ38zGeok7Bf1qvfx0/0foi3Tnvd3/yNu19v/fbf7Q5Zqrzb3B9F//+Hw6t3dX3+J"
    "r3fvDh8ecsqLurSOonUUGVtaR9E6imQyyWSSySSTaR11Qa2jFuE6gixpkSUTTpYPVLsbQdWtdgdqFrEcR8V3tpRDuW11kP5iMTa/BGA13Yh58P"
    "xuN9vM0HP1B0/tLYoRA54+wmdpR1NJN3ANuIYmWAniU8+y5XzflrfUxdGfFMilAuxHjJZ/Qn+gP9AfenTRo4seXdXq0bWwasJOly5VKO3Y0a1p"
    "/M7qxN/6LdMBNn8x/LaNB/iL4bdjPMBfDL8yXWg6QuwmdpN2c9a0m3P07eYcO7q5ufoIm3ZESMs+Wvadfcu+tj5CO+5xegrSUzCHt7vdPQWjAy"
    "8m41x8RwqP2dA/XJY0OKxI/0B1edGk25VcRFn0WCJ0aLc1sV0tx/KfuXw7d3UbwB3/igRlTuG5upZfV4FZedupqc2KLeFVoSYr9D1XR+aTS33t"
    "yXGe3V3RD6nIoncm5WKXWy7mJi0XW212B8rFKBejXIxyMcrFKBejXIxyMcrFKBejXIxysWzlYto141UwXixng3INue3Vaw01qYrOVDQlzOPGDb"
    "8SNecrXD5+dsaaugson6PlMCh3XY3yPsr7KO+jvI/yPsr7KO+7jPI+S0r7KOujrK+Qsj5fJsvsKJqjsI/CPgr7KOyjsI/CPgr7KOyjsI/CPgr7"
    "KOyjsI/CPgr7KOyjsI/CPgr7KOyjsI/CPgr7KOyjsI/CPgr7KOyjsK/cwj639kQ4x1T2rfyV6O7327vdezHZbf/Oo3BvtXIcCvdUqZrJRD63wW"
    "iadTWsF9yIa9W9p/k8q7efrx4qH1054HWHN7nwrcwRKh/d8c3CngjVxVlyZI62os6BmGWP0I2NMHtRSPYIvbgIewN/aPxRURdqxcRX5LelujDL"
    "X/5Z7LCiPlVe66qRoALp1h/KVYLbwaLbL/lkddSfdmKymvXKzpirC46iSPL4FunP5hkqcBzdYBvGl8vW0KfrJqf7Z8ulgAQVOPK6ueVeMc3MQH"
    "jlhtHRvKuv5AUq/dqoyy/Cd3KhsLqeFKW78eEVVAeZODwNQp2FtRvLlKOAl3dwuVYbJKgVGC1mnjz0yGxBnbpMIIoth0RAttA62tDkO2MwvjE6"
    "/9dpfGEJxxeWeHzV+6J8jC/jqJccR0MTR6PkOJqaOJolx6F26aPpzPwgqNbqUWymB0G1A5eDoGPDIKhG4DI61/xFVfvvKDbjF7WhDc2Gi9rUPg"
    "2ziVzdThteAjotf/Uwj7acZjlyRzPQ9QazK9nmYZXFbXq6D+uCKGt46OyStaE7dK8YJBseukDHWs8AHfNxx2qimI87bnnFueNW3YQ7rmcRgTn0"
    "G9CE5TYyMECZe7Fjrq+GhD/CMzzXb7V14aVeqi1i5V1tCMPxq1jknuyRUIuw6A2sS46m/3SfBV1f1+Um/EkCzGSqyY2avCwmi7BrUvqlJOW9//"
    "u3vlrAhLe+FYm7jldo54psg64ax4T3mVwmLLfdgprGROYz45dqR9sxKpfeh5mSIYWzliuhgS1J7xADqiXxyStctThpVcv+XvQ364P8I7blImyL"
    "ctTqB/7iqjuZDPMYQsOD6b4bwr+iYtSmpYuwvwADJf2m0EVozTmEK8GV7OBK86V8Db1BLCGWEEtQIahQikav4deEHWevHh8e0ApoBbQCWgGtgF"
    "ZAK6AV0ApoBbRK4orUsya5rFysG0i4YKLpuigXxO0ID6ZWGaambgUZTiGzX6u27tDZr1VHd+jsRq2mOzSkEFIIKYQUQgozkELt6Ap4BDwCHgGP"
    "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"
    "uNC43ySNC1UKVQpVClVKVrEPWcXxTfxtDH8Lfwt/C38Lfwt/C38Lfwt/C38Lfwt/S1Yx7CjsKOwo7CjsKOwo7CjsKOwo7CgmV5hbmFuYW5jbaZ"
    "tck5tI0gSSFJIUkhSSFJIUkhSSFJIUkhSSFJIUkhSSFJIUkhSSFJIUkhSSFJIUkhSSFJIUCylEJEQkRCRE5EQtpOlN7GgKOwo7CjsKOwo7CjsK"
    "Owo7CjsKOwo7Cjs6HXYUAhICEgISAhICEgISAhICEgISAhICEgISAhICcjBWLbuJVctg1WDVYNVg1WDVYNVg1WDVYNVg1WDVYNXwHA7zDLnPZV"
    "6CU3VSf7HhI+Ej4SPhI+Ej4SPhI+Ej4SNJjSU1Fq4UrhSuFLMmZs23tHJ+E62cQytDK0MrQytDK0MrQytDK0MrQytDK0MrQysP8wy5D8cedn68"
    "2hDLEMsQyxDLEMsQyxDLEMsQyxhdIW8hbyFvIW8hb+9P3s5vIm/nkLeQt5C3kLeQt5C3kLeQt5C3kLeQt5C3EyJvsd3CjsKOwo7CjsKOwo7Cjs"
    "KOwo7CjsKOwo7Cjn7z7KivPOSbw5NreEgza4hIeEh4SHhIeEh4SHhIeEh4SHhIeEh4SHjIafCQ+DRhImEiYSJhImEiYSJhImEiYSJhImEiYSJh"
    "ImEi9ZhIcxsTaWAiYSJhImEiYSJhImEiYSJhImEiYSJhIqfDRDpLzyqsA3tWeyw36m83lk2IUohSiFKIUohSiFKIUohSiFKIUohSiFKIUohSNa"
    "I0vI0oDSFKIUohSiFKIUohSiFKIUohSiFKIUohSiFKByNK8ZRClUKVQpVClUKVQpVClUKVQpVClUKVQpVClUKV6lGl0W1UaQRVClUKVQpVClUK"
    "VQpVClUKVQpVClUKVUqXzUF4SOcztMBQCksKSwpLCksKSwpLCksKSwpLqgIxk46o+s9f3+MzGFwYXBhcGNzvjsGNb2NwYxhcGFwYXBhcGFwYXB"
    "hcGFwYXBhcGFwYXPqTwpLCksKSwpLCksKSwpLCksKSwpLiJYWJhImEiYSJvMxEJrcxkQlMJEwkTCRMJEwkTCRMJEwkTCRMJEwkTORkmEjsmhCR"
    "EJEQkRCREJEQkRCREJEQkRCREJEQkRCREJF6RGR6GxGZQkRCREJEQkRCREJEQkRCREJEQkRCREJEYokk1haeFJ4UnhSeFJ4UnhSeFJ4UnhSeFJ"
    "4UnhSeFJ506jxpdhtPmsGTwpPCk8KTwpPCk8KTwpPCk8KTwpPCk2LYhIiEiISIhIiEiISIhIiEiISIhIikvyYkKSQpJCkk6bV8ZH4bH5nDR8JH"
    "wkfCR8JHwkfCR8JHwkfCR8JHwkfi28S3CV0KXQpdCl0KXQpdCl0KXQpdCl0KXQpdCl0KXfqN0KXza+jSxS+//eP3v/zn//zXz79OgyltKNLy0O"
    "tURXoJ14viuK63fQTkzkvbtcI+nbt6vR3voP3KZUfCtyh2xWJ9/Kh6YpN0oAuqzVEVnLPsfAI2zIbi/dgy9zlctf9Ug5YqxvZcRNV+o5T3XdTn"
    "Mpp6EexvfLrcaFpSSMCzLzf1sfzhChq1BdVzP+AmRNsr2+PP4MYi5x7t24t8MVR7hx+u4EFbNP1pFmfNXdQbe0i+PixWgXbNdXObLcB9VQxQ07"
    "64ys3oEhndsz0jUiaq3PRmC+/QbkL6vCOZfO1jsT/2HvnXVxmGnXwFWAXHcrPTfrTn7s3vi/Y75+Y3Kw+AuetyvV0Gj/ZQ0T54AxTmxy+OJ79a"
    "Fds/XkGytph2z/ZZW+11uepIhLcvH4Nd/wq1O6x7wHOXd4vuUBwbgOqPXNL98w7yyF2/FwiFil5XY54MXzlVwsf8Sr9u5O6C5gEy9xpwsl9Gah"
    "VNECY0C6cPU+ZWJrRT5kPBdSsTWng+FFy3MKE87XwpuG5hwr9+3jsXXLcKwZI09jkLVuFMf76cK0J1evIGoHNZWJXjkplXYnMuDI3hQx2am96v"
    "qraKePD1IjD86yp4tBRcsFOtcm6G/5/g1A+SIwneoSlxynMXd4JTnztnvXtdGvqeabg575div11vnyw/tunDLDtLzW5f22PhTd9rC2Lp5+rY88"
    "pu1npRlcU+kAS6oxCGb6i5N/vTDmquWARPv/7133/+NTj8x+9//RV+Dn4Ofg5+Dn4Ofm5K/BwEEwQTZ/9K8+fzYTtH2rccaXMo+00dynp8bDdI"
    "hskI30YcbUzhaMNcebTBmcZAZxqcGXBmwJmBP2cGfNnzZa/+Zc+HM5+AfALyYcOHzWAfNuHNnO0v/x+fN1C2fH7x+cXnF5QtlsrhfGd8ecIp82"
    "kMp4yBCwOXBpnMSQxk/H3sPfMOD81uX+o+aN47fDjx48Tv/Sd+0TUnfi+4NDjy48iPIz+O/DjyQ8vBiRoxYP7EgPmYtsXxI3FWOGyQV3Go9906"
    "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"
    "odKlTvsLt6hwrVO+yu3qFC9Q67q3eoUL2j7uodKVTvqLt6RwrVO+qu3pHGkUl39Y4UqnfUXb0jheoddVfvSKF6R93VO1Ko3lF39Y4UqnfUXb0j"
    "heoddVfvSKF6x93VO1ao3nF39Y4VqnfcXb1jheodd1fvWOPEu7t6xwrVO+6u3rFC9Y67q3esUL3j7uodK1TvuLt6xwrVO+6u3rFC9U66q3eiUL"
    "2T7uqdKFTvpLt6JwrVO+mu3olC9U66q3eiQVh2V+9EoXon3dU7UajeSXf1ThSqd9JdvROF6p10V+9EoXqn3dU7VajeaXf1ThWqd9pdvVOF6p12"
    "V+9UoXqn3dU7VajeaXf1TjX0Jt3VO1Wo3ml39U4VqnfaXb1TheqddlfvVKF6Z93VO1Oo3ll39c4UqnfWXb0zheqddVfvTKF6Z93VO1Oo3ll39c"
    "4UqnfWXb0zDblgd/XOFKp31l29M4XqnXVX70yheufd1TtXqN55d/XOFap33l29c4XqnXdX71yheufd1TtXqN55d/XOFap33l29c4XqnXdX71xD"
    "7d1dvXOF6p13V+9coXrPu6v3XKF6z7ur91yhes+7q/dcoXrPu6v3XKF6z7ur91yhes+7q/dcoXrPu6v3XKF6z7ur91yhes+7q/dcw6zTXb3nKm"
    "6dS3YdDb/O7IJhR8NnaWYXLDsaVkszu2Da0XBbCkkEb0Bp+HZmF4w7Gp5LIXPgDSgN787sgnlHw3lpZhfsOxrmSzO7YOBR8V9eMmDqODAvWTA1"
    "KvolE6aKC/OSDVPFh3nJiKnixLxkxVTxYl4yY6q4MS/ZMVX8mJcMmSqOzEuWTA1PprlgyjQarkxzwZZpQhVX/SVbvUZFv2DNNBreTHPBnGk03J"
    "nmgj3TaPgzzQWDptFwaJoLFk2j4dE0F0yaRsOlaS7YNI2GT9NcMGoaDaemuWDVNBpeTXPBrGkilaSUS1EpGhX9gmHTaDg2zQXLptHwbJoLpk2j"
    "4do0F2ybRsO3aS4YN42Gc9NcsG4aDe+muWDeNBruTXPBvmk0/JvmgoHTaDg4zQULp4lV0q8uxV9pVPQLNk6j4eM0F4ycRsPJaS5YOY2Gl9NcMH"
    "MaDTenuWDnNBp+TnPB0Gk0HJ3mgqXTaHg6zQVTp9FwdZoLtk6j4es0F4ydJlFJNLwUaahR0S+YO42Gu9NcsHcaDX+nuWDwNBoOT3PB4mk0PJ7m"
    "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"
    "hWCFYI1vsRrOOwoG9Zx/Am1jGEdYR1hHWEdYR1hHWEdYR1hHWEdYR1hHWcEOuIpRheFF4UXhReFF4UXhReFF4UXhReFF4UXhReFF4UXvSVF41u"
    "4kUjeFF4UXhReFF4UXhReFF4UXhReFF4UXhReFF4UXhReFF4UXhReFF4UXhReFF40W+SF4V7hHuEeyT01mtaM76J1oyhNaE1oTWhNaE1oTWhNa"
    "E1oTWhNaE1oTUJmYU0hDSENIQ0hDSENIQ0hDSENIQ0xEwJoQmhCaGJmfIr1jG5iXVMYB1hHWEdYR1hHWEdYR1hHWEdYR1hHWEdYR1hHWEdYR1h"
    "HWEdYR1hHWEdYR1hHbEqwuzB7MHsfWtWxfQm0jCFNIQ0hDSENIQ0hDSENIQ0hDSENIQ0hDScDmkILwcvBy8HLwcvBy8HLwcvBy8HLwcvBy8HL6"
    "fBy41PcGU3EVwZBBcEFwQXBBcEFwQXBBcEFwQXBBcEFwQXrrhhniH3EclLcKpO6i821CDUINQg1CDUINQg1CDUINQgQaEEhUJbQltCW2InvIpt"
    "zW9iW3PYVthW2FbYVthW2FbYVthW2FbYVthW2FbY1mGeIfeZ0cPOj1cbvhW+Fb4VvhW+Fb4VvhW+Fb4VKyacJpwmnCacpkec5vwmTnMOpwmnCa"
    "cJpwmnCacJpwmnCacJpwmnCac5IU4TkyakIaQhpCGkIaQhpCGkIaQhpCGkIaQhpCGk4bdD7L05Tb6G2DOzhtmD2IPYg9iD2IPYg9iD2IPYg9iD"
    "2IPYg9ibBrGHHxBqD2oPag9qD2oPag9qD2oPag9qD2oPag9q75ui9sxt1J6B2oPag9qD2oPag9qD2oPag9qD2oPag9qbDrXnLD2rsA7s4eex3K"
    "gf4WEqhHmEeYR5hHmEeYR5hHmEeYR5hHmEeYR5hHmcOvP4+eLG/Q0+a7/Bg9r1kTvKGe5bJjS8jQkNYUJhQmFCYUJhQmFCYUJhQmFCYUJhQmFC"
    "YUIHY0JxYcKFwoXChcKFwoXChcKFwoXChcKFwoXChcKFwoWOyIVGt3GhEVwoXChcKFwoXChcKFwoXChcKFwoXChcKJ0cByEanc/QAksoNCg0KD"
    "QoNCg0KDQoNCg0KDSoCsRMOqLqP399j8+gaKFooWihaPsH5ca3UaIxlCiUKJQolCiUKJQolCiUKJQolCiUKJQoPTChHaEdoR2hHaEdoR2hHaEd"
    "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"
    "YvhQ06tpv8yY5M6loS1vvy6VSdJjswYesxeYWlECXe9jqa+sjykXsQqA1sPnYXAq2RSZniw/UhUBuZ6cq2n+yowrGz7dVGFo2dbq82slgp0zlR"
    "y3RONTOd81synQ8LMp3JdCbTmUxnMp3JdCbTmUxnMp3JdCbTmUxnMp3JdCbT+Z4DIqWXlF5SeknpJaWXlF5SeknpJaWXlF5SeknpJaWXlF7Cbg"
    "m71YMeu2nz1fMmGOLgaChlyuK4PpVC5Vlv7Z9PX43LuaztVwOswm8v8u4fwok5df8WL7t6vfWGTnAiz9yzHbQU5PHjrhzixMJ551y48yAL/Xg/"
    "9bzrp/ZocXSB/1YDso1AldqfI3A/w0qjunoLRuY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5Te"
    "Y3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5TeY3md9kfpP5Teb3aJnfb5LDOjK/n0+BrW9N6nf5"
    "Fg6p30Onft+anDqINfNyYnjjUrSpeMFhf1r4Yqy6Pr44GSLyNb5fmmcq4J3wT5C5h3SjYX5EF/XXgHMJcPMjDPIb9EH+rt/AuS3/yd+fwH3W99"
    "PrTxBM8zdwH/P9tKjD3r/CbjPGbxBKeId7D94N/H2/QDS1THgp+suj5MnrgverelFUPqNOpZluLdi7aYXwexdqd10U/7v73vSJ029kbyubfNt7"
    "plZvLzFypP5DbcaYIfdR0MONK1TUJ7j+oY5GuZmz9D+sx5lGdxB8cxwyyoPtPr9oWgDYaMKbexfc8WvHffzRAG+2eV53XXDW3UbI4nUxcTtKH3"
    "aeLxehs3KvXgLL2/mL2p3Mv/AetnMRsEFVNgPqUHp7cjKVTP4z3M6V6XB8+Og7cDHU3/spT6aRjX+GOxUfFc+BZ/Kj4jly54r58HFXHA7Bcb0p"
    "+wK3KbRjrPTuQP+GIrRbwtX6aeVHVvXXsN1x/p9gb2xUn5+oTQfqW30R90Mtn+9V68366OeppDvFv43+roujx5VEiPH/DHz54C3wRARulVhDxO"
    "E+HJ931cMY0NNu6P0nfTzomcSA+BM/fIY5lw7YDrvyxuJ95dGHO1B/tRjxGDEZtGHxlfd0d0rblvsnu/erq1HmNhG/qGwr4uUQsdtnd4wG7F99"
    "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"
    "MuFEm3mZaKrNvEw0zWZeE+jdLbUD8755t9RRbALdu6U0D++/OqXkD/8/O6WYEO+/O6VIEf8/PKX8Ee+/PKWsEv8/PaVgE++/PaUQFP8/PqXEFO"
    "+/PoV0lQl075ajWHyf8miq3buljBfvvz6lPBj/vz6l8Bjvvz6FDoQT6N4thNX4371baIM4ge7dQidF/7t3u8Nvxu/efaEZo9HpxXjPVoxjd++O"
    "E43u3XGq0b07zjS6d8e5RvfueK7RvTuZaXTvToxK9+4kVOnenUQq3buTWKV7d5KodO9OUpXu3Umm0r07yVW6dydzle7d6Uyle3dqVLp3p6FK9+"
    "40UunencYq3bvTRKV7d0fjxTG74nY0XhyzKW5H48Uxe+J2NF4csyVuR+PFMTvidjReHLMhbkfjxTH74XY0XhyzHW5H38Uxu+F2tV0csxtuV9vF"
    "MetUV9vFMQtVV9vFMStVV9vFMUtVV9vFMWtVV9vFMYtVV9vFMatVR9vFUbt357FO9+480enenacq3bvzTKV7d56rdO/O5yrdu+czle7dc6PSvX"
    "seqnTvnkcq3bvnsUr37nmi0717nup0755nOt2757lO9+75XKV7dzibqXTvDmdGpXt3OAtVuneHs0ile3c4i1W6d4ezRK97d3hz9+4d3bvp3k33"
    "brp3e929u/KpeffBo+bdL0Fl5+ZY3riojNO8u4Vz0IBD9266d9O9m+7ddO+mezfdu+neTfduunfTvZvu3XTvpns33bs/d2aqd/fu3/2+nuFxr+"
    "bd4zfSjhQaacdTbaSdTLORdjrdRtrZRBtp55NtpB3PJ9pIezbZRtpmko20w6k20o6m2Eg7nm4j7WSijbTT6TbSzibaSDufaiPtZD7JRtqzqTbS"
    "NlNspB1OtZF2NNVG2vFEG2knE22knU61kXY20Ubabr3T9hi8R0lzzwXTbZWtypP3yN1u22bOD74jN9Kce488nGZL7WiaLbXjabbUTqbZUjudZk"
    "vtbJottfNJttSWO4Hn0+wEPp9mJ3DPW2qH02ypHU2zpXY8zZbayTRbaqfTbKmdTbOldj7JltpyJ/B8mp3A59PsBO55S+1woi21JWtQ5fuZidwM"
    "3PeTh2+vH7j3z0omIff+Wckn2sx8LjUz9/1ZkfqCR/4/LFJr8HiqrcHjKTwukQTd/8clnmon+UTqJO//45JK0P1/XDLJijvNLuHpFB6XuQTd+8"
    "dFaBXufzNFoVd4NoHHRWgWnk3hcYkkQ/s0u4XnU3hcEgm6/49LKmUO+P64ZALwCTwuuQTd/8dlLsZCTLRn+GwCD4zUNnw2gSdGChLxv4GonDoy"
    "gScmFrH7/8QkYsDKRNuHh1N4YjIRu/9PTC6m4Pj+xMwl5P4/MVJ0yxROeKWkl3iqncTNFM54hRQZM4VDXiF0xvh/yisk1JgpHPMKgTZmCue8Ql"
    "Nxk061qbiZwkmv0FfcTOGoV+gsbvw/642NhNz/J0ZoT26mcNorNDk3/h/3Co3SzRTOe4V262YKB75C03bj/4mvkDhkkX9+ZDzGnkvYJ/DEzMUg"
    "Ss+fGKGRfTiFM18heiicwplvEoppob4/MWLO6QSemFjE7v8Tk4iRrr4/MamEfAJPTCZi9/+JycXcXd+fmLmE3P8nJp2J2L1/YlIjhiN7/sSkoY"
    "R8Ak9MJGL3/4mJ5QTrtmvVOBHWxh0ytLBxN4+VDXE0I9017bxrONJds867RiPdNe+8azzSXeedd01Gaig/67xrOtJdTedds5HuGnbeNR/prlHn"
    "Xecj3TXurhKzkW57oTiNVJ2y7upkRipPWXd5MiPVp6y7PpmRClTWXaDMSBUq765QZqQSlXeXKDNSjcq7a5QZqUjl3UXKjFSl8u4qFY5UpfLuKh"
    "WOVKXyC3uokapU3l2lwpGqVN5dpcKRqlTe0co9OH7clSN1kJc7uYdj3lZu5B6NeVu5j3s85m3lNu7JmLeVu7inY95WbuKejXnbVLxtPuZtM/G2"
    "8zFvm8vlYjbmfTvK1Ih1KpzJdcqEY95XLlQmGvO+cqUy8Zj3lUuVSca8r1yrTDrmfeViZbIx7ytXK5OPeV+5XJn5mPeV61U4G/O+Xduqm1uOXX"
    "1b07WtGvG2XduqEW/bta0a8bZd26oRb9u1rRrxtl3bqhFv27WtGvG2XduqEW/bua0a8b6d26rx7ht2bqtGvG/ntmrE+3Zuq0a8b+e2asT7dm6r"
    "Rrxv57ZqxPt2bqtGvG/ntmrE+3Zuq4a/7//5dG/bs/aNquyHP/33L//4+S2SP//y9//4vflPNweb4Ppv86a/95t2Q//x87//6TOc49tWJZ//sa"
    "zKxXG/fvOX33/53+YPD9vo7Snn7z//9ve//fX3hgL/4W/mT//562//+uP/+/nvf/rbXy1L/qc//9yi+8fv//PLl1+zzvYxy+W+PNxGgsdf/irO"
    "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"
    "vibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvibImzJc6WOFvi"
    "bImzJc6WOFvibImz/S7jbMOr42zD1zjbZUGcLXG2xNl+P3G2zvp0Kk7BQ/2hh//jfR6oQbN1r73ngKm7195y0Dzea29KUi9JvST1ktRLUi9JvS"
    "T1ktT7aUjOZXg5iaTepBO6z0m9qfS2ex7VS64zuc7kOpPrTK4zuc7kOk8p1zkXTi28f0EJpCaQmkBqAqkJpCaQeuqB1PFcWoU93/kQR00c9bcc"
    "R/2tBsu6BS6dwbJKw7o+JzUSx+RVZu058Luk/J7fdiIZvwTiEohLIC6BuATiEohLIC6BuATiEohLIC6BuATiEohLIC6BuATiEohLIC6BuATiEo"
    "hLIC6BuATiEohLIC6BuATiEohLIC6BuATHEhxLcCzBsQTHEhxLcCzBsQTHEhxLcCzBsQTHEhxLcOyNwbHRrcGxhwXBsQTHEhz7/QTHDprVOloi"
    "64i5q6Srkq5KuirpqqSrkq5KuirpquRlkpdJXiZ5meRlkpdJXubU8zKJnSR2kthJYieJnSR2cuqxk8msYzGr1pv1keBJgicJntQA7eY7ytXzZr"
    "306RivWBzXp1Ko8uut/fPpq5G5iZHVADuhtxd590/hxJy5f42XYHf06uDeCT53T3jLIg8VL+m88Vy48SB7sdF+7HTW8WP7U5yd0L/RuNq7JKS6"
    "bjyRjFQX9FSgcy3oYJCE30EUfzfk+xL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa"
    "/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa/EvhL7Suwrsa9dsa9vlEodsa/LYiJRr03Ga3k4DB3z2oRnrhc2BKnejhbzWg6d"
    "8jpMgGwihaD2vnIqRaD2vrLsN+996dzrPN2513m67tOMg/2IVAjouiJ+tvyw0ooPuyLD9jU/QRuamIH7FNgU3D7BvbFQiHsnAiejhRinY4UYZ9"
    "4k5F4R07rXx+WsgwdbAssm5E0ZnftLq1afNfeXUnWyq0e9rnyYuFAK2X057n3AF7nTP9R/2LhrdesROPHOgFRnAT4Vp8ZzuXvuk6ofOitwa6Y7"
    "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"
    "men/qx9f6KLUsA56d+TN0YVC2avD6+6OR9h1dWRu9LTOObzjUzT7WvdZy5thMeu1b2E45wx01UfPhVWdocBxXezikcD27/Sdbm5p5kfPxQZnDX"
    "hOoBYHOAK5tR47TQORwboHONda6xzjXmmmt8KzE90mTj27Ufabbx7dqPNN34du0pPq9eU6n66DGHebQTdl6QDhqe/aDh423XnROpWoXujonyhN"
    "/j0t0pkVxtafFQ18HBk0/mPf4OnsPg21Tuhb7ab+cxl/dpDg6+DYTr72ch0k43B5iY5gDfiYNzuHZlV2f8YI8ztefQ+umrgMtZzGv79sYCP2zy"
    "cSc0+QRt8tEmH23y0SYfbfLRJh9t8tEmn6fR5FMd4a8dPtrhox0+2uGjHT7a4aMdPtrhox0+2uGjHT7a4aMdPtrhox0+2uGjHT7a4aMdPtrhox"
    "0+2uGjHT7a4aMdPtrhox0+2uGjHT5z7/CJlTqwtotouwhzu8h41z1St8i48iM1i4wrP1KvyLiytopoq4i2isy0VeTpdWKMiTIHTfSbbiLwJzQR"
    "RG0i0CYCbSLQJgJtItAmAm0i0CYCPSnktGul3r56++rtq7ev3r56++rtq7ev3r56++rtq7ev3r56++rtP5q3f/53tfXV1ldbX219tfXV1ldbX2"
    "19tfXV1ldbX219tfX1PI5v7DyOcqaMNZfj0OlPKiYCTx4xQLqtLJweZaK9KXqUiR5lov0p2p+i/Sl6lIkeZaJHmWgX0hRdSOGELqSkXUjahaRd"
    "SNqFpF1I2oWkXUjahaRHmWgLkrYgaQuStiBpC5K2IGkLkrYgaQuStiBpC5K2IGkLkrYgaQuStiBpC5K2IGkLkrYgaQuStiBpC5K2IGkLkrYgaQ"
    "uStiA9ixYkbWjRs1a0n0XPWtGzVrSXRXtZtJdFW0X0rJV5djnEE7ocsnY5aJeDdjlol4N2OWiXg3Y5aJeDnrVy2rXSrgLtKpigq0AtfrX4uy3+"
    "87/fPjBfbJmNCDXl1ZRXU15NeTXl1ZRXU/7O0DKqyX/CQarHP7gafg5u/MgR5iDGjxxRrXi14tWKVyt+Oh5Vp1WdVnVa1WlVp1Wdfmbq9JWq06"
    "pOs6vTV4+mTl89mjp99Wjq9JWq06pOqzqt6vQznLL/TdvT6cvt6ezVnlZ7WlxBm71PWB1QoQLfvAU+VcCaCtiIEXgx5iVbqcqgKoOqDAIqw1Wp"
    "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"
    "Qdd1Y2VX+xjH91zMn6GvofQ+as1arSpP23+1Gp9c9+tl95P1j4sXB51O8OW3zENVxZyiqmjPsqoq8qrK4xyXokedqNnz7I86UfNIzaNnbB5dvx"
    "p355/msEepeKTikYpHKh6peFTDq85XncfVcxhPtS3VtlTbUm1LtS3VtlTbUm1LtS3VtlTb+hIBqvyraXyrPgdDIthqbWEOdKq8OT1mSB1AdQDV"
    "AVQHUA/UUkNRDUU1FNVQVEPxORuK9hRD0aqhqIaiGopqKKqhqIaiGopqKOpstOrVCuAH0XIv+4vIxCrceitbDVO1U9XOKdTOctqvbx8T5b+Alg"
    "Ce9FdQtVjVYlWLVS1WtVjVYlWL/aa12PvHpZdr9uviGjx2DprsAx5SXVZ12eeiy6pZ+X+0suJv77sfbOJGkaqLqi6quqjqoqqLqi6quihAV0zX"
    "5c3Lxe3zgTieLVfujj9bJvhO9LERYOuPk+dmpJYHs9wWxhab8YeD8I0WAN4UJapP7oiT6Wal86ZUv/FXV6+2h44nm5Tra4t/DHkAN8n52bK/+t"
    "Ur/KhoraK1itYqWk8qWtMpojWpaK2itYrWKlqraK2itYrWKlqraK2itYrWKlqraK2itYrWKlqraK2i9TciWt9sbuxcRetbNhWtVbTW+cM6f1iF"
    "ahWqT5o/PO4eZq7zh2/ZdP6wWvJ6bLyK6Cqiq4iuIrqK6Cqi6wxdNZbVWP7kh8Jyc9NvLKsUrFKwSsEqBX9jUrA7RQp2KgWrFKxSsErBKgWrFK"
    "xSsErBKgWrFKxSsErBKgWrFPxcpeDy+9n1/mJ9vbiSHQ9iI2I71YScGq6Y5Lvlfszy9Ub80s3L9R7wtRL+KFVFVxVdVXReFV2tZR0P/fzGQ79Y"
    "blVmVplZvVf1XtV7Ve9VvVf1XtV7Ve9VBzDrAOZ5DmBWebiDTgcMq0usLrG6xOoSfxMusT/FJfbqEqtLrC6xusTqEqtLrC6xusTqEqtLrC6xus"
    "TqEqtLrC6xusQ6mVl1WNVhVYdVHVaH+D71Ib6qvar2+ogzfGc8wlcn+KrJrCazmsxqMqvJrCazmsxqMs/eZAY6bvF3jOq4T0PHVStVrVS1UtVK"
    "/cas1HCKlRrUSlUrVa1UtVLVSlUrVa1UtVLVSlUrVa1UtVLVSlUrVa1UtVJ1wq1OuFWlV5VeVXpV6dUJtzrhVlVfVX3VC1UvVL1Q9ULVC1UvVL"
    "1Q9UJ1wq1OuNUJtzrhVifcqkusLrG6xOoSPxeXOJ7iEkd1idUlVpdYXWJ1idUlVpdYXWJ1idUlVpdYXWJ1idUlfq4usSqxqsSqEqtKrCqxqsTq"
    "lFudcqvqq6qvOuVWp9yqzaw2s9rMajOrzaw2s9rMajPrlFtVctVMVTNVzVQ1U9VM7TdT0wlmalIzVc1UeTN1Lire7FWy2dtbaiHVhQjVQ+YrYH"
    "yjVWaKlTfmJF9ioVRlk66xUK6izaDGouqAqgNPVx0YOcIc3IHbIvhM3YFbNnUHTncHbsvgM5UHbtnUHvgKe2A33nIT2AOxsrj9ZtWEWde8Uqy9"
    "H728On+1WTO/B9ZX0vpKWvK1bz7hta8b9LWvvvbVgQQ6kEAHEuhAAh1IoAMJZjaQ4PrVuDv/NIvSpFa0tK9+gr76mRT/5lV1q1WfFnMuPy1mXH"
    "9aaAFKC1BagHoWBShtXv3aAtRi3hWoxZxLUIsZ16AWMy5C3dY9H6sIdVt/+2b7Y8uvhsfXd3OoQgVbfYk5BzrtLf5s6VBbWrxrVNueP68+V9sG"
    "5Tt8tRn0eTaDzrslb87l92+558oPpxTfjRbftfiuxXctvmvxXYvvWnzX4rueBnDaaQDHMXtmtscB3NE9wfMAvvi5SyWE5zTc/3i/2tnO9r+j09"
    "n+2rx9okZyd+PMVCO5g1ONRDUS1UhUI1GNRDWSrxiCbuY8Bt2oRqIaiY5ZVxVCVQhVIVSFeIpzsXX2dAdd+Wf/cnOzXqy2h54ZDDrVWhWaZ6jQ"
    "mBMUGq/zK1ShUYVGFRpVaFShUYVGFRqdX6EGzQwMGp38odKNSjfPTrqZle2iVoRaEXowfKcUMZPyedmKmEn5/KlqEXbOWoRO11AtYl5aRPFJfv"
    "XTalM5/fYxf+PoqA8d9aF+i/ot6reo3/L4dE7PfZ+f3aLyiMojp8sj9hR5ROevqDyi8ojKIyqPqDyi8ojKIzp/RR0IdSC+hdNPdHqG+gTqE6hP"
    "oD6B+gTqE6hPoD7BM/cJtCauNXGtiWtNXGviWhP/pudR6NQILfw/x8I/nVL4t1r418K/Fv618K+Ffy38a+FfC/9a+NfCvxb+tfCvhf9P3pNdj0"
    "8Gs6j+38PMQgG4e17ivzIOwdg5yAD3MPRNGgFap9M6ndbptE43xzpddYs3iyvZak60AO3FC1m2ahxZ8cvmAJr0ZfPoGa6vLzRWA3F8NTPBh9JV"
    "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"
    "Zj2K97jN+y3TS+n90fprkR+sqCZX9ofLu+Lfl+j5liZVlofBVwvditt+enHmJBX2D7jIsvfjy9Ke1LzjZbHsbhWFfbw/5qM7nsc3xkmWJxgwK+"
    "57tadn1eXl2N3vJy9cP60LV4uW1k+cPJh7XTF4g+Z6NrfT069J1r+7K++sM4imO72P3Qd0HK7z6X+4vDT4txVH/X2rF2USb4IMudcVeLSW7B4t"
    "fysN9eX15cX4/bRc/iZVPmeFUOf++8U8qay9VY7Rxf1vauXf7dOL4XOoq2nXdK2S/5/nX3uuWv5fhj6IfFfnVz3rN05Tib63FfOD7J72ZRshwf"
    "ccZL2PFn+prXtT+8erHpaTmqHDu1/Pv5/mp3vdv2/PooVwTHtUfkzpWp+uy7218s1ttlz+Ku+kN1tz30PEiWS27Xm+Xoc74ek+dy37N4cQ95fX"
    "V7POtyN/l5SpurMXF6Vy7uH2OxZnw0OvoP05+RND53vbjYHNY9V7pcajpej4vDq/N1z8rFb+Nm/HHUu7CtvWD4z6tt18LFb+L1q+3J3QH0BRWZ"
    "cd1TD/elL6itnC/3P7C+CitXVY6/VsfXmSeHDH1BleS49uvxcbLrh3C5yjButePD9dWrrkQvFwxu+xAXx7emPVek/PL/bu2vuCb0BW/yxzmft9"
    "jj+4GbnsWpsvgtdu/i5fMwxjPvj58oc/0hlH9d3e263O8xUvFmXH1/nG64+anjLk/lm2W/WpytVj3rFu+Tq135RfaXL+vKzV/Xh96Fy++7rw8X"
    "u+Nrxh6TPQW4dI/JniJcusdkTwku3WOyp1xZ+rhwx7p5qKw7fp1O3aQ/W9lUVt4dDj/teu67bCsrn/cuTJWFX6zHExb3XUu7ytJjn8CrroV95U"
    "Hh+DuqZ93yKZ2b9XK/4laIy6dyjs36Y9HhqvQ6+lFham+wf3zxasNbiy0fCnpz+7B1vet5lz4M1STbXe0PXWWpssSx2ZqxoN21sK0tfHzFsn7Z"
    "tTbV1j4+H558tT9f3dVWv31C3Heu7mur75h9Ilv97G3fZ2+rn73t/uxt9bO3E3z2tvrZ2wk+e1v97C33Z0/Vz576PnuqfvbU/dlT9bOnCT57qn"
    "72NMFnT9XPnrg/e1f+7A+r3WKCy+jKN8Bx9QkuoyvfAnfsh33P70hfvizX69H96CsHlK/IceFjQaBrZaqtXGktO6GGUW7NMouz5avzfbGN7oTF"
    "TWXx8e7o5baVpVebq+u+Xw2+LMSMa1+vltvO1xi+LDUcP8vjSxL2zjxb/Tasrm64WapfoOO7LP5LU/3WHc0Zgcvjqvmy3FxKAPka0G0bLjdNAB"
    "8X/80TazSbq5cv+XFSDediu3jF3UoeynvwWL15tRvdsdEx/6qXKA8FePMlAvz1j6PJcxmmGcD6+Ar8zAawUltRP9ryo75x4unl5jH09P7X476+"
    "rJ1aNO9/LR7ry3a9Ei8v2/l+KpeNslG0734jbirPW0en9uLQNzDG8B+6PRrMpmMq55gfZnJV/Ha6mORRlmXL/BZL8hzL8vDMWyzJQyzL0vst1l"
    "YSK9Zu2Di5+n5cNU2uvR9XzT3W7lCu5J8tN0cp4pHO/x3+9mWBYg2kO5OFsxBuJQtHVbjFKBleH2TpXO1s1sXyTPBc1vKvy1uus5UkV6hyrZaS"
    "XLX8tHHyNoW7u0Py1N5yh8Pd3SHJRUP97hDlqrU7kZm8p+I22SYKkK5oI8J4Z7L7Qrm54yPeSnbDJ1/HW2w2r2XhQuPO28rixcadJ4yXGneeMF"
    "5Gd95W9s4rD3Idk9QNHUnqKkdujufcvBjHlp/67P8FA1w/rn3WszbhtVc9azu8NvXYVuXpqseP0fesWhsb4ULPqrVHO9fzaOdqP41dz0/j2hnt"
    "44c2xWGU0x/QfgQ7m+Pp7EewlShYPTdO/u5NTFabGr3avd5PczTm1Key38OdCcN5BLcShgsIboJbro8uVqpnE91yU5/Gfkd2JkuW62QrUbJyJ+"
    "od2SR32tTHrx++H6WTV3vht8CVbti/2GR/7pcbau/ZZH/rh8qmcB3c5D25x7/47kew7J8cIJzwvRIhnPDNUk7N29t4f3ktWKQr9xrfka1GF7X7"
    "up0/VMdPvW7lbuWzOVw3WyebwXUryztzuG6uTjaD61Z7hxB73iHE2juE2PMOIdbeIcSedwix9g4h9rxDiJX8u43mCW7IjjpKGgCa/B2ZKgk4hy"
    "tnAdoMrlwlA+dw5VwdbQYXrmw5zeOeC4jteO1kL115vuA8brqE2OQvXXmeziz2iPJ4h9VyJpcu18zQvskTrnK66+kjladWYXPtMS33PKaVZzUc"
    "/2BxH7Y8uuEDmqQTWx7k8AFN0ovNGaKJurFDrehshqFr5ISprtvliQ9V+3ywXetS7TMa7QD5t6OVoRIP+M6E+XyDbyXMVw7V7asjnLwra4Zqss"
    "oLs2ZIEE7UmjVDhnCi6qwx1Xg1XfFabhD6eLtsRf9oi28XWTjCt4ssnKveLq7rdqml86uzOei0xgTMJ+zTGhMxn7BQa8rNSJf3eNJOrTG5cf/J"
    "aqGm3CD14P6T5jON+0+az+L7T9isNZZquWqpJ1dt9al8tD1GlbTLrjXWN1Y/61o9NFZfda0e66sfF+9SbI2tNl/aru5LW22/tLmru7n6GEhdj4"
    "HV5htDfd3Y1Se4Gfi2hgjTncnSOUy3kqXzmE5WvzVUDaU7WVNawTUUG4Bn0oCpAbiSBswAcOSTtnGNG6qva2eg5BpnMN6ZMJ7FeCthPMJ4woau"
    "cbXdYx6WrnG+wSf8JsGFBp/wm4Rqx5U5teVqcrJUv3IzkH6Nyw0+4TvPDw0+4TuvevKbfB3d+Orvc9/1+7zcMXX8m+VHS3kP2WTnSwXIJjpkyk"
    "fIJlpN99X3Er7rvYSvvpfwXe8lQvW9ROh6LxFqJ1jOpJoebINPeC8J1OAT3kvKTUeXf59LNT1Us3UG1fT6QYMzqKbXTyqcQTU9VOM1dMVruS3q"
    "4+0iWhOOA75dZOEMvl1k4aquWOxyxWItnWdSTY8O80lX06PHfNLV9HKf1OXf51JNj7Fx/wlXg8u9Ww/uP2m+3Lj/hPnKrWAf7z/panqqVh1TV9"
    "UxVZ/Kp6imJ2qs3lVNT66xelc1Pfn66v3V9BSqn2foWrf6rjP1TV6uj17uegxM1V/ZqetXdq4+wc2hmp4NppOtpmeL6WSr6ZkwnXA1PVdDaSbV"
    "9Opxt3OppufQAJSupucIAOdQTc+p+rp2DtX0nDGebDXdDgPGWwnjGYwnXE2vHCQ78s2jml45jPYBn/DhB4Nr8AmffzDUGnCP/9JzXkao/90zqI"
    "XbITb4pO+b1OATvm/KbVnr7Xr/8qdjdJnu15bL7ztiq9zd9RHPCuNZjEfCeITxnDCeA3jjQ9um++Z73YXnG3hWFi808EgWLzbwnCxewnirCYJv"
    "3wWYG4BWGNAODUCSBjQNQCcNWJ6HNT5Mnq8vRZUsW27nukc7E0XzCG0lihYQ2lYUrXp0Vd/ZVdX+M9vVf2ar/We2q//MVvvPbFf/mS33n+1+WM"
    "zi61zuYntAJ/qNLnexPaAT/VKXu9ge0Il+r6k2z39zLLcd+STfu1uKteMGJsPreilrqTbXf0K+HrzyUS8/3H3A4h9vuUFsefNysXtx+5DfE6mu"
    "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"
    "GkHSlrq4/iS/mZmtYmSHcmTJchnexcTUsDpBOerGnJVE8rMl2HIFXPVqK+w5Xqpyt1Ha9E1fOVqOuAJaqesERdRyxV27NsV3uWrbZn2a72LFtt"
    "z7Jd7VmW6o+JfYP0rBvAymddKxuw8qprZQtW7hqhZx3Vc6z3Sju0dN+l9mjpvmsd0NKdF7v6OHDef18nuHbf5c5w7a7r7Qe4dt8F99Wv5LL/in"
    "uLF++65J7w4n3X3OHFOy96/fTBrr3RV/dG37U3+ure6Lv2Rl/dG33X3uir38bjiE7R6Zw2VL/NxxGdwrM5bblBYhQ2xM0+W26PuEc7E0VzCG0l"
    "iuYR2lYULSC0l6JoEaGJmn223BPx4Su6k4XLCE7c7LPlBo0HfMLV1XKTxgM+4fJqrO0P8zD7bKy+JYldb0li9S1J7HpLEqtPgrHrSTBWnwRj31"
    "HU9bOou54EY/VJMHY9CcbqedQxdx2ePVRPzx661q2+lUxdbyVT9bluBmZfIggna/YlB+Fkzb7kIZys2ZcCvudELasU8T0nC5fwPScLlyGcrNmX"
    "B/yFEL1yufpwNwuzL1uIJ232ZYJ40mZfdhBP2uzLHt97wvJXDvjek8aL+N6Txkv43pPGqz6E556HcBpqD+HHf+lZ11TXNV3rVgNW3OyjgRDbmS"
    "ybQ2wrWTaP2GTNPhqqqToHs4+GCPHOpPESxFtJ42WIJ232kak+is/A7CNjIN2ZMJ2FdCthOoJ0wmYfmdq72uO/dGzfxlfX9V3rhuq6oWvdWF03"
    "dq2bquumrnVzdd2ux0RbfUy0XY+JtvqYaLseE239MbHPxyFLYOWzrpUdWHnVtbIHK3dpOGRDPcd6r3RES/dd6oSW7rvWGS3dd7Gp+jjQ7ZkRGb"
    "h21+UmC9fuut5EcO3OC179Si4nuOIeL953yQNevO+aR7x450Wv7o1dtjdVD+OgrsM4yFX3Rte1N7rq3ui69kZX/TaKm33kqt/mGZh9VBbC19uX"
    "Py32m9E+7D4X+PX3Hc/sZaf8I52VpYuYjmTpEqZzsnS5Trec4r4b31L08JXt+o98VprPYD6S5rOYz0nzEfh2XL06yOZeuc/gI51s7nmP6WRzzw"
    "dMJ5t7HuwZyynuu97vRcJ84rmXMZ907oUB80nnXgD7xmacIi2be8FiOtncC4TpZHMvOEwnm3sB7BnLKe673u9FwHzSuRci5hPPvYT5xHOvvm+M"
    "vTET3H09cHFAcFYYziA4EoazCM7JwP3HX4DfOf/AUfnuzX+/+/PtQ9yf3/3xz/fH/5nrH88XL2lhz15df/yf++fbf7y5pz6sCy8315v16rC/eP"
    "Av79/97+27pbNPKljv3/76x++/vT8ifve7efOvX379+I//9faPN7//Nv4Vb35+ewv35/v/effp9N/SBV6en48v7a5PurzuU/uruOxut7lYLQ8X"
    "V9uet4HFU6SvLi/X+/3V/qSFP75E++3XN7+8/ce7X47/hYd0v/3rXw/+4cWL7z5BKW7JF7vj5TMdF8/Xl7Udy4b6stSxbKwv6zqWTeVld1f7Q8"
    "eqxW3ibHm9Xowf7vW6Z+my+XK93p5fbC8ON8tNz9rFr+nFdrdYXZ4vSn7iz//+f//+8+0vxbVt521f9lQ+0FhmGoI0xEzjII1jpvGQxjPTBEgT"
    "mGkipInMNAnSJGaaDGkyL01Z5bmnMQMzDcxiw5zFFmaxYc5iC7PYMGexhVlsmLPYwiw2zFlsYRYb5iy2MIsNcxZbmMWGOYstzGLDnMUEs9gyZz"
    "HBLLbMWUwwiy1zFhPMYsucxQSz2DJnMcEstsxZTDCLLXMWE8xiy5zFBLPYMmcxwSy2zFnsYBYTcxY7mMXEnMUOZjExZ7GDWUzMWexgFhNzFjuY"
    "xcScxQ5mMTFnsYNZTMxZ7GAWE3MWO5jFxJzFHmaxY85iD7PYMWexh1nsmLPYwyx2zFnsYRY75iz2MIsdcxZ7mMWOOYs9zGLHnMUeZrFjzmIPs9"
    "gxZ3GAWeyZszjALPbMWRxgFnvmLA4wiz1zFgeYxZ45iwPMYs+cxQFmsWfO4gCz2DNncYBZ7JmzOMAs9sxZHGEWB+YsjjCLA3MWR5jFgTmLI8zi"
    "wJzFEWZxYM7i8sDml/vdYr1dnm0mMnBu11pXmM4vrsd//QwrNLCsDFZsYJEMVmpgORms3MDyIljlWdcPsIIMlmlgRRks28BKMljUwMoyWA5jTa"
    "P0nI7VSHkjk/KpkfJGJuVTI+WNTMqnRsobmZRPjZQ3MimfGylvZFI+N1LeyKR8bqS8kUn53Eh5I5PyuZHyViblcyPlrUzK50bKW5mUz42UtzIp"
    "nxspb2VSPjdS3sqkvBkaMW+DEFcj520U4moEvU1CXI2kt1mIqxH1NAhxNbKejBBXI+zJCnE10p5IiKsR9+SEuBp5T0J5bxp5T0J5bxp5T0J5bx"
    "p5T0J5bxp5T0J5bxp574Ty3jTy3gnlvWnkvRPKe9PIeyeU96aR904o700j751Q3ttG3juhvLeNvHdCeW8bee+E8t428t4J5b1t5L0XynvbyHsv"
    "lPe2kfdeKO9tI++9UN7bRt57oby3jbz3QnlPjbz3QnlPjbz3QnlPjbz3QnlPjbz3QnlPjbwPQnlPjbwPQnlPjbwPQnlPjbwPQnlPjbwPQnlP1b"
    "wXmbPkBojDPWjJGYjDPmnJQhzuUUuOIA73rCXnIA73sCXnIQ73tCUXIA73uCUXIU7mxkkIh3vgknEwlbknLhkPU5l75JLxMJW5Zy4ZD1PZsA/A"
    "g6nMPXXJeJjK3GOXjIepzD13yXiYytyDl4yHqcw9ecl4mMrco5eMh6nMPXvJBJjK3MOXTICpzD19yQSYytzjl0yAqWzZ55LCVOYewGQCTGXuCU"
    "wmwFTmHsFkAkxl7hlMJsBU5h7CZAJMZe4pTCbCVOYew2QiTGXuOUwmwlTmHsRkIkxl7klMJsJUJvZx0TCVuWcxmQhTmXsYk4kwlbmnMZkIU5l7"
    "HJOJMJW55zGZBFOZeyCTSTCVuScymQRTmXskk0kwlblnMpkEU5l7KJNJMJUd+xR/mMrcY5lMgqnMPZfJJJjK3IOZTIKpzD2ZyWSYytyjmUyGqc"
    "w9m8lkmMrcw5lMhqnMPZ3JZJjK3OOZTIapzD2fyWSYyp79cBWYytwTmkyGqcw9oslkmMrcM5rsAFOZe0iTHWAqc09psgNMZe4xTbbcH3m2/+Gu"
    "js5u8NhyY+QDIPb7xzeA2O+g0ABiv4diA4j7pJ5y8+MDIO7Despdjw+AuM/rKbc7PgDiPrKn3Of4AIj7BLVyg+NHIP5D1BpJzX6OmmkkNftRaq"
    "aR1OynqZlGUrMfqGYaSc1+ppppJDX7sWqmkdTsJ6vZRlKzH65mG0nNbflY20hqbs/H2kZSW/YTL6tJfX2oPOM/4hng1nqMY5lxAsYhZpyIcRwz"
    "TsI4nhknY5zAi0MDxonMOAbjJGYci3EyMw5BnNIT/aPi4FQ2zKlMOJUNcyoTTmXDnMqEU9kwpzLhVDbMqUw4lQ1zKjucyoY5lR1OZcOcyg6nsm"
    "FOZYdT2TKnssOpbJlT2VVTebe/nurZ/af1dQVoe/U5T2jwWGae2OAhZp7U4HHMPLnB43l5/NDgCcw8psETmXlsgycx81CDJzPzOMwzyUP8KTyN"
    "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"
    "3EC2AZS4gagBlLmBHAbidvJdaCQ1t5PvQiOpuZ18FxpJze3ku9BIam4n34VGUnM7+S42kprbyXexkdTcTr6LjaTmdvJdbCQ1t5PvYiOpuZ18Fx"
    "tJze3ku4gMPuJ28l2MGIfZ/owJ4zDbnzFjHGb7Mw0Yh9n+TAbjMNufyWIcZvszEcZhtj+TwzjM9mfyEIfbyU84lbmd/IRTmdvJTziVuZ38hFOZ"
    "28nPOJW5nfyMU5nbyc84lbmd/IxTmdvJzziVuZ38jFOZ28nPOJW5nfwMnT1id/JzavAwO585N3h4nU8/DA0ex8xjGjyemcc2eAIzDzV4IjOPa/"
    "AkZh7f4MnMPAHzMDv5fmjkM7OT74dGPjM7+X5o5DOzk+9NI5+ZnXxvGvnM7OR708hnZiffm0Y+Mzv53jTymdnJ96aRz8xOvjeNfGZ28r1p5DOz"
    "k+8Ncu9IxMn3JmMmAZfT2wEzkQSTwUxOgsliJi/BRJgpSDA5zBQlmDxmShJMATNlCaYImSScfG9xjks4+d7iHJdw8j3hHJdw8j3hHJdw8j3hHJ"
    "dw8j3hHJdw8j3hHJdw8j3hHJdw8j3hHJdw8j3hHJdw8j3hHGd18v/jL65j58nHj++7N//97s+3Dyl/fvfHP98f/9vXP54vXtIinL168Pvjn2//"
    "8eYe9bBe/V/+9Wa9OuwvHvzL+3f/e/yHy7NPPoL3b3/94/ff3v95/KffzZt//fLrx3/8r7d/vPn9t3//+uebn9/ewv35/n/efXJlixm7PD/fr6"
    "+vT7qm7pNlizG53O02F6vl4eJhYeULlqZPJxqWll5dXV6u9/urPW/Zp4RysTtePtNx8Xx9WduxbKgvSx3LxvqyrmPZVF52d7U/dKxafvRaXq8X"
    "44d7ve5ZuvzK8nq9Pb/YXhxulpuetYtf04vt7lZV5G7+Kb98/EDD7JOXXz1+oGGWycsvHj/QMJvk5deOH2iYNfLyS8cPNMwOefmV4wcaZoG8/M"
    "LxAw2zPV5+1fiBhlkdL79kvKfh7vCxMIu523sszGLu3h4Ls5i7scfCLObu6rEwi7lbeizMYu5+HguzmLuZx8Is5u7ksTCL2Y/WgFnMfq4GzGL2"
    "QzVgFlvus49gFlvug49gFlvuU49gFlvuI49gFlv2k+kgDfthR5CG+6QjmMWWu6USZjFx91PCLCbuZkqYxcTd8w6zmLgb3mEWE/tcEkjDPpQE0r"
    "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"
    "18ZnbyyTXymdnJJ9fIZ2Ynn1wjn5mdfHKNfGZ28sk18pnZySfXyGdmJ59cI5+ZnXxyjXxmdvLJNfKZ2cknj9w7I+LkkzeYyUowWcxEEkyEmZwE"
    "k8NMXoLJY6YgwRQwU5RgipgpSTAlzJQlmDJkknDyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3DyKeAcl3"
    "DyKeAcl3DyKeIcl3DyKUJLz7I7+RRtA8hyA1EDiNv0jK4BxG16Rt8A4jY9Y2gAcZueMTaAuE3PmBpA3KZnzA0gbtMzDRiI28mn1EhqbiefUiOp"
    "uZ18So2kZnfyUyOp2Z381Ehqdic/NZKa3clPjaRmd/JTI6nZnfzUSGp2Jz83kprdyc+NpGZ38jMy+Cy7k58J4zDbn9lhHGb7M3uMw2x/5oBxmO"
    "3PHDEOs/2ZE8Zhtj9zxji89qcbBoyTmXEMxGF28t2AU5nZyXcDTmVmJ98NOJWZnXw34FRmdvLdgFOZ2cl3A05lZiffDTiVmZ18N+BUZnbyncGp"
    "zOzkO4NTmdnJdwanMrOT7wx09iy3k++Ma/BYZh7f4CFmntDgccw8scHjmXlSgycw8+QGD6/z6ezQ4EnMPKbBk5l5LOZhdvKdbeQzs5PvbCOfmZ"
    "18Zxv5zOzkO9vIZ2Yn39lGPjM7+c428pnZyXe2kc/MTr6jRj4zO/mOGvnM7OQ7auQzs5PvqJHPzE6+I+TeWREn35HHTFaCKWAmkmCKmMlJMCXM"
    "5CWYMmYScDmdGzBTlGAymClJMFnMlCWYCDJJOPnO4RyXcPKdwzku4eQ7h3Ncwsl3Due4hJPvHM5xCSffOZzjEk6+8zjHJZx853GOSzj5zuMcl3"
    "Dyncc5LuHkO49zXMLJdx5aesTu5DsfGkCWGyg2gIgbKDWAHDdQbgAxm54uDA2gwA1kGkCRG8g2gBI3EDWAMjeQw0DcTr4LjaTmdvJdaCQ1t5Pv"
    "QiOpuZ18FxpJze3ku9BIam4n38VGUnM7+S42kprbyXexkdTcTr6LjaTmdvJdbCQ1t5PvYiOpuZ18F5HBR9xOvosR4zDbnzFhHGb7M2aMw2x/pg"
    "HjMNufyWAcZvszWYzDbH8mwjjM9mdyGIfZ/kwe4nA7+QmnMreTn3Aqczv5Cacyt5OfcCpzO/kZpzK3k59xKnM7+RmnMreTn3Eqczv5Gacyt5Of"
    "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"
    "RAVZm6R5NsUVWmbtIkW1SVqbs0yRZVZeo2TRK+4vOYRyd38Ej4fs8TEPn6MQkg8hVkE0Dka8glgKhv6ml9Aoj6sp42JICo7+sRbQKI+soeIRJA"
    "1DeoCYkD0V+illBq8nvUREKpya9SEwmlJr9NTSSUmvxCNZFQavI71URCqcmvVRMJpSa/WU0mlJr8cjWZUGpql4+UCaWm9vlImVBqSX7jJajUuz"
    "2wx7/jHeBSGhxHEuNYHEcR4zgcRxPjeBzHEOMEHMfS4qgWx3HEOALH8cQ4EscJxDgKxYnt6O+Kg6uyIFZlhauyIFZlhauyIFZlhauyIFZlhauy"
    "IFZlhauyIFZljauyIFZljauyIFZljauyIFZljauyJFZljauyJFZlDaryZrsbau/+bbYDgFbrH3lsgkcS87gEjyLm8QkeTcwTEjyGlse0CR5LzC"
    "MSPI6YRyZ4PDGPSvAEYh6N8wyyib+FJ6HPglifTUKfBbE+m4Q+C2J9Ngl9FsT6bBL6LIj12Sb0WRDrs03osyDWZ5vQZ0Gszzahz4JYn21CnyWx"
    "PtuEPktifbagPq+2Q23nH0bzBcizXY4WPzI5nElyMHmcSXEwBZxJMzC5FmcyHEwCZ7IcTBJnchxMCmfyHEwaZwocTAZlGmTLfzMTruOCQ8cdru"
    "OCQ8cdruOCQ8cdruOCQ8c9ruOCQ8c9ruOCQ8c9ruOCQ8c9ruOCQ8c9ruOCQ8c9ruOSQ8c9ruOSQ8c96tIT9J587xNA1E5PHxJA1E7P0CaAqJ2e"
    "QSSAqJ2eQSaAqJ2eQSWAqJ2eQSeAqJ2ewSSAqJ2eweJA5J78kFBqck9+SCg1uSc/JJSa2pOv2oRSU3vyVZtQampPvmoTSk3tyVdtQqmpPfmqTS"
    "g1tSdftQmlpvbkqzah1NSefNUmlJrak69azMEnqD35qg04Dq37U4kWx1HEOALH0cQ4EscxxDgKx7HEOBrHccQ4BsfxxDgWxwnEOA7FIfbkK4Gr"
    "MrEnXwlclYk9+UriqkzsyVcSV2ViT76SuCoTe/KVxFWZ2JOvJK7KxJ58JXFVJvbkK4mrMrEnX0lclYk9+UriqkzsyVcS9ewJak++Um2CRxLziA"
    "SPIuaRCR5NzKMSPIaYRyd4LDGPSfA4Yh6b4PHEPC7BE4h5PM5D7MlXKqHPxJ58pRP6TOzJVzqhz8SefKUT+kzsyVc6oc/EnnylE/pM7MlXOqHP"
    "xJ58pRP6TOzJVzqhz8SefKUT+kzsyVc6oc/EnnxlMO+dYPHkKyNwJsnBJHEmxcGkcCbNwaRxJsPBZHAmy8FkcSbHweRwJs/B5HGmwMEUUCYOT7"
    "6yuI5zePKVxXWcw5OvLK7jHJ58ZXEd5/DkK4vrOIcnX1lcxzk8+criOs7hyVcW13EOT76yuI5zePKVxXWcw5OvHK7jHJ585VCXniT35CsnE0CS"
    "GkglgKidnk4ngKidns4kgKidns4mgKidns4lgKidns4ngKidni4kgKidnr7Fgag9+conlJrak698QqmpPfnKJ5Sa3JPvE0pN7sn3CaUm9+T7hF"
    "KTe/J9QqnJPfk+odTknnyfUGpyT35IKDW5Jz8klJrckx8wB58k9+QHheMQuz+DxnGI3Z/B4DjE7s9gcRxi92dwOA6x+zN4HIfY/RkCjkPr/tRt"
    "i+MEYhyB4hB78nWLqzKxJ1+3uCoTe/J1i6sysSdft7gqE3vydYurMrEnX7e4KhN78nWLqzKxJ1+3uCoTe/K1wFWZ2JOvBa7KxJ58LXBVJvbka4"
    "F69iS1J18LneCRxDwmwaOIeWyCRxPzuASPIebxCR5LzBMSPLSeTy3bBI8n5hEJnkDMI3EeYk++lgl9Jvbka5nQZ2JPvpYJfSb25GuZ0GdiT76W"
    "CX0m9uRrmdBnYk++lgl9Jvbka5XQZ2JPvlYJfSb25GuV0GdiT75WCX0m9uRrhXnvJIsnXyuDM0kOJoszKQ4mhzNpDiaPMxkOpoAzMXg5tW5xJs"
    "fBJHAmz8EkcabAwaRQJg5Pvta4jnN48rXGdZzDk681ruMcnnytcR3n8ORrjes4hydfa1zHOTz52uA6zuHJ1wbXcQ5Pvja4jnN48rXBdZzDk68N"
    "ruMcnnxtUJeeIvfka2MTQJIayCWAFDWQTwBpaqCQACJ2emrbJoAsNZBIADlqIJkA8tRAKgEUqIE0DkTtydc2odTUnnxtE0pN7cnXNqHU1J58bR"
    "NKTe3J1zah1NSefO0SSk3tydcuodTUnnztEkpN7cnXLqHU1J587RJKTe3J1y6h1NSefO0wB5+i9uRr53AcYven8zgOsfvTBRyH2P3pWxyH2P3p"
    "BY5D7P70Eschdn96heMQuz+9xnGI3Z/eoDjUnnyPqzK1J9/jqkztyfe4KlN78j2uytSe/ICrMrUnP+CqTO3JD7gqU3vyA67K1J78gKsytSc/4K"
    "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"
    "NA1E7P4BJA1E7P4BNA1E7PEBJAxE5P37Y4ELUn37cJpab25Ps2odTUnnzfJpSa2pPv24RSU3vyfZtQampPvm8TSk3tyfdtQqmpPfm+TSg1tSff"
    "twmlpvbke5FQampPvhcJpab25HuBOfgctSffC4XjSGIcjeMoYhyD42hiHIvjGGIch+NYYhyP4zhinIDj0Lo/vWxxnECMI1AcYk++l7gqE3vyvc"
    "RVmdiT7yWuysSefC9xVSb25HuJqzKxJ99LXJWJPfle4qpM7Mn3EldlYk++V7gqE3vyvcJVmdiT7xWuysSefK9Qz56j9uR7pRM8kpjHJHgUMY9N"
    "8GhiHpfgMcQ8PsFjiXlCgofW8+l1m+DxxDwiwROIeSTOQ+zJ9zqhz8SefK8T+kzsyfc6oc/EnnyvE/pM7Mn3OqHPxJ58rxP6TOzJ9zqhz8SefG"
    "8S+kzsyfcmoc/EnnxvEvpM7Mn3JqHPxJ58bzDvnWPx5HtjcCbJwWRxJsXB5HAmzcHkcSbDwRRwJgYvp7ctzuQ4mATO5DmYJM4UOJgUysThyfcW"
    "13EOT763uI5zePK9xXWcw5PvLa7jHJ58b3Ed5/Dke4vrOIcn3ztcxzk8+d7hOs7hyfcO13EOT753uI5zePK9w3Wc1JP//5y4ftLmwvX10x//37"
    "/+9qdLyr/89V9//mf/v979Mm2Wk2V36HwhWX/+0//+4xvqfjb5d/7ZYjbZb+cXf/nnX/+//g/L8XeP4J9/+vu//vHf//yt/9M/xB//z9/+fv7j"
    "//3Tv/74j//+9e+//fEvfzrC/fbP//nrdzMbfSdG0+l2ttvdNKf6u2Gjy3q02Szmk9F+fplYuWJo9d3Q0dU5WS+Xs+12vSVN+0QX5XzTT5/ImD"
    "wDDyszhrXwsCpjWAcPqzOG9fFhN+vtPmPUeKgc7WZN93B3s5yh4/7G3Ww1na/m+8NokTN29DWdrWbbx2+3vUrv/+V//v7rb//q//WXl6fzv/vX"
    "3/779c34uX3/b518/PWff/7rP3qFaX9uvweLvujb2WjRbF62+WgZZAogm+wHQTuMthlwGtDHgdAyyKLis1/vX59o85Ch3HGP4mG92DeLRTM6PO"
    "b+8kPG73Yw24qbLaqFk+ftdrbaD8GWs16iivqwnf3yPFtNssXp6Q8fR4vbGt+0qRlxqlPc4/jONmZlQzW9mbCyRVX9KEy3PtDvx9XwuOOccQ08"
    "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"
    "3xscc5Yyt87EnO2BofW21yBof6CuicsmINpfF0ThYPLDbROVs7sHBE53wax4tAjg8t/wP2y0vGxSAtDDZmBYNf/fwP1ywwWDdufvcGJgMapYwm"
    "/aUa+cvsMNpmwGkMbswMZzC4CTOcxeAGWHJ5dA5Inw205DLIPEw25iULMNmElQy4+GUz2ErLQBNxE+v0aPbl/SiMV5G8sfF+7scrSt7YeL/1Ld"
    "RQy+b034nXh/S/+PUjmPcnWxSOea04FI55scT1/LiMt8sdY5IuXj/ySjbp7g/Nnrfp7PHj8xYvJhkXMG/xmpJxKfMWFfVJCfOmYLIC5g0SdZcj"
    "6g46mXA5JxMOOplwOScTDjqZcDknE8D9Lq/SPMCCzMijuICg8a9IDyhgATPnBYJWwMwBGljCzCkYrYCJi5uvylhzBmPr54536qKaPC5j0TmMjX"
    "/qfLztSxFTFzA29qkDL3z4mNH20nwvbjPfLy9nolrvq/W+Wu+r9T7Det/pSfNw63V2n9l53//gQt3372jlOfDf0cpz4b+jVSd+eU78/uF0JiT+"
    "JIwUCbwSzfgXeCXa8Zer556tVD9+P3ulevLf2Qr05b+z/W68+eeVUp4//7xSyvPon1fK78Wn3/3i53G5Pv0zXpE+/TNekT795RtdmU79i7VXol"
    "P/Yu2V6NS/WHslOvXPa+935NXv40dnHuuc6Xcw618MPrxb/2Lw4e36r4P3Y1e7/qex6x8fWqmW/TNcgbb9M1yB1v0zXIn2/Z7u1etdpoP/gq9I"
    "E/8FX5E+/hNfh1emk/949lqsm/9MV6Kj/0xXoqv/TFeks7/DK9ncf4FXor//Au/3Y/F//dHFmvwv8Eq0+V/gMS2ZS9OMvNE0M/paTTPVNFNNM9"
    "U0M4xpZvT1d2aa6X5wqaaZN7QCTTNvaAWaZt7QqmmmQNNM93BKNs2c8Yo0zZzxqmnmdtNMN3vFmmbe2Eo0zbyx/X5MM+8rpUDTzPtKKdA0875S"
    "fjemmdHXok0z73hlmmbe8app5gOmmfPaK9I0c157RZpmzmuvmmZKMc108eN+ppnz4HcwzZwHv4Np5jh4Nc18LtNM/9CKNc28w5VomnmHK9E08w"
    "5XpGmmoyvaNHPmK9M0c+Yr0zTzyleuaaY/ey3XNPNOV6Rp5p2uSNPMO12ZppnR16JNM2e8Ik0zZ7zfkWnm+KPLNc2c8Yo0zZzxCjDNqNtMM7PV"
    "5bW51TVTXTPVNVNdMxmumdebuPsNkshOfIxyruOWOJ3kpVM4neKl0zid5qUzCF33SbjIXnhZ18DbBJ1kpXMJOsVK5xN0mpUu4HSTAQRvm8EXtx"
    "ld8ElmPpHgU8x8MsGnmfnim8zuS3U6W7J6NuMmozcyTstm3GL0Rsbp2IwbjN7IOA2blPaiftSchJOEDJsyx7CpoESvykn0xs04my9NCa9w3NNz"
    "Acf5FscdPRdwnC9y3M9zAcf5LivoVrNFn6Pv8Tgzdwq81mwwuqzMjoIuNhsQL4POxxfe69Nlf7bx+yAOj83m4biXz7EZEBpx+lHF8HfMfnld5d"
    "xPKW7hOT+l4R08/XzqT2Ld2Xw5vuvsb3rcAnR6Sh3iJ/EB9aPmbMuAi2q3s+lRUDpNLvC22hPdZAi6PJuCBPlOEY1njV8mr/TVyavxZKlld0Z+"
    "mYqq2auavarZq5q9ysheHX0fT624wydbJ3hZNd8nNMmLphA0xYumETTNi2YQNMOLZhE0y4vmEDTHi+YRNM+LFhC0wIoWT1C9oomWFw2JBoI3Gk"
    "gkGgjeaCCRaCB4o4FEooHgjQYSiQaCNxpIJBoI3mggkWggeKOBRKKB4I0GEokGgjcaKCQaSN5ooJBoIHmjgUKigeSNBgqJBpI3GigkGkjeaKCQ"
    "aCB5o4FCooHkjQYKiQaSNxooJBpI3migkGggeaOBRqKB4o0GGokGijcaaCQaKN5ooJFooHijgUaigeKNBhqJBoo3GmgkGijeaKCRaKB4o4FGoo"
    "HijQYaiQaKNxoYJBpo3mhgkGigeaOBQaKB5o0G8R4NL6Ptar567PLjj5GZ+8uv//Xrb3/6W5RPRtOMo8VouwQyjav1dtkljK7ozHBBJVmoTIJK"
    "sVDF5X8733f55wXbE3QJKp4n6BNUPE8wXr+y3fZrar7bz7ZDUD2Mnhd7kOqPD90fr+ix0Ne5t0PgXO88sJD9zwpiEKjlt5XEIAoCUcQgt/RCuC"
    "sIZD60hhgEajVmLTEIVCxiHTEIZGS0nhgkQOEbcJbcX/ldiyGxhEgnMCSW+OgkhqRZkBSGZFiQNIZkWZAMhuRYkCyG5FmQHIYUWJA8giRaFiRM"
    "vQWLentMvQWLentMvQWLentMvQWLentMvQWLentMvQWLentMvQWLentMvQWLentMvQWLentMvSWLentMvSWLegdMvSWLegdMvSWLegdMvSWLeg"
    "dMvSWLegdMvSWLegdMvSWLegdMvSWLegdMvSWLegdMvRWLegdMvRWLeosWk28leZgw/VaKhwkTcKV5mDAFV4aHCZNwZXmYMA1XjocJE3HleZgw"
    "FVeBhwmTcd3yMGE6rnl0XGA6rnl0XEAZRyGIU44CvmZYSGoUBaIoahQNomhqFAOiGGoUC6JYapR4Y5T+RWRLtol4ceg7FJPWBBSKZ9MYLwh9h+"
    "LZNcZLQd+heLaN8SLQdyiefWO8/PMdimfjGC/8fIfi2TnGSz7foXi2jvFizzconvSbkKii8yTghEQVnScFJySq6DxJOKFQRedJwwmFKjpPIk4o"
    "VNF5UnFCoYrOk4wTClV0nnScUKii8yTkhEIVnSclJxSq6DxJOaFQRedJywmFKjpPYk5oVNF5UnNCo4rOk5wTGlV0nvSc0Kii8yTohEYVnSdFJz"
    "Sq6DxJOqFRRedJ0wmNKjpTok6jis6UqdOoojOl6gyq6Ey5OoMqOlOyzqCKzpStM6iiM6XrDKroTPk6gyo6U8LOoIrOlLEzqKIzpewMquhMOTsD"
    "dTbv/0Kb/AArJwV16aQAaycFdfGkAKsnBXX5pADrJwV1AaUAKygFdQmlAGsoZ/ucDt8CLImc7WXWuA4cV2WN68Fxdda4ARzX5IzrWnBc+5FxL/"
    "v+mxv7/m+/7P5Q+/7Xvv+173/t+z9I3/9OUZrd/A+zGzv/60Eva4ubsN7RJCeaQtEUJ5pG0TQnmkHRDCeaRdEsJ5pD0RwnmkfRPCdaQNECI1rc"
    "5vWGdmPn/4HR0GggOKOBRKOB4IwGEo0GgjMaSDQaCM5oINFoIDijgUSjgeCMBhKNBoIzGkg0GgjOaCDRaCA4o4FCo4HkjAYKjQaSMxooNBpIzm"
    "ig0GggOaOBQqOB5IwGCo0GkjMaKDQaSM5ooNBoIDmjgUKjgeSMBgqNBpIzGmg0GijOaKDRaKA4o4FGo4HijAYajQaKMxpoNBoozmig0WigOKOB"
    "RqOB4owGGo0GijMaaDQaKM5ooNFooDijgUGjgeaMBgaNBpozGhg0GmiWaHCZ3bW3ZXf3T9vdU83u1uxuze7W7O4g2d2X7Wr/tF5Mm/z07mayHz"
    "rBe6aTvHQKp1O8dBqn07x0BqczvHQWp7O8dA6nc7x0HqfzvHQBpwusdPHE7ztdfuY3jw6PFYI3Vkg8VgjeWCHxWCF4Y4XEY4XgjRUSjxWCN1ZI"
    "PFYI3lgh8VgheGOFxGOF4I0VEo8VgjdWKDxWSN5YofBYIXljhcJjheSNFQqPFZI3Vig8VkjeWKHwWCF5Y4XCY4XkjRUKjxWSN1YoPFZI3lih8F"
    "gheWOFxmOF4o0VGo8VijdWaDxWKN5YofFYoXhjhcZjheKNFRqPFYo3Vmg8VijeWKHxWKF4Y4XGY4XijRUajxWKN1YYPFZo3lhh8FiheWOFwWOF"
    "5o0VUCOU7bKIZA/UEuUdj3n2TAKPN9RCbVLe8XhjLdQw5R2PN9hCrVPe8XijrQkJPN5wa9sEHm+8tSKBxxtwrcTxmLM+NhE1mNM+NhE1mPM+Nh"
    "E1mBM/NhE1mDM/NhE1mFM/NhE1mHM/NhE1mJM/LhE1mLM/LhE1mNM/LhE1mPM/LhE1mBNALhE1mDNALhE1mFNALhE1mHNALhE1mJNALhE1mLNA"
    "LhE1mNNAPhE1mPNAPhE1mBNBPhE1mDNBPhE1mFNBPhE1mHNBPhE1mJNBPhE1mLNBPhE1mNNBPhE1mPNBPhE1mBNCIRE1mDNCIRE1mFNCIRE1mH"
    "NCIRE1mJNCIRE1uLJClxWH7saKw+V08a1WHNaKw1pxWCsOB6s47DRlgBz07lKAhis4PMJJXjiFwileOI3CaV44g8IZXjiLwlleOIfCOV44j8J5"
    "XriAwgVWOLjQsIfLzzjnwaERQvBGCIlGCMEbISQaIQRvhJBohBC8EUKiEULwRgiJRgjBGyEkGiEEb4SQaIQQvBFCohFC8EYIhUYIyRshFBohJG"
    "+EUGiEkLwRQqERQvJGCIVGCMkbIRQaISRvhFBohJC8EUKhEULyRgiFRgjJGyEUGiEkb4TQaIRQvBFCoxFC8UYIjUYIxRshNBohFG+E0GiEULwR"
    "QqMRQvFGCI1GCMUbITQaIRRvhNBohFC8EUKjEULxRgiDRgjNGyEMGiE0b4QwaITQvBECqSMsIIWDlBEWkMNBqggLSOIgRYQFZHGQGsIC0jhICW"
    "EBeRykgrCARA5SQFhAJgepHywglYOUDxaQy7F4rGBO5lg8VjBncyweK5jTORaPFcz5HIvHCuaEjsVjBXNGx+Kxgjml4/BYwZzTcXisYE7qODxW"
    "MGd1HB4rmNM6Do8VzHkdh8cK5sSOw2MFc2bH4bGCObXj8FjBnNtxeKxgTu54PFYwZ3c8HiuY0zsejxXM+R2PxwrmBI/HYwVzhsfjsYI5xePxWM"
    "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"
    "RJ8Fgz5bRJ8Fgz5bRJ8lgz5bRJ8lgz5bRJ8lgz5bRJ8lgz5bRJ8lgz5bRJ8lgz5bRJ8lgz5bRJ8lgz47RJ8lgz47RJ8lgz47RJ8Vgz47RJ8Vgz"
    "47RJ8Vgz7Hi8cny2nT2frIHTjOojTEZ2POoTTEWQnnURrivIQLKA1xZsK3KA1xbsILlIY4O+ElSkOcn/AKpSHOUHiN0VB7cjyqxdSuHI9qMbUv"
    "x6NaTO3M8agWU3tzPKrF1O6cgGoxtT8noFpM7dAJqBZTe3QCqsXULp2AajG1TyegWkzt1AmoFlN7dQKqxdRunYBqMbVfJ6BaTO3YES0qxtSmHd"
    "Giakzt2xEtKsfU1h3RonpM7d4RLSrI1AYe0aKKTO3hES0qyWQ2nsuiTXNr0aasRZu1aLMWbdaizQGLNpUqp2hT6XKKNpUpp2hT2XKKNpUrp2hT"
    "+XKKNlUop2hTt+UUbWpRTtGmluUUbWpVTtGm1uUUbWpTTtGmtuUUbWpXTtGm9uUUbepQTtGmacsp2jSinKJNI8sp2jSqnKJNo8sp2jSmnKJNY8"
    "sp2jSunKJN48sp2jShnKJN25ZTtGlFOUWbVpZTtGlVOUWbVpdTtKlUWUWbSpdVtKlMWUWbypZVtKlcWUWbypdVtKlCWUWbui2raFOLsoo2tSyr"
    "aFOrsoo2tS6raFObsoo2tS2raFO7soo2tS+raFOHsoo2TVtW0aYRZRVtGllW0aZRZRVtGl1W0aYxZRVtGltW0aZxZRVtGl9W0aYJZRVt2rasok"
    "0ryiratLKsok2ryiratLq0ok1qBw5etEntwcGLNqldOHjRJrUPBy/apHbi4EWb1F4cvGiT2o2DF21S+3Hwok1qRw5etEntycGLNqldOXjRJrUv"
    "By/apHbm4EWb1N4cvGiT2p2DF21S+3Pwok1qhw5etEnt0cGLNqldOnjRJrVPBy/apHbq4EWb1F4dvGiT2q2DF21S+3Xwok3jiiraNL6ook0Tii"
    "ratG1RRZtWFFW0SW3gSRRtUnt4EkWbZDaey6JNe0PR5nj7pavBrEWbtWizFm3Wos1BijbH21aQrvd4vWaHIWkxFIChaDE0gKFpMQyAYWgxLIBh"
    "aTEcgOFoMTyA4WkxAoARSDHidZjjbaxJ3z0xABUVtCoqARUVtCoqARUVtCoqARUVtCoqARUVtCoqARUVtCoqARUVtCoqARUVtCoqARUVtCqqAB"
    "WVtCqqABWVtCqqwKOk+LaYvpbyxCJLqKU8sagSailPLLqEWsoTiymhlvLEYkuopTyxuBJqKU8svoRayhNLKKGW8pWFutG1RnSXus21RnSXusm1"
    "RnSXusW1RnSXusG1RnSXur21RnSXurm1RnSXurW1RnSXurG1QXSXuq21QXSXuqm1QXSXuqV1vEZytx/tm4HOpB9G8wVAs1pvl91h+hVFkm9Akg"
    "HIYECKAchiQJoByGFAhgHIY0CWAShgQI4eKF4q+QbkGYAEBhQYgCQCNMhp961AmFILBqW2mFILBqW2mFILBqW2mFILBqW2mFILBqW2mFILBqW2"
    "mFILBqV2mFILBqV2mFILBqV2mFJLBqV2mFJLBqWOF05uOmPYUJv8b7MdyHNN0eQbi6RlsRiLomVxGIumZfEYi6FlCRiLJWWJl0q+sThaFoGxeF"
    "oWibEEWhaFsAyyb7+BBdNdQau7HtNdQau7HtNdQau7HtNdQau7HtNdQau7HtNdQau7AdNdQau7AdNdQau7AdNdQau7AdNdSau7AdNdSaS7l9Ul"
    "4Zrqks3St22tKqlVJbWqpFaVDFJVMnnebmerfTO67W16/y//8/dff/vX8cU8/6t//e2/X1+Nn9v3/9bpx1//+ee//qOXmPbn9opCkzeyMSeZws"
    "gmnGQaI1txkkWlp4sFN+5O1RUFJ2+/V204f7CDfrDL+cEe+MHN82qc/7puJvt//8Xtz+K6XxwwtjErW7z65I1twssmMLbl6CsvXVSGD+tFFx2y"
    "n+nh4+9XvHTlyDWecHJpkGsy4uQyINdi0YwOj5xsFl5jK04uB68xVi4PrzFWrgByrbaMXPGqmde1v2Je+/FSmiPbMaTzxk0lUboxb+RUCqWb8O"
    "6HlEbpuAO7MvjCW/HSWXzhMdM5fOEx03mUbrFa8uIF4MtIhYwvo3itTjeqbnNGFdCoImfU+PH7+mW2zf+G+/Ly8WAUL6Z5BRuzgmkYbMIKZmCw"
    "/POHLDIbX7qjSbN5GWKdHUbbDDqH0o2Z6TxKN2GmCyjdAMsuCy9evdOlaAZbdxlsAmMb87JJjG3Cy6YwtkFWXAZcPDg83LrWrqje6QYd5wxqgU"
    "EnOYM6YNBbH8sVpTCjbg+ZO7EBGThncuOlKaeBcyY4XmJyGjhrkuO1ItPdJneS4zUfp4GzJlkjA2dNskEGzptkCzy+IebZ4WNnTbXHx86a7YCP"
    "nTXhDvoUczmfYg76FHM5n2LxGoB+VJkzqoJGVTmjRt+9h+3sl+fZavItNwY//SH2Td9e91Efd+fvn6ZNn8jiPYiLu/Xf2HgPWOPu/Tc23uPVuJ"
    "v/jY33jCvu7n9je2Rl85D++Rz985D++Rz9izvw+3kcKP2WN5MKpWM+BY679N/pmE+BvUHpHpnpLL7ueFXZO3zd8eqy9/i64422cf//bPX4rdku"
    "5qtG5NK9PH38qCBeEHCGy9n0xQ3+57Fztn5xw/55bJ0ztoLHHg3xwLrTxJxHpnG8rEdm8LGzHpnFx856ZA5ZDuvnPe875nG4rAcW8LFzHhhwb8"
    "95cJ01OKIOoyEeWd5bBlzLc+aTWT9e4YPnPTaND5732BCFWOzXvG8acB/OmS7voTl88LyH5vHB8x4aohKjIR5a5rsmWpwv67EJgQ+e9diExAfP"
    "emwCVoku0zTAQ8t6ZhqDy3tiBhs673lZbOi8pxWVh+77Y7rsXuE+L8jpfhDxSolNMXjxA/hDIXgSKJwuBS9eS/2lFDwoqdD/JeOVkwocN0sl4j"
    "ULx3GzJEKCRV8yq+pLAv2ES3n8UEL+g3g/jB73Jo0G/PFZ9h8RrwIYbQYFzKnehI7n+79kPJi4k/8UEEcFPJi4mX9TEKBCgmIRgBoJi0UAGiQw"
    "FgFowZfPZr18YLmtyqq3VR4c12eNG8Bxc1zwArqyopgFEHfUn4LjKDc4xp31XdQZ7ufn7Ay0QkLjiD80anAjqLM2gnGX/GtoHG0K+N0WjoxF8D"
    "k4MBbB5+G4WARfgMNiCXwG3JKarC2pEeC4Imtc8APXZH3gGvAD12R94BoNR8Uinr+Bg+JH+H4Y3cJBcaBfnxMU4/7116A42MP5yJblohHbxbYK"
    "acS2m3UxfBnU16+1G1vtxla7sdVubIN0Yzv0TSru0KLi6sZOEqIac1IpiGrCSaXBJ3iXNiNXc8W7PfStf1gfooWwxqxP0UFYE9YX0YMPkXdxRe"
    "V2fpf2kXkd3+Z3aRyZ1+ltfpeWkXn93eZDrKgcqri49/1LFowLPZ4onQ+ClTNbBioMu09NmMjo6rZ5arazQ8Z3QTy7+uXlPp1Trv6xHqAas1IF"
    "gGrCSRVPwHZUnYGMlSsqz/3hwb26peS1YTuSjZnJFEg2YSbTINkQ6yyPzQBsd2qPktd1reca83I5iGvCy+UhrmGW2NBN1roT5V1Wv4N4evk47H"
    "jwNmvHYSfD91k7TsKt29sr+qT1EWzKGcA0InlTXsXToOINQpYBZsFH2Sy/sj5NhzzNIdjyHigsfQPBZbAF8BBuALSM70cDHEoMgZUxX/E08euG"
    "nPklMPDOd8/+DhgFvgPcr4ABe8UMQJZzKmAM8m6uON9NC76bK85308EPcsX6IIETj6dmvhyg8WlGrZYJENnsKy+ZbSGyQY4+csgERLaaMZOBEW"
    "CYlZZXy2kVTDfEasuk0zDdQIcgOXQGphti1WXSQWchTwOA5XDFc5Oi6RvALO9zp8DVbPEEpSyCLf5RoEpgi3dMnBfxTON9F+dFPNN498Z5Gc8U"
    "igxDBYanTEujuMHS6OoFs9XSWC2N1dJYLY3V0lgtjdXSWC2N1dJYLY3V0lgtjf1kac6Zqn7I6oesfsjqh6x+yOqHrH7I6ocsxg95/IrjNVxpDX"
    "4K8FquAD9kCZYrbbFAwW88dIjGsDsPfaG2K8gSuWC3XbXIG7oqzhRZgvFKAtKxe2F1n8NuyCHAhjdDHhVtGLTt0H7I16fJ7b21yANlN7g67Jny"
    "W4OrO7K6I6s7srojqzuyuiOrO7K6I6s78nO5I+UN7khT3ZHVHVndkdUdWd2R1R1Z3ZHVHVndkdUdWd2R1R1Z3ZHVHVndkdUdWd2R1R1Z3ZHVHV"
    "ndkdUdWd2R1R1Z3ZHVHVndkdUdWd2R1R1Z3ZHnq0H6fF3e7SCwu5Hbdwm7G9l9l6JY36Us1nepivZd6qJ9l6Zo36Ut2nfpCvVd+oJ9l6Fc32Xc"
    "21iI71IU7LuUBfsuVYG+y0tvo7rB2yirt7F6G6u3sXobq7exehurt7F6G6u3sXobq7cx39s4b6azJScVkPzdfOEGMwXaCC2t4bLNcTcOYFmIGx"
    "SzDSEy3MUQotq7GEKUoHUeXnu+gPj77uZVu5pNUXucribTlE7gq6kMpRP4aipL6QS+mspRO26vJvPUjturyQK14/Zasrg58H6u1qu5BK2r9Wou"
    "SetqvZoLugt7gF1kjlpoSO+H2eBmoYEJ0EHI8l5L0NYyDFoGGSz/Az3SvIkD3d2D0WXAgbaY6WzB244MtMVsZxNeMgEbAYaYtTwjgEEafw0xc5"
    "l0cHuXYb4Dctg0bFW4S24282psyQ9mYZMCL5iDHQq8YB62J/CCBdibwApmIac782mkBY65x9xcwFH3hJtLQc+R/WDZauhR8qMZ6Gnyo1logzZi"
    "3zwCbsiObczPBnYAnvCzBfiZcm+7XQs/U3Y2AT9Tdra4saXZTUaLWY5VKiroo/xx42qs8weOaunmZZs/clQKO3nuEk3z1f6QM7SDhu4HXuTYGl"
    "1UiGarx2/dms2zj7l4Pu9L0892N3iOla4Fhj5uCHMHj77H602OAdLL+Jgfcj9eunX19W5dXe9pr27d6tatbt3B3Lqje1S/X7ulAby6Y1amuFN3"
    "wsoUP9G8ixn2aqb4YeZdnLBXM8XPMe9ig72aKSpuo+XmHn7Tq6E8ADXmhAoA1IQRKu7M7aBWnFDAZypnzluC+SretK0E7AvMFoG4O7f7rHoY5V"
    "gaJfRt/LBY5Axri+xHGpfW568HRr2PO2tHh04yppySAZ0IPrAeakHNP5+2vFiwNYA58Q56g3m9t/Gk0Gqz06Rf03EP8Gi3H+1pOaIyvJq9zA4r"
    "WhALgCyXtBzx48/56PGBlsMD83HjUVU2R1SOuxMz3dIeP7UQh6DliArubtN9PZFiSGg6FC2HinMsiJ+KBjAkLYYBMIgfioWCHPFTcRAH8WPxEA"
    "fRc7lMophbkiiyJlFqEqUmUWoSpSZRahKlJlE+bRKF96QPTKKMSkyijEtMokyKS6JwZ3YkADXlXFTxHEpPxbqqNETFuqzMvXJzGafG0t4xCZbD"
    "Bfm7eal8kUkJGcrMsALdWXJTmfEcTHYqM55AYe/0A2RQxI1VW/dJoMwlNUb801tRYwBNr6kxgP7WxBgaaGVNjQGYX6a7lwJyBV9eNtQcaoiM8H"
    "1SBbdnzO+TK5hvxG5fQrJgI6k5gGNBRc3hocyap+UAE6+BlMNAiVdDmwCON8HoOWiTWgbKvBrapJZREAdtstFoiIPWUWMMxGFoOSzEYWk5HMRB"
    "61QwkJ4aWj01kJ4aWj21kJ5aWj21AnJuEAdcKyHvBjUI5GWh3oJYSFItraRaSFItraRaSFItraRaSFItraRaSFItraRaSFItraQ6SFIdraQ6aI"
    "vqaLeoDtqiOtotqoO2qI52i+ogPXW0euogPXW0euogPXWW3g9nb/DDqdpUoPrhqh+u+uEG8sNlp/7ilrbs1B/gShsV6Erjde+ZAt17tkD3nivQ"
    "vecLdO+FAo1yoCdtXKInbVKcJ42528Bnqupfjr52ZKxcpkif1SfqKsBdYS19Yeavy49Nd+3HZl+IPZ803efjpn5x1i/O+sVZvzgH+eLkLrqQJb"
    "bTUgXuJQXk2X9ccXbHAb54m1GBn7wN79lA/Ju34T0c8MDjGxf31XtoWI8H4l+9h4b1fOATtbNj/8BURX7I6TILZkyhLQntfXr/uSI/p6PaPN5+"
    "mayy7wmbfJssLvvED1NRtZyvprTmeQU4LZb77YYWJN7f4Hk1vnHTng0Sld/n1fRAixGV2/VheyigKqubjZtf7vsUZnUTQk8CuC0OnY4W0NquE7"
    "jNeldAtVp3+EytZlFVne422/W+gIK1yaR7NqMCStYmm6fncQEla5PnbSfwBdSsdYe8m3EJZWvdAnkYzRcFFK7t9rdehHOfwrXFetIdLBfR5m63"
    "H28KKF3r9yL7AkrX+s3IvoDSted+B7AvoHZtzQAi4b3IvoDytcV+81xA9VofaMb7AsrX/rBezRZfCqhfO6wXe/Ipierq48O+gPq13dN2vy+gfm"
    "2xXx8WBdSv7fbPm2kB9Wv9vYrbbQH1aw+rL+QgUUmdzSZrahAN3PO4flgUUMDWfd5NyJ8NVHIhyqhgkwUUsHXN7afE1x/EK9i6do3b2aKAErZ1"
    "txHZbQqoYeuS3j1LAVVsK3oOBW4RqZ8NdLp6oAaJuxDoJ8TGPzS7zSoVyaW70F/tLhwtl7vqK6y+wuorrL7CQXyF3cH4fr6cZefPt7uhzYWdk3"
    "q73w1eDNc7s7NGjb6w+2V/jJ2d7t9divgwFr+XLte/ny03uWibyX5oo99kvdrTfsbEvX09B+13DNBY/Xm/mNEehsQtfN0/owaJ2/aeRqspOQnQ"
    "jOPwRE4SPyB6mS7ISVRcodf060RDbzBta5C48+6Rfj7iyrp5pieJauvsax9wyVk8+OlNjgLkNBdTcrGPm/Dmq8mOnCSqsfPlhn5OIMNIc49ymz"
    "brttmeasxJBeU8mwknlYGo7lNxczWXjcfMzfphvF8VYODrPrDWK3KUqDIvOkfDgRwlqsxPqyk1SNzF1/0zchABfJaQg4C31Moibqklvy0XakSn"
    "dRH31O60KcDCt13u5xtdgIXvCKJK6D7fg8gS2s/3IKL2ny+u/3x/+CtYjy3jhr6eq5G8YBr6cpssck6QwYbzrgC/3mK9W0xnqwL8ev+rq5mnBo"
    "mK6GzZPRtqkqiKduUUqzExSdy21+0J11tqEhFPjvVFpSV0nu8+Nx+opwTan1pVG8/XxvO18XxtPP8B095oOd7nJ4yns8fmIbb78tHdl5Kxvmvh"
    "amfUuPZcq96o6o2q3qjhvFFdDuE+aaA8Y9QRq7y+a0es8jqvHbGK7L3WmY2LbL/Wc5XYga3nKrEJ2/E5FtiH7fgcC2zFdnyO5XVj6+vuX0b7bA"
    "/n4C3ZOrCe6zmncZZCBp7mDKyBgQdoQZbXgczAYFkzaeFxp4O3NjuOmz+PQzflPmJlzSJ0X8JugO6DGT837pAaoiVihirEzVI9VM4jiBuf+lFz"
    "lnHcuPTwkt++MadNYty41FNlzSBw2Hhg/rEWxMr6tfHeiy+d7j0NoPQ5P9jDZFm/GDgsPPD/ZN0iaDm/WcPXXeWMCt52NcoRm7g7px92nDOqBk"
    "fNgjXQsDkdUTXYaHWSBVtko1XtB+pDqK5wrPQN9xfLAhwr3dkFOQh0BQE9CdCkmpwDuo2JHEQDHZ/JQcDW0+QkcQ18WNA/HAeQPJKT+Hg53XZJ"
    "PylQztWEAowsfe63LcDG0nOIAkwsPYesHpbiPCwrhv1I3MXSt0onJ3FQAxtyEqBV6pieBCgsJAeBzCwH+m2ag/ql/kJOIoEWsvQkkL46VUATqp"
    "5DF9CDqucwBfSg6jloPYIO8gg6Wo+ggzyCjtYj6KD9qqPdr3pov+pp96s+qqmzw2yV1Z3Hx5v+fOv93IvHnIHj9SRP0ybnCNNraNScs0ZvoFFz"
    "DgW9hUb9kC/wwo95cUKV8GMuJptmM1pddsOsjszqyKyOzOrIzOlWt/jWRtbZX379r19/+9PfosPK3A5ZEgKRxCAKAlHEIBoC0cQgBgIxxCAWAr"
    "HEIA4CccQgHgLxxCABAgm0IHEzZAciWmIQSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbJKSFkFsbIqSFkl"
    "sbIqSFklsbIqSFklsbIqSFklsbIqSFklsbIqSFklsbIqSFklsbIqSFklsbIqSFklsbIqSFklsbJqSFkVsbJqSFkVsbJqSFkVsbICnenm1McjQG"
    "e6OfXpCNCZbk59OAJ0pptTn40Ajenm1EcjQF+6OfXJCNCWbk59MAJ0pZtTn4sAXenm1MciwMWyc+pTEQPoKfWhiAH0lPpMBGhSN6c+EjGAnlKf"
    "iBhAT6kPRAygp9TnIYCrd059HAK4eufUpyGAq3dOfRgCuHrn1GchgKt3Tn0UArh659QnIUBnujn1QQjQmW5OfQ4CdKabUx+DAJ3p5tSnIEBnuj"
    "n1IQhg5p1Tn4E4QE+pj0AcoKfUJyCAi3dOfQACuHjn1OcfgIt3roj1FHDxzhWxngIu3rki1lPAxTtXxHoKuHjnilhPARfvXBHrqQf0VBHrqQf0"
    "VBPrqQf0VBPrqQf0VBPrqQf0VBPrqQf0VBPrqQf0VBPrqQf0VBPrqQf0VBPraQD0VBPraQD0VBPraQD01BDraQD01BDraQD01BDraQD01BDraQ"
    "D01BDraQD01BDraQD01BDraQD01FAbdVtAUA21UbcFFNUEahBAUm1LDQJoqqUugWgBUbXUJRAtoKqWugSijZcWtcTX2bfxUqSW+Db7Nl661Cpi"
    "jBDHoK0vF/GyqKjz4q4Y8S7HrSXGiPc0bh0xRrwDcuuJMeIFlG0gxogXXIqWGCOuooJYReNVU1HLxV0x4ioqiFU0XjEVNVzcEyNeLxX1W9wVI6"
    "6iglhFgc7wglhFgT7yglhFga7zglhFgR7zklhFgZb0klhFgQ72klhFgY71klhF49VRUZvFPTHitVFRl8VdMeIqKolVNF4XFfVY3BUjrqKSWEXj"
    "NVFRh8VdMeIqqohVNF4PFfVX3BUjrqKKSEUve/2IW3r9PC7W41Ft9lOb/dRmP7XZzzDNfvbzZRnNfnqQIpr99CBFNPvpQYpo9tODFNHspwcpot"
    "lPD1JEs58epIhmPz1IEc1+OpAymv30IEU0++lBimj204MU0eynBymi2U8PUkSznx6kiGY/PUgRzX56kCKa/fQgRTT76UDKaPbTgxTR7KcHKaLZ"
    "Tw9SRLOfHqSIZj89SBHNfnqQIpr99CBFNPvpQYpo9tODFNHspwMpo9lPD1JEs58epIhmPz2IKqHbTw+iS2j304OYEvr99CC2hIY/PYgroeNPD+"
    "JLaPnTg4QSev50INRFbwZSVuqqNwMpK3XZm4GUlbruzUDKSl34ZiBlpa58M5CyUpe+GUhZqWvfDKSs1MVvBlJW6uo3CykrdfmbhZSVuv7NQspK"
    "XQBnIWWlroCzkLJSl8BZSFmpa+AspKzURXAWUlbqKjgLKSt1FZyFlJW6Cs5BykpdBecgZaWugnOQslJXwTlIWamr4BykrJZKWS/taupau9rLoh"
    "lvZ6Mvs221q1W7WrWrVbvaIHa1edPdAn7bsOr9v/zP33/97V/9v95MLn71v/72369vxs/t+3/r5OOv//zzX//RK0z7c3uFfW06WzbzRm1y0UYZ"
    "YAoGWwhOMI2ASU4wg4ApTrC4cDE/RgdAsT5CD0CxPr54XRKvPAC1nrdeVzwsEyDyj5xMUX0/8AeeuKnu0InCAK/gIYNLA1xygLcwh8sAXGoAHc"
    "3hsuBzXHFiOfAxsmJ58CmyYgVo69ChLRjB4t69ExjnjMW9fN0HcrN52Tb79T6X7cshQ/WB2/xmo8VgeC8ZdAqly5ezLDiNw0lWOIPDKVa4eN/A"
    "2WTAV2KbgecgKennbzPAdjZr8jxOx/xShAQd61uh2wQd62sR9yb2dF20GGTZ5UQKLbE4NsCqy4JTKJzkhdMonOKFM+ii436uFqdjfrAOp2N+sk"
    "igmAwkJxlRFrg0cTaaDCcoGXjAXYrveJIZT+B4ihkP/qyYrR6/NQ8vuXzLl6cMPIXjbQ+8eBp8uEPNXvd0cwANDjjA/GUCgnFj85CRkI67NTcP"
    "N6vVFdbLflSZM2qARlUZo8ZNkQ/b2S85g0bFbLz90qdqSdP8cYfjkWRFC6IgkM4ostnMprQ0GqLp3vnpN1oWA7Hs9tvHZrd5pMWxEM7o+Ws3PQ"
    "vaHl9x1+MFDm3HROAGxNmudbTt+eLex35eNutdM57vaR9T3AF5gUP7mIALEbvHZGlbWwI3IvYgtM0tgSsRexDa9pbAnYg9CO0bBFyK2IPQtrgE"
    "bkXsQWibXMavRdy9NKPJvnluFtOMLVH8qsPT2P0WYJczeEAG7/yVm0XG4PFLCdeb5mmbw+xBifI5e28PCo7P2XzHbwDcPXWWxuynF7/Vb31YTP"
    "OHjr7jj6tp85A/NujtapZzTjOOdzDY6CsnGOTxktwzFmAw1hkLLeSKY56xIGAw3hmTgDuOe8IUyMU7Xxpw7nHPlwG5eOfLYq5x7klzOBzvzHkY"
    "jnnaAkLGOmfAhYMnr+gQ03bIgRMoXP7MZcFJxM3KPnMKhWOeOY34bdlnzqBwzDOHOILZJ85hbMzz5mHLMvu8BYyNd95EC3uquedNCIyNed4kkE"
    "q8ec6uuTexH/fW33vNRYjvvpwBnnSWMUcI3HM1wNPO5LOoTXKI+XvJwcP9uUNMXxYeZtCdbIZZfdscwIADDrL8cgAlaDIY4t14+sO/o3UI4ko2"
    "AbPlP9lMtqhOz/bPzctou2qo76ONF+6dcUIJFzu+41DfTxsv0zvjiBIuejzjyBIufDzjqBIufjzj6BIugDzjmBIugjy/6G0JF0KecUQJF0OecW"
    "QJF0SecVQJF0WecXQJF0aecUwJF0eecWwJF0iecajvOoXcZUJRX3caQBLiXY5uIRJNLMNagCTECqwlSEIsvlqBJMS6qzVIQiy52oAkxGqrQbXt"
    "zS/k+xjtcBzqt8jjONSvUsBxiN8n0+I4xC+VETgO8ZtlJI5DvI8xCsch3sfE672Ws/0Jh3gzE6/uOuMQ72jitVzvONTnNvEasDMOsSrHi8fOOM"
    "SqHK86O+MQq3K8XO2MQ6zK8UK3Mw6xKser3c4vOvGbFa95O+MQv1k2ocrEb5ZNqDL1m4WrMvV+x+KqTL3fsbgqU+93LK7K1PudePVbf4QkiSUn"
    "Xvh2JCFWm3jl25GEWGjipW9HEmKNide+HUmI5SVe/HYkIVaWePXbkYRYVOLlb0cSaj3xEAn1x0G8su5IQqwnHtRY6k8CD2os9deABzWW+kPAgx"
    "pL/Q3gQY0VxHriQY0VxHrioQrj/i+0JA4koZ4TMNfmiY+nPJhr88QnUwHMtQXiuBPAXFsgjjsBzLUF4rgTwFxbII47AdRYRb1OQI1V1OsE3Mcq"
    "6nUC7mMV9ToB97GKeH8SwH2sot2fyBbcxypLTALuYxVRLL68kS5ceyPdtMtq9XemjVbTeiVdvZKuXklXr6Qb5Eq6Tle6dZ+z0oAb5Y7jfmipXe"
    "jjxYYY0cfDaLJeNYeHgZTxuzOeqoxVGasy/h6VcaieqKs1sOC/zXY/XaGk2+chetZ+N8p3GLv9evPTNVdxzruG85P5IB10t7MDQPPwMv3pius3"
    "H0bPi/0AID+M8x3Kav3Hh+6PV9y52X89zFdDdKztR7oc6HuF/PLTFfdsbmcPzcP2l74I9GkAov32eQY9q9FiN/vpils2l/tts+56+s4GaXh8Ix"
    "F04nkQg5x4bmbQizVZrHezH1dzAGkCPY2ETj4Pw2Twb6QRII1goJEgjWSgUSCNYqDRII1moDEgjWGgsSCNZaBxII1joAG1WDJosQS1WDJosQK1"
    "WDFosQK1WDFosQK1WDFosQK1WDFosQK1WDFosQK1WDFosQK1WDFosQK1WDFoMVh1e1AMWgxW3h4UgxbHq28fxk13ZLigPQOL6vBmtJotGGCALs"
    "PrLjO12m/XxDTxyyK73ve3f2hee9n91U184nW5x/5C6+c9a3+heKHucr1fb4eZue1mOfRVka908zv0pG1/FhmXRL5ydf/3y+WRxKALTmTcEvmK"
    "190kyMsWYLbDHRoiXssVr/WdTprFfPXlLmR510L20tYdSHZiO53l3CgXVfHJctp0Z8TN8TT43wb/y6//9etvf/pbdHQZ1fHdfrTdX33iHK/k7Z"
    "m6U+chcG44cI6X8R7nZ7cfhuW7VMgPZ87bZZfLuOqaxt3BmCF4btwcGXBTbSwHDrirNo4DB9xWG8+BA+6rTWDAseAhh205cMBTDis4cMBjDis5"
    "cMBzjth1cvfHAQ86YpfK3R8HVGXLocoWVGXLocoWVGXLocrgBZaHGy+bU1dcR9lvFW7/kNKDfYJe+qfkNf6pp+fVfjTvvv72nbt0tB3KRlUNpt"
    "VGVW1Uv3cbVe/9EN198qPxYjaE8v840neLfzrfdX+9xlXVY0lWLAVhKVYsDWFpVizk0FI0o8WSuBMHTCPpaZCjSUVPg5xEanoa6Pt3tj3Mpo0I"
    "xMVHKA1x2xTQb3WioS0lBP1WJxrackLQb3WioS0pBP1WJxrassK432qyX3en06NHWhToq3e2B2A+8Kl5PY3DgtSteb9rPwivTSpIjwUtdrqABT"
    "Fuurg56y2osdMJbN19l45lyOjGzVtv646dTmHrjp1OY+uOnc4A3wpi2ucpv1vTHK+FBfBkGXhQqYQqA88DeLoMvACtve7bsukRWb5T486xfs3x"
    "YkFHM4oXCzqa0bxY0Olts58vZzeH++wDXHz3rzXtLhe86OGEY4hxLI5jiXGAxNdmMfrWTBffco7ctcfHzjl31wEfO+fwPW60Wn3dN8sugdOPTv"
    "uMDH7wYQQxDn7yYSQxDn70YRQxDq5+hlj9DK5+xuS8J7iUGZszdlSXnrukT/ORRKq6wvQ0Hj13nrnRPsusCG7zmsX65eYvID3wF5AFt3tl4IHb"
    "vjLwwO1fGXgKXHtPc346DS69EugMuPJKoLPgwuOkOxt3rLjKuDPeq8vbPWrTo+rWqW6d6tYpoOnRD+P8UOOw33Z//EStjyYvzWTy8nvpe/RvbY"
    "bK73k02jdd26NCuh39YbYdrtlRrvGm8/Tun3fUVwMFBMUXYLk5oYQC/DavKMQ3nMTNNicUUYDT5oQiC7DZnFBUAR6bE4ouwGNzQiFuIx7V28fZ"
    "6vQ+E79EHqchfo8CTkP7KsUNM2ca2rcpbpA509C+UHFDzJmG9p2KG2DONLTt+eOGlzMN7T4mbnA509BuZeJ+ljMN7W5G4VpMvKFRuBYT72kUrs"
    "XE2xqNazHxzkbjWky8udG4FhPvb8CWRkV3NCqwm1GpfYwmz9vtbLUvro9RsR2MNuuXWe1e9J/Qveh44nif3kV936Ku6H6Q3jw3nBUb5Kx4MJ7c"
    "vkXHWpiBjJRY46Ifz2njPplJ1yZw0VI7iCyMQu0ecjAKsW8y7tl5RSH2TMZNPq8ojhYlbuh5RfHEKAJGCcQoEkQRLTGKglGIfZtxB84rCrFn08"
    "JqK4jV1sJqK4jV1sJqK4jV1kLnE30T35b6HQoYDPFb5FoMhvg9cgKDIX6TnMRgiN8lpzAY4rfJaQyGePfiDAZDvH9xFoMh3sE4h8EQ72EcpsDU"
    "uxiHKTD1PsZjCky9k/GYAlPvZTymwNS7GY8pMPV+xmvw2LWzPjE1PnxjiwryZruedAbk+SrHRustOnSOldY7dOgcO6336NBZltqADp1TDRVadO"
    "icYqgg0KFdztASHdrnXYhs5VUXIn/r7sDYT5uDrLUBtTag1gbU2oBBagMWk6eXLrjHUxu3Bfjp7LF5+HjuK14t0CdXm8VyPwRgVspQQJbW7T7r"
    "fo0P0w1wQ0e8COC4JPaz5SY33Zi7IOKV06XQRTVrdhhtms3tldeR5bCbZ8DF80Dr1bQEuKiArueLZjpb7EfNhpUOaOc5WU2LWHYSUPFS8OI75d"
    "l20jlk+u6NA9g+vhvl5paEURnf3NgzVl1RYrC5sfOruqJWYHNj/1Z1hel/c2MXVnWFe39zYy9VdYUHf3NjR1R1hZN+9vDQnHZAzC9O3Fvf873t"
    "gLjfnLjfvg94u65SrwDtiVvw+6BXCiD02bnpGpZNnpo9N1/8/O95uWn66MyOF5fE5+3jrIBdTdzIf+zFs940T9tsuu+GGKYv5ZHu+MmQ0yhIIT"
    "2Ihyn2zjXpH7q9R+egnDU76uts486jp0Wzeb5Rju506fBq0Zy+YV8K8Oj3M9M3IqWGia7g0Wo/384m3yaLbBP1bjbJeHnjbuVTrX62+za6RLur"
    "uLbZI8dLo0cPs/23O9132j2rIaYk/o1gc/becSPvxubsvQ2QEzs0m/VufvsR+VDdfC9TG/La1EbXM7KmNmpqo6Y2amqjpjZqaqOmNmpqo6Y2am"
    "qjpjZyUxtPo+MR8h3Kk68Gi3/7PI3ZweIfUE8TdjALPcrDepF9DtuPkXEcAaR8usdZApyHHmkJcDUJVZNQNQlVk1A1CVWTUDUJVZNQNQlVk1A1"
    "CXX3JJS6Mgl12NX6mpqEqkmomoSqSaiahBogCRUVnz7KQCuC4zet1sAP+jbb1aRaTarVpFpNqtWkWk2q/Ycm1Wr5U8081cxTzTzVzFPNPNXMU8"
    "08/Q4zT8ANJZ1nZrSYT8lv4IzfStLz7LaPzWr2Qk9koIOcl/2WYTFHxfahQ5n3d9wsFvQT5LBHtv+2qanUmkotK5Xav73zVRE7YwOeEz/tiuAr"
    "NMeL3gXSi8+yO129121WV9M5jK6bRN6589DSWz/v7+mZvXrtBfjl7abvJftE6cvLx+HiN4v0cF9envLBnj7+XOMXjfRk00kRRu349SOvz/Xwga"
    "PCKy4UeduOTG69rO2KG0Le3hhutYlfGtJvDZejr83+acr92C3KN53mPBkHjb173jRfDtnJhO+G+JATSV/lRPpSO/1WJ1J1IlUnUnUicTiRzH+g"
    "EymU7NyBPBRPBVsoCnHuSFmwcydunijGuaPLdu6Ysp07tnTnjrtDp19/h06/YfhOv3E7RZ7VJW6AyLO6xD0LeVaXuM2gIKuLLt7qYkq3utjSrS"
    "6ucKuLBwLz0e1SwgQGDrPL1Qm8tmSzS9zqMIzZJe5beFs4/ZNh3dJpaMO5KQNP38Mq9GG23PMscyezEdsPsnewK7H9GHcnwxPbD/J3sUxx/Zx4"
    "GqkYj0o8jzSQRyWeBBrCoxJPAQ3jUYlf9z6QRyV+fXteuX/8Fva8cn8niraCxK9XL8UK4sBP0+2s+zw9LHIeTFRP9uNu17P+2j2bnKENMnRH/p"
    "GhL5Oi5tqkaO0RXpOiNSlak6I1KVqTojUpWpOiNSlak6I1KTpE72b+dga+1HYGodB2BkCOt4we4UCyuIwe4UDWuYwe4TV9XdPXNX1d09c1fV3T"
    "1zV9XdPXNX1d09c1fV3T1zV9/btNX29sjh/aARcJmMGTzQMlss39Etn2volse2Uiu94zUBPZNZFdE9k1kV0T2YMkst1nuGfg2+XxxXe/qLuBoC"
    "bma2K+JuZrYr4m5mu1cq1Wrunemu6t6d6a7q3p3prurenemu6t6d6a7uX9OfEIp8Un+x3x7vgbLT/b74h/3mj12X5H/JNK68/2O+JJVm0+2++I"
    "3yrYxZpP9jviNxZ0YeaT/Q57j6t5hv01t90UY9x9Lvdh/U3+TtcDDfujvtu0J1JK8WsX8q8Y4nxM8dsa8i8pqh686sEr1oNX0DVHri37mqPa26"
    "b2thnCEoi6DTedBmSMWfRlUq70y6RcyZdJ+WIvk/KlXyblB75MatBCbX/Hy6h80ZdR+WEvo/p+7DteJOXLv0jKXWU1n4x2zXLXcVe3eXWbV7d5"
    "dZsP6zb/PTjNo96kqwmjkvE063w//LN3byP87Xy1p1uB1vHl/GtnkfilCMD4Cy+6bdmkj+3sTrW4hbwDLMNIF/eQj5bjZjTflusi7+avd+Hvi/"
    "SQn+CYiwNc4sVgxvPoa8EMFwC4O1YFXG0sbQG2LpXXPK2f7+TdvBpPQMsu17mpIKUfdTo17z64BkhtDd2jbTQpAS0q8RNZhILGrfonOF4VAEz6"
    "shAFBSz6sggFjfvzO7gSFDQAbPdV0Dxvfr/ssr3vAhi5CAXVkL5PFttjwpBbquLe/G76igGMC/3TfLGYDeLPH+jz/fqq77hD/+0XjRbLz/eLLF"
    "Sa9tTnEvajfSE/Kdeo3/+kTVez8jl/UjR8Pa333anHw2I9gFl/oJ/UwbyAK+/4RxrPPvkTMtBn0GLRF+50y+7z/STo02nWFYZ2RXmf7wfdy8lP"
    "/0vu5eWn/yXQx+Anfm+gT8hP+97EXWLaf75fEq/h0+Hz/RIfdy7ve3fx4rGQ39PtNuO/p9+gXmHm3+2nTX/2P9kvPt0vilv5t1L232bzx0/3pW"
    "Dj1mOjPt27Y+MGnMNjs+y+ebrkfCG/aLYajRdQ8Uh3qtb99YcfBufyu3KL9WH2eX+ZhhJbm+yaBAMmV/b3KQHpT5M396kBOZ5o7u9UA9IlTbqC"
    "vllzWBwGrwGZiL7bzMOoq9x6HLwhc39YOQC5A84rhyGPitJiNpo2fZubT9FdeTTZF9ITKl4z0Z2U9Hj9+8HNZwG+frdTAl98o2xzer3FSy/606"
    "suf9VsBvjRWSmieOHF07zPX/HTxSsvtrNlIS+cB/Pso/3x+XInI+L1F92nUrMdrR5zoqVX8E/vc5/8P10jieMSPFXeoKlj9vkDE++lrG0HA/Ku"
    "wMt6kHBdPcjLrpaC1FKQWgpSS0FqKQhxKQjBvQO3AtZ6iwLrLRbdUemr+YDf8V7rLWq9Ra23qPUWtd6i1lvUeotab1HrLWq9Ra23qPUWtd6i1l"
    "t8mnqLjfK1zKLUMouNbj/fL6mFFZ+vsKLb8k7W68UA97wUUlrRPaWXZtrFxsXoW62xqDUW96+x+MyvEPS5+Ylfof/wcovHxbdJ9/6UU29x/T40"
    "Xm/RnfvP+9tmO0NFKS9QVzO6v0xC/JDsW02306vqLvrvs2+bWbOVspZeFFZ6cSq7aLoSjFp6UUsvaulFLb2opRe19KKWXtTSi1p6UUsvaulFLb"
    "2opRcZpRcXniH8Ko5FI1vT1uKLWnxRiy9q8cVgxRf7UqsvFuvuG6+vvrj1A1KTFE7UmoeC7pgohS66kKejMuscdpvRdtZsRM6BxyctUXj76S7n"
    "p0fD4e7V7N1b9li93vESg13ZJQa7kksMdr3b8XEYM2Gef7dFlvSNGTR1RYHA28hq8AKB3aAFAruCKwR2Q5cIvD0Um/NQ4tooy1CwuMV/V7bFf1"
    "eyxX8nS1GwgCxpJXJs9Jg2Kjm4QX8nC1GwuEP/7YfrnB8e1cbVc9/6s8vAZRU9xKXtWx8XFqPtcoCzmB/G+cHKsV2OFte42jskyYcEXgPQ9B6G"
    "GfGRFWgtbzbPN273xV084adF/2Fn+JCu7jcWQcoS92Xv3nzZtCwCYHl6HNOCYAr54T7zQ/qX31gMLYsGAluuA3lI93AnwN1hQsfUGT8GwLnBi2"
    "mxJ+Vpp8ZhLIGWJe5a6LqOvBpvaR9SQGwjGX7ZDzpC42ar/aJZ3uo/i6N09ob1HrIJLtaTHzcQcYvqc5dU2A1Ac/kh8B3JbPV4jcG0f6UXo8eh"
    "Jmc5Wj1fpkq+Qxo979fXeENP75ShVeK4m3N3Pzfn7o5uzt393Jy7O7o5+1O+7qumycowW/AAsbNENg95g8e9nP23fTa3E+DQA3Bj+y+rB3dyTl"
    "ad8N+uKtcYOjfb9ePpu/9On/3V0Mlp6HxblNXWWZStc/bw0HzIskDm68yxTV56wsTVnrDvU6zVE1Y9YdUTVj1hGZ6wzq1StiNsvpxnzaiCfvVR"
    "vVeP3D/93o1+B6pV/M/3vM3K9rzNvzZl2966jWQpJrDqf6P1v5Vtf9tsZ7uC3W/8eFgqU+bYM6p17Xff2/bexrWyfWvs7zZuW+PHwxwdqs1ZM9"
    "VzRtIU9q6Ws2OOY3sHy1lxhrNi7WbVbFbNZleazTozSHdCdZiV4jdrxt82o92uus6Kdp3xrBpIhavhrGjD2anLY7doijCcvbw6zlb7Ehxnvdmp"
    "Ws4ILGdHV1kc6ORGq5azajlLWc52N98Cca3prO/Clzk4ajrLJYdtZ0OQU9vO1p3vbH1/49nsLt/+mb6zPiFVtuesOs5KdJxNSrac/WeZze7TxE"
    "xebVjrF2M1rFXDWjWsVcPaIIa1Pqlfpl+tPwPtLGv3caz1CUX2nw0e4g3xs6Hvx9e7Fnlat4G5XUamaq2r1rpqravWumqtq9a6aq2r1rpqravW"
    "umqtq9a6aq2r1rpqravWumqtq9a6aq2r1rpqravWumqtq9a6aq2r1rpqravWumqtq9a6aq0r0lqHXs77OnGNLMH3p67y/W07f8S0mv6q6a+a/q"
    "rp7z//5tLJ8/a1Td0AgJvJ/mExyiBUcDu5Sews5cZuch/gG8LzpsFFwRyy467FbQlkcPKJPTctHPC9Ny2ALSrH6/mimfJe8hY3fm4nU/alFjd9"
    "Lkogixs+99umE7LmOyX74BMF9PDazL/EzlREzjcs6tSU7eBOzSFMbajFMsvUJu29TG0SO4WQOadicW9jQV3R4+7GHrDbEnU7onzA3Ncr7pLsg+"
    "Cu6wBcgKk4brbsI2EpgJAjvbv0tAQ8BUXrEuCiQvkwX3SXOHLvJuLGzz6t2Dytn7e7uxg/r35tLQj3WnmTfWL/wyg3A7p4IcmqOX0MsgtfPD+2"
    "mDaHxaHZrHcDAGbQBWhb1l9F3SX9P5ra/jBe7vFYC8nQdrbvr1WcfrYfFI9LTy+9WbB/Cfef7QdF49hmtJot+vOGZvfy2X6QAp5Q91nTuWc+3+"
    "/R9zBisv0a6KKuThN2s8+43FAznfpsv8bdw0vK9mv8PdyobL8GdWTbT/ZrDFbSot1n+zXiHpZatl8j72HKZfs1qBmy/Wy/BtsOmM+2HTDYwaaR"
    "n+3XYHsB89n2Aqg133y2vUDc3D+fzHIs2sP+mNlqNF5ADvjuZLH76zU1AsOZNzMOguL1Ai+j7Wq+esw2OUej7XrTnR7mjhyPfKOH2f5b9tjxD9"
    "Nvk8Use2gsKFgxvMX+NLIc3mB/GlkN768fwI9tsQ8Kawa31vf5rC7vv+9MKtwZY8CePxvx5f8vDZj6WgPmpaexGjCrAbMaMKsBsxowqwGzGjCr"
    "AbMaMKsBsxowMQPm5qmP06PezZELmMOmYLYxN5uG2SbcbAZ7pof1IvutOGTAWeyhcsM57Klyw1U/bPXDVj9s9cNWP2z1w1Y/bPXDVj9s9cNWP2"
    "z1w1Y/bPXDVj9s9cNWP2z1w1Y/bPXDVj9s9cNWP2z1w1Y/bPXDVj/sf7Qf1lzlh93VhqTVD1v9sNUP+7vxw3ZJt2URdlgD22FLuz+7TBdfCVbW"
    "uIvv3crKfMeuRL2szHCgH2M6W+xHDa/pIW7i205W05dyb9xeFIMXjerd7U7r7T2drZkXdw/RWtTfrbVovS87fV/2AK1F4zaxgqyUcavYm5VyuS"
    "/ASmlKt1La0q2UrmwrpS/ZShnorZRX32bdgm7Fzlj0xOyl1KJwL+X/z97b9chuY+e/9+dTCLnKH8hkim96uVSpVF2VrXqxpOre7ZuBkziJcRx7"
    "4HEO8P/2h6ru3u7tWQ931V4SyckQwQCDscN+itRaohZ/zyJNZnlgKW999mjSauj2m/Yr7pu9laW8WZ3Gu7J7778Ti1BP7zBIv2pyRMj5vwGc9p"
    "kcu4wHH87JCzW77npTpW8x0V9IPj2/LGZvCdZGpbvI472LnMmqLcCYfDVptgAhkq4in5nR+kot1RKE1VdeJr1ago/6Si1iCbrpK7XIJdikr9Si"
    "XGRRZqmeGeTczQbRSEgcbJBxsUHbe73FN1Als6BBhQMNYoouERk0w4RUS6FBxWopNKgQS6FBvq8unwMNKmDPnWxig+p+qVPBW+OZvrl8STToi8"
    "reo0H5rWhQapWX0KCEBiU0KKFBCQ1KaFBCgxIalNCgv0s0aBgy2+prOmZconvbzeJKLG4dXFyFxTWhxQHG6XVZZ+neZscY5u7u9ba0MQiUruWN"
    "QWACtxK4lcCtBG4lcCuBWwncSuBWArcSuJXArQRuJXArgVsJ3ErgVgK3EriVwK0EbiVwK4Fbf5vg1rsqlAPcqr/tjLRXM4zZU21LZ4ngSgRXIr"
    "gSwTULwXW974oRSTR6ZS8Zyerp0rtL283wApj7itJJ3kN9lRhWnUbqpvJVcHUGLu2+D68uh+ouHyd1Iqy84gvyZFh55RfkqbDyyBz7aL8Qh/Mm"
    "2/SPQU9vaELxipuO56/IeTdAhtu93ar3dvcX9ofDK6ntfn8xHIN3hehuUUiOd4WoPeE8tNmwfzjWXdiFNfCJnh7nbNxxnugcDr6S2WPon05mQo"
    "suZdfjdrtNmL3H16fB7Vt+9jZf14Hvf+JvYNeuI38FS3wLddYeB3v0PbAyp8LX0V/O9kL6njM2Gb+7T5fW9WHvTEThm9nvWW5tUeWuwTf7+oEz"
    "eOFU3rGij4ajXgfnfvjQcNNob8iz9ItNmJvAbxwacBrq0AU5Gm3adpf2+kk2Bn9Va2CkOKwzi3Y2z0Fvz6SxppeXieVOT57RIXpXU9uUeDqOdR"
    "MBx3Tdvtj3yt3v2mVApk9y7t1XLAMz2Zf5o2fKQENidXjKDvXHCDimNzH7YwQgkzX5XK/t7R8fYiCZttMlMbva99RI9PR65gxojml6cQV4emmQ"
    "6U2M7yUycIlMBBhTd46BX5puuekDvIxohGn3+HxNdXcf0y5DMdVd3R8iIJimZzYXEeBLVyEyAnbpKkTFAC492J3u3vMuF9w8NmbTq/luKwFbjQ"
    "F7br8qcrRxOtsv4MND4zfd0vzTtpt2TsOj72xLI1Pb7rqRexTe5VQuOdK3HBrNepOjvMsRDjnDo+/vNBoC+/TseJejnM+OdznaIefsf7Fo69T5"
    "sMm6zbUGwmFi6L4KtrhSX8YTs1ZekAmzOzX1ZPs6zNGPxg5zGhEVfP1Lv5vMkvbEbab37HjgtvAZ3vNxd1OEFSR3775a93eIEgBVsye1UFOlW3"
    "9zSfNCm+x0GadfPUNPpa8/tSvBMdJXIEe/Ww+F1kOEXg+NlMnQygxajKe2/cBZjBwN/NzWPWfgAg18sEl7xxm5RCNv6mfOuBUad3e69NwHgHX6"
    "WK3gZO6PlzuRFULcZ5Wsu8UJJM6+EGybiaCvlUo5TpXv3czMvqzwyPt4xRMHEVae+YI8GVZe/gV5Kqy8AssbrdGgOYSVV7rlDWNQ3kKsVljfpr"
    "WfIk+B9QlQsmquRNPdy/u70SUefXq2maMrPPrXPJq/G127Rx84fjaxwmfQE/R1N0z2189Fc8m2I+fJyJ0K7ybS/lrhw3ug7359ZGI6Xg6Z/WT8"
    "YD89Btb60Nhzb0O2O3FBKbGqXKMzSSlBe0M+aeehUgK4Q15Hn2Ap1ujSNTqTmBbA5PE6un1mWINr1+B3f4f8fnTjGv3AMrkJYJF4ex7v/B75/e"
    "CFa/C7P0pmfwUKZ6jfezquZv4sEcKZK4a2mcEGz5AnnclmOsdmecacycZuowJv7yROV3yvvpDKNTr3NSG1UzvzNSGNa3Tua0LmrtG5rwlZuEZn"
    "viZk6Rr8awPmvVVc3G4VH8a2PiSbeLKJJ5t4soknm3iyiSebeLKJJ5t4somHtokP4yGbpSv+3C7xSdjV2nrp26B9yZNRPBnFk1E8GcWTUTwZxZ"
    "NRPBnFk1E8GcWTUTwZxZNRPBnFk1E8GcWTUTwZxZNRPBnFk1E8GcWTUTwZxZNRPBnFk1E8GcVZTmzOgWWyic9sE+etxnImcZ6uZBFPFvFkEU8W"
    "8WQRTxbxZBFPFvFkEV/QIp4c4skhnhziySEetUO8H5JBPBnEk0E8GcSTQXwWg7i81SAu0l3iySSeTOLJJJ5M4skknkziySSeTOLJJJ7uEk93if"
    "+tWsTnMmEXC5qw6e+/OUzYtHd8HhP2ajkTtljQhC2jNmGrJU3YekkTtlnShJ0vacIu4jZh0w708CZsVUVlI17FZCMWcdmIZVw2YhWLjVjHZCM2"
    "EdmIaeN5KBsx7TsPZCOmvecBbMS07zyUjXgVk41YxGIjljHYiFVcNmIdl43YxGEjph3nAWzEpojERmzKSGzEtNM8jI14FZWNWERhI5Zx2YhVVD"
    "ZiHZeN2ERlI6Yd6MFsxMiBHshG/AULunc5VVw24lVcNmKxpI1YLmkjVvHZiHXENmKzlI2YNovHcN807TSPxEhclAsZiWnDeBT3Ta+ivW9aLGUm"
    "lkuZidViZmK9kJnYRGsmxpbvCMzE2DYegZmYdojHYiZexW0mFnGbiWXcZmIVt5lYR20mdjnFI/ASV8WCVmLa5z2Tk7iqFjUSrxY1Eovo75qWkT"
    "uJ1aJOYr2ok9gs6SRe5Us6iVfFkk5it4Ob6xFzO7i5TuLVok5isaSTWC7pJFbz3jV9j3/7biPwPfbtu22899i3uSbcL/m3M97o5ZIWWod7eg4L"
    "7WpRC61Y1EIrF7XQqiUttHppC6263UKb7lhO9tlkn0322WSfTfbZZJ9N9tlkn0322f9NdyyzLjFOdywnA20y0CYDbTLQJgNtMtAmA20y0CYDbT"
    "LQJgNtMtAmA20y0CYDbTLQJgNtMtAmA20y0CYDbTLQJgNtMtAmA20y0LIOtZJ9Nqp7eFeR3sObrLPJOpuss8k6m6yzyTqbrLPJOpuss1HewZuc"
    "s8k5m5yzyTm7sHO2H5JxNhlnk3E2GWeZxll9i3G2f9paADFZZpNlNllmk2V2DstsKwLj3fTmrZWhZZEpolWhZWFn0zCex8BtRQU42QvdiJXeTg"
    "7n0G1Y6a3ivVE+//WY9B5zHXoZ6d3pZpzhWGOY26rZh1ZF7is269BLSOavMfRkkflh9zwEf+JLICx05qINn1ZY6B7otKfzG8a+CTg5OSPSX6qh"
    "Z44+zG9Cv41ox+fQ7ELrysF8hY5NYORsdsGFAdQo9BOmAWoU+gmj/ZT2IzP0a4l2VlphoZ8w4LTcbkO/lmijo31fhv5koz2PG/4jxtuR0e7HDX"
    "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"
    "YmCphtffvGRAmzrW/jmChhtvXtHBMlzLa+rWOihNnWt3dMlDDb+jaPiRJmW9/uMVHCbOvbPiZKmG0L772/Ybb1bSATJcy2vh1kooLZ1reFTFQw"
    "2/r2kIkKZlvfJjJRwWzr20UmKphtfdvIRAWzrW8fmahgtvVtJBMVzLa+nWSigtm29H7VAsy2pfe7FmC29e0lkyuYbX17yeQKZlvfXjK5gtnWt5"
    "dMrmC29e0lkyuYbX17yeQKZlvfXjK5gtnWt5dMrmC29e0lkyuYbX17yaRA2da7l0zSXrKdpr1kt9/yRxvDruNK1rgKjqtY42o4rmaNa+C4hjVu"
    "DsfNWeMWcNyCNW4Jxy1Z41Zw3IozLm1AmsalDEh3jAvjTbDiTcJ4E6x4kzDeBCveJIw3wYo3CeNNsOJNwngTrHiTMN4EK94kjDfBijcJ402w4k"
    "3BeJOseFMw3iQr3hSMN8mKNwXjTbLiTcF4k6x4UzDeJCveFIw3yYo3BeNNsuJNwXiTrHhTMN4kK940jDfFijcN402x4k3DeFOseNMw3hQr3jSM"
    "N8WKNw3jTbHiTcN4U6x40zDeFCveNIw3xYo3DeNNseLNwHjTrHgzMN40K94MjDfNijcD402z4s3AeNOseDMw3jQr3gyMN82KNwPjTbPizcB406"
    "x4MzDeNCvechhvhhVvOYw3w4q3HMabYcVbDuPNsOIth/FmWPGWw3gzrHjLYbwZVrzlMN4MK95yGG+GFW85jDfDircCxlvOircCxlvOircCxlvO"
    "ircCxlvOircCxlvOircCxlvOircCxlvOircCxlvOircCxlvOircCxlvOircSxlvBircSxlvBircSxlvBircSxlvBircSxlvBircSxlvBircSxl"
    "vBircSxlvBircSxlvBircSxlvBircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJircKxlvJiTe1"
    "gvFWrVjjwnirBGtcGG+VZI0L461SrHFhvFWaNS6Mt8qwxoXxVuWscWG8VQVrXBhvVckaF8ZbxYo3geKNRFLuGFfAcVnxBvkSweJLFORLBIsvUZ"
    "AvESy+REG+RLD4EgX5EsHiSxTkSwSLL1GQLxEsvkRBvkSw+BIF+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+"
    "RLD4EgX5EsHiSxTkSwSLL1GQLxEsvkRBvkSw+BIF+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4EgX5Es"
    "HiSxTkSwSLL1GQLxEsvkRBvkSw+BIF+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4EgX5EsHiSxTkSwSL"
    "L1GQLxEsvkRBvkSw+BIF+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4EgX5EsHiSxTkSwSLL1GQLxEsvk"
    "RBvkSw+BIF+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4EgX5EsHiSxTkSwSLL1GQLxEsvkRBvkSw+BIF"
    "+RLB4ksU5EsEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4EgX5EsHiSxTkSwSLL1GQLxEsvkRBvkSw+BIF+RLB4ksU5E"
    "sEiy9RkC8RLL5EQb5EsPgSBfkSweJLFORLBIsvUZAvESy+REG+RLD4Eg35EsHiSzTkSwSLL9GQLxEsvkRDvkSw+BIN+RLB4ks05EsEiy/RkC8R"
    "LL5EQ75EsPgSDfkSweJLNORLBIsv0ZAvkSy+RAO+ZJgGZgUcAEyuA7MiDhAm14FZIQcQk+vArJgDjMl1YFbQAcjkOjAr6gBlch2YFXYAM7kOzI"
    "o7wJlcB2YFHgBNpoFZpImWOPJYqImWOPJYrImWOPJYsImWOPJYtImWOPJYuImWOPJYvImWOPJYwImWOPJYxImWOPJYyIlWOPJYzIlWOPJY0IlW"
    "OPJY1IlWOPJY2IlWOPJY3IlWOPJY4IlWOPJY5IlWOPJY6IlWOPJY7IlWOPJY8InWOPJY9InWOPJY+InWOPJY/InWOPJYAIrWOPJYBIrWOPJYCI"
    "rWOPJYDIrWOPJYEIrWOPJYFIrWOPJYGIo2OPJYHIo2OPJYIIo2OPJYJIo2OPJYKIo2OPJYLIo2OPJYMIo2OPJYNIo2OPJYOIo2OPJYPIo2OPJY"
    "QIrOceSxiBSd48hjISk6x5HHYlJ0jiOPBaXoHEcei0rROY48Fpaicxx5LC5F5zjyWGCKznHkscgUnePIY6EpusCRx2JTdIEjjwWn6AJHHotO0Q"
    "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"
    "iAVekcm4UBrCrn2Ky4dGI5gonlCOfYrLh0gjmCB+Y4yRzBI3OcaI7goTlONkfw2BwnnCN4cI6TzhE8OseJ5wgenuPkcwSLzxFOQEewAB3hJHSE"
    "4PFyzrhkITrCyegIFqMjnJCOYEE6wknpCBalI5yYjmBhOsLJ6QgWpyOcoI5ggTrCSeoIFqkjnKiOYKE6wsnqCBarI5ywjpA8kNUZlyxaRzhxHc"
    "HCdYST1xEsXkc4gR3BAnaEk9gRLGJHOJEdwUJ2hJPZESxmRzihHcGCdoST2hEsakc4sR3BwnaEk9sRikeYO+OSBe4IJ7kjWOSOcKI7goXuCCe7"
    "I1jsjnDCO4IF7wgnvSNY9I5w4juChe8IJ78jWPyOcAI8ggXwCCfBI1gEj3AiPMLwrB/OuGQxPMIJ8QgWxCOcFI9gUTzCifEIFsYjnByPYHE8wg"
    "nyCBbII5wkj2CRPMKJ8ggWyiOcLI9gsTzCCfMIFswjnDSPyHmeLGdcsnAe4eR5BIvnEU6gR7CAHuEkegSL6BFOpEewkB7hZHoEi+kRTqhHsKAe"
    "4aR6BIvqEU6sR7CwHuHkegSL6xFOsEcUPLOkMy5ZZI9woj2ChfYIJ9sjWGyPcMI9ggX3CCfdI1h0j3DiPYKF9wgn3yNYfI9wAj6CBfgIJ+EjWI"
    "SPcCI+goX4CCfjI0qei9kZlyzIRzgpH8GifIQT8xEszEc4OR/B4nyEE/QRLNBHOEkfwSJ9hBP1ESzURzhZH8FifYQT9hEs2Ec4aR/Bon2EE/cR"
    "Fa+9gDMuK15/AWdcsngf6eR9BIv3kU7eR7B4H+nkfQSL95FO3keyeB/p5H0ki/eRTt5Hsngf6eR9JIv3kU7eR7J4H+nkfSSL95FO3keueI0/hH"
    "NsVlw6eR/J4n2kk/eRLN5HOnkfyeJ9pJP3kSzeRzp5H8nifaST95Es3kc6eR/J4n2kk/eRvH48Tt5H8hryOHkfyezI44xLXkseJ+8jeT15nLyP"
    "5DXlcfI+kteVx8n7SF5bHifvI3l9eZy8j+Q15nHyPpLF+0gn7yNZvI908j6SxftIJ+8jJa9VljMuWbyPdPI+ksX7SCfvI1m8j3TyPpLF+0gn7y"
    "NZvI908j6SxftIJ+8jWbyPdPI+ksX7SCfvI1m8j3TyPpLF+0gn7yMVr4edMy5ZvI908j6SxftIJ+8jWbyPdPI+ksX7SCfvI1m8j3TyPpLF+0gn"
    "7yNZvI908j6SxftIJ+8jWbyPdPI+ksX7SCfvIw2vuaQzLlm8j3TyPpLF+0gn7yNZvI908j6SxftIJ+8jv473ed+gXd7YoN1eGns4n47tZ5e7ph"
    "7tqUf71/Vot/3Zs2aJFu22PTtv4AIOrHgDl/8/e2+3Xdd1XFvf5ynY/ACn7apZ8+8SJkAJxyCAACAk5YaNtqUTt6ZIapKS5/82aMci4zVHierg"
    "xnY+XuRGjIuLwBoD2Gv1XnM5ONjguRxc2eDlc+H9anY42ZaTO5zsy8kDTi7LyRNOXv283q9lh5OX+TOYv+Wz4P1Sdjh5mUCDCVw+B96vZIeTlx"
    "k0mMHlM+D9QnY4eZlBgxlcPv/dr2OHk5cZNJjB5bPf/TJ2OHmZQYcZXD733a9ih5OXGXSYweUz3/0idjh5mUGHGVw+792vYYeTlxl0mMHls979"
    "EnY4eZlBhxlcPufdr2CHk5cZLDCDy2e8+wXscPIygwVmcPl8d79+HU5eZrDADC6f7e6Xr8PJywwWmMHlc9396nU4eZnBAjO4fKa7X7wOJy8zGD"
    "CDy+e5+7XrcPIygwEzuHyWu1+6DicvMxgwg8vnuPuV63DyMoMBM7h8hrtfuA4nLzMYMIPL57f7detw8jKDFWZw+ex2v2wdTl5msMIMLp/b7let"
    "w8nLDFaYwaWjuV+0DicvM1hhBpd+5n7NOpy8zGCFGVy6mfsl63DyMoONPhNdZrDBDC6tzP2GdTh5mcEGM7g0Mvf71eEj4mUGG8zg0sbcb1eHk5"
    "cZbDCDSxNzv1sdTl5msMMMLi3M/WZ1OHmZwU5fTCwz2GEGl/7lfq06nLzMYIcZXLqX+6XqcPIygx1mcOld7leqw8nLDHaYwaVzuV+oDicvMzhg"
    "Bpe+5X6dOpy8zOCgbweXGRwwg0vTcr9LHb54XGZwwAwuLcv9JnU4eZnBATO4NCz3e9Th5GUGJ8zg0q7cb1GHk5cZnDCDS7Nyv0MdTl5mcNJX9M"
    "sMTvyOfhnCSV/SL53K/f50OnoZw0lf0y+Nyv32dDp6FcT9d4GOrsvR9E39Uqc0ysqst6cbpWXWy9ON8jLr3emGiZklMmMcmbHlaJrGJTRjGJpZ"
    "UjOGqZklNmMYm1lyM4a5mSU4YxicWZIzhsmZJTpjGJ1ZsjNG2Zn1wnSj8Mx6X7oZJtiWaaT4zHpbulF+Zr0s3ShAs96VbpSgWa9KN4rQrDelG2"
    "Vo1ovSjUI06z3pRima9Zp0oxjNeku6UY5mvSTdHAOlyzRSkma9It0oSrPekG6UpVkvSDcK06z3oxuladbr0Y3iNOvt6EZ5mvVydKNAzXo3ulGi"
    "Zr0a3ShSs96MbgXz3cs0UqhmvRfdKFWzXotuFKtZb0U3ytWsl6IbBWvWO9GNkjXrlehG0Zr1RnSjbM16IbpRuGa9D90oXbNeh24V6xbLNFK+Zr"
    "0M3Shgs96FbpSwWa9CN4rYrDehG2Vs1ovQjUI26z3oRimb9Rp0o5jNegu6Uc5mvQTdKGiz3oFuDdtPyzRS1Ga9Ad0oa7NegG4UtlnvPzdK26zX"
    "nxvFbdbbz43yNuvl50aBm/Xuc6PEzXr1uVHkZr353Chzs158bh3LiMs0UupmvfbcKHaz3npulLtZLz03Ct6sd54bJW/WK8+NojfrjedG2Zv1wn"
    "Oj8M1637lR+ma97twofrPedm4Du8HLNFIAZ73r3CiBs151bhTBWW86N8rgrBedG4Vw1nvOjVI46zXnRjGc9ZZzoxzOesm5URBnvePcKImzXnFu"
    "E6v6yzRO7Oov00hZnPV+c6Msznq9uVEWZ73d3CiLs15u7pTFWe82d8rirFebO2Vx1pvNnbI468XmTlmc9V5zpyzOeq257/DqDFuOpmlcsjhOWZ"
    "z1TnOnLM56pblTFme90dwpi7NeaO6UxVnvM3fK4qzXmTtlcdbbzB3vsVmyOI4X2SxZHOebbJZpxKtsliyO4102SxbH8TKbJYvjeJvNksVxvM5m"
    "yeI43mezZHEcL7RZsjhOWZz1CnOnLM56g7lTFme9wNwdL5ZappGyOOv15U5ZnPX2cqcsznp5uVMWZ7273CmLs15d7pTFWW8ud8rirBeXO2Vx1n"
    "vLnbI467XlTlmc9dZyL3jP2zKNlMVZ7yx3yuKsV5Y7ZXHWG8udsjjrheVOWZz1vnKnLM56XblTFme9rdwpi7NeVu6UxVnvKnfK4qxXlXvFaxeX"
    "aaQsznpRuVMWZ72n3CmLs15T7pTFWW8pd8ri+HrhzcPDOLQTfr3x5uFhHBvtao00G13UImk2OtQqaTa6ql3SbHRTy6TZ6K62SbPRQ62TZqOn2i"
    "eNRq9X3xhN43r3jdE0rpffGE3jevuN0TSu198YTeN6/43RNK4X4BhN43oDjtE0rlfgGE3jegeO0zSul+A4TeN6C47TNK7X4DhN43oPjtM0rhfh"
    "OE3jehOO0zSuV+E4TeN6F47TNK6X4ThN43obTqFpXK/DKTSN6304haZxvRCn0DSuN+IUmsb1SpxC07jeiVNoGtdLcQpN43orTqFpXK/FKTSN67"
    "04AdNY1ntxwuhoU/um2WhXC6fZ6KI2TrPRoVZOs9FV7Zxmo5taOs1Gd7V1mo0eau00Gz3V3mk0en2UVKVpXJ8lVWka14dJVZrG9WlSlaZxfZxU"
    "pWlcnydVaRrXB0pVmsb1iVKVpnF9pFSlaVyfKdVoGteHSjWaxvWpUo2mcX2sVKNpXJ8r1Wga1wdLNZrG9clSjaZxfbRUo2lcny3VaBrXh0s1ms"
    "b16VKdpnF9vFSnaVyfL9VpGtcHTHWaxvUJU52mcX3EVKdpXJ8x1Wka14dMdZrG9SlTnaZxfcxUp2lcnzM1aBrXB00Nmsb1SVODpnF91NSgaVyf"
    "NTVoGteHTQ2axvVpU4OmcX3c1KBpXJ83NWga1wdODZrG9YlTk6ZxfeTUpGlcnzk1aRrXh05Nmsb1qVOTpnF97NSkaVyfOzVpGtcHT02axvXJU5"
    "OmcX301KRpXO/F2dE0rvfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfi"
    "UBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrP"
    "fiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBanrPfiUBan"
    "rPfiUBYn1ntxKIsT6704lMWJ9V4cyuLEei8OZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZX"
    "FifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYV"
    "ZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifU"
    "YVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFi"
    "fUYVZXFifUYVZXFifUYVZXFifUYVZXFifUYVZXFivReHsjjRdmpJNRttakk1G+1qSTUbXdSSajY61JJqNrqqJdVsdFNLqtnorpZUs9FDLalmo6"
    "daUo1G951aUs1Gm1pSzUa7WlLNRhe1pJqNDrWkmo2uakk1G93Ukmo2uqsl1Wz0UEuq2eipllSj0WOnllSz0aaWVLPRrpZUs9FFLalmo0MtqWaj"
    "q1pSzUY3taSaje5qSTUbPdSSajZ6qiXVaPTcqSXVbLSpJdVstKsl1Wx0UUuq2ehQS6rZ6KqWVLPRTS2pZqO7WlLNRg+1pJqNnmpJNRlddzu1pJ"
    "qNNrWkmo12taSajS5qSTUbHWpJNRtd1ZJqNrqpJdVsdFdLqtnooZZUs9FTLalGo9dnVFEWp67PqKIsTl2fUUVZnLo+o4qyOHV9RtVvZnH+5W/j"
    "f1ff/cD7u9f/8fXPb979y/789U9/+vFh5O2r37+8On22/0vPn5/d/jL3T2/++Pq//9q7s+f/eC1nF2fP727O3/mTH7/+r4c/+PJifw/98v/+45"
    "vvfvrh+x9/fvijH+z1N99+98sf/vubn17/8P1fvvv59Z/fvL2+n3/8z6/fPxxx6yt0cnp6c3Z7+0Ffn3h/z9vm2Ovri/PnJ3fnV5dg9Obtcn1y"
    "eXbx7Obs5PSrDxptf/8v33/3+ts3f/z624f/wbvX9/0337zzBy9e/O79n9tbF7P/fr+6OHt2e3dyd0tu363Zf72d9g989/8HZrdkNoldT2YXMH"
    "skswPMnsnsSs4g3SXDGxluyfBOhnsyfJDhJRk+yfDQw99r0Q8enqTT0Im1STzN0VHxyfCCTr5Ohgc6yDcZXtG5pMnwho5ZFMMddrl7MhwtbC3J"
    "8ILO9EmGBzqiJBmO7paWDEd3S0+Gd7QPOxk+0HrfZPhE20r1cNTnJUko6vOSJNTYaqxkeEGbfpLhgRaXJMMr2sOQDG9IKxfDC+zzMpLhTPpLhh"
    "fkMCXDAykZyfCKCPNkeEPAbDK8I/4vGT4QzpQMn4jO0MNRn0eSUNTnkSTU2KuAZHhBTzaT4YGetyXDSUJrklDU51UlNGCf10iGo2ecNRmO7paW"
    "DEd3S0+Go7tlJMPR3TKT4aTP2y4ZTvq8WTKc9HlzPRz1eUsSivq8JQlFfd6ShKI+b0lCUZ+3JKGoz1uSUNTnTSW0wj7vu2Q4enhuyXByt3RPhp"
    "O7pZdkOLlbeiTDyd3SazKc9HlvyXDS570nw0mf96GHoz7vSUJRn48koajPR5JQ1OcjSSjq85EkFPX5SBKK+nyohDbY56Mlw9Hd0pPh6G4ZyXB0"
    "t8xkOLlb5i4ZTu6Waclw0ufTk+Gkz2dJhpM+n6GHoz6fSUJRn88koajPZ5JQ1OczSSjq85kk1BixkEQUFbrtVEY7bHTbeTIdvUDflWQ6eoO+i2"
    "Q6eoW+q8l0ds+0ZDq7Z3oyHXEuu5FMR6DLbibTEeki8aJOURdLsspYF0uyymAXS7LKaBdLsspwF0uyyvrdkqyyfpeU0aD9LjGjQftdckaD9rsE"
    "jQbtd0kaDdrvEjUatN8lazQwxxjJdNTvkjYatN8lbjRov3uSVdbvnmSV9bsnWWX9XpKssn4vSVZZv5ckq6zfJXU0ab9L7GjSfpfc0aT9LsGjSf"
    "tdkkeT9rtEjybtd8keTdrvEj6atN8lfTQxqe56Ouv3SLLK+j2SrLJ+jySrrN8jySrr90iyyvo9kqyyflcU0n53Dux3hSG9nY7uGcUhvZ2O7hkF"
    "Ir2dju4ZRSK9nY7uGYUivZ2O7hnFIr2djvpdwUhvp6N+VzTS2+mo3xWO9DAdqkhJVqGLlGSV9XtLssr6vSVZZf3ekqyyfm9JVlm/KyrJqF1qCk"
    "sy6pea4pKMGqamwCSjjqkpMsmwZarQJMOaqWKTDHumCk4yLJoqOsmwaarwJMOqaU+yyvq9J1mFsmmSVdbvPckq6/eeZJX1+0iyyvpdUUpGjVNT"
    "mJJR5dQUp2TUOTUFKhmVTk2RSkatU1OoklHt1BSrZNQ7NQUrGRVPTdFKRs1TU7iSUfXUZpJV1u8zySrr95lklfX7TLIK1wkkWWX9PpOssn5X1J"
    "JRA9UUtmRUQTXFLRl1UF1xS0YlVFfcklEL1RW3ZFRDdcUtGfVQXXFLRkVUV9ySURPVFbdkVEX1XZJV1O++S7KK+t13SVZRv7slWUX97pZkle2L"
    "sSSrcGGMyio1Ul1xS0aVVFfcklEn1RW3ZFRKdcUtGbVSXXFLRrVUV9ySUS/VFbdkVEx1xS0ZNVNdcUtG1VT3JKus3z3JKut3T7LK+t2TrLJ+9y"
    "SrrN89ySrrd8UtGTVUXXFLVvFKMEumo3tGcUtGJVVX3JJRS9UVt2RUU3XFLRn1VF1xS0ZFVVfcklFT1RW3ZFRV9ZJklfV7JFll/R5JVlm/R5JV"
    "1u+RZJX1eyRZZf2uuCWjxqorbsmosuqKW7KGdz6OZDq7Z2YyHd0zklui2qpLbol6qy65JSquuuSWqLnqklui6qrXJKus32uSVdbvNckq6/eaZJ"
    "X1e02yyvq9JVll/S65JeqvuuSWqL/qklui/qpLbon6qy65pY63+rZkOrtnejId9bvklqi/6pJbov6qS26J+qvek6yyfu9JVlm/9ySrrN97klXW"
    "7z3JKuv3nmSV9bvklqi/6pJbov6qS26J+qsuuSXqr7rklqi/6pJbov6qS25p4L3tkUxH/S65JeqvuuSWqL/qI8kq6/eRZJX1+0iyyvp9Jlll/T"
    "6TrLJ+n0lWWb9Lbon6qy65JeqvuuSWqL/qklui/qpLbon6qy65JeqvuuSWqL9aJLdE/dUiuaWJT+ZwPZ0dzbFLssrO5tglWWWHc+ySrLLTOXZJ"
    "VtnxHLskq+x8jl2SVXZAh+KWnPqrRXFLTv3Vorglp/5qUdySU3+1KG7Jqb9aFLfk1F8tilty6q8WxS059VeL4pac+qtFcUu+w0cvJVmFZy8lWW"
    "X97klWWb97klXW755klfW7J1ll/a64Jaf+alHcklN/tShuyam/WhS35NRfLYpbcuqvFsUtOfVXi+KWnPqrRXFLTv3Vorglp/5qUdySU3+1lCSr"
    "rN9LklV4uF6SVdbvJckq6/eSZJX1eyRZZf2uuCWn/mpR3JJTf7Uobsmpv1oUt+TUXy2KW3LqrxbFLTn1V4vilpz6q0VxS0791aK4Jccnpypuyf"
    "HRqTXJKuv3mmSV9XtNssr6vSZZhcenJlll/V6TrLJ+V9yS4xNUFbfk+AhVxS059VeL4pac+qtFcUtO/dWiuCWn/mpR3JJTf7Uobsmpv1oUt+TU"
    "Xy2KW3Lqr5aWZJX1e0uyyvq9JVll/d6TrLJ+70lWWb/3JKvwgGyVVeqvFsUtOfVXi+KWnPqrRXFLTv3Vorglp/5qUdySU3+1KG7Jqb9aFLfk1F"
    "8tilty6q8WxS059VfLSLLK+n0kWWX9PpKssn4fSVZZv48kq6zfR5JV1u+KW3LqrxbFLTn1V4vilpz6q0VxS0791aK4Jaf+alHcklN/tShuyam/"
    "WhS35NRfLYpbcuqvFsUtOfVXy0yyivo9dklWUb/HLskq6vfYJVlF/R67JKuo32OXZBX1eyhuyam/GopbcuqvhuKWnPqrobglp/5qSG6J+qshuS"
    "Xqr4bklqi/GpJbov5qSG6J+qshuSXqr4YlWWX9bklWWb9bklXW75ZklfW7JVll/e5JVlm/S26J+qshuSXqr4bklqi/GpJbov5qSG6J+qshuSXq"
    "r4bklqi/GpJbov5qSG6J+qshuSXqr0ZJssr6vSRZZf1ekqyyfi9JVlm/lySrrN9LklXW75Jbov5qSG6J+qshuSXqr4bklqi/GpJbov5qSG6J+q"
    "shuSXqr4bklqi/GpJbov5qSG6J+qsRSVZZv0eSVdbvkWSV9XtNssr6vSZZZf1ek6yyfpfcEvVXQ3JL1F8NyS1RfzUkt0T91ZDcEvVXQ3JL1F8N"
    "yS1RfzUkt0T91ZDcEvVXQ3JL1F+NlmSV9XtLssr6vSVZZf3ekqyyfm9JVlm/tySrrN8Vt1SovxqKWyrUXw3FLRXqr4bilgr1V0NxS4X6q6G4pU"
    "L91VDcUqH+aihuqVB/NRS3VKi/GopbKtRfjZ5klfX7SLLK+n0kWWX9PpKssn4fSVZZv48kq6zfFbdUqL8ailsq1F8NxS0V6q+G4pYK9VdDcUuF"
    "+quhuKVC/dVQ3FKh/moobqlQfzUUt1SovxqKWyrUX42ZZJX1+0yyyvp9Jlll/T6TrLJ+n0lWUb/XXZJV1O9VcUuF+qtVcUuF+qtVcUuF+qtVcU"
    "uF+qtVcUuF+qtVcUuF+qtVcUuF+qtVcUuF+qtVcUuF+qtVcUuF+qvVkqyifq+WZBX1e7Ukq6jfqyVZRf1eLckq63dLssr6XXFLhfqrVXFLhfqr"
    "VXFLhfqrVXFLhfqrVXFLhfqrVXFLhfqrVXFLhfqrVXFLhfqrVXFLhfqrVXFLhfqr1ZOssn73JKus3z3JKuv3kmSV9XtJssr6vSRZZf2uuKVC/d"
    "WquKVC/dWquKVC/dWquKVC/dWquKVC/dWquKVC/dWquKVC/dWquKVC/dWquKVC/dWquKVC/dUaSVZZv0eSVdbvkWSV9XskWWX9HklWWb9HklXW"
    "74pbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrTXJKuv3lmSV9XtLssr6vSVZZf3ekq"
    "yyfm9JVlm/K26pUH+1Km6pUH+1Km6pUH+1Km6pUH+1Sm6J+qtVckvUX62SW6L+apXcEvVXq+SWqL9aJbdE/dXak6yyfu9JVlm/9ySrrN97klXW"
    "7z3JKuv3kWSV9bvklqi/WiW3RP3VKrkl6q9WyS1Rf7VKbon6q1VyS9RfrZJbov5qldwS9Ver5Jaov1olt0T91TqTrLJ+n0lWWb/PJKus32eSVd"
    "bvM8kq6/eZZJX1u+SWqL9aJbdE/dUquSXqrzbJLVF/tUluifqrTXJL1F9tklui/mqT3BL1V5vklqi/2iS3RP3Vtkuyivq97ZKson5vuySrqN+b"
    "JVlF/d4sySrq92ZJVlG/N8ktUX+1SW6J+qtNckvUX22SW6L+apPcEvVXm+SWqL/aJLdE/dUmuSXqrzbJLVF/tUluifqrzZOssn73JKus3z3JKu"
    "t3T7LK+t2TrLJ+9ySrrN8VtxTUX22KWwrqrzbFLQX1V5viloL6q01xS0H91aa4paD+alPcUlB/tSluKai/2hS3FNRfbYpbCuqvtpJklfV7JFll"
    "/R5JVlm/R5JV1u+RZJX1eyRZZf2uuKWg/mpT3FJQf7Upbimov9oUtxTUX22KWwrqrzbFLQX1V5viloL6q01xS0H91aa4paD+alPcUlB/tdUkq6"
    "zfa5JV1u81ySrr95pklfV7TbLK+r0lWWX9rriloP5qU9xSUH+1KW4pqL/aFLcU1F9tilsK6q82xS0F9Veb4paC+qtNcUtB/dWmuKWg/mpT3FJQ"
    "f7X1JKus33uSVdbvPckq6/eeZJX1e0+yyvq9J1ll/a64paD+alPcUlB/tSluKai/2hS3FNRfbYpbCuqvNsUtBfVXm+KWgvqrTXFLQf3VpriloP"
    "5qU9xSUH+1jSSrrN9HklXW7yPJKuv3mWSV9ftMssr6fSZZZf2uuKWg/mpT3FJQf7Upbimov9oUtxTUX22KWwrqrzbFLQX1V5viloL6q11xS0H9"
    "1a64paD+alfcUlB/te+SrKJ+77skq6jf+y7JKur3vkuyivq975Kson7vuySrqN+74paC+qtdcUtB/dWuuKWg/mpX3FJQf7Urbimov9oVtxTUX+"
    "2KWwrqr3bFLQX1V7viloL6q11xS0H91W5JVlm/e5JV1u+eZJX1uydZZf3uSVZZv3uSVdbvilsK6q92xS0F9Ve74paC+qtdcUtB/dUuuSXqr3bJ"
    "LVF/tUtuifqrXXJL1F/tklui/mqX3BL1V3tJssr6vSRZZf1ekqyyfi9JVlm/lySrrN8jySrrd8ktUX+1S26J+qtdckvUX+2SW6L+apfcEvVXu+"
    "SWqL/aJbdE/dUuuSXqr3bJLVF/tUtuifqrvSZZZf1ek6yyfq9JVlm/1ySrrN9rklXW7zXJKut3yS1Rf7VLbon6q11yS9Rf7ZJbov5ql9wS9Ve7"
    "5Jaov9olt0T91S65JeqvdsktUX+1S26J+qu9JVll/d6SrLJ+b0lWWb/3JKus33uSVdbvPckq63fJLVF/tUtuifqrXXJL1F/tklui/mqX3BL1V7"
    "vklqi/2iW3RP3VLrkl6q92yS1Rf7VLbon6q30kWWX9PpKssn4fSVZZv48kq6zfR5JV1u8jySrrd8UtVeqvdsUtVeqvdsUtVeqvdsUtVeqvdsUt"
    "VeqvdsUtVeqvdsUtVeqvdsUtVeqvdsUtVeqvdsUtVeqv9plkFfX72CVZRf0+dklWUb+PXZJV1O9jl2QV9fvYJVlF/T4Ut1SpvzoUt1SpvzoUt1"
    "SpvzoUt1SpvzoUt1SpvzoUt1SpvzoUt1SpvzoUt1SpvzoUt1SpvzoUt1SpvzosySrrd0uyyvrdkqyyfrckq6zfLckq63dPssr6XXFLlfqrQ3FL"
    "lfqrQ3FLlfqrQ3FLlfqrQ3FLlfqrQ3FLlfqrQ3FLlfqrQ3FLlfqrQ3FLlfqrQ3FLlfqroyRZZf1ekqyyfi9JVlm/lySrrN9LklXW7yXJKut3xS"
    "1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q8OxS1V6q+OSLLK+j2SrLJ+jySrrN9rklXW7zXJKuv3"
    "mmSV9bvilir1V4filir1V4filir1V4filir1V4filir1V4filir1V4filir1V4filir1V4filir1V4filir1V0dLssr6vSVZZf3ekqyyfm9JVl"
    "m/tySrrN9bklXW74pbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHYpbqtRfHT3JKuv3kWSV9ftI"
    "ssr6fSRZZf0+kqyyfh9JVlm/K26pUn91KG6pUn91KG6pUn91KG6pUn91SG6J+qtDckvUXx2SW6L+6pDcEvVXh+SWqL86JLdE/dUxk6yyfp9JVl"
    "m/zySrrN9nklXW7zPJKur3uUuyivp9Sm6J+qtTckvUX52SW6L+6pTcEvVXp+SWqL86JbdE/dUpuSXqr07JLVF/dUpuifqrU3JL1F+dlmQV9fu0"
    "JKuo36clWUX9Pi3JKur3aUlWWb9bklXW75Jbov7qlNwS9Ven5Jaovzolt0T91Sm5JeqvTsktUX91Sm6J+qtTckvUX52SW6L+6pTcEvVXpydZZf"
    "3uSVZZv3uSVdbvJckq6/eSZJX1e0myyvpdckvUX52SW6L+6pTcEvVXp+SWqL86JbdE/dUpuSXqr07JLVF/dUpuifqrU3JL1F+dklui/uqMJKus"
    "3yPJKuv3SLLK+j2SrLJ+jySrrN8jySrrd8UtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNeqvTsUtNe"
    "qvzppklfV7S7LK+r0lWWX93pKssn5vSVZZv7ckq6zfFbfUqL86FbfUqL86FbfUqL86FbfUqL86FbfUqL86FbfUqL86FbfUqL86FbfUqL86FbfU"
    "qL86FbfUqL86e5JV1u89ySrr955klfV7T7LK+r0nWWX9PpKssn5X3FKj/upU3FKj/upU3FKj/upU3FKj/upU3FKj/upU3FKj/upU3FKj/upU3F"
    "Kj/upU3FKj/upU3FKj/uqcSVZZv88kq6zfZ5JV1u8zySrr95lklfX7TLLK+l1xS436q1NxS436q1NxS436q7ZT4FKjAut+vCXjKxvvyfjGxpdk"
    "fGfjIxk/2PiajJ9sfNPjUc3vxyeZRT2/H5+EFhX9fnySWmOptSS1xlJrSWqNpdaS1BpLraKYGrVZ9+MjGc/uHMUxtcB9r0CmFrjvFcnUAve9Qp"
    "la4L5XLFML3PcKZmqB+17RTC1w3yucqQXue09SC/vek9TCvvcktbDvPUkt7HtPUgv73pPUwr5XVFOruO8V1tQq7nvFNbWK+16BTa3ivldkU6u4"
    "7xXa1Crue8U2tYr7XsFNreK+V3RTq7jvFd7UKu77kqQW9n0kqYV9H0lqYd9HklrY95GkFvZ9JKmFfa8op9Zw3yvMqTXc94pzag33vQKdWsN9L0"
    "mnhvteok4N971knRruewk7Ndz3knZquO8l7tRw39cktbDva5Ja2Pc1SS3s+5qkFvZ9TVIL+74lqYV9L6mnjvteYk8d973knjruewk+ddz3knzq"
    "uO8l+tRx30v2qeO+l/BTx30v6aeO+17iTx33fU9SC/u+J6mFfd+T1MK+70lqYd/3JLWw73uSWtj3koIauO8lBjVw30sOauC+lyDUwH0vSaiB+1"
    "6iUAP3vWShBu57CUMN3PeShhq47yUONXDfjyS1sO9HklrY9yNJLez7maQW9v1MUgv7fiaphX0vqaiJ+15iURP3veSiJu57CUZN3PeSjJq47yUa"
    "NXHfSzaKOrJmko2ikux+vCXjJxvvejzre9slqWV9b7sktazvbZeklvW97ZLUsr63XZJa1ve2S1LL+t4UG9WpLWum2KhOddn9eEvGsztHsVGdCr"
    "P78SUZz+4cxUZ1qszux9dkPOt7xUb1He57xUb1He57xUb1He57S1IL+96T1MK+9yS1sO89SS3se09SC/vek9TCvldsVDfc94qN6ob7XrFR3XDf"
    "KzaqG+57xUZ1w32v2KhuuO8VG9UN971io7rhvldsVDfc94qN6ob7viSphX1fktTCvi9JamHflyS1sO9LklrY95GkFva9YqO6475XbFR33PeKje"
    "qO+16xUd1x3ys2qjvue8VGdcd9r9io7rjvFRvVHfe9YqO6475XbFR33Pc1SS3s+5qkFvZ9TVIL+74mqYV9X5PUwr6vSWph3ys2qhfc94qN6gX3"
    "vWKjOvZrTbFRHfu1ptiojv1aU2xUx36tKTaqY7/WFBvVsV9rio3q2K81xUZ17NdaS1IL+74lqYV935LUwr7vSWph3/cktbDve5Ja2PeKjerYrz"
    "XFRnXs15piozr2a02xUR37tabYqI79WlNsVMd+rSk2qmO/1hQb1bFfa4qN6tivNcVGdezX2khSC/t+JKmFfT+S1MK+H0lqYd+PJLWw70eSWtj3"
    "io3q2K81xUZ17NeaYqM69mtNsVEd+7Wm2KiO/VpTbFTHfq0pNqpjv9YUG9WxX2uKjerYrzXFRnXs19pMUsv63ndJalnf+y5JLet73yWpZX3vuy"
    "S1rO99l6SW9b0rNqpjv9YVG9WxX+uKjerYr3XFRnXs17pko7Bf65KNwn6tSzYK+7Uu2Sjs17pko7Bf65KNwn6tW5Ja2PeWpBb2vSWphX1vSWph"
    "31uSWtj3nqQW9r1ko7Bf65KNwn6tSzYK+7Uu2Sjs17pko7Bf65KNwn6tSzYK+7Uu2Sjs17pko7Bf65KNwn6tlyS1sO9LklrY9yVJLez7kqQW9n"
    "1JUgv7viSphX0v2Sjs17pko7Bf65KNwn6tSzYK+7Uu2Sjs17pko7Bf65KNwn6tSzYK+7Uu2Sjs17pko7Bf65GkFvZ9JKmFfR9JamHf1yS1sO9r"
    "klrY9zVJLex7yUZhv9YlG4X9WpdsFPZrXbJR2K91yUZhv9YlG4X9WpdsFPZrXbJR2K91yUZhv9YlG4X9Wm9JamHftyS1sO9bklrY9y1JLez7lq"
    "QW9n1LUgv7XrFRA/u1rtiogf1aV2zUwH6tKzZqYL/WFRs1sF/rio0a2K91xUYN7Ne6YqMG9mtdsVED+7Wu2KiB/VrvSWph348ktbDvR5Ja2Pcj"
    "SS3s+5GkFvb9SFIL+16xUQP7ta7YqIH9Wlds1MB+rSs2amC/1hUbNbBf64qNGtivdcVGDezXumKjBvZrXbFRA/u1rtiogf1an0lqYd/PJLWw72"
    "eSWtj3M0kt7PuZpJb1fdklqWV9XxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWxQbNbBfWyxJ"
    "Lev7YklqWd8XS1LL+r5YklrW98WS1MK+tyS1sO8VGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1sUGzWwX1"
    "sUGzWwX1s8SS3se09SC/vek9TCvi9JamHflyS1sO9LklrY94qNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtiv"
    "LYqNGtivLYqNGtivLZGkFvZ9JKmFfR9JamHfR5Ja2PeRpBb2fSSphX2v2KiB/dqi2KiB/dqi2KiB/dqi2KiB/dqi2KiB/dqi2KiB/dqi2KiB/d"
    "qi2KiB/dqi2KiB/dqi2KiB/dpSk9TCvm9JamHftyS1sO9bklrY9y1JLez7lqQW9r1iowb2a4tiowb2a4tiowb2a4tiowb2a4tko7BfWyQbhf3a"
    "Itko7NcWyUZhv7ZINgr7tUWyUdivLT1JLez7nqQW9n1PUgv7viephX3fk9TCvh9JamHfSzYK+7VFslHYry2SjcJ+bZFsFPZri2SjsF9bJBuF/d"
    "oi2Sjs1xbJRmG/tkg2Cvu1RbJR2K8tM0kt7PuZpBb2/UxSC/t+JqmFfT+T1MK+n0lqYd9LNgr7tUWyUdivLZKNwn5tSDYK+7Uh2Sjs14Zko7Bf"
    "G5KNwn5tSDYK+7Uh2Sjs14Zko7BfG7sktazvY5eklvV97JLUsr4PS1LL+j4sSS3r+7AktazvQ7JR2K8NyUZhvzYkG4X92pBsFPZrQ7JR2K8NyU"
    "ZhvzYkG4X92pBsFPZrQ7JR2K8NyUZhvzY8SS3se09SC/vek9TCvvcktbDvPUkt7HtPUgv7XrFRE/u1odioif3aUGzUxH5tKDZqYr82FBs1sV8b"
    "io2a2K8NxUZN7NeGYqMm9mtDsVET+7Wh2KiJ/dooSWph30eSWtj3kaQW9n0kqYV9H0lqYd9HklrY94qNmtivDcVGTezXhmKjJvZrQ7FRE/u1od"
    "ioif3aUGzUxH5tKDZqYr82FBs1sV8bio2a2K8NxUZN7NdGTVIL+74mqYV9X5PUwr6vSWph39cktbDvW5Ja2PeKjZrYrw3FRk3s14Zioyb2a0Ox"
    "URP7taHYqIn92lBs1MR+bSg2amK/NhQbNbFfG4qNmtivDcVGTezXRk9SC/u+J6mFfd+T1MK+70lqYd/3JLWw73uSWtj3io2a2K8NxUZN7NeGYq"
    "Mm9mtDsVET+7Wh2KiJ/dpQbNTEfm0oNmpivzYUGzWxXxuKjZrYrw3FRk3s18ZIUgv7fiSphX0/ktTCvp9JamHfzyS1sO9nklrY94qNmtivDcVG"
    "TezXhmKjJvZrQ7FRE/u1odioif3aUGzUxH5tKDZqYr+2KjZqYr+2KjZqYr+2KjZqYr+27pLUsr6vuyS1rO/rLkkt6/u6S1LL+r7uktSyvq+7JL"
    "Ws76tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6tioyb2a6slqYV970lqYd97klrY956kFva9"
    "J6mFfe9JamHfKzZqYr+2KjZqYr+2KjZqYr+2KjZqYr+2SjYK+7VVslHYr62SjcJ+bZVsFPZrq2SjsF9bJRuF/dpaktTCvi9JamHflyS1sO9Lkl"
    "rY9yVJLez7SFIL+16yUdivrZKNwn5tlWwU9murZKOwX1slG4X92irZKOzXVslGYb+2SjYK+7VVslHYr62SjcJ+ba1JamHf1yS1sO9rklrY9zVJ"
    "Lez7mqQW9n1NUgv7XrJR2K+tko3Cfm2VbBT2a6tko7BfWyUbhf3aKtko7NdWyUZhv7ZKNgr7tVWyUdivrZKNwn5tbUlqYd+3JLWw71uSWtj3PU"
    "kt7PuepBb2fU9SC/teslHYr62SjcJ+bZVsFPZrq2SjsF9bJRuF/doq2Sjs11bJRmG/tko2Cvu1VbJR2K+tko3Cfm0dSWph348ktbDvR5Ja2Pcj"
    "SS3s+5GkFvb9SFL72/r+X/72V/yuvour/u71f3z985t3/74/f/3Tn358GHl9e/bq9Or66vzy7vaXqX9688fX//2X3p09/8crObs4e353c/7On/"
    "z49X89/MGXF+/d8j+++e6nH77/8eeHP/rBXn/z7Xe//OG/v/np9Q/f/+W7n1//+c3bq/v5x//8+v2v0taX6OT09Obs9vaDvjrx3tjNzJ5cX1+c"
    "Pz+5O7+6BKM383p9cnl28ezm7OT0q38c/ee//L+//Pzm283Z/vf/8v13r79988evv334X7x7gd9/8807f/Dixe/eu5rNeO/vr1cXZ89u707ubs"
    "EdvJntv95Nz3Zbv018zH9okxfjh72YLi+mHPZihryY+MCLeW/0lKMrGb2Ng/x9dkOzTc7uaLbL2QPNLnL2RLNDzd76JeYDZsumMEOzZfDN0WyZ"
    "YytotoyloViazKWhXLrMpaFcusyloVy6zKWhXLrMpaFcusylo1y6zKWjXLrMpaNcusylo1y6zKWjXLrMpaNcFplLR7ksMpeOcllkLh3lsshcOs"
    "plkbksKJdF5rKgXBaZy4JyWWQuC8plkbksKJdF5rKgXIbMZUG5DJnLgnIZMpcF5TJkLgvKZchcBsplyFwGymXIXAbKZchcBsplyFwGymXIXAbK"
    "ZZW5DJTLKnMZKJdV5jJQLqvMZaBcVpnLinJZZS4rymWVuawol1XmsqJcVpnLinJZZS4rymWTuawol03msqJcNpnLinLZZC4rymWTuWwol03msq"
    "FcNpnLhnLZZC4bymWTuWwol03msqFcdpnLhnLZZS4bymWXuWwol13msqFcdpnLjnLZZS47ymWXuewol13msqNcdpnLjnLZZS47yuWQuewol0Pm"
    "sqNcDpnLjnI5ZC47yuWQuRwol0PmcqBcDpnLgXI5ZC4HyuWQuRwol0PmcqBcTpnLgXI5ZS4HyuWUuRwol1PmcqBcTpnLiXI5ZS4nyuWUuZwol1"
    "PmcqJcTpnLybACmcsJuQIZzMnAgp1M5mRkwU5GczK0YCezORlbsFPhfPiOoOFVDmd0wa7J4Qwv2HU5nPEFuyGHM8BgN+VwllCJ/hhFf0wOZwmV"
    "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"
    "ilQyap2aQpWMaqemWCWj3qkpWMmoeGqKVjJqnprClYyqpzaTrLJ+n0lWWb/PJKus32eSVbhOIMkq6/eZZJX1u6KWjBqoprAlowqqKW7JqIPqil"
    "syKqG64paMWqiuuCWjGqorbsmoh+qKWzIqorriloyaqK64JaMqqu+SrKJ+912SVdTvvkuyivrdLckq6ne3JKtsX4wlWYULY1RWqZHqilsyqqS6"
    "4paMOqmuuCWjUqorbsmoleqKWzKqpbrilox6qa64JaNiqituyaiZ6opbMqqmuidZZf3uSVZZv3uSVdbvnmSV9bsnWWX97klWWb8rbsmooeqKW7"
    "KKV4JZMh3dM4pbMiqpuuKWjFqqrrglo5qqK27JqKfqilsyKqq64paMmqquuCWjqqqXJKus3yPJKuv3SLLK+j2SrLJ+jySrrN8jySrrd8UtGTVW"
    "XXFLRpVVV9ySNbzzcSTT2T0zk+nonpHcEtVWXXJL1Ft1yS1RcdUlt0TNVZfcElVXvSZZZf1ek6yyfq9JVlm/1ySrrN9rklXW7y3JKut3yS1Rf9"
    "Ult0T9VZfcEvVXXXJL1F91yS11vNW3JdPZPdOT6ajfJbdE/VWX3BL1V11yS9Rf9Z5klfV7T7LK+r0nWWX93pOssn7vSVZZv/ckq6zfJbdE/VWX"
    "3BL1V11yS9RfdcktUX/VJbdE/VWX3BL1V11ySwPvbY9kOup3yS1Rf9Ult0T9VR9JVlm/jySrrN9HklXW7zPJKuv3mWSV9ftMssr6XXJL1F91yS"
    "1Rf9Ult0T9VZfcEvVXXXJL1F91yS1Rf9Ult0T91SK5JeqvFsktTXwyh+vp7GiOXZJVdjbHLskqO5xjl2SVnc6xS7LKjufYJVll53PskqyyAzoU"
    "t+TUXy2KW3LqrxbFLTn1V4vilpz6q0VxS0791aK4Jaf+alHcklN/tShuyam/WhS35NRfLYpb8h0+einJKjx7Kckq63dPssr63ZOssn73JKus3z"
    "3JKut3xS059VeL4pac+qtFcUtO/dWiuCWn/mpR3JJTf7Uobsmpv1oUt+TUXy2KW3LqrxbFLTn1V4vilpz6q6UkWWX9XpKswsP1kqyyfi9JVlm/"
    "lySrrN8jySrrd8UtOfVXi+KWnPqrRXFLTv3Vorglp/5qUdySU3+1KG7Jqb9aFLfk1F8tilty6q8WxS05PjlVcUuOj06tSVZZv9ckq6zfa5JV1u"
    "81ySo8PjXJKuv3mmSV9bvilhyfoKq4JcdHqCpuyam/WhS35NRfLYpbcuqvFsUtOfVXi+KWnPqrRXFLTv3Vorglp/5qUdySU3+1tCSrrN9bklXW"
    "7y3JKuv3nmSV9XtPssr6vSdZhQdkq6xSf7Uobsmpv1oUt+TUXy2KW3LqrxbFLTn1V4vilpz6q0VxS0791aK4Jaf+alHcklN/tShuyam/WkaSVd"
    "bvI8kq6/eRZJX1+0iyyvp9JFll/T6SrLJ+V9ySU3+1KG7Jqb9aFLfk1F8tilty6q8WxS059VeL4pac+qtFcUtO/dWiuCWn/mpR3JJTf7Uobsmp"
    "v1pmklXU77FLsor6PXZJVlG/xy7JKur32CVZRf0euySrqN9DcUtO/dVQ3JJTfzUUt+TUXw3FLTn1V0NyS9RfDcktUX81JLdE/dWQ3BL1V0NyS9"
    "RfDcktUX81LMkq63dLssr63ZKssn63JKus3y3JKut3T7LK+l1yS9RfDcktUX81JLdE/dWQ3BL1V0NyS9RfDcktUX81JLdE/dWQ3BL1V0NyS9Rf"
    "DcktUX81SpJV1u8lySrr95JklfV7SbLK+r0kWWX9XpKssn6X3BL1V0NyS9RfDcktUX81JLdE/dWQ3BL1V0NyS9RfDcktUX81JLdE/dWQ3BL1V0"
    "NyS9RfjUiyyvo9kqyyfo8kq6zfa5JV1u81ySrr95pklfW75JaovxqSW6L+akhuifqrIbkl6q+G5JaovxqSW6L+akhuifqrIbkl6q+G5JaovxqS"
    "W6L+arQkq6zfW5JV1u8tySrr95ZklfV7S7LK+r0lWWX9rrilQv3VUNxSof5qKG6pUH81FLdUqL8ailsq1F8NxS0V6q+G4pYK9VdDcUuF+quhuK"
    "VC/dVQ3FKh/mr0JKus30eSVdbvI8kq6/eRZJX1+0iyyvp9JFll/a64pUL91VDcUqH+aihuqVB/NRS3VKi/GopbKtRfDcUtFeqvhuKWCvVXQ3FL"
    "hfqrobilQv3VUNxSof5qzCSrrN9nklXW7zPJKuv3mWSV9ftMsor6ve6SrKJ+r4pbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrY"
    "pbKtRfrYpbKtRfrYpbKtRfrYpbKtRfrZZkFfV7tSSrqN+rJVlF/V4tySrq92pJVlm/W5JV1u+KWyrUX62KWyrUX62KWyrUX62KWyrUX62KWyrU"
    "X62KWyrUX62KWyrUX62KWyrUX62KWyrUX62KWyrUX62eZJX1uydZZf3uSVZZv5ckq6zfS5JV1u8lySrrd8UtFeqvVsUtFeqvVsUtFeqvVsUtFe"
    "qvVsUtFeqvVsUtFeqvVsUtFeqvVsUtFeqvVsUtFeqvVsUtFeqv1kiyyvo9kqyyfo8kq6zfI8kq6/dIssr6PZKssn5X3FKh/mpV3FKh/mpV3FKh"
    "/mpV3FKh/mpV3FKh/mpV3FKh/mpV3FKh/mpV3FKh/mpV3FKh/mpV3FKh/mqtSVZZv7ckq6zfW5JV1u8tySrr95ZklfV7S7LK+l1xS4X6q1VxS4"
    "X6q1VxS4X6q1VxS4X6q1VyS9RfrZJbov5qldwS9Ver5Jaov1olt0T91Sq5Jeqv1p5klfV7T7LK+r0nWWX93pOssn7vSVZZv48kq6zfJbdE/dUq"
    "uSXqr1bJLVF/tUpuifqrVXJL1F+tklui/mqV3BL1V6vklqi/WiW3RP3VKrkl6q/WmWSV9ftMssr6fSZZZf0+k6yyfp9JVlm/zySrrN8lt0T91S"
    "q5JeqvVsktUX+1SW6J+qtNckvUX22SW6L+apPcEvVXm+SWqL/aJLdE/dUmuSXqr7ZdklXU722XZBX1e9slWUX93izJKur3ZklWUb83S7KK+r1J"
    "bon6q01yS9RfbZJbov5qk9wS9Veb5Jaov9okt0T91Sa5JeqvNsktUX+1SW6J+qtNckvUX22eZJX1uydZZf3uSVZZv3uSVdbvnmSV9bsnWWX9rr"
    "iloP5qU9xSUH+1KW4pqL/aFLcU1F9tilsK6q82xS0F9Veb4paC+qtNcUtB/dWmuKWg/mpT3FJQf7WVJKus3yPJKuv3SLLK+j2SrLJ+jySrrN8j"
    "ySrrd8UtBfVXm+KWgvqrTXFLQf3VpriloP5qU9xSUH+1KW4pqL/aFLcU1F9tilsK6q82xS0F9Veb4paC+qutJlll/V6TrLJ+r0lWWb/XJKus32"
    "uSVdbvLckq63fFLQX1V5viloL6q01xS0H91aa4paD+alPcUlB/tSluKai/2hS3FNRfbYpbCuqvNsUtBfVXm+KWgvqrrSdZZf3ek6yyfu9JVlm/"
    "9ySrrN97klXW7z3JKut3xS0F9Veb4paC+qtNcUtB/dWmuKWg/mpT3FJQf7Upbimov9oUtxTUX22KWwrqrzbFLQX1V5viloL6q20kWWX9PpKssn"
    "4fSVZZv88kq6zfZ5JV1u8zySrrd8UtBfVXm+KWgvqrTXFLQf3VpriloP5qU9xSUH+1KW4pqL/aFLcU1F/tilsK6q92xS0F9Ve74paC+qt9l2QV"
    "9XvfJVlF/d53SVZRv/ddklXU732XZBX1e98lWUX93hW3FNRf7YpbCuqvdsUtBfVXu+KWgvqrXXFLQf3VrriloP5qV9xSUH+1K24pqL/aFbcU1F"
    "/tilsK6q92S7LK+t2TrLJ+9ySrrN89ySrrd0+yyvrdk6yyflfcUlB/tStuKai/2hW3FNRf7YpbCuqvdsktUX+1S26J+qtdckvUX+2SW6L+apfc"
    "EvVXu+SWqL/aS5JV1u8lySrr95JklfV7SbLK+r0kWWX9HklWWb9Lbon6q11yS9Rf7ZJbov5ql9wS9Ve75Jaov9olt0T91S65JeqvdsktUX+1S2"
    "6J+qtdckvUX+01ySrr95pklfV7TbLK+r0mWWX9XpOssn6vSVZZv0tuifqrXXJL1F/tklui/mqX3BL1V7vklqi/2iW3RP3VLrkl6q92yS1Rf7VL"
    "bon6q11yS9Rf7S3JKuv3lmSV9XtLssr6vSdZZf3ek6yyfu9JVlm/S26J+qtdckvUX+2SW6L+apfcEvVXu+SWqL/aJbdE/dUuuSXqr3bJLVF/tU"
    "tuifqrXXJL1F/tI8kq6/eRZJX1+0iyyvp9JFll/T6SrLJ+H0lWWb8rbqlSf7UrbqlSf7UrbqlSf7UrbqlSf7UrbqlSf7UrbqlSf7UrbqlSf7Ur"
    "bqlSf7UrbqlSf7UrbqlSf7XPJKuo38cuySrq97FLsor6feySrKJ+H7skq6jfxy7J6m/r93/529/wsL3+l0D97vV/fP3zm3f/vj9//dOffnwY+e"
    "XF7f7vfFbt2XwnAn9688fX//2X3p09/8crObs4e353c/7On/z49X/9dd57N/uPb7776Yfvf/z54Y9+sNfffPvdL3/4729+ev3D93/57ufXf37z"
    "9up+/vE/v37vi7R585ycnt6c3d5+0Fcn3hu7edecXF9fnD8/uTu/ugSjN2+Z65PLs4tnN2cnp1990Gj7+3/5/rvX377549ffPvwP3r2+77/55p"
    "0/ePHid++fMLl1Mfvb69XF2bPbu5O7W3T/qp8G1JAeioyr1JAeioyr1JAeioyr1JAeioyr1JAeioyr1JAeioyr1JAeioyr1JAeioyr1JAeioyr"
    "1JAelmSV/QZhSVbZbxCWZJX9BmFJVtlvEJZklf0G4UlW0SfEoci4Sg3poci4Sg3poci4Sg3poci4Sg3poci4Sg3poci4Sg3poci4Sg3poci4Sg"
    "3poci4Sg3poci4Sg3pUZKssn4vSVZZv5ckq6zfS5JV1u8lySrr95JklfW7IuMqNaSHIuMqNaSHIuMqNaSHIuMqNaSHIuMqNaSHIuMqNaSHIuMq"
    "NaSHIuMqNaSHIuMqNaSHIuMqNaRHJFll/R5JVlm/R5JV1u81ySrr95pklfV7TbLK+l2RcZUa0kORcZUa0kORcZUa0kORcZUa0kORcZUa0kORcZ"
    "Ua0kORcZUa0kORcZUa0kORcZUa0kORcZUa0qMlWWX93pKssn5vSVZZv7ckq6zfW5JV1u8tySrrd0XGVWpID0XGVWpID0XGVWpID0XGVWpID0XG"
    "VWpID0XGVWpID0XGVWpID0XGVWpID0XGVWpID0XGVWpIj55klfX7SLLK+n0kWWX9PpKssn4fSVZZv48kq6zfFRlXqSE9FBlXqSE9FBlXqSE9FB"
    "lXqSE9JBlHDekhyThqSA9JxlFDekgyjhrSQ5Jx1JAekoyjhvSYSVZZv88kq6zfZ5JV1u8zySrr95lkFfX73CVZRf0+JRlHDekpyThqSE9JxlFD"
    "ekoyjhrSU3JL1JCekluihvSU3BI1pKfklqghPSW3RA3pKbklakhPS7KK+n1aklXU79OSrKJ+n5ZkFfX7tCSrrN8tySrrd8ktUUN6Sm6JGtJTck"
    "vUkJ6SW6KG9JTcEjWkp+SWqCE9JbdEDekpuSVqSE/JLVFDekpuiRrS05Ossn73JKus3z3JKuv3kmSV9XtJssr6vSRZZf0uuSVqSE/JLVFDekpu"
    "iRrSU3JL1JCekluihvSU3BI1pKfklqghPSW3RA3pKbklakhPyS1RQ3pGklXW75FklfV7JFll/R5JVlm/R5JV1u+RZJX1u+KWGjWkp+KWGjWkp+"
    "KWGjWkp+KWGjWkp+KWGjWkp+KWGjWkp+KWGjWkp+KWGjWkp+KWGjWkp+KWGjWkZ02yyvq9JVll/d6SrLJ+b0lWWb+3JKus31uSVdbviltq1F+d"
    "iltq1F+diltq1F+diltq1F+diltq1F+diltq1F+diltq1F+diltq1F+diltq1F+diltq1F+dPckq6/eeZJX1e0+yyvq9J1ll/d6TrLJ+H0lWWb"
    "8rbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3UqbqlRf3XOJKus32eSVdbvM8kq6/eZZJX1+0yy"
    "yvp9Jlll/a64pUb91am4pUb91am4pUb9VdspcKlRgXU/3pLxlY33ZHxj40syvrPxkYwfbHxNxk82vunxqOb345PMop7fj09Ci4p+Pz5JrbHUWp"
    "JaY6m1JLXGUmtJao2lVlFMjdqs+/GRjGd3juKYWuC+VyBTC9z3imRqgfteoUwtcN8rlqkF7nsFM7XAfa9opha47xXO1AL3vSephX3vSWph33uS"
    "Wtj3nqQW9r0nqYV970lqYd8rqqlV3PcKa2oV973imlrFfa/AplZx3yuyqVXc9wptahX3vWKbWsV9r+CmVnHfK7qpVdz3Cm9qFfd9SVIL+z6S1M"
    "K+jyS1sO8jSS3s+0hSC/s+ktTCvleUU2u47xXm1Brue8U5tYb7XoFOreG+l6RTw30vUaeG+16yTg33vYSdGu57STs13PcSd2q472uSWtj3NUkt"
    "7PuapBb2fU1SC/u+JqmFfd+S1MK+l9RTx30vsaeO+15yTx33vQSfOu57ST513PcSfeq47yX71HHfS/ip476X9FPHfS/xp477viephX3fk9TCvu"
    "9JamHf9yS1sO97klrY9z1JLex7SUEN3PcSgxq47yUHNXDfSxBq4L6XJNTAfS9RqIH7XrJQA/e9hKEG7ntJQw3c9xKHGrjvR5Ja2PcjSS3s+5Gk"
    "Fvb9TFIL+34mqYV9P5PUwr6XVNTEfS+xqIn7XnJRE/e9BKMm7ntJRk3c9xKNmrjvJRtFHVkzyUZRSXY/3pLxk413PZ71ve2S1LK+t12SWtb3tk"
    "tSy/redklqWd/bLkkt63vbJallfW+KjerUljVTbFSnuux+vCXj2Z2j2KhOhdn9+JKMZ3eOYqM6VWb342synvW9YqP6Dve9YqP6Dve9YqP6Dve9"
    "JamFfe9JamHfe5Ja2PeepBb2vSephX3vSWph3ys2qhvue8VGdcN9r9iobrjvFRvVDfe9YqO64b5XbFQ33PeKjeqG+16xUd1w3ys2qhvue8VGdc"
    "N9X5LUwr4vSWph35cktbDvS5Ja2PclSS3s+0hSC/tesVHdcd8rNqo77nvFRnXHfa/YqO647xUb1R33vWKjuuO+V2xUd9z3io3qjvtesVHdcd8r"
    "Nqo77vuapBb2fU1SC/u+JqmFfV+T1MK+r0lqYd/XJLWw7xUb1Qvue8VG9YL7XrFRHfu1ptiojv1aU2xUx36tKTaqY7/WFBvVsV9rio3q2K81xU"
    "Z17NeaYqM69mutJamFfd+S1MK+b0lqYd/3JLWw73uSWtj3PUkt7HvFRnXs15piozr2a02xUR37tabYqI79WlNsVMd+rSk2qmO/1hQb1bFfa4qN"
    "6tivNcVGdezXmmKjOvZrbSSphX0/ktTCvh9JamHfjyS1sO9HklrY9yNJLex7xUZ17NeaYqM69mtNsVEd+7Wm2KiO/VpTbFTHfq0pNqpjv9YUG9"
    "WxX2uKjerYrzXFRnXs15piozr2a20mqWV977sktazvfZeklvW975LUsr73XZJa1ve+S1LL+t4VG9WxX+uKjerYr3XFRnXs17piozr2a12yUdiv"
    "dclGYb/WJRuF/VqXbBT2a12yUdivdclGYb/WLUkt7HtLUgv73pLUwr63JLWw7y1JLex7T1IL+16yUdivdclGYb/WJRuF/VqXbBT2a12yUdivdc"
    "lGYb/WJRuF/VqXbBT2a12yUdivdclGYb/WS5Ja2PclSS3s+5KkFvZ9SVIL+74kqYV9X5LUwr6XbBT2a12yUdivdclGYb/WJRuF/VqXbBT2a12y"
    "UdivdclGYb/WJRuF/VqXbBT2a12yUdiv9UhSC/s+ktTCvo8ktbDva5Ja2Pc1SS3s+5qkFva9ZKOwX+uSjcJ+rUs2Cvu1Ltko7Ne6ZKOwX+uSjc"
    "J+rUs2Cvu1Ltko7Ne6ZKOwX+uSjcJ+rbcktbDvW5Ja2PctSS3s+5akFvZ9S1IL+74lqYV9r9iogf1aV2zUwH6tKzZqYL/WFRs1sF/rio0a2K91"
    "xUYN7Ne6YqMG9mtdsVED+7Wu2KiB/VpXbNTAfq33JLWw70eSWtj3I0kt7PuRpBb2/UhSC/t+JKmFfa/YqIH9Wlds1MB+rSs2amC/1hUbNbBf64"
    "qNGtivdcVGDezXumKjBvZrXbFRA/u1rtiogf1aV2zUwH6tzyS1sO9nklrY9zNJLez7maQW9v1MUsv6vuyS1LK+L4qNGtivLYqNGtivLYqNGtiv"
    "LYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLYqNGtivLZaklvV9sSS1rO+LJallfV8sSS3r+2JJamHfW5Ja2PeKjRrYry2KjR"
    "rYry2KjRrYry2KjRrYry2KjRrYry2KjRrYry2KjRrYry2KjRrYry2KjRrYry2KjRrYry2epBb2vSephX3vSWph35cktbDvS5Ja2PclSS3se8VG"
    "DezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXFsVGDezXlkhSC/s+ktTCvo8ktbDvI0kt7PtIUgv7Pp"
    "LUwr5XbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm1RbNTAfm2pSWph37cktbDvW5Ja2PctSS3s"
    "+5akFvZ9S1IL+16xUQP7tUWxUQP7tUWxUQP7tUWxUQP7tUWyUdivLZKNwn5tkWwU9muLZKOwX1skG4X92iLZKOzXlp6kFvZ9T1IL+74nqYV935"
    "PUwr7vSWph348ktbDvJRuF/doi2Sjs1xbJRmG/tkg2Cvu1RbJR2K8tko3Cfm2RbBT2a4tko7BfWyQbhf3aItko7NeWmaQW9v1MUgv7fiaphX0/"
    "k9TCvp9JamHfzyS1sO8lG4X92iLZKOzXFslGYb82JBuF/dqQbBT2a0OyUdivDclGYb82JBuF/dqQbBT2a0OyUdivjV2SWtb3sUtSy/o+dklqWd"
    "+HJallfR+WpJb1fViSWtb3Idko7NeGZKOwXxuSjcJ+bUg2Cvu1Idko7NeGZKOwXxuSjcJ+bUg2Cvu1Idko7NeGZKOwXxuepBb2vSephX3vSWph"
    "33uSWtj3nqQW9r0nqYV9r9ioif3aUGzUxH5tKDZqYr82FBs1sV8bio2a2K8NxUZN7NeGYqMm9mtDsVET+7Wh2KiJ/dpQbNTEfm2UJLWw7yNJLe"
    "z7SFIL+z6S1MK+jyS1sO8jSS3se8VGTezXhmKjJvZrQ7FRE/u1odioif3aUGzUxH5tKDZqYr82FBs1sV8bio2a2K8NxUZN7NeGYqMm9mujJqmF"
    "fV+T1MK+r0lqYd/XJLWw72uSWtj3LUkt7HvFRk3s14Zioyb2a0OxURP7taHYqIn92lBs1MR+bSg2amK/NhQbNbFfG4qNmtivDcVGTezXhmKjJv"
    "ZroyephX3fk9TCvu9JamHf9yS1sO97klrY9z1JLex7xUZN7NeGYqMm9mtDsVET+7Wh2KiJ/dpQbNTEfm0oNmpivzYUGzWxXxuKjZrYrw3FRk3s"
    "14Zioyb2a2MkqYV9P5LUwr4fSWph388ktbDvZ5Ja2PczSS3se8VGTezXhmKjJvZrQ7FRE/u1odioif3aUGzUxH5tKDZqYr82FBs1sV9bFRs1sV"
    "9bFRs1sV9bFRs1sV9bd0lqWd/XXZJa1vd1l6SW9X3dJallfV93SWpZ39ddklrW91WxURP7tVWxURP7tVWxURP7tVWxURP7tVWxURP7tVWxURP7"
    "tVWxURP7tVWxURP7tVWxURP7tVWxURP7tdWS1MK+9yS1sO89SS3se09SC/vek9TCvvcktbDvFRs1sV9bFRs1sV9bFRs1sV9bFRs1sV9bJRuF/d"
    "oq2Sjs11bJRmG/tko2Cvu1VbJR2K+tko3Cfm0tSWph35cktbDvS5Ja2PclSS3s+5KkFvZ9JKmFfS/ZKOzXVslGYb+2SjYK+7VVslHYr62SjcJ+"
    "bZVsFPZrq2SjsF9bJRuF/doq2Sjs11bJRmG/ttYktbDva5Ja2Pc1SS3s+5qkFvZ9TVIL+74mqYV9L9ko7NdWyUZhv7ZKNgr7tVWyUdivrZKNwn"
    "5tlWwU9murZKOwX1slG4X92irZKOzXVslGYb+2tiS1sO9bklrY9y1JLez7nqQW9n1PUgv7viephX0v2Sjs11bJRmG/tko2Cvu1VbJR2K+tko3C"
    "fm2VbBT2a6tko7BfWyUbhf3aKtko7NdWyUZhv7aOJLWw70eSWtj3I0kt7PuRpBb2/UhSC/t+JKn9bX3/L3/7K363/x32l2D97vV/fP3zm3f/vj"
    "9//dOffnwYeXp+8tnl1e3d+fPbX4b+6c0fX//333l39vwfL+Ts4uz53c35O3/y49f/9fAH/9ffu+N/fPPdTz98/+PPD3/0g73+5tvvfvnDf3/z"
    "0+sfvv/Ldz+//vObtxf384//+fX7X6Str9DN2cnpVx/0pbG//5fvv3v97Zs/fv3tw//gq7N3/sHff/PNL39yefW79y5jM+LPr16+OLl4hOt4cX"
    "J+sbyQm5f7v+O9i9kshBfPty/mz3/5f3/5+c23m1fj8Kuyme2785dXr+4+6KsS703djPTN7fX5JZm6GbXrq4vTi6/A1LmY+uLmX8HUbRLi5PT0"
    "5uz2lszdTNPJ9fXF+fOTu/OrS7Twamv2y5Mvb+7IF3gbTDi/PH+O7oZtYuDs/mxr6odH6N2v5HsJunrx4v0IbbMFz1+eXl+eku/GWIz9/PwLMn"
    "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"
    "bzO01dms3v268f6ouh8ehmzn5ofXQlZz+0kaF1MbQ/uuCzHzrI0L4YOh/9OfTDzb8jU5eRskcXcx6m+qMbOQ9TSap8lSqLR9dwHqaSXPkqV0aC"
    "tVj2eG6HVaEXP3H9sFexHd17O8ZHkfd+hA8iT+7Lk17V9lPIk/t42qva7q5bO8oHkCd3T35d2/155099XZsNzOvhHlzSdn3fH7a+F3bW/WHrey"
    "FzXR34a7F4lOpH8SC1HMVj1DiCh6gfCoY89g+F7UeqJ1dP9GP93ed69dc813v7RunTg72P+WDv5eUn+vcT/fv/Q/r3xc3nh76OT/TvPxn9uzcE"
    "72+Ogf59ClS9Hgt0246Fh+5HC+qOYwV1Fwjxq8+PFiH+YFD3V+K/l4/+CPls+ycYfIR89mq/i/HRHyEfHp9YPHQ+OG60eOx8cNxocazQwXGj7U"
    "fNRwF8z8fBqn/F0+LnH76l5yDPiz+/e/Lr2v4A/OXT3x6lHCsWHceKRW+v3TuGK2sfBYvuHwWL3izMh5/9Lx59z9erSzZ1+2EsRbi3H64eA9O8"
    "/YD1CDDwbYgVY57bhP7Jq4u7R0dS94vhrm4oPdp+3VPmZ59ff3rK/Okp829+yrz/dPPsYWn84U8LbdvHs3x2tn9wdfir2fz5d/H8D8/2v1Xutx"
    "9dXRzB0+f/vpzPz07ujuAx9POLm2f779XpUSyi+P3J7dtv07Onf25kq+t7+L4dwfX56vpePb/47Aiuryy/fnfHcHmhavSgzyNs9Zzo2X7D/92r"
    "w7pHtnpY9CQXs3pi9CQXszAEnubbtFnlN1dXL5/dnT39c6zNbn+4sGdPTbdtPx5/+yNn/zP5+omfPW0/Zn/7A+cYrq4sv3a3x7kr47f8qD7Uto"
    "xXR/KFa9uPyI7jK9cXZ4Cevl33ffO0jzi2XyTsj2i4ufgtPxN+zfkV9EnH9suA3/ykQz7K/62ft999fNJ/zeOTf7u6PPu0o/OTffvJvv1k336E"
    "BySnm6boE2B6m3LpE1B6mz7qE0B6mwrr4Rk9amfHx7Cz68ews9vHsLP7x7Czx8ews+dHsLOXHvF4dAbs1fmhjantj7Ovzj9YNv0VH0Mf/nUHFm"
    "lj9a/zxz8pcP+vK0dAjT3868qjHyf48K+LI2DAHv518eif2R7+dfWwXtxu9a+rj/4p7+Ff1w77r1u2Snv0jYIP/7p+2H/dslX6o+8gfPjXjSNw"
    "aB/+dePxDzj85MR+cmI3r6Iew1rBq3YESwVPr/oRrBQ8vTpsC23zXh/sSv+KBYQfbDq/P3P7s9EV+Q0sFjuf49HPVj30p426O4b9DNsHwh76t/"
    "e63TkH/i17+/zaQ/82vH3S7aF/a62LHSaH7d+62GFy2P6tj7OC6lccdss+i9fHWf/0P861e5TlTb/iIFv2aa9tv2JCn7Ha9vNT9MmmbT8+/W2f"
    "J9599Th+zavH28+ev/z05vFjvnncX+7ZzT06jzw+wlP7+hEe2reP8My+f4RH9uM43qDO43iDunxZV47kZV0cycu6ehTH6R3+JWocyUvUeiQvUV"
    "fkwzyGZRqn29uGP+qFLPv0wIVqq0a1A1eqryrVDtypvupUO3Cp+qpU7cCt6qtWtQPXqq9q1Q7cq74Eyg5crKv10pd24Gb1VbP6gZvVV83qB25W"
    "X/6ueuBmLatm9QM3a1k1qx+4WcuqWf3AzVpWzeoHbtayalY/cLOWVbP6gZu1LGHdAzdrWeK6B27WsmrWcuBmLatmLQdu1lg+Bjhws8aqWcuBm3"
    "V1nN5lOXCzxqpZy4GbNVbNWg7crLFq1nLgZl0d23dZDtyssWrWOHCzxlKFOHCzxqpZ48DNWlfNGgdu1rp8wnrgZq2rZo0DN2tdNWscuFnrqlnj"
    "wM1aV80aB27WumrWOHCz1lWz1gM3a101az1ws9alZnbgZm2rZq0Hbta2atZ64GZty5dXB27WtmrWeuBmbatmrQdu1rZq1nrgZm2rZq0Hbta2at"
    "Z24GZtq2Zth5aqV83aDq1VLw3eAzdrXzVrO1SzvstUzV/DVN1cfGKq/kmZKkZwPj7A2R6f3+yPj2+OY6Dn5zHA8wuW6sDw/IKkOjA8v+CoDgzP"
    "LyiqA8PzC4bqwPD8gqA6MDy/4Kfu5zGsZrz/wKPaP9JSxnuzI1jHuL+MA28kWNSnHXh1wKI/LY5g+8T+Mg7boAti6t7aEWyr2F9GP4ZDke5tHM"
    "OZSPc2j+FIpHvfHcE2jP1lHHhdzOp3UD+C7Rn7yzhsiy4IqXuPI9i2sb+MA680WbSotyPYzrG/jAMvCVm0qB/DNo/9ZRy2RRdU1H3ZHcP+j/ti"
    "x7AA5L74MWwAuS/lGFaA3Jc4hh0g96UewxKQ+9KOYQvIfelHsAZkfxkH3kayaNFy2BZdEFD3cdgWXfBP93HYFl2tNAk/ip0mUY5iqUnEcWw1qU"
    "ex1iTaUew1iX4Ui01iHMVmk5hHsNpk/9T+sC26YJ3u64FXMi1atB62RRec0309bIsuKKf7etgWbasXS4dt0bZaDnXYFl3wTff1sC26oJvu62Fb"
    "dME23dfDtuiCbLpvh23RBdd03w7boguq6b4dtkUXTNN9O2yLLoim+3agFv2FZxq73a/hmU5P7k6enZzfnD07Pbk+P38MqOn/+nvvWf/3Q02RQ0"
    "0Px8vdnl3evjg5v3iEO+Hk4uTm5eJmuLy6eXly8bsciLo5u9t/44/gRL66vrrPX718hFPlbj7/7Re34Glvj+NLt/mj6PPzzz4/gmvbPl/46osj"
    "uLS5+rLt77fz0ye+47Y5s/0X7iguzlb1dnp2+vvL06M8eHj/hTt9nMujX73tQypfXt+cXNy8fIIfDIvzfR6m2FNcTl1ejj/F5bTl5ZSnuJy+vJ"
    "x4isvZLPgX5xd3+7v5SW7mxamUl/szOS9On+aatqm3F/tfuE/3v+A8zSXZ9k+/h5b8H7MOd03bvX1+vf89//nVy+unKKNtNu6Xa3qKRlqcJHz+"
    "8AP4yb53dfEz9/z0xc0TfeDZRuge7vAn/BS2DdTtXaIn+3nrQ13Rk9zgU13RU/zULTt1RU/xg3cbvru4esoC3ybxLq6essC3sbxfrukp7u9tRu"
    "/i6ikLfBvY+/3J6f3Vxd3JZ2dPcUmb/f1yvxv87vTV2RN9WNpG+V6+/f3y9KmuabPBL6/2j6ee6orm9hV9cfdUV7RN+11/8faXk6e6ps0Ov315"
    "9Yenuru3KcDbu8vT3391/YFP7B7pihZrJm4fyvKpnqRvn4B4fXv76sn6exsVfHV5evPi4ubJLmqzwZ9//sX9xf311e0jPMb87Y/htmnC3198cX"
    "Pz6vLu/OUZvbrPb27B1W1W+vP9t/Morm6z3t/+incMl7fNJL79be8oLm/72cvdcXztth/C3B3HV277acxdOYqLi9XjhqO4um1852x/fX+9vKe9"
    "us0fFGeXn311FF+7vvgxdhQXt/2T4urq4tXd+cW/3V0+6U/Zbb7y87OTu2O4um3scv+NPYqLs1WfHMXVuXincfHy7onfAbeyfsRycf7y/MmvTz"
    "zDP4rrq+vHi49yfajztiHQv769epSro7zQ4iH/3z62PkI8/r/2zq23cWTL0u/zK4gDzEE3cC6iSErUIy3RksoUqSIpOV0vA3eWTpUBp51wOusy"
    "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"
    "LIXaejfJ0yZRlTOsBfdDMj0T573zpE6dV9IbtnzbpkqoboDlemWa4hHhNcoUB2AhpAJc5aeZXJodY1AR98Jm6rISIqXK4YCnhnkY1TUbxszrmq"
    "mJHj51zQac65r5jCuHDZlXDlPrQMWedCudL8xqnmexZBNf1F6a5sjGe2p8x1XttTGf2msxq9prBLvjqvbagHnJKt9ayaqhtZJVaguixaaenefa"
    "jYcWS1apCZiHq07vcmpdAJh1WbyT4kv/ilAdAJgvjZfpqXEAZlYmwsZIjLqn7+ytKTqqIZpZ2tSK8tbGCRpRzOa0uRj1vvt2IWic1TeJhrzrm0"
    "TkTf+Qe6CF8iaTJ1pEi+AoTsDi5mBCdFzm4m+0KjpK4SmZzXpnaC1qjuHrmmO5qqRcprPmUc3mhWbLEdXyj5tUFEnQantEtb1eRhrNjqlm66Lu"
    "S+2/rnXKhktxatdaWydUy5tcu2214igbFzbQOu36dNCaLQ+plmf5zPjzednuaqODf/rk9FssT7TAUp+cftulzkHBJ6deKixx9M5f/ritbVGvQe"
    "fk6JNz8EzzguGTc3BWFGV/3aVL8QrR+Pkyn+k2Tk7EpsiBTsvkRKySU62G6Zl44m0qrfVuGLa0rTvUUUvbWTHVKcE7HLW0XZVbnRV1SM7Jk02d"
    "aS1R6nz9YituHPLIrtHwhGx4Oct0fn3qFLmwUivy7CIrqrXOz0+d4n5ofDXTbHzY0vhiqdm4GjYVHprSZU7vYxKPPTN5GdKMOqJa1h7sEdWy9k"
    "iTRU3EeV0Mtk7TMdW09kBPqJZ1B1qd1ZQt6w40kY8UZc2T7VxA1I7lsJAu8cEjvqBl+Opy7j7AkBpALgEqV6fm4y6scACdk5Bqvk0o7Mvc9ZiN"
    "qdCKjeuknjq5LDLXInE7y3qPXYe88Je2e3e+Q2p4f0ctxZu1bGU8NTyXGSLBbIi2K+OPK9MfN8u1gcYDsvFVrt24+tBjDNV/YaxAg/FPc76TLj"
    "nf2TKZ50VVP03ics77luI17IWBEb14ih2/GM+/vZ4jFp92Za6mYM9nD+qii6INT9Sima5OMxPyTPcBCslwhNKVXJh+AyMFcL0VUn39rtbLXKdV"
    "tdJZSDuJzVpTp4jJtnWHeEK2LEYjLXu6YIQd8tH6qo06H21GtlFnjlfJO5ErFUteqqU2qd12xQoscfm6LHQGm8gNptW6yKu0Mp4bnBeFQIQbGr"
    "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"
)

if __name__ == '__main__':
    main()
