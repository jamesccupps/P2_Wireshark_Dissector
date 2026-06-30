"""
firmware_registry.py — Known APOGEE P2 firmware builds and dialect lookup.

Implements APOGEE_P2_SPEC.md §30 (Appendix F). The registry lets a P2
client skip the dynamic dialect-detection probe (§11.2) when a panel's
firmware build tag has already been parsed from a prior 0x010C SystemInfo
response. The §11.2 probe costs ~2 seconds against modern panels that
silently drop the legacy probe; for a fleet of dozens of panels this is
meaningful startup latency.

The registry is non-exhaustive. Siemens does not publish a complete build
catalog and OEM respins can carry identifiers not listed here. Clients
SHOULD fall back to dynamic detection (§11.2) for any build not present.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple


# Known builds — see APOGEE_P2_SPEC.md §30.2 for the source table.
#
# Each entry:
#   dialect      — "legacy" / "modern" / "n/a"
#   read_family  — opcode family for point reads on this build
#   version      — human-readable firmware version (informational)
#   build_date   — approximate build date (informational)
#   notes        — anything specific to this build
KNOWN_BUILDS = {
    "PME1121": {
        "dialect": "legacy",
        "read_family": "0x0271",
        "version": "V2.8.5",
        "build_date": "~2012",
        "notes": "Older P2 build; predates the dialect break.",
    },
    "PME1252": {
        "dialect": "legacy",
        "read_family": "0x0271",
        "version": "V2.8.10",
        "build_date": "Oct 2013",
        "notes": "CONNECT-response uses 0x0100 in 0x2E body (§9.12); "
                 "the highest known build before the dialect transition.",
    },
    "PME1300": {
        "dialect": "modern",
        "read_family": "0x0220",
        "version": "V2.8.18",
        "build_date": "Sep 2019",
        "notes": "Final P2 release; adds Adaptive Control (LSM-ADAPT); "
                 "CONNECT-response uses 0x4640 IdentifyBlock.",
    },
    "BME1290": {
        "dialect": "n/a",
        "read_family": "bacnet",
        "version": "V3.5.2",
        "build_date": "~2019",
        "notes": "BACnet firmware on identical PXC hardware; not "
                 "addressable via this protocol's wire opcodes.",
    },
}


# msg_type integers corresponding to the named dialects (per §5.1).
# Callers that already use 0x33 / 0x34 as session_msg_type can resolve
# the dialect string to the wire byte directly.
DIALECT_MSG_TYPE = {
    "legacy": 0x33,    # DATA
    "modern": 0x34,    # HEARTBEAT
    # "n/a" intentionally absent — BACnet panels don't speak this protocol.
}


def negotiate_dialect(build_tag: Optional[str]) -> Optional[Tuple[str, str]]:
    """Fast-path dialect lookup by firmware build tag.

    Returns (dialect, read_family) when the build is in the registry,
    None when caller should fall back to §11.2 dynamic detection.

    A BACnet-family build (BME####) returns ("n/a", "bacnet") so callers
    can recognize the panel is unreachable via this protocol without
    paying the probe cost.
    """
    if build_tag is None:
        return None
    tag = build_tag.strip()
    entry = KNOWN_BUILDS.get(tag)
    if entry is None:
        return None
    return entry["dialect"], entry["read_family"]


def classify_unknown_build(build_tag: Optional[str]) -> str:
    """Heuristic dialect classification for builds not in the registry.

    Used when a fresh panel returns an unlisted PME####/BME#### tag.
    Per APOGEE_P2_SPEC.md §30.3 the 1253-1299 build-number gap is
    treated as ambiguous, not interpolated — a hypothetical PME1275
    could be on either side of the dialect break.

    Returns one of:
      "legacy"          — PME with build number <= 1252
      "modern"          — PME with build number >= 1300
      "not_applicable"  — BME (BACnet firmware family)
      "unknown"         — PME in the 1253-1299 gap, or unrecognized
                          prefix (caller should use dynamic detection)
    """
    if not build_tag:
        return "unknown"
    tag = build_tag.strip()
    if tag.startswith("PME"):
        suffix = tag[3:]
        try:
            num = int(suffix)
        except ValueError:
            return "unknown"
        if num <= 1252:
            return "legacy"
        if num >= 1300:
            return "modern"
        return "unknown"  # 1253-1299 gap — don't extrapolate
    if tag.startswith("BME"):
        return "not_applicable"
    return "unknown"


def parse_build_tag(model_string: Optional[str]) -> Optional[str]:
    """Extract the PME####/BME#### build tag from a 0x010C response string.

    The 0x010C SystemInfo response carries the build tag in a TLV that
    Siemens internally labels "panel model" but holds the firmware-build
    identifier — e.g. "PME1252 " or "PME1300 " (trailing space preserved).
    Strips whitespace, validates the PME/BME prefix, and returns just the
    canonical 7-character form (prefix + 4 digits) or None.
    """
    if not model_string:
        return None
    tag = model_string.strip()
    if not (tag.startswith("PME") or tag.startswith("BME")):
        return None
    prefix = tag[:3]
    # Walk the digits after the prefix
    i = 3
    while i < len(tag) and tag[i].isdigit():
        i += 1
    if i == 3:
        return None
    return prefix + tag[3:i]


# ─────────────────────────────────────────────────────────────────────────────
# Per-host build-tag cache
#
# Populated by clients when they parse a 0x010C SystemInfo response from a
# panel. Persisted by site.json loaders for cross-process reuse. Looked
# up at handshake time so a known panel skips the §11.2 dialect probe.
# ─────────────────────────────────────────────────────────────────────────────

_BUILD_TAG_CACHE: Dict[str, str] = {}


def get_cached_build_tag(host: str) -> Optional[str]:
    """Return the cached build tag for `host`, or None."""
    return _BUILD_TAG_CACHE.get(host)


def cache_build_tag(host: str, build_tag: str) -> None:
    """Store the build tag for `host`. Idempotent."""
    if build_tag:
        _BUILD_TAG_CACHE[host] = build_tag


def evict_build_tag(host: str) -> None:
    """Remove the cached entry for `host`. Safe when a previously-cached
    tag stops working (firmware upgrade, panel swap)."""
    _BUILD_TAG_CACHE.pop(host, None)


def all_cached_build_tags() -> Dict[str, str]:
    """Snapshot copy of the cache for persistence."""
    return dict(_BUILD_TAG_CACHE)


def load_build_tags(tags: Optional[Dict[str, str]]) -> None:
    """Bulk-update the cache from a saved site.json."""
    if tags:
        _BUILD_TAG_CACHE.update(tags)


def describe_build(build_tag: Optional[str]) -> str:
    """Human-readable one-line description of a build for log output.

    Returns a string like:
      "PME1300 (modern dialect, V2.8.18, Sep 2019)"
      "PME9999 (heuristic: legacy/modern/unknown — not in registry)"
      "(no build tag)"
    """
    if not build_tag:
        return "(no build tag)"
    tag = build_tag.strip()
    entry = KNOWN_BUILDS.get(tag)
    if entry:
        return (f"{tag} ({entry['dialect']} dialect, {entry['version']}, "
                f"{entry['build_date']})")
    classification = classify_unknown_build(tag)
    return f"{tag} (heuristic: {classification} — not in registry)"
