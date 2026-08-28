# APOGEE P2 (Protocol II) — Technical Reference

## Table of Contents

- [Summary](#summary)
- [1. Introduction, Scope, Lineage & Conventions](#1-introduction-scope-lineage--conventions)
  - [1.1 What P2 is](#11-what-p2-is)
  - [1.2 The protocol family — P1, P2, BACnet coexistence](#12-the-protocol-family--p1-p2-bacnet-coexistence)
  - [1.3 Audience and goal](#13-audience-and-goal)
  - [1.4 Document conventions](#14-document-conventions)
  - [1.5 Lineage (informative)](#15-lineage-informative)
  - [1.6 Conformance levels](#16-conformance-levels)
- [2. Architecture & Layering](#2-architecture--layering)
  - [2.1 The layered stack](#21-the-layered-stack)
  - [2.2 Node roles and the object hierarchy](#22-node-roles-and-the-object-hierarchy)
  - [2.3 Service model (informative)](#23-service-model-informative)
- [3. Topology & Addressing](#3-topology--addressing)
  - [3.1 Network tiers](#31-network-tiers)
  - [3.2 BLN forms](#32-bln-forms)
  - [3.3 The point-address 3-tuple: LAN / Drop / Address](#33-the-point-address-3-tuple-lan--drop--address)
  - [3.4 Named scopes and their constraints](#34-named-scopes-and-their-constraints)
  - [3.5 Inter-BLN routing](#35-inter-bln-routing)
  - [3.6 Liveness and replication cadence (topology layer)](#36-liveness-and-replication-cadence-topology-layer)
  - [3.7 No multicast discovery beacon](#37-no-multicast-discovery-beacon)
  - [3.8 FLN / P1 fieldbus hanging off a panel](#38-fln--p1-fieldbus-hanging-off-a-panel)
  - [3.9 Documented topology limits](#39-documented-topology-limits)
- [4. Physical & Datalink Layer](#4-physical--datalink-layer)
  - [4.1 Ethernet/IP transport (the canonical P2 transport)](#41-ethernetip-transport-the-canonical-p2-transport)
  - [4.2 AEM serial-to-TCP tunnel (a second observable P2-bearing TCP port)](#42-aem-serial-to-tcp-tunnel-a-second-observable-p2-bearing-tcp-port)
  - [4.3 Serial BLN datalink (dedicated RS-485 trunk)](#43-serial-bln-datalink-dedicated-rs-485-trunk)
  - [4.4 FLN / P1 field bus (RS-485 two-wire)](#44-fln--p1-field-bus-rs-485-two-wire)
  - [4.5 Open items — serial and field-bus framing](#45-open-items--serial-and-field-bus-framing)
  - [4.6 The serial trunk is token-passing, and its parameters are named](#46-the-serial-trunk-is-token-passing-and-its-parameters-are-named)
  - [5.0 Documented timer defaults, and how they scale](#50-documented-timer-defaults-and-how-they-scale)
- [5. Discovery, Liveness & Replication](#5-discovery-liveness--replication)
  - [5.1 EPing — Ethernet-BLN availability probe (liveness, not a beacon)](#51-eping--ethernet-bln-availability-probe-liveness-not-a-beacon)
  - [5.2 Multicast availability channel (optional, off by default) — and the beacon myth](#52-multicast-availability-channel-optional-off-by-default--and-the-beacon-myth)
  - [5.3 Node-name-table replication (the self-organizing BLN)](#53-node-name-table-replication-the-self-organizing-bln)
  - [5.3.6 The EBLN diagnostic reads, and what each one returns](#536-the-ebln-diagnostic-reads-and-what-each-one-returns)
  - [5.3.1 Replication opcodes](#531-replication-opcodes)
  - [5.3.2 EBLN configuration & node-management opcodes (struct-derived)](#532-ebln-configuration--node-management-opcodes-struct-derived)
  - [5.3.3 Peer identity lives in three separate stores](#533-peer-identity-lives-in-three-separate-stores)
  - [5.3.4 Deletion is tombstone-based](#534-deletion-is-tombstone-based)
  - [5.3.5 Removing an entry, and why not to reach for a power cycle](#535-removing-an-entry-and-why-not-to-reach-for-a-power-cycle)
  - [5.4 What a fresh client learns, and what it cannot](#54-what-a-fresh-client-learns-and-what-it-cannot)
  - [5.5 FLN discovery (P1WhoAreYou)](#55-fln-discovery-p1whoareyou)
  - [5.6 Open items — discovery & FLN timing](#56-open-items--discovery--fln-timing)
- [6. Frame Format (Wire)](#6-frame-format-wire)
  - [6.1 Frame byte layout](#61-frame-byte-layout)
  - [6.2 The msg_type discriminator (message class / dialect)](#62-the-msg_type-discriminator-message-class--dialect)
  - [6.3 The direction byte](#63-the-direction-byte)
  - [6.4 Routing slots](#64-routing-slots)
  - [6.5 Sequence number and request/response pairing](#65-sequence-number-and-requestresponse-pairing)
  - [6.6 Legacy and modern dialect differences](#66-legacy-and-modern-dialect-differences)
  - [6.7 Segmentation](#67-segmentation)
  - [6.8 The byte-oriented P2 encoding (non-TCP links)](#68-the-byte-oriented-p2-encoding-non-tcp-links)
- [7. Service Model & Message Types](#7-service-model--message-types)
  - [7.1 The ASDU service model](#71-the-asdu-service-model)
  - [7.2 Success vs error responses](#72-success-vs-error-responses)
  - [7.3a The stack's service primitives](#73a-the-stacks-service-primitives)
  - [7.3 Connection and session model](#73-connection-and-session-model)
    - [7.3.1 Session establishment, in order](#731-session-establishment-in-order)
    - [7.3.2 Response timing, measured](#732-response-timing-measured)
  - [8.1 The string TLV](#81-the-string-tlv)
- [8. Body Encoding Primitives](#8-body-encoding-primitives)
  - [8.2 Scope tag and command priority](#82-scope-tag-and-command-priority)
  - [8.3 Numeric value fields](#83-numeric-value-fields)
  - [8.4 String character encoding — RAD-50 vs ASCII](#84-string-character-encoding--rad-50-vs-ascii)
  - [8.5 ASDU field convention](#85-asdu-field-convention)
- [9. Function-Code (Opcode) Catalog](#9-function-code-opcode-catalog)
  - [9.1 The AP2 function code](#91-the-ap2-function-code)
  - [9.1.1 The wire opcode is the bottom of a three-tier model](#911-the-wire-opcode-is-the-bottom-of-a-three-tier-model)
  - [9.2 Naming, families, and value layout](#92-naming-families-and-value-layout)
  - [9.3 Destructive and sensitive operations](#93-destructive-and-sensitive-operations)
  - [9.4 Family overview](#94-family-overview)
  - [9.4.1 Which of these does a panel actually implement?](#941-which-of-these-does-a-panel-actually-implement)
  - [9.5 The catalog](#95-the-catalog)
  - [9.5.2 Opcodes the panel implements that the enum does not name](#952-opcodes-the-panel-implements-that-the-enum-does-not-name)
  - [9.6 The session/keepalive opcode 0x4640 (EBLN_PING)](#96-the-sessionkeepalive-opcode-0x4640-ebln_ping)
  - [9.7 Wire behavior: message classes, directions, error tails](#97-wire-behavior-message-classes-directions-error-tails)
- [10. Message Body Structures](#10-message-body-structures)
  - [10.1 Encoding convention](#101-encoding-convention)
  - [10.2 Shared sub-types](#102-shared-sub-types)
  - [10.2.1 Two body idioms not covered above](#1021-two-body-idioms-not-covered-above)
  - [10.2.2 0x099F UPL_ALL_PORT — reading a panel's communication ports](#1022-0x099f-upl_all_port--reading-a-panels-communication-ports)
  - [10.2.3 Range-and-resume: how every enumeration is paged](#1023-range-and-resume-how-every-enumeration-is-paged)
  - [10.3 Read / command / COV core](#103-read--command--cov-core)
  - [10.4 The point model (Point_base)](#104-the-point-model-point_base)
  - [10.5 CABINET_DISPLAY — firmware / identity block (0x010C)](#105-cabinet_display--firmware--identity-block-0x010c)
  - [10.6 Session / EBLN node block (0x4640)](#106-session--ebln-node-block-0x4640)
  - [10.7 Node / BLN management bodies](#107-node--bln-management-bodies)
  - [10.8 Upload / PPCL / TEC / trend / alarm representatives](#108-upload--ppcl--tec--trend--alarm-representatives)
  - [10.9 Buildability register — what a reader can and cannot decode](#109-buildability-register--what-a-reader-can-and-cannot-decode)
  - [10.10 The full structure set is enumerable](#1010-the-full-structure-set-is-enumerable)
- [11. Point Model](#11-point-model)
  - [11.1 The three point layers](#111-the-three-point-layers)
  - [11.2 Logical point types](#112-logical-point-types)
  - [11.3 Physical-subpoint composition](#113-physical-subpoint-composition)
  - [11.3.1 Hand/Off/Auto — a point can be taken away from the panel at the terminal](#1131-handoffauto--a-point-can-be-taken-away-from-the-panel-at-the-terminal)
  - [11.4 Point teams (.ptd) and the FLN subpoint model](#114-point-teams-ptd-and-the-fln-subpoint-model)
  - [11.5 Analog scaling, sensor types, and enumerations](#115-analog-scaling-sensor-types-and-enumerations)
- [12. Change-of-Value (COV)](#12-change-of-value-cov)
  - [12.1 The subscription opcode set](#121-the-subscription-opcode-set)
  - [12.1.1 When subscriptions are registered — concentrated at session establishment](#1211-when-subscriptions-are-registered--concentrated-at-session-establishment)
  - [12.2 The COV class mask and subscription type](#122-the-cov-class-mask-and-subscription-type)
  - [12.3 The annunciate / value payload](#123-the-annunciate--value-payload)
  - [12.4 Command priority (carried in the COV payload)](#124-command-priority-carried-in-the-cov-payload)
  - [12.5 COV behavior and tuning](#125-cov-behavior-and-tuning)
- [13. Alarming](#13-alarming)
  - [13.1 Standard vs Enhanced alarms](#131-standard-vs-enhanced-alarms)
  - [13.2 Alarm priority is distinct from command priority](#132-alarm-priority-is-distinct-from-command-priority)
  - [13.3 Analog limits, transitions, and deadband](#133-analog-limits-transitions-and-deadband)
  - [13.4 Alarm destinations and routing](#134-alarm-destinations-and-routing)
  - [13.5 Controller alarms as digital points](#135-controller-alarms-as-digital-points)
  - [13.6 Alarm report and acknowledgment opcodes](#136-alarm-report-and-acknowledgment-opcodes)
- [14. PPCL over the Wire](#14-ppcl-over-the-wire)
  - [14.1 Program model](#141-program-model)
  - [14.2 Point references, names, and macros](#142-point-references-names-and-macros)
  - [14.3 Statement / keyword vocabulary](#143-statement--keyword-vocabulary)
  - [14.4 Expressions, operator precedence, and the command parameter array](#144-expressions-operator-precedence-and-the-command-parameter-array)
  - [14.5 PPCL program-management opcodes](#145-ppcl-program-management-opcodes)
- [15. Scheduling (TOD / EQS)](#15-scheduling-tod--eqs)
  - [15.1 Time-of-day mode bitmask](#151-time-of-day-mode-bitmask)
  - [15.2 TOD opcodes (per-point time-of-day scheduling)](#152-tod-opcodes-per-point-time-of-day-scheduling)
  - [15.3 EQS — equipment scheduling](#153-eqs--equipment-scheduling)
  - [15.3.1 SSTO — start-stop time optimization](#1531-ssto--start-stop-time-optimization)
  - [15.3.2 An EQS zone being created, on the wire](#1532-an-eqs-zone-being-created-on-the-wire)
- [16. Database, Bulk Transfer, On-Disk (.P2) Format, Application Catalog & Firmware](#16-database-bulk-transfer-on-disk-p2-format-application-catalog--firmware)
  - [16.1 Bulk database transfer](#161-bulk-database-transfer)
  - [16.2 On-disk (.P2) panel-database format](#162-on-disk-p2-panel-database-format)
  - [16.2.1 The supervisor-side device-backup container](#1621-the-supervisor-side-device-backup-container)
  - [16.3 Application catalog (controller applications)](#163-application-catalog-controller-applications)
  - [16.4 Reading a controller application from a live panel](#164-reading-a-controller-application-from-a-live-panel)
  - [16.4.1 `AP2_SERVICES_RENDERED` — the capability document](#1641-ap2_services_rendered--the-capability-document)
  - [16.5 Firmware and revision identity](#165-firmware-and-revision-identity)
  - [16.6 Cabinet lifecycle and destructive opcodes](#166-cabinet-lifecycle-and-destructive-opcodes)
- [17. Security Considerations](#17-security-considerations)
  - [17.1 P2 has no cryptographic security](#171-p2-has-no-cryptographic-security)
  - [17.2 The only gate is the BLN name](#172-the-only-gate-is-the-bln-name)
  - [17.3 Pre-authentication information disclosure](#173-pre-authentication-information-disclosure)
  - [17.4 Ungated destructive operations](#174-ungated-destructive-operations)
  - [17.5 Registration versus impersonation](#175-registration-versus-impersonation)
  - [17.6 Guidance for implementers and owner-operators](#176-guidance-for-implementers-and-owner-operators)
  - [17.7 Detecting BLN-name enumeration](#177-detecting-bln-name-enumeration)

- [18. Appendices](#18-appendices)
  - [Appendix A — Value-enum reference](#appendix-a--value-enum-reference)
  - [Appendix B — Opcode-family index](#appendix-b--opcode-family-index)
  - [Appendix C — Glossary](#appendix-c--glossary)
  - [Appendix D — Open-questions register](#appendix-d--open-questions-register)
  - [Appendix E — Evidence-tag legend and lineage pointer](#appendix-e--evidence-tag-legend-and-lineage-pointer)

## Summary

P2 ("Protocol II") is the application-layer network protocol of the Siemens APOGEE building-automation system — the language supervisory workstations and field panels use to exchange point values, change-of-value (COV) reports, alarms, schedules, control-program (PPCL) source, trend data, and node-routing information. This reference describes P2 as it runs over TCP/IP, the transport used by all Ethernet-attached APOGEE installations.

**At a glance:**

- **Transport.** TCP, default port **5033** — every field panel and the supervisor listens here; some installations add a second supervisor-side listener on 5034. Frame semantics derive from a frame's contents and direction, never from the TCP port that carried it.
- **Peer model.** On the backbone (the BLN, also called the ALN) every member — supervisor and panel alike — is an equal node, and any node may originate traffic. "Request" and "response" describe the role of a *frame*, not of a node.
- **Frame.** Big-endian throughout: `u32 total_len | u32 message_type (low byte = message class) | u32 sequence | u8 direction | four NUL-terminated ASCII routing slots [BLN, dst-node, BLN, src-node] | (request/push frames only) u16 opcode | body`. The opcode is present only on `direction == 0x00` frames; a response is matched to its request by the echoed sequence number.
- **Dialect.** The message class is a legacy/modern pair fixed by a panel's firmware generation — data `0x33`/`0x34`, second channel `0x2E`/`0x2F`, peer carriers `0x29`/`0x2A` — not by direction. A client reads a panel's firmware once (via `CABINET_DISPLAY`, opcode `0x010C`) and selects the dialect and the string encoding (ASCII vs RAD-50) from it; there is no on-wire negotiation.
- **Operations.** A 2-byte function code (the "AP2 function code") selects the operation; about 630 are defined and **135** are observed on the wire in the reference corpus (§9.5). The high-volume operations are the COV value push (`0x0274`), the liveness/identity heartbeat (`0x4640`), point command and read (`0x0240` / `0x0220`), COV subscribe/unsubscribe (`0x0271` / `0x0273`), and the database upload/replication family.
- **Encoding.** Strings are length-prefixed TLVs (`01 00 <len> <ascii>`); analog values are IEEE-754 single-precision big-endian floats; command priority rides a scope tag. Bodies are ordered, positionally-typed field structures (ASDUs).
- **Control logic.** Panels run a resident, line-numbered control language — Powers Process Control Language (PPCL); the supervisor reads, edits, and uploads it over P2 but never executes it (§14).
- **Security.** P2 carries no authentication and no encryption; the only admission gate is a matching BLN name. Any party with network reachability and the BLN name can read points, command points, and reconfigure panels. §17 covers the implications and an owner-operator hardening posture.

The sections that follow specify each layer: transport and ports (§2, §4), framing (§6) and encoding primitives (§8), addressing and identity (§3), discovery / liveness / replication (§5), the operation catalog (§9) and body structures (§10), the point model (§11), COV (§12) and alarms (§13), PPCL (§14), scheduling (§15), database and firmware (§16), and security considerations (§17).

## 1. Introduction, Scope, Lineage & Conventions

### 1.1 What P2 is

P2 ("Protocol II") is the application-layer trunk protocol of the Siemens APOGEE building-automation system. It is the language that supervisory workstations and field panels use to exchange point values, change-of-value (COV) reports, alarms, schedules, control-program (PPCL) source, trend data, and node-routing information across a building's automation network. [D/I]

P2 is a **peer protocol**: on the network tier where it runs, every member — supervisor and field panel alike — is an equal node, any node may originate traffic, and there is no single bus master. [W][D] At the wire level the protocol is symmetric: the same frame format carries traffic in both directions, and the terms "request" and "response" describe the role of a *frame*, not the role of the node that emitted it (see §6 for framing, §7 for the session model). [W]

This document specifies P2 as it operates over **TCP/IP**, which is the transport used by all current (Ethernet-attached) APOGEE installations. A reader who works through this reference can implement a conformant P2 peer — a client that establishes sessions, reads and writes points, receives COV reports, enumerates panel contents, and participates in node-routing exchange — interoperating on a live P2 network exactly as a supervisor or panel does. The two normative conformance levels (minimal client, full peer) are defined in §1.6. [I]

Within the APOGEE product family the protocol is also written **"PII"** — the same "Protocol II" — so "P2", "PII", and "Protocol II" all denote this one protocol. [D/I]

### 1.2 The protocol family — P1, P2, BACnet coexistence

An APOGEE installation layers several distinct protocols. An implementer must keep them separate; this document specifies only P2.

| Protocol | Tier | Role | In scope here |
|---|---|---|---|
| **P2 (Protocol II)** | BLN / backbone | Peer network among supervisors and field panels; the subject of this document. | Yes |
| **P1 (Protocol I)** | FLN / fieldbus | Master/slave polling bus beneath a single panel, carrying terminal-equipment controllers (TEC) and unitary controllers (UC). A panel mediates P1; P1 device data is reached *through* the panel using P2 opcodes, never as a separate TCP transport. | Reached via P2 (§2.2, §3.8), not specified at the byte level |
| **BACnet/IP & BACnet MSTP** | Coexisting on later panels | A separate, standardized protocol stack present on DXR/BACnet-capable panels and on the modern supervisor. It uses its own ports, framing, segmentation (TSM), and object model — none of which are P2. | **Out of scope** |

The vendor's own topology metadata tags a network backbone as `BLN Type="BLN_PII"` (a Protocol-II backbone) and a fieldbus as `FLN Type="FLN_P1"` (a Protocol-I fieldbus), and distinguishes an Ethernet BLN (`EBLN`) from a BACnet BLN (`BBLN`). [S][D] On a mixed site, the same physical panel may carry both a P2 (EBLN) presence and a BACnet (BBLN) presence; the two are independent stacks selected at the panel. [D] BACnet coexistence is noted here only so an implementer can recognize and ignore BACnet traffic; the BACnet stack, its segmentation, and its object model are **explicitly out of scope** of this reference. [I]

### 1.3 Audience and goal

The intended reader is an engineer implementing a compatible P2 device or client — for example, an owner-operator building a monitoring tool, a gateway, or a replacement supervisor for legacy hardware they own and operate. The goal of the document is **implementation completeness**: every layer needed to put a conformant P2 node on the wire — transport, framing, encoding primitives, addressing, the session handshake, the operation/opcode catalog, the point model, replication and discovery, COV/alarms, error codes, and the on-wire form of PPCL programs — is specified here. [I]

Where a claim derives from observable wire behavior, from the protocol's type-system definitions, or from vendor documentation, that provenance is recorded with an evidence tag (§1.4), so each statement is traceable to how it was established. [I]

### 1.4 Document conventions

#### 1.4.1 Evidence tags

Every non-trivial claim carries an inline tag, at the end of the sentence or in the final column of a table, recording how it was established:

| Tag | Meaning |
|---|---|
| **[W]** | **Wire-verified.** Directly observed in a packet capture or opcode census of live P2 traffic. Ground truth for byte-level claims. |
| **[S]** | **Struct/metadata-derived.** From the protocol's own type system — the function-code enumeration, the ASDU body-structure definitions, and the value enums (priorities, point types, COV masks, native types, node states, etc.). Definitional truth for names, field order, and constant values. |
| **[F]** | **Firmware-attested.** The value or behavior is carried in a controller firmware image itself, rather than in a supervisor-side binary. Stronger than [S] for the question *does a panel actually implement this*, because [S] describes only what a supervisor knows how to ask for. |
| **[C]** | **Codec-attested.** Read out of the vendor's own compiled P2 codec — the encoder or decoder that lays bytes down, supervisor side. Definitive for field width, byte order, padding and string encoding, because the arithmetic is in the instruction stream. Weaker than [F] for *does a panel implement this*, and weaker than [W] because a link the codec serves may never have been captured. |
| **[D]** | **Doc-sourced.** Taken from vendor help text, manuals, or templates. Reliable for behavior, topology, timing, and semantics — but **not** for byte-level wire layout. |
| **[I]** | **Inferred / synthesis.** Reasoned from one or more of the above. |
| **[OPEN]** | **Not yet confirmed.** A specific gap that needs a capture or a live test to close; flagged explicitly rather than papered over. |

A field-layout table is tagged **[S]** when its field order and types come from the ASDU structure definitions, and **[W]** when the layout has additionally been confirmed on the wire. A behavioral claim tagged **[D]** must never be presented as a byte-level wire fact; where the byte offsets behind a documented behavior are not pinned, the gap is tagged **[OPEN]**.

#### 1.4.2 Byte, integer, and field conventions

- Hexadecimal byte values are written `0xNN`. A run of literal bytes is written space-separated, e.g. `01 00 04`.
- **All multi-byte integers in the P2 header and in body integer fields are big-endian.** The header length, message-type, and sequence fields are unsigned 32-bit big-endian (`u32 BE`); the opcode and the error code are unsigned 16-bit big-endian (`u16 BE`). [W]
- Analog values are **IEEE-754 single-precision (32-bit) floats in big-endian byte order** (`f32`, big-endian). [W]
- Byte/field layouts are presented as tables of the form:

  | Offset | Field | Type | Value/Notes | [tag] |
  |---|---|---|---|---|

  Offsets are relative to the start of the structure under discussion (frame, body, or sub-structure); each table states its origin.

#### 1.4.3 Terminology

The following terms are used consistently throughout (cross-referenced in detail in §2 and §3):

- **BLN** — Building Level Network: the P2 peer backbone. Later product generations also call this the **ALN** (Automation Level Network); the two names denote the same trunk and the same wire field. [D]
- **FLN** — Floor/Field Level Network: the P1 fieldbus sub-bus beneath one panel. [D]
- **CEC** — the controller/panel exec (a field panel as an addressable executive). [S][D]
- **P2 = Protocol II** — the BLN/backbone protocol (this document). **P1 = Protocol I** — the FLN/fieldbus protocol. [S][D]
- **PXC / MEC / PXM** — field-panel hardware families (modern modular/compact controllers, the modular equipment controller, and the panel-mount operator/controller variant). Legacy panel families include **SCU**, **RCU**, **MBC**, and **MEC**. [S][D]
- **TEC** — terminal equipment controller (a P1/FLN field device); **UC** — unitary controller. [S][D]
- **AEM** — APOGEE Ethernet Microserver (a serial-to-TCP terminal server that tunnels a serial P2 byte stream over TCP; §2.1.4). [D]
- **EPing** — the Ethernet-BLN liveness/discovery ping (the `0x4640`-class heartbeat at the protocol layer; §5 and §10). [S][D]
- **PPCL** — Powers Process Control Language, the line-numbered control language a field panel executes (§14). [S][D]
- **AP2 function code** — the name for the 2-byte wire opcode (also abbreviated `fc`, "function code"; §9.1). [S]

#### 1.4.4 Scope summary

**In scope:** the P2 wire protocol over TCP/IP and the adjacent layers an implementer must understand to use it — transport and ports, framing and encoding, addressing and identity, the session handshake, the full operation/opcode catalog, the point model, replication/discovery, COV/alarms, error codes, and PPCL-over-the-wire.

**Out of scope:** the BACnet protocol stack (BACnet/IP and BACnet MSTP) that coexists on later panels; the serial-era physical layer except as lineage context (§1.5); and any management-station-internal supervisor-to-station RPC that does not appear on the panel wire. [I]

### 1.5 Lineage (informative)

This subsection is informative; nothing in it is required for interoperation. It orients an implementer to why the protocol is shaped as it is.

**Powers → Landis & Gyr → Siemens.** P2's data model and much of its vocabulary descend from the **Powers System 600** of the 1980s and its **Protocol II** — the peer ("token-passing") network discipline of that era — as distinct from **Protocol I**, the master/slave polling discipline that survives conceptually as the FLN sub-bus beneath a panel. [D/I] The product line passed through **Landis & Gyr** (and a parallel **Staefa Control System** branch) before consolidating under Siemens' APOGEE, which is why conventions from several BAS lineages coexist in the modern system. [D/I]

**PPCL.** The control language a panel executes is **Powers Process Control Language**, carrying the Powers name forward into the modern product. PPCL is specified, to the extent needed to read and write programs over the wire, in §14. [D]

**The model is stable; the encoding and transport evolved.** The point taxonomy, the linear analog calibration (`engineering value = digitized value × slope + intercept`), the command-priority ladder, the point-condition/COV mask, and the peer network model are all carried forward essentially unchanged from the Powers/Protocol-II era. [S][D] What changed is the wire. The original serial-era constructs — the RS-485 multidrop trunk, the circulating media-access token, packed numeric point addressing, RAD-50 name packing, and a serial-link CRC — are **not** part of P2 over TCP: the modern transport is TCP, integrity and ordering are provided by TCP itself, there is no token because there is no shared bus to arbitrate, and routing is by NUL-terminated ASCII name rather than by packed numeric address. [W][I] The peer-equality concept of Protocol II survives (panels originate their own connections, pushes, and routing advertisements) while the serial mechanism that once implemented it does not. An implementer building for TCP MUST NOT implement RS-485 token arbitration, the serial CRC, or numeric wire addressing; these survive only inside a panel's internal database and CLI reports (§5.5). [I]

**A note on string encoding across the lineage.** Name/string encoding is a per-firmware-revision, per-platform property, not a per-frame one. Early (pre-IP) field-controller and supervisor revisions pack names in **RAD-50** — three characters per 16-bit word, over the 40-symbol alphabet `" ABCDEFGHIJKLMNOPQRSTUVWXYZ$.?0123456789"` (index 0 = space, 1–26 = A–Z, 27 = `$`, 28 = `.`, 29 = `?`, 30–39 = `0`–`9`), packed as `((c0×40)+c1)×40+c2`. [S] All P2/IP revisions use plain ASCII in the length-prefixed TLVs and NUL-terminated routing slots of §6 and §8. Whether a given platform uses RAD-50 or ASCII is keyed by firmware/platform class (a per-platform `STRING_TYPE` of RAD50 vs ASCII). [S][D] A peer presenting RAD-50-packed names is a pre-IP revision and is out of scope for a TCP/5033 implementation, which is ASCII throughout. [I]

### 1.6 Conformance levels

Two conformance levels are defined.

- **Minimal client (read-mostly).** MUST implement: the Ethernet/IP transport (TCP/5033, §4.1); the frame format (§6) including the four NUL-terminated routing slots and the rule that the opcode is present only when the direction byte is `0x00`, parsed by scanning the slots rather than at a fixed offset (§6.4); the service model and error handling (§7); the encoding primitives (§8); a session via `EBLN_PING` `0x4640` (§5.1, §10.6); and the read/COV opcodes `POINT_LOG_VALUE` `0x0220`, `COV_ENABLE`/`COV_DISABLE`/`COV_ANNUNCIATE` `0x0271`/`0x0273`/`0x0274`, and `CABINET_DISPLAY` `0x010C`. This is sufficient to discover a panel's identity and read live point values.
- **Full peer.** Additionally MUST implement: commanded writes with priority (`POINT_CMD_VALUE` `0x0240` / `POINT_CMD_PRIORITY` `0x0241`, §8.2, §12.4) honoring the command-priority `>=` gate and release semantics; the upload family (`UPL_ALL_*`, §9); node-table participation and global-data replication (`EBLN_REPL_*` `0x4633`–`0x4636`, §5.3); and PPCL transfer (§14). A full peer that emits node-management or cabinet-lifecycle opcodes (§16.6, §17.4) MUST treat them as destructive.

Both levels MUST NOT depend on a multicast discovery beacon — none exists (§5.2) — and MUST treat the BLN-name slot as the only admission gate (§3.4, §6.4).

---

## 2. Architecture & Layering

### 2.1 The layered stack

A P2/IP node is best understood as a small stack of layers. From bottom to top:

```
  +-------------------------------------------------------------+
  | Application / ASDU layer                                    |
  |   AP2 function code (2-byte opcode) + typed ASDU body       |  §9, §10, §8
  +-------------------------------------------------------------+
  | Transport layer                                            |
  |   unicast TCP, canonical port 5033 (full mesh among peers)  |  §2.1
  +-------------------------------------------------------------+
  | Physical / datalink (one of)                               |
  |   - Ethernet (TCP/IP) ............ the modern, in-scope path |
  |   - RS-485 serial BLN ............ legacy multidrop trunk    |  §2.1.3
  |   - P1 / FLN fieldbus ............ sub-bus beneath a panel   |  §2.2
  |   - AEM serial-over-TCP tunnel ... serial P2 wrapped in TCP  |  §2.1.4
  +-------------------------------------------------------------+
```

The same application/ASDU layer rides over whichever datalink a node uses; this document specifies the application layer and the **TCP/IP** transport. The serial, FLN, and AEM paths are described only enough to delimit them from the TCP wire. [I]

#### 2.1.1 TCP/5033 — the canonical transport

P2 runs over **TCP**, and **TCP port 5033 is the canonical and default P2 port.** [W][D] Every node that participates in the BLN — the supervisor and every field panel — listens on TCP/5033 for inbound P2 connections, so the BLN is a **full mesh at the transport layer**: any node may open a connection to any other node's 5033 listener, and a communicating pair commonly holds two connections, one initiated in each direction (§7.3). [W]

The port is configurable but must be set identically across all panels and the supervisor on a given BLN; the vendor exposes a small fixed set of selectable "Transport Server Port" slots, defaulting to 5033, applied uniformly BLN-wide. [D] An implementer should default to 5033 and treat any other value as site configuration. A P2/IP deployment additionally requires, at the network layer, that every node reach every other node by its actual IP address — **network address translation between panels and the supervisor is not supported**; each node must present a stable, directly reachable address. [D]

#### 2.1.2 TCP/5034 — an optional second supervisor-side listener (NOT a protocol-standard port)

Some installations run a supervisor that **also** listens on TCP/5034 as a second listener distinct from the canonical 5033. A client MUST NOT assume it exists and MUST default to 5033. [W]

**Why a second port exists at all.** The supervisor's listening port is a configurable setting, documented as defaulting to 5033, which an integrator is directed to change only when a *second* P2 application shares the same management station — the two must not collide on one host. A non-5033 supervisor port is therefore a **deployment artifact of co-hosted P2 applications**, not a protocol feature and not a Siemens-standard second channel. The vendor's own configuration procedure states it directly — accept the default `5033` when the supervisor runs alone, and change it only so it does not conflict when a second P2 engineering application shares the management station. [D] This is the operational reason behind the `<host>|<port>` identity form of §3.3.1: one host can present more than one P2 endpoint, so the port disambiguates the identity. Expect the common case to be a supervisor on 5033 with no suffixed identity at all. [D] Where it appears, only the supervisor host listens on 5034; field panels never do — the listener set on 5033 is the full mesh, while 5034 is a star into one supervisor box. On the wire, 5034 carries the **panel→supervisor push/announce (reverse) channel**: panels open a connection to the supervisor's 5034 listener and push COV/value frames there, while the supervisor reaches panels on their 5033 listeners (§7.3). What that endpoint *is* was previously recorded here as undeterminable from traffic. It is largely determinable, and the answer matters to an implementer: **the second port is a P2 node with its own points, not a listener.** See §2.1.8. [W] The protocol carried on 5034 is identical to that on 5033 — the same frames, opcodes, and semantics — and unsolicited pushes (COV, alarms) are **port-agnostic**: a push rides whichever connection/port the receiving supervisor is listening on, and the port number does not change the meaning of any frame. [W]

The decisive evidence that 5034 is not a protocol feature: a supervisor's identity string commonly carries a `|5034` suffix (e.g. `DCC-SVR|5034`), and that exact suffixed identity appears in thousands of frames captured on a **5033-only** connection, while the literal text `5033` appears in zero frames anywhere. The supervisor stamps its `HOST|PORT` identity into the routing slot regardless of which TCP port carries the frame — so the `|PORT` suffix is part of the *identity string*, not a live port indicator (§2.1.5, §6.4). [W] A conformant implementation derives all frame semantics from the frame's direction and contents, never from the TCP port that carried it, and defaults to 5033 only (exposing any other port as explicit configuration). [I]

**And the two listeners on one host need not be the same service.** At an
observed supervisor, panel-initiated sessions succeed on `5034` — a panel
connects, pushes COV reports and point commands, and every one is answered —
while `5033` on that same host accepts the connection, reads the request and
closes with no application reply: 984 such connections in 25 minutes, nine panels
retrying every 14 seconds, zero payload bytes returned (§5.1). The reason is a
deployment one and it generalises: **the canonical port was already taken by
another product on that machine**, so the supervisor's P2 peer service was
configured onto a second port. Whoever binds `5033` there answers the TCP
handshake and then drops the session. A client MUST NOT infer from an open port
that the peer speaks P2, and MUST treat a silently closed session as a
configuration outcome rather than a fault. [W]

#### 2.1.3 The serial BLN (legacy datalink, context only)

Before Ethernet, the BLN was a **terminated RS-485 multidrop trunk** (8 data bits, no parity, 1 stop bit), with up to a few trunks (trunk numbers 0–3) and a firmware-tiered baud rate (e.g. 38400 baud where all firmware on the trunk is recent enough, otherwise 19200; modem links lower). [D] The serial BLN implements the same peer model and the same data model as the Ethernet BLN, but with the serial-era mechanics (token, CRC, packed addressing) noted in §1.5. It is **not** the subject of this document; an implementer targeting TCP/5033 does not implement it. [I]

#### 2.1.4 The AEM tunnel (serial-over-TCP, context only)

The **APOGEE Ethernet Microserver (AEM)** is a Lantronix-class serial-to-TCP terminal server that tunnels an existing **serial** P2 byte stream **verbatim** over TCP (commonly channel 1 ≈ TCP 3001 for P2, channel 2 ≈ TCP 3002 for the HMI console; 8/N/1). [D] The AEM does **not** define a new framing layer — it is a transport wrapper around the serial stream, so the bytes inside an AEM tunnel are the serial-P2 bytes, not the native TCP/5033 P2 frames of §3. An implementer targeting native P2/IP does not interact with the AEM path; it is documented only to explain the `AEM socket` construct present in the vendor datalink layer and to warn that an AEM-bearing port (≈3001) is a *different* byte stream from a 5033 listener. [I]

#### 2.1.5 The `|port` identity-suffix convention

A node's source-identity string — carried in the source-node routing slot and exchanged at session establishment — commonly appears as `NAME|PORT`, e.g. `P2SCAN|5033` or `DCC-SVR|5034`. The `|PORT` portion is part of the **identity string** (a `HOST|PORT` disambiguator that lets one host present distinct identities); it is **not** a network-layer port indicator and **not** a field delimiter. [W][D] Handling rules: when **building** a frame, emit the full literal identity including the suffix and do not split on `|`; when **parsing**, accept both the suffixed and bare forms (responses and routing-table entries frequently return the bare `NAME`) and match identities with the suffix tolerated on either side. [W] See §6.4 for the identity model.

#### 2.1.6 No multicast discovery beacon

P2 has **no multicast presence or discovery beacon that a client can listen for to find nodes.** [W][D] There is no periodic UDP multicast that a node emits to announce itself for discovery. A multicast group exists in the protocol, but only as an **optional, default-disabled peer failure-detection (liveness) feature**: when an operator explicitly enables it, panels join a configured Ethernet-BLN availability multicast group (the vendor-documented default group is `234.5.6.7`, UDP port `8`, up to four group/port pairs per panel) solely to detect peer *failure* — not to advertise presence for discovery. [D] It is off by default and must not be relied upon for node discovery; an implementation MUST NOT implement a "beacon listener" as a discovery mechanism, because there is no P2 discovery beacon to receive. Node discovery is performed by connecting to known addresses on TCP/5033 and exchanging frames, and on mixed sites by the BACnet-side and Ethernet-BLN discovery exchanges of §10. [I]

> **Correction of a common misattribution.** Traffic to the multicast group `233.89.188.1` (UDP/10001), sometimes mistaken for an "APOGEE multicast beacon," is **not** Siemens-sourced. It is the **Ubiquiti device-discovery protocol**, and the captures identify it positively rather than merely excluding Siemens: the source is the gateway (`x.x.x.1`), the payload is the constant four bytes `01 00 00 00`, and each datagram is dual-emitted to `233.89.188.1:10001` *and* the directed broadcast `255.255.255.255:10001`. `233.89.188.1:10001` is Ubiquiti's discovery group and port. Siemens devices on the same segment emit only BACnet/IP and ARP, never to that group or port. The `233.89.188.1` "beacon" does not exist as a P2 feature. Do not implement or rely on it. [W]

#### 2.1.7 Surrounding network services

A P2/IP node typically depends on several platform services around the P2 port itself: name resolution (DNS) to resolve node names to addresses — and where a site has no DNS the vendor's procedure is to populate the management station's `hosts` file with each panel's and each AEM's name and address, which is worth knowing because it makes name resolution a per-station configuration rather than a network service [D] — address assignment (BootP/DHCP) where dynamic addressing is used, file transfer (FTP) and a console (Telnet and/or a serial CLI) for firmware administration, and management (SNMP) for monitoring. [D] These are platform services around the P2 node and are **outside** the P2 wire protocol; only TCP/5033 (and, where present, the site-specific 5034) carries P2 itself. [I]

#### 2.1.8 What is on the second port: a node, not a listener

An earlier edition recorded the second supervisor-side port as a "reverse
channel" whose nature could not be settled from traffic. It can be, once
requests are resolved by **who is treated as what** rather than by which port
carried them.

Every operation the supervisor drives goes outward to a panel on `5033` — reads,
COV subscriptions, uploads, priority commands. The point-**write** opcode runs
the other way: **96.7% of `0x0240 POINT_CMD_VALUE` in the corpus is a panel
sending into the second port.** [W]

The full request mix addressed to that port, across the corpus: [W]

| Opcode | Requests |
|---|---:|
| `0x0274 COV_ANNUNCIATE` | 59,458 |
| `0x0240 POINT_CMD_VALUE` | 32,453 |
| `0x4634` (node-table replication) | 1,391 |
| `0x0271 COV_ENABLE` | 690 |
| `0x0272 COV_DELETE_STUB` | 199 |
| `0x4635` / `0x4636` | 147 |
| `0x0508 ALARM_PRINT` | 63 |

Peers **write its points**, **subscribe to COV on it**, **replicate node tables
with it**, and **send it alarms**. That is the behaviour of a field panel. A
node that other nodes subscribe to and command is a peer in the BLN, whatever
else runs on the same machine.

The point names confirm it. Every write addressed to that port names one of only
**nine distinct points**, and 97% of those writes carry the **`.BN` / `.BAC`
name-twin suffixes** — the BACnet-twin convention of §11. The endpoint is
publishing BACnet-side values into the P2 name space. [W]

Two identifications fit, and the wire does not separate them:

- **A software field panel.** Vendor documentation describes field-panel
  firmware run as a service on a workstation — a virtual panel that behaves on
  the network like a physical one — and identifies it by exactly the observed
  form: **host name, a pipe, and a TCP port that must differ from the transport
  server port**. A second host in the corpus presents the same `HOST|PORT` form,
  so it is a naming rule rather than a local accident. [D][W]
- **A BACnet-side trunk.** The vendor's BACnet integration presents a BACnet
  network to the supervisor *as though it were a P2 trunk*; an endpoint on the
  supervisor host whose points are overwhelmingly BACnet twins is what that
  looks like from the wire. [D][I]

They are not exclusive — a BACnet trunk realised as a software panel satisfies
both readings.

**What an implementer should take from this.** Do not model a non-canonical P2
port as "the supervisor's other socket". Model it as **another node**, resolve
it by the node identity in the routing slots rather than by its port, and expect
it to behave as a full peer: it holds points, it answers COV subscriptions, and
it participates in replication. The port number remains site configuration and
must never be used to infer a frame's meaning (§2.1.2). [I]

### 2.2 Node roles and the object hierarchy

#### 2.2.1 Node roles

| Role | Examples | Behavior on the BLN |
|---|---|---|
| **Field panel** (CEC) | PXC (modular/compact), MEC, PXM; legacy SCU, RCU, MBC | A peer node. Listens on 5033, answers reads/writes/commands/enumerations addressed to it, and **originates** its own traffic — COV reports, alarm reports, routing-table pushes, and heartbeats — on its own initiative. Mediates the P1/FLN devices beneath it. [W][D] |
| **Supervisor** | Insight (legacy), Desigo CC / GMS, WCIS, DataMate | A peer node that manages one or more panels: it opens outbound connections to each panel to poll, read, write, command, and enumerate, and it accepts inbound connections (including panel pushes). On the BLN the supervisor is "node 100" conceptually (the management station; §5.4). [W][D] |
| **FLN device** | TEC, UC (and other P1 field controllers) | **Not** a P2 peer. Lives in a separate namespace on the P1 fieldbus behind one panel; reached only *through* that panel via the FLN browse/enumerate opcodes (§9). [S][D] |

Every P2 node — supervisor or panel — is a peer: there is no single master that owns the network. A panel originates traffic without a prior request, using the request encoding (direction byte `0x00`), and a supervisor likewise originates reads, writes, and commands; both directions use the identical frame format (§6). [W]

#### 2.2.2 The object hierarchy

P2 addresses entities by name through a five-level hierarchy, broadest to narrowest:

```
  BLN  (Building Level Network — the peer backbone; one BLN System Name)
   └─ Site  (a grouping container inside a BLN; affects liveness/replication cadence, not admission)
       └─ Node / CEC  (a supervisor or field panel — the addressable executive)
           └─ Point  (a logical point name on that node; may group 1–4 subpoints)
               └─ FLN device / drop  (a P1 sub-device on the panel's fieldbus — a separate namespace)
```

This hierarchy is corroborated by the vendor's own object model, which nests **BLN → CEC → Point** at the database and codec layers (a building network contains controllers, which contain points), with a **point team** abstraction whose default member is the logical point. [S] Addressing detail for each level is specified in §3; the FLN device level is reached through the panel and is *not* carried in the four routing slots (§6.4). A panel and the supervisor are each a **Node** (equivalently a **CEC**, the controller/panel exec). [S]

#### 2.2.3 Point teams

A "point team" groups the physical/virtual subpoints that make up one logical point. A logical point name may bind **1 to 4** subpoints under a single name — but that is a *product* constraint, not a wire one, and a decoder must not encode it: `member_count` is an `UNSIGNED16` and the member array is `nrOfreport_members : UNSIGNED_16` followed by `Team_Members[]`, so the encoding admits 65,535. Read the count; do not size a fixed array of four. [S]

The team's *default member* is the logical point a client normally reads or commands, and a panel's point-team metadata maps the team's members to their subpoint indices, link types, and engineering-unit scaling. [S][D] FLN sub-device subpoints derive their names from the parent point name plus a suffix describing the subpoint. The point team is the unit a panel uploads when a supervisor enumerates a device's points (§9), and the FLN/TEC point-team templates (the vendor's `.ptd` device-family library) define, per device family, which subpoint indices exist and what each means. [S][D] Full point-model detail is in §11.

### 2.3 Service model (informative)

This subsection is **informative orientation**, not part of the normative wire specification. It describes the request/response service model that the wire framing of §6–§10 realizes; nothing here is required to build a conformant node.

#### 2.3.1 Confirmed and event services

P2 follows the classic ISO/OSI confirmed-service idiom: a **Request** at the originator becomes an **Indication** at the receiver, and a **Response** at the receiver becomes a **Confirm** back at the originator, with the operation's payload carried as an **ASDU** (Application Service Data Unit). Operations fall into two service classes, which the implementer sees on the wire as the **direction byte** (§6.3):

- **Confirmed** service — a request that expects a matching response, correlated by the sequence number.
- **Event** service — an asynchronous, unsolicited indication with no prior request: a panel-originated push (COV report, alarm, routing advertisement, heartbeat).

On the wire, both a confirmed request and an event push are emitted with `direction == 0x00` and carry an opcode (§6.3); the difference is only whether the peer was expecting them. This confirmed-vs-event distinction is the origin of the wire's request/push-vs-response structure — for example, COV is a register/cancel *subscription* with an asynchronous annunciate indication (§11, §12). [I]

#### 2.3.2 Dispatch

A practical consequence for an implementer: the wire opcode is the primary dispatch key on a request/push frame, but a robust receiver dispatches on the opcode **together with** the body shape and direction, because the same opcode can select different operations by body and direction (§3.7). A management station may use a different internal index for an operation, but only the wire opcode appears on the wire; a conformant peer keys solely on the wire opcode (plus body and direction). [I]

## 3. Topology & Addressing

P2 (Protocol II) is the backbone protocol of an APOGEE automation network. This section defines the network tiers a P2 deployment is built from, the forms a BLN (Building Level Network) can take, the way nodes and points are named and numbered, how those identifiers are carried on the wire versus how they live in a node's database, how traffic crosses from one BLN to another, and the documented size limits of the architecture. Frame-level encoding of the routing identifiers is specified in §6 (frame encoding); the session admission rules that gate membership are in the handshake section; this section is about *structure and naming*, not bytes on the wire except where the structure dictates them.

### 3.1 Network tiers

A P2 installation is organized into three stacked network tiers. P2 is the protocol of the middle tier.

| Tier | Name | Role | Protocol on the tier | [tag] |
|---|---|---|---|---|
| Top | MLN — Management Level Network | Supervisory workstations (Insight, Desigo CC, WCIS, DataMate); operator presentation, database of record, cross-BLN brokering | Supervisor-internal RPC (DCE/MS-RPC), not P2 | [D] |
| Middle | BLN — Building Level Network (also "ALN", Automation Level Network in later product generations) | Peer network of field panels and the supervisor's BLN proxy; carries point data, alarms, schedules, control-program data, node-routing | **P2 (Protocol II)** | [D][S] |
| Bottom | FLN — Field/Floor Level Network | Sub-bus beneath one panel, carrying field controllers (TEC, lab/unitary controllers) polled master/slave by the panel | **P1 (Protocol I)** fieldbus, or BACnet MS/TP on later panels | [D] |

The two upper names matter to an implementer because the **supervisor's RPC layer is a different protocol from the wire P2 stack**. Supervisor-internal command classes (the `__Rpc*`/CPI vocabulary used between a workstation and its station services) operate above P2; they are not what travels between panels. The wire-level command vocabulary is the AP2 function-code set (see §8). When this document says "P2 wire" it means the BLN tier exclusively. [I]

The vendor's own name for the BLN-tier protocol is "APOGEE PII protocol" — Protocol II — confirming P2 = Protocol II, the Powers/Landis-&-Gyr System 600 lineage carried into the IP era. [S][D]

### 3.2 BLN forms

A single logical BLN can be realized over three different physical media. P2 framing and the AP2 function-code semantics are identical across all three; only the datalink underneath differs.

#### 3.2.1 Ethernet BLN (EBLN)

The modern form. All panels and the supervisor sit on a switched IP network and speak P2 over **TCP/5033** (see §4 for transport). Every node listens on TCP/5033, so an EBLN is a *full mesh* at the transport layer: any node may open a connection to any other node. [W][D]

EBLN discovery is performed by the vendor's "EPing" (Ethernet Ping) mechanism, an application-layer liveness/discovery exchange (AP2 function code `0x4640` `EBLN_PING`), not by any multicast beacon (see §3.7). The discovery engine reports each BLN's own name during the exchange, so the BLN name is obtainable from the EPing dialog rather than from a passive broadcast. [S][D]

The vendor's discovery layer distinguishes `EBLN` (Ethernet BLN) from `BBLN` (BACnet BLN). They are separate stacks (see §3.2.4). [S]

#### 3.2.2 Serial RS-485 BLN

The legacy form. Panels are wired on a **terminated, 2-wire RS-485 multidrop** trunk; the supervisor reaches them through a serial port (or, historically, a dial-up modem with the ESC fallback protocol). [D]

| Property | Value | [tag] |
|---|---|---|
| Signalling | RS-485 multidrop, terminated at both ends | [D] |
| Framing | 8 data bits, no parity, 1 stop (8/N/1) | [D] |
| Trunk numbering | Trunk 0–3 (the "LAN"/trunk number, §3.3) | [D] |
| Baud, all-firmware-modern | 38400 if every node's firmware is ≥ rev 2.2 | [D] |
| Baud, mixed firmware | 19200 (fallback when any node is older) | [D] |
| Baud over modem | ≤ 19200 | [D] |

Each link class on a panel carries its own configurable baud — the vendor exposes separate `BLN_BAUD_RATE`, `FLN_BAUD_RATE`, `HMI_BAUD_RATE`, and `MSTP_BAUD_RATE` settings. The BLN baud is uniform across a serial trunk; FLN and HMI bauds are per-link. [S][D]

#### 3.2.3 Remote P2 RS-485 via AEM (transport-tunneled serial)

A serial RS-485 BLN segment can be carried over IP by an **AEM (APOGEE Ethernet Microserver)** — a Lantronix-class serial-to-TCP terminal server. The AEM tunnels the existing serial P2 byte stream **verbatim** over TCP (channel 1 ≈ TCP/3001 = P2, channel 2 ≈ TCP/3002 = HMI; 8/N/1). The AEM defines no new RS-485 framing — it is a transport wrapper only, so a P2 implementation that speaks the serial byte stream sees an AEM-tunneled link as an ordinary serial BLN reached over a TCP socket. An alternate P2-bearing TCP port (3001) therefore exists at AEM sites; it is not the canonical 5033. [D][I]

#### 3.2.4 BACnet BLN (BBLN) — separate stack, noted only

Later product generations support a **BACnet BLN (BBLN)**: panels that are BACnet-native (or dual P2+BACnet, e.g. DXR-class controllers) and present themselves over BACnet/IP (UDP/47808, I-Am/Who-Is) rather than over P2. The discovery engine has distinct `HandleAddEBlnRequest` (P2) vs `HandleAddBBlnRequest` (BACnet, via `IAm`) paths. [S][D]

A BBLN is **out of scope for this document**: it is a different protocol stack with a different addressing model, different framing, and a different security surface. The only cross-tier fact a P2 implementer needs is the negative one in §3.5: **there is no BACnet→P2 routing path**. A point on a BBLN is not reachable through a P2 frame and vice versa. [D][I]

#### 3.2.5 The logical BLN is self-organizing

Regardless of medium, a BLN is a *logical* peer group, not just a wire. Membership is gated by the **BLN System Name** (see §3.4.1): two nodes exchange traffic only if their BLN names match exactly. Within a matched-name group the BLN self-organizes — each node maintains a **node-name table** (the roster of known peers) that auto-replicates BLN-wide, so every node converges on the same membership view. Peers gate communication to nodes the table marks dead. This is why the membership unit is the *name*, not the cable: an Ethernet panel and a serial-trunk panel that share a BLN name and a route are members of the same logical BLN. [D][S]

### 3.3 The point-address 3-tuple: LAN / Drop / Address

Every point on a P2 network has a canonical numeric coordinate, the **LAN / Drop / Address** 3-tuple. This is the addressing model the vendor's own database export uses for every point record (`PointLan` / `PointDrop` / `PointAddress`). [D]

| Component | Database field | Meaning | Range / form | [tag] |
|---|---|---|---|---|
| **LAN** | `PointLan` | The BLN / trunk number the point's panel lives on | trunk 0–3 on serial; the BLN identifier on Ethernet | [D] |
| **Drop** | `PointDrop` | The panel / node number within the BLN (the "drop" on the trunk) | 0–99 panel range; 100 = supervisor (§3.4.4) | [D][S] |
| **Address** | `PointAddress` | The point / subpoint index within that panel's database | point index | [D] |

The 3-tuple is the identity a point database stores, and it **does** appear on the wire — as the physical-address field of any point that has a physical location (§10.4.2). What it is **not** is the wire routing key — P2/IP routes frames by NUL-terminated node **name** strings in the four routing slots (§6), and reads/writes a point by its **logical point name** carried in the request body, not by the numeric tuple (see §11 for the point model). An implementer uses LAN/Drop/Address to reason about and index topology, and uses names on the wire. [W][S][I]

The vendor's database tags the tuple's network types explicitly: a BLN is `BLN_PII` (Protocol II backbone) and an FLN is `FLN_P1` (Protocol 1 fieldbus), confirming the two-protocol stack the tuple spans. [D]

#### 3.3.1 Node numbering: serial integer vs. Ethernet name

A node has two parallel identities depending on the BLN medium.

- **Serial node integer.** On an RS-485 BLN a node is a numbered drop, **0–100**: panels occupy 0–99 and the supervisor/management station takes **100** (one number is consumed by the supervisor). The protocol carries a set of **resident liveness points** named `NODE0`..`NODE99` — one per possible drop — whose value reflects that drop's online/failed/ready state. These resident points are how a node's liveness becomes a readable point value to the rest of the BLN. [D][S][I]

- **Ethernet pingable DNS node name.** On an EBLN a node is identified by a **DNS-resolvable node name of ≤ 30 characters** (see §3.4.2). The Ethernet node is reached by resolving its name to an IP and connecting on TCP/5033; the numeric drop survives as a conceptual coordinate (and in the database tuple) but is not the wire address. [D][W]

- **`<host>|<port>` — the identity form for an IP participant that is not a physical panel.** Node-table dumps contain entries carrying a pipe, such as the supervisor's `SUP|5034` alongside its bare `SUP` (§5.3). §2.1.1 establishes from the wire that this suffix is part of the identity string rather than a live port indicator; the naming rule behind it is documented too. It is a defined identifier form: **the machine's host name, a literal `|`, and a TCP port number**. It exists because more than one P2 endpoint can live on one host, and the host name alone would not distinguish them; the port disambiguates. Virtual panels are named this way as a rule and, unlike a physical panel, take **no site or system name component** in the identifier at all. A parser must therefore treat a node name as an opaque string that may legally contain `|`, and must not assume one endpoint per host. [D][W]

  A deployment constraint follows, and it is worth recording because it is otherwise inexplicable: **two P2 endpoints on the same host may not be given port numbers differing by exactly 100.** If one uses 5407, then 5307 and 5507 are both unavailable to the others. A ±100 exclusion is the signature of an endpoint quietly occupying a *second* port at a fixed offset of 100 from its configured one, so that two endpoints spaced 100 apart would collide on it. What that second port carries is **[OPEN]**; the exclusion rule itself is documented. Note this does **not** explain the `5033`/`5034` pair seen in captures — those differ by 1, and §2.1.1 covers them separately. [D][I]

A practical consequence for an implementer: the same logical panel can be referenced as a serial drop integer (in legacy databases and in `NODEnn` liveness points) and as a DNS node name (on the Ethernet wire). They denote the same node. [I]

#### 3.3.2 Node name length: ≤ 30 wire, ≤ 15 where RAD-50 packed

Node-name length has two regimes, keyed to the firmware's string encoding (cross-ref §8 for the RAD-50 codec and the platform encoding table):

- **ASCII regime (all P2/IP revisions):** node names are plain ASCII, ≤ 30 characters, NUL-terminated in the routing slots. [W][S]
- **RAD-50-packed regime (pre-IP / legacy field-controller and supervisor revisions):** names are packed three characters per 16-bit word from the 40-symbol RAD-50 alphabet, which budgets a **node-name field to ≤ 15 characters**. A system name is modeled as **Base + Suffix**, with the base length-bounded, corroborating the ≤15-character node-name basis. The documented 15-character node-name limit is also why the session handshake's ≥15-character self-identity acceptance threshold lands where it does (cross-ref the handshake admission rules). [S][D]

**Correction — the ≤15 limit is not only a legacy artifact.** An earlier
revision of this document concluded that "the ≤15 limit applies only to legacy
RAD-50 platforms". That is wrong. On a current Ethernet BLN the limit is keyed
to the **role of the named party**, not to the string codec, and both limits are
documented rules for present-day configuration: [D]

| Named party | Max length | Character set | Other rules |
|---|---:|---|---|
| **Supervisor node name** | **15** | letters, or letters and digits | must not be all digits; no spaces, underscores, periods or special characters; unique; case-insensitive |
| **Field panel node name** | **30** | letters, digits and **hyphens** | no other punctuation; unique on the network; **it is the pingable DNS host name** |
| **BLN system name** | **30** | letters and digits | no periods, spaces or special characters; must match at panel and supervisor or they will not communicate |

Two consequences. First, the hyphen is legal in a panel node name and illegal in
a supervisor node name, and the underscore is illegal in both — so a validator
cannot use one rule for the routing slots. Second, **the ≤15 supervisor limit is
the documented origin of the 15-character self-identity threshold** in the
session handshake: the handshake is checking a supervisor identity against the
longest one that can legitimately exist. The earlier text reached that
conclusion by inference; it is a documented rule.

The panel node name "replaces the node number on a dedicated (P2) BLN" — which
states the architectural split of §3.3.1 from the vendor's own side: a serial
BLN addresses by **number**, an Ethernet BLN by **name**, and the name is a DNS
name rather than a protocol-internal identifier. [D]

A peer presenting RAD-50-packed names is a pre-IP revision and is out of scope
for an ASCII TCP/5033 client. [I]

### 3.4 Named scopes and their constraints

P2 addresses entities by name. Five named scopes nest from broadest to narrowest:

```
BLN (Building Level Network)
 └─ Site
     └─ Node (panel / supervisor)
         └─ Point (logical point name)
             └─ FLN device / drop (sub-bus, separate namespace)
```

**The point-name separator is configurable, and a parser must not hard-code
it.** Point names are compound — the observed corpus is full of dotted forms —
but the character joining the parts is a **site setting chosen from six**:
period, apostrophe, comma, dash, underscore or space. Period is the default and
the vendor recommends it, which is why almost everything one sees uses it, and
exactly why a tokenizer written against observed traffic will hard-code the
wrong thing. [D]

Note that this is the opposite constraint from the scopes below it: BLN, node
and site names *forbid* periods and spaces (§3.4.1–§3.4.3), while a point name
may be joined by either. A client splitting a compound name must take the
separator from configuration, and one that cannot should treat the name as
opaque rather than guess — the wire carries the name as a single `TEXT_` TLV in
any case (§8.1), so nothing in the protocol requires it to be split at all.

The wire-level enforcement asymmetry of these names (BLN strict, destination node case-insensitive, source identity format-shaped) is specified with the handshake; this section gives the naming constraints themselves.

#### 3.4.1 BLN name

| Property | Value | [tag] |
|---|---|---|
| Encoding | ASCII, NUL-terminated on the wire | [W] |
| Maximum length | 30 characters | [D] |
| Permitted characters | Letters and digits | [D] |
| Forbidden | Periods, spaces, underscores, other special characters | [D] |
| Case sensitivity | MUST match exactly across all nodes; treat as case-significant | [W][D] |
| Role | Membership gate — two nodes exchange P2 traffic only if BLN names are identical | [W][D] |

The BLN name is fixed for the life of a network and appears **twice** in every frame's routing slots (slots 0 and 2; see §6). Later product generations call the same trunk the ALN (Automation Level Network); the wire name field is unchanged. [W][D]

#### 3.4.2 Node name

| Property | Value | [tag] |
|---|---|---|
| Encoding | ASCII, NUL-terminated on the wire (≤15 RAD-50 packed, §3.3.2) | [W][S] |
| Maximum length | 30 characters (Ethernet/field-panel node names) | [D] |
| Permitted characters | Letters, digits, dash (`-`) | [D] |
| Case sensitivity | Not case sensitive; a node MAY render its own name in a different case in a reply (cosmetic, not structural) | [W][D] |

A **supervisor / management-station identity** is shaped differently from a panel node name: it is a composite `HOST|PORT` token (e.g. `DCC-SVR|5034`, or the placeholder `P2SCAN|5033`). The `|PORT` suffix is part of the identity string — a `HOST|PORT` disambiguator that lets one host present distinct identities — and is **not** a connect-address. The supervisor stamps the same suffixed identity into its source slot regardless of which TCP port the frame actually rides (a frame seen on TCP/5033 routinely carries a source identity suffixed `|5034`). The suffix number may coincide with a real listener on the host, but a client MUST treat the whole token as one opaque identity, MUST NOT parse the suffix to choose a TCP port, and derives the connect port from configuration (defaulting to 5033). [W][I]

#### 3.4.3 Site name

The Site name is a grouping container *inside* a BLN. It scopes the cadence of background liveness/replication traffic between physical locations (intrasite vs. intersite EPing periods, §3.6) but does **not** gate data exchange and is **not validated** during the handshake. [D][W]

| Property | Value | [tag] |
|---|---|---|
| Encoding | ASCII, NUL-terminated on the wire | [W] |
| Permitted characters | Letters and digits | [D] |
| Forbidden | Periods, spaces, special characters | [D] |
| Case sensitivity | Not case sensitive | [D] |

A node accepts a peer whose Site name differs from or is unknown to it, provided the BLN name matches and the destination node is known. Site grouping additionally appears in a node's database as a *container* — observed test injections created orphan site groupings (e.g. `<DIAGSITE>`) in a panel's field-panel log, so the Site is a real on-node structure, not merely a cadence selector. [W][D]

#### 3.4.4 Node numbering and the management station

A node has a conceptual numeric identity **0–99** for field panels; number **100** is reserved for the management station (supervisor/host), which sits above the panel range. This is the conceptual node-id model from the protocol's lineage. On the P2/IP wire, **routing is by node NAME, not number** — a client places the node's name string in a routing slot, never a numeric id. The 0–99/100 model remains useful for reasoning about topology (and is the `Drop` of §3.3) but is not a wire field on EBLN. [D][S][I]

### 3.5 Inter-BLN routing

P2 panels do **not** talk panel-to-panel across BLN boundaries. A panel on BLN-A cannot directly address a panel on BLN-B; the BLN name is a hard membership gate (§3.4.1), and a frame whose BLN name does not match the receiving panel's own is rejected at the transport layer (TCP RST on a field panel). [W][D]

Cross-BLN data flow is **brokered by the supervisor**, via its CrossTrunkService. The supervisor is a member of (or a proxy onto) multiple BLNs and relays data between them — BLN-A ⇄ supervisor ⇄ BLN-B. The four routing slots in every frame (`[BLN, destination-node, BLN, source-node]`, see §6) carry exactly the information this brokering needs: the BLN name in slots 0/2 scopes which trunk the frame belongs to, and the source/destination node names in slots 1/3 identify the endpoints. When the supervisor relays a frame across BLNs it is operating on these slots. The repeated-BLN structure of the four slots is the wire expression of the per-trunk scoping that makes brokered cross-trunk routing possible. [W][I]

Two hard constraints bound cross-BLN traffic:

- **No BACnet→P2 path.** A point on a BACnet BLN (§3.2.4) is not reachable through a P2 frame; the supervisor brokers within and between P2 BLNs, but BACnet and P2 are separate stacks with no protocol-level bridge in the P2 direction. [D][I]
- **~300-point cross-BLN COV-share cap.** The number of points that can be shared across BLNs by change-of-value subscription is bounded at approximately **300 points** per the cross-BLN sharing limit. Beyond this cap, cross-BLN COV sharing is not available; an implementer must not assume unbounded cross-trunk COV propagation. (COV mechanics are in §12.) [D]

**Cross-trunk behaviour an implementer has to plan around.** Vendor
documentation for the feature adds three constraints that are not visible in the
frame format and will surprise anyone treating a cross-BLN reference as
equivalent to a local one: [D]

- **Commands and COV reports cross the boundary at one per second, and excess is
  coalesced rather than queued** — if several commands are issued within a
  second, *only the last is sent*. A cross-BLN write is therefore not a reliable
  sequence of writes, and a client must not use one to drive a state machine.
- **It is explicitly not intended for real-time control**, and the vendor
  directs that cross-trunk references be kept out of control-loop statements.
- **The direction is one-way.** The brokering lets a P2 panel reference points on
  another P2 BLN or on a BACnet BLN; it does **not** let a BACnet panel reference
  P2 points. That is the same asymmetry the first bullet above states from the
  wire side, now confirmed from the vendor's own description of the service.

The feature is also enabled per BLN rather than globally, and is not supported on
every panel generation — so its availability is a site property, and a client
must not assume a cross-BLN reference will resolve. [D]

A node-eviction operation exists at the node-management layer, by which a node can be force-evicted from the BLN roster; it is a node-table mutation, documented here for topology completeness and flagged as **destructive** (it removes a node from the operating membership view). It is not a routing facility and is not part of normal traffic. [S][D]

### 3.6 Liveness and replication cadence (topology layer)

BLN membership is maintained by two background mechanisms whose *cadence* is topology-relevant (the per-frame timing is in the session/COV sections, not here):

- **EPing (Ethernet liveness/discovery), two-tier:** intrasite period **10 s**, timeout **5 s**; intersite period **60 s**, timeout **5 s** (intersite period configurable up to ~900 s). The Site name (§3.4.3) selects which tier a peer relationship uses. [D]
- **Node-table replication:** notify ~10 s, poll ~30 s, full cycle ~75 s, holdback ~10 s, **tombstone 86400 s (24 h)** before a removed entry is reaped. The node-name table auto-replicates BLN-wide so all members converge on one roster. [D]

The 24-hour tombstone and the auto-replication are why stale roster entries persist and propagate across a BLN — relevant to the accumulation behavior discussed in the findings, and the reason an implementer should expect a roster to contain entries for nodes not currently reachable. [D][I]

#### 3.6.1 Node states

A node-table entry carries a state. The node-state vocabulary (the values an entry can hold, and the events that transition it) is the liveness taxonomy: [S]

| State | Meaning | [tag] |
|---|---|---|
| `defined` | Configured/known but not yet live | [S] |
| `ready` | Online and serving | [S] |
| `failed` | Was live, now unreachable | [S] |
| `offline` | Administratively offline | [S] |
| `remote` | Reached via another trunk/broker (cross-BLN) | [S] |
| `extended_timeout` | Slow-link timeout regime (e.g. modem) | [S] |
| `orderly_removed` | Cleanly de-registered | [S] |
| `no_cov_links` | Live but no COV subscriptions established | [S] |
| `TIU_cabinet` | Terminal-interface-unit cabinet class | [S] |
| `unknown_protocol` / `p3_protocol_detected` | Peer speaking an unrecognized / P3 protocol | [S] |

Node-table transition events include `node_added`, `node_removed`, `node_failed`, `node_ostracized`, `node_coldstarted`, `node_made_online`/`node_made_offline`, `node_made_ext_timeout`, and `node_make_ready`. The `ostracized` and `coldstarted` events correspond to the destructive node-management operations (§9.3, and the cabinet-coldstart opcodes in §9). [S]

### 3.7 No multicast discovery beacon

P2 has **no multicast presence/discovery beacon**. There is no periodic broadcast a node emits to announce itself and nothing to passively listen for to enumerate P2 nodes. Discovery is active: connect to known addresses on TCP/5033 and exchange EPing/IdentifyBlock frames (§3.2.1). [W][D]

Two clarifications an implementer must not get wrong:

1. **An optional, default-DISABLED multicast failure-detection feature exists.** When an operator explicitly enables it, panels join a configured multicast group/port (the real Ethernet-BLN availability group is **234.5.6.7, UDP port 8**; up to four group/port pairs per panel) solely to detect *peer failure* faster. It is a liveness heartbeat among already-known peers, off by default, and is **not** a discovery beacon — a fresh node is not discoverable by listening for it. [D][S]

2. **The `233.89.188.1` "APOGEE multicast beacon" does not exist.** Traffic to `233.89.188.1:10001` observed on test networks is **UniFi-gateway-sourced** (source IP = the gateway's own, Ubiquiti OUI, 4-byte `01 00 00 00` payload, ~10.5 s cadence), not Siemens. Siemens devices on the same segment emit only BACnet/IP and ARP. Any tooling that labels `233.89.188.1:10001` as a Siemens P2 beacon is misattributing gateway traffic. A P2 implementation MUST NOT implement a beacon listener as a discovery mechanism, because there is no P2 beacon to receive. [W]

### 3.8 FLN / P1 fieldbus hanging off a panel

Beneath an individual panel hangs a Field Level Network — a sub-bus of field controllers the panel polls master/slave. FLN device points are a **separate namespace** from BLN points: they are not addressed through the four P2 routing slots; the parent panel mediates all access to them. [D][W]

| Property | Value | [tag] |
|---|---|---|
| Medium | RS-485, 2-wire | [D] |
| Devices per FLN trunk | ≤ 32 (drop 0–31) | [D] |
| FLN trunks per panel | up to 3 (4 on NCRS-class panels) | [D] |
| FLN protocol | P1 (Protocol 1), or BACnet MS/TP on later panels (`Fln_type` = `P1` / `MSTP`) | [S][D] |
| Discovery | `P1WhoAreYou` poll on the FLN; BLN→FLN route-through via the parent panel | [D] |
| Auto-discover baud | 1200 (MMI 1200–38400) | [D] |

FLN device classes are enumerated by the vendor `FLN_Device_Type` set: `TEC` (terminal equipment controller), `TCU`, `UC` (unitary controller), `PXM`, `DPU`/`MPU`, `P1BIM` (P1 Bus Interface Module), `GATEWAY`/`FLOAT_GATEWAY`, `GLOBAL_IO`, and `FSCS`. [S]

An implementer reaches FLN data by establishing a session to the parent panel (§7.3.1) and issuing the FLN browse/enumerate opcodes of the `0x09xx` upload family (`UPL_ALL_TEC`, etc.; see §9 and §10). FLN-scoped operations ride a session-carrier message class on the wire (§6). The panel returns the FLN device's point data on behalf of the field controller; there is no direct P2 transport to an FLN device. An FLN point is selected by its drop number on the addressed FLN plus its subpoint index — this is the lowest level of the LAN/Drop/Address tuple (§3.3) and the FLN-device tail of the named-scope hierarchy (§3.4). [W][S][I]

### 3.9 Documented topology limits

The architectural maxima below are deployment limits, not wire-protocol constants; they bound what a conformant deployment may contain and are useful sanity checks for an implementer sizing tables or validating configuration. [D]

| Limit | Value | Scope | [tag] |
|---|---|---|---|
| BLNs per supervisor | 64 | one supervisor manages up to 64 BLNs | [D] |
| Panels per BLN | ~99 RS-485 panels + the supervisor | per BLN (the 0–99 drop range, §3.4.4) | [D] |
| Panels per **Ethernet** BLN | 100 | per logical EBLN — a separate limit, see the note below | [D] |
| FLN trunks per panel | up to 3 (4 on NCRS) | per panel | [D] |
| Devices per FLN trunk | 32 (drop 0–31) | per FLN trunk | [D] |
| Panels per workstation | 1000 | total Ethernet field panels across all managed BLNs | [D] |
| Ethernet connections per workstation | 64 | concurrent EBLN connections | [D] |
| Remote auto-dial BLNs | 300 | dial-up reachable BLNs | [D] |
| Cross-BLN COV-share | ~300 points | total points shareable across BLN boundaries (§3.5) | [D] |
| Concurrent peer sessions per panel | **≥ 9 observed** (full mesh); documented only as firmware-dependent | per panel TCP/5033 listener — see the measurement below | [W][D] |

**The two per-BLN limits have different origins, and the difference matters.** On an RS-485 BLN the ~99 ceiling is an *addressing* artifact: it is the 0–99 drop range and nothing more. An Ethernet BLN does not use drop numbers at all — its members are identified by DNS-resolvable names (§3.4.2) — and yet it is still capped, at 100 panels per logical BLN. A limit that survives the removal of the addressing scheme that supposedly caused it is not an addressing limit. It is a **node-table capacity**, which is the right way for an implementer to think about it when sizing the replicated table of §5.3. [D][I]

**Concurrent sessions, measured.** The last row is the only one of these that
the corpus can speak to, and vendor documentation gives it no number. Sweeping
connection lifetimes across 11,529 connections that have a P2 listener at one
end, on 515 distinct listeners: a single **field panel's** 5033 listener serves a
peak of **9 concurrent sessions from 9 distinct peer hosts**, and in each capture
where that peak occurs exactly **10** P2 hosts are present — so the peak is
*every other node on the BLN at once*. A supervisor listener peaks at the same 9.
Counted as sockets rather than hosts the peak is **18**, because a peer commonly
holds two connections to the same node (the 5033/5034 pattern of §2.1.2). [W]

Read this as a **floor, not a ceiling**: nothing in the corpus was refused a
connection, so no firmware limit was reached, and the site is a 10-node BLN — 9
is what full mesh costs here, not what the panel can bear. The useful conclusion
for an implementer is the shape rather than the number: **a panel must expect
every other node on its BLN to hold an open session simultaneously**, so a
listener that accepts only one or two peers is not conformant.

These figures derive from vendor topology documentation; treat them as the *documented* ceiling, not a guarantee that a given firmware enforces each one identically. Where a finding or operation depends on a limit (e.g. the cross-BLN COV cap), the dependency is called out at the relevant section. [D][I]
## 4. Physical & Datalink Layer

P2 (Protocol II) is a logical application protocol that has been carried over several physical media across its lineage. The dominant modern transport is Ethernet/IP (the **Ethernet BLN**, or EBLN); the original and still-supported transport is a serial RS-485 multidrop trunk (the **dedicated serial BLN**). Below P2's BLN tier sits the field bus, **P1 (Protocol I)** over RS-485, addressed by route-through from the BLN. This section defines what is known about each medium at the physical and datalink layers. The byte-level frame grammar (length prefix, routing slots, opcode, ASDU body) is medium-independent and is specified in the framing section (see §6); on the serial media that same logical frame is carried inside a medium-specific link framing whose exact bytes are not established here.

### 4.1 Ethernet/IP transport (the canonical P2 transport)

Native P2 over IP runs on **TCP**. Every BLN member — the supervisor and every field panel — listens for inbound P2 connections on a single configurable unicast **Transport Server Port**, default **TCP/5033** [W][D]. The BLN is therefore a full mesh at the transport layer: any node may open a TCP connection to any other node's listener (see §7). The port is observed carrying P2 in the capture corpus on 5033 and (at sites with a second supervisor listener) 5034 [W].

| Property | Value | Tag |
|---|---|---|
| Transport | TCP, connection-oriented, length-prefixed frames | [W] |
| Default port | TCP/5033 (slot 1) | [W][D] |
| Configurable port slots | Up to 8 selectable listener-port slots per panel (TCP Port 1 = default 5033 … TCP Port 8 = default blank) | [D] |
| BLN-wide uniformity | The active Transport Server Port must be identical across every panel and the supervisor on a given BLN; a node on a different port cannot participate | [D] |
| Addressing constraint | NAT is **not supported** between peers — every node must be reachable by its real IP address (the BLN mesh and the replicated node-name/IP table both assume direct real-IP reachability, §5.3) | [D] |

The 8-slot model means a panel can be told to listen on an alternate port (e.g. to deconflict with a co-resident supervisor product on the same host, which is the origin of the site-specific TCP/5034 second listener); slot 1 always defaults to 5033 and is the canonical port. A client should default to 5033 and treat any other value as site configuration. See §2.1.5 for why the `|PORT` suffix that appears inside identity strings (e.g. `NODE1|5034`) is part of the *identity string* and is **not** a live port indicator — the same suffixed identity rides whichever TCP port actually carried the frame [W].

**The 5034 listener and the two-connection pattern.** In the observed Desigo deployment, 5034 is not merely a "site-specific second port" — it is the **supervisor-side inbound listener for the reverse (panel→supervisor) channel**: field panels listen on 5033 for the supervisor's poll/command channel, while the supervisor listens on 5034 for node-originated push/value traffic and node announcements. Each node-pair therefore maintains (at least) two TCP connections — supervisor→panel:5033 and panel→supervisor:5034 — one opened in each direction (§7.3). The exact supervisor port assignment is deployment-specific (it can equally be 5033, and the 8-slot model permits other values), but the **two-listener / two-connection model is the structural pattern**, independent of the specific port numbers. [W]

#### 4.1.1 Surrounding observable service footprint

A P2/IP panel is a small embedded host that exposes platform services around the P2 port. These are **not P2** and carry no P2 frames; they are listed only as the observable footprint of a real panel, useful for fingerprinting and for understanding what else is on the wire. Only TCP/5033 (and optionally a second supervisor listener) carries P2 itself.

| Service | Port(s) | Role on a panel | Tag |
|---|---|---|---|
| FTP | TCP/20, TCP/21 | firmware / database file transfer | [D] |
| Telnet | TCP/23 | firmware-admin CLI (node-name table, field-panel reports, point-look) | [W][D] |
| DNS | UDP/53 (client) | resolves Ethernet node names to IP addresses (Ethernet BLN uses DNS names, §3.4.2) | [D] |
| BootP / DHCP | UDP/67, UDP/68 | address assignment where dynamic addressing is used | [D] |
| SNMP | UDP/161, UDP/162 | platform monitoring / traps | [D] |
| P2 multicast (availability) | UDP/8, group 234.5.6.7 | **off by default** peer-liveness heartbeat — see §5.2 | [D] |

The Telnet CLI is a significant secondary observation surface: panel-side node-name-table reports, field-panel reports, and point-look output are read over Telnet, and these have been used to corroborate wire findings (e.g. confirming a registered identity appears as a `Permanent` node-table entry) [W]. The CLI is not part of the P2 wire protocol.

### 4.2 AEM serial-to-TCP tunnel (a second observable P2-bearing TCP port)

The **AEM (APOGEE Ethernet Microserver)** is a Lantronix-class serial-to-TCP terminal server that bridges a legacy serial BLN onto IP by tunneling the panel's serial RS-232 byte stream verbatim over TCP [D]. To the supervisor the tunneled BLN appears as an always-connected remote BLN.

| Property | Value | Tag |
|---|---|---|
| Device class | Lantronix-class terminal server (e.g. AEM100 / AEM200); `Local_1>` admin prompt | [D] |
| Channel 1 (Remote ALN / P2) | default **TCP/3001**, default 38400 bps (BLN baud tied to panel firmware) | [D] |
| Channel 2 (HMI / setup) | default **TCP/3002**, 9600–115200 bps | [D] |
| Panel-side attachment | the panel's **HMI/Modem** port, with the BLN name set and **the modem disabled** | [D] |
| Exclusivity | one AEM serves **one** management station; two stations need two AEMs | [D] |
| Serial line params | 8/N/1, no hardware flow control | [D] |
| Fallback addressing | AutoIP 169.254.x when no DHCP; SNMP/Telnet/TFTP/HTTP admin services present | [D] |

Critically, the AEM **does not define new P2 framing** [D]. It encapsulates the existing serial P2 byte stream inside a TCP connection — the same bytes that would have crossed the RS-485 trunk, wrapped in TCP. Channel 1 (TCP/3001) is therefore a **second observable P2-bearing TCP port** distinct from native 5033, but the application bytes inside it are serial-BLN P2, not the IP-native framing of §6 (the IP-native handshake/heartbeat opcode behavior is specific to the EBLN stack). An implementer treating an AEM Channel-1 stream must speak the serial-BLN dialect, not assume the TCP/5033 IP-native conventions.

### 4.3 Serial BLN datalink (dedicated RS-485 trunk)

The original P2 BLN is a terminated, multidrop **RS-485-style two-wire trunk** — the Powers "dedicated BLN" — tapped via a Trunk Interface (TI / TI2, e.g. part 538-670) at the workstation COM port.

| Property | Value | Tag |
|---|---|---|
| Medium | Terminated RS-485 multidrop, two-wire, terminated at both ends | [D] |
| Line params | 8/N/1 (8 data bits, no parity, 1 stop) | [D] |
| Trunk numbering | Trunk number 0–3 (the `LAN`/trunk field of the address model, §3.3) | [D] |
| Capacity | Up to 99 RS-485 panels per BLN + 1 workstation node | [D] |
| Baud (firmware-tiered) | **38400** if all panels are firmware ≥ 2.2; **19200** if any panel is older (e.g. FW 12.5 / 1.5) | [D] |
| Modem / Auto-Dial path | ≤ 19200 baud, software flow control | [D] |
| MMI / tool port | up to 115200 on newer panels | [D] |
| Backward-compat timing | a per-panel **Extended Timeout** flag exists for panels older than firmware Rev 2.1 — direct evidence that link timeouts are firmware-version-dependent | [D] |

Observed operator-terminal (MMI/HyperTerminal) capture of a legacy panel shows the LAN bus speed reported as `4800 baud` for LAN #1–#3 on that panel, confirming the serial-BLN baud is a per-panel configurable parameter at the operator layer [W][D]. The firmware-tiered default (19200 legacy / 38400 modern) is the documented network-wide rule; individual panels may be configured otherwise.

### 4.4 FLN / P1 field bus (RS-485 two-wire)

Beneath each panel sits the Field Level Network (FLN), running **P1 (Powers Protocol I)** over a two-wire differential RS-485 trunk. FLN device points live in a separate namespace from BLN points and are reached by route-through from the hosting panel (§5.5); the panel is the gateway/master polling its FLN devices.

| Property | Value | Tag |
|---|---|---|
| Medium | 2-wire differential RS-485 ("FLN TRUNK", labeled `+ / − / Shield`), with a per-controller communication-status LED (`BST`) | [D] |
| Capacity per trunk | ≤ 32 devices, drop addresses **0–31** | [D] |
| Trunks per panel | 3 P1 FLN trunks per APOGEE panel (4 on NCRS-class) | [D] |
| Device identity | drop number + application number (see §5.5) | [D] |
| Discovery transaction | **P1WhoAreYou** (see §5.5); a mismatch yields a `Failed P1WhoAreYou` error | [D] |
| Auto-discover baud | default 1200 baud | [D] |
| MMI / tool-port baud | 1200–38400 (options 1200/2400/4800/9600/19200/38400) | [D] |

On a modular panel the RS-485 FLN trunks are provided either by built-in ports or by an add-on **RS-485 FLN expansion module** — Siemens' `PXX-485.3` carries "three RS-485 P1 FLN connections OR one MS/TP FLN connection" per the public *PXC Modular Series* datasheet. This module sits on the panel's downstream (field) bus and is wholly separate from the upstream ALN/supervisor link that carries P2 — it has no bearing on the P2 wire dialect (§6.6). [D]

A panel may alternatively host a BACnet MS/TP field bus in place of P1 (`Fln_type_enum`: `P1` = 0, `MSTP` = 1) [S]. Which one is available tracks the panel's **firmware track**, not the hardware: proprietary-P2/APOGEE firmware (the subject of this spec) drives a **P1 FLN only**, while the separate BACnet firmware build of the same hardware adds the MS/TP option. MS/TP is a different protocol stack and is out of scope for this P2 specification; only the P1/FLN bus is treated here. [D]

### 4.5 Open items — serial and field-bus framing

> **[OPEN, PARTLY ANSWERED] Serial-BLN P2 link framing bytes.** Only the line parameters (8/N/1, baud tiers, trunk numbering) were established for the dedicated serial BLN. **The message layer above the framing is now recovered from controller firmware — see §6.8** — giving the address byte and its position, a compact operation encoding, a 253-byte cap, and the forwarding rule for a message addressed elsewhere. **The message layer is now attested from the supervisor end as well** — a supervisor-side codec builds the same encoding, agreeing with the panel on the group/ordinal pair and adding the ordinal's byte order (§6.8). [C] What is still unobserved is the **link** layer beneath it: start/sync delimiting, CRC/checksum, and the medium's segmentation, all of which a lower layer has already stripped before the code in §6.8 sees the message. The supervisor's link-layer component was examined for them and does not carry them: it is a transport — ports, partners, sequence numbers, a socket path and a modem path — and it hands the codec's output down without prefixing a P2 header, so the three bytes preceding the group byte are added below it or supplied by the medium. [C] An AEM Channel-1 capture (TCP/3001) remains the way to see them, since the AEM tunnels the serial stream verbatim.

> **[OPEN] FLN/P1 frame bytes.** The P1 fieldbus discovery transaction (P1WhoAreYou), addressing (drop + application number), physical layer (RS-485 2-wire), and baud are documented, but the P1 frame byte layout itself is unobserved. The on-wire P1 frame structure, the WhoAreYou request/response bytes, and the per-poll cadence/retry behavior require a P1-bus capture or a route-through capture from the BLN. **The route-through opcode is now named: `0x0313 AP2_P1_ROUTE`, with `0x0314` alongside it** (§9.1.1). Sixteen distinct field-device operations tunnel through `0x0313`, so a capture containing it carries P1 payloads inside a P2 frame — which is the cheapest route to these bytes, and needs no access to the RS-485 segment itself. Neither opcode occurs in any capture in the present corpus.

> **[OPEN, LARGELY ANSWERED] P2 segmentation thresholds and reassembly rules.** The ~256-byte figure from vendor connection-test material is a *connection-test ping* size, **not** a maximum P2 data-packet cap — single P2 frames are observed with `total_len` up to ≈1,587 bytes (a ~1,530-byte body of packed records plus header+slots) in one response [W]. **The ceiling and the reassembly rule are now recovered from the supervisor's AP2 codec.** A segment buffer is **16,384 bytes**, of which the encoder is handed `buf+2` with a capacity of **16,382 bytes**; the two reserved bytes at `buf[0]` are the `u16` function code, which is why the wire carries the opcode immediately before the body and why `total_length` includes it. Reassembly is a cursor against a declared total: each mapped segment copies `n` bytes and advances the cursor, except the last, whose length is `total - cursor`; the sender therefore knows the total before it begins. The command object carries an explicit **more-follows** field, set on the segmenting path and cleared on the direct one. [S] **What is still open is the wire behaviour at the threshold.** No body in the corpus exceeds 16,382 B — the largest complete body is 1,570 B and the largest *declared* is 12,073 B — so the corpus is consistent with the ceiling without exercising it. Whether a result larger than one segment appears as two P2 frames, and what marks the continuation on the wire, needs a capture of an upload large enough to segment. [W][OPEN]

### 4.6 The serial trunk is token-passing, and its parameters are named

The frame bytes remain open (§4.5), but the **medium-access discipline** is
settled: the serial trunk driver is configured with a token hold time and a
local node address, which is a token-passing MAC, not a master/slave poll.
[S] The driver's parameter set, with the values it ships with:

| Parameter | Default | What it governs |
|---|---:|---|
| `BaudRate` | 9600 | line rate (the tiers of §4.3) |
| `OurNode` | 255 | this station's trunk address; 255 is the unset/broadcast value |
| `TokenHoldTime` | 1000 | how long a station may hold the token |
| `TryTime` | 1000 | retry interval for an unacknowledged transmission |
| `XTryTime` | 2500 | extended retry interval |
| `QuickAckTimeout` | 5 | short acknowledgement window |
| `ClientTrnxTimeout` | 30 | client-side transaction timeout |
| `ServerTrnxTimeout` | 40 | server-side transaction timeout |
| `IdleTime` | 20000 | idle-line threshold |
| `InterCharTime` | 16 | inter-character gap — the frame delimiter on an RS-485 line with no start byte |
| `FScanAnnounce` | 16 | fast-scan announce interval |

Two of these are structurally informative. **`InterCharTime`** implies the
serial framing delimits by an inter-character silence gap rather than a start
delimiter, which is consistent with §4.5 finding no start/sync byte — there may
not be one to find. And the **two distinct transaction timeouts**, client 30
and server 40, mean the responder is given a longer budget than the requester
waits, so a server that answers between those two values produces a response
the client has already abandoned.

The driver exposes **eight channels** and up to four installed adapters, each
with a legacy ISA I/O base and a shared upper-memory segment. That is the
architecture the trunk was designed around, and it is why trunk numbering
(§4.3) is per-channel rather than per-host. [S]

---

## 5. Discovery, Liveness & Replication

A P2 BLN is a **self-organizing peer network**. There is no central registry: nodes find and monitor one another using a liveness probe (EPing), an optional multicast availability channel, and a node-name/IP table that auto-replicates across the whole BLN. Below the BLN, the panel discovers its FLN devices with the P1WhoAreYou transaction. This section defines each mechanism, its wire opcode where one exists, and its documented timing.

### 5.0 Documented timer defaults, and how they scale

The discovery and replication timers of §5.1–§5.3 have documented defaults, and
four of them are **not constants — they scale with the number of panels on the
BLN**. All values in seconds. [D]

| Setting | Intra-site | Inter-site |
|---|---:|---:|
| EPing period | 10 | **60 + panel count**, capped at 900 |
| EPing timeout | 5 | 5 |
| Replication notification period | 10 | **10 + panel count**, capped at 900 |
| Replication polling period | 30 | **180 + panel count**, capped at 900 |
| Replication cycle timeout | 75 | **75 + panel count**, capped at 900 |
| Holdback delay | 10 | 10 |
| Tombstone lifetime | 86400 | 86400 |

**Measured against the wire.** Five opcodes run on a fixed period, measured per
peer connection across 621,268 frames — every one with a median absolute
deviation of **0.00 s**: [W]

| Opcode | Period | Intervals | Connections |
|---|---:|---:|---:|
| `0x4636` `EBLN_REPL_CHANGES`, `0x4635` `EBLN_REPL_PULL_MORE` | 1.00 s | 147 / 111 | 16 / 8 |
| `0x4640` `EBLN_PING` | **10.00 s** | 99,383 | 366 |
| `0x010C` `CABINET_DISPLAY` | 30.01 s | 102 | 17 |
| `0x4634` `EBLN_REPL_PULL` | 60.01 s | 9,805 | 168 |

`EBLN_PING` at 10.00 s is the EPing row of the table above, confirmed on the
wire. `EBLN_REPL_PULL` at 60 s per peer does **not** match the 30 s
"replication polling period", and the discrepancy is left open rather than
reconciled: the mapping from that documented timer name to this opcode is an
assumption — §5.3 describes `0x4634` as the digest advertisement, not
necessarily as what the polling timer governs. Either the timer is not this
opcode's, or this site is configured off-default. **[OPEN]**

**One candidate explanation is now ruled out.** Both timers above have an
*intrasite* and an *intersite* default, so 60 s could simply have been the
intersite figure showing up in a mixed site. It is not, and two measurements
close it off:

| | intervals in band | connections whose **median** is that band |
|---|---:|---:|
| `0x4634` at 60 s | 9,652 of 9,805 | **153 of 179** |
| `0x4634` at 30 s | **4** | 1 |
| `0x4640` at 10 s | 99,291 of 99,383 | **378 of 426** |
| `0x4640` at 60 s | 0 | 0 |

There is no second population in either. `EPing` runs at its **intrasite**
default of 10 s on every connection and never at the 60 s intersite value, which
establishes that every peer here is intrasite — and an all-intrasite site should
then show replication at 30 s, not 60 s. So the disagreement is real and is not
a site-topology artifact: this is one timer at twice its documented intrasite
default, uniformly, on 153 connections. What remains open is only whether
`0x4634` is the opcode that timer governs. [W]

**Measure per peer connection, not per node.** A node with several peers emits
one of these per peer, so a per-node aggregate reads far faster than the
protocol cadence — for `EBLN_PING` on a node with three or more peers the
aggregate median is 0.01 s, which is the emission burst, not the timer. Every
period above is per connection.

The intra-site column is what a single-site capture shows, and it is the column
this document's observed timings match. The scaling rule applies only to the
inter-site timers, and the guidance is to leave the defaults alone **below 50
panels** — so a small deployment runs entirely on the constants above.

Two things follow for an implementer. A client that infers "the EPing period is
10 seconds" from a capture has measured the intra-site default and should not
generalise it. And the 900-second cap means the inter-site timers stop scaling
at 720–840 panels depending on the setting, which is far above the
liveness-addressable node ceiling of §14.2 — the cap is not the binding limit on
BLN size.

### 5.1 EPing — Ethernet-BLN availability probe (liveness, not a beacon)

The Ethernet BLN's availability/liveness primitive is **EPing** (Ethernet Ping). On the wire EPing is the **AP2 function code `0x4640` (`AP2_EBLN_PING`)** [S], and `0x4640` is **the single most frequent opcode in the capture corpus** (78,623 requests against 53,101 for the COV value-push `0x0274`). That ranking inverted when panel-side captures were added: measured from the supervisor alone `0x0274` leads, because a supervisor sees COV pushes and point reads while a panel mostly sees the mesh keeping itself alive — the steady ~10-second per-peer heartbeat, present in the tens of thousands of frames in any multi-hour supervisor capture [W]. **That cadence is configuration, not protocol.** The EPing interval is a per-device supervisor setting whose documented *minimum* is 10 seconds, so an observed ~10 s means the site is sitting at the floor; other installations may ping far less often. A client MUST NOT hard-code the interval, MUST NOT infer a peer is dead from a single missed interval, and MUST NOT use the observed cadence to fingerprint a firmware or product generation. [D]

**Measured, and it is remarkably tight.** Over 16.7 continuous hours on a
panel's own switch port, each of its eight panel↔panel pairs exchanged
**6,008–6,010 pings at a median interval of 10.0 s and a maximum of 10.5 s** —
essentially no jitter, sitting exactly on the configured floor. Across the whole
window no peer was silent for longer than a single interval, so a peer that
misses two consecutive pings is genuinely unusual and is a reasonable liveness
threshold at a site configured this way. **The supervisor is on its own
schedule**, however: the panel↔supervisor pair carried 8,403 pings at a median
of 8.8 s over the same window — about 40% more traffic and a shorter interval
than any peer pair. Liveness cadence is therefore per-endpoint, and a client
must derive it by observation per peer rather than assuming one value network-wide. [W] The same `0x4640` opcode also serves as the session establish / IdentifyBlock exchange and the in-session keepalive (see §6, §7): establishing presence and proving continued liveness are the same operation, which is why this one opcode is so prominent in the traffic. `0x4640` is observed under every message class seen anywhere — `0x29`, `0x2A`, `0x2E`, `0x2F`, `0x33`, `0x34` — and on both observed ports `5033/5034`. (`0x2A` carries it only in panel↔panel sessions, so it appears in panel-side captures and not in the supervisor-side census; see §9.7.) Its body is the **`eBLN_Node` block** (§10.6) and its length is variable. **Do not compute it arithmetically.** An earlier edition of this document gave `35 + node-name length`, which reproduces every observation in the corpus and is still wrong to publish: the corpus is a single site, and that 35 is `3 (name TLV header) + 6 (site_name TLV) + 10 (bln_name TLV) + 16 (fixed tail)` — the site's own site-name and BLN-name lengths baked into a constant. At a site whose site or BLN name differs in length the figure differs, and an implementation using it would mis-frame every ping.

**The correct rule.** Parse the three leading TLVs, then take a 16-byte tail. Where a length must be computed rather than parsed — sizing a buffer, or validating a frame before decoding it — the general form is:

```
body_length = 25 + len(node_name) + len(site_name) + len(bln_name)

  25 = 3 TLV headers (3 bytes each) + the 16-byte fixed tail
```

All three name lengths are site and node configuration; only the 25 is a protocol constant. Checked against every distinct body size observed: `25+5+3+7 = 40`, `25+6+3+7 = 41`, `25+15+3+7 = 50` — the last being a supervisor identity of 15 characters. Substituting this site's `site_name` (3) and `bln_name` (7) collapses it to the old `35 + node-name length`, which is how the site-specific terms went unnoticed across 621,268 single-site frames. [W] **Whether a ping is answered depends on which side opened the session.** Every
*supervisor-initiated* `0x4640` in the corpus drew a reply. Panel-initiated pings
into a supervisor's `5033` may not: in a 25-minute capture at one supervisor, nine
panels each opened a fresh TCP connection to its `5033` every **14.0 seconds**,
sent a well-formed `EBLN_PING`, and were answered with **zero payload bytes and a
FIN** — 984 connections, no application reply on any of them, while that same
supervisor answered its own outbound pings to those panels on a 10.0-second
cadence, 100%. A client must therefore treat an unanswered EPing as a possible
*policy* outcome and not only as a liveness failure, and must not assume the
absence of a reply means the peer is down. [W]

On the wire the `EBLN_PING` (`0x4640`) request and response bodies each carry, in order: `TLV(node-name)` + `TLV(site)` + `TLV(BLN-name)`, then the `eBLN_Node` trailer — **five 1-byte boolean flags** (`failed, ready, replication_online, reresolve_all, reresolve_unresolved`; observed `00 01 01 00 00`), a `u32 spare` (0), a **`u32 baseTime` — an absolute Unix-epoch wall-clock timestamp** (e.g. `0x6A3D…` ≈ a 2026 date/time; it advances frame-to-frame because it tracks wall-clock, **not** an uptime/tick counter), a `u16` timezone offset, and a `u8` DST flag. [W] This is the `eBLN_Node` identity element of §10.6 realized on the wire — the node/site/BLN triple is the same identity the access gate checks (§6).

EPing is **two-tier**, distinguishing peers in the same physical site from peers across a slower inter-site link:

| Tier | Probe period (default) | Timeout (default) | Notes | Tag |
|---|---|---|---|---|
| Intrasite | 10 s | 5 s | the canonical ~10 s heartbeat seen on the wire | [W][D] |
| Intersite | 60 s | 5 s | configurable up to 900 s; the supervisor scales the intersite period upward as panel count grows (≈ 60 + N) | [D] |

A node that stops seeing a peer's EPing within the timeout treats that peer as unavailable and gates communication to it (§5.3). These are discovery/liveness-layer periods, **not** P2 frame-level retry counts or per-frame ACK timeouts — the latter are not established (see §5.6 open items).

> Note: EPing/`0x4640` is a *unicast* TCP exchange between known peers; it is not a broadcast or a discovery beacon. Discovery of a peer's existence comes from the replicated node-name/IP table (§5.3), not from passively listening for EPing.

### 5.2 Multicast availability channel (optional, off by default) — and the beacon myth

P2 supports an **optional** IP-multicast availability/failure-detection channel layered over the unicast TCP transport. It is **disabled by default** and activates only when an operator configures a multicast port.

| Property | Value | Tag |
|---|---|---|
| Default group | **234.5.6.7** | [D] |
| Default UDP port | **8** | [D] |
| Default state | **DISABLED** (enabled only by configuring the multicast port) | [D] |
| Capacity | up to **4** multicast address/port pairs per panel | [D] |
| BLN-wide rule | the group/port must match across all panels and the supervisor | [D] |
| Purpose | peer-to-peer availability/failure detection (group-optimized liveness), **not** node discovery | [D] |
| Related opcodes | `0x462C` `AP2_EBLN_FP_MULTICAST_CONFIGURE`, `0x463D` `AP2_EBLN_MULTICAST_DISPLAY` | [S] |

This is a **peer-liveness heartbeat group, not a discovery beacon**: a node does not announce itself to the world for newcomers to find, and a P2 implementation must not implement a multicast beacon-listener as a discovery mechanism — there is no such beacon to receive. Discovery is via the replicated node table (§5.3).

> **Beacon-myth correction.** A previously asserted "APOGEE multicast beacon at **233.89.188.1**" does **not exist** as a P2 mechanism [I]. That assertion was a misattribution: the traffic in question was unrelated gateway/network-appliance traffic (UniFi-class), mislabeled by an early dissector. The only multicast P2 uses is the **off-by-default** availability group at **234.5.6.7 / UDP 8** above. Independent confirmations: the vendor field-panel/LocalNet configuration documents `234.5.6.7:8` as the group [D]; and on a live network with multicast disabled, no `233.89.188.1` P2 traffic is present in capture [W]. Any tool keyed to `233.89.188.1` for P2 discovery is wrong.

### 5.3 Node-name-table replication (the self-organizing BLN)

BLN membership is carried in a **node-name table** (name ↔ IP, with state) that is **entered once on any one panel and auto-replicates to every panel on the BLN** [D]. Each panel continuously monitors every other peer and **temporarily disables communication to any peer that becomes unavailable**, resuming when the peer returns [D]. This is the application-layer membership model built on top of the EPing/multicast liveness layer — there is no central master; the table is the shared, replicated source of truth for "who is on this BLN and at what IP."

The replication of shared/global data (the node-name table, plus alarm destinations, user accounts, state-text tables, etc.) runs on a notify + poll + cycle schedule with dead-node tombstoning:

| Timer | Intrasite default | Intersite default | Tag |
|---|---|---|---|
| Notification | 10 s | 10 + N s | [D] |
| Polling | 30 s | 180 + N s | [D] |
| Cycle | 75 s | 75 + N s | [D] |
| Holdback delay | 10 s | 10 s | [D] |
| Tombstone lifetime | 86400 s (24 h) | 86400 s (24 h) | [D] |

(`N` scales with node count.) A dead node's entry persists for 24 hours (tombstone lifetime) before it expires. This replicated background traffic — distinct from per-point change-of-value (see §12) — accounts for the steady low-rate `0x46xx` replication frames seen alongside the EPing heartbeat.

#### 5.3.1 Replication opcodes

The replication exchange is a small family of AP2 function codes. In the current capture corpus **only `0x4634` (`EBLN_REPL_PULL`) is routinely wire-observed** (thousands of frames); the other four appear only rarely (empty bodies) in the broader capture set and did **not** fire during captures that contained live database changes — so they are documented from the type system, not confirmed as the delta-carrier here (see step 3 below):

| Opcode | AP2 name | Role | Status in corpus | Tag |
|---|---|---|---|---|
| `0x4633` | `AP2_EBLN_REPL_NOTIFY` | "I have changes" notification to peers | 41 requests; **40 of 41 request bodies empty** (the notification carries no payload) — the one exception is 12 bytes | [W] |
| `0x4634` | `AP2_EBLN_REPL_PULL` | pull replicated data (carries the node-table version digest; leaks node membership) | routinely observed (the dominant replication opcode) | [W] |
| `0x4635` | `AP2_EBLN_REPL_PULL_MORE` | continuation pull (segmented replication payload) | 130 frames; request bodies 8–12 B, **none empty**; 64% panel-initiated | [W] |
| `0x4636` | `AP2_EBLN_REPL_CHANGES` | changed-records delta exchange | **the live replication carrier**: 180 requests corpus-wide, of which **170 requests + 170 replies** fall in a single passive supervisor capture, bodies 331–1551 B, **none empty**; bidirectional (62% supervisor→panel, 37% panel→supervisor) | [W] |
| `0x464C` | `AP2_EBLN_REPL_DIAG_NODELIST` | replication-diagnostic node list | observed once | [W] |

`0x4634` (`EBLN_REPL_PULL`) is the mechanism by which a node advertises/obtains the current node roster — the same roster that constitutes BLN membership; its request carries the full version digest and the matched response is an empty (`0 B`) success ack (§5.3 step 3). The actual changed-record delta propagation observed on the wire rides the `DBCHANGE_*`/`UPL_ADDED_*`/`UPL_DEL_*` family on the second channel, not these `0x463x` opcodes.

> Note on naming: an earlier behavioral label for `0x4634` was "PushRoutingTable" (from its observed effect of conveying the node/routing roster). The function-code enumeration names it `AP2_EBLN_REPL_PULL` [S]; the roster-bearing behavior is consistent (a pull of replicated routing/membership data). This reference uses the enum name; the behavioral description (roster transfer) is unchanged.

**`EBLN_REPL_PULL` (`0x4634`) body — the replicated node table as a versioned digest.** The body is the full node-name table carried as a *version-vector digest*, wire-confirmed [W]: an **8-byte header** (`00 00 00 00`, then a 2-byte table-level version, then a 2-byte entry count) followed by one entry per node, each a `TLV(01 00 <len> <node-name>)` immediately followed by a **`u32` per-node version**. A `$paneldefault` entry leads, then every BLN node and the supervisor (the supervisor participates as ordinary node entries — e.g. both its `SUP` and `SUP|5034` identities appear; the pipe form is the defined `<host>|<port>` identifier described in §3.3.1, not an artifact).

```
offset 0:  00 00 00 00  <u16 table-version>  <u16 entry-count>     -- 8-byte header
then, per node entry:
   01 00 <len> "<node-name>"      -- name TLV
   <u32 per-node version>         -- this node's current change generation
first entry:  ... "$paneldefault"
then:         every BLN node + the supervisor identity(ies)
finally:   00 00 00 00                -- 4-byte trailer/terminator after the last entry
```

The `u32` after each name is that node's **change generation** — it increments whenever that node alters its replicated state. Crucially, the version is a **per-node convergence counter, not a timestamp, and it does not grow during a quiet capture.** Across a 3-hour supervisor capture (1,653 pull digests) each node's advertised version was *constant in time within any one observer's view*, but **differed by vantage**: the supervisor advertised a *lower* per-node version than the panels did for the same node (observed panel−supervisor offsets ranged ≈ +1,781 to +3,564). That gap is a **snapshot of how far the supervisor's replicated copy lags the panels' current state**, i.e. the mesh's convergence state at capture time — it is **not** a per-second increment. (An earlier reading that took a node's min-to-max version across digests as growth-over-time was conflating two *vantages'* digests, not two points in time.) A burst of growth would appear only when a node's database actually changes (add/rename/command), bumping its own counter and the header table-version; these captures were largely quiescent. The 2-byte table-level version tracks the table as a whole, and the entry set reflects the advertising node's **own** view of membership, so roster length can differ between nodes.

**How a name added on one panel reaches all of them.** This is masterless anti-entropy gossip over the full mesh (§7.3), reconciled by version comparison — no central coordinator:

1. You add (or rename) a node entry on panel **A**. A inserts the row, **bumps its own per-node version** (and the header table-version).
2. On its next replication round A sends its full digest to its peers via `EBLN_REPL_PULL` (`0x4634`) — observed flowing *mutually* in every direction (panel→panel, panel→supervisor, supervisor→panel), so every node periodically advertises its whole table to every other node. [W]
3. Each receiver compares the advertised per-node versions against its own. If they already match, it answers with an **empty (0-byte) success ACK** — the steady-state case, and it is overwhelmingly
the case: **10,003 of 10,016** matched `0x4634` responses are empty. The digest
*request* carries the full version vector; the response is just an ack. An
earlier edition said *every* matched response was empty. **Thirteen are not** —
each carries a 4-byte body holding the `u32` value **3** (nine of them) or **2**
(four). What that count is, is **[OPEN]**; that it exists means a client must
read the response length rather than assume zero. [W] If a peer is behind on some node (A's version is newer, or A carries an entry the peer lacks), it fetches the delta. Two delta paths are seen. The **commonly observed** one, during live database activity, is the ordinary database-change opcode family flowing on the `0x2E`/`0x2F` second channel: `DBCHANGE_*` (e.g. `0x0956 DBCHANGE_CONTROLLER`), `UPL_ADDED_*` (`0x0971 POINT`, `0x0974 TREND`, `0x0976 TEC`, …), and `UPL_DEL_*` (`0x0961`/`0x0964`/`0x0966`/…) — i.e. the changed records propagate as the same add/delete operations the supervisor uses, addressed peer→peer. [W] The dedicated replication-delta opcodes — `EBLN_REPL_NOTIFY` (`0x4633`, "I have changes"), `EBLN_REPL_CHANGES` (`0x4636`, changed records), `EBLN_REPL_PULL_MORE` (`0x4635`, paging) — are **also a live carrier**, not merely a formal one. A single passive supervisor capture holds 340 `0x4636` frames with bodies of 331–1551 bytes and **none empty** — the supervisor continuously distributing host-table state across the BLN. An earlier reading of this document called them rare and empty-bodied; that was a corpus-wide frame-count artifact and is withdrawn. Both paths are real: the `DBCHANGE_*`/`UPL_ADDED_*`/`UPL_DEL_*` family carries record propagation on the second channel, and the `EBLN_REPL_*` family carries the anti-entropy digest and delta. [W][S]
4. Each peer that merges the new entry then re-advertises it on its own next round, so the addition **ripples across the entire mesh until every panel and the supervisor converge** — typically within a poll cycle or two given the ~10 s notify / ~30 s poll cadence above. A removed entry lingers as a tombstone for ~24 h before it is reaped, which is also how a deletion propagates without a node that missed the change silently re-adding it.

Because the key is the **exact node-name string**, adding a name that differs only in case or spelling creates a *separate* replicated entry rather than updating the existing one — the capture shows two co-existing supervisor rows differing only in case, each independently versioned and mesh-replicated. Obtaining this roster via `0x4634` is also the pre-auth membership-disclosure path of §17.3.

#### 5.3.2 EBLN configuration & node-management opcodes (struct-derived)

Adjacent to the replication family is the full EBLN configuration/management opcode block. These set or display the very identity, IP, port, BLN/site name, multicast, and host-table values that the replication layer then propagates. They are definitional from the vendor function-code enum [S]; most are not seen in the read-only capture corpus (they are write/config operations). Several are **destructive or identity-mutating** and must be treated accordingly by any tooling (document, do not exercise blindly):

| Opcode | AP2 name | Effect | Tag |
|---|---|---|---|
| `0x461F` | `AP2_EBLN_FP_NAMES_DISPLAY` | display field-panel names | [S] |
| `0x4620` | `AP2_EBLN_FP_NAME_SET` | **set a panel's node name** (identity mutation) | [S] |
| `0x4621` | `AP2_EBLN_FP_IP_CONFIGURE` | **set a panel's IP** (network mutation) | [S] |
| `0x4622` | `AP2_EBLN_FP_TCP_PORTS_CONFIGURE` | **set the TCP Transport Server Port slots** (§4.1) | [S] |
| `0x4628` / `0x4629` | `AP2_EBLN_TRUNK_SETTINGS_REPLACE` / `_DISPLAY` | replace / display trunk settings | [S] |
| `0x462A` | `AP2_EBLN_FP_SITE_NAME_SET` | **set Site name** | [S] |
| `0x462B` | `AP2_EBLN_FP_BLN_NAME_SET` | **set BLN name** (changes membership gate, §3.4/§6) | [S] |
| `0x462C` / `0x463D` | `AP2_EBLN_FP_MULTICAST_CONFIGURE` / `AP2_EBLN_MULTICAST_DISPLAY` | configure / display multicast (§5.2) | [S] |
| `0x462D` / `0x462E` / `0x462F` | `AP2_EBLN_HOSTTABLE_ENTRY_ADD` / `_REMOVE` / `_DISPLAY` | **add / remove / display host-table (node-name/IP) entries** | [S] |
| `0x4638` | `AP2_EBLN_MAC_ADDRESS_SET` | **set MAC address** | [S] |
| `0x4644` / `0x4645` | `AP2_EBLN_TELNET_ENABLE` / `_DISABLE` | **enable / disable the Telnet admin CLI** (`0x4644` wire-observed, count 1; `0x4645` [S]) | [W] |

The host-table add/remove pair (`0x462D`/`0x462E`) is the explicit write path for the node-name table whose contents §5.3 says auto-replicate BLN-wide. Companion node-state operations in the `0x003x` range govern membership at the routing layer: `0x0032` `AP2_REMOTE_NODE_CHECK`, `0x0033` `AP2_GET_COMPLETE_NODE_STATE`, `0x0034` `AP2_SET_NODE_STATE`, `0x0035` `AP2_SET_COMPLETE_NODE_STATE`, and `0x0030`/`0x0031` `AP2_SET_GLOBAL_DATA` / `AP2_GET_GLOBAL_DATA` [S]. The node lifecycle these drive is enumerated in `Node_table_event_enum` — including `node_added`, `node_failed`, and `node_ostracized` (a force-evict of a node from the BLN, a node-availability denial mechanism) [S].

> **Security note (struct-derived, not a wire claim).** The EBLN config block and the node-state setters are full, unauthenticated-protocol write paths to a panel's network identity, BLN membership, port configuration, multicast, host table, and Telnet enablement, gated only by the BLN-name admission check (see §6). `0x4620`/`0x4621`/`0x462B`/`0x4638` (name/IP/BLN/MAC mutation), the host-table writers (`0x462D`/`0x462E`), the node-state setters (`0x0034`/`0x0035`), and node-ostracize are destructive to availability and identity. They are documented here for completeness; legitimate tooling for owner-operators should treat them as read-only-by-default and must not exercise the mutating members against production panels.

#### 5.3.3 Peer identity lives in three separate stores

A peer name is not held in one place. Three distinct stores exist, and which of
them contain an entry for a given name determines whether — and from which
panels — outbound sessions are initiated. Conflating them is the usual reason a
removal appears to work and then does not. [W]

| Store | Scope | Survives restart? | Populated by | Reached via |
|---|---|---|---|---|
| **Node-name table** | **Per-panel** (see note) | Yes — entries are `(Permanent)` | Any handshake carrying the correct BLN — **accepted or silently rejected** | `nodeNametable` sub-shell: `Display` / `Add` / `Remove` |
| **Runtime peer state** | Per-panel, volatile | No | A handshake terminating on that panel | not directly; cleared on restart |
| **Persistent active-peer state** | BLN-shared, replicated | Yes — survives cold restart and power-off | A handshake, propagated BLN-wide | `Fieldpanels` sub-shell: `Log` / `dElete` / `Modify` |

**Scope correction.** The node-name table was previously described here as BLN-shared and replicated. Console evidence contradicts that: after a name-guessing campaign against one panel, that panel's `NODE NAME TABLE REPORT` listed ~150 probe identities while a peer panel on the same BLN, checked minutes later, listed only the 13 legitimate entries. The names *are* carried in `0x4636` replication traffic addressed to eight peers, but peers do not materialise every replicated change record as a node-name-table row; what governs that is **[OPEN]**. The *persistent active-peer state* below does propagate — three phantom entries reached a panel that was never probed. [W]

The node-name table is a flat `name → IP (Permanent)` mapping. The persistent
active-peer state is a `BLN → site → peer` hierarchy that the firmware treats as
the set of peers this BLN should actively maintain sessions with — so an entry
there causes every panel to initiate outbound sessions to that name and to
re-establish them after a restart. [W]

The practical consequence: clearing the node-name table alone does not stop
outbound sessions, because the persistent active-peer state still lists the peer.
Both BLN-shared stores must be cleared, and in the order given in §5.3.5.

#### 5.3.4 Deletion is tombstone-based

Removal via `Remove` (node-name-table shell) or `dElete` (Fieldpanels shell)
does not simply drop a local row. It generates a **tombstone** — a deletion
marker that propagates BLN-wide over the same replication mechanism as an
addition, and which every receiving panel honours by removing its local copy. [W]

This is why removal is a **single-panel operation, not a per-panel sweep**.
Deleting on one panel is sufficient; the tombstone does the rest, within
`Intrasite_poll_repl_period` (60 s) or `Intersite_poll_repl_period` (100 s).

The tombstone itself persists for `Tombstone_lifetime` (86 400 s = 24 h), so that
a panel offline during the deletion window still receives the removal when it
returns. The corollary is a real operational constraint: **every panel on the BLN
must come online and apply the tombstone within 24 hours.** A panel absent longer
than that can re-propagate an entry that every other panel has already forgotten.

#### 5.3.5 Removing an entry, and why not to reach for a power cycle

There is **no protocol-level removal**. No opcode deregisters a peer; the write
paths in §5.3.2 add, and nothing on the wire subtracts. Removal is a console
operation. [W]

Order matters:

1. Console into **any one** panel on the BLN.
2. In the `Fieldpanels` sub-shell, `dElete` the entry from the BLN → site → peer
   hierarchy (the persistent active-peer state).
3. In the `nodeNametable` sub-shell, `Remove` the same name.
4. Wait for tombstone propagation (§5.3.4), then verify on a *different* panel —
   `nodeNametable Display`, and the field-panel listing.

**Reversing steps 2 and 3 strands the field-panel entry.** Recovering a stranded
entry requires a privilege level above the normal engineering account. Do the
field-panel delete first. [W]

> **Do not use a power cycle as a cleanup.** It does not work and it carries real
> risk. It does not work because the BLN-shared stores are non-volatile: a
> restarted panel is repopulated by peers that were not restarted, so entries
> return. And older PXC hardware is known to sometimes fail to reload after a
> power interruption, entering a `Not ready` state that requires a
> vendor-supervised reflash from a backup configuration to recover — observed
> once on a production panel during the investigation that produced this
> section. The console procedure above is non-disruptive and is the correct
> mechanism. [W]

#### 5.3.6 The EBLN diagnostic reads, and what each one returns

The `0x464A`–`0x4650` block is the EBLN replication diagnostic set. None of
these values appears in the supervisor-side `AP2_Function_Code` enum except
`0x464C`, and none occurs in ordinary traffic — **this** supervisor never
issues them, across the whole corpus. Whether another supervisor product or a
maintenance tool does is untested.
They are nonetheless implemented: every one below answered `dir=0x01` **success**
with a distinct structured body opening with the standard `SYST` scope preamble.

| Opcode | Body | What the body contained |
|---|---:|---|
| `0x464A` | 0 B | empty success |
| `0x464B` | 22 B | scope + a single node name |
| `0x464C` | 125 B | scope + a list of nine node names |
| `0x464D` | 12,073 B declared | **replication data store** — see below |
| `0x464E` | 117 B | scope + two replication grain keys, each with node name and USN |
| `0x464F` | 26 B | scope + one node name + a 4-byte tail |
| `0x4650` | 217 B | scope + default-panel tag, panel number, eleven node names, and the supervisor identity in both plain and `<name>\|<port>` form — **the host table** |

`0x4642` and `0x4643` answered `not_supported`: a handler was reached and
refused. `0x4647` returned nothing at all and remains **[OPEN]**.

**`0x464C` is the NodeList report**, established from three independent
directions rather than inferred: the vendor function enum names it
`AP2_EBLN_REPL_DIAG_NODELIST`; the panel firmware's own resource names an
*EBLN Replication NodeList Report* with columns `Node Name | Connection |
Replication`; and the captured body is exactly a list of node names. [W][S]

**`0x464D` is the replication data store.** The 4,380 bytes that arrived before
the client reset contain **57 replication grain keys** in the
`&<origin>&MMDDYYHHMMSS&<counter>` form of §5.3, from eight distinct origin
nodes. At that density the full declared 12,073 bytes carries on the order of
150 grains. [W]

**`0x4650` puts the host table on the wire.** This matters for anyone reasoning
about who can see that table: it is not surfaced in supervisor operator tooling,
but it is retrievable over P2 by any peer that satisfies the BLN check of §4.
"Not visible" is true of the operator UI and false of the protocol. [W]

#### The report catalogue

The panel's own firmware resource names the reports this family produces. Six
concern replication:

```
EBLN Replication Partners Report
EBLN Replication NodeList Report        Node Name | Connection | Replication
EBLN Replication Poll Schedule Report   Node_Name | Last_Polled_Time |
                                        Is_Partner | Reconcile_Pending
EBLN Replication Add Data Store Report
EBLN Replication Delete Data Store Report
EBLN Replication Diagnostic view
```

alongside `TRUNK_SETTINGS_REPORT`, `Ethernet TCP/IP Port Configuration Report`,
`Ethernet Setup Report`, `MII (Media Independent Interface) Report`,
`MAC Address Report`, `MultiCast Address Report` and
`MTU (MAXIMUM TRANSFER UNIT) REPORT`. [S]

**Which opcode emits which named report is deliberately left unstated** for all
but `0x464C`. Six report names and seven responding opcodes invite a positional
mapping, and a positional mapping across a range whose gaps are unknown is
exactly the reasoning that produced a wrong Telnet binding earlier in this
document's history. Where a body's content identifies it, that is recorded
above; where it does not, the gap stands.

#### Intra-site and inter-site are configured separately

The trunk settings the panel exposes are, in resource order:

```
Intrasite_eping_period          Intersite_eping_period
Intrasite_eping_timeout         Intersite_eping_timeout
Intrasite_notif_repl_period     Intersite_notif_repl_period
Intrasite_poll_repl_period      Intersite_poll_repl_period
Intrasite_repl_cycle_timeout    Intersite_repl_cycle_timeout
Tombstone_lifetime              Holdback_delay
```

Every replication timer exists **twice** — once for peers on the same site and
once for peers on another — and `Tombstone_lifetime` / `Holdback_delay` are
shared. The distinction does not appear in captured traffic because every
observed peer was intra-site; a deployment spanning sites will show the second
column's timers governing its cross-site exchanges. [S]

### 5.4 What a fresh client learns, and what it cannot

Because membership lives in the replicated node table rather than a beacon, a client's discovery path is:

- **Liveness of a known peer:** send/observe EPing (`0x4640`) and watch the ~10 s cadence (§5.1) [W].
- **Membership / roster:** obtain the node roster via the replication pull (`0x4634`) once admitted, or read it from a panel's host-table display (`0x462F`) / Telnet node-name-table report [W][S].
- **Cold discovery of an unknown site:** there is **no** P2 broadcast that enumerates nodes for an unauthenticated newcomer. With multicast off (the default) and no replicated table access (admission requires the correct BLN name, §6), a fresh client cannot passively discover P2 nodes; it must know addresses to connect to. This read-only posture is by design and is consistent across the evidence [W][I].

### 5.5 FLN discovery (P1WhoAreYou)

Below the BLN, a panel discovers and identifies the devices on each of its P1 FLN trunks using the **P1WhoAreYou** transaction [D]. An FLN device's identity is its **drop number + application number**: the drop number (0–31, §4.4) locates it on the bus, and the application number identifies which point-team/application it runs (the supervisor reads the device's application self-ID — conventionally subpoint 2, "APPLICATION" — to learn which point map the device implements; see the point-model section). A definition must match both the FLN device's system name **and** its address; a mismatch produces a `Failed P1WhoAreYou` error [D].

Access from the BLN to an FLN device is **route-through**: a client connects to the hosting BLN panel (over P2/TCP) and then addresses the device behind it; the panel polls its FLN device over P1 and returns the data (see §3 / the addressing section). The FLN-scoped browse/enumerate operations on the BLN side are the `0x09xx` upload/enumerate family and the FLN-topology query `0x5301` `AP2_GET_FLN_TOPOLOGY` [S]; FLN scan enable/disable is `0x4630`/`0x4631` (`AP2_FLN_SCAN_ENABLE` / `_DISABLE`) [S]. The route-through model is why BLN-to-FLN access never appears as a separate transport — it is always layered on an established P2 node session.

### 5.6 Open items — discovery & FLN timing

> **[OPEN] FLN/P1 wire bytes.** P1WhoAreYou, FLN addressing (drop + application number), and the route-through model are documented at the behavioral level, but the P1 frame bytes — the WhoAreYou request/response layout and the per-device poll cadence — are unobserved. Needs a P1-bus or route-through capture.

> **[OPEN] Per-frame retry/ACK timing.** All established timing is at the discovery/replication layer (EPing periods/timeouts; replication notify/poll/cycle; the binary Extended-Timeout pre-Rev-2.1 compatibility flag). P2 *frame-level* retry counts and per-frame ACK/sequence timeouts are not established and should not be inferred from the discovery-layer periods.

**`0x4636` body layout.** Mapped from the read-only corpus; 1,412 of 1,412 grains decode under the constraint that each record must tile the buffer exactly. [W]

```
u16   reconciliation
u32   boc_usn_changed
u8    more_data
u16   srce_cycle_number
u16   srce_cycle_pdu_number
u16   n_utdv                     "up-to-dateness vector" entry count
      utdv[] :  TLV node name | u32 USN          <- the version vector
u16   n_grain
      grain[] :
        TLV   record key         "&<origin>&MMDDYYHHMMSS&<counter>"
        u32   local USN
        u8    replication command type
        u8    grain type
        TLV   target             host-table name; MAY be zero-length (BLN scope)
        u16   embedded length
              u16 opcode | TLV scope ("SYST") | 23 3f ff ff ff | TLV name | tail
        u32   counter
        u32   origin time        unix epoch seconds
        TLV   origin node
        u32   origin USN
```

Field names follow the vendor's `ATOMGrainMetaData` / `ATOMReplicationUpToDatenessVector` structures, which also define `tombstone time` and `holdback time` members corresponding to the `Tombstone_lifetime` and `Holdback_delay` trunk settings of §5.3. [S] A zero-length target TLV is legal and marks a BLN-scope rather than host-scope record; a decoder that rejects empty TLV values silently drops those records. [W]

> **[OPEN]** The COV/condition block carried inside change records for point-value updates is still not mapped; the grains observed carry host-table and configuration operations. Confirming it needs a capture taken during live point-value replication.
## 6. Frame Format (Wire)

This section defines the P2 on-wire frame: the exact byte layout, the message-type
discriminator, the direction byte, the four routing slots, the opcode field, and segmentation.
P2 ("Protocol II", the APOGEE BLN/backbone protocol) runs over TCP/5033 (see §4/§3 for transport
and addressing). The frame format is uniform across all message classes and both protocol
dialects; only body conventions and session role differ. Every multi-byte integer in the
header is big-endian (lengths and the sequence number are big-endian u32; the opcode and the
error code are big-endian u16; analog values in bodies are IEEE-754 big-endian f32).

### 6.1 Frame byte layout

A frame is a fixed 13-byte header, followed by four NUL-terminated ASCII routing slots,
followed — **only on request/push frames** — by a 2-byte AP2 function code (the opcode),
followed by an opcode-specific body. [W]

| Offset | Field | Type | Value/Notes | Tag |
|---|---|---|---|---|
| 0 | `total_len` | u32 BE | Total frame length, **including these 4 bytes** (self-inclusive). | [W] |
| 4 | `msg_type` | u32 BE | High three bytes `0x00 0x00 0x00` in **all 621,268 trusted frames, without exception**; low byte is the message-class discriminator (§6.2). | [W] |
| 8 | `sequence` | u32 BE | Per-connection request sequence; echoed verbatim in the matching response (§6.5). | [W] |
| 12 | `dir` | u8 | Direction byte: `0x00` request/push, `0x01` success, `0x05` error (§6.3). | [W] |
| 13 | `slot[0]` | ASCIIZ | BLN name. | [W] |
| … | `slot[1]` | ASCIIZ | Destination node name (on a request) / source node name (on a response). | [W] |
| … | `slot[2]` | ASCIIZ | BLN name (identical content to slot[0]). | [W] |
| … | `slot[3]` | ASCIIZ | Source node / self identity (on a request) / destination (on a response). | [W] |
| `S` | `opcode` | u16 BE | The 2-byte AP2 function code. **Present if and only if `dir == 0x00`** (§6.4). | [W] |
| `S+2` | `body` | bytes | Opcode-specific request body, or — on a response — the result payload / 2-byte error tail. | [W] |

`total_len` is self-inclusive: it equals the exact on-wire byte count of the frame counting the
four length bytes. For a body-less success response the value is `13 + (sum of the four
NUL-terminated slot lengths including their NUL terminators)`. [W]

`S` is the **variable** post-slot offset at which the opcode (request) or body (response) begins.
It is variable because the four routing slots are variable-length strings. A parser MUST locate
`S` by scanning forward from offset 13 and counting four NUL terminators; it MUST NOT assume a
fixed offset. The four slots are the only variable-length region of the header, so once four NULs
have been consumed the parser is positioned at the opcode (if `dir == 0x00`) or at the response
body. [W] A fixed-offset opcode parser is wrong and fabricates phantom values. [W]

#### 6.1.1 Framing over TCP

Framing is a pure length prefix over the reassembled TCP byte stream — no record delimiter, no
escape mechanism. A receiver reads four bytes, decodes `total_len`, then reads `total_len − 4`
further bytes to complete the frame. A single TCP segment may carry several P2 frames, and one P2
frame may span multiple segments; a receiver MUST buffer across segment boundaries until a whole
frame has arrived. [W] An implementation should reject any frame whose declared `total_len`
exceeds a sane ceiling (for example 65536 bytes) before buffering, to bound memory against a
malformed or hostile length prefix. [I] It should equally reject one that is
too **small**: 13 header bytes plus four NUL terminators is 17, and a request
adds two opcode bytes for 19, so any `total_len` below that cannot describe a
valid frame and a reader that subtracts without checking will underflow. No
frame in the corpus comes close — the observed range is **31 to 1,622 bytes**,
median 85 — but the floor is a property of the format, not of the traffic. [W]

#### 6.1.2 Annotated hex example

A legacy-dialect (`msg_type` low byte `0x33`) ReadShort-class request, addressed from supervisor
identity `P2SCAN|5033` on BLN `BLNNAME` to destination node `NODE1`, carrying opcode `0x0220`
(`POINT_LOG_VALUE`, the modern compact read) with a `SYST` read-scope prefix. All values are
sanitized placeholders; the body grammar of a given opcode is defined in §8.

```
00 00 00 5E   total_len  = 0x5E = 94 bytes (self-inclusive)            [W]
00 00 00 33   msg_type   = low byte 0x33 (legacy DATA dialect)         [W]
00 00 1A 2F   sequence   = 0x00001A2F (per-connection, big-endian)     [W]
00            dir        = 0x00 (request — opcode IS present)          [W]
42 4C 4E 4E 41 4D 45 00              slot[0] "BLNNAME"\0   (BLN)        [W]
4E 4F 44 45 31 00                    slot[1] "NODE1"\0     (dst node)  [W]
42 4C 4E 4E 41 4D 45 00              slot[2] "BLNNAME"\0   (BLN again) [W]
50 32 53 43 41 4E 7C 35 30 33 33 00  slot[3] "P2SCAN|5033"\0 (src id)  [W]
02 20            opcode = 0x0220 (POINT_LOG_VALUE / ReadShort)         [W]
01 00 04 53 59 53 54                 SYST scope-name TLV               [W]
00 3F FF FF FF                       scope selector: scope_byte 0x00 (read) + mask [W]
00 00                                name_space = system (§8.5)        [W]
01 00 0A 43 54 4C 52 30 31 2E 30 30 31   name TLV part 1 "CTLR01.001" (10) [W]
01 00 07 52 4F 4F 4D 54 4D 50            name TLV part 2 "ROOMTMP"     (7)  [W]
00 00 01 00 00 01 00 00              read trailer (8 bytes)            [W]
```

The two BLN-name slots are byte-identical; both MUST be populated. The opcode sits immediately
after the NUL terminator of `slot[3]`. On the matching response (§6.3) `dir` becomes `0x01`, slots
[1] and [3] swap, and the two opcode bytes are absent — the response body begins immediately after
`slot[3]`'s NUL. See §6.4 for the consequences of reading post-slot bytes off a response frame.

### 6.2 The msg_type discriminator (message class / dialect)

`msg_type` is a 32-bit field whose top three bytes are always `0x00 0x00 0x00`; only the low byte
varies. The low byte is a per-transaction message-class / dialect selector. The header layout and
the four-slot routing structure are identical for every value — only body conventions and session
role differ. Six low-byte values are observed; **`0x40` is never observed** in any capture and is
not a P2 message class. [W]

| Low byte | Name | Role | Tag |
|---|---|---|---|
| `0x33` | DATA, legacy dialect | Operational data traffic, legacy dialect. The dominant class — the great majority of all request classes. | [W] |
| `0x34` | DATA, modern dialect | Operational data traffic, modern dialect. Byte-for-byte a `0x33` frame with the low byte incremented; carries the same opcode set. | [W] |
| `0x2E` | second channel, legacy | Announce / reverse / DB-sync carrier for **legacy-firmware** panels (pairs with `0x33` data). Carries identity (`0x4640`), DB-change/replication records, and alarm prints; may also carry an entire transaction in "single-type carrier" mode. | [W] |
| `0x2F` | second channel, modern | The **modern-firmware** counterpart of `0x2E` (pairs with `0x34` data) — same role, selected by panel generation, **not** by direction. | [W] |
| `0x29` | session carrier | Lowest-volume session carrier; appears only at the very start of a connection at low sequence numbers, accompanying session establishment. | [W] |
| `0x2A` | peer-session carrier | The modern-dialect counterpart of `0x29`, carrying the `EBLN_PING` (`0x4640`) identity exchange in peer-to-peer (panel↔panel) sessions. **Wire-observed in panel-side captures** — 12,556 frames across five taps on two different panels — carrying `0x4640`, `0x0271` and `0x4634`. It is absent from the supervisor-side census only because that vantage point cannot see panel↔panel sessions. Which of `0x29`/`0x2A` a peer uses is a property of that peer, not of the link: see §9.7. | [W] |

Class-frequency profile (shape, reproducible per-capture; absolute totals are deployment-dependent):
`0x33` (legacy data) dominates, then the legacy second-channel `0x2E`, then the modern data dialect
`0x34`, then the modern second-channel `0x2F`; the session carrier `0x29` is small and the peer
carrier `0x2A` appears only in panel-to-panel (mirror) captures. **`0x2E` consistently outnumbers
`0x34`** — the second channel runs on every legacy panel, while `0x34` runs only on the (typically
few) modern-firmware panels. Representative single 3-hour supervisor capture (≈163,700 P2 frames): `0x33`
≈ 130,000; `0x2E` ≈ 18,900; `0x34` ≈ 11,500; `0x2F` ≈ 3,300. (A panel-side mirror capture additionally
shows the peer carriers — in this corpus `0x29` only, 10 frames, §9.7.) [W]

**The session / second-channel band.** The low-byte values `0x29`–`0x2F` form a **session /
second-channel band** (`0x29` session carrier, `0x2A` peer-session carrier, `0x2E`
legacy second channel, `0x2F` modern second channel) — all of which carry the `EBLN_PING` (`0x4640`)
identity exchange — as distinct from the **data band** `0x33` (legacy dialect) / `0x34` (modern
dialect) that carries the operational opcode set. The pairing within the band is by **panel firmware
generation**, not by session role or direction (§6.6): a legacy panel uses `0x2E` in both directions,
a modern panel uses `0x2F` in both. [W]

- **`0x2E`** = the **legacy** panel's second channel — the `0x4640` identity exchange plus the
  panel→supervisor announce and DB-change/replication records and alarm prints (§5.3, §13). [W]
- **`0x2F`** = the **modern** panel's second channel — the same role as `0x2E`, selected by firmware
  generation. The identity body is `TLV(node-name) + TLV(site) + TLV(BLN-name)` (the same triple as
  the `0x4640` `eBLN_Node` body, §5.1, §10.6). [W]
- **`0x29` / `0x2A`** = the peer (panel↔panel) carriers of the same exchange (session /
  peer-session), visible only from a panel-side mirror. [W]

The residual nuance — which peer is treated as **primary** vs secondary within a panel↔panel
`0x29`/`0x2A` session (and on what criterion the primary is chosen) — is not pinned. The role/initiator
meaning of the band itself is established. [W][OPEN]

**Parsing vs emitting.** `0x33` and `0x34` are interchangeable for parsing — a receiver treats
them identically. Only the **emit-side** dialect choice must match the peer. When a client must
discover a peer's dialect, the candidate set is exactly `{0x33, 0x34}`, probed in that order; the
carriers `0x2E`/`0x2F`/`0x29`/`0x2A` are session/second-channel carriers, **not** data dialects, and
MUST NOT be iterated during dialect detection. Dialect is not negotiated by a handshake message; it is
a **fixed per-peer property of the panel's model + firmware generation** (§6.6) — legacy panels speak
`0x33`+`0x2E`, the newer platform speaks `0x34`+`0x2F` — and is best discovered by fingerprinting the
peer via `CABINET_DISPLAY` (`0x010C`, §10.5) rather than blind-probing. [W]

**The second channel (`0x2E`/`0x2F`) carries more than identity.** Between a supervisor and a panel,
the `0x2E` (legacy) / `0x2F` (modern) class is the **announce / reverse / DB-sync channel**: besides
the `0x4640` identity exchange it carries database-change and replication records (`DBCHANGE_*`,
`UPL_ADDED_*`, `UPL_DEL_*`) and alarm prints (`ALARM_PRINT 0x0508`) flowing panel→supervisor. The
peer (panel↔panel) carriers `0x29` and `0x2A` are visible only from a panel-side mirror, never from
the supervisor's own vantage. Measured there, **both are dominated by the `0x4640` identity/keepalive
exchange**, not by COV: across five panel-side captures on two panels `0x29` carries `0x4640` (43,610), then `0x4634` (6,223),
then `0x0271` (245), with `0x4633`/`0x4636` in single figures, and `0x2A` carries `0x4640` in roughly
ninety-nine frames out of a hundred (6,228) with `0x0271` (46) and `0x4634` (4) making up the rest. An earlier edition described `0x2A` as the
panel↔panel COV-subscription carrier; COV management rides it, but calling it that mistakes a minority
of its traffic for its purpose. [W]

**Second-channel session establishment.** Session establishment is not a distinct opcode or message
class — it rides the second channel as the `0x4640` (`EBLN_PING` / IdentifyBlock, §7) identity
exchange. When the source identity in `slot[3]` matches a node already in the receiver's peer list,
the receiver replies with a distinct, short (~48-byte) second-channel response that is effectively an
**outbound peer offer** back to the peer — different from the passive ~91-byte `0x33` DATA-dialect
response returned to a freshly-accepted (wildcard) identity. [W] Critically, this second-channel identity path accepts an arbitrary `slot[3]` identity (it
is not bound by the data-service identity-length gate of §7); empirically it has accepted identities
at lengths 10 and 15. [W]

**`0x2F` is the modern counterpart to `0x2E` — a per-panel-platform pair, not a direction.**
`0x2F` is to `0x2E` exactly what `0x34` is to `0x33`: the **modern-platform** form of the second
channel. The choice between the pair is fixed by the panel's firmware generation (§6.6), **not** by
traffic direction — a legacy panel uses `0x2E` in *both* directions (supervisor→panel and
panel→supervisor) and a modern panel uses `0x2F` in both. An earlier reading that mapped `0x2E` to the
supervisor→panel direction and `0x2F` to the panel→supervisor direction was an artifact of a small
capture in which the one modern panel happened to be the main reverse-pushing node; a three-hour
fleet capture shows the split tracks the panel, not the direction. [W] A client that does not
originate peer-to-peer connect offers need not emit `0x2F`, but MUST accept and correlate inbound
`0x2F` frames by sequence, and MUST emit the pair member that matches the peer's generation. [W]

**Connection modes.** The second-channel class chosen for a connection follows the panel generation;
within that, two usage patterns appear, by whether the carrier hands off to the data class:

| Mode | Carrier (second-channel) class | Data class | Applies to | Tag |
|---|---|---|---|---|
| Legacy | `0x2E` | `0x33` | older-firmware panels | [W] |
| Modern | `0x2F` | `0x34` | newer-firmware panels | [W] |
| Single-type carrier | `0x2E` or `0x2F` (every frame stays on the carrier class) | — | schedule/program edits and alarm bursts, on either generation | [W] |

In the first two rows the carrier class establishes/keepalives the session (via `0x4640`) and carries
the panel→supervisor announce + DB-change records, while operational reads/writes ride the matching
data class; in the single-type-carrier pattern a whole transaction (e.g. a schedule edit or an alarm
burst) stays on the carrier class start to finish. A parser distinguishes a session-establishment
frame from an operational frame by inspecting the two bytes after the routing slots on a `dir == 0x00`
frame: if they equal `0x4640`, the frame is a session establish/keepalive; otherwise they are an
ordinary opcode. [W]

### 6.3 The direction byte

The single byte `dir` at offset 12 selects the meaning of everything after the routing slots.
Exactly three values are defined. [W]

| `dir` | Meaning | Post-slot content | Tag |
|---|---|---|---|
| `0x00` | request / unsolicited push | a 2-byte opcode followed by the request body | [W] |
| `0x01` | success response | a result body (may be empty); **no opcode** | [W] |
| `0x05` | error response | exactly 2 bytes — a u16 BE error code (§7.2); **no opcode**. Validated across the corpus: all **6,006** error responses have a 2-byte body, with no exceptions. | [W] |

Observed corpus distribution: `0x00` 314,273; `0x01` 300,989; `0x05` 6,006 (summing to 621,268). [W]

The governing rule is: **the opcode field is present if and only if `dir == 0x00`.** A response of
either kind carries no opcode. An unsolicited push — for example a change-of-value report (opcode
`0x0274`, `COV_ANNUNCIATE`) or an `0x4640` heartbeat — uses `dir == 0x00` exactly like a request,
carries an opcode and body, and is acknowledged by the peer with a `dir == 0x01` empty success. [W]
The `dir == 0x05` error response is the panel's application-layer error path; it is distinct from a
TCP-level reset (which signals a wrong-BLN rejection or a fault, §7) and from the comm-status flag
inside a value block (which signals device health). [W][I]

### 6.4 Routing slots

The four slots carry the routing identity of the frame as **NUL-terminated** ASCII strings. They
carry no length prefix — distinct from the length-prefixed TLV form (`<textType> <len:u16>`) used
inside bodies; the two MUST NOT be conflated. [W]

**There are always exactly four, and the count is not conditional on anything** —
direction, message class, opcode or body: **621,268 frames of 621,268** carry
four, with no exceptions. A parser may therefore read four NUL-terminated
strings unconditionally after the header and does not need to probe for a
terminator count. [W]

**Slot lengths, measured.** Across those frames — about 2.5 million slot
strings — the two node-name slots stay well inside the documented 30-character
limit of §3.4.2, and the source-identity slot runs longest because of its
`|PORT` suffix: [W]

| slot | role | distinct values | longest |
|---|---|---:|---:|
| 0 | BLN name | 137 | 255 — **all six over-30 values are our own probes**, below |
| 1 | destination node name | 119 | **16** |
| 2 | BLN name (doubled) | 138 | 255 — same six |
| 3 | source node identity | 159 | **21** |

**The documented 30-character limit cannot be tested from outside, and it is
worth saying why.** Exactly six distinct slot strings in the corpus exceed 30
characters, at lengths 32, 63, 64, 127, 128 and 255 — powers of two and their
off-by-ones, each appearing exactly twice because the BLN name is doubled into
slots 0 and 2. All six are `0x4640` frames from a single capture whose name
marks it a probe, and no P2 frame returned on the reverse tuple for any of
them.

That is **not** evidence the panel enforces a length limit. A 255-character BLN
name is, by construction, *not this site's BLN name* — so the BLN-correctness
gate of §17.2 rejects it on identity long before any length check could matter,
and the two variables are confounded. The rejection is what §6.4's wrong-BLN
result already predicts, and it would look the same at 31 characters as at 255.

A length limit on the BLN-name slot can therefore only be tested from the
inside, by configuring an over-length BLN name on a panel and observing whether
the firmware accepts it. Treat 30 as a **documented** bound (§3.4.1) that
vendor traffic never approaches — the longest real name here is well under
it — rather than as an enforced wire constraint. [W]

On a request (`dir == 0x00`, including an unsolicited push) the slot order is:

```
slot[0] = BLN name           (the building-level-network name)
slot[1] = destination node   (the node being addressed)
slot[2] = BLN name           (identical content to slot[0])
slot[3] = source node / self identity (the sender)
```

On a response (`dir == 0x01` or `0x05`) the destination and source contents swap, so each frame's
`slot[1]` always names that frame's destination. A request addressed `[BLNNAME, NODE1, BLNNAME,
P2SCAN]` produces a reply addressed `[BLNNAME, P2SCAN, BLNNAME, NODE1]`. Slots 0 and 2 are stable
(both the BLN name); slots 1 and 3 reverse. The BLN name appears **twice** in every frame; both
copies carry the same value, and a conformant node MUST populate both. [W] The vendor framing logs
the routing as name/channel/trunk/cabinet, with the trunk corresponding to the BLN. [S]

**Why the BLN name appears twice — a better answer, and a way to test it.** The routing object in
the supervisor's own stack does not model four independent slots. It models **four roles**: a trunk
id, a panel id, a supervisor id, and an object name. [S] Read against that, the wire's four slots
are not `[BLN, dst, BLN, src]` but **two `(trunk, node)` pairs** — each identity carried together
with the trunk it lives on. The duplication is then not redundancy at all; it is one field per pair,
and both pairs happen to name the same trunk on a single-BLN network.

That is a **falsifiable prediction**: on a frame that crosses between two BLNs, slots 0 and 2 should
carry **different** trunk names. The present corpus cannot test it — across **621,268** trusted
four-slot frames, slots 0 and 2 are identical in **206,045**, and every one of the five exceptions
is a deliberately malformed research probe rather than production traffic. Every capture to hand is
single-BLN, so the pair reading is **untested, not confirmed**. A capture taken where two BLNs
exchange traffic would settle it in one frame. [W] **[OPEN]**

Two further details from the same object model. Names decompose into a **base plus a suffix** with
an explicit truncate operation — which is the mechanism behind the length limits of §3.3.2 rather
than a separate rule — and there are **two distinct name types**, a *system* name and a *user* name,
each with its own base/suffix pair. §3.4's system-name-versus-user-name distinction is therefore
structural in the implementation, not merely a UI convention. [S]

Implementation note: node names may differ in letter case between a request and its reply (e.g.
`node1` vs `NODE1`). Case variation is cosmetic and does not affect routing. [W]

**Slot meaning and validation.** The three identity fields are enforced unequally. The BLN name is
the membership gate — two nodes exchange P2 traffic only if their BLN names are identical. [W]

| Field | Typical enforcement | Wrong-value symptom | Tag |
|---|---|---|---|
| BLN name (slots 0/2) | strict, case-sensitive | TCP RST (panel) or graceful FIN (supervisor listener); no application processing, no node-table side effect | [W] |
| destination node (slot 1) | case-insensitive match against the known-peer list | frame silently dropped, connection stays up | [W] |
| source identity (slot 3) | deployment-dependent; format-shaped, not authenticated | ignored on permissive configs; silently dropped on configs that enforce a peer list | [W] |

A wrong-BLN handshake is **footprint-free**: in a controlled 24-handshake test (8 wrong-BLN
variants × 3 reps) the panel returned TCP RST for every attempt, with zero data responses, zero
silent drops, and zero new NODE NAME TABLE entries. [W] Registration is gated by BLN-correctness,
not by data-service acceptance: a **right-BLN** handshake with a novel `slot[3]` identity writes a
Permanent NODE NAME TABLE entry at the sender's IP even when the panel refuses to serve data at the
5033 data layer (the data-service identity check is a separate, later gate — see §7). [W]

**The `|port` identity suffix.** A source identity in `slot[3]` commonly appears as `NAME|PORT`,
for example `P2SCAN|5033` or `DCC-SVR|5034`. The `|PORT` portion is part of the *identity
string* — a `HOST|PORT` disambiguator that lets one host present distinct identities — and is **not**
a network-layer port indicator and **not** a field delimiter. [W] Decisive evidence: a supervisor
stamps `DCC-SVR|5034` into `slot[3]` in thousands of frames captured on a **5033-only** link,
and the literal `5033` appears in no slot of any frame in the corpus. The same suffixed identity rides whatever TCP port
carried the frame. [W] Handling: when **building** a frame, emit the full literal identity including
the suffix and do not split on `|`; when **parsing**, accept both the suffixed and bare forms —
responses and routing-table entries frequently return the bare `NAME` without the suffix. [W]

**Opcode presence warning.** The opcode is present **only when `dir == 0x00`**. Reading the two
post-slot bytes off a `0x01` success or a `0x05` error frame fabricates phantom opcodes — the
values `0x0100`, `0x0200`, `0x0300`, `0x0400` seen by such a parser are response-payload artifacts,
not function codes. Any census, dissector, or scanner that tallies opcodes off response frames is
inventing them. A robust dispatcher keys on `(opcode, body shape)` together, because several
opcodes are polymorphic — the same value selects different operations by body shape, scope tag, and
direction (e.g. `00 FF` read trailer vs `00 00` command trailer on the same addressing grammar).
[W] Some opcodes carry a 2-byte sub-field immediately after the opcode (e.g. `00 00` or `00 01`)
before the body; its presence is opcode-specific. The session opcode `0x4640` carries no such
sub-field — its TLVs begin immediately after the opcode. [W]

### 6.5 Sequence number and request/response pairing

`sequence` is a per-connection 32-bit (big-endian) value. A response — success (`0x01`) or error
(`0x05`) — echoes the `sequence` of the request it answers. This echo is the **only** correlation
between a request and its reply: because a response carries no opcode, the requester recovers the
meaning of a response body by looking up the opcode of the outstanding request bearing the same
`sequence`. A sender increments `sequence` per request; each TCP connection has an independent
sequence-number space. [W]

The vendor datalink maintains three change counters — Master / Primary / Secondary
(`ChangeMseq` / `ChangePseq` / `ChangeSseq`) — underneath this single wire field. [S] These map to
**multiple independent sequence spaces by role/channel**: a node's outbound-request counter, its
COV/value push counter, and each peer-channel counter are distinct number lines, not one shared
counter. [W] A sender should initialize `sequence` to a random value rather than 0/1. The normative
correlation rule is **exact echo**: a response carries the verbatim `sequence` of the request it
answers, and a robust requester matches on that exact value against its set of outstanding requests.
[W]

**Pipelining is real and confirmed.** Two overlapping live captures show the request `sequence` and
the reverse-direction response `sequence` carrying the **identical** value range — the response echoes
the request's `sequence` verbatim, which is exactly how a client matches a reply to its outstanding
request — and up to **14 requests outstanding** observed before their responses arrive. Measured
across the whole corpus (306,990 paired exchanges), the peak depth per connection is 1 for the
large majority — 2,073 connections never exceed one outstanding request — with a tail through
2, 3, 5, 9, 10 and a single connection reaching **14**. 14 remains a *capture-bound* maximum, not a
protocol limit; treat it as "at least 14" and use a sliding-window matcher with no fixed depth. A reply may therefore
lag a request by a small number of steps (never arrive ahead of it); a sliding-window matcher keyed on
exact `sequence` is the correct implementation, not merely defensive accommodation. [W]

**Implementation note — each TCP connection has its own narrow counter at a distinct base.** Every
TCP connection carries its **own** sequence space, and that space is **narrow** — no single
connection's `0x33`/`0x34` sequence was observed spanning more than ≈0.04M over a 3-hour capture.
The wide ranges you see when you (wrongly) merge a host-pair's two connections are an artifact: a
supervisor↔panel pair runs **two** concurrent connections (the panel's `:5033` data-listen channel
and the supervisor's `:5034` push/command channel), each at a **very different base**. On one
multi-panel supervisor capture: legacy panel node6's `:5033` data channel ran ≈3.300M–3.338M while
*its own* `:5034` channel ran ≈7.087M–7.123M; a second legacy panel's `:5034` channel sat near
≈0.311M; the modern panel's `:5033` (`0x34`) ran ≈3.300M–3.338M and its `:5034` ran ≈4.372M–4.373M.
Distinct, widely-separated bases per connection **refute a single global counter shared across
connections** — if one counter fed every link they would share one contiguous range, which they
plainly do not. [W] Within a single connection the value increments by `≥1` with small **gaps** (the
node's other concurrent channels/operations consume intervening values), so a receiver MUST treat
`sequence` as **opaque per-connection match data** and MUST NOT assume a strict `+1` increment. A reconnecting node **resumes** its counter (the first frame on a
freshly-opened TCP connection continues the prior high value, it does not reset to 0/1). [W] The
normative rule remains **exact echo**: a response carries the request's `sequence` verbatim; match on
that against the set of outstanding requests on that connection. [W]

### 6.6 Legacy and modern dialect differences

The legacy dialect (`0x33`) and modern dialect (`0x34`) are byte-compatible. For the same operation
the only required byte difference is the `msg_type` low byte:

```
legacy:  <total_len> 00 00 00 33 <sequence> 00  <slots> <opcode> <body...>
modern:  <total_len> 00 00 00 34 <sequence> 00  <slots> <opcode> <body...>
```

The header layout, four-slot routing, opcode position, direction semantics, TLV grammar, scope tag,
f32 encoding, and error tail are all identical across the two dialects. The two carry the **same
operational opcode set and the same value encoding** — a side-by-side check of `COV_ANNUNCIATE`
payloads on both dialects returns identical big-endian `f32` values; only the `msg_type` low byte
differs. [W]

**Dialect is a stable per-peer property fixed by the panel's firmware generation — not a
per-transaction choice, and not by hardware type.** In a single supervisor capture spanning a
nine-panel fleet, each panel used exactly **one** dialect pair for its entire lifetime in the capture,
and the split tracked **firmware generation on identical hardware**: all nine were the same hardware
platform (a modular-cabinet controller — `PXME` in the firmware identity string), but the eight on an
older firmware build (a 2013-era revision) spoke **legacy** `0x33` DATA + `0x2E` on their second
channel, while the one on a newer firmware build (a 2019-era revision) spoke **modern** `0x34` DATA +
`0x2F` exclusively. [W] The panel's firmware revision string, version, and build date are all readable
in one round-trip via `CABINET_DISPLAY` (`0x010C`, §10.5), so a client SHOULD **fingerprint the peer
and select the dialect from its firmware generation** rather than blind-probing. As a fallback when the firmware is unknown, the candidate set is exactly
`{0x33, 0x34}` (§6.2), legacy first; for **parsing**, the two are interchangeable (a receiver treats
them identically). Note this legacy↔modern split is a **revision within the proprietary-P2 firmware
line** (a later 2.x build emits the modern classes) — it is *not* a protocol-family change, and is
distinct from the separate "P2 vs BACnet firmware" choice the same hardware platform can be ordered
with (§10.5); a BACnet-firmware unit is not a P2 node at all and does not appear on the P2 BLN. Opcode coverage overlaps but is not identical: most high-volume operations occur in
both, while certain single-shot and legacy-supervisor operations occur only in the legacy dialect. [W]

Implementation note: name/string **encoding** is a per-firmware-revision property, not a per-frame
one. Early (pre-IP) revisions pack names in **RAD-50** — three characters per 16-bit word over the
40-symbol alphabet `" ABCDEFGHIJKLMNOPQRSTUVWXYZ$.?0123456789"` (index 0 = space, 1–26 = A–Z, 27 =
`$`, 28 = `.`, 29 = `?`, 30–39 = `0`–`9`), packed as `((c0 × 40) + c1) × 40 + c2`. [S] All P2/IP
revisions use plain ASCII in the length-prefixed TLVs and NUL-terminated slots. A node uses one
string encoding for its whole revision; the firmware/platform identity selects the encoding (the
vendor's per-platform `STRING_TYPE` = RAD50 or ASCII). A peer presenting RAD-50-packed names is a
pre-IP revision, out of scope for a TCP/5033 ASCII implementation. [S][D]

**The per-peer capability model — how one client speaks to every panel generation.** Dialect and
encoding are not negotiated on the wire; there is no capability handshake, no version byte exchanged
per transaction, no feature bits. Instead the encoding and dialect are **learned once per peer, at
connect, from the peer's firmware revision**, and then applied statically for the life of the session.
A conformant multi-generation client (this is exactly how a supervisor talks to a mixed fleet) keeps a
small per-peer record — `{ device generation, string encoding, message-class dialect }` — and fills it
in the first time it reaches a peer:

1. **Learn.** Read the peer's firmware revision once at connect — `CABINET_DISPLAY` (`0x010C`, §10.5)
   returns the revision string, version, build date, and platform in a single empty-request round-trip
   (a pre-IP serial peer is identified by its revision-table entry instead). The revision string is the
   the single defining input. [W]
2. **Classify.** Map the revision to a **device generation**, which is purely a function of the
   revision value: a **field-bus (FLN/P1) device**, a **modern APOGEE Ethernet panel** (revision at or
   above the APOGEE threshold), a **legacy / pre-APOGEE panel** (revision below it), a **LON-integrated
   panel**, or a **BACnet-firmware unit** (which is not a P2 node at all and never appears on the P2
   BLN, §10.5). This classification is the same one the field's own supervisor makes, and it is
   derivable entirely from the observable revision — no probing required. [S][I]
3. **Select encoding.** The generation selects the string encoding — pre-IP revisions = **RAD-50**, all
   IP/APOGEE revisions = **ASCII** (above) — via the vendor's per-revision `STRING_TYPE`. [S][D]
4. **Select dialect.** The generation selects the message-class dialect — **modern `0x34`/`0x2F`** for
   the newer-firmware generation, **legacy `0x33`/`0x2E`** otherwise (§6.2). The selector reduces to a
   single bit driven by the stored per-peer generation, not by anything on the wire. **Measured across
   the corpus, and it holds:** [W]

   | | pairs | mixing the two dialects |
   |---|---:|---:|
   | source→destination pairs carrying a data dialect | 762 | **34** |
   | …carrying a second-channel frame | 362 | **0** |
   | …carrying a peer carrier `0x29`/`0x2A` | 857 | **0** |

   The 34 are not counter-examples. **Twenty-nine mix by exactly one frame**, the
   rest by two to five, and the largest — eighteen — is in a capture named for a
   supervisor enumeration test: they are our own scanner probing both dialects,
   not a peer alternating. **728 of 762 pairs never mix at all.**

   The generations also agree between the two channels: of the nodes emitting
   exactly one data dialect and exactly one second-channel class, **263 of 263**
   pair `0x33` with `0x2E` and `0x34` with `0x2F`, with **zero** disagreements.

   Note the unit. A *node* may well emit both `0x33` and `0x34` — 34 of 461
   sources do — because a supervisor speaking to a mixed fleet uses each peer's
   dialect. Group by the **pair**, never by the sender, or the mixed-fleet
   supervisor looks like a protocol violation. [W]
5. **Cache and reuse.** A client may store the record against the peer and reuse it for every
   subsequent frame: the dialect itself is stable per peer for as long as any connection to it lasts
   (item 4). What a client must **not** assume is that the identity block behind it is read once.
   The observed supervisor **re-reads `CABINET_DISPLAY` on a fixed timer** — measured per peer across
   the corpus, successive reads to the same peer fall in two tight populations, **30.006 s**
   (σ 0.0043 s, n=82 intervals over 7 peers) and **≈3600.4 s** (n=33 over 10 peers), with one peer
   showing both. All 115 of those intervals are **within a single live connection**, so neither is a
   reconnect artifact, and only 13 of the 115 connections carrying an `0x010C` open with one — it is
   a poll, not a session handshake. Whether the supervisor is refreshing its dialect record or merely
   using the same opcode for periodic health is not observable from the wire; what is observable is
   that a peer must expect the identity block to be re-read on a schedule regardless of whether
   anything about it has changed. [W]

   (§5.0's cadence table measures the same opcode **per connection** and reports 30.01 s over 102
   intervals; this measurement is **per peer**, which is a different denominator, and it is what
   exposes the hourly population — an hourly peer contributes few intra-connection intervals.
   The two figures agree where they overlap; neither corrects the other.)

The practical consequence for an implementer: you do **not** blind-probe `{0x33, 0x34}` or guess the
encoding. You issue one `CABINET_DISPLAY`, classify the generation from the returned revision, and from
that one read you know both how to encode names (RAD-50 vs ASCII) and which dialect to frame in — for
that peer, permanently. This learned-once-per-peer record is the entire mechanism behind "it just works
with every controller on the BLN." [W][S][I]

### 6.7 Segmentation

P2 carries large payloads across multiple frames via a **more-follows / segment** mechanism in the
application layer. The application layer exposes a more-follows segmentation flag and
`MapSegment` / `GetSegBufferCopy` segment-buffer machinery; a partial reply sets more-follows and
the requester pulls the next segment (the replication family `EBLN_REPL_PULL` / `EBLN_REPL_PULL_MORE`
/ `EBLN_REPL_CHANGES` carries explicit `srce_cycle_number` + `srce_cycle_pdu_number` segment
cursors and a `more_data : BOOLEAN_` field for exactly this). [S]

**The ~256-byte figure is NOT a frame-size cap.** A previously cited "roughly 256 bytes as the
maximum P2 data packet" is a vendor *connection-test ping* figure, not a limit on how large a single
P2 frame may be. [D] On the wire a single P2 frame's `total_len` is bounded only by the header's u32
length field (implementations cap at a sane ceiling); the largest single **legitimate** frame observed
in the corpus has `total_len` = **1,622 bytes** — a **1,570-byte body** of packed
`TLV(name)+value` records plus the 13-byte header and the NUL-terminated routing slots. (A raw census
maximum of 65,536 B is a stream-desynchronization artifact, not a real frame.) Large multi-record
read/trend responses arrive as one large frame, not as a 256-byte-segmented exchange. [W]

**The sender's ceiling, and the two reserved bytes.** The supervisor's AP2 codec
allocates a **16,384-byte** segment buffer and hands its encoder `buf+2` with a
capacity of **16,382 bytes**. The two bytes it holds back at `buf[0]` are the
`u16` function code, written after the body is encoded — which is exactly why the
wire carries the opcode immediately before the body, and why `total_length`
counts it. An implementer reading a body is reading the encoder's `buf+2`. [S]

**Reassembly is a cursor against a declared total**, not a negotiation. Each
mapped segment copies `n` bytes into the buffer and advances the cursor; the
final segment's length is `total - cursor`. The sender knows `total` before it
begins, and the command object carries an explicit more-follows field, set on the
segmenting path and cleared on the direct one. [S]

**The ceiling is not exercised by anything we have captured.** No body in the
corpus exceeds 16,382 B: the largest complete body is 1,570 B and the largest
*declared* body is the 12,073-byte replication data store of §9.5. So a client
may size a receive buffer at 16 KB with confidence for this implementation, but
the on-wire form of a **multi-segment** exchange — whether it appears as two P2
frames and what marks the continuation — remains unobserved (§4.5). [W][S]

**The observed continuation mechanism for `UPL_ALL_*` is application-layer cursoring, not a
frame-level more-follows flag.** Bulk enumerations (`UPL_ALL_POINT 0x0981`, `UPL_ALL_TEC 0x0986`,
`UPL_ALL_EQS_CMD_TABLE 0x0988`, …) are **paginated by request**: each request carries the
last-returned object's name as a **cursor** (a `TLV(name)` after the application-number TLV), and the
response returns the next object's record. To walk a list the client re-issues the opcode with the
previous response's object name until the panel returns end-of-list. A controller with a long point
list (e.g. an AHU returning consecutive ~1514-byte records) is walked the same way — each response is
one near-MTU frame and the **next** record is fetched by cursor, not by a continuation bit. Across
every `UPL_ALL_*` capture the panel kept each response to a single frame (frame ≤ 1,622 B) and the client
advanced by cursor; the data-channel more-follows flag was **not observed firing**. [W] The codec
*has* a more-follows mechanism [S] and the `EBLN_REPL_*` replication bodies use explicit segment
cursors (above), but for ordinary `0x33`/`0x34` reads the on-wire pattern is cursored request/response
pagination capped near one MTU.

**[OPEN]** Whether a single object whose record exceeds the largest observed
frame triggers the codec's frame-level more-follows flag (and at what byte) is
still unpinned — no single record that large was captured; every large result
was continued by cursor instead. [S][OPEN]

**Do not read the Ethernet MTU as the boundary.** A P2 frame is not capped near
1,514 bytes: **128 frames in the corpus exceed it**, running to 1,622, in both
dialects and across five captures, each one arithmetically exact
(`13 + slots + body = total_len`). 122 of the 128 are responses and 6 are
`0x4636` replication requests. So a P2 frame routinely spans more than one
Ethernet segment and a receiver *must* reassemble across TCP segment boundaries
(§6.1.1) — the MTU is a property of the link, not a protocol limit, and the
pagination described above is a *cursor* convention rather than a size ceiling
the codec enforces. [W]

P2 segmentation is **distinct** from the BACnet-side Transport Segment Management (TSML) layer
(High/Low halves, per-TSM `invokeID`/`userID`, `ReqACK`, out-of-order `expected/received`
reassembly) that rides over the BACnet IPC connection. TSML is a different stack and is out of scope
for the P2 wire. [S]

---

### 6.8 The byte-oriented P2 encoding (non-TCP links)

Everything in §6 so far describes P2 as it rides TCP. A controller also speaks P2
over a byte-oriented link, and it is **not the same encoding** — same protocol,
same operations, a far more compact frame. This is recovered from controller
firmware, not from a capture: the corpus is entirely TCP/5033. [F]

```
  offset  size  field
  ------  ----  ---------------------------------------------------------
     0     1    node address  -- checked against the receiver's own id
     1     1    [OPEN]
     2     1    [OPEN]
     3     1    group         -- selects a translation table (§9.4.1)
     4     2    ordinal (u16) -- the operation within that group
     6   ...    arguments

  total <= 253 bytes; payload after the 4-byte header <= 249 (0xF9),
  enforced -- an over-length route is rejected with error 2.
```

Two things identify this as P2 rather than P1 or an internal bus. First, the
receiver's rule for a message whose address byte is **not** its own id: it does
not interpret the message, it wraps the raw four header bytes and the payload
verbatim and raises it as operation **`0x0136`**, whose name in the function-code
enumeration is **`AP2_P2_ROUTE`**. Second, the encode path is byte-for-byte
symmetric — given `0x0136` it restores the same four header bytes and payload and
puts them back on the link. A multi-drop link forwarding P2 between nodes. [F][S]

The operation is encoded as `(group, ordinal)` rather than as the 16-bit AP2
function code, and §9.4.1 gives the tables that translate between the two, in
both directions. The ordinal's width is fixed by the firmware's 2-byte read
primitive and independently by group `0xE0`, whose ordinals run 256–259 and could
not fit in a byte. **The ordinal is big-endian**, and the group byte precedes it
directly. [C]

**The pairing is attested from both ends.** Everything above is the panel's side.
A supervisor-side codec builds the same encoding, and for group `0xE0` it emits
ordinals 256, 257, 258 and 259 — the same four the panel's `0xE0` table holds,
plus a fifth, 260, that this panel generation does not implement. Two
independent implementations for two different processors agreeing on four exact
values in a 16-bit space is what makes the group/ordinal reading safe to build
on. [C][F] The same codec shows that not every leading byte is a group selector:
some classes are followed by an ordinal, others by a fixed addressing prefix of
their own, so a decoder must switch on the class byte before assuming an ordinal
follows it. [C]

Set against the TCP framing of §6.1 — `u32 total_len | u32 msg_type | u32 seq |
u8 dir | four NUL-terminated slots | u16 opcode` — the difference is stark: one
address byte where TCP carries four variable-length name slots, and a
group+ordinal pair where TCP carries the function code. **An implementer should
not assume one P2 parser handles both.**

**Which serial link is [OPEN].** Two carry P2 outside the TCP framing — the
dedicated RS-485 BLN and the dial-up path. A one-byte node address with
multi-drop forwarding fits the RS-485 BLN, but nothing observed excludes the
modem path, and both may use this same encoding.

**And the framing beneath it is [OPEN].** The firmware receives the four header
bytes already parsed into fields, so start/sync delimiting and any CRC are
stripped by a lower layer this code does not contain.

**Two layers above the wire have been checked and neither adds the three bytes
that precede the group selector.** The supervisor's protocol adapter builds the
request object, points it at a 600-byte buffer, calls the encoder — which writes
the group byte at offset 0 — and hands *that same buffer and the encoder's own
length* to the transmit call, with nothing prepended. The link component beneath
it is a transport: ports, partners, sequence numbers, a socket path and a modem
path, and no P2 header assembly. [C] So on the supervisor's send path a message
begins at the group byte, and the `node | ? | ?` prefix is either added below
both of them or is not present on that path at all.

That second possibility is worth stating because it is testable and would
explain the shape: the panel-side header is described by code that **forwards a
message whose address byte is not its own** (`0x0136`), which is a routing
concern. A directly-addressed message may simply not carry it. This document
does not choose between the two — it records that the two layers where the
prefix would most naturally be added do not add it. [C][OPEN]

> **A note on the ~256-byte figure.** §6.7 records, correctly, that the ~256-byte
> number in vendor connection-test material is a *ping* size and not a maximum
> P2 data-packet cap — TCP frames run to 1,622 bytes. That stands. But a
> **253-byte cap, enforced in code**, now exists on this link, and the proximity
> is suggestive: the vendor figure may describe this encoding's frame limit
> rather than anything about TCP. Offered as a plausible origin, not a
> demonstrated one. [I]

## 7. Service Model & Message Types

### 7.1 The ASDU service model

P2 is an ISO/OSI-style application protocol. The vendor codec frames every transaction as a service
primitive carrying an **ASDU** (Application Service Data Unit) as its payload, with the classic
four-primitive shape: **Request → Indication** on the originator/receiver pair, and **Response →
Confirm** on the reply path. [S] The 2-byte wire opcode is the **AP2 function code** (a 16-bit
word); a management station may use a different internal command index for the same operation, but
the **wire** carries the AP2 function code only. [S]

The model has two transaction shapes, which map directly onto the direction byte (§6.3):

| Shape | Wire pattern | Direction bytes | Tag |
|---|---|---|---|
| **Confirmed** (request → response) | client sends opcode + body (`dir 0x00`); peer replies with success body (`dir 0x01`) or error tail (`dir 0x05`), same `sequence` | `0x00` → `0x01`/`0x05` | [W][S] |
| **Event** (async indication) | originator pushes opcode + body (`dir 0x00`) on its own initiative; peer acknowledges with an empty success (`dir 0x01`) | `0x00` → `0x01` | [W][S] |

The stack-selector layer's read primitives confirm the split: `ReadConfirmedInd` (confirmed
request/response) versus `ReadEventInd` (asynchronous event indication). [S] The dominant Event-class
transaction is the change-of-value push `0x0274` (`COV_ANNUNCIATE`): 120,764 request frames in the corpus under the criteria of §9.5 —
almost all acknowledged with a 0-byte success, a small minority unanswered. [W] COV itself is a
register/cancel **subscription** — a peer arms COV with `COV_ENABLE` (`0x0271`) / disarms with
`COV_DISABLE` (`0x0273`), after which the panel emits `COV_ANNUNCIATE` events. [W][S] The
session/heartbeat opcode `0x4640` (`EBLN_PING`) is a Confirmed transaction reused as the
~10-second in-session keepalive (its ASDU body is a single `eBLN_Node` element). [W][S]

A second corroboration of the Confirmed model: bulk database transfer (the upload / `UPL_ALL_*` and
`DBCHANGE` families) proceeds **record-by-record**, each record drawing its own success-or-fault
reply. This per-record success/fault pattern is the Confirmed request/response loop applied
iteratively, and it is what the per-record `dir == 0x01` / `dir == 0x05` outcomes in upload captures
show. [W][S]

### 7.2 Success vs error responses

A response correlates to its request solely by the echoed `sequence` (§6.5) and never carries an
opcode (§6.4).

- **Success (`dir == 0x01`).** Carries a result body that may be empty. Many command/acknowledge
  operations reply with a 0-byte success (the corpus shows `ok:0B` for `0x0240` `POINT_CMD_VALUE`,
  `0x0273` `COV_DISABLE`, `0x4634` replication, and others). Read/enumerate
  operations reply with a sized body whose length varies with the embedded name/value TLVs and
  firmware. [W]
- **Error (`dir == 0x05`).** Carries **exactly two bytes**: a big-endian u16 error code, and nothing
  else. The error frame is the panel's application-layer rejection path; it is distinct from a TCP
  RST/FIN (transport-layer wrong-BLN rejection) and from a "no response at all" (the V2-class DoS
  signature, where the trigger draws neither an error nor a success before the panel's TCP stack
  goes silent). [W]

  *Worked error example.* A `TREND_DATA_DISPLAY` (`0x0295`) request naming a point that has no trend
  log returns `dir == 0x05` with the 2-byte tail `0x0003` ("not found", §7.2.2) — the same
  not-found code returned for any named object that does not exist. [W]

  *The whole error vocabulary the corpus exercises.* Pairing all **6,006** error responses back to
  their request by sequence gives seven codes and no unknowns — every one is already named in the
  error table of §7.2.2, which is the first time that table has been checked against traffic rather
  than against the type system: [W]

  | Code | Name | Count | % | Chiefly answering |
  |---|---|---:|---:|---|
  | `0x0003` | `not_found` | 5,805 | 96.7% | `0x0220`, `0x0271`, `0x0273`, `0x0295`, `0x0272`, `0x0986` |
  | `0x00AC` | `not_supported` | 127 | 2.1% | `0x400F`, `0x4133`, `0x4010`, `0x4011`, `0x09BB`, `0x4500` |
  | `0x0E15` | `physical_point_not_commandable` | 38 | 0.6% | `0x0240` |
  | `0x0002` | `invalid_command` | 28 | 0.5% | `0x0244`, `0x0247`, `0x0564`, `0x0565` |
  | `0x0E11` | `fln_invalid_drop_number` | 4 | 0.1% | `0x0204` |
  | `0x0E12` | `fln_device_failed` | 3 | 0.0% | `0x4225`, `0x4224` |
  | `0x0009` | `already_exists` | 1 | 0.0% | `0x0540` |

  These sum to 6,006, the whole `dir == 0x05` population. **97% of all errors are
  `not_found`**, and exactly one error response in the corpus cannot be paired
  back to its request. Three operations in the corpus **never** succeed —
  `0x0272 COV_DELETE_STUB` (0 ok / 46 err), `0x400F TEAM_DESC_UPLOAD` (0/12) and
  `0x5354 HOA_MAP_LOOK` (0/6) — and `0x0220 POINT_LOG_VALUE` fails more often than it succeeds
  (1,910 ok / 2,415 err), which reflects how a supervisor walks point space rather than anything
  about the opcode. An implementer sizing retry logic should not read a high error rate on
  `0x0220` as a fault. [W]

**Reliability and acknowledgment.** P2 runs over TCP and relies on TCP for in-order delivery and
retransmission; there is **no application-layer retransmit** and **no separate app-layer ACK frame**.
On a busy link ~1.2% of frames are TCP retransmissions — handled entirely by the transport, invisible
to the P2 codec. [W] The application-level acknowledgment of a request *is* its `dir == 0x01` success
(or `dir == 0x05` error) response, matched to the request by the **echoed `sequence`** (§6.5). A
peer that needs to know a request was received and acted on waits for that sequence-matched response;
nothing else on the wire confirms receipt. [W]

**Measured round-trip latency.** Median application round-trip (request `dir == 0x00` → matched
response `dir == 0x01`/`0x05`, by echoed `sequence`) on a busy live link, with p95 < ~2× the median and
up to 14 requests pipelined outstanding (§6.5):

| Opcode | Operation | Median RTT | Tag |
|---|---|---|---|
| `0x4640` | `EBLN_PING` (heartbeat/identity) | ≈ 6 ms | [W] |
| `0x0274` | `COV_ANNUNCIATE` (value push ack) | ≈ 6 ms | [W] |
| `0x0271` / `0x0273` | `COV_ENABLE` / `COV_DISABLE` | ≈ 10–12 ms | [W] |
| `0x0240` | `POINT_CMD_VALUE` (write) | ≈ 18 ms | [W] |
| `0x0220` | `POINT_LOG_VALUE` (read) | ≈ 25 ms | [W] |
| `0x0295` | `TREND_DATA_DISPLAY` (trend retrieval) | ≈ 53 ms | [W] |

These figures are deployment- and link-dependent; they are illustrative of **relative** cost, not
absolute guarantees. The ordering is the durable observation: pings and COV are cheap, point read/write
are mid-cost, and trend retrieval is the slowest by an order of magnitude over pings. [W]

#### 7.2.1 Error classes (vendor AP2 error taxonomy)

The vendor codec defines a fixed set of AP2 error classes (C++ RTTI types in the codec, mirrored as
named members in the managed type system). These are the definitional error categories; the wire
carries a numeric code (§7.2.2) that maps onto them. [S]

| Error class | Meaning | Tag |
|---|---|---|
| not supported | The opcode / function code is not supported (or not permitted) in context. | [S] |
| `AP2BadTagValue` | A TLV tag/value in the request body is malformed or out of range. | [S] |
| `AP2BadPacketLength` | The declared/observed packet length is inconsistent with the parsed body. | [S] |
| `AP2BadNoOfElements` | An element-count field in the body does not match the elements present. | [S] |
| `AP2EncodeOverflow` | The response would overflow the encode buffer. | [S] |
| `AP2BufferTextOverflow` | A text/string field would overflow its buffer. | [S] |
| `AP2Error` | Base/generic AP2 error. | [S] |
| `AP2MappingError` | An AP2↔CPI function-code mapping failure. | [S] |

#### 7.2.1a Nothing retries a failed request

There is **no retry behaviour** in the observed clients. A first look suggested
the opposite — of 6,005 error responses paired to their requests, **5,522 are
followed by the same opcode on the same connection, at a median of 0.02 s** —
but that test cannot tell a retry from the next request in a poll cycle, and
`POINT_LOG_VALUE` is issued constantly.

The control settles it. Measuring how long until the **identical** request
recurs — same opcode *and* same body length — split by whether the answer was an
error or a success: [W]

| Opcode | recurs after **error** | after **success** |
|---|---:|---:|
| `0x0220 POINT_LOG_VALUE` | 0.42 s (n=2,570) | **0.01 s** (n=4,001) |
| `0x0271 COV_ENABLE` | 0.68 s (n=1,319) | **0.10 s** (n=5,120) |
| `0x0240 POINT_CMD_VALUE` | 4.36 s (n=29) | **0.43 s** (n=32,371) |
| `0x0986 UPL_ALL_TEC` | 2.58 s (n=29) | **0.00 s** (n=902) |

A retried request would recur **faster** after a failure. It recurs *slower* —
42× slower for `POINT_LOG_VALUE`. So a client that receives an error moves on,
and the request reappears only when its normal cycle comes round again.

Two consequences for an implementer. A panel **must not** rely on a client
re-asking; an error is final for that exchange. And a client gains nothing by
implementing retry against these panels' behaviour — if a name is `not_found` it
will still be `not_found`, which is what 97% of these errors are (§7.2.2).

**Scope.** Every client in this corpus is the same supervisor product, so this
characterises *that implementation*, not a protocol requirement. Nothing in the
wire format forbids a retry; nothing here performs one. [W]

#### 7.2.2 Observed wire error codes

These 2-byte codes appear as the `dir == 0x05` error tail in the corpus. Distribution across the
621,268 trusted P2 frames, of which 6,006 are error responses: `0x0003` 5,805; `0x00AC` 127;
`0x0E15` 38; `0x0002` 28; `0x0E11` 4; `0x0E12` 3; `0x0009` 1 - summing exactly to 6,006. **`not_found` is 97% of all errors.** [W]

| Wire code | Meaning | How established | Tag |
|---|---|---|---|
| `0x0003` | **not found** — the named object does not exist on the panel (also returned for an unrecognized-opcode probe) | wire behaviour and the vendor error catalog agree | [W][D] |
| `0x00AC` | **not supported** — the function code is unused on this panel, **or is specific to a different firmware revision** | wire behaviour and the vendor catalog agree, **and the revision case is now firmware-attested** — see below | [W][D][F] |
| `0x0002` | **invalid command** — the command is not valid for the addressed object (seen on `POINT_CMD_ALARM 0x0244` and on `CMD_ALARM_DISABLE 0x0247` addressed to a point name that does not exist; the documented example is commanding a non-virtual LDI or LAI point). **Also returned for an over-length `0x0136 P2_ROUTE`**, see below | wire behaviour and the vendor catalog agree, plus firmware | [W][D][F] |
| `0x0009` | **already exists** — a define collided with a record already present | vendor catalog; the single wire observation answers `0x0540` | [D][W] |
| `0x0E11` | **FLN: invalid drop number** — the addressed FLN device's drop number is invalid (seen answering `POINT_ADD_LAI 0x0204`) | vendor catalog | [D][W] |
| `0x0E12` | **FLN: device failed** | vendor catalog | [D][W] |
| `0x0E15` | **physical point not commandable** — the point cannot process commands (seen on `POINT_CMD_VALUE`) | wire behaviour and the vendor catalog agree | [W][D] |

**Where `0x00AC` comes from, read off the panel.** A controller does not hold
one opcode table. It holds **at least eight**, each a list of
`{u16 internal_code, u16 ap2_opcode}` records with its own count, and it picks
between them at dispatch time on a per-peer selector value. An incoming opcode
is matched against the **second** field of each record; when the selected table
has no matching entry, the panel writes `0x00AC` into the response and stops.
So "not supported" is not a single global judgement about the function code —
**it is the answer from one particular translation table**, which is exactly why
the same opcode can be refused by one panel and answered by another. The
revision reading of this error was documentary until now; it is the structure
the firmware actually implements. [F]

The same function special-cases `0x0136 AP2_P2_ROUTE` ahead of any table lookup
and enforces its length bound inline — payload ≤ 249 bytes, total ≤ 253 (§6.8) —
writing **`0x0002`** if the frame exceeds it. [F]

**`0x0E10`–`0x0E17` is the FLN error band.** Every code in it reports a fault in
the field-level network, the device, or the physical point — invalid FLN number,
invalid drop number, device failed, invalid point number, physical point failed,
not commandable, value out of range, application invalid for device. A client
should read any `0x0Exx` tail as *field-level*, not as a record-state rejection.
[D]

**A correction, recorded because the wrong reading shipped.** The error table in
earlier editions of this document and in the released tools was wrong in **26 of
its 42 entries**, and almost all of it was a single defect: the list was
**shifted by one entry** against the vendor's catalog, from `0x0007` through
`0x0210` and again across the FLN band, so each code carried the name belonging
to the next code up. The `_v2` suffixes the old table used
(`already_exists_v2`, `value_out_of_range_v2`) are the tell -- the duplicate
names the shift produced were suffixed rather than investigated. Among the
consequences: `0x0009` was unnamed when it is *already exists*, `0x0E11` was
named *already exists* when it is an invalid FLN drop number, `0x0E12` was
*invalid point number* when that is `0x0E13`, and `0x000B`/`0x000C` had *value
out of range* one code early. One consequence was behavioural rather than
cosmetic: the released scanner treated `0x0E11` as a **success**, so a failed
FLN point-add was reported as having worked. The whole table is regenerated and
fixed in the tools and here. [D]

**The full catalog.**

Seven codes is what this corpus produced; it is not what a panel can return. The
complete set is **42 codes**, and a decoder needs all of them — a code this site
never elicited is not a rare code, it is a code for a condition this site never
hit. The `E`-number column is the vendor's own label for each error and is simply
the decimal of the code, which is worth knowing because vendor material and panel
displays cite errors that way (`E172`, not `0x00AC`). [D]

| Code | `E`-number | Name | Seen here |
|---|---:|---|---:|
| `0x0001` | E1 | `no_memory_available` | — |
| `0x0002` | E2 | `invalid_command` | **28** |
| `0x0003` | E3 | `not_found` | **5,805** |
| `0x0004` | E4 | `priority_too_low` | — |
| `0x0005` | E5 | `no_change` | — |
| `0x0007` | E7 | `point_failed` | — |
| `0x0008` | E8 | `out_of_service` | — |
| `0x0009` | E9 | `already_exists` | **1** |
| `0x000A` | E10 | `trend_already_exists` | — |
| `0x000B` | E11 | `value_unchanged` | — |
| `0x000C` | E12 | `value_out_of_range` | — |
| `0x000D` | E13 | `not_hostcaller_node` | — |
| `0x0016` | E22 | `line_not_traced` | — |
| `0x0028` | E40 | `invalid_dst_pair` | — |
| `0x0040` | E64 | `invalid_report_id` | — |
| `0x0065` | E101 | `command_not_supported` | — |
| `0x0080` | E128 | `invalid_user_id` | — |
| `0x0081` | E129 | `invalid_password` | — |
| `0x0082` | E130 | `user_accounts_database_full` | — |
| `0x00AB` | E171 | `coldstart_required` | — |
| `0x00AC` | E172 | `not_supported` | **127** |
| `0x00B7` | E183 | `too_many_framing_errors` | — |
| `0x00B8` | E184 | `scu_no_answer` | — |
| `0x00F9` | E249 | `invalid_point_address` | — |
| `0x00FA` | E250 | `failed_io_device` | — |
| `0x00FE` | E254 | `io_timeout` | — |
| `0x0200` | E512 | `monitor_list_full` | — |
| `0x0202` | E514 | `flt_transfer_in_progress` | — |
| `0x0203` | E515 | `flt_transfer_killed` | — |
| `0x0205` | E517 | `tec_not_added` | — |
| `0x0206` | E518 | `connection_lost` | — |
| `0x0207` | E519 | `warm_started` | — |
| `0x0209` | E521 | `protocol_error` | — |
| `0x0210` | E528 | `timeout` | — |
| `0x0E10` | E3600 | `fln_invalid_fln_number` | — |
| `0x0E11` | E3601 | `fln_invalid_drop_number` | **4** |
| `0x0E12` | E3602 | `fln_device_failed` | **3** |
| `0x0E13` | E3603 | `fln_invalid_point_number` | — |
| `0x0E14` | E3604 | `fln_physical_point_failed` | — |
| `0x0E15` | E3605 | `physical_point_not_commandable` | **38** |
| `0x0E16` | E3606 | `fln_value_out_of_range` | — |
| `0x0E17` | E3607 | `fln_application_invalid_for_device` | — |

Three properties an implementer should read off it. The catalog is **sparse and
irregular** — 42 codes over a range of 3,600 — so a decoder must use a lookup and
not an array index. The **bands are meaningful**: `0x0001`–`0x0210` are panel and
record errors, `0x0080`–`0x0082` are the user-account band, and `0x0E10`–`0x0E17`
is the FLN band described below. And **the observed distribution is nothing like
the catalog** — one code is 97% of every error this corpus contains, while 35 of
the 42 never appeared at all. A decoder tested only against a capture is a
decoder tested against one row. [W][D]

**On the code↔AP2 error class pairing, which an earlier edition left open.** The
question was whether the type system's per-operation `*_Error_enum` types define
a second, per-operation error namespace that would have to be mapped onto the
wire codes. **They do not, and there are far fewer of them than the question
assumed** — 16 in the whole type system, fifteen of those RACS partner and port
operations. Where they carry a value it is the *same* value the global catalog
uses:

| `*_Error_enum` member | value | the global code it is |
|---|---:|---|
| `invalid_partner_number` | 2 | `0x0002` `invalid_command` |
| `partner_not_found` (11 enums) | 3 | `0x0003` `not_found` |
| `partner_already_here` | 9 | `0x0009` `already_exists` |

So a per-operation error enum is a **named subset** — it says which of the global
codes that operation can return, and gives each a name in that operation's terms.
There is no translation to perform. [S]

Two members do not fit, and are reported rather than smoothed over:
`no_ram_available` / `no_ram` = **0** in the two RACS partner add/modify enums,
and `port_not_found` = **0** in the three RACS port enums. The global catalog
defines no code 0 — its memory error is `0x0001` and its not-found is `0x0003`.
Both are the first-declared member of their enum, which would suggest a generator
default, except that `AP2_Racs_Partner_Delete_Error_enum` has exactly one member
and it is `partner_not_found` = 3, so the first member is not auto-zeroed. Either
0 is a real code the catalog omits, or those five enums number from a different
base. That is a narrow open item: it affects five RACS operations and no code
this corpus has seen. [S][OPEN]

#### 7.2.3 Implementation guidance

A parser MUST inspect `dir` before interpreting any post-slot bytes. An error tail and a value block
can both begin `00 03`: read as a value block, `0x0003` ("not found") would fabricate a phantom value
where the peer actually reported an error. [W] A robust client treats `dir == 0x05` as an
application-layer "operation failed with code N," distinct from transport-level RST/FIN (connection
rejected/closed) and from silence (no reply). A 0-byte `dir == 0x01` is a positive acknowledgement,
not an empty/failed result — and it is the **majority** shape, not an edge case:
of 300,985 success responses paired to their requests, **169,462 (56.3%) carry a
zero-length body**. [W]

**But emptiness is a property of the exchange, not of the opcode**, and a client
must not key on it. Some opcodes always ack empty — `0x0274 COV_ANNUNCIATE`
(120,749 of 120,749), `0x0273 COV_DISABLE`, `0x4636`, `0x4635`, `0x0508`,
`0x4633`. Others always return a body — `0x4640 EBLN_PING`, `0x0981
UPL_ALL_POINT`, `0x0271 COV_ENABLE`, `0x0220 POINT_LOG_VALUE`. And at least two
do **both**: `0x0240 POINT_CMD_VALUE` answers empty 32,451 times and with a body
30 times (a `Name_response` — the point's name and suffix echoed back), and
`0x4634` answers empty 10,003 times and with a `u32` 13 times (§5.3). Read the
length; do not infer it. [W]

### 7.3a The stack's service primitives

Beneath the opcode catalog the P2 stack presents a small, named set of service
primitives. They are worth stating because they explain *why* the opcode
families are shaped as they are: [S]

| Primitive | Role |
|---|---|
| `Request` / `Response` | the ordinary confirmed exchange of §7.1 |
| `ReturnData` | the data-bearing half of a response, separable from its status |
| `ReadConfirmedInd` | a confirmed indication delivered to the application |
| `ReadEventInd` | an **unconfirmed** event indication — the COV/alarm path of §12 and §13 |
| `GetFirst` / `GetNext` / `CancelGetNext` | the enumeration cursor |
| `NetMgrRequest` | network-management request, distinct from ordinary data |
| `SourceData` | the originating-side data path |

The **`GetFirst` / `GetNext` / `CancelGetNext` triple is the same cursor idiom**
§7.2's continuation discussion describes at the application layer: enumeration
is a stack-level concept, not a per-opcode convention, which is why the
`UPL_ALL_*` family and the browse families all cursor the same way. The third
member matters to an implementer and is easy to miss — **a cursor can be
abandoned explicitly.** A client that walks half an enumeration and disconnects
leaves the server holding cursor state that a `CancelGetNext` would have
released.

The stack selector also enumerates the transports the same service layer can
sit on — Protocol II, Ethernet, Profibus, a remote link, and an "other"
catch-all — which is the layering §2 describes, from the implementation's own
side. [S]

### 7.3 Connection and session model

P2 runs over TCP with a **role-asymmetric, multi-connection** topology. A field panel listens for P2
on **TCP/5033** (§4.1); a supervisor listens on its own P2 port(s) for node-originated traffic — in
the observed Desigo deployment the supervisor listens on **TCP/5034** for panel push/value traffic and
also accepts node announcements there (§4.1, §2.1.2). Exact supervisor port assignment is
deployment-specific, but the two-listener / two-connection pattern below is the model. [W]

**Two connections per node-pair.** Each side opens a TCP connection to the *other* side's listener, so
a communicating pair maintains at least **two** long-lived TCP connections, one per direction:

- supervisor → panel:5033 — the supervisor's poll/command channel.
- panel → supervisor:listener — the panel's announcement + COV/value-push channel.

The message classes a given pair uses are fixed by the **panel's firmware generation**, not by which
of these two connections a frame rides: a legacy panel uses `0x33` data + `0x2E` second-channel in
both directions, a modern panel uses `0x34` + `0x2F` (§6.2/§6.6). The second channel (`0x2E`/`0x2F`)
is where the panel's announce/identity and DB-change/replication records flow toward the supervisor.

These connections are long-lived; reconnects (panel reboot, link flap, supervisor restart) add further
connections over the life of a capture. [W]

**How long-lived, measured.** In the 16.7-hour capture, **24 sessions carry
substantive traffic and all 24 run the entire capture** — every one opens within
**0.1 minutes** of the start, every one is still open at the end, and all 24 are
open *simultaneously* at the midpoint. There is not a single reconnect. The
steady state is a permanently-established mesh, so a client should open its
connections once and keep them. [W]

**Size a panel from the per-listener figure, not this one.** The 24 above is the
whole capture — every session between every pair of nodes — and sizing a
listener from it would be the wrong denominator. What one panel actually holds
is measured in §3.9: a peak of **9 concurrent peers on 18 sockets**, which in
those captures is every other node on the BLN at once. Expect roughly two
sockets per peer, and expect them to stay open. [W]

> **A trap worth naming, because it produced a phantom finding.** Dividing a
> capture's connection count by its duration does *not* give a reconnect rate —
> 24 connections over 16.7 hours reads as "a new connection every 42 minutes"
> and is completely wrong when the 24 are concurrent and permanent. Check
> whether sessions overlap before treating their count as a rate. The same
> capture also shows 2,393 single-frame tuples against those 36 real sessions,
> so a raw tuple count is not a session count either.

#### 7.3.1 Session establishment, in order

Everything below is stated elsewhere in this document; what was missing is the
*order*, and a responder cannot be written from facts scattered across five
sections. This is the whole sequence, from TCP connect to steady state. [W][S]

1. **Connect.** Open TCP to the peer's listener — `5033` for a field panel
   (§4.1). A supervisor's listener is deployment-specific (§2.1.2); do not infer
   it from a `|PORT` identity suffix (§6.4).

2. **Send `0x4640` (`EBLN_PING` / IdentifyBlock) as the first frame.** There is
   no separate handshake opcode: establishment *is* this exchange (§6.2). Frame
   it on the **second-channel** class matching the peer's generation — `0x2E`
   legacy, `0x2F` modern (§6.6) — with `dir = 0x00`, slots `[0]` and `[2]` both
   the BLN name, `[1]` the destination node name, `[3]` your own identity. The
   body is the `eBLN_Node` block of §10.6: three name TLVs then exactly 16 bytes.

3. **The BLN name is the gate, and it is checked before anything else.** A
   wrong BLN name draws a **TCP RST** from a panel or a graceful **FIN** from a
   supervisor listener, before any application processing and with no node-table
   side effect (§17.2). Nothing else in the frame is examined — not the
   identity, not the body.

4. **A correct BLN name is admitted, and the reply tells you which kind of
   peer you are.** A `slot[3]` identity already in the receiver's peer list draws
   a short (~48-byte) second-channel response — effectively a peer offer back.
   A novel identity draws the longer data-dialect response *and writes a
   Permanent node-table entry at your IP* (§5.3.3, §6.2). Registration is gated
   by BLN-correctness, not by being served data: the data-service identity check
   is a separate, later gate.

5. **Learn the peer's generation once, then stop guessing.** Issue
   `CABINET_DISPLAY` (`0x010C`, §10.5) and classify from the returned revision.
   That one read fixes both the dialect to frame in and how names are encoded
   for that peer, permanently (§6.6). Do not blind-probe `{0x33, 0x34}`.

   > You do **not** need to decode the whole block to do this. `revstring` is
   > **field 1** — the first `TEXT_` TLV in the body — so the generation is
   > three bytes and a string into the response. §10.9 lists this response as
   > not fully decodable, which is true of the other fifty fields and
   > irrelevant here.

6. **Hold the connection and keep it alive.** Re-send `0x4640` every **10.0 s**
   (§5.1). Sessions here are permanent: 24 of 24 substantive sessions ran an
   entire 16.7-hour capture with no reconnect (§7.3). Open once and keep it.

7. **Expect the reverse connection.** The pair is two connections, one per
   direction (§7.3), so a conformant node also *listens* and repeats steps 3–4 as
   the receiver.

**Role asymmetry is real and will bite a symmetric implementation.** A
panel-initiated `EBLN_PING` into a supervisor's `5033` may be accepted at TCP
and answered with **zero payload bytes and a FIN** while that same supervisor
answers its own outbound pings on 10.0 s — 984 such connections in 25 minutes at
one observed supervisor (§5.1). Do not treat "the TCP connection was accepted"
as "the session was established"; the establishment signal is the `0x4640`
*reply*.

#### 7.3.2 Response timing, measured

Across **306,990 paired request/response exchanges** — every request matched to
the response echoing its `sequence` on the reverse direction of the same
connection: [W]

| | |
|---|---:|
| median latency | **6.5 ms** |
| p90 | 21.8 ms |
| p99 | 161.6 ms |
| maximum | 8.78 s |
| requests with no response | **41 (0.01%)** |

**A P2 request is essentially always answered.** Forty-one unanswered out of
307,031 is the entire corpus-wide total, and that figure only becomes meaningful
after excluding connections whose *reverse direction was never captured* — those
contribute 7,224 requests whose replies the tap could not have seen. Counting
them produces "2% unanswered", which measures the vantage and not the panel.
Restricted to `EBLN_PING` on connections with both directions visible and 20 or
more pings, **268 of 274 connections have zero unanswered**, and the six that do
have exactly one each, in a capture taken across a deliberate power cycle.

**Reaching through to an FLN device costs about 40× a panel-local read**, and a
client must size its expectations accordingly: [W]

| Operation | Median | n |
|---|---:|---:|
| `0x4640 EBLN_PING` | 6.0 ms | 101,294 |
| `0x0981 UPL_ALL_POINT` | 10.5 ms | 12,545 |
| `0x0220 POINT_LOG_VALUE` | 10.9 ms | 6,935 |
| `0x0986 UPL_ALL_TEC` — the panel's **stored** TEC record | 15.7 ms | 1,047 |
| `0x4200 TEC_LOG` | 33.8 ms | 248 |
| **`0x4221 TEC_REMOTE_INIT_VALUE_LOG`** — the value **from the device** | **674.7 ms** | 1,173 |

The `LOCAL` / `REMOTE` distinction in the `0x422x` names is exactly this: local
reads the panel's copy, remote crosses the field bus. The remote form's p99 is
3.7 s, which sits well inside the 30-second `ClientTrnxTimeout` of §4.6 — so a
client should not treat a multi-second reply to an FLN-crossing opcode as a
fault, and should not apply one timeout to every opcode.

**The BLN is a full peer mesh.** Every node holds live P2 sessions with the supervisor **and** with
every other node on the BLN — panel↔panel sessions run over `panel:5033` just like the supervisor's
poll channel (carried by the `0x29`/`0x2A` peer-session band, §6.2). This realizes the self-organizing
logical BLN of §5.3 at the connection layer. Inter-panel traffic is **only visible at a panel's own
switch port**, never from the supervisor's vantage — a capture taken at the supervisor sees
supervisor↔panel traffic but none of the panel↔panel mesh. [W]

**Connection establishment (observed at SYN level).** A panel-side switch-port mirror captures the
TCP handshakes directly: panels open connections **to port 5033** — both to the supervisor
(`panel → supervisor:5033`) and to each other (`panel → peer-panel:5033`) — and the listener answers
with SYN-ACK. In one mirror window a single panel dialed five different peer panels' `:5033` plus the
supervisor, and other panels dialed back to it, in waves (initial connect, then reconnects). This is
the peer mesh forming at the transport layer. The supervisor's own outbound connections to panels are
**off-vantage** in a supervisor-side capture (it is the SYN-ACK side there), so "who initiates" is only
directly observable for the connections that cross the mirrored port; what is established is that every
panel both **listens on 5033** and **dials 5033** on its peers. [W] A reconnecting node does **not**
reset its `sequence` — the first frame on a freshly-opened TCP connection continues the node's prior
high sequence value for that channel (§6.5). The first application traffic on a fresh data path
depends on the channel role: on a supervisor→panel poll channel (TCP/5033) to a legacy panel it is a
periodic database-change poll (`0x0959`/`DBCHANGE` family) at a ~5-second cadence; on a panel→supervisor
push channel (e.g. TCP/5034) it is typically a COV push/enable (`0x0274`/`0x0271`). The constant across
all fresh streams is the `0x4640` (`EBLN_PING`) identity exchange. There is **no dedicated P2 "connect
handshake" opcode** — the TCP handshake plus the message-class context (§6.2) is the session. [W]

```
                       supervisor "SUP"  (192.0.2.10)
                       listener: TCP/5034
                          ▲              │
        panel→SUP push    │              │  SUP→panel:5033 poll/command
        (announce/COV)    │              ▼
                    ┌─────┴──────┐  ┌────────────┐
                    │   NODE1    │  │   NODE2    │
                    │ (192.0.2.21)│ │(192.0.2.22)│
                    │ TCP/5033   │  │ TCP/5033   │
                    └─────┬──────┘  └─────┬──────┘
                          │   panel↔panel  │
                          └────────────────┘
                    NODE1:5033 ↔ NODE2:5033 (peer mesh,
                    0x29/0x2A band — invisible at SUP)
```

Each arrow is an independent TCP connection with its own `sequence` space (§6.5).

## 8. Body Encoding Primitives

Request and response bodies (everything after the 2-byte AP2 function code on a request frame, or after the routing slots on a response frame) are assembled from a small, fixed set of encoding primitives. This section defines each primitive at the byte level. The opcode/operation grammars in §9 are built entirely from these; the point-model value forms they feed are detailed in §11. All multi-byte integers in P2 bodies are **big-endian** unless explicitly stated otherwise; header length and sequence fields are big-endian `u32`, and analog `f32` values are big-endian (see §8.3). [W][S]

The primitives are:

| Primitive | Role | Subsection |
|---|---|---|
| String TLV | Tagged, length-prefixed string/name/scope field | §8.1 |
| Scope tag + command priority | Addressing prefix that also sets command priority and read/write path | §8.2 |
| Numeric value field | Integer and `f32` value encodings | §8.3 |
| String character encoding | RAD-50 vs ASCII codec selection | §8.4 |
| ASDU field convention | How ordered typed fields realize on the wire | §8.5 |

### 8.1 The string TLV
The universal container for a string, name, or scope-name field is a tag-length-value (TLV) structure. It is the single most common primitive in any P2 body. [W]

| Offset | Field | Type | Value/Notes | [tag] |
|---|---|---|---|---|
| 0 | `textType` | u8 | `0x01` for text; **`0x00` also occurs** — see below | [W] |
| 1 | `textLen` | **u16 BE** | Number of content bytes that follow | [S][W] |
| 3 | content | `textLen` bytes | Usually ASCII text; occasionally binary | [W] |

**`textType` is not always `0x01`, and the earlier claim that it was could not
have detected otherwise.** A previous edition of this table read "always `0x01`
in the corpus" on the strength of a scan that located TLVs *by looking for the
byte `0x01`* — so a TLV with any other type could not appear in its output, and
the 1,223,162 figure it produced is a count of `0x01` bytes, not a census. Re-run
by **structural position** instead — reading whatever byte sits at each place a
structure requires a `TEXT_` — the corpus gives: [W]

| Field role | TLVs | `0x01` | `0x00` |
|---|---:|---:|---:|
| point name | 39,450 | 39,446 | 4 |
| name suffix | 39,450 | 39,446 | 4 |
| point descriptor | 19,727 | 19,723 | 4 |
| engineering units | 14,896 | 14,884 | 12 |
| **total** | **113,523** | **113,499** | **24** |

Every one of the 24 has `textLen` = 0 and no content, so `00 00 00` and
`01 00 00` are **two encodings of the empty string** and no non-empty value of
another type has been seen. The practical rule: a decoder must take the TLV from
its position in the structure and must **never** test `textType == 0x01` to
decide whether one is present — a parser that does will desynchronise on an
empty field, which is exactly how twelve point bodies in this corpus fail to
decode. `textType` is a **[OPEN]** discriminator: the firmware's own string
handling distinguishes RAD-50 from ASCII (§8.4), which is the obvious candidate
for what it selects, but no non-`0x01` value with content exists here to
confirm it.

**The length is two bytes, not one.** An earlier edition of this section
described the primitive as a fixed 2-byte prefix `01 00` followed by a
*one-byte* length. Every observed TLV is consistent with that reading, because
the protocol's own type system defines the field as

```
TEXT_ :  textType : UNSIGNED_8      textLen : UNSIGNED_16      text : Byte[]
```

so the `00` that looked like the second half of a constant tag is the **high
byte of a 16-bit length**. The two readings coincide for every string shorter
than 256 bytes, and no string in the corpus is longer: **1,223,162 TLVs, every
one with a zero high byte.** (That scan located TLVs by their `0x01` type byte,
which invalidates it as a census of `textType` above but not as a test of the
length, which is what it was built for — and the 24 TLVs it could not see are
all zero-length.) The longest content observed from vendor traffic is 183 bytes;
the only 255-byte TLV in the corpus is a deliberately maximal test name of our
own.

An implementer must use the 16-bit reading anyway, because the one-byte reading
is only accidentally correct here and fails destructively where it is not: the
codec's own string caps put message text, license strings, point descriptions
and **PPCL program-line text in a band around 248–257 bytes** (§8.4), straddling
the boundary. A decoder that reads one byte will take a 256-byte line's length
as `0x00`, emit an empty string, and then resynchronise in the middle of the
text — silently, on the most variable-length field in the protocol.

**[OPEN]** — no observed frame settles it from the wire alone. The falsifying
test is cheap and safe, and is the same shape as the name-length probes already
run: present a name TLV of 256 or more bytes and observe whether the panel reads
the length as 16-bit. Until then this is `[S]` from the type system with `[W]`
consistency, not a wire-proven width.

Worked examples (verbatim wire bytes): [W]

```
01 00 04 53 59 53 54         ->  "SYST"   (length 4)
01 00 0A <10 content bytes>  ->  a 10-byte name
01 00 00                     ->  ""       (empty TLV, length 0)
```

Properties an implementer must honor:

- **Content is NOT NUL-terminated.** The length byte alone bounds the content. This is the inverse of the four routing slots in the header (see §6), which are NUL-terminated and carry no length prefix. The two MUST NOT be conflated. [W]
- **A single TLV's content is bounded by `textLen`, a 16-bit field**, so the
  structural cap is 65,535 bytes rather than 255. What actually bounds a field
  is the *codec's* per-field maximum (§8.4) — 31 bytes for object and point
  names, ~13 for a short descriptor, ~248–257 for free text — not the length
  field. Standard P2 name fields are far under either. [S][W]
- **The empty TLV `01 00 00` (length 0) is common** and serves as a positional placeholder inside request bodies — reserving or separating a field that carries no value in a given request (for example a device-name slot left empty to address a BLN-virtual point). [W]

Notation used throughout §9: `S<n>` abbreviates a string TLV — `<textType> <n:u16 BE> <n content bytes>` — and `S()` abbreviates the empty placeholder TLV. Worked examples render these as `01 00 <n> …` and `01 00 00` because they are verbatim capture bytes and `textType` is `0x01` in 113,499 of the 113,523 TLVs measured. **Read the notation as positional, not literal:** the leading byte is a type, the empty form occurs on the wire as `00 00 00` as well as `01 00 00`, and a decoder must take each TLV from its structural position rather than matching the leading byte (§8.1). [W][I]

The TLV's `TEXT_` content is what realizes a logical name on the wire. In the vendor's own ASDU field model (§8.5) a name field decomposes into a `name_space` selector plus `name` and `suffix` `TEXT_` fields; on the wire each `TEXT_` field is a string TLV, and a multi-component name is carried as consecutive TLVs. [S]

### 8.2 Scope tag and command priority
Most addressable requests open with a **scope tag**: a scope-name string TLV (§8.1) immediately followed by a 5-byte selector of the form `<scope_byte> 3F FF FF FF`. [W]

```
01 00 04 53 59 53 54   23 3F FF FF FF
|------- TLV "SYST" --| |- selector -|
                        scope_byte=0x23, then wildcard mask 3F FF FF FF
```

**This block is a `User_profile`, and reading it as one explains every field.**
The structure catalog defines `User_profile` as `user_logon : TEXT_`,
`point_priority : Point_priority`, `access_class : BITSTRING32` — a name, a
priority and a 32-bit rights mask — which is exactly the TLV + byte + four bytes
seen here. [S][W]

| Field | Observed |
|---|---|
| `user_logon` | `NONE` (13,557), `SYST` (5,448), `CC` (59, on alarm print and acknowledge), and an **operator's login name** where the operation came from an interactive session |
| `point_priority` | `0x00` none (17,650), `0x23` **oper** (35, 1,061), `0x01` **tec_ovrd** (356) — the §7 command-priority enum |
| `access_class` | `0x3FFFFFFF` on 19,066 of 19,067 requests; `0xBFFFFFFF` on one |

So the "scope names" are **logon identities**: `SYST` and `NONE` are what the
stack presents for system-originated work, and a human login appears in the same
field when a person drives the operation. The single `0xBFFFFFFF` came from a
panel operation issued while an operator was logged into that panel's Telnet CLI
— same mask as the system contexts plus the top bit, i.e. a different
access-rights set for a privileged session, not a different mask format. A
parser should therefore **read all three fields** rather than matching a fixed
prologue: an unfamiliar name in the first TLV is an operator, not a parse
failure. [W] The leading `scope_byte` **is the command priority** at which the operation acts — it is not a separate flag. The same byte both sets the priority a write commands the target at, and (through the read-vs-write handler split) selects the body grammar that follows. [W][S]

Defined scope-name TLVs observed on the wire: [W]

| Scope TLV | Use |
|---|---|
| `"NONE"` | The **default scope for routine point operations** addressed by full point name — both reads and the bulk of commands. In a 3-hour supervisor capture it was the scope on **all 13,796 `POINT_CMD_VALUE` writes** (zero `"SYST"`); a separate 4-minute command capture showed 444 writes split **439 `NONE` / 5 `SYST`** (the `SYST` cases carrying `scope_byte = 0x23`). It typically carries `scope_byte = 0x00`, with the command's effective priority carried instead in the trailing priority byte after the value (§12.4). [W] |
| `"SYST"` | System / whole-panel scope, routed through the panel's system-scope handler. Its `scope_byte` is the operation's command priority: system-scope **writes** (e.g. `0x4221`, `0x0295`, `0x0240`/`0x0241`/`0x0244`) carry `0x23` (OPER), while the system-scope **read** path — dominated by `0x0220` `POINT_LOG_VALUE` — carries `0x01` (tec_ovrd) or `0x00` (none). By raw frame count across the corpus the most common `SYST` `scope_byte` is `0x01`, **not** `0x23`; `0x23` is dominant only on write opcodes. Reserved for system-level points (e.g. panel day/night mode); ordinary point commands use `"NONE"`. Many system-scoped operations require this tag and reject the request if it is absent. [W] |
| `"CC"` | Command-and-control opcode family; typically carries `scope_byte = 0x23` (OPER). [W] |

#### 8.2.1 The command-priority ladder [S]

The `scope_byte` takes its values from the `User_command_priority` enumeration, the command-priority ladder. Higher numeric value = higher priority; acceptance of a command at a point is a **`>=` gate** against the priority already held at that point. [S]

| Name | Value (dec) | Value (hex) | Notes | [tag] |
|---|---|---|---|---|
| `none` | 0 | 0x00 | The read path; no command authority. Read-style operations carry `0x00`. | [W][S] |
| `tec_ovrd` | 1 | 0x01 | TEC (terminal-equipment-controller) local override. | [S] |
| `pdl` | 5 | 0x05 | PDL (process/peer data link) program command. | [S] |
| `host_2` | 10 | 0x0A | Host band level 2. | [S] |
| `host_3` | 15 | 0x0F | Host band level 3. | [S] |
| `host_4` | 20 | 0x14 | Host band level 4. | [S] |
| `host_5` | 25 | 0x19 | Host band level 5. | [S] |
| `host_6` | 30 | 0x1E | Host band level 6. | [S] |
| `emer` | 32 | 0x20 | Emergency. | [S] |
| `smoke` | 34 | 0x22 | Smoke control. | [S] |
| `oper` | 35 | 0x23 | Operator — highest. The system-scope **write** priority; `"SYST"` with `0x23` routes the write path. | [W][S] |

The same five priority names are exposed in the PPCL control language as the literals `@NONE`, `@PDL`, `@EMER`, `@SMOKE`, `@OPER`, and the field-controller priority field is a single byte (`GetPriority -> BYTE`), confirming `scope_byte` is exactly the 1-byte command priority. [D]

Priority semantics an implementer must honor:

- A **write** commands the target at the priority in `scope_byte`; a **read** uses `0x00` (`none`). The read-vs-write body shape for a polymorphic scoped opcode is discriminated by `scope_byte` (`0x23` write vs `0x00` read) **together with** traffic direction — never by TCP port and never by the message class. [W][S]
- **Priority is held until released.** A command placed at a given priority holds the point at that priority. A held priority MUST be explicitly released (commanded back to `none`) before a lower-authority source — for example a PPCL program commanding at `NONE` — can reclaim control of the point. A PPCL `NONE` command does not override a higher held priority. [D][I]

#### 8.2.2 Point priority overlay (BACnet 16-level band) [S]

The `Point_priority_enum` superset extends the command ladder of §8.2.1 with the BACnet 16-level priority array, values **101–116** (`bacnet_1` … `bacnet_16`), where `bacnet_1` (101) is highest within that band.

**The translation between the two ladders is a documented, and configurable,
table.** When a P2 control program commands a BACnet point, the supervisor maps
the P2 priority onto a BACnet level: [D]

| P2 priority | BACnet level |
|---|---|
| `OPER` | 8 |
| `SMOKE` | 10 |
| `EMER` | 12 |
| `PDL` | 14 |
| `NONE` | 16 |

The ordering survives the translation — BACnet numbers ascend as priority
*falls*, so `OPER` at 8 outranks `NONE` at 16, exactly as `35` outranks `0` on
the P2 ladder (§8.2.1). What an implementer must not do is treat the mapping as
fixed: it is overridable per project by a plain-text configuration file, so a
tool that infers a P2 priority from an observed BACnet level, or the reverse, is
reading a site setting rather than a protocol constant.

Later, BACnet-capable controllers also expose an MMI/BACnet priority band in the 8–16 region (`APP_PRIORITY` / `MMI_PRIORITY` enums on BACnet-TEC platforms). A point on such a controller resolves its effective command from the combined ladder: the legacy P2 command priorities (0–35) and the BACnet array (101–116) coexist in one priority space, with the same higher-value-wins `>=` arbitration. The classic P2 wire `scope_byte` carries only the 0–35 legacy band; the 101–116 band is reached through the point's BACnet command path on controllers that implement it. [S][I]

### 8.3 Numeric value fields
#### 8.3.1 Integers [W]

Integer fields embedded in bodies are big-endian. Both 16-bit (`u16 BE`) and 32-bit (`u32 BE`) fields occur — 2-byte error codes, 2-byte record markers and element counts, and 4-byte counts or identifiers in enumeration and routing bodies. (Header `total_len`, `msg_type`, and `sequence` are `u32 BE`; the AP2 function code and the error code are `u16 BE` — see §6.) The vendor field model uses the signed/unsigned 8/16/32 widths of the `Native_type_enum` (§8.3.3), and counts are typically `UNSIGNED16` / `UNSIGNED_16`, e.g. an array length preceding a variable-length element list. [W][S]

#### 8.3.2 Floating-point (analog) values [W][S]

Analog point values are **IEEE-754 single-precision (32-bit) floats in big-endian byte order** (`f32 BE`), embedded directly in the body with no scaling on the wire. Example: the bytes `41 EB 3C 0C` decode to 29.404. Runs of `f32` values appear inside multi-value response bodies (setpoint and limit tables, schedule data). [W]

Values are raw engineering units as the point holds them; any slope/intercept conversion to display units is applied by the client from a per-point table, not from any wire field. Each analog point carries a **`Slope`** and **`Intercept`** (and a `Sensor Type`) in its configuration; display value = `slope * raw + intercept`, with the device-range ↔ signal-range mapping (`PointDeviceHigh/Low` ↔ `PointSignalHigh/Low`) defining the conversion. This metadata is not on the value wire; it lives in the point database. (See §11 for the full point-read value-block layout that wraps the `f32`.) [D][S]

This BLN/P2 `f32` value form is **distinct** from the FLN/P1 raw-count analog representation: an FLN field device reports an analog as an **integer raw count** whose width is governed by `P1MaxRange` (most commonly an 8-bit count, 0–255), which the parent panel converts to engineering units using the point-team scaling before presenting the point as a P2 `f32`. An implementer reading P2-over-TCP sees the `f32` form; the raw-count form appears only across the P1 fieldbus and in FLN-device point definitions (cross-ref §11). [D][I]

#### 8.3.3 Native primitive types [S]

The vendor's `Native_type_enum` enumerates the primitive value types a point or field may take. An implementer mapping a typed field to wire bytes uses this set:

| Value | Name | Wire meaning | [tag] |
|---|---|---|---|
| 0 | `NVT_TYPE_UNKNOWN` | unknown/unset | [S] |
| 1 | `NVT_TYPE_SIGNED_CHAR` | signed 8-bit | [S] |
| 2 | `NVT_TYPE_UNSIGNED_CHAR` | unsigned 8-bit | [S] |
| 3 | `NVT_TYPE_SIGNED_SHORT` | signed 16-bit BE | [S] |
| 4 | `NVT_TYPE_UNSIGNED_SHORT` | unsigned 16-bit BE | [S] |
| 5 | `NVT_TYPE_SIGNED_LONG` | signed 32-bit BE | [S] |
| 6 | `NVT_TYPE_UNSIGNED_LONG` | unsigned 32-bit BE | [S] |
| 7 | `NVT_TYPE_ENUM` | enumerated (multistate); maps to an enum-table id (§11) | [S] |
| 8 | `NVT_TYPE_ARRAY` | array; a count followed by repeated elements | [S] |
| 9 | `NVT_TYPE_STRUCT` | structure; ordered typed fields (§8.5) | [S] |
| 10 | `NVT_TYPE_UNION` | union | [S] |
| 11 | `NVT_TYPE_BITF` | bit field | [S] |
| 12 | `NVT_TYPE_FLOAT` | IEEE-754 `f32` BE — the analog value type (§8.3.2) | [W][S] |
| 13 | `NVT_TYPE_SIGNED_QUAD` | signed 64-bit BE | [S] |
| 14 | `NVT_TYPE_REFERENCE` | reference/handle | [S] |
| 15 | `NVT_TYPE_UNSIGNED_QUAD` | unsigned 64-bit BE | [S] |

The analog wire value (§8.3.2) is `NVT_TYPE_FLOAT` (12). The width and byte order of every other primitive follows the table above, big-endian for all multi-byte forms. [S]

#### 8.3.4 Date/time stamp [W]

Event records (alarm prints, §13.6, and trend/log samples) carry an absolute timestamp as a **packed
8-byte calendar field**, one byte per component, in order:

```
<year-1900> <month> <day> <day-of-week> <hour> <minute> <second> <centisecond>
   u8         u8     u8        u8         u8      u8       u8         u8
```

The year byte is the calendar year **minus 1900** (so `0x7E` = 126 → 2026); month is 1–12, day is
1–31, **day-of-week is 1 = Monday … 7 = Sunday**, then 0-based hour (0–23) / minute (0–59) / second
(0–59) and a trailing hundredths-of-a-second byte. Worked example: `7E 06 19 04 0C 3B 23 48` →
2026-06-25, day-of-week 4 (Thursday — which is the true weekday of that date, an independent check on
the field order), 12:59:35.72. [W] A record may carry more than one such stamp — an alarm report (§13.6) carries **three**:
an event time, a reference time, and a created/configured time; a second observed stamp `7C 01 1E 02 10 0B 0A 59`
decodes to 2024-01-30, day-of-week 2 = Tuesday, 16:11:10, again weekday-consistent (a recurring "created" base). [W]

**The weekday byte makes the field order self-checking, so it was checked on
everything rather than on two examples.** Taking every 8-byte window in the
corpus whose year, month, day, hour, minute, second and centisecond are all
plausible — and *ignoring* the weekday byte while selecting — gives **738
distinct stamps**, spanning 2020 to 2026. The day-of-week byte matches the true
calendar weekday of the decoded date in **738 of 738**.

That is the discriminating result rather than a restatement, because a wrong
field order does not survive it: swap month and day and every date with a day
past the 12th becomes invalid while the rest decode to the wrong weekday, and a
weekday byte that was really something else would agree about one time in
seven. 100% against a 14% null is the field order, confirmed. [W]

This wire
form is distinct from the `eBLN_Node` `baseTime`/`offset` clock-sync fields (§10.6), which are a
separate `u32` time base plus a `u16` zone offset used for replication time alignment, not a calendar
stamp. [W][S]

### 8.4 String character encoding — RAD-50 vs ASCII
String content inside a TLV (§8.1) is carried in one of two character encodings, selected **per firmware platform**, not per frame. The encoding in force is a fixed property of the device's firmware revision (`STRING_TYPE = RAD50 | ASCII`, keyed per platform class in the firmware revision library). A node uses one string encoding for its whole revision. [D]

#### 8.4.1 The RAD-50 codec [S]

RAD-50 packs three characters into a single 16-bit word, drawing from a fixed 40-character alphabet. The alphabet (index → character) is: [S]

```
index:  0                                              39
char:   " ABCDEFGHIJKLMNOPQRSTUVWXYZ$.?0123456789"
```

| Index range | Characters |
|---|---|
| 0 | space (`' '`) |
| 1–26 | `A`–`Z` |
| 27 | `$` |
| 28 | `.` |
| 29 | `?` |
| 30–39 | `0`–`9` |

Three characters `c0 c1 c2` (each mapped to its index 0–39) pack into one unsigned 16-bit word: [S]

```
word = ((c0 * 40) + c1) * 40 + c2
```

The maximum packed word is `39*40*40 + 39*40 + 39 = 63999` (`0xF9FF`), so every RAD-50 word fits a `u16`. To unpack, decode `c2 = word % 40`, `c1 = (word / 40) % 40`, `c0 = (word / 40 / 40) % 40`, then map each index back through the alphabet. Names whose character count is not a multiple of 3 are padded with the space character (index 0) in the trailing position(s) — the packer leaves unused positions at index 0 and zero-fills whole trailing words, which is the same thing. [C] **Each packed word goes on the wire big-endian**: the codec builds the word natively and then writes it through its 2-byte primitive with the byte-reversal flag set, exactly as it does for every other multi-byte field (§8.3). [C] An n-character field therefore occupies **2 × ceil(n / 3) bytes**, so a 6-character name is 4 bytes and a 12-character name is 8. [C] RAD-50 appears only on pre-IP field-controller and supervisor revisions, so an implementer targeting P2-over-TCP normally encounters ASCII (§8.4.2) and treats a RAD-50-packed peer as an out-of-scope legacy revision. [S][I]

Only the 40 alphabet characters are representable: uppercase letters, digits, space, and the three symbols `$ . ?`. Lowercase and other punctuation cannot be RAD-50-encoded, which is consistent with the uppercase-only, restricted character sets of legacy name fields. [S][I]

**Two encoder rules that a decoder-only reading of the alphabet misses.** The packer **uppercases its input first** — a lowercase name is silently folded to uppercase, not rejected — so an implementer must uppercase before comparing a round-tripped name with the original. And **`?` (index 29) is refused on encode**: the packer returns an error for it exactly as it does for a character outside the alphabet, which makes `?` a decode-only symbol. An over-length source is rejected before a single byte is written, rather than truncated. [C]

#### 8.4.2 ASCII [W][D]

All P2/IP revisions carry plain ASCII in both the length-prefixed TLVs (§8.1) and the NUL-terminated routing slots (§6). This is the encoding observed throughout the TCP/5033 wire traffic. A TCP/5033 implementation is ASCII end-to-end; it does not need a RAD-50 codec to interoperate with current panels. [W][D]

#### 8.4.3 Field length budgets by encoding [D]

String fields have encoding-dependent capacity budgets. Name fields (point name, node name) on RAD-50 platforms are constrained to roughly a 12-character budget (and ~30 for longer object-name fields); free-text fields such as a point **Description** run to roughly 60 ASCII characters. Concrete name-field limits used by the protocol model: a logical point name up to 15 characters (historically a 6-character field; shorter names interoperate everywhere), a point descriptor up to 12 characters (display-only), and an object/display name up to 30 characters. Node and BLN names also fall in the ~30-character band. These budgets are firmware-platform properties; an implementer should treat the larger limit as the worst case and not assume a fixed width. The ~15-character node-name truncation is consistent with the Base + Suffix decomposition of a system name (the name is split into a base and a suffix, with the base length-bounded). [D][I]

**Codec-enforced byte maxima (cross-validated).** The ASCII serializer applies a fixed maximum byte length per string field, and the same caps recur across dozens of independent operation bodies — so they are reliable worst-case widths for an encoder, not per-opcode accidents. The dominant cap is **31 bytes (0x1F) for object / point / program-name fields** (seen on the command, COV, cabinet, EBLN, and enum families alike — it is by far the most common string cap; this is the byte width of the 30-character object-name field above, i.e. 30 usable characters within a 31-byte budget), with **13 bytes for a short descriptor or secondary name** (the 12-character descriptor above in its field budget), roughly **21 bytes for an operator credential / logon identity**, and a **free-text band of ~248–257 bytes** for message text, license strings, point descriptions, and PPCL program-line text. (This 31-byte object-name cap is distinct from the ≤15-byte **node**-name limit above — they are different fields: the node name is the access-gate identity in the routing slot / node-name table, while the 31-byte cap governs point, object, and program names inside the body.) An encoder SHOULD truncate to these maxima before framing; an over-length field is the most common reason a panel silently rejects an otherwise well-formed write. [D][I]

### 8.5 ASDU field convention
A P2 body is an **Application Service Data Unit (ASDU)** — the payload the request/response service carries. Each ASDU body is a sequence of **ordered, typed fields** in declaration order (an AsnBase-style structure: there are 1,144 such request/response/sub-type structures defined in the vendor type system). There is no per-field tag/name on the wire beyond what each primitive carries; field identity is **positional**, fixed by the structure definition for that opcode. A parser walks an ASDU left to right, consuming each field per its declared type. [S]

Field-type-to-primitive mapping:

| ASDU field type | Wire realization | Primitive |
|---|---|---|
| `TEXT_` | A string TLV `<textType> <len:u16> <bytes>`, usually `01 00 <len> …` | §8.1 |
| `FLOAT_` | `f32 BE` (4 bytes) | §8.3.2 |
| `UNSIGNED8` / `UNSIGNED_8` / `BOOLEAN_` | `u8` (1 byte) | §8.3.1 |
| `UNSIGNED16` / `UNSIGNED_16` | `u16 BE` (2 bytes) | §8.3.1 |
| signed/unsigned 32/64 | per `Native_type_enum` width, BE | §8.3.3 |
| `<EnumName>` | the enum's underlying integer (typically `u8` or `u16 BE`) | §8.3.3 |
| `<SubStruct>` | that sub-structure's ordered fields, inlined | §8.5 (recursive) |
| `<Type>[]` | a `UNSIGNED_16` count followed by that many elements | §8.3.1 + element |

Composite name fields decompose into a `name_space` selector plus `TEXT_` components, each component a string TLV on the wire:

- `Name_single` = `name_space`, `name` (`TEXT_`), `suffix` (`TEXT_`) — addresses one named object. [S]
- `Name_response` = `name_space`, `name`, `suffix` — the echoed name in a reply. [S]
- `Name_search` = `name_space`, `name_pattern`, `suffix_pattern`, plus `last_name_space`/`last_name`/`last_suffix` for resumable/paged browse. [S]

A worked structural example — the point-command-value request — shows the convention end to end: [S]

```
AP2_Point_Cmd_Value_Request =
    user_profile   : User_profile      ; sub-structure (inlined fields)
    name_search    : Name_search       ; name_space + name/suffix TLVs (+ resume fields)
    point_value    : Point_value       ; the f32 value block
    point_priority : Point_priority     ; the command priority (§8.2.1 ladder)
```

On the wire this serializes as the sub-structure's fields, then the name TLV(s), then the `f32` value, then the priority field — in that order, positionally. The command priority here is the same ladder value that a scoped request carries in its `scope_byte` (§8.2.1); whether the priority rides as a scope-tag selector byte or as a trailing typed field depends on the specific opcode's structure, but the value space is identical. [S][I]

> **Layout-precision note.** ASDU field *order and type* are definitional truth from the vendor type system ([S]). For the **COV annunciate condition/priority block specifically**, the offsets are now pinned: the `Annunciate_request` defines exactly ten status fields after the value and the wire block is exactly ten bytes, so the mapping is **one byte per field in schema order** (§12.3.3) — position/size/order are [W]/[S], and only the *asserted values* of the alarm/flag/priority bytes remain to be confirmed from an alarmed capture. For the **per-type value arms of `All_points`** the position is now measured rather than open, and it splits by arm. An arm's interior layout is confirmed the moment a body carrying it consumes to the byte, because a wrong interior offset displaces everything after it — so the corpus settles the arms it exercises and says nothing about the rest: [W]

| arm | bodies reaching it | of those, consuming exactly |
|---|---:|---:|
| `ldi` | 28 | 28 |
| `ldo` | 128 | 128 |
| `lai` | 112 | 112 |
| `lao` | 148 | 148 |
| `l2sl` | 13 | 13 |
| `lenum` | 7 | 7 |

**Six of the sixteen arms are confirmed; the other ten are never exercised here and stay `[OPEN]`** — `looap`, `lpaci`, `l2sp`, `looal`, `lfssl`, `lfssp`, `ldao`, `lfmsl`, `lfmsp`, `ppcl_lai`. That is the same ceiling §10.9 describes: this site runs six point types, and no amount of further reading of this capture set will produce a seventh. [W][OPEN] For the replication change-record framing the interior offsets remain **[OPEN]**; treat byte-offset claims there as inferred.

For the byte-level grammar of each opcode's request and response ASDU, see §9; for the point-model structures (value blocks, multistate enum tables, FLN-device subpoints, slope/intercept scaling) these primitives compose into, see §11.
## 9. Function-Code (Opcode) Catalog

Every P2 request, panel-originated push, and response is dispatched on a single 2-byte field, the **AP2 function code** (the wire opcode). This section catalogs that field. §10 then gives the body (ASDU) structures that follow each opcode.

### 9.1 The AP2 function code

The AP2 function code is a 16-bit big-endian value that sits on the wire immediately after the fourth NUL-terminated routing slot, in `direction == 0x00` frames (requests and panel-originated async pushes). It is the dispatch key the panel exec (CEC) uses to select the operation; the bytes following it are the operation's ASDU body (§10). The opcode is meaningful only in `direction == 0x00` frames — reading the post-slot bytes off a `0x01` success or `0x05` error response yields response-payload bytes, not an opcode, and fabricates phantom values (see §6.4). [W][S]

The complete command vocabulary of the protocol is defined by the vendor's `AP2_Function_Code` enumeration: **641 named members across 630 distinct opcode values** (a handful of values carry two names — historical aliases such as `AP2_DUMMY_CMD`/`AP2_REV_STRING` at 0x0100, or the `CONTROLLER`/`TEC` doublets). The enum's numeric values **are** the wire opcodes: cross-checking every opcode seen on the wire against the enum, all matched exactly. [S]

Of the 630 defined values, **135 are observed in the capture corpus** (621,268 trusted P2 frames across the 121 captures that carry P2; see §9.5 for the counting criteria and for why an earlier figure of 135 was withdrawn); the remaining 495 are defined-but-unobserved (overwhelmingly configuration, database-management, upload, and BACnet/LON-integration operations that a passive supervisor↔panel capture does not exercise). A further **15 opcode values appear on the wire without an enum definition at all** and therefore have no catalog row; thirteen of them are real panel operations and two are artifacts of a deliberately malformed test frame (§9.5). Counting those, **148 distinct operations** have been observed. Every defined opcode is enumerable from the catalog below; "not observed" means absent from this corpus, not undefined. The corpus combines passive supervisor↔panel and panel↔panel site captures with a smaller set of active read/enumeration test captures; opcode counts are corpus frequencies, not a claim about steady-state operation. [W][S]

Rows that were seen on the wire are tagged **[W]** and carry their frame count; defined-but-unobserved rows are tagged **[S]** (struct/metadata-derived from the vendor enum — definitional truth). Wire counts in the catalog come from the corpus census; per-opcode response shapes, error tails, and message-class distributions are in §9.7.

> **Vantage point bounds every count in this section.** Almost all of the corpus was captured at the supervisor, and a supervisor-side tap structurally cannot see a session between two panels — P2 is unicast TCP, so the switch shows that tap only the conversations the supervisor is in. Taps placed on a panel's own switch port — five of them, on two different panels — each show it holding P2 sessions with **nine peers**, of which the supervisor is one. Read the counts here as frequencies in *supervisor-facing* P2, and read a zero as "the supervisor does not invoke this," never as "panels do not exchange this." The message-class figures in §9.7 make the difference concrete: class `0x2A` is absent from the supervisor-side census and plainly present from a panel-side one. [W]

### 9.1.1 The wire opcode is the bottom of a three-tier model

An implementer reading only the wire sees one identifier per request. The stack
that produces it carries three, and knowing that resolves several things this
document previously treated as anomalies. [S]

```
  __Rpc<Operation>          the supervisor-side operation, by name
        |
        v
  CPI function code         "Common Protocol Interface" dispatch id
        |
        v
  AP2 function code         what appears on the wire (§6)
```

The command object exposes both lower tiers side by side —
`GetAP2FunctionCode` / `SetAP2FunctionCode` alongside `GetCPIFunctionCode` — so
the two codes are genuinely distinct fields, not two names for one value. They
are reachable from either end: one factory builds a command from a CPI code,
another (`BLN2CPI`) builds one by parsing a received wire frame and dispatching
on the AP2 function code inside it. [S]

Scale: **353 CPI codes carry a recovered operation name**, **356** reach a
command class, and **347** of those have a request encoder that resolves onto
**399 distinct wire opcodes**. The names are plainly
descriptive (`__RpcRegisterCOVxx`, `__RpcCancelCOVxx`, `__RpcColdStartCabinet`,
`__RpcMakeNodeOffline`, `__RpcBACnetWhoIs`, `__RpcBPing`), which makes the CPI
tier the most legible statement of *what operations exist* that this protocol
has. [S]

**The receive path is narrower than the send path, and by how much is
measurable.** `BLN2CPI` dispatches an inbound frame through a chain of **twelve
range switches**, each of which states its own first opcode and its own length.
Together they reach **700 opcode values**; **97 of those have a dedicated
handler** and the remaining 603 fall through to a single shared default. [S]

| band | opcodes | cases | band | opcodes | cases |
|---|---|---:|---|---|---:|
| 1 | `0x0030`–`0x0042` | 19 | 7 | `0x0601`–`0x0606` | 6 |
| 2 | `0x0051`–`0x0136` | 230 | 8 | `0x0611`–`0x0615` | 5 |
| 3 | `0x0240`–`0x0334` | 245 | 9 | `0x095B`–`0x09A4` | 74 |
| 4 | `0x0337`–`0x0368` | 50 | 10 | `0x09B0`–`0x09BC` | 13 |
| 5 | `0x0402`–`0x040E` | 13 | 11 | `0x462D`–`0x4640` | 20 |
| 6 | `0x0544`–`0x054D` | 10 | 12 | `0x4821`–`0x482F` | 15 |

Two properties of this make it usable rather than trivia. **An opcode outside
every band cannot be dispatched at all** by this receive path — 700 of the
catalog's values are reachable and the rest are not, which bounds what a peer
can meaningfully send *to a supervisor*. And **falling inside a band is not the
same as being handled**: the 603 defaulted opcodes reach a single address that
sets an error rather than decoding a body, so a client that receives a success
for one of them is talking to something other than this codec. [S][I]

The map is checked against an artifact that did not produce it: **all 97
opcodes with a dedicated handler carry a name in the AP2 function-code
enumeration — 97 of 97**, against 29% for the defaulted ones. If any band's
base or length were off by one, its dedicated set would slide onto neighbouring
values and that agreement would collapse toward the background rate. [S]

#### The opcode carries an operand, which is why the catalog is so large

The obvious model — one operation, one wire opcode — is wrong, and the way it is
wrong is useful. **The wire opcode is selected while the request is being
encoded, not when the command is created.** The supervisor builds the body
first, and only then reads the function code out of the command object and
writes it into the frame. An operation whose parameter can take a few values
therefore emits a *different opcode per value*, and that parameter never appears
in the body at all. [S]

The relation, measured across the supervisor's whole operation catalog: [S]

| | |
|---|---:|
| operations that emit exactly one opcode | **299** |
| two | 26 |
| three | 20 |
| four | 1 |
| thirteen | 1 |
| opcodes emitted by exactly one operation | **385 of 399** |
| by two or three | 13 |
| by sixteen | 1 — `0x0313`, the P1 tunnel |

So for the large majority the opcode does identify the operation. The
exceptions divide into two kinds, and both are worth knowing.

**Kind one: the opcode encodes a parameter.** These families are enumerations
of one operation, not lists of separate operations:

| Parameter in the opcode | Operation | Opcodes |
|---|---|---|
| **filter**, 13 values | point log | `0x0220`–`0x022C`: `POINT_LOG_` `VALUE`, `ALARM`, `CTRL_STAT`, `FAILED`, `TOTAL`, `PRIORITY`, `DISABLED`, `TYPE`, `TROUBLE`, `ANY`, `ODSB`, `PDSB`, `ALARM_CMD` |
| **state**, 4 values | point command | `0x0244` `CMD_ALARM`, `0x0245` `CMD_NORMAL`, `0x024C` `CMD_INTO_TROUBLE`, `0x024D` `CMD_OUTOF_TROUBLE` |
| **bus number** | set FLN baud rate | `0x0123` / `0x0124` / `0x0125` (FLN 1/2/3) |
| **port number** | set MMI baud rate | `0x0120` / `0x0121` |
| **upload phase** | upload PPCL, program, EQS zone, trend, … | `UPL_DEL_x` → `UPL_ADDED_x` → `UPL_ALL_x` |
| **boolean** | enable / disable anything | `TELNET_ENABLE`/`DISABLE`, `PPCL_ENABLE_LINES`/`DISABLE_LINES`, `EQS_ZONE_ENABLE`/`DISABLE`, `POINT_CMD_ENABLE`/`DISABLE` |

This is the practical reading of §9.5's catalog: whole runs of consecutive
opcodes are one operation with a dial on it. `0x0220`, one of the busiest
opcodes in any capture, is not "the read opcode" — it is **point log with the
filter set to value**, and `0x0221`–`0x022C` are the same operation asking for
points in alarm, failed points, disabled points, points of a given type, and so
on. A decoder that treats the run as an enumeration recovers the operand for
free.

#### Which operands live traffic actually uses

Knowing the enumeration exists is half of it; the other half is which values a
working supervisor sends. Counting **only frames a supervisor originated** —
research tooling generates enumerations at a rate no supervisor does, and
including it would skew exactly this measurement — **18.6% of supervisor request
frames carry an opcode-encoded operand** (18,520 of 99,752), and the
distribution is lopsided: [W]

| Operand | Frames | Reading |
|---|---:|---|
| upload phase = **all** | 5,796 | bulk re-read of a whole object class |
| COV state = enable | 4,614 | subscriptions being created |
| point log filter = **value** | 4,331 | the only filter of the thirteen ever seen |
| COV state = disable | 3,697 | subscriptions torn down |
| upload phase = added | 38 | the live-change tail |
| upload phase = deleted | 31 | the live-change tail |
| category node list action = append / remove | 10 / 1 | |
| point command state = alarm | 2 | barely exercised |

Three things an implementer can take from this. Uploads in practice are
**whole-class re-reads**, not incremental sync — the added/deleted phases exist
and are used, but as a thin live tail against a bulk baseline, which matches
what §5.3 describes for replication. COV subscribe and unsubscribe arrive in
near-equal numbers, so a panel implementation must expect subscriptions to churn
rather than accumulate. And of point log's thirteen filters, **only `value` was
ever observed** — the other twelve are a defined but unexercised surface, which
is worth knowing both for a decoder (do not expect them) and for anyone
assessing what a panel will answer that nobody normally asks.

**Kind two: a tunnel.** `0x0313 AP2_P1_ROUTE` is emitted by **16** distinct
operations — a P1 pass-through, TEC point and revision reads, and the whole
unitary-controller upload/define set including its time-set and trace-clear.
Sixteen operations, sixteen command classes, **one shared encoder**: the wire
opcode does not name the operation because its job is to say *route this onto
P1*. The operation is inside the payload. `0x0314 AP2_P1_LINETEST` pairs with it
and is shared by two. `0x0136 AP2_P2_ROUTE` is the same idea for the panel-local
serial link of §6.8. [S]

**For a dissector:** labelling a frame from its AP2 opcode alone is right for
the great majority, wrong for `0x0313` in particular — where it collapses
sixteen operations into one name — and *incomplete* for the enumerated families,
where the opcode also carries a parameter the label should mention.

> **How much of this to trust.** The structure above is read out of the
> supervisor's own dispatch and encoders: each operation reaches a command class,
> and that class's request encoder writes the opcodes listed for it. The value,
> the class and the opcode all come from one path, so the pairing cannot drift —
> an earlier version of this section relied on a mapping that paired two
> separately collected lists and was displaced by one entry, which is why it
> reported eight many-to-one opcodes and fifteen operations on `0x0313`.
> Cross-checks: **86 of the 125 wire-attested opcodes** in the corpus are
> accounted for here, and when the operation names are deliberately shifted by
> one entry the agreement between operation names and opcode names collapses
> eightfold. Where a derived name still disagrees with what a panel was observed
> to do, **the observed behaviour wins**. [S]

#### The second selector exists - and never reaches the wire

The command object carries a **second 16-bit selector** beside the opcode: the
AP2 function code sits at object offset `+0x04` and this value at `+0x06`, and it
is tempting to call it a sub-opcode and go looking for it in the body.

**It is the CPI function code** — the middle tier of the model above. The
supervisor's accessors settle it: one reads the halfword at `+0x04` and is named
for the AP2 function code, the next reads the halfword at `+0x06` and is named
for the CPI function code. The two identifiers of a command sit four bytes apart
in the same object, which is also why a command can be built either from a CPI
code or by parsing a wire frame — the supervisor has a factory for each
direction. [S]

**And it is not in the body.** Nine operations with a known selector value were
checked against their captured request bodies - `0x0271` (0x0010), `0x0273`
(0x0011), `0x0272` (0x0012), `0x0241` (0x0030), `0x0294` (0x0704), `0x0295`
(0x0702) among them. In **none** of them does the value appear anywhere in the
request body; the single apparent hit was a TLV length header matching by
coincidence. The field is internal to the sender and is dropped before framing.
[W][S]

That is a more interesting result than a sub-opcode would have been, because of
what it implies for the many-to-one opcodes above. **The receiving panel does
not get the selector either.** Where several operations share one wire opcode
the panel cannot be distinguishing them by a discriminator field - it must be
dispatching on the shape and content of the body itself, or the operations are
genuinely identical from the panel's point of view and differ only in how the
supervisor handles the reply. For `0x0313` that fits the tunnel reading: the
panel forwards to P1 and does not care which supervisor operation asked. [W/I]

An implementer should therefore not go looking for a hidden selector byte on
the wire. There is not one.

#### The message-structure catalog, and three command shapes

The supervisor's own symbol vocabulary names **505 structures** on a
strict convention: an operation contributes `<OPERATION>_REQ` (**343** of them)
and, where it answers with data, `<OPERATION>_RESP` (**158**), with shared field
groups as `<NAME>_TYPE` (**4**) — 343 + 158 + 4 = 505. Only the 343 are
*requests*; the read/write split below is taken over those, which is why it
counts 343 and not 505. That is a second, coarser view of the same surface the
type-system catalog of §10.1 describes in 1,144 structures; the two use
different suffixes because they come from different layers of the stack, and
neither count contradicts the other. The
names track the families of §9.4 exactly - `ALARM_ACK_REQ`/`_RESP`,
`ANNUNCIATE_COV_REQ`, `BACKUP_FLASH_DBASE_REQ`, `BACNET_MGT_READ_BBMD_REQ`/
`_RESP`, `ADD_CONTROLLER_REQ`. [S]

Every operation is wrapped in one of exactly **three command shapes**, and the
shape is declared rather than inferred: [S]

| Shape | Operations | Meaning |
|---|---:|---|
| request-only | **189** | fire-and-forget; the operation returns status, never a body |
| request-response | **151** | the operation returns a body |
| response-only | **4** | no request exists - these are unsolicited, panel-originated |

This is worth more to an implementer than the name convention, because it
answers a question you otherwise have to discover by sending: **will this
operation come back with data?** For 189 of 340 the answer is no, and a client
that waits for a body will wait forever. The four response-only structures are
the counterpart - messages a panel emits with nothing having asked, which is
the same category as the COV and alarm notifications of §12 and §13.

A rough read/write split falls out of the verb the operation name starts or
ends with. Of 343 request structures, roughly **112 are unambiguously reads**
(`REPORT` 63, `UPLOAD` 61, `READ`, `GET`, `ENUM`, `LOOK`, `DISPLAY`, `QUERY`),
**170 are writes** (`DEFINE` 38, `DELETE`, `ADD`, `REMOVE`, `REPLACE`, `SET`,
`MODIFY`, `CLEAR`, `RESET`, `INITIALIZE`, `COLDSTART`), **23 are notifications**
(`POST` 21, `ANNUNCIATE`), and **38 resist classification** by name alone
(`PASS_THROUGH`, `NET_MGT`, `CHARACTERIZE`, `OSTRACIZE_NODE`, `LON_WINK` and
similar). [S/I]

> **Do not turn that split into a safety allowlist.** The verb classification is
> a property of the *operation name*; a tool needs the *wire opcode*, and the
> name-to-opcode binding is exactly the layer shown unreliable above. A
> classification that is 90% right is worse than none when the 10% contains a
> write. Safety allowlists in this project are built per-opcode from observed
> behaviour, and should stay that way.

### 9.2 Naming, families, and value layout

Opcode names follow the form `AP2_<FAMILY>_<operation>`. The value space is grouped: contiguous blocks share a family and an operation-style suffix vocabulary that recurs across families:

- `_LOG` / `_DISPLAY` / `_LOOK` / `_QUERY_*` — **reads** (return data, no state change).
- `_ADD` / `_REMOVE` / `_MODIFY` / `_COPY` / `_REPLACE` / `_DELETE` — **definition / configuration writes**.
- `_CMD_*` — **runtime command** (commands a live point or object).
- `_ENABLE` / `_DISABLE` — toggle.
- `UPL_ALL_*` / `UPL_ADDED_*` / `UPL_DEL_*` — the three-phase **upload** (bulk read of a whole object class / incremental adds / incremental deletes) used for supervisor↔panel database synchronization.
- `DBCHANGE_*` — database-change notification (panel tells the supervisor a class changed).

The high byte of the opcode tracks the family band, and it does so **structurally rather than descriptively**: the supervisor's AP2 command factory selects which command subclass to build by switching on `opcode & 0xFF00` — `0x0000`, `0x0100`, `0x0200`, `0x0300`, `0x0600`, `0x0E00` and the higher bands each take their own branch. So the band is a real classification in the implementation and not merely a pattern noticed after the fact. [S] The bands: 0x00xx node/cabinet/license, 0x02xx point and COV, 0x03xx session/database/user/EMS/ENVELOPE, 0x04xx enum/alarm/calendar/language, 0x09xx upload + DBCHANGE, 0x28xx/0x38xx RACS, 0x40xx team/PPCL/program, 0x42xx TEC/UC, 0x43xx–0x44xx LON, 0x46xx EBLN + session keepalive, 0x48xx–0x4Bxx BACnet integration, 0x50xx EQS, 0x53xx I/O-module / FLN-topology / flash / HOA, 0x70xx web. The catalog (§9.5) is grouped by these families and sorted by value within each.

### 9.3 Destructive and sensitive operations

A subset of opcodes mutate panel firmware state, node-table membership, point values, or device configuration. These are flagged **DESTRUCTIVE** in the catalog and must be blocklisted in any read-only scanner or bridge (refuse to emit, even behind a flag). They are documented here for completeness; this is a reference, not an exploitation aid, and no attack code is given. [S/W]

**Panel lifecycle (reboot / firmware).** `AP2_CABINET_COLDSTART` (0x010A) and `AP2_CABINET_WARMSTART` (0x010B) reboot the panel; `AP2_CABINET_BOOT_MONITOR` (0x0108) drops it to the boot monitor. *Correction of record:* 0x010A is the cold-start (reboot) command — **not** a benign "GetRevString sibling" as an earlier behavioral reading guessed; the firmware-revision string read is `AP2_CABINET_DISPLAY` (0x010C, §10.5). The cold-start *display/history* operations are distinct from the restart commands: `AP2_CABINET_COLDSTART_DISPLAY` (0x012A) is read-only, while `AP2_CABINET_COLDSTART_CLEAR_HISTORY` (0x012B) **clears the cold-start history** and is therefore state-changing (flag it; not read-only). [S]

**Node-table / cabinet membership.** `AP2_CABINET_ADD` (0x0041), `AP2_CABINET_REMOVE` (0x0042), `AP2_CABINET_ONLINE` (0x0046), `AP2_CABINET_OFFLINE` (0x0047), `AP2_SET_NODE_STATE` (0x0034), `AP2_SET_COMPLETE_NODE_STATE` (0x0035). These add, remove, force-online, force-offline, and evict a cabinet's node-table membership; the eviction case force-removes a peer from the logical BLN (a node-eviction denial-of-service mechanism). Adding/removing entries here is the same node-table surface that registration touches (see §5 addressing and the registration-vs-impersonation footprint asymmetry). [S][I]

**EBLN panel reconfiguration.** `AP2_EBLN_FP_NAME_SET` (0x4620), `AP2_EBLN_FP_IP_CONFIGURE` (0x4621), `AP2_EBLN_FP_SITE_NAME_SET` (0x462A), `AP2_EBLN_FP_BLN_NAME_SET` (0x462B), `AP2_EBLN_FP_MULTICAST_CONFIGURE` (0x462C), `AP2_EBLN_HOSTTABLE_ENTRY_ADD`/`REMOVE` (0x462D/0x462E), `AP2_EBLN_MAC_ADDRESS_SET` (0x4638), `AP2_EBLN_TELNET_ENABLE`/`DISABLE` (0x4644/0x4645). These rewrite the panel's network identity (IP, MAC, names) and management surface. [S]

**Point command (write).** `AP2_POINT_CMD_VALUE` (0x0240) and `AP2_POINT_CMD_PRIORITY` (0x0241) command a live point's value/priority — the primary actuation write path (§10.3). High wire volume (32,044 / 101) confirms these as the routine supervisor write opcodes. The full `AP2_POINT_CMD_*` band (0x0240–0x024E) includes alarm-state forcing, limit setting, totalizer/trouble commands, and `RELEASE`. [W]

**Database / flash / memory / license / COLBAS.** `AP2_RESTORE_FLASH_DBASE` (0x5331, overwrites the panel flash DB), `AP2_CLEAR_FLASH_DBASE` (0x5332, erases it), `AP2_CABINET_MEMORY_MODIFY` (0x012F, direct memory write), `AP2_LICENSE_MANAGER_DELETE`/`DELETE_ALL` (0x0111/0x0112), `AP2_COLBAS_WRITE`/`ABORT` (0x4A03/0x4A04). `AP2_BACKUP_FLASH_DBASE` (0x5330) is a read/export and is **not** destructive. [S]

*Correction of record (COV pair).* `AP2_COV_ENABLE` (0x0271) and `AP2_COV_DISABLE` (0x0273) are the change-of-value subscription enable/disable pair — **not** "ReadExtended"/"PointExistenceProbe" as an earlier behavioral reading labeled them. `AP2_COV_ANNUNCIATE` (0x0274) is the actual COV report (the highest-volume opcode in the corpus, 53,101 request frames under the §9.5 criteria), and `AP2_COV_DELETE_STUB` (0x0272) tears down a subscription stub. These are not destructive but are corrected here because the wrong names propagated into earlier notes. [W][S]

### 9.4 Family overview

- **NODE/STATE** (0x0030–0x0035, 0x5301/0x5304, logger-state) — BLN global data get/set, remote node check, node-state get/set, FLN/MEC-expansion topology query. The destructive members are the set-node-state pair.
- **CABINET** (0x003E–0x0131, plus report-descriptor) — per-panel identity, lifecycle, and link configuration: timeouts, add/remove/online/offline, boot-monitor/cold/warm start, `CABINET_DISPLAY` (the firmware/identity block, §10.5), per-link baud setters (MMI/FLN1-3/BLN), P-bus and modem state, memory display/modify/available, cold-start history.
- **BLN/DIAG** (0x005B/0x005C) — BLN diagnostic counter display and reset.
- **LICENSE** (0x010F–0x0116) — license manager display/add/delete/db-change/message-send (FlexLM-style feature licensing).
- **ROUTING** (0x0136, 0x030E, 0x0310) — P2 route, route-object, P-bus poll. Inter-BLN/cross-trunk brokering rides this family (the source of the multi-slot `[BLN,dst,BLN,src]` routing seen in cross-BLN frames).
- **PBUS** (0x0140–0x0143) — peripheral-bus module display, diagnostics reset, line test.
- **POINT** (0x0200–0x0309) — the point lifecycle: typed `POINT_ADD_*` per L-type, the `POINT_LOG_*` read family, the `POINT_CMD_*` command family (writes), modify/look/remove/definition, totalizer enable/disable/display, set-prefix, save. Read core is `POINT_LOG_VALUE` (0x0220); write core is `POINT_CMD_VALUE` (0x0240).
- **COV** (0x0271–0x0275) — change-of-value subscription enable/disable/delete-stub, the annunciate report, and the COV cross-reference display.
- **MONITOR** (0x0280–0x0282) — name-based monitor add/remove/start (point watch lists).
- **TREND** (0x0290–0x02A9) — trend setup add/delete/enable/disable, data and definition display, multipoint, copy/modify/look, query families, archive setup/upload, and the trend-event subfamily. Data read is `TREND_DATA_DISPLAY` (0x0295, §10).
- **TOD/TIME** (0x0301/0x0302, 0x4500–0x450F) — panel time display/set/software-clock, and the time-of-day scheduling point/command add/remove/enable/disable/display family.
- **MISC** (0x0303–0x0311) — message send, quick keys, development toggle, print-error.
- **SESSION** (0x0304/0x0305) — `LOGON_CEC` / `LOGOFF_CEC` operator session establish/teardown at the panel exec.
- **DATABASE** (0x0307/0x0308/0x030B) — whole-database load/save and tape trailer (legacy archive).
- **PPCL** (0x030A, 0x4100–0x4138) — Powers Process Control Language program editing: add/edit/remove/enable/disable lines, clear trace, program log/search/query/display (incl. unresolved-reference display), modify/copy/setup-modify/look lines, PDL reset/init/display, and the `PROGRAM_*` wrapper ops. PPCL is the panel's resident control-logic language layered over P2.
- **COLBAS** (0x030D, 0x4A00–0x4A06) — COLBAS scripting: immediate/connect/disconnect/write/abort/upload. The write/abort members are destructive.
- **P1/FLN** (0x030F–0x0317, 0x4230–0x4232) — Protocol-I fieldbus operations: P1 poll/route/line-test/reset-counters, FLN scan enable/disable, P1 diagnostics log. P1 is the fieldbus tier below P2 (§3.8).
- **ENVELOPE** (0x0316, 0x031B–0x0320) — message-envelope open/close for destination, text, and user lists (alarm/report routing envelopes).
- **LOGGER** (0x0325/0x0327) — event-logger and buffer-alarm setup.
- **USER/ACCESS** (0x0330–0x0358) — user-account log/display/add/modify/copy/delete/look and db get/replace; access-group log/modify/db get/replace. The operator-credential database.
- **EMS** (0x0360–0x0368) — Energy Management System dial enable/disable, db replace/get/display, entry replace, dial-flags / destinations get, print.
- **ENUM** (0x0401–0x040E) — enumeration-type and enumeration-element add/delete/modify/display/look/log and db get/replace. Backs LENUM multistate text tables.
- **ALARM** (0x0500–0x056A) — alarm setup add/remove/copy/modify/display, alarm point query lists, alarm ack (+ pending query), the alarm-mode subfamily (mode add/copy/list-by-*/definition/modify/query/delete), the category subfamily (0x0540–0x054D: add/remove/descriptor/dial+print enable/disable/db-get/log/nodes-append/nodes-remove/query/default-db-get/replace), and the alarm-message subfamily (0x0560–0x056A: look/enable/disable/delete/copy/add/query/log/modify).
- **CAL/DST** (0x0600–0x0615) — calendar date/db add/reset/display/get (holiday spec + other), and daylight-saving year/db add/delete/display/get.
- **LANGUAGE** (0x0900–0x0902) — localized string/prompt get and report-data (the multilingual UI string service).
- **UPL** (0x0950–0x09C3, 0x4131–0x4133) — the bulk upload engine: `DOWNLOAD_ME`, and per-object-class `UPL_DEL_*` / `UPL_ADDED_*` / `UPL_ALL_*` triplets for point, alarm-setup, alarm-mode, trend, PPCL, TEC, EQS (zone/cmd-table/mode-sched/override), loop, alarm-message, SSTO (general/start/stop/night), port, partner, UC, TOD point/cmd, LON, command/miscdata report, MSTP-device, and program. This is how a supervisor pulls a panel's whole configured database.
- **DBCHANGE** (0x0951–0x09C0, 0x4130, 0x5356) — the panel→supervisor change-notification mirror of the upload classes (point, alarm, trend, PPCL, controller, EQS, SSTO, port, partner, UC, TOD, LON, reports, MSTP-device, program, HOA-map).

**How the `0x09xx` bank is organised, and why the opcode is not a simple sum.**
The bank is one object-class list crossed with a small set of transfer
operations, and a supervisor selects an opcode from a **triple**: the database
*section* (point, alarm-setup, alarm-mode, trend, PPCL, TEC, EQS zone / cmd /
mode / override, SSTO general / start / stop / night, TOD point / cmd, LON,
program, terminal-def, reports, MSTP-device, BACnet schedule / change, …), the
transfer *direction and scope* (download-all, download-changes, upload-all,
upload-changes), and the record *state* (added, deleted, modified). The last of
those maps straight onto the wire families — added ↔ `UPL_ADDED_*`, deleted ↔
`UPL_DEL_*`, modified ↔ `DBCHANGE_*` — over the section list. [S][D]

That is worth stating because the obvious shortcut does not work: **the section
list and the opcode bank are independently ordered**, so an opcode cannot be
computed as a base plus a section index. The correspondence holds for the first
few classes and then breaks. Dispatch on the opcode, never on an arithmetic
relationship to a section number. [S]
- **RACS** (0x2824, 0x3800–0x382A) — Remote Access / Communication System partner, port, and system add/copy/delete/disable/display/enable/log/look/modify/statlog (dial-up / WAN inter-site connectivity management).
- **TEAM** (0x4000–0x4018) — point-team / application descriptor and member operations: team-desc and member-desc add (analog/digital/enum/LPACI/L2SL), team/member/report log/list, descriptor uploads and db-changes. A "point team" is a logical point whose default member is the logical point value (see §11 point model).
- **TEC** (0x4200–0x4225) — Terminal Equipment Controller (FLN device) operations: controller/TEC log/add/copy/modify/remove/look/query/definition, member/report log, and the local/remote init-value log/set/restore/initialize/update family (TEC application init values).
- **UC** (0x4241–0x4249) — Unitary Controller add/remove/look/member-log.
- **LON** (0x4300–0x4452) — LonWorks integration: device log/add/modify/remove, member/report log, init-value family, diagnostics, send-service-pin, get/set-domain, request-wink, status-clear, agent db export/import, peak-db-clear.
- **EBLN** (0x461F–0x464C) — Ethernet-BLN management: field-panel names display, name/IP/TCP-ports/site/BLN/multicast/MAC set/configure, host-table add/remove/display, trunk-settings replace/display, the replication subfamily (notify/pull/pull-more/changes/diag-nodelist), point-location-get, MII configure/display, IP/ports/multicast/MAC display, telnet enable/disable, and `EBLN_PING` (0x4640) — the session-establish/keepalive opcode (see §9.6 and §10.6).
- **WEB** (0x465D, 0x700C) — embedded web-server and ApogeeEdit get-state.
- **BACNET** (0x4821–0x4B03) — BACnet-side integration carried over P2: BBMD add/remove/display, object-id log, application-priority and device-name replace/remove/display, COV-table, BACnet trend-log, MSTP-device (BNMSTP) family, and BNEEO. This is the BACnet bridge configuration surface, distinct from the native P2 point model.
- **EQS** (0x5000–0x5054) — Equipment Scheduling: zone, command-table, mode-entry, and override add/modify/remove/look/enable/disable; display variants; zone log; and the SSTO (Start-Stop Time Optimization) setup/look/display/reset/enable/disable subfamily.
- **IO** (0x5300/0x5303/0x5305) — global and local I/O-module display (incl. MEC expansion bus).
- **FLASH** (0x5330–0x5332) — flash-database backup (read), restore (overwrite), clear (erase).
- **HOA** (0x5351/0x5354/0x5355) — Hand-Off-Auto map modify/look/add (physical HOA-switch mapping).

### 9.4.1 Which of these does a panel actually implement?

The catalog that follows joins a supervisor-side enumeration with a wire census.
Both are one-sided. The enumeration says what a supervisor knows how to *ask*;
the census says what one particular supervisor happened to ask during the
captures. Neither answers the question an implementer actually has, which is
whether a controller will do anything with a given function code.

There is a third source, and it sits on the other end of the wire. Controller
firmware images carry **tables pairing a 16-bit function code with a 16-bit
id**, laid out as 4-byte records:

```
  00 c1 02 20     id 0x00c1  <-  opcode 0x0220
  00 c1 02 29     id 0x00c1  <-  opcode 0x0229
  00 a1 02 73     id 0x00a1  <-  opcode 0x0273
  00 b4 05 47     id 0x00b4  <-  opcode 0x0547
```

The same table is present in images built for **two different instruction sets**
— 68000-family and PowerPC — at the same size and with the same contents. That
is what identifies it as protocol data rather than compiled code. [F]

**What the id is for.** An earlier reading of this section called these dispatch
tables. Disassembly shows otherwise, and the difference matters. The lookup
result is not a jump target: it is handed to a two-byte write against a
serialisation buffer object — one carrying a base pointer, a write cursor, a
capacity and an overflow flag — which memcpys it and advances the cursor. **The
id is emitted into an outgoing message.** A miss yields `-1`, which is a
sentinel a translator writes, not an index a dispatcher could use.

So the panel converts a wire opcode into some other number and emits it. Two
questions follow — whether that number reaches the wire, and what it is — and
both are now answered.

**It does not reach the wire.** Every trusted request frame in the capture
corpus whose opcode has a mapping was searched for its own id as a 16-bit
big-endian value at every body offset, against a shuffled-pairing control:
**83,771 frames, 69 opcodes, 3 real hits against 2 control**. Repeating it on
the panel's *replies* — paired back to their request by sequence number, since
a response carries no opcode — gives **83,876 pairs, 72 opcodes, 1 real hit
against 315 control**. The real mapping scored worse than its own control.
Whatever the panel writes the number into, **it is not a P2 frame**. [W]

*Coverage, since a negative is only as good as its denominator.* The corpus holds
764 capture files, 271 distinct by content, of which **121 carry P2 and hold
621,268 trusted frames between them** — and all 121 were in scope, 100% of frames.
Both ports are represented: 432,368 frames on 5033 and 188,900 on 5034, so the
result is not an artifact of testing only the supervisor-facing channel. [W]

**It is a two-stage internal operation number.** The default table maps an
opcode to a *group*; where the group needs finer resolution, that group has its
own table mapping the same opcodes to an *ordinal*. The group id and the second
table's selector are the same value, which is why the eight selectors are
themselves ids in the default table. `0xB6` is the plainest case — the default
assigns it to nine `CABINET_SET_*` opcodes, and table `0xB6` numbers exactly
those nine 1…11:

```
0x0120 SET_MMI1_BAUDRATE -> 1     0x0126 SET_BLN_BAUDRATE -> 6
0x0121 SET_MMI2_BAUDRATE -> 2     0x0128 SET_BLN_ADDRESS  -> 7
0x0123 SET_FLN1_BAUDRATE -> 3     0x0129 SET_MODEM_STATE  -> 8, 9
0x0124 SET_FLN2_BAUDRATE -> 4     0x0127 SET_PBUS_STATE   -> 10, 11
0x0125 SET_FLN3_BAUDRATE -> 5
```

Seven of the eight group tables hold only opcodes the default assigns that
group. Group `0xC1` is the catch-all — 144 of 317 opcodes, across every family —
and needs no second stage; 61 groups contain a single opcode each, skewed toward
the specific and destructive (`SET_NODE_STATE`, `CABINET_ADD`/`REMOVE`,
`CABINET_COLDSTART`, `CABINET_MEMORY_MODIFY`, the point limit and totaliser
commands). [F]

**The translation runs both ways, and the duplicates are a parameter.** A second
function decodes: it reads a group byte, reads a 16-bit ordinal, and scans the
same table the other way — matching the ordinal and returning the opcode. Which
means the ordinal is genuinely deserialised from a link, even though §9.4.1's
wire tests rule out that link being P2.

The decode path also explains the duplicates. `0x0129 SET_MODEM_STATE` occupies
ordinals 8 and 9, `0x0127 SET_PBUS_STATE` occupies 10 and 11, and decoding
ordinal 8 or 10 — the first of each pair — sets a flag byte on the constructed
operation that decoding 9 or 11 leaves clear. **The duplicate ordinal carries the
on/off argument**, rather than the body carrying it. The encoder's first-match
scan always produces the flag-set form; the second form exists for the decoder.
So a group's ordinals are dense and small because they enumerate *operation
variants*, not opcodes. [F]

**Add and copy share an ordinal.** Only two groups reuse an ordinal across
different opcodes, and the pattern is the same each time — `ALARM_MODE_ADD` with
`ALARM_MODE_COPY`, `ALARM_SETUP` with `ALARM_SETUP_COPY`, `ALARM_MESSAGE_ADD`
with `ALARM_MESSAGE_COPY`. The encoding cannot tell an add from its copy variant,
which is consistent with copy being "add, with a source" and distinguished by the
body — the same conclusion this section reaches from the other direction. [F]

#### A panel-only opcode band: `0x1002`–`0x1005`

One group pairs four otherwise-unknown opcodes with named alarm operations at
identical ordinals:

| Ordinal | Named | Unnamed |
|---|---|---|
| 1 | `0x0520 ALARM_MODE_ADD` / `0x0521 ALARM_MODE_COPY` | `0x1004` |
| 2 | `0x052B ALARM_MODE_DELETE` | `0x1005` |
| 7 | `0x0500 ALARM_SETUP` / `0x0506 ALARM_SETUP_COPY` | `0x1002` |
| 8 | `0x0501 ALARM_REMOVE` | `0x1003` |

These four appear **nowhere else** — not in the supervisor function-code
enumeration, not in any capture, and the whole `0x10xx` band is empty in both of
those sources. They are known only from controller firmware, which places them
as a parallel numbering of the alarm setup/remove and alarm-mode add/delete
operations. Stated at the confidence the evidence supports: **grouped with**, not
**identical to** — a shared ordinal shows the decoder treats them as the same
variant, which is weaker than shared semantics. A tool should not emit them:
nothing has been observed accepting one. [F]

**Why this matters to an implementer, given it is never transmitted.** §9.1.1
records the supervisor carrying a second 16-bit selector per operation that
likewise appears in no captured body. Both ends of the wire maintain a
sub-operation number, and **neither serialises it**. So where several operations
share one wire opcode, a receiver is not reading a sub-code off the frame — it
is dispatching on the body. Build a decoder the same way: key on
`(opcode, body shape)`, never on a sub-field that is not there. [W][F]

**There is more than one table, and a class code selects between them.** The
firmware stores each table's length in a 16-bit word immediately after it, so
the layout is exact rather than inferred — in one image, ten tables laid end to
end, 513 records in total, each stored count matching its span:

| Selector | Records | | Selector | Records |
|---|---:|---|---|---:|
| `0xAC` | 12 | | `0xE0` | 4 |
| `0xCF` | 6 | | `0xB4` | 3 |
| *default* | **317** | | `0xB6` | 11 |
| `0xB2` | 9 | | `0xA6` | 6 |
| `0xB8` | 3 | | (unlabelled) | 142 |

The selector comes from a method on the calling object, and the default table
applies when no group-specific one matches. [F]

Presence in these tables says the panel firmware *knows* the function code and
carries a translation for it. It does not by itself prove the panel implements
the operation — for that, §9.5's rule still holds: classify by what the panel
did when asked.

Across 42 images spanning firmware revisions 1.3 to 2.6 and the MEC, MBC, FLN,
SV5, PPC, LON and MECF product lines, **164 function codes appear both in a
panel's opcode tables (in at least 28 of the 42 images) and in the supervisor
enumeration**. For sets of that size drawn from a 16-bit space, chance overlap
would be about 2.5. Those 164 are the subset of the catalog that is confirmed
implemented at both ends. [F][S]

**A caution on reading the tables directly.** The blob holds several adjacent
sub-tables that do not share a 4-byte phase, and its tail reverses the field
order to `(code, handler)`. An extractor that assumes one layout will mis-split
a minority of records. This is why the count above is stated as the intersection
with an independent source rather than as a raw table read: 234 further codes
appear in the firmware tables alone, and those are candidates, not findings.

#### The supervisor vocabulary has real gaps, and the firmware measures them

**Correction.** An earlier edition of this subsection asserted that seven
function codes seen on the wire — `0x0203`, `0x0204`, `0x0260`, `0x0274`,
`0x0508`, `0x4500`, `0x5038` — were missing from the supervisor enumeration, and
rested its argument on `0x0274`, the COV value push. That is wrong. **All seven
are defined in the enumeration**, and §9.5's catalog, which is generated by
joining that enumeration with the census, names every one of them —
`| 0x0274 | AP2_COV_ANNUNCIATE | …`. The two sections contradicted each other.
The conclusion below is unchanged, but it needed different evidence, and the
correct evidence is considerably stronger.

Resolving every opcode value known from any source across the three independent
authorities — the supervisor's `AP2_Function_Code` enumeration (630 values under
641 names, eleven of which are aliases), the ten count-validated panel-firmware
dispatch tables of one image, and the wire census: [W][S][F]

| Region | Count |
|---|---:|
| enum only | 338 |
| enum + firmware, not on the wire | 157 |
| **all three** | **78** |
| enum + wire, not in the firmware tables | 57 |
| **firmware only** | **82** |
| firmware + wire, not in the enum | **0** |
| wire only | 15 |
| **union — every opcode value known from any source** | **727** |

Three things follow, and the middle one is the point:

**82 opcodes are in the panel firmware and not in the supervisor enumeration.**
That is the measured width of the gap. The panel's vocabulary is not a subset of
the supervisor's; a name list derived from supervisor binaries is a list of what
a supervisor knows how to *ask for*, and it is 82 codes short of what this panel
image knows how to *answer*. This is the concrete form of the rule in §9.5:
**classify an operation by what the panel did with it, never by its absence from
a derived name list.**

**Fifteen wire values are in neither authority** — and the panel answered eight
of them with structured success responses (§9.5). They are absent from the enum
*and* from this image's tables, which is exactly what one expects when the
captured panel and the disassembled image are different devices.

**No opcode is in the firmware tables and on the wire but missing from the
enum.** Where the panel image and the wire agree that an operation exists, the
enumeration knows about it. The enumeration is incomplete as a specification,
but it is not arbitrary.

One scope note that applies to all three: the firmware column is **a single
image**. An opcode absent from it may well be present in another panel
generation, so "firmware only" and "wire only" are statements about this image,
not about APOGEE panels in general. [F]

#### The high bands are a later protocol generation

Coverage by the firmware tables splits sharply by the function code's high byte:

| High byte | Present in these images |
|---|---|
| `0x00`–`0x09`, `0x41`, `0x42`, `0x45` | yes, near-completely |
| `0x40`, `0x44`, `0x46`, `0x48`, `0x49`, `0x4B`, `0x50`, `0x53`, `0xF0` | **no, entirely absent** |

That is not a gap in the extraction. These images are revision 2.6 and earlier;
the absent bands are present in the newer supervisor stack and are answered by
current panels on the wire. **The `0x46xx`, `0x48xx` and `0x50xx` families are a
later addition to the protocol.** [F][W]

For the unnamed `0x4646`–`0x4650` block this settles one question and reframes
another: these images cannot name it, and its absence from them is evidence of
the block's age rather than of its non-existence.

### 9.5 The catalog

The catalog below is generated by joining the vendor `AP2_Function_Code` enum (the 630 distinct opcode values) with the corpus census. A recount under stated criteria — trusted frames only, `dir == 0x00` only, content-deduplicated captures — gives **150 distinct opcode values across 314,273 request/push frames**, of which 135 carry a name from the enum. Two of the 150 are not operations at all (below), so **148 distinct operations** have been observed. (Three further values appear only in frames the parser marked untrusted after a resynchronisation: `0x0631`, `0x1826`, `0x2226`. `0x1826` is precisely the fictitious opcode a mid-record resync manufactures — a TLV length `0x18` followed by ASCII `&` — and is the reason the trusted flag exists. Editions of this document have cited 135, then 125, then 127; each was the honest count over the corpus held at the time, and the corpus has twice grown. The current figure is reproducible from the stated criteria by re-running the census.) Columns: hex opcode, name(s), observed wire count (or `-`), notes (destructive flag where applicable), and evidence tag ([W] wire-observed, [S] enum-defined). Within each family, rows are sorted by opcode value. Fifteen wire values do **not** appear in the catalog, because the enum does not define them, and they fall into three groups rather than one. **Four are artifacts.** `0x0C44` and `0x4443` are slot-walk misalignments of `0x4640`; `0x0000` and `0xFFFF` are the opcode field of a *deliberately malformed* test frame whose routing slots read `GARBAGEBLN` / `garbagenode` / `GARBAGE15CHARSXX`, sent once each to probe the handshake gate and never answered. Neither is an operation, and a reader reproducing the census should expect to see them and discard them. [W] **One is unimplemented:** `0x0510` drew `not_found`. [W] **The remaining ten — `0x4641`, `0x4642`, `0x4643`, `0x4647`, `0x464A`, `0x464B`, `0x464D`, `0x464E`, `0x464F`, `0x4650` — are real panel operations, and an earlier reading of this document that dismissed them as noise is withdrawn.** Absence from `AP2_Function_Code` proves nothing: that enum is the **supervisor-side** vocabulary and does not describe what a panel implements. Classify by what the panel did. `0x464A`–`0x4650` each answered `dir=0x01` **success with distinct structured bodies** (0 B, 22 B, 125 B, a 12,073-byte declared node table, 117 B, 26 B, 217 B respectively), and `0x4641` answered success, while `0x0510` — equally absent from the enum — answered `not_found` from the same panel in the same campaign. The `0x464D` reply is the sharpest case and needs stating precisely: the panel answered, and its response header **declared** 12,073 bytes of node table, of which **4,380 arrived** before the client reset the connection. No complete frame exists, so a strict framer reports the exchange as unanswered — it was not. A panel that begins streaming 12 KB of structured node table for one value and answers `not_found` to another is not treating them alike. `0x4642`/`0x4643` answered `not_supported`, i.e. a handler was reached and refused; `0x4647` returned nothing at all and remains **[OPEN]**. Low frame count is not evidence of unreality — it measures how often the *supervisor* uses an operation, and a panel-side operation the supervisor never invokes is expected to appear exactly once, when probed. [W]

<!-- BEGIN GENERATED CATALOG (do not hand-edit; regenerate with working/sweep/s91_gencatalog.py, which joins p2_data.py with the census of working/sweep/s90_census.py) -->

#### Family: NODE/STATE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0030 | AP2_SET_GLOBAL_DATA | - || [F] |
| 0x0031 | AP2_GET_GLOBAL_DATA | - || [S] |
| 0x0032 | AP2_REMOTE_NODE_CHECK | - || [S] |
| 0x0033 | AP2_GET_COMPLETE_NODE_STATE | - || [S] |
| 0x0034 | AP2_SET_NODE_STATE | - |**DESTRUCTIVE** (set node state)| [F] |
| 0x0035 | AP2_SET_COMPLETE_NODE_STATE | - |**DESTRUCTIVE** (set complete node state)| [S] |
| 0x0326 | AP2_GET_LOGGER_STATE | - || [S] |
| 0x0328 | AP2_GET_BUFFERALARM_STATE | - || [S] |
| 0x5301 | AP2_GET_FLN_TOPOLOGY | - || [S] |
| 0x5304 | AP2_GET_MEC_EXPBUS_TOPOLOGY | - || [S] |

#### Family: CABINET

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x003E | AP2_CABINET_TIMEOUT_NORMAL | - || [F] |
| 0x003F | AP2_CABINET_TIMEOUT_EXTENDED | - || [F] |
| 0x0041 | AP2_CABINET_ADD | - |**DESTRUCTIVE** (add cabinet to node table)| [S] |
| 0x0042 | AP2_CABINET_REMOVE | - |**DESTRUCTIVE** (remove cabinet from node table)| [F] |
| 0x0044 | AP2_CABINET_MAKE_READY | - || [F] |
| 0x0046 | AP2_CABINET_ONLINE | - |**DESTRUCTIVE** (force cabinet online)| [F] |
| 0x0047 | AP2_CABINET_OFFLINE | - |**DESTRUCTIVE** (force cabinet offline)| [F] |
| 0x0050 | AP2_DISK_LOG | 166 || [W] |
| 0x0051 | AP2_DISK_ADD | - || [S] |
| 0x0058 | AP2_REPORT_PRINTER_LOG | - || [F] |
| 0x0059 | AP2_REPORT_PRINTER_ADD | - || [S] |
| 0x0100 | AP2_DUMMY_CMD / AP2_REV_STRING | 9 || [W] |
| 0x0108 | AP2_CABINET_BOOT_MONITOR | - |**DESTRUCTIVE** (reboot to boot monitor)| [S] |
| 0x010A | AP2_CABINET_COLDSTART | 1 |**DESTRUCTIVE** (panel cold start (reboot))| [W] |
| 0x010B | AP2_CABINET_WARMSTART | - |**DESTRUCTIVE** (panel warm start (reboot))| [S] |
| 0x010C | AP2_CABINET_DISPLAY | 250 || [W] |
| 0x010D | AP2_SERVICES_RENDERED | - || [S] |
| 0x010E | AP2_SERVICES_RENDERED_CHANGED | - || [S] |
| 0x0120 | AP2_CABINET_SET_MMI1_BAUDRATE | - || [F] |
| 0x0121 | AP2_CABINET_SET_MMI2_BAUDRATE | - || [F] |
| 0x0123 | AP2_CABINET_SET_FLN1_BAUDRATE | - || [F] |
| 0x0124 | AP2_CABINET_SET_FLN2_BAUDRATE | - || [F] |
| 0x0125 | AP2_CABINET_SET_FLN3_BAUDRATE | - || [F] |
| 0x0126 | AP2_CABINET_SET_BLN_BAUDRATE | - || [F] |
| 0x0127 | AP2_CABINET_SET_PBUS_STATE | - || [F] |
| 0x0128 | AP2_CABINET_SET_BLN_ADDRESS | - || [F] |
| 0x0129 | AP2_CABINET_SET_MODEM_STATE | - || [F] |
| 0x012A | AP2_CABINET_COLDSTART_DISPLAY | - || [F] |
| 0x012B | AP2_CABINET_COLDSTART_CLEAR_HISTORY | - || [F] |
| 0x012F | AP2_CABINET_MEMORY_MODIFY | - |**DESTRUCTIVE** (modify panel memory)| [F] |
| 0x0130 | AP2_CABINET_MEMORY_DISPLAY | - || [F] |
| 0x0131 | AP2_CABINET_MEMORY_AVAILABLE | - || [F] |
| 0x400E | AP2_REPORT_DESC_ADD | - || [S] |
| 0x4011 | AP2_REPORT_DESC_UPLOAD | 19 || [W] |

#### Family: BLN/DIAG

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x005B | AP2_BLN_DIAGNOSTICS_DISPLAY | - || [F] |
| 0x005C | AP2_RESET_BLN_DIAGNOSTIC_COUNTERS | - || [F] |

#### Family: LICENSE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x010F | AP2_LICENSE_MANAGER_DISPLAY | - || [S] |
| 0x0110 | AP2_LICENSE_MANAGER_ADD | - || [S] |
| 0x0111 | AP2_LICENSE_MANAGER_DELETE | - |**DESTRUCTIVE** (delete license)| [S] |
| 0x0112 | AP2_LICENSE_MANAGER_DELETE_ALL | - |**DESTRUCTIVE** (delete all licenses)| [S] |
| 0x0113 | AP2_LICENSE_MANAGER_DBCHANGE | - || [S] |
| 0x0114 | AP2_LICENSE_MANAGER_DISPLAY_LICENSE | - || [S] |
| 0x0116 | AP2_LICENSE_MANAGER_MESSAGE_SEND | - || [S] |

#### Family: ROUTING

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0136 | AP2_P2_ROUTE | - || [S] |
| 0x030E | AP2_ROUTE_OBJECT | - || [F] |
| 0x0310 | AP2_PB_POLL | - || [S] |

#### Family: PBUS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0140 | AP2_PBUS_MODULE_DISPLAY | - || [F] |
| 0x0142 | AP2_PBUS_DIAGS_RESET | - || [S] |
| 0x0143 | AP2_PBUS_LINETEST | - || [S] |

#### Family: POINT

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0200 | AP2_POINT_ADD | - || [F] |
| 0x0201 | AP2_POINT_ADD_LDO | - || [F] |
| 0x0202 | AP2_POINT_ADD_LDI | - || [F] |
| 0x0203 | AP2_POINT_ADD_LAO | 2 || [W] |
| 0x0204 | AP2_POINT_ADD_LAI | 8 || [W] |
| 0x0205 | AP2_POINT_ADD_L2SL | - || [F] |
| 0x0206 | AP2_POINT_ADD_L2SP | - || [F] |
| 0x0207 | AP2_POINT_ADD_LFSSL | - || [F] |
| 0x0208 | AP2_POINT_ADD_LFSSP | - || [F] |
| 0x0209 | AP2_POINT_ADD_LOOAL | - || [F] |
| 0x020A | AP2_POINT_ADD_LOOAP | - || [F] |
| 0x020B | AP2_POINT_ADD_LPACI | - || [F] |
| 0x020C | AP2_POINT_ADD_LDAO | - || [S] |
| 0x020D | AP2_POINT_ADD_LFMSSL | - || [S] |
| 0x020E | AP2_POINT_ADD_LFMSSP | - || [S] |
| 0x020F | AP2_POINT_ADD_LENUM | - || [S] |
| 0x0220 | AP2_POINT_LOG_VALUE | 6942 || [W] |
| 0x0221 | AP2_POINT_LOG_ALARM | - || [F] |
| 0x0222 | AP2_POINT_LOG_CTRL_STAT | - || [F] |
| 0x0223 | AP2_POINT_LOG_FAILED | - || [F] |
| 0x0224 | AP2_POINT_LOG_TOTAL | - || [S] |
| 0x0225 | AP2_POINT_LOG_PRIORITY | - || [F] |
| 0x0226 | AP2_POINT_LOG_DISABLED | - || [F] |
| 0x0227 | AP2_POINT_LOG_TYPE | - || [F] |
| 0x0228 | AP2_POINT_LOG_TROUBLE | - || [F] |
| 0x0229 | AP2_POINT_LOG_ANY | - || [F] |
| 0x022A | AP2_POINT_LOG_ODSB | - || [S] |
| 0x022B | AP2_POINT_LOG_PDSB | - || [S] |
| 0x022C | AP2_POINT_LOG_ALARM_CMD | - || [S] |
| 0x0240 | AP2_POINT_CMD_VALUE | 32521 |**DESTRUCTIVE** (point command (write value))| [W] |
| 0x0241 | AP2_POINT_CMD_PRIORITY | 60 |**DESTRUCTIVE** (point command (write priority))| [W] |
| 0x0242 | AP2_POINT_CMD_ENABLE | - || [F] |
| 0x0243 | AP2_POINT_CMD_DISABLE | - || [F] |
| 0x0244 | AP2_POINT_CMD_ALARM | 27 || [W] |
| 0x0245 | AP2_POINT_CMD_NORMAL | 5 || [W] |
| 0x0246 | AP2_POINT_CMD_ALARM_ENABLE | 3 || [W] |
| 0x0247 | AP2_POINT_CMD_ALARM_DISABLE | 5 || [W] |
| 0x0248 | AP2_POINT_CMD_INIT_LPACI | - || [F] |
| 0x0249 | AP2_POINT_CMD_LOWLIMIT | - || [F] |
| 0x024A | AP2_POINT_CMD_HIGHLIMIT | - || [F] |
| 0x024B | AP2_POINT_CMD_TOTALIZER | - || [F] |
| 0x024C | AP2_POINT_CMD_INTO_TROUBLE | - || [F] |
| 0x024D | AP2_POINT_CMD_OUTOF_TROUBLE | - || [F] |
| 0x024E | AP2_POINT_CMD_RELEASE | - || [S] |
| 0x0260 | AP2_POINT_MODIFY | 2 || [W] |
| 0x0261 | AP2_POINT_LOOK | - || [F] |
| 0x0262 | AP2_POINT_DEFINITION_DISPLAY | - || [F] |
| 0x0263 | AP2_POINT_REMOVE | 6 || [W] |
| 0x0264 | AP2_POINT_DEFINITION_BYADDR_DISPLAY | - || [F] |
| 0x0265 | AP2_POINT_QUERY_NAME | - || [F] |
| 0x02E0 | AP2_POINT_TOTAL_ENABLE | - || [F] |
| 0x02E1 | AP2_POINT_TOTAL_DISABLE | - || [F] |
| 0x02E2 | AP2_POINT_TOTAL_DISPLAY | - || [F] |
| 0x0300 | AP2_POINT_SET_PREFIX | - || [S] |
| 0x0309 | AP2_POINT_SAVE | - || [F] |

#### Family: COV

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0271 | AP2_COV_ENABLE | 7359 || [W] |
| 0x0272 | AP2_COV_DELETE_STUB | 222 || [W] |
| 0x0273 | AP2_COV_DISABLE | 6043 || [W] |
| 0x0274 | AP2_COV_ANNUNCIATE | 120764 || [W] |
| 0x0275 | AP2_XREF_COV_DISPLAY | - || [F] |

#### Family: MONITOR

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0280 | AP2_MONITOR_ADD_NAME | - || [S] |
| 0x0281 | AP2_MONITOR_REMOVE_NAME | - || [S] |
| 0x0282 | AP2_MONITOR_START | - || [S] |

#### Family: TREND

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0290 | AP2_TREND_SETUP_ADD | - || [S] |
| 0x0291 | AP2_TREND_SETUP_DELETE | 14 || [W] |
| 0x0292 | AP2_TREND_ENABLE | - || [S] |
| 0x0293 | AP2_TREND_DISABLE | - || [S] |
| 0x0294 | AP2_TREND_SETUP_LOG | 59 || [W] |
| 0x0295 | AP2_TREND_DATA_DISPLAY | 750 || [W] |
| 0x0296 | AP2_TREND_DEFINITION_DISPLAY | - || [S] |
| 0x0297 | AP2_TREND_MULTIPOINT_DISPLAY | - || [F] |
| 0x0298 | AP2_TREND_SETUP_MODIFY | - || [S] |
| 0x0299 | AP2_TREND_MODIFY | - || [S] |
| 0x029A | AP2_TREND_SETUP_COPY | - || [S] |
| 0x029B | AP2_TREND_COPY | - || [S] |
| 0x029C | AP2_TREND_LOOK | - || [F] |
| 0x029D | AP2_TREND_QUERY_SINGLE_NAME | - || [F] |
| 0x029E | AP2_TREND_QUERY_NAMES | - || [F] |
| 0x029F | AP2_TREND_QUERY_TRENDS | - || [F] |
| 0x02A0 | AP2_TREND_ARC_SETUP | - || [S] |
| 0x02A1 | AP2_TREND_ARC_DATA_UPLOAD | - || [S] |
| 0x02A2 | AP2_TREND_ARC_UPLOAD_ME | - || [S] |
| 0x02A5 | AP2_TREND_EVENT_SETUP_ADD | - || [S] |
| 0x02A6 | AP2_TREND_EVENT_MODIFY | - || [S] |
| 0x02A7 | AP2_TREND_EVENT_COPY | - || [S] |
| 0x02A8 | AP2_TREND_EVENT_ARC_SETUP | 8 || [W] |
| 0x02A9 | AP2_TREND_EVENT_ARC_ENABLE | - || [S] |

#### Family: TOD/TIME

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0301 | AP2_TIME_DISPLAY / AP2_TIME_SOFTWARE | - || [S] |
| 0x0302 | AP2_TIME_DISPLAY_CLOCK / AP2_TIME_SET | 3 || [W] |
| 0x4500 | AP2_TOD_POINT_ADD | 5 || [W] |
| 0x4501 | AP2_TOD_POINT_REMOVE | - || [F] |
| 0x4502 | AP2_TOD_POINT_ENABLE | - || [F] |
| 0x4503 | AP2_TOD_POINT_DISABLE | - || [F] |
| 0x4504 | AP2_TOD_CMD_ADD | - || [F] |
| 0x4505 | AP2_TOD_CMD_REMOVE | - || [F] |
| 0x4506 | AP2_TOD_CMD_DISABLE | - || [S] |
| 0x450E | AP2_TOD_POINT_DISPLAY | - || [F] |
| 0x450F | AP2_TOD_CMD_DISPLAY | - || [F] |

#### Family: MISC

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0303 | AP2_MESSAGE_SEND / AP2_MESSAGE | - || [F] |
| 0x0306 | AP2_QUICK_KEYS | - || [S] |
| 0x030C | AP2_TOGGLE_DEVELOPMENT | - || [S] |
| 0x0311 | AP2_PRINT_ERROR | - || [S] |

#### Family: SESSION

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0304 | AP2_LOGON_CEC | - || [S] |
| 0x0305 | AP2_LOGOFF_CEC | - || [S] |

#### Family: DATABASE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0307 | AP2_LOAD_DATABASE | - || [S] |
| 0x0308 | AP2_SAVE_DATABASE | - || [S] |
| 0x030B | AP2_TAPE_TRAILER | - || [S] |

#### Family: PPCL

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x030A | AP2_PPCL_SAVE | - || [S] |
| 0x4100 | AP2_PPCL_ADD_LINE | 3 || [W] |
| 0x4101 | AP2_PPCL_EDIT_LINE | - || [S] |
| 0x4103 | AP2_PPCL_REMOVE_LINES | 3 || [W] |
| 0x4104 | AP2_PPCL_ENABLE_LINES | 7 || [W] |
| 0x4105 | AP2_PPCL_DISABLE_LINES | 2 || [W] |
| 0x4106 | AP2_PPCL_CLEAR_TRACE | 5 || [W] |
| 0x4107 | AP2_PPCL_PROGRAM_LOG | 8 || [W] |
| 0x4108 | AP2_PPCL_SEARCH_NAME_TYPE | - || [F] |
| 0x4109 | AP2_PPCL_QUERY_PROGRAM | - || [F] |
| 0x410A | AP2_PPCL_PROGRAM_DISPLAY | - || [F] |
| 0x410B | AP2_PPCL_MODIFY_LINE | - || [S] |
| 0x410C | AP2_PPCL_COPY_LINE | - || [F] |
| 0x410D | AP2_PPCL_SETUP_MODIFY_LINE | - || [S] |
| 0x410E | AP2_PPCL_LOOK_LINES | - || [F] |
| 0x410F | AP2_PPCL_PDL_RESET | - || [F] |
| 0x4110 | AP2_PPCL_PDL_INIT | - || [F] |
| 0x4111 | AP2_PPCL_PDL_DISPLAY | - || [F] |
| 0x412A | AP2_PPCL_PROGRAM_DISPLAY_UNRESOLVED | - || [F] |
| 0x4134 | AP2_PROGRAM_ADD | - || [S] |
| 0x4135 | AP2_PROGRAM_REMOVE | - || [S] |
| 0x4137 | AP2_PROGRAM_LOG | - || [S] |
| 0x4138 | AP2_PROGRAM_MODIFY | - || [S] |

#### Family: COLBAS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x030D | AP2_COLBAS_TEST | - || [S] |
| 0x4A00 | AP2_COLBAS_IMMEDIATE | - || [S] |
| 0x4A01 | AP2_COLBAS_CONNECT | - || [S] |
| 0x4A02 | AP2_COLBAS_DISCONNECT | - || [S] |
| 0x4A03 | AP2_COLBAS_WRITE | - |**DESTRUCTIVE** (COLBAS write)| [S] |
| 0x4A04 | AP2_COLBAS_ABORT | - |**DESTRUCTIVE** (COLBAS abort)| [S] |
| 0x4A05 | AP2_COLBAS_UPLOAD_BEGIN | - || [S] |
| 0x4A06 | AP2_COLBAS_UPLOAD_CONTINUE | - || [S] |

#### Family: P1/FLN

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x030F | AP2_P1_POLL | - || [S] |
| 0x0313 | AP2_P1_ROUTE | - || [F] |
| 0x0314 | AP2_P1_LINETEST | - || [F] |
| 0x0317 | AP2_P1_RESET_COUNTERS | - || [F] |
| 0x4230 | AP2_FLN_SCAN_ENABLE | - || [S] |
| 0x4231 | AP2_FLN_SCAN_DISABLE | - || [S] |
| 0x4232 | AP2_P1_DIAGNOSTICS_LOG | - || [F] |

#### Family: ENVELOPE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0316 | AP2_OPEN_ENVELOPE | - || [F] |
| 0x031B | AP2_ENVELOPE_OPEN_DEST | - || [S] |
| 0x031C | AP2_ENVELOPE_CLOSE_DEST | - || [S] |
| 0x031D | AP2_ENVELOPE_OPEN_TEXT | - || [S] |
| 0x031E | AP2_ENVELOPE_CLOSE_TEXT | - || [S] |
| 0x031F | AP2_ENVELOPE_OPEN_USERS | - || [S] |
| 0x0320 | AP2_ENVELOPE_CLOSE_USERS | - || [S] |

#### Family: LOGGER

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0325 | AP2_SETUP_LOGGER | - || [S] |
| 0x0327 | AP2_SETUP_BUFFERALARM | - || [S] |

#### Family: USER/ACCESS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0330 | AP2_USER_ACCT_LOG | - || [S] |
| 0x0331 | AP2_USER_ACCT_DISPLAY | - || [S] |
| 0x0332 | AP2_USER_ACCT_ADD | - || [S] |
| 0x0333 | AP2_USER_ACCT_MODIFY | - || [S] |
| 0x0334 | AP2_USER_ACCT_COPY | - || [S] |
| 0x0335 | AP2_USER_ACCT_DELETE | - || [S] |
| 0x0336 | AP2_USER_ACCT_LOOK | - || [S] |
| 0x0337 | AP2_USER_ACCT_DB_GET | - || [S] |
| 0x0338 | AP2_USER_ACCT_DB_REPLACE | - || [S] |
| 0x0350 | AP2_ACCESS_GROUPS_LOG | - || [S] |
| 0x0353 | AP2_ACCESS_GROUPS_MODIFY | - || [S] |
| 0x0357 | AP2_ACCESS_GROUPS_DB_GET | - || [S] |
| 0x0358 | AP2_ACCESS_GROUPS_DB_REPLACE | - || [S] |

#### Family: EMS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0360 | AP2_EMS_DIAL_ENABLE | - || [F] |
| 0x0361 | AP2_EMS_DIAL_DISABLE | - || [F] |
| 0x0362 | AP2_EMS_DB_REPLACE | - || [S] |
| 0x0363 | AP2_EMS_DB_GET | - || [S] |
| 0x0364 | AP2_EMS_DB_DISPLAY | - || [S] |
| 0x0365 | AP2_EMS_ENTRY_REPLACE | - || [F] |
| 0x0366 | AP2_EMS_DB_GET_DIALFLAGS | - || [F] |
| 0x0367 | AP2_EMS_DB_GET_DESTINATIONS | - || [S] |
| 0x0368 | AP2_EMS_PRINT | 8 || [W] |

#### Family: ENUM

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0401 | AP2_ENUM_TYPE_ADD | - || [S] |
| 0x0402 | AP2_ENUM_TYPE_DELETE | - || [S] |
| 0x0403 | AP2_ENUM_TYPE_DB_DELETE | - || [S] |
| 0x0404 | AP2_ENUM_TYPE_DISPLAY | - || [S] |
| 0x0405 | AP2_ENUM_TYPE_LOOK | - || [S] |
| 0x0406 | AP2_ENUM_TYPE_LOG | - || [S] |
| 0x0407 | AP2_ENUM_ELEMENT_ADD | - || [S] |
| 0x0408 | AP2_ENUM_ELEMENT_DELETE | - || [S] |
| 0x0409 | AP2_ENUM_ELEMENT_MODIFY | - || [S] |
| 0x040A | AP2_ENUM_TYPE_DB_GET | 28 || [W] |
| 0x040B | AP2_ENUM_TYPE_DB_REPLACE | - || [S] |
| 0x040E | AP2_ENUM_TYPE_REPLACE | - || [S] |

#### Family: ALARM

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0500 | AP2_ALARM_SETUP | - || [S] |
| 0x0501 | AP2_ALARM_REMOVE | - || [F] |
| 0x0502 | AP2_ALARM_POINT_QUERY_LIST_EALARMABLE | - || [F] |
| 0x0503 | AP2_ALARM_POINT_QUERY_REC_EALARMABLE | - || [F] |
| 0x0504 | AP2_ALARM_POINT_SETUP_QUERY_LIST | - || [F] |
| 0x0505 | AP2_ALARM_POINT_SETUP_QUERY_RECORD | - || [F] |
| 0x0506 | AP2_ALARM_SETUP_COPY | - || [S] |
| 0x0507 | AP2_ALARM_SETUP_MODIFY | - || [S] |
| 0x0508 | AP2_ALARM_PRINT | 71 || [W] |
| 0x0509 | AP2_ALARM_ACK | 7 || [W] |
| 0x050A | AP2_ALARM_ACK_PENDING_QUERY_LIST | - || [S] |
| 0x050B | AP2_ALARM_SETUP_DISPLAY_BY_MODE | - || [F] |
| 0x050C | AP2_ALARM_SETUP_DISPLAY_BY_CATEGORY | - || [F] |
| 0x050D | AP2_ALARM_SETUP_DISPLAY | - || [F] |
| 0x0520 | AP2_ALARM_MODE_ADD | 1 || [W] |
| 0x0521 | AP2_ALARM_MODE_COPY | - || [F] |
| 0x0522 | AP2_ALARM_MODE_LISTBY_SETPOINT_NAME | - || [F] |
| 0x0523 | AP2_ALARM_MODE_LISTBY_PRIORITY | - || [F] |
| 0x0524 | AP2_ALARM_MODE_LISTBY_SETPOINT_VALUE | - || [F] |
| 0x0525 | AP2_ALARM_MODE_DEFINITION_DISPLAY | - || [F] |
| 0x0526 | AP2_ALARM_MODE_LOOK | - || [F] |
| 0x0528 | AP2_ALARM_MODE_MODIFY | - || [S] |
| 0x0529 | AP2_ALARM_MODE_QUERY_RECORD | - || [F] |
| 0x052B | AP2_ALARM_MODE_DELETE | - || [F] |
| 0x052C | AP2_ALARM_MODE_LISTBY_CATEGORY | - || [F] |
| 0x052D | AP2_ALARM_MODE_LISTBY_MESSAGE | - || [F] |
| 0x0530 | AP2_ALARM_MODE_QUERY_LIST | - || [F] |
| 0x0540 | AP2_CATEGORY_ADD | 1 || [W] |
| 0x0541 | AP2_CATEGORY_REMOVE | 14 || [W] |
| 0x0542 | AP2_CATEGORY_DESCRIPTOR | 1 || [W] |
| 0x0543 | AP2_CATEGORY_ENABLE_DIAL | 1 || [W] |
| 0x0544 | AP2_CATEGORY_ENABLE_PRINT | 1 || [W] |
| 0x0545 | AP2_CATEGORY_DIAL_DISABLE | 1 || [W] |
| 0x0546 | AP2_CATEGORY_PRINT_DISABLE | 1 || [W] |
| 0x0547 | AP2_CATEGORY_DB_GET | 1 || [W] |
| 0x0548 | AP2_CATEGORY_LOG | 1 || [W] |
| 0x0549 | AP2_CATEGORY_NODES_APPEND | 13 || [W] |
| 0x054A | AP2_CATEGORY_NODES_REMOVE | 1 || [W] |
| 0x054B | AP2_CATEGORY_QUERY_LIST | 1 || [W] |
| 0x054C | AP2_CATEGORY_DEFAULT_DB_GET | 1 || [W] |
| 0x054D | AP2_CATEGORY_REPLACE | 1 || [W] |
| 0x0560 | AP2_ALARM_MESSAGE_LOOK | 1 || [W] |
| 0x0561 | AP2_ALARM_MESSAGE_ENABLE | 1 || [W] |
| 0x0562 | AP2_ALARM_MESSAGE_DISABLE | 1 || [W] |
| 0x0563 | AP2_ALARM_MESSAGE_DELETE | 1 || [W] |
| 0x0564 | AP2_ALARM_MESSAGE_COPY | 1 || [W] |
| 0x0565 | AP2_ALARM_MESSAGE_ADD | 1 || [W] |
| 0x0566 | AP2_ALARM_MESSAGE_QUERY_RECORD | 1 || [W] |
| 0x0567 | AP2_ALARM_MESSAGE_LOG | 1 || [W] |
| 0x0568 | AP2_ALARM_MESSAGE_QUERY_LIST | 1 || [W] |
| 0x056A | AP2_ALARM_MESSAGE_MODIFY | - || [S] |

#### Family: CAL/DST

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0600 | AP2_CAL_DATE_ADD | - || [F] |
| 0x0601 | AP2_CAL_DATE_RESET | - || [F] |
| 0x0602 | AP2_CAL_DB_ADD | - || [S] |
| 0x0603 | AP2_CAL_DB_RESET | - || [F] |
| 0x0604 | AP2_CAL_DB_DISPLAY | - || [F] |
| 0x0605 | AP2_CAL_DB_GET_HOL_SPEC | - || [F] |
| 0x0606 | AP2_CAL_DB_GET_OTHER | 41 || [W] |
| 0x0610 | AP2_DST_YEAR_ADD | - || [F] |
| 0x0611 | AP2_DST_YEAR_DELETE | - || [F] |
| 0x0612 | AP2_DST_DB_ADD | - || [S] |
| 0x0613 | AP2_DST_DB_DELETE | - || [F] |
| 0x0614 | AP2_DST_DB_DISPLAY | - || [F] |
| 0x0615 | AP2_DST_DB_GET | - || [F] |

#### Family: LANGUAGE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0900 | AP2_LANGUAGE_GET_STRING | - || [S] |
| 0x0901 | AP2_LANGUAGE_GET_PROMPT | - || [S] |
| 0x0902 | AP2_LANGUAGE_REPORT_DATA | - || [S] |

#### Family: UPL

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0950 | AP2_DOWNLOAD_ME | - || [S] |
| 0x0961 | AP2_UPL_DEL_POINT | 25 || [W] |
| 0x0962 | AP2_UPL_DEL_ALARM_SETUP | - || [F] |
| 0x0963 | AP2_UPL_DEL_ALARM_MODE | - || [F] |
| 0x0964 | AP2_UPL_DEL_TREND | 26 || [W] |
| 0x0965 | AP2_UPL_DEL_PPCL | 16 || [W] |
| 0x0966 | AP2_UPL_DEL_TEC | 11 || [W] |
| 0x0967 | AP2_UPL_DEL_EQS_ZONE | 6 || [W] |
| 0x0968 | AP2_UPL_DEL_EQS_CMD_TABLE | - || [S] |
| 0x0969 | AP2_UPL_DEL_EQS_MODE_SCHED | 26 || [W] |
| 0x096A | AP2_UPL_DEL_LOOP | - || [S] |
| 0x096B | AP2_UPL_DEL_ALARM_MESSAGE | - || [F] |
| 0x0971 | AP2_UPL_ADDED_POINT | 32 || [W] |
| 0x0972 | AP2_UPL_ADDED_ALARM_SETUP | - || [F] |
| 0x0973 | AP2_UPL_ADDED_ALARM_MODE | - || [F] |
| 0x0974 | AP2_UPL_ADDED_TREND | 21 || [W] |
| 0x0975 | AP2_UPL_ADDED_PPCL | 23 || [W] |
| 0x0976 | AP2_UPL_ADDED_TEC | 22 || [W] |
| 0x0977 | AP2_UPL_ADDED_EQS_ZONE | 6 || [W] |
| 0x0978 | AP2_UPL_ADDED_EQS_CMD_TABLE | - || [S] |
| 0x0979 | AP2_UPL_ADDED_EQS_MODE_SCHED | 26 || [W] |
| 0x097A | AP2_UPL_ADDED_LOOP | - || [S] |
| 0x097B | AP2_UPL_ADDED_ALARM_MESSAGE | - || [F] |
| 0x097C | AP2_UPL_ADDED_SSTO_GENERAL | 8 || [W] |
| 0x097D | AP2_UPL_ADDED_SSTO_START | 8 || [W] |
| 0x097E | AP2_UPL_ADDED_SSTO_STOP | 8 || [W] |
| 0x097F | AP2_UPL_ADDED_SSTO_NIGHT | 8 || [W] |
| 0x0981 | AP2_UPL_ALL_POINT | 12547 || [W] |
| 0x0982 | AP2_UPL_ALL_ALARM_SETUP | 27 || [W] |
| 0x0983 | AP2_UPL_ALL_ALARM_MODE | 27 || [W] |
| 0x0984 | AP2_UPL_ALL_TREND | 288 || [W] |
| 0x0985 | AP2_UPL_ALL_PPCL | 2672 || [W] |
| 0x0986 | AP2_UPL_ALL_TEC | 1049 || [W] |
| 0x0987 | AP2_UPL_ALL_EQS_ZONE | 81 || [W] |
| 0x0988 | AP2_UPL_ALL_EQS_CMD_TABLE | 601 || [W] |
| 0x0989 | AP2_UPL_ALL_EQS_MODE_SCHED | 114 || [W] |
| 0x098B | AP2_UPL_ALL_ALARM_MESSAGE | 19 || [W] |
| 0x098C | AP2_UPL_ALL_SSTO_GENERAL | 81 || [W] |
| 0x098D | AP2_UPL_ALL_SSTO_START | 81 || [W] |
| 0x098E | AP2_UPL_ALL_SSTO_STOP | 81 || [W] |
| 0x098F | AP2_UPL_ALL_SSTO_NIGHT | 81 || [W] |
| 0x099D | AP2_UPL_DEL_PORT | - || [F] |
| 0x099E | AP2_UPL_ADDED_PORT | - || [F] |
| 0x099F | AP2_UPL_ALL_PORT | 114 || [W] |
| 0x09A1 | AP2_UPL_DEL_PARTNER | - || [F] |
| 0x09A2 | AP2_UPL_ADDED_PARTNER | - || [F] |
| 0x09A3 | AP2_UPL_ALL_PARTNER | 19 || [W] |
| 0x09A5 | AP2_UPL_DEL_EQS_OVERRIDE | - || [S] |
| 0x09A6 | AP2_UPL_ADDED_EQS_OVERRIDE | - || [S] |
| 0x09A7 | AP2_UPL_ALL_EQS_OVERRIDE | 19 || [W] |
| 0x09A9 | AP2_UPL_DEL_UC | - || [F] |
| 0x09AA | AP2_UPL_ADDED_UC | - || [F] |
| 0x09AB | AP2_UPL_ALL_UC | 19 || [W] |
| 0x09B1 | AP2_UPL_DEL_TOD_POINT | - || [F] |
| 0x09B2 | AP2_UPL_ADDED_TOD_POINT | - || [F] |
| 0x09B3 | AP2_UPL_ALL_TOD_POINT | - || [F] |
| 0x09B5 | AP2_UPL_DEL_TOD_CMD | - || [F] |
| 0x09B6 | AP2_UPL_ADDED_TOD_CMD | - || [F] |
| 0x09B7 | AP2_UPL_ALL_TOD_CMD | - || [F] |
| 0x09B9 | AP2_UPL_DEL_LON | - || [S] |
| 0x09BA | AP2_UPL_ADDED_LON | - || [S] |
| 0x09BB | AP2_UPL_ALL_LON | 19 || [W] |
| 0x09BD | AP2_UPLD_COMND_REPORT | - || [S] |
| 0x09BF | AP2_UPLD_MISCDATA_REPORT | - || [S] |
| 0x09C1 | AP2_UPL_DEL_MSTP_DEVICE | - || [S] |
| 0x09C2 | AP2_UPL_ADDED_MSTP_DEVICE | - || [S] |
| 0x09C3 | AP2_UPL_ALL_MSTP_DEVICE | 1 || [W] |
| 0x4131 | AP2_UPL_DEL_PROGRAM | - || [S] |
| 0x4132 | AP2_UPL_ADDED_PROGRAM | - || [S] |
| 0x4133 | AP2_UPL_ALL_PROGRAM | 19 || [W] |

#### Family: DBCHANGE

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x0951 | AP2_DBCHANGE_POINT | 19 || [W] |
| 0x0952 | AP2_DBCHANGE_ALARM_SETUP | - || [S] |
| 0x0953 | AP2_DBCHANGE_ALARM_MODE | - || [S] |
| 0x0954 | AP2_DBCHANGE_TREND | 14 || [W] |
| 0x0955 | AP2_DBCHANGE_PPCL | 13 || [W] |
| 0x0956 | AP2_DBCHANGE_CONTROLLER | 11 || [W] |
| 0x0957 | AP2_DBCHANGE_EQS_ZONE | 4 || [W] |
| 0x0958 | AP2_DBCHANGE_EQS_CMD_TABLE | - || [S] |
| 0x0959 | AP2_DBCHANGE_EQS_MODE_SCHED | 16 || [W] |
| 0x095A | AP2_DBCHANGE_LOOP | - || [S] |
| 0x095B | AP2_DBCHANGE_ALARM_MESSAGE | - || [S] |
| 0x095C | AP2_DBCHANGE_SSTO_GENERAL | 4 || [W] |
| 0x095D | AP2_DBCHANGE_SSTO_START | 4 || [W] |
| 0x095E | AP2_DBCHANGE_SSTO_STOP | 4 || [W] |
| 0x095F | AP2_DBCHANGE_SSTO_NIGHT | 4 || [W] |
| 0x099C | AP2_DBCHANGE_PORT | - || [S] |
| 0x09A0 | AP2_DBCHANGE_PARTNER | - || [S] |
| 0x09A4 | AP2_DBCHANGE_EQS_OVERRIDE | - || [S] |
| 0x09A8 | AP2_DBCHANGE_UC | - || [S] |
| 0x09B0 | AP2_DBCHANGE_TOD_POINT | - || [S] |
| 0x09B4 | AP2_DBCHANGE_TOD_CMD | - || [S] |
| 0x09B8 | AP2_DBCHANGE_LON | - || [S] |
| 0x09BC | AP2_DBCHANGE_COMMAND_REPORT | - || [S] |
| 0x09BE | AP2_DBCHANGE_MISCDATA_REPORT | - || [S] |
| 0x09C0 | AP2_DBCHANGE_MSTP_DEVICE | - || [S] |
| 0x4130 | AP2_DBCHANGE_PROGRAM | - || [S] |
| 0x5356 | AP2_DBCHANGE_HOA_MAP | - || [S] |

#### Family: RACS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x2824 | AP2_RACS_SYSTEM_DISPLAY | - || [S] |
| 0x3800 | AP2_RACS_PARTNER_ADD | - || [S] |
| 0x3801 | AP2_RACS_PARTNER_COPY | - || [S] |
| 0x3802 | AP2_RACS_PARTNER_DELETE | - || [S] |
| 0x3803 | AP2_RACS_PARTNER_DISABLE | - || [S] |
| 0x3804 | AP2_RACS_PARTNER_DISPLAY | - || [S] |
| 0x3805 | AP2_RACS_PARTNER_ENABLE | - || [S] |
| 0x3806 | AP2_RACS_PARTNER_LOG | - || [S] |
| 0x3807 | AP2_RACS_PARTNER_LOOK | - || [S] |
| 0x3808 | AP2_RACS_PARTNER_MODIFY | - || [S] |
| 0x3809 | AP2_RACS_PARTNER_STATLOG | - || [S] |
| 0x380A | AP2_RACS_PARTNER_STATLOG_RESET | - || [S] |
| 0x3810 | AP2_RACS_PORT_ADD | - || [S] |
| 0x3811 | AP2_RACS_PORT_COPY | - || [S] |
| 0x3812 | AP2_RACS_PORT_DELETE | - || [S] |
| 0x3813 | AP2_RACS_PORT_DISABLE | - || [S] |
| 0x3814 | AP2_RACS_PORT_DISPLAY | - || [S] |
| 0x3815 | AP2_RACS_PORT_ENABLE | - || [S] |
| 0x3816 | AP2_RACS_PORT_LOG | - || [S] |
| 0x3817 | AP2_RACS_PORT_LOOK | - || [S] |
| 0x3818 | AP2_RACS_PORT_MODIFY | - || [S] |
| 0x3819 | AP2_RACS_PORT_STATLOG | - || [S] |
| 0x381A | AP2_RACS_PORT_STATLOG_RESET | - || [S] |
| 0x3820 | AP2_RACS_SYSTEM_ADD | - || [S] |
| 0x3821 | AP2_RACS_SYSTEM_COPY | - || [S] |
| 0x3822 | AP2_RACS_SYSTEM_DELETE | - || [S] |
| 0x3823 | AP2_RACS_SYSTEM_DISABLE | - || [S] |
| 0x3825 | AP2_RACS_SYSTEM_ENABLE | - || [S] |
| 0x3826 | AP2_RACS_SYSTEM_LOG | - || [S] |
| 0x3827 | AP2_RACS_SYSTEM_LOOK | - || [S] |
| 0x3828 | AP2_RACS_SYSTEM_MODIFY | - || [S] |
| 0x3829 | AP2_RACS_SYSTEM_STATLOG | - || [S] |
| 0x382A | AP2_RACS_SYSTEM_STATLOG_RESET | - || [S] |

#### Family: TEAM

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4000 | AP2_TEAM_LOG / AP2_APPLICATION_LOG | - || [S] |
| 0x4001 | AP2_TEAM_DESC_ADD / AP2_APPLICATION_DISPLAY | - || [S] |
| 0x4002 | AP2_MEMBER_DESC_ADD_ANALOG | - || [S] |
| 0x4003 | AP2_MEMBER_DESC_ADD_DIGITAL | - || [S] |
| 0x4004 | AP2_MEMBER_DESC_ADD_ENUM | - || [S] |
| 0x4005 | AP2_MEMBER_DESC_ADD_LPACI | - || [S] |
| 0x4006 | AP2_MEMBER_DESC_ADD_L2SL | - || [S] |
| 0x400B | AP2_TEAM_MEMBER_LOG | - || [S] |
| 0x400C | AP2_TEAM_REPORT_LOG | - || [S] |
| 0x400D | AP2_TEAM_REPORT_LIST | - || [S] |
| 0x400F | AP2_TEAM_DESC_UPLOAD | 38 || [W] |
| 0x4010 | AP2_MEMBER_DESC_UPLOAD | 19 || [W] |
| 0x4015 | AP2_TEAM_DESC_DB_CHANGE | - || [S] |
| 0x4016 | AP2_TEAM_MEMBER_DB_CHANGE | - || [S] |
| 0x4017 | AP2_TEAM_DESC_UPLOAD_ADDED | - || [S] |
| 0x4018 | AP2_TEAM_MEMBER_UPLOAD_ADDED | - || [S] |

#### Family: TEC

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4200 | AP2_CONTROLLER_LOG / AP2_TEC_LOG | 248 || [W] |
| 0x4201 | AP2_TEC_ADD | - || [S] |
| 0x4202 | AP2_TEC_COPY | - || [F] |
| 0x4203 | AP2_TEC_MODIFY / AP2_CONTROLLER_MODIFY | - || [S] |
| 0x4204 | AP2_CONTROLLER_REMOVE / AP2_TEC_REMOVE | - || [F] |
| 0x4205 | AP2_TEC_LOOK / AP2_CONTROLLER_LOOK | - || [F] |
| 0x4206 | AP2_TEC_QUERY_RECORD / AP2_CONTROLLER_QUERY | - || [F] |
| 0x4207 | AP2_TEC_QUERY_LIST | - || [S] |
| 0x4208 | AP2_TEC_DEFINITION | 1 || [W] |
| 0x4210 | AP2_TEC_MEMBER_LOG | - || [F] |
| 0x4211 | AP2_TEC_REPORT_LOG | - || [F] |
| 0x4212 | AP2_TEC_REPORT_QUERY_LIST | - || [F] |
| 0x4220 | AP2_TEC_LOCAL_INIT_VALUE_LOG | 1 || [W] |
| 0x4221 | AP2_TEC_REMOTE_INIT_VALUE_LOG | 1173 || [W] |
| 0x4222 | AP2_TEC_SET_INIT_VALUE | 38 || [W] |
| 0x4223 | AP2_TEC_RESTORE_INIT_VALUE | - || [F] |
| 0x4224 | AP2_TEC_INITIALIZE | 2 || [W] |
| 0x4225 | AP2_TEC_UPDATE_LOCAL_INIT_VALUES | 4 || [W] |

#### Family: UC

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4241 | AP2_UC_ADD | - || [S] |
| 0x4244 | AP2_UC_REMOVE | - || [S] |
| 0x4245 | AP2_UC_LOOK | - || [S] |
| 0x4249 | AP2_UC_MEMBER_LOG | - || [S] |

#### Family: LON

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4300 | AP2_LON_LOG | - || [S] |
| 0x4301 | AP2_LON_ADD | - || [S] |
| 0x4303 | AP2_LON_MODIFY | - || [S] |
| 0x4304 | AP2_LON_REMOVE | - || [S] |
| 0x4310 | AP2_LON_MEMBER_LOG | - || [S] |
| 0x4311 | AP2_LON_REPORT_LOG | - || [S] |
| 0x4320 | AP2_LON_LOCAL_INIT_VALUE_LOG | - || [S] |
| 0x4321 | AP2_LON_REMOTE_INIT_VALUE_LOG | - || [S] |
| 0x4322 | AP2_LON_SET_INIT_VALUE | - || [S] |
| 0x4323 | AP2_LON_RESTORE_INIT_VALUE | - || [S] |
| 0x4324 | AP2_LON_INITIALIZE | - || [S] |
| 0x4325 | AP2_LON_UPDATE_LOCAL_INIT_VALUES | - || [S] |
| 0x4332 | AP2_LON_DIAGNOSTICS_LOG | - || [S] |
| 0x4401 | AP2_LON_SEND_SERVICE_PIN | - || [S] |
| 0x4402 | AP2_LON_GET_DOMAIN | - || [S] |
| 0x4403 | AP2_LON_SET_DOMAIN | - || [S] |
| 0x4404 | AP2_LON_REQUEST_WINK | - || [S] |
| 0x440B | AP2_LON_STATUS_CLEAR | - || [S] |
| 0x4450 | AP2_LON_PKCMSAGTSRVDBEXPORT | - || [S] |
| 0x4451 | AP2_LON_PKCMSAGTSRVDBIMPORT | - || [S] |
| 0x4452 | AP2_LON_PEAK_DB_CLEAR | - || [S] |

#### Family: EBLN

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x461F | AP2_EBLN_FP_NAMES_DISPLAY | - || [S] |
| 0x4620 | AP2_EBLN_FP_NAME_SET | - |**DESTRUCTIVE** (rename field panel)| [S] |
| 0x4621 | AP2_EBLN_FP_IP_CONFIGURE | - |**DESTRUCTIVE** (reconfigure panel IP)| [S] |
| 0x4622 | AP2_EBLN_FP_TCP_PORTS_CONFIGURE | - || [S] |
| 0x4628 | AP2_EBLN_TRUNK_SETTINGS_REPLACE | - || [S] |
| 0x4629 | AP2_EBLN_TRUNK_SETTINGS_DISPLAY | - || [S] |
| 0x462A | AP2_EBLN_FP_SITE_NAME_SET | - |**DESTRUCTIVE** (set site name)| [S] |
| 0x462B | AP2_EBLN_FP_BLN_NAME_SET | - |**DESTRUCTIVE** (set BLN name)| [S] |
| 0x462C | AP2_EBLN_FP_MULTICAST_CONFIGURE | - |**DESTRUCTIVE** (reconfigure multicast)| [S] |
| 0x462D | AP2_EBLN_HOSTTABLE_ENTRY_ADD | - |**DESTRUCTIVE** (add host-table entry)| [S] |
| 0x462E | AP2_EBLN_HOSTTABLE_ENTRY_REMOVE | - |**DESTRUCTIVE** (remove host-table entry)| [S] |
| 0x462F | AP2_EBLN_HOSTTABLE_DISPLAY | - || [S] |
| 0x4633 | AP2_EBLN_REPL_NOTIFY | 41 || [W] |
| 0x4634 | AP2_EBLN_REPL_PULL | 10019 || [W] |
| 0x4635 | AP2_EBLN_REPL_PULL_MORE | 130 || [W] |
| 0x4636 | AP2_EBLN_REPL_CHANGES | 180 |corpus-wide count; a single passive capture alone holds 170 requests + 170 replies — see §5.3| [W] |
| 0x4637 | AP2_EBLN_POINT_LOCATION_GET | - || [S] |
| 0x4638 | AP2_EBLN_MAC_ADDRESS_SET | - |**DESTRUCTIVE** (set MAC address)| [S] |
| 0x4639 | AP2_EBLN_MII_CONFIGURE | - || [S] |
| 0x463A | AP2_EBLN_MII_DISPLAY | - || [S] |
| 0x463B | AP2_EBLN_IP_DISPLAY | - || [S] |
| 0x463C | AP2_EBLN_PORTS_DISPLAY | - || [S] |
| 0x463D | AP2_EBLN_MULTICAST_DISPLAY | - || [S] |
| 0x463E | AP2_EBLN_MAC_ADDRESS_DISPLAY | - || [S] |
| 0x4640 | AP2_EBLN_PING | 108430 || [W] |
| 0x4644 | AP2_EBLN_TELNET_ENABLE | 1 |**DESTRUCTIVE** (enable telnet)| [W] |
| 0x4645 | AP2_EBLN_TELNET_DISABLE | - |**DESTRUCTIVE** (disable telnet)| [S] |
| 0x464C | AP2_EBLN_REPL_DIAG_NODELIST | 1 || [W] |

#### Family: WEB

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x465D | AP2_WEBSERVER_GET_STATE | - || [S] |
| 0x700C | AP2_WS_APOGEEEDIT_GET_STATE | - || [S] |

#### Family: BACNET

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4821 | AP2_BAC_DBCHANGE_BBMD | - || [S] |
| 0x4822 | AP2_BAC_UPL_DEL_BBMD | - || [S] |
| 0x4823 | AP2_BAC_UPL_ADDED_BBMD | - || [S] |
| 0x4824 | AP2_BAC_UPL_ALL_BBMD | - || [S] |
| 0x4825 | AP2_BAC_BBMD_ADD | - || [S] |
| 0x4826 | AP2_BAC_BBMD_REMOVE | - || [S] |
| 0x4827 | AP2_BAC_BBMD_DISPLAY | - || [S] |
| 0x4828 | AP2_BAC_BBMD_REMOVE_ALL | - || [S] |
| 0x4829 | AP2_BAC_OBJECT_ID_LOG | - || [S] |
| 0x482A | AP2_BAC_APPLICATION_PRIORITY_REPLACE | - || [S] |
| 0x482B | AP2_BAC_APPLICATION_PRIORITY_REMOVE | - || [S] |
| 0x482C | AP2_BAC_APPLICATION_PRIORITY_DISPLAY | - || [S] |
| 0x482E | AP2_BAC_DEVICE_NAME_REPLACE | - || [S] |
| 0x482F | AP2_BAC_DEVICE_NAME_REMOVE | - || [S] |
| 0x4830 | AP2_BAC_DBCHANGE_COVTAB | - || [S] |
| 0x4831 | AP2_BAC_UPL_DEL_COVTAB | - || [S] |
| 0x4832 | AP2_BAC_UPL_ADDED_COVTAB | - || [S] |
| 0x4833 | AP2_BAC_UPL_ALL_COVTAB | - || [S] |
| 0x4834 | AP2_BAC_COVTAB_ADD | - || [S] |
| 0x4835 | AP2_BAC_COVTAB_REMOVE | - || [S] |
| 0x4837 | AP2_BAC_COVTAB_REMOVE_ALL | - || [S] |
| 0x4838 | AP2_BAC_TREND_LOG_ADD | - || [S] |
| 0x4839 | AP2_BAC_TREND_LOG_DELETE | - || [S] |
| 0x483A | AP2_BAC_TREND_LOG_MODIFY | - || [S] |
| 0x4842 | AP2_BAC_TREND_LOG_LOG | - || [S] |
| 0x4843 | AP2_BAC_TREND_DBCHANGE | - || [S] |
| 0x4844 | AP2_BAC_TREND_UPL_DELETED | - || [S] |
| 0x4845 | AP2_BAC_TREND_UPL_ADDED | - || [S] |
| 0x4846 | AP2_BAC_TREND_UPL_ALL | - || [S] |
| 0x4877 | AP2_BAC_DBCHANGE | - || [S] |
| 0x4878 | AP2_BAC_UPLOAD_ADDED | - || [S] |
| 0x4879 | AP2_BAC_UPLOAD_DELETED | - || [S] |
| 0x4960 | AP2_BACNET_SET_MSTP | - || [S] |
| 0x4961 | AP2_BACNET_SET_FLN_TYPE | - || [S] |
| 0x4963 | AP2_BNMSTP_ADD | - || [S] |
| 0x4965 | AP2_BNMSTP_MODIFY | - || [S] |
| 0x4966 | AP2_BNMSTP_REMOVE | - || [S] |
| 0x4967 | AP2_BNMSTP_LOOK | - || [S] |
| 0x496B | AP2_BNMSTP_MEMBER_LOG | - || [S] |
| 0x496E | AP2_BNMSTP_LOCAL_INIT_VALUE_LOG | - || [S] |
| 0x4970 | AP2_BNMSTP_SET_INIT_VALUE | - || [S] |
| 0x4971 | AP2_BNMSTP_RESTORE_INIT_VALUE | - || [S] |
| 0x4972 | AP2_BNMSTP_INITIALIZE | - || [S] |
| 0x4973 | AP2_BNMSTP_UPDATE_LOCAL_INIT_VALUES | - || [S] |
| 0x4B01 | AP2_BNEEO_ADD | - || [S] |
| 0x4B02 | AP2_BNEEO_REMOVE | - || [S] |
| 0x4B03 | AP2_BNEEO_LOOK | - || [S] |

#### Family: EQS

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x5000 | AP2_EQS_ZONE_ADD | 2 || [W] |
| 0x5001 | AP2_EQS_ZONE_REMOVE | 2 || [W] |
| 0x5002 | AP2_EQS_ZONE_MODIFY | - || [S] |
| 0x5003 | AP2_EQS_ZONE_LOOK | 39 || [W] |
| 0x5004 | AP2_EQS_ZONE_ENABLE | - || [S] |
| 0x5005 | AP2_EQS_ZONE_DISABLE | - || [S] |
| 0x5018 | AP2_EQS_CMD_TABLE_ENTRY_ADD | - || [S] |
| 0x5019 | AP2_EQS_CMD_TABLE_ENTRY_MODIFY | - || [S] |
| 0x501A | AP2_EQS_CMD_TABLE_ENTRY_REMOVE | - || [S] |
| 0x501B | AP2_EQS_CMD_TABLE_ENTRY_LOOK | - || [S] |
| 0x5020 | AP2_EQS_MODE_ENTRY_ADD | 10 || [W] |
| 0x5021 | AP2_EQS_MODE_ENTRY_MODIFY | - || [S] |
| 0x5022 | AP2_EQS_MODE_ENTRY_REMOVE | 8 || [W] |
| 0x5023 | AP2_EQS_MODE_ENTRY_LOOK | - || [S] |
| 0x5024 | AP2_EQS_MODE_ENTRY_ENABLE | - || [S] |
| 0x5025 | AP2_EQS_MODE_ENTRY_DISABLE | - || [S] |
| 0x5028 | AP2_EQS_OVERRIDE_ADD | - || [S] |
| 0x5029 | AP2_EQS_OVERRIDE_MODIFY | - || [S] |
| 0x502A | AP2_EQS_OVERRIDE_REMOVE | - || [S] |
| 0x502B | AP2_EQS_OVERRIDE_LOOK | - || [S] |
| 0x5035 | AP2_EQS_DISPLAY_ZONE | - || [S] |
| 0x5036 | AP2_EQS_DISPLAY_MODE_ENTRY | - || [S] |
| 0x5037 | AP2_EQS_DISPLAY_CMD_TABLE | - || [S] |
| 0x5038 | AP2_EQS_ZONE_LOG | 25 || [W] |
| 0x5039 | AP2_EQS_DISPLAY_OVERRIDES | - || [S] |
| 0x503A | AP2_EQS_SSTO_SETUP_GENERAL | 2 || [W] |
| 0x503B | AP2_EQS_SSTO_SETUP_START | 2 || [W] |
| 0x503C | AP2_EQS_SSTO_SETUP_STOP | 2 || [W] |
| 0x503D | AP2_EQS_SSTO_SETUP_NIGHT | 2 || [W] |
| 0x503E | AP2_EQS_SSTO_LOOK_GENERAL | - || [S] |
| 0x503F | AP2_EQS_SSTO_LOOK_START | - || [S] |
| 0x5040 | AP2_EQS_SSTO_LOOK_STOP | - || [S] |
| 0x5041 | AP2_EQS_SSTO_LOOK_NIGHT | - || [S] |
| 0x5042 | AP2_EQS_SSTO_RESET | - || [S] |
| 0x5043 | AP2_EQS_SSTO_ENABLE | - || [S] |
| 0x5044 | AP2_EQS_SSTO_DISABLE | - || [S] |
| 0x5050 | AP2_EQS_SSTO_DISPLAY_GENERAL | - || [S] |
| 0x5051 | AP2_EQS_SSTO_DISPLAY_START | - || [S] |
| 0x5052 | AP2_EQS_SSTO_DISPLAY_STOP | - || [S] |
| 0x5053 | AP2_EQS_SSTO_DISPLAY_NIGHT | - || [S] |
| 0x5054 | AP2_EQS_MEMBER_LOG | - || [S] |

#### Family: IO

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x5300 | AP2_GLOBAL_IO_MODULE_DISPLAY | - || [S] |
| 0x5303 | AP2_GLOBAL_IO_MODULE_DISPLAY_MEC_EXPBUS | - || [S] |
| 0x5305 | AP2_LOCAL_IO_MODULE_DISPLAY | - || [S] |

#### Family: FLASH

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x5330 | AP2_BACKUP_FLASH_DBASE | - |flash-database read/export (non-destructive)| [S] |
| 0x5331 | AP2_RESTORE_FLASH_DBASE | - |**DESTRUCTIVE** (restore flash database (overwrite))| [S] |
| 0x5332 | AP2_CLEAR_FLASH_DBASE | - |**DESTRUCTIVE** (clear flash database (erase))| [S] |

#### Family: HOA

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x5351 | AP2_HOA_MAP_MODIFY | - || [S] |
| 0x5354 | AP2_HOA_MAP_LOOK | 27 || [W] |
| 0x5355 | AP2_HOA_MAP_ADD | - || [S] |



#### Family: EBLN (panel-side, outside the supervisor enum)

| 0xHEX | Name | Observed (count) | Notes | Tag |
|---|---|---|---|---|
| 0x4623 | AP2_EBLN_FP_DISPLAY | - || [S] |
| 0x4624 | AP2_EBLN_STORAGE_NODES_REPLACE | - || [S] |
| 0x4625 | AP2_EBLN_STORAGE_NODES_DISPLAY | - || [S] |
| 0x4626 | AP2_EBLN_REPORT_PRINTER_REPLACE | - || [S] |
| 0x4627 | AP2_EBLN_REPORT_PRINTER_DISPLAY | - || [S] |
| 0x4630 | AP2_EBLN_NODE_ADD | - || [S] |
| 0x4631 | AP2_EBLN_NODE_REMOVE | - || [S] |
| 0x4632 | AP2_EBLN_NODE_LIST_DISPLAY | - || [S] |<!-- END GENERATED CATALOG -->

#### 9.5.1 Four request bodies, decoded against their ASDU definitions

Every opcode in the catalog carries a name; not all of them carried a *body*.
Four wire-observed opcodes had no body description anywhere in this document.
All four are defined in the protocol's ASDU model, and three decode against it
with nothing left over: [S][W]

| Opcode | Request ASDU | Observed | Decode |
|---|---|---|---|
| `0x0606 CAL_DB_GET_OTHER` | `User_profile` | 12 B | **exact** |
| `0x09AB UPL_ALL_UC` | `Team_search` | 11 B | **exact** |
| `0x0954 DBCHANGE_TREND` | (no body) | 0 B | **exact** (§16.1.2) |
| `0x4208 TEC_DEFINITION` | `User_profile` + `Team_search` | 25 B | 23 consumed, 2 over |

```
0x0606   01 00 04 "SYST"  23  3F FF FF FF
         User_profile{ user_logon, point_priority=0x23, access_class=0x3FFFFFFF }
         response: 00 00  ->  nrOfcalendar_entries = 0, an empty calendar

0x09AB   00 00 | 01 00 01 "*" | 00 00 | 01 00 00
         Team_search{ system, pattern "*", system, resume "" }   (§10.2.3)
         response: 0x0003  ->  no unitary controllers on this panel
```

**The two bytes `0x4208` leaves over are a field its ASDU definition omits.**
They read `FF FF`, and every sibling in the TEC family carries a 2-byte
`application_number` in exactly that position. Decoding the family together
rather than reading one frame: [W]

| Opcode | Tail after `User_profile + Team_search` | ASDU definition |
|---|---|---|
| `0x4225 TEC_UPDATE_LOCAL_INIT_VALUES` | `FF FF` | `application_number : UNSIGNED16` ✔ |
| `0x4224 TEC_INITIALIZE` | `FF FF 01 00` | `application_number` + 2 × `BOOLEAN_` ✔ |
| `0x4200 TEC_LOG` | `FF FF` | `application_number : SHORT_` ✔ |
| `0x4208 TEC_DEFINITION` | `FF FF` | **absent from the definition** |

`0xFFFF` is the **wildcard application number**. `0x4224` now decodes field for
field with nothing left over — `User_profile` + `Team_search` +
`application_number = 0xFFFF` + `clear_panel_initvals = true` +
`clear_device_initvals = false` in 30 bytes.

Two cautions an implementer should carry from this:

- **`0x4200` is one operation invoked two ways — not two operations.** The
  function-code enumeration gives this opcode two names, `AP2_TEC_LOG` and
  `AP2_CONTROLLER_LOG`, and the wire carries two cleanly separated request
  forms. It is tempting to pair them off. **The responses show that would be
  wrong.** [W]

  | Form | Frames | Request | `application_number` | `name_pattern` | resume key |
  |---|---:|---|---|---|---|
  | **A** | 70 | variable, 28–38 B | `FFFF` | 27 distinct object names | always empty |
  | **B** | 178 | fixed 220 B, zero-padded | `0000` | `*` only | 60 distinct values |

  Form A is a **named lookup** of one object; form B is a **wildcard enumeration**
  walking the set with the resume key of §10.2.3. They address the *same*
  objects — names that appear as form A targets reappear as form B resume keys —
  and the `application_number` split follows from the search, not from the
  target: naming one object asks for any application on it (`0xFFFF`), while
  enumerating supplies no application at all (`0x0000`).

  Decisively, **every response to both forms is the same structure**:
  `Team_response` + `TEC_body`, with `team_family = 0x0010` (`tec_na`).
  242 of 242 responses parse, and the parse is self-validating — `nrOfnames`
  must equal the number of `Team_response` entries that actually follow before
  the descriptor, and it does in every one: [W]

  ```
  Team_response          name_space=0, name="<team name>"
  Team_description_base  team_family=0x0010 (tec_na)
                         team_type=0x0AA1, team_revision=0x0000
  nrOfnames            = 2
     names[0]            name_space=0 (system), name="<team name>"
     names[1]            name_space=1 (user),   name="<team name>"
  descriptor           = "<free text>"
  … access_class, si_units, lan, drop, duct_available, nightOverride, …
  ```

  The `team_type` values overlap between the two forms, so they are not even
  reaching different classes of TEC. **Both forms are `AP2_TEC_LOG`, and
  `AP2_CONTROLLER_LOG` does not appear anywhere in the corpus.** [W]

  A caution for the eleven aliased opcode values generally: a second wire form is
  **not** evidence of a second operation. Check the response structure before
  pairing a form with a name.

  **[OPEN]** — what `AP2_CONTROLLER_LOG` looks like. The prediction, if the names
  mean what they say, is that a `0x4200` naming a panel rather than a TEC returns
  something that is *not* a `TEC_body`, or fails. Nothing in this corpus has ever
  asked.

  *Independently reproduced.* A later pass matched all 1,144 declared structures
  against these bodies without reference to the opcode's name, and `Team_response
  | TEC_body` was the **only** shape of the 1,144 that consumes all 60 responses,
  with the request decoding as `user_profile | team_search | application_number`.
  Two methods, one answer. [W]

- **Some TEC requests use a fixed 220-byte zero-padded buffer.** Form B above and
  every one of `0x4221`'s 1,173 requests are exactly 220 bytes with the remainder
  zero-filled — `0x4221` consumes 44 and pads 176. The padding is not opaque
  content: the fields end and zeros follow. A parser must therefore **stop at the
  end of the declared structure and not treat trailing zeros as data**, and must
  not infer the operation from the frame length. [W]

- **Sibling opcodes do not share a search type.** `0x4221`'s request is
  `Def_TEC_app` = `user_profile` + `application_family` + `team_type` +
  **`Name_search`** + `all_init_values`, not `Team_search`. Decoded on the wire:
  `application_family = tec_na`, `team_type = 0xFFFF`, and a `Name_search` whose
  `suffix_pattern` is `*` and whose `last_suffix` advances one subpoint per
  request — the suffix walk of §10.2.3, in use. A parser that assumes the shorter
  search type mis-frames everything after it. [W][S]

### 9.5.2 Opcodes the panel implements that the enum does not name

**The catalog above cannot contain these, by construction.** It is generated by
joining the vendor `AP2_Function_Code` enum with the corpus census (§9.5), so an
opcode absent from the enum has no row to appear in — however the panel behaved
when one was sent. Fifteen observed opcodes fall outside the enum, and eight of
them drew a substantive answer: [W]

| Opcode | Panel response |
|---|---|
| `0x4641`, `0x464A`, `0x464B`, `0x464E`, `0x464F`, `0x4650` | **implemented** — answered with a success |
| `0x4642`, `0x4643` | **reached a handler and refused** — an application error, not a not-supported |
| `0x0510` | not implemented |
| `0x0000`, `0x0C44`, `0x4443`, `0x4647`, `0x464D`, `0xFFFF` | never answered — inconclusive |

Every one of these was seen only in deliberate probe traffic — one or two frames
each, from research hosts, never from a supervisor or a panel in normal
operation. That is why they carry no body documentation and no family: nothing
is known about them beyond the response class.

**The conclusion is narrow and worth stating precisely.** It is *not* that these
are secret operations; it is that **the supervisor-side function-code
enumeration is not a complete inventory of what a panel implements.** Six
opcodes it does not list are answered with success, and two more reach a handler
and refuse — a refusal is itself evidence of a handler, distinct from the
not-supported error a panel returns for an unimplemented code (§7.2.2). An
implementer should treat the enum as the set of operations the *supervisor*
issues, not as the panel's capability surface, and a scanner must not conclude
"unsupported" from absence in a name table.

They sit in the `0x464x` band, immediately around the documented EBLN
management operations (`0x4640` ping, `0x4644`/`0x4645` Telnet enable/disable),
which is consistent with their being further EBLN node-management operations.
What each one *does* is **[OPEN]** and is not guessed here — and given the
neighbours include Telnet control and node eviction (§17.4), the honest position
is that an unidentified operation in this band should be assumed capable of
changing panel state and left alone.

### 9.6 The session/keepalive opcode 0x4640 (EBLN_PING)

`AP2_EBLN_PING` (0x4640) is the most cross-cutting opcode in the corpus: it is the only opcode that appears under every message class seen anywhere — 0x29, 0x2A, 0x2E, 0x2F, 0x33 and 0x34 — and it dominates the peer carriers, though it is not alone under them: panel-side captures show class 0x29 also carrying `0x4634`, `0x4633`, `0x4636` and `0x0271` (see §9.7) — and it serves three roles. As **session establish** it is the IdentifyBlock handshake carrying the peer's identity slots; as **keepalive** it recurs on a ~10-second cadence (the EPing / Ethernet-Ping liveness heartbeat — a configurable interval whose documented minimum is 10 s, not a protocol constant; see §7.1); and its request/response body is the `eBLN_Node` block (§10.6). It is also the opcode whose malformed slot-walk produces the `0x0C44`/`0x4443` phantoms in §9.5. Its length is variable: three leading TLVs (`node_name`, `site_name`, `bln_name`) followed by a fixed 16-byte tail. The `35 + node-name length` shorthand of earlier editions is this corpus's single site expressed as a constant — see §7.1. Every *supervisor-initiated* request in the corpus drew a reply; panel-initiated pings into a supervisor's `5033` are a different matter (§5.1). [W][S]

### 9.7 Wire behavior: message classes, directions, error tails

The corpus distribution grounds the catalog in observed behavior:

- **Message classes (`msg_type` low byte).** Six classes are defined — the legacy/modern pairs of §6.2/§6.6 — and any other low-byte value is parser noise from a desynced stream. Corpus distribution, over **621,268 trusted frames in 121 distinct P2-carrying captures** (content-deduplicated; criteria stated because an earlier edition of this table gave counts that cannot be reproduced from the evidence base, see the note below):

  | Class | Role | Frames |
  |---|---|---:|
  | `0x33` | legacy data dialect | 420,024 |
  | `0x29` | session carrier (panel-to-panel) | 100,200 |
  | `0x34` | modern data dialect | 40,962 |
  | `0x2E` | legacy 2nd-channel / announce + DB-sync | 42,542 |
  | `0x2A` | peer-session carrier (panel-to-panel) | 12,556 |
  | `0x2F` | modern 2nd-channel | 4,984 |

  These sum to the 621,268 trusted frames of 9.5. **The peer carriers moved
  by four orders of magnitude when panel-side captures entered the corpus**
  - `0x29` from 10 frames to 100,200, and `0x2A` from zero to 12,556 -
  because a supervisor-side tap structurally cannot observe a
  panel-to-panel session. The earlier figures were not wrong for what they
  measured; they measured one vantage point.

  Most high-volume operations occur in both `0x33` and `0x34`; certain single-shot and legacy-supervisor operations occur only in `0x33`.

  **The peer carriers behave exactly as described, and the tiny counts above are a property of the vantage point, not of the protocol.** Isolating conversations where neither endpoint is the supervisor or a research host leaves **10 frames in this census** — all class `0x29`, all `EBLN_PING`, all captured during a power cycle as panels re-established sessions with each other. A supervisor-side tap structurally cannot see a panel↔panel session, so the census measures how often the *supervisor* participates, not how much peer traffic exists.

  **Taps on a panel's own switch port settle it.** The corpus now holds five, on **two different panels**, each showing its panel holding sessions with nine peers continuously. Both carriers are wire-observed there — so `0x2A` is `[W]`, not an inference from the legacy/modern pairing. Neither carrier is single-opcode: alongside `0x4640` they carry the replication family (`0x4634`, `0x4633`, `0x4636`) and `0x0271 COV_ENABLE`. The census figures above are counts of *supervisor-facing* P2 and remain correct for what they measure. [W]

  **Which peer carrier a node uses is a property of the node, not of the link.** Resolving every peer-carrier frame in the corpus to its host pair gives 13 pairs on `0x29` and 2 on `0x2A` — and the two `0x2A` pairs share one endpoint, which appears in **none** of the thirteen `0x29` pairs:

  | Class | Host pairs | Pattern |
  |---|---:|---|
  | `0x29` | 13 | every pair among the other nodes |
  | `0x2A` | 2 | both involve the *same single node*, which never appears on `0x29` |

  Two independent panels each speak `0x29` to every peer they have **and `0x2A` to that one node**. A single vantage could not distinguish this from "one link happens to differ"; two vantages on two devices make it a per-node property. The natural reading is a firmware-generation split — one node on the BLN speaks the other dialect of the pair, and its peers switch carrier to match it. An implementer should therefore select the peer carrier **per peer**, from what that peer presents, and must not assume one carrier BLN-wide. Which of the two is the newer generation is **[OPEN]**: it needs `0x010C CABINET_DISPLAY` read from the odd node. [W]

  > **Why the numbers changed.** A previous edition of this list gave 433,425 / 43,668 / 43,780 / 7,322 / 2,200 / 296, totalling 530,691 frames. That total is reproducible from neither the deduplicated corpus (621,268) nor a naive count over all 764 capture files including duplicates (1,326,186), and both counts put `0x2A` at zero in the supervisor-side set. The likeliest explanation is now a mundane one: the corpus has since been shown to have been **incomplete** — thirty-four captures, 271,636 frames, were recovered into it after this note was first written — so an earlier edition counting a capture set that no longer existed in the evidence tree is exactly what one would expect. The figures here are replaced with counts reproducible from the current corpus under the stated criteria, and a reader who reproduces them should expect them to move again if the corpus grows. [W]
- **Direction byte.** 0x00 request/push (314,273), 0x01 success response (300,989), 0x05 error response (6,006) - summing exactly to the 621,268 trusted frames of 9.5. A success response carries the operation's payload after the routing slots; an error response carries exactly a 2-byte error code and nothing else. [W]
- **Error tail values (the 2-byte code on a 0x05 response).** `0x0003` not-found / unrecognized-opcode (5,805×), `0x00AC` not-supported (49×), `0x0E15` physical-point-not-commandable (28×), `0x0002` invalid-operation (4×), `0x0E11` FLN-invalid-drop-number (2×), `0x0E12` FLN-device-failed (3×), `0x0009` already-exists (1×). See §7.2.2; `0x0E1x` is the FLN band. An opcode the panel does not implement returns `0x05 ... 00 03`; this is how the defined-but-unimplemented-on-this-firmware opcodes announce themselves on the wire. [W]
- **Per-opcode response shapes.** Response lengths vary by opcode and by the addressed object; representative shapes from the census (opcode → success-response sizes): 0x010C → 230/231 B (firmware/identity block, §10.5); 0x0220 (read) → 126/138 B or `err 0003` when the point is absent; 0x0271 (COV enable) → 96/108 B; 0x0274 (annunciate) → 0 B (acknowledged, no payload); 0x4640 → 40/41/45/47 B at this site (three TLVs + a 16-byte tail; the length follows the *sender's* node name, not the addressee's — see §7.1); 0x0981 (enumerate points) → 88/115/118 B. The "0 B success" pattern (direction 0x01, empty body) is a bare acknowledgement used by push/command/replication opcodes. [W] **A request may also carry a zero-length body**, and 220 in the corpus do: `0x010C` (163×), `0x4633 EBLN_REPL_NOTIFY` (22×), `0x0951 DBCHANGE_POINT` (11×), `0x0100` (9×) and the rest of the `DBCHANGE` family. This is the natural encoding of a **parameterless operation** — the `u16` opcode is the whole message. An encoder must be willing to emit an ASDU of length zero, and a decoder must accept it as complete rather than truncated: after the two opcode bytes are taken off, `total - 2` is legitimately 0. [W]

---

## 10. Message Body Structures

### 10.1 Encoding convention

The bytes after the opcode are the operation's **ASDU** (Application Service Data Unit; the service model is ISO/OSI-style Request → Indication on the receiver, Response → Confirm back). The complete set of bodies is defined as **1,144 distinct ordered-field ASDU structures** in the protocol's type system — **536 `*_Request` forms, 357 `*_Response` forms, and 251 shared component types** (`Alarm_level`, `Point_base`, `Name_search` and the like) that the request and response forms build on — each an ordered list of typed fields. Fewer responses than requests is not an extraction gap: a large minority of operations are fire-and-forget and answer with status only (see the command shapes in §9). This section documents the encoding rules, then the ~30 most important structures in field tables; the full set is enumerable from the structure library, so any opcode in §9 has a known body shape even where not detailed here. [S]

Field types in the structure tables map to wire encodings as follows. These are the [S] definitional types; the [W] encodings (TLV framing, f32, scope tag) are established from captures (cross-reference §8 of the framing sections):

| ASDU type | Wire encoding | Notes |
|---|---|---|
| `TEXT_` | string TLV: `textType` u8 (`0x01`, but see §8.1 — `0x00` also occurs) + `textLen` **u16 BE** + content | See §8.1 — the length is **two** bytes; ASCII content, not NUL-terminated inside the TLV; empty = `01 00 00` **or** `00 00 00`. [S][W] |
| `UNSIGNED8` / `UNSIGNED_8` | 1 byte | [S] |
| `UNSIGNED16` / `UNSIGNED_16` | 2 bytes, big-endian | counts/markers/error codes are u16 BE. [W] |
| `UNSIGNED32` | 4 bytes, big-endian | sequence numbers, identifiers. [W] |
| `SHORT_` / `LONG_` | 2 / 4 bytes, big-endian, signed | [S] |
| `FLOAT_` | 4 bytes IEEE-754, big-endian | analog values; raw engineering units, no scaling on the wire. [W] |
| `BOOLEAN_` | 1 byte (0/1) | [S] |
| `NULL_` | 0 bytes | a present-but-empty CHOICE alternative or placeholder. [S] |
| `DATE_TIME` / `DATE_` / `TIME_` | packed date/time block | [S] |
| `<Name>` (capitalized) | nested sub-structure | expanded inline; shared sub-types defined once in §10.2. [S] |
| `<Name>[]` | repeating array | preceded by a `nrOf<name>` u16 BE count field — **always** u16, see below. [S] |
| `<Enum>` | integer, **width per enum** — see below | value space per the enum tables (priorities, point types, cov masks, node states, etc.). The structure library does **not** state the wire width of any enum; each must be pinned separately. [S] |

**No documented maximum is an encoding bound.** Every variable-length
repetition in P2 is a count followed by elements, and the count is **always
`UNSIGNED_16`** — measured across the library, 159 of 162 array-typed fields are
immediately preceded by an `nrOf<name> : UNSIGNED_16`, and **all 159 count
fields are u16; not one is u8 or u32**. The three exceptions are not arrays in
the usual sense: `BITSTRING_128` is a fixed 128-bit field, and `TEXT_`'s two
byte-array fields are bounded by its own `textLen : UNSIGNED_16` — the same
pattern under a different field name. [S]

This matters because the document quotes a number of vendor-documented
maxima — 4 multicast address/port pairs per panel (§5.2), 8 listener-port slots
per panel (§4.1), 1–4 members in a point team (§2.2.3), 32 devices per FLN trunk
(§3.8) — and **none of them is what the encoding allows.** `IP_Address_Settings`
carries `nrOfmulticast : UNSIGNED_16` and `nrOfapp_ports : UNSIGNED_16`; a team's
`member_count` is `UNSIGNED16`. Each documented figure is a *product* constraint
that a given firmware imposes, and a decoder must read the count field and size
from it. Sizing a fixed array from a documented maximum is the one mistake this
type system makes easy and does not warn about: the buffer is right on every
frame at this site and wrong on the first frame from a panel configured
differently.

**A caution that governs this whole section: a generated lookup fails
plausibly, not loudly.** Four independent properties of the protocol's type
system each produce, in a mechanically generated decoder, a *valid wrong answer*
rather than an error — which is the hardest kind of defect to notice, because
the output looks like a successful decode:

| Property | What a generated lookup does |
|---|---|
| **Enum values are sparse** (below) — 18 of 66 have gaps | an array-index lookup returns a different, valid name past the first gap |
| **A CHOICE `tag_` is sometimes an enum value, not an ordinal** (§10.4.1, §10.4.6) | positional arm selection is right for 66 of the 71 CHOICEs whose numbering is fully recovered, and silently wrong for the five where the arms mirror an external enumeration — `All_points`, the two BACnet point CHOICEs, the BACnet event-parameter CHOICE, and one 1-based case |
| **A two-armed CHOICE looks safe and is not** (§10.4.6) | "only two arms, so an ordinal reading cannot diverge" is the reasoning that put an assumption into §10.9's register; `Pdl_display_data` numbers its two arms 1 and 2, and two other CHOICEs have two `NULL_` arms that no body can tell apart |
| **`Name_space_enum` is defined twice, with incompatible values** — `0 system / 1 user / 65535 any`, and separately `1 LAO_actuator / 2 HOA` | whichever definition the generator loads last silently wins for every `Name_space` field |
| **An enum's members can be bit positions, not values** — `Schedule_days` has 14 members and a 4-byte field | sizing the field from the enum's maximum gives one byte instead of four, and then decodes a mask as a value |

The first two have each already produced a wrong claim in an earlier edition of
this document. The third has not, because §8.5 documents the first definition
and every observed value (`0000`, `FFFF`) belongs to it — but a decoder built by
scraping the enum dump has a one-in-two chance of the other. The fourth was
found by trying to *use* an enum's value range as a constraint while solving for
widths, and discovering that the constraint is unsound (§10.1, below).

**The defensive rule:** resolve every enum value through a lookup keyed by
*value* within a namespace named by the *field*, never by position and never by
enum name alone. Where a value is not in the table, fail — do not fall through
to a neighbour. [I]

**Enum values are sparse. Never index an enum positionally.** Of the 66 value
enums in the protocol's type system, **18 have gaps** — the value space is not
`0..n-1` and a value is not an ordinal. `Point_type` skips 5 and 8–10 and 16–19;
`Point_priority` uses 0, 1, 5, 10, 15, 20, 25, 30, 32, 34, 35 and then a
BACnet band at 101–116; `Node_complete_state` runs 2–15 with 4–6 missing. Any
code that treats an enum value as an index into a list of names — or into the
arm list of a CHOICE — is correct only up to the first gap and wrong
thereafter, **silently**, because the wrong name is still a valid name. This is
not hypothetical: an earlier edition of §10.4.1 read the `All_points` tag as an
ordinal and mislabelled seven of eleven point types. [S]

A related hazard follows from the same sparseness. **Four values are legal in
both `Point_priority` and `Point_type`** — `0`, `1`, `15` and `20` — so a
decoder that is off by one field between a priority byte and a type byte
produces a plausible value rather than an error. Where both appear in one
structure, validate against the field's own enum, not against "is this a
sensible small integer". [S]

**The catalog is a flattening, and it drops nested types.** The 1,144-structure
figure counts the *named* types the vendor system declares. Types declared
**inside** another — the lowercase, trailing-underscore names like `real_addr_`,
`use_proof_` and the sixteen `All_points` arms — survive the flattening as a
field's type name with no definition attached, which is why so many structures
appeared to reference something undeclared. They are declared; read directly,
the type system holds **277 further definitions**, and recovering them closed
the largest gaps in this document (§10.4.1, §10.4.2, §10.9).

The recovery was validated before it was used, against the one thing already
known independently: the five `real_addr_` variants. Four had been measured on
the wire, painfully, and **all four reproduce exactly**; the fifth had never
been measured and is corrected (§10.4.2). Where a definition and the wire
disagree, the wire wins and the disagreement is a finding — but here they do
not disagree.

**Enum field widths are still not in the structure library, and they have to
be.** For an enum field the system gives only a type name — so **field order is
fully specified and field width is not**, and a decoder cannot be built from the
type system alone.
**Fifty-three** distinct enum types appear as fields. The widths pinned so
far: [W][S]

| Enum | Width | How it is pinned |
|---|---:|---|
| `Name_space` | 2 | §8.5; `0`/`1`/`0xFFFF` = system/user/any |
| `Point_priority` | 1 | the command-priority ladder, §8.2 |
| `Access_class` | 4 | `BITSTRING32` inside `User_profile` |
| `Application_family` | 2 | inside `Def_TEC_app`; `tec_na` = 16 |
| `Cov_mask` | 2 | `COV_ENABLE` = `Name_response` + 2 bytes |
| `Control_status`, `Alarm_state`, `Alarm_priority`, `Out_of_service`, `Failed`, `Proof_on` | 1 each | §12.3.3's ten-byte COV status block, one byte per field |
| **`Point_value`** | **4** | solved from the wire: 40 of 40 bodies parse with zero remainder at 4 bytes, **0 of 40** at 1 or 2 |
| `Point_type` | 1 | the `All_points` selector, §10.4.1 |
| **`State_text_table`** | **2, signed** | §11.5 — every observed value is negative, and `Enum_type.type_id` is declared `SHORT_` |
| `Representation` | 1 | inside `Analog_format`, constant across analog points |
| `Proof_status` | 1 | the only width that closes an `l2sl` body, §10.4.1 |
| `Total_rate` | 1 | inside the totalizer arm, §10.4.5 |
| `time_`, `trend_cov_` | 4 each | the two `Trend_type` arms; consumption across 5 and 2 opcodes (161 / 86 bodies) |
| `Occurrence` | 1 | `u8` in §15.3's `0x0989` decode; consumption narrows `0x5020`/`0x0979` to this or 4 and §15.3 chooses |
| `TEC_valid`, `Failed_status` | 1 each | the `0x0986 UPL_ALL_TEC` body, 59 of 60 consuming exactly once its absent trailing field is allowed for |
| `Ssto_zo_mod_cl`, `Ssto_zo_mod_ht` | 1 each | **resolved, see below** — an apparent contradiction whose cause was an undeclared field, not a width |
| **`Schedule_days`** | **4** | a **bitmask**, §15.3 — see the warning below |
| `loggerOn_` | 1 | 2 opcodes, 23 bodies |
| `Ssto_amd`, `Ssto_desop_value` | 1 each | 2 opcodes, 6 bodies |
| `Sensor_type` | **1** | originally derived rather than fitted — 1 is the only width giving the wire-measured 17-byte `Physical_address_AI`. **Now directly attested**: the panel's own encoder writes it with the one-byte primitive, masked `& 0xff` (§10.4.2) [F] |
| `Alarm_mode_type` | **1** | `0x0982` and `0x0983`, 8 bodies each; `0x0983` carries the field **twice**, so a wrong width compounds. Widths 2 and 4 land inside the trailing `DATE_TIME` run and read `0x7e` as an alarm tag. Pinning it made 19 operations decodable — the largest single gain in §10.9 |
| `Grain_Type`, `Repl_Cmd_Type` | 1 each | **one opcode only** (`0x4636`, 60 bodies) — unique for it, uncorroborated |
| `Baud_rate` | **2** | `0x099f`, 60 bodies, and the record carries its own oracle — see below |
| `Port_number`, `Port_type` | 1 each | same 60 bodies; `Port_number` corroborated by `Port_request`, which types the same concept `UNSIGNED8` |

**How that split was closed, and why it is worth reading.** For a long time
only the **sum** of those three was measured: they co-occur in `0x099F` and
nothing isolated them, so the entry here read "4 together, split **[OPEN]**".
Three enums summing to 4 bytes means exactly one is two bytes wide — and the
value spaces gave no clue, because `Baud_rate` 0–12, `Port_number` 0–4 and
`Port_type` 0–1 all fit comfortably in one byte each. The obvious inference was
that the wide one must be whichever had the most members, which is the
value-range reasoning §10.9 records as false.

What settled it was not a new capture but reading the body properly (§16.1.3).
`Baud_rate` is **2**, `Port_number` and `Port_type` **1** each, and the split
reproduces the previously measured sum of 4 exactly — two independent
measurements meeting. The decisive evidence is inside the record: its
`DiagPortString` spells the port's settings in ASCII as `;bd=9600;…`, and the
`Baud_rate` enum decodes to `baud9600` in all 60. [W]

The library also offers a second, still-unused check on the same value, worth
keeping for a commissioning capture: six request structures carry
`baud_rate : Baud_rate` **and nothing else** —

```
AP2_Cabinet_Set_BLN_BaudRate_Request  = baud_rate : Baud_rate     (0x0126)
AP2_Cabinet_Set_FLN1..3_Baudrate      = baud_rate : Baud_rate     (0x0123-0x0125)
AP2_Cabinet_Set_MMI1..2_Baudrate      = baud_rate : Baud_rate     (0x0120-0x0121)
```

so the body length of any one of those six frames is `Baud_rate`'s width on its
own, and should read 2. None appears in this corpus — they are configuration
writes, which a monitoring supervisor never sends. [S]

**A contradiction worth showing, because of how it resolved.** `Ssto_zo_mod_cl`
and `Ssto_zo_mod_ht` came out as **1** from `0x097d` and as **2** from
`0x098d`. A type has one width, so one parse was wrong — and taking the majority
would have reached the right answer for the wrong reason. The cause is in the
declarations:

```
AP2_Upl_Added_SSTO_Start_Response :  team_response | ssto_start_setup
                                     | state_text_id : SHORT_ | panel_logging
AP2_Upl_All_SSTO_Start_Response   :  team_response | ssto_start_setup
```

The **All** variant declares nothing after `ssto_start_setup`; its own **Added**
sibling declares a `state_text_id` there, and the wire carries one in both. Two
fields at +1 each is the same two bytes as one missing tail, which is exactly
why width 2 appeared to fit. Restore the tail and **60 of 60 bodies consume at
width 1**, with the tail reading `-1005` ×45 and `-2005` ×15 — the same two
state-text tables in the same split as `0x098C`, `0x098E` and `0x098F` (§11.5).
Three independent confirmations, and none of them a vote. [W][S]

**Do not size an enum field from its enum's value range.** The obvious shortcut
— *the largest member is 13, so one byte is enough* — is wrong, and
`Schedule_days` is the counter-example. Its fourteen members are `Sunday` …
`Saturday` and `Replacement1` … `Replacement7`, values 0–13, and the field is
**four bytes**, because the members are **bit positions in a mask**, not values
the field takes. A decoder sized that way reads one byte where four are
required, and reads a value where a mask is meant. Both failures are silent, and
this is the fourth member of the family in the caution at the head of this
section. [W][S]

The remainder are **[OPEN]**, and the honest scoping matters: a large share of
them are BACnet-side object types (`analog_input_`, `binary_output_`,
`multi_value_` and their siblings) belonging to the `BAC_*` structures, which
this document places out of scope (§3.2.4) and which cannot appear in P2 traffic
at all.

**A naming convention separates the two kinds of undefined type.** Types written
lowercase with a trailing underscore — `ldi_`, `lao_`, `time_`, `trend_cov_`,
`point_choice_` — are **not scalars**: they are the arms of a CHOICE, and **70
of their 98** field uses sit inside a structure whose first field is `tag_`. Asking
for their "width" is a category error; they are decoded like `All_points`
(§10.4.1). Types in ordinary capitalised form are the genuine scalars. [S]

**How much of the type system is undeclared, exactly.** The 1,144 structures
between them make **4,432 field uses** naming **439 distinct field types**. Of
those types, **224 are declared or primitive and 215 are neither** — 83 are the
lowercase CHOICE arms just described, and **132 are capitalised types used as
fields but never defined anywhere in the library**. So the library is complete
in field *order* and materially incomplete in field *type*, and the gap is not
a long tail of exotica: the single most-used undeclared type,
`Point_extension2`, appears in **89** structures. Widths for the ones that
matter are pinned from the wire in §10.4.2. Regenerate every count in this
section with `s164_typecensus.py`. [S]

**Three rules a decoder needs that the structure library does not state.**
Each was found by a body that would not consume, and together they take request
bodies from 91% to **99.2%** decoded (2,494 of 2,515): [W]

| Rule | Evidence |
|---|---|
| **A trailing declared field may be absent.** A body ending exactly on a field boundary with fields still to come is truncated, not malformed — the library describes a **later firmware revision than a given panel emits**. Report what was not received; do not reject the body. | `0x0986 UPL_ALL_TEC` omits its final `is_bacnet` in **59 of 60** bodies |
| **Request bodies are padded with zeros to a fixed size** — **220 bytes** at this site. Content of 2 to 65 bytes pads to the same total. | 174 bodies across 8 opcodes; `0x040A`'s entire declared body is one `SHORT_` and the frame carries `f8 2a` then 218 zeros |
| **Some responses carry one or two bytes the library does not declare**, consistently per opcode. | **402 bodies across 9 operations**, tabulated below — an undeclared trailing field, not padding |

**The undeclared tails, recounted.** An earlier edition of the row above said
"43 bodies: `0x0291` always +2, `0x0987` and `0x5038` always +1". Walked
field-by-field there are nine operations and 402 bodies, and they are two
different things that should not be counted together: [W]

| operation | bodies | tail | what it is |
|---|---:|---|---|
| `0x0291` `TREND_SETUP_DELETE` | 14 | 2 B, always `00 00` | an **empty `Point_extension2`** — entry count zero (§10.4.2) |
| `0x02A8` `TREND_EVENT_ARC_SETUP` | 8 | 2 B, always `00 00` | the same |
| `0x0987` `UPL_ALL_EQS_ZONE` | 60 | 1 B | a boolean: `1` on 59, `0` on 1 |
| `0x5038` `EQS_ZONE_LOG` | 20 | 1 B | a boolean: `0` on all 20 |
| `0x0989` `UPL_ALL_EQS_MODE_SCHED` | 60 | 2 B | a **state-text table id**: `-1005` on 36, `-2005` on 24 |
| `0x098C`–`0x098F` `UPL_ALL_SSTO_*` | 60 each | 2 B | the same two ids, `-1005` on 45 and `-2005` on 15 in each |

The last five are not really undeclared. `-1005` and `-2005` are the two
state-text tables this site defines, and a **sibling structure in the same
library declares the field**: `AP2_Upl_Added_SSTO_Start_Response` carries
`state_text_id : SHORT_` where `AP2_Upl_All_SSTO_Start_Response` declares
nothing. The wire carries it in both. So this is the same *"a trailing declared
field may be absent"* asymmetry as the first rule, seen from the other side — the
library is inconsistent between an operation and its `_Added_` variant, not
silent about a field. [S][W]

The first four are genuinely undeclared, and two of those four are now explained:
an empty `Point_extension2` is exactly two bytes, so `0x0291` and `0x02A8` carry
a field the library forgot on a structure that its neighbours all have. What
remains open is narrow — **the meaning of the two single-byte booleans** on
`0x0987` and `0x5038`. Their width and position are not in doubt. [W][OPEN]

**These are in the published package.** `p2_asdu.OP_TAILS` carries all nine and
`p2_body.py` applies them after the declared structure, naming them so a reader
can see they are observed rather than declared. Until this pass the reference
model applied them and the shipped walker did not, so 342 bodies this document
reports as fully decoded stopped one or two bytes short for anyone using the
package — a gap between what the document measured and what it shipped. Model
and walker now both consume **3,803 of 4,063** bodies to exactly zero. [W]

**`0x010C CABINET_DISPLAY` was the opposite case, and it is now one byte.** It never ran out of body — it ran out of *structure*: the walk reached the tag of `BACnet_MSTP_LAN_Settings` after 224 of 230 bytes, and the six left over are `21 00 03 00 03 00`, **byte-identical in every one of the sixty responses**. An earlier edition left the cause open between "one of the three BACnet CHOICEs is not what the library says" and other readings. Neither is right. The declared tail from that point is

```
BACnetMSTPLANSettings : BACnet_MSTP_LAN_Settings   tag + arm
bacnet_ip_aln_choice  : BOOLEAN_                    1
ip_network_number     : UNSIGNED16                  2
BACnetMSTPALNSettings : BACnet_MSTP_ALN_Settings   tag + arm
```

which is **five** bytes with both CHOICEs on their zero-length arm — one short. So one byte is undeclared, and there are five places it could be. Testing all five: [W]

| an undeclared byte placed before … | responses that then consume exactly |
|---|---:|
| **`BACnetMSTPLANSettings`** | **60 of 60** |
| `bacnet_ip_aln_choice` | 0 of 60 |
| `ip_network_number` | 0 of 60 |
| `BACnetMSTPALNSettings` | 0 of 60 |
| at the very end | 0 of 60 |

One position fits and it fits everything, so the six bytes read:

```
21        <- ONE undeclared byte, constant across all 60
00        BACnetMSTPLANSettings  tag 0 = noMSTPLAN
03        bacnet_ip_aln_choice
00 03     ip_network_number = 3
00        BACnetMSTPALNSettings  tag 0 = noMSTPALN
```

**The BACnet CHOICEs were never the problem.** What remains open is only what the one byte *means*; its position and its constancy are measured, and a decoder that skips one byte there reads the response completely. `p2_asdu.STRUCT_SKIPS` carries it and `p2_body.py` applies it, emitting it as a named `<undeclared>` field rather than stepping over it silently — all 60 now decode to 230 of 230. One caution while reading the result: `bacnet_ip_aln_choice` is declared `BOOLEAN_` and carries `3`, so this codec does not constrain a boolean to 0/1. [W][OPEN]

**Where the whole corpus stands, with nothing hand-waved.** Four categories, and every body is in one of them: [W]

| | bodies | |
|---|---:|---|
| consume to **exactly** zero remainder | **3,863** | 95.1% |
| requests **zero-padded** to 220 bytes | 174 | the rule two rows above |
| a **non-zero** remainder | 21 | four operations, below |
| fail outright | 5 | malformed `user_profile` — all five are this project's own probe frames, not supervisor or panel traffic (§9.7) |

That is **4,037 of 4,063 fully accounted for, 99.4%**, against 3,359 at the start of the pass that produced §10.4.2's `Point_extension2` correction. The twenty-one are:

| operation | bodies | remainder |
|---|---:|---|
| `0x0964 UPL_DEL_TREND` response | 12 | a constant 6 bytes, the first three of which read as an empty string TLV |
| `0x0291 TREND_SETUP_DELETE` request | 6 | a 4-byte `f32`, reading 60.0 on four and 3.0 on two |
| `0x0541 CATEGORY_REMOVE` request | 2 | a **length byte followed by that many characters of a node name** — `0x0F` and fifteen, which is §3.3.2's RAD-50 node-name limit. Not a string TLV: one length byte, not three |
| `0x4208 TEC_DEFINITION` request | 1 | `ff ff`, which is how `application_number = -1` reads on the sibling `0x4200` (§9.5.1) |

None of the four is a decoding hazard — each is a trailing field on one operation, and the body before it reads completely — but each is a field the library does not declare, and the last two have a plausible name that is not yet confirmed. [W][OPEN]

On the trailing-byte rule above: **[OPEN]** whether the constant is the body or the whole frame.
Every observed instance is one supervisor talking to one panel, so the routing
slots are the same length throughout and the two readings cannot be told apart
here. At a site with different node-name lengths a frame-sized buffer would give
a different body size — so an implementer should treat 220 as *this site's*
observation, not a protocol constant.

Two structural conventions recur. **CHOICE / tagged union:** several structures begin with a `tag_ : UNSIGNED_8` followed by one alternative per possible type (e.g. `All_points`, `Alarm_object`, `Physical_address_Lenum`); the tag selects which one alternative is actually present on the wire. **Counted array:** a `nrOf<x> : UNSIGNED_16` immediately precedes its `<x> : <T>[]` array. [S]

### 10.2 Shared sub-types

These sub-types appear inside many request/response bodies and are defined once here. Field order is the wire order.

**`User_profile`** — the requester's credential/priority context, prepended to most addressable requests. [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | user_logon | TEXT_ | operator logon name |
| 2 | point_priority | Point_priority (enum) | command priority of this requester |
| 3 | access_class | Access_class | access-rights class |

**`Name_search`** — the addressing/search key in read and command requests (selects the target point/object by name + suffix within a namespace). [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_space | Name_space (enum) | system / user / any (0 / 1 / 0xFFFF) |
| 2 | name_pattern | TEXT_ | point/object base name (may be a pattern) |
| 3 | suffix_pattern | TEXT_ | name suffix (the `Base + Suffix` split; see naming §) |
| 4 | last_name_space | Name_space (enum) | resume key for paged search |
| 5 | last_name | TEXT_ | resume key |
| 6 | last_suffix | TEXT_ | resume key |

**Wire-confirmed, including the paging.** This sub-type was defined here from the
type system. Parsing every request body in the corpus against it (after the
scope preamble where one is present) gives **10,743 bodies that are *exactly* a
`Name_search`** — the struct consumes the whole body, nothing left over — and
**480 more where it fits as a prefix** with operation-specific fields following.
The wire layout is `u16 name_space | TLV name_pattern | TLV suffix_pattern |
u16 last_name_space | TLV last_name | TLV last_suffix`, with the TLV of §8. [W]

Twenty opcodes are covered. Exactly a `Name_search`: `0x0981 UPL_ALL_POINT`,
`0x0220 POINT_LOG_VALUE`, `0x0984 UPL_ALL_TREND`, `0x0971`, `0x0961`, `0x0982`,
`0x0294`, `0x0974`, `0x0263`, `0x0244`. As a prefix: `0x0240 POINT_CMD_VALUE`,
`0x0241`, `0x4222`, `0x0295`, `0x0983`, `0x02A8`, `0x0291`, `0x0964`, and
`0x0220`/`0x0294` again — **the same opcode takes both forms**, so a parser must
key on body length, not assume one shape per opcode. [W]

**The resume keys resume.** "Resume key for paged search" was an interpretation
of the field names. Across consecutive calls on the same connection, the next
request's `last_name` appears in the previous reply **6,957 times with zero
exceptions**. A caller opens a walk with `*` patterns and empty resume keys; each
reply supplies the keys for the next call; the walk ends when the panel answers
`0x0003 not_found`. That is the enumeration idiom for the whole `UPL_ALL_*`
family, and it is now observed rather than inferred. [W]

**`Name_response`** — how a returned object names itself. [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_space | Name_space (enum) | namespace of the returned name |
| 2 | name | TEXT_ | base name |
| 3 | suffix | TEXT_ | suffix |

**`All_points`** — the polymorphic point-value body (CHOICE). The `tag_` byte selects exactly one L-type alternative; the alternative's layout is the per-type value/quality block. [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | tag_ | UNSIGNED_8 | selects the point type (maps to `Point_type` enum: 1=ldi … 24=ppcl_lai) |
| 2..17 | ldi / ldo / lai / lao / l2sl / looap / lpaci / l2sp / looal / lfssl / lfssp / ldao / lenum / lfmsl / lfmsp / ppcl_lai | per-type value block | exactly one present, per `tag_`; the analog types carry an `FLOAT_` value, digital/state types carry state + quality |

**`Physical_address_Lenum`** — optional LENUM physical address (CHOICE: `not_present : NULL_` or `present : present_`), trailing many point responses. [S]

**`Point_priority`** (enum, 1 byte on the wire) — the command-priority ladder shared by writes and the scope tag: `none=0, tec_ovrd=1, pdl=5, host_2=10, host_3=15, host_4=20, host_5=25, host_6=30, emer=32 (0x20), smoke=34 (0x22), oper=35 (0x23)`, plus the BACnet 16-level band 101–116. The `User_command_priority` enum is the same ladder truncated to the operator-reachable subset. [S]

**`Point_value`** — the typed value carried in commands and trend samples; its concrete encoding is the per-type block selected by point type (analog = `FLOAT_` BE; digital/enum = small integer state). [S]

**`Cov_mask`** (enum) — the COV condition bitmask: `data=0, failure=1, alarm=2, service=3, priority=4, TCU=5, temp_all=6, proof_on=7`. Selects which change classes a subscription annunciates. [S]

#### 10.2.1 Two body idioms not covered above

Both were found by decoding operations the catalog listed but never described,
and both change how a parser must be written. [W]

**A `;key=value;` text sub-encoding inside a TLV.** Some records carry
configuration as ASCII key/value pairs inside an ordinary TLV — semicolon
separated, terminated by a full stop — rather than as typed fields:

```
;bd=9600;pa=1;mk=0.
;mid=<node-name>;ety=110;pdl=24.
```

A decoder that treats every TLV as an opaque string will not be wrong, but it
will miss structure that is there to be read.

**A type-tagged optional value.** A single tag byte selects whether a value
follows and how wide it is:

```
02 42 70 00 00     tag 0x02 -> a big-endian f32 follows (here 60.0)
00                 tag 0x00 -> no value
```

Two otherwise identical requests therefore differ in total length by four bytes.
**Any field after such a tag is at a variable offset**, so a fixed-offset reader
of the remainder is wrong whenever the value is absent. Observed in
`0x0291 TREND_SETUP_DELETE` and `0x02A8 TREND_EVENT_ARC_SETUP`, which share one
request grammar.

#### 10.2.2 `0x099F UPL_ALL_PORT` — reading a panel's communication ports

A three-byte request returns the panel's entire port inventory, one record per
call. It is the clearest example of the paging convention of §10.2.3.

```
request:  <begin> <end> <last>   begin/end bound the port range; last is the
                                 resume key -- 0xFF (outside the range) starts
00 04 FF -> 00 04 00 -> 00 04 01 the walk, thereafter the port just returned
-> 00 04 02 -> 00 04 03          past the end -> dir=0x05, 0x0003 not_found
-> 00 04 04
```

An earlier version of this section read the first two bytes as a fixed prefix
and the third as an index. They are the requested range: **the caller chooses
which ports to enumerate**, and every observed walk asked for `0`–`4`. [W]

The reply is a TLV sequence: the node's own name, two single-`.` TLVs, then two
TLVs in the `;key=value;` form of §10.2.1, then a human-readable description.
A complete walk of one panel:

| `pa` | Description | `bd` |
|---:|---|---|
| 0 | USB Modem port | 9600 |
| 1 | HMI port | 9600 (115200 on one panel) |
| 2 | Telnet port | 9600 |
| 3 | USB Tool port | 9600 |
| 4 | USB Printer port | 9600 |

`pa` tracks the walk index across all five records, so it is the **port
address** — not, as the abbreviation invites, parity. `bd` is the line rate and
`mk` a mask; the second pair carries the node's own id plus two values constant
across every record and every panel observed.

This is the cheapest way to learn what links a panel actually has, and it is
directly relevant to §6.8: these panels carry a modem port, an HMI port and a
tool port, all serial, all enumerable over the network with their line
parameters. [W]

#### 10.2.3 Range-and-resume: how every enumeration is paged

Every bulk read in P2 is a **single-record walk driven by a resume key the
caller echoes back**, and the request is always the same two parts: a selector
saying what to enumerate, and the key of the last record received. There is no
frame-level continuation flag and no server-side cursor — §12 makes the same
point for `UPL_ALL_*`; this is the request-side shape it takes. [W][S]

The selector comes in four encodings, and which one an operation uses is
predictable from what its objects are named by:

| Selector | ASDU type | Objects | Example operations |
|---|---|---|---|
| **name + suffix** | **`Name_search`** | things with a point-style two-part name | upload point, alarm setup, alarm mode, trend |
| **name only** | **`Team_search`** | things with a single name | upload PPCL, TEC, EQS zone/mode, SSTO, UC, LON, MS/TP device, program |
| **numeric range** (`begin`, `end`) | — | things addressed by number | ports (`u8`), partners (`u16`), alarm messages (`u16`) |
| **object id** (`u32`) | — | BACnet-side objects | the BACnet object upload |

The two name selectors are named types in the protocol's own model, and their
fields make the "selector plus resume key" shape explicit — **the resume key is
not a separate trailing field, it is the second half of the search struct**: [S][W]

| `Team_search` | | `Name_search` | |
|---|---|---|---|
| `name_space` | `Name_space` (§8.5) | `name_space` | `Name_space` |
| `name_pattern` | `TEXT_` — the selector | `name_pattern` | `TEXT_` — the selector |
| | | `suffix_pattern` | `TEXT_` |
| `last_name_space` | `Name_space` | `last_name_space` | `Name_space` |
| `last_name` | `TEXT_` — **the resume key** | `last_name` | `TEXT_` — **the resume key** |
| | | `last_suffix` | `TEXT_` |

So "start at the beginning" is `last_name` = the empty TLV `01 00 00`, and a walk
advances by copying the name just returned into `last_name`. Wire-confirmed: an
11-byte `Team_search` reading `00 00 | 01 00 01 '*' | 00 00 | 01 00 00` — namespace
`system`, pattern `*`, empty resume — draws the first record, and the same
request with the returned name in `last_name` draws `0x0003` (§15.3.2). The two
types are **not interchangeable**: `Name_search` is four bytes plus two TLVs
longer, and a decoder that assumes the shorter one mis-frames everything after
it. [W]

The resume key follows the selector and its width tracks the object: nothing at
all where the search pattern itself carries the resume name, one byte for alarm
mode, two for PPCL, and the same width as the range for numeric selectors. Two
conventions are worth stating because a client gets them wrong on the first
try:

**A resume value outside the requested range means "start at the beginning".**
Ports use `0xFF` against a `0`–`4` range, partners `0xFFFF` against `0`–`16`,
alarm messages `0` against `1`–`250`. It is not a fixed sentinel — it is any
value the range cannot contain. [W]

**Paging can happen inside an object, not only across objects.** The PPCL upload
resumes on a **line number** (`u16`): the walk enumerates program text one line
at a time, and the resume key advances within the program before moving to the
next one. Its responses carry the program name, a mode field, and the line's
text — PPCL source travels in clear. [W]

Measured across the corpus: of the upload requests whose object class uses a
name selector, **6,998 are exactly the search struct** with no resume tail and
**2,517 carry the two-byte PPCL line key**; the alarm-mode walk's one-byte key
appears exactly where the struct table says it should. A handful of families carry an
additional trailing key. The **TEC** family's is now identified: a 2-byte
**`application_number`** after the search struct, with `0xFFFF` as the wildcard —
confirmed across four sibling opcodes, one of whose ASDU definitions omits it
while the wire carries it. The EQS schedule set and trend delete remain
**[OPEN]**. [W]

### 10.3 Read / command / COV core

**`AP2_POINT_LOG_VALUE` request (0x0220)** — present-value read. [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | user_profile | User_profile | requester context |
| 2 | name_search | Name_search | target point selector |

**`AP2_POINT_LOG_VALUE` response (0x0220)** — present-value reply (this same response shape backs `UPL_ALL_POINT`, `POINT_LOG_ALARM`, and `COV_ENABLE` responses). [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_response | Name_response | the point's own name |
| 2 | point | All_points | typed value + quality block (analog → f32 BE) |
| 3 | lenum_address | Physical_address_Lenum | optional LENUM address |
| 4 | point_extension2 | Point_extension2 | optional extension block |

On the wire the value block sits inside the `All_points` alternative: an f32 BE value preceded by a **4-byte quality sentinel** (`3F FF FF Fx` good, `00 00 00 00` otherwise) and then a **3-byte group `00 <comm-status> <point-subtype>`** — the comm-status byte is 0 (live) / 1 (stale), and the trailing byte is a 1-byte point sub-type code (observed `0x02`/`0x04`/`0x06`, and `0x01`). [W]

**`AP2_POINT_CMD_VALUE` request (0x0240)** — point command / write (DESTRUCTIVE). [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | user_profile | User_profile | requester (carries command priority) |
| 2 | name_search | Name_search | target point |
| 3 | point_value | Point_value | the value to command (analog f32 BE; digital/enum state) |
| 4 | point_priority | Point_priority (enum) | priority at which to command |

**`AP2_POINT_CMD_PRIORITY` request (0x0241)** — command at a priority without changing value / release a priority level (DESTRUCTIVE). [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | user_profile | User_profile | requester |
| 2 | name_search | Name_search | target point |
| 3 | point_priority | Point_priority (enum) | priority to assert/release |

**`AP2_COV_ENABLE` request (0x0271)** / **`AP2_COV_DISABLE` request (0x0273)** — subscribe / unsubscribe to change-of-value on a point. Identical body. [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_response | Name_response | target point name |
| 2 | cov_mask | Cov_mask (enum) | which change classes to (un)subscribe |

The COV-enable response returns the point's `All_points` value block (same shape as the read response). On the wire the enable/disable pair is also distinguishable by a 2-byte trailer (`00 FF` enable vs `00 00` disable). [W]

**`AP2_COV_ANNUNCIATE` request (0x0274)** — the panel-originated COV report (highest-volume opcode, 53,101 request frames under the §9.5 criteria; pushed on `direction == 0x00`, acknowledged with a 0-byte success). [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | nrOfannunciate_request | UNSIGNED_16 | count of annunciate records that follow |
| 2 | annunciate_request | Annunciate_request[] | the records (see below) |

**`Annunciate_request`** (one COV record) — the per-point change payload. [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_response | Name_response | the changed point |
| 2 | value | FLOAT_ | new value (f32 BE) |
| 3 | point_priority | Point_priority (enum) | active command priority |
| 4 | control_status | Control_status (enum) | remote / tool-override / by-priority / manual / etc. |
| 5 | out_of_service | BOOLEAN_ | point OOS |
| 6 | failed | BOOLEAN_ | comm-failed |
| 7 | proof_on | BOOLEAN_ | proof active |
| 8 | operator_disabled | BOOLEAN_ | operator-disabled |
| 9 | program_disabled | BOOLEAN_ | PPCL-disabled |
| 10 | commanded_to_alarm | BOOLEAN_ | forced alarm |
| 11 | alarm_state | Alarm_state (enum) | normal / alarm / high / low / trouble |
| 12 | alarm_priority | Alarm_priority (enum) | priority_0..6 |

The boolean run (fields 5–10) is the wire source of the point operating-state names (Normal / Failed / Out-of-Service / Proofing / Alarm-by-Command / Operator-Disabled / Program-Disabled); these are the semantic meaning of the COV condition bits. [S][I]

**They are six independent flags, not a seven-way enumeration — do not model them as one state.** The type system declares six separate `BOOLEAN_` fields and imposes no exclusivity among them, so a point may legitimately report `failed` and `out_of_service` together, and "Normal" is not a value but the absence of all six. A client that collapses the run into a single state field must therefore choose a precedence order of its own, and that order is a local UI decision, not something P2 specifies. [S]

**The vendor's own display confirms the combinations are real.** Its subpoint
status column shows *"one of five statuses: Alarm, Failed, Out of Service,
**Alarm/Out of Service**, **Alarm/Failed**"* — two of the five are compound, so
the underlying condition is a set of flags being rendered, not an enumeration
being named. It also shows what a client's precedence choice looks like in
practice: this one surfaces the two combinations it considers worth
distinguishing and does not attempt all 64. [D]

The *asserted* values remain unconfirmed from the wire and this corpus cannot settle them: across the cached `0x0274` bodies the entire run is zero, because every point reporting was healthy. Confirming which flag carries which meaning needs a capture taken while a point is in each state — the same gap §8.5's layout-precision note records. **[OPEN]**

### 10.4 The point model (Point_base)

`Point_base` is the rich point-definition structure returned by point-look/definition reads; it shows the full point model the protocol carries. [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | point_type | Point_type (enum) | L-type (ldi/ldo/lai/lao/l2sl/looap/lpaci/…/lenum) |
| 2 | nrOfnames | UNSIGNED_16 | count of names |
| 3 | names | Name_response[] | the point's name(s) |
| 4 | point_descriptor | Point_descriptor | free-text descriptor |
| 5 | access_class | Access_class | access-rights class |
| 6 | out_of_service | BOOLEAN_ | OOS flag |
| 7 | failed | BOOLEAN_ | comm-failed flag |
| 8 | control_status | Control_status (enum) | control source |
| 9 | point_value | Point_value | current value |
| 10 | point_priority | Point_priority (enum) | active priority |
| 11 | point_totalizer | Point_totalizer | accumulator (LPACI) |
| 12 | alarm_object | Alarm_object | alarm configuration (CHOICE by alarm-object type) |

The point types are the L-type vocabulary: ldi=Digital Input, ldo=Digital Output, lai=Analog Input, lao=Analog Output, l2sl/l2sp=2-State Latched/Pulsed, looal/looap=On/Off/Auto Latched/Pulsed, lfssl/lfssp=Fast-Slow-Speed Latched/Pulsed, lpaci=Pulse-Accumulator/Counter Input, ldao=Dual Analog Output, lenum=Enumerated, lfmssl/lfmssp=Fast-Multi-Speed variants, ppcl_lai=PPCL-resident analog. Analog points carry per-point Slope + Intercept for engineering-unit conversion, applied by the client from the point table — not carried on each value frame. Both are **on the wire**, inside the analog form of `real_addr_` (§10.4.2), so a client reading a point definition has the scaling without a separate lookup. [S][W]

#### 10.4.1 `All_points` — the point CHOICE, and how to read its tag

Most point-bearing bodies do not carry a point *structure* directly; they carry
`All_points`, a tagged union whose arms are the sixteen logical point types:

```
All_points :  tag_ : UNSIGNED_8
              ldi_  ldo_  lai_  lao_  l2sl_  looap_  lpaci_  l2sp_
              looal_  lfssl_  lfssp_  ldao_  lenum_  lfmsl_  lfmsp_  ppcl_lai_
```

**`tag_` is a `Point_type` enum value, not a positional index.** This
distinction is not cosmetic: the enum **skips 5 and jumps from 7 to 11**, so
counting arms and reading the enum agree for the first four values and diverge
for every one after. [S][W]

| `tag_` | arm | | `tag_` | arm |
|---:|---|---|---:|---|
| 1 | `ldi` — digital input | | 13 | `looal` |
| 2 | `ldo` — digital output | | 14 | `lfssl` |
| 3 | `lai` — analog input | | 15 | `lfssp` |
| 4 | `lao` — analog output | | 20 | `ldao` |
| 6 | `l2sl` — two-state latched | | 21 | `lenum` — enumerated |
| 7 | `looap` — on/off/auto pulsed | | 22 | `lfmssl` |
| 11 | `lpaci` | | 23 | `lfmssp` |
| 12 | `l2sp` | | 24 | `ppcl_lai` |

Sixteen arms, not eleven — the enum runs to 24, and the values above 15 are as
real as the rest: **`lenum` (21) is wire-observed**, in COV responses. The
`All_points` arm list and `Point_type_enum` agree name-for-name at every value,
with one caveat that matters to an implementer: the arm list spells arms 22
and 23 `lfmsl`/`lfmsp` while the enum spells them `lfmssl`/`lfmssp`. The values
are not in doubt, and this is not a transcription slip to be shrugged off — it
is what breaks the arm-resolution rule below for those two arms. [S]

A decoder that indexes the declared arm list positionally will read the first
four point types correctly and **mislabel the other twelve** — silently, because
each arm still parses, just as the wrong type. The arm list is written in enum
order, which is exactly what makes the mistake easy.

**The `lao` arm carries no undeclared bytes, and three editions of this section
said it did.** The retraction is worth the space, because the error was not a
misread byte — it was a *second* rule invented to absorb the shortfall of a
first one, and each hid the other.

Earlier editions recorded: "the `lao` arm carries two bytes the structure does
not declare", holding on `0x4221` (42 bodies), `0x0981` (30), `0x0271` (28),
`0x0220` (2), `0x0971` (2) — **104 bodies for the rule and none against it**.
That measurement was correct. What it measured was not the `lao` arm.

`Point_extension2` was being read as a u16 **byte length** followed by that many
bytes. It is a u16 **entry count** followed by that many self-describing entries
(§10.4.2), so the length reading falls short by 3 bytes of header per entry —
and the `lao` points are precisely the ones whose extension is non-empty. Two
bytes of the shortfall were being made up in the arm, which put the walk back on
track for the operations above and derailed it for the trend responses, whose
extension sits elsewhere in the body.

The 2×2, over all 4,063 bodies, counting only those that consume to **exactly**
zero remainder: [W]

| | `Point_extension2` as a length | as an entry count |
|---|---:|---:|
| `lao` +2 applied | 3,359 | 3,255 |
| **no `lao` +2** | 3,255 | **3,401** |

Per body rather than in total: **42 bodies for the count-and-no-`+2` reading and
zero against it.** The 42 are the `0x0294`/`0x0295` trend responses, which now
consume to zero on **every** body — 52 of 52 and 60 of 60 — and with them the
last two `All_points` arms reach 100%: `lao` is 148 of 148 (§8.5).

Two lessons, both general. **A rule with "104 for and none against" can still be
false** if what it corrects for is an error upstream of it; the earlier test held
the extension reading fixed, so it could only ever confirm the pair. And **a
compensating error is easiest to find where the compensation does not apply** —
here, in the one family of responses that carries the extension somewhere else.
[W]

The mapping is corroborated by an authority independent of both the structure
definition and the enum — the **point descriptors**, free text written by
whoever commissioned the site. Across all 71 `0x0508 ALARM_PRINT` request
bodies: [W]

| `tag_` | Arm | Frames | What the descriptors describe |
|---|---|---:|---|
| `0x01` | `ldi` — logical digital input | 14 | boiler and fire-panel **alarm and status** inputs, without exception |
| `0x03` | `lai` — logical analog input | 47 | supply, return and zone **temperatures**, without exception |
| `0x06` | `l2sl` — logical two-state, latched | 10 | supply and exhaust **fan start/stop** points, without exception |

Alarms and statuses under the digital-input arm, temperatures under the
analog-input arm, fan start/stop under the two-state latched arm, across all 71
frames. The
descriptors are free text typed into a panel database by a commissioning
engineer; they cannot have been fitted to a structure ordering they know nothing
about, which is what makes them an independent check rather than a restatement.

**The arms are named, and the "prologue" is `Point_base`.** The structure
library types each arm *field* in lowercase with a trailing underscore — `ldi_`,
`lao_` — and names the *structure* in upper case with a `_type` suffix:

```
ldi_ -> LDI_type    lai_ -> LAI_type    l2sl_ -> L2SL_type    lenum_ -> LENUM_type   …
```

A resolver matching the field type literally will not find them and will report
the point arms as undefined. They are not.

**The rule resolves twelve of the sixteen. Four have no structure to find:** [S]

| arm field | expected structure | status |
|---|---|---|
| `lfmsl_`, `lfmsp_` | `LFMSL_type`, `LFMSP_type` | the structures are spelled **`LFMSSL_type`, `LFMSSP_type`** — double S |
| `ldao_` | `LDAO_type` | **referenced** by `AP2_Point_Add_LDAO_Request`, never declared |
| `ppcl_lai_` | `PPCL_LAI_type` | absent entirely |

A generator that trusts the rule silently drops four point types; one that
trusts it *and* falls through to a neighbour mislabels them. Neither of the four
is wire-observed here, so the failure would not show up in testing against this
corpus either.

**None of the four is actually undeclared — the extraction lost them.** The
structure catalog of §10.1 is produced by flattening the vendor type system, and
a nested type flattens to a bare name with no definition attached. Read back out
of the type metadata directly, all four are there:

| arm | what the type system declares | so |
|---|---|---|
| `lfmsl_`, `lfmsp_` | `LFMSSL_type` (8 fields), `LFMSSP_type` (9) | present; only the **double S** defeats the naming rule |
| `ppcl_lai_` | `{ pb, lai : LAI_type }` — it **reuses `LAI_type`** outright | decodable with no new information at all |
| `ldao_` | `{ pb, ldao : LDAO_type }` where `LDAO_type` is declared with **zero fields** | an `ldao` point is the base and nothing more |

The same recovery settles `use_proof_`, which gated the seven proofed arms and
was the largest single blocker in the document at 48 operations:

```
use_proof_  =  physical_address_DI : Physical_address_DI    (CHOICE: 1 B or 6 B)
               point_proof_delay   : Point_proof_delay      (proof_delay u16
                                                             + proof_status)   3 B
```

so **4 bytes for a proofed point with no physical proof input, 9 with one** — it
has no single width, which is why no fixed-width search could ever have found
it. The content is exactly what the name promises: the address of the contact
that reports the point actually did what it was told, and how long to wait
before deciding it did not.

**All sixteen arms are now decodable**, six of them wire-observed here and ten
resting on the type system alone. That is the state to hold in mind when reading
§10.9: the arms stopped being the document's bottleneck. [S]

And what precedes the arm is `Point_base`, common to every point: [S][W]

| Field | Type | Wire |
|---|---|---|
| `point_type` | `Point_type` | 1 byte — the tag above |
| `nrOfnames` | u16 BE | 2 in every observed body |
| `names[]` | `Name_response` × n | system view, then user view |
| `point_descriptor` | `TEXT_` | free text (declared empty in the library; a TLV on the wire) |
| `access_class` | `BITSTRING32` | 4 |
| `out_of_service`, `failed` | `BOOLEAN_` | 1 each |
| `control_status` | enum | 1 |
| **`point_value`** | `Point_value` | **4 — IEEE-754 f32** |
| `point_priority` | `Point_priority` | 1 — the §8.2 ladder |
| `point_totalizer` | CHOICE | tag `0` = `disabled`, 0-byte arm |
| `alarm_object` | CHOICE | tag `0` = `no_alarming`, 0-byte arm |

then the arm's own fields, then `Physical_address_Lenum` and
`Point_extension2` where the enclosing response carries them.

**Worked example — an enumerated point, every byte accounted for.** `LENUM_type`
is a single `state_text_table`, so this is the whole tail after the descriptor,
fixed at 20 bytes across 139 responses: [W]

```
00 00 00 00   access_class
00 00 00      out_of_service, failed, control_status
3F 80 00 00   point_value  = 1.0            <- f32
23            point_priority = 0x23 = OPER  <- the ladder of 8.2
00            point_totalizer  tag 0 = disabled
00            alarm_object     tag 0 = no_alarming
FC 13         state_text_table = -1005      <- LENUM_type, SIGNED (the arm ends here)
01            lenum_address tag 1 = present  <- the ENCLOSING structure
01            present_
00 00         point_extension2, entry count 0
```

Note where the point stops. `state_text_table` is the last byte of the arm; the
three fields after it belong to the **enclosing response**, which declares
`lenum_address : Physical_address_Lenum` and then `point_extension2` after
`All_points`. Reading them as part of the point is how an earlier edition of
§10.4.2 came to describe `real_addr_` as eight bytes.

An enumerated point's value arrives as an f32 of `0.0`/`1.0`/`2.0`; the priority
byte reads off the command ladder; and the two bytes before the address are the
state-text-table id. A decoder can therefore read **point type, identity, value,
priority, alarm state and text-table** out of any point-bearing body.

**The rule generalises, and it is the safe way to read any CHOICE here.** A
`tag_` is an enum value drawn from that structure's own enum type — not an
ordinal. `Eqs_start_where` makes the same point from the other direction: its
tag `0` selects `beginning : NULL_` and tag `1` selects `last_mode : SHORT_`,
which *is* positional, because that particular enum happens to start at zero and
skip nothing. Reading either structure by position alone gets one of them wrong.
[S][W]

**But most CHOICEs here are far easier than that, and it is worth knowing which
kind you are looking at before reaching for an enum table.** Counting over the
complete type system — the flattened catalog plus the nested types it drops
(§10.1) — there are **73** CHOICE structures in three groups: [S]

| shape | count | what a decoder needs |
|---|---:|---|
| **2 arms, one of them `NULL_`** — an optional field | **42** | nothing but the arm order: one tag means absent and consumes no further bytes, the other means present |
| 2 arms, neither `NULL_` — a union of two forms | 14 | which tag picks which of the two |
| **3 or more arms** | **17** | a genuine selector |

For the 56 two-arm CHOICEs the enum and ordinal readings **cannot diverge** —
there are only two arms. So the "tag is an enum, not an ordinal" hazard is
confined to the 17, and among those only two selectors have been identified:

| CHOICE | selector | values |
|---|---|---|
| `All_points` | `Point_type_enum` | **sparse** — skips 5, 8–10 and 16–19, so the tag is *not* the arm index |
| `Alarm_object` | `Alarm_object_type_enum` | **ordinal** 0–8, so for this one the tag *is* the arm index |

**`All_points` is the sparse one, and as far as the evidence goes it is the only
one.** The other fifteen — `MiscData` at 48 arms, `Command_Type` at 8,
`Trend_type` and `Duct_type` at 3 — have no selector enum that can be matched to
their arm names. Ordinal is the natural guess and is right for `Alarm_object`;
it is wrong for `All_points`, which is precisely why the guess must not be
silent. Two of the fifteen are now settled anyway, by other means:

- **`Trend_type` is ordinal**, and confirmed three ways. Its three arms —
  `point_cov : NULL_`, `trend_cov` (4 B), `time` (4 B) — correspond one-to-one
  with the three trend definitions a vendor engineering tool offers: *use the
  point's own COV limit* (nothing to carry), *a special trend COV limit* (a
  value), and *a sampling interval* (a time). [D] On the wire **all three tag
  values occur — 0, 1 and 2 in declaration order** — across 60 `0x0984`
  responses that consume exactly under that reading: tag 0 on 48 definitions,
  tag 1 on 4, tag 2 on 8. [W]
- **`Duct_type` does not need its mapping to be decoded.** All three arms are
  **8 bytes** — `Rectangle {height, width}`, `Circle {pad, diameter}`,
  `Oval {height, diameter}`, two `f32` each — so the tag cannot change the
  framing, only the labels on the two floats. Of 60 `0x0986` TEC responses, 59
  carry `no_duct` and one carries a duct, tagged `1`. An earlier edition left the
  *labels* open on that single observation; the tag map is read from the codec's
  own jump table (§10.4.6) and `Duct_type` is `0` `Rectangle`, `1` `Circle`,
  `2` `Oval`, so the one duct in this corpus is a **`Circle`** and its two floats
  are `pad` and `diameter`. One observation was never the evidence that
  mattered. [S][C][W]

> A single transcription discrepancy causes both failures at once. The arm
> fields are spelled `lfmsl`/`lfmsp` and both the structures **and**
> `Point_type_enum`'s members are spelled `lfmssl`/`lfmssp`. That one extra `S`
> defeats the mechanical rule that resolves an arm to its structure *and* the
> match that identifies a CHOICE's selector enum.

**What does bite on the two-arm ones is arm order, and it is not uniform.** Of
the 42 optional-presence CHOICEs, **34 put `NULL_` first** — so tag `0` means
*absent* — and **8 put it second**, where tag `0` means *present*:

```
LocalOrRemote          client_COV_Increment_   NetworkVariable_
Physical_address_AI    Physical_address_AO     Physical_address_DI
Physical_address_DO    Physical_address_PA
```

Five of the eight are the physical-address family of §10.4.2 — the most-used
structures in the point model. An implementer who generalises "tag 0 means the
field is absent" from the common case reads **every physical address backwards**,
and gets a plausible parse rather than an error. Read the arm order from the
structure, every time. [S]

**Where this now stands.** Every width in the point body is measured, and the
model consumes **5,795 of 5,807 walked points (99.8%) with zero remainder**: [W]

| leaf | width | how it is pinned |
|---|---|---|
| `State_text_table` | 2, **signed** | §11.5 — every observed value is negative; unsigned it is nonsense |
| `Representation` | 1 | constant across analog points; `Analog_format` = repr + `decimal_places` u8 |
| `cov_limit_` | 5 | CHOICE tag + f32 deadband; the f32 reads `1.0` on points with a deadband and `0.0` without |
| `present_` | 1 | forced jointly with `Point_extension2` by the LENUM tail |
| `Point_extension2` | **u16 entry count + self-describing entries** | §10.4.2 |
| `real_addr_` | **5 / 17 / 12** | §10.4.2 — it is *not* one width, see there |
| `Alarm_object` arms | 38 / 47 / 55 | §10.4.4 |
| `Proof_status` | 1 | the only width that closes an `l2sl` body against the §10.4.4 anchor — 0, 2 and 3 all fail; the enum has two values |
| `enabled_` | 43 | the `Point_totalizer` enabled arm — §10.4.5 |

The twelve bodies that do not close are all points named `test*`, and they fail
for one reason: a `TEXT_` whose `textType` is `0x00` rather than `0x01`
(§8.1). [W]

Six of the sixteen arms are wire-observed here — `ldi`, `ldo`, `lai`, `lao`,
`l2sl` and `lenum`. The remaining tag values are definitional from the enum, but
their bodies have not been seen at this site. [S]

**The same rule, checked on a second CHOICE.** `Alarm_object`'s nine arms —
`no_alarming`, `std_digital`, `std_single_analog`, `std_analog`,
`enhanced_digital`, `enhanced_analog`, `enhanced_lenum`, `bacnet_alarm_analog`,
`bacnet_alarm_digital` — match `Alarm_object_type_enum` name-for-name at every
value, **9 of 9**. That enum happens to be contiguous from 0, so there the tag
*does* coincide with arm position. The lesson is that the coincidence is a
property of the enum, not of the protocol: read the enum, and only then note
whether it happens to be dense. [S]

#### 10.4.2 The physical address, and how a TEC subpoint differs from a panel point

Every point arm ends with a `Physical_address_*` field, and it is a CHOICE with
two arms that answer a question an implementer has to get right: [S][W]

```
Physical_address_AI / _AO / _DI / _DO / _PA
    tag_ : UNSIGNED_8
    real_addr    : real_addr_     <- the point has a physical location
    virtual_addr : NULL_          <- it does not; zero further bytes
```

A **panel-resident software point** — a calculated value, a PPCL variable, a
schedule mode — takes `virtual_addr` and costs one byte. A point on a **terminal
device on the panel's FLN** takes `real_addr_`.

**`real_addr_` is not one structure.** The library names the arm identically in
all five `Physical_address_*` CHOICEs, but that name is the flattened form of an
**anonymous inline type**: the arm of `Physical_address_AI` and the arm of
`Physical_address_DO` are given the same name and carry different content. Three
distinct layouts are wire-measured: [W]

| CHOICE | `real_addr_` | layout |
|---|---:|---|
| `_DI` / `_DO` | **5 B** | FLN, drop, point u16 BE, one boolean |
| `_AI` | **17 B** | FLN, drop, point u16 BE, **slope f32, intercept f32**, 5 B |
| `_AO` | **12 B** | FLN, drop, point u16 BE, **slope f32, intercept f32** |
| `_PA` | **9 B** | FLN, drop, point u16 BE, **gain f32**, one boolean |

**Field by field.** The five variants are declared separately in the vendor type
system — the extraction that produced §10.1's structure catalog flattens a
nested type to a bare name, which is what made them look like one field with
three widths. Read back out of the type metadata they are: [S]

| enclosing CHOICE | `real_addr_` fields | width |
|---|---|---:|
| `Physical_address_DO` | `FLN_lan_number` u8 · `FLN_drop_number` u8 · `FLN_point_number` u16 · `inverted` bool | 5 |
| `Physical_address_DI` | … · `normally_closed` bool | 5 |
| `Physical_address_AO` | … · `analog_scale : Analog_scale` | 12 |
| `Physical_address_AI` | … · `analog_scale` · `analog_sensor : Analog_sensor` | 17 |
| `Physical_address_PA` | … · `gain` f32 · `count_both_edges` bool | 9 |

with `Analog_scale = slope f32 + intercept f32` (8 B) and
`Analog_sensor = sensor_type + intercept_adjustment f32` (5 B).

**Four of these five were already wire-measured, and all four reproduce
exactly** — DI 5, DO 5, AO 12, and AI 17, the last only if `Sensor_type` is one
byte, which is the *only* width that yields 17 (2 gives 18, 4 gives 20). That
agreement is what licenses the fifth. [W][S]

**`_PA` is a correction, and it is now confirmed from the panel.** It was
carried here as 5 B by analogy with `_DI` and `_DO`, and never tested:
`Physical_address_PA` is used by exactly one structure, `LPACI_type`, and **no
`lpaci` point occurs anywhere in the corpus** — 0 of 5,807 walked points. It is
9 bytes, because a pulse-accumulator address carries a `gain` f32 that a digital
one does not. **The controller's own encoder writes exactly that**, in this
order and with these widths — `u8 lan, u8 drop, u16 point, f32 gain, u8
count_both_edges` — so the one width in this table that no capture could reach
is attested by the firmware that produces it. [F]

**The same encoder settles the tag, and it settles it the way §10.4.2 feared.**
The `Physical_address_*` encoder writes the tag byte and then emits the address
**only when that tag is zero**:

```c
FUN_802e9a30(buf, tag);            // the tag, one byte
if (tag == 0) {                    //  <-- tag 0 IS the real_addr arm
    write u8 lan; write u8 drop; write u16 point;  ...
}
```

So for this CHOICE family **tag `0` selects the arm that *has* an address**, and
the empty `virtual_addr` arm is `1`. That was inferred here from arm order and
wire widths; it is now read off the code, on both sides — the panel's encoder
above, and the supervisor's decoder, which compares against `1` and takes
`virtual_addr`. [F][C]

**And it is declaration order after all**, which is worth saying because an
earlier edition of this section drew the opposite conclusion. `Physical_address_*`
declares `real_addr` first, so tag `0` being the address arm *is* the ordinal
reading; what makes it look inverted is only that most other optional-presence
CHOICEs declare the empty arm first. §11.5.1's `scale_` does exactly that — it
declares `virtual_pt` first — and its tags follow **its** declaration order in
turn: tag `0` empty, tag `1` the 20-byte scaling arm (§11.5.1, now settled from
the same source). Two CHOICEs covering the same virtual/physical distinction
number their tags oppositely because they *declare* them oppositely, not because
either departs from a convention. What an implementer must not do is carry a tag
assignment from one CHOICE to another that "means the same thing" — read each
one's own arm order, or its entry in §10.4.6. [C][S]

The distinction the flattening destroyed is also semantic and worth keeping: the
digital-output boolean is `inverted` and the digital-input one is
`normally_closed`. Same width, same position, different meaning — a decoder that
labels both "inverted" is right about the bytes and wrong about the point. [S]

**`real_addr_` is not the exception it looks like — it is the general case.**
Sixty-five names in the type system are declared *inside* a parent, and a
decoder must resolve them **against the enclosing type, not globally**. Six more
turned up behaving exactly like `real_addr_` once anyone looked:
`LON_extension_` (different under `Extended_team_desc` than under
`Extended_team_member`), `name_suffix_`, `xfixed_` (a lone `f32` inside
`cov_limit_`, a counted address array inside `dns_`), `address_` (a
virtual/physical CHOICE in one parent, a bare `UNSIGNED32` IP in another),
`alarm_info_` and `Fln_type_`. Resolving those six by parent removed them from
§10.9's blocked list at a stroke. **A flat type table is therefore not enough to
decode P2**: the same field name, in two structures, is two different layouts,
and nothing in the name says so. [S]

```
a digital output      03 01 00 07 01
                      FLN3 Drop1 Pt7  inverted

one terminal device, two of its analog inputs:
  units " CFM"        02 08 00 23 │ 40 80 00 00 │ 00 00 00 00 │ 06 00 00 00 00
                      FLN2 Drop8 Pt35  slope 4.0    intercept 0.0
  units "DEG F"       02 08 00 04 │ 3e 80 00 00 │ 42 40 00 00 │ 06 00 00 00 00
                      FLN2 Drop8 Pt4   slope 0.25   intercept 48.0
```

This is where an analog point's **slope and intercept** live — §10.4's statement
that analog points carry per-point scaling is a wire fact, not an inference, and
this is the field. A `0.25 / 48.0` pair on a DEG F point is a 0–10 V or 4–20 mA
temperature scaling; `4.0 / 0.0` on a CFM point is a plain gain.

**How the widths are established, and why the obvious method fails.** A width
cannot be settled by whether a body parses: choose any three widths that sum
correctly and every body "parses". The measurement that works is a **difference
between two populations that share every other field** — the same point type
with a real address and with a virtual one:

| LDO tail | composition | length |
|---|---|---:|
| real | `stt 2 │ tag 0 │ real_addr_ │ lenum tag │ ext2` | 11 |
| virtual | `stt 2 │ tag 1 = NULL_ │ lenum tag │ ext2` | 6 |

The difference **is** the address: 5 bytes, independent of what follows it. A
competing split — a 4-byte address with the fifth byte read as the
`Physical_address_Lenum` tag — fits the same totals and is refuted by the tag
being a **value**, not a width: it reads `0x00` (= `not_present`, no `present_`
byte) in 1,084 of 1,095 real-addressed bodies, which under that split makes them
10 bytes long. Every one is 11. [W]

**The field roles are measured against the point names, not asserted from the
layout.** Bytes 0 and 1 are constant within a device in 34 of 34 devices while
byte 3 is constant in only 5; three subpoints of one device read `02 08 00 19`,
`02 08 00 18`, `02 08 00 13` while the same subpoints on a second read
`02 0b 00 …` — same trunk, different drop, same point numbers. Byte 0
independently takes exactly `0`–`3`, the trunk range §3.3 documents from vendor
sources. Three sibling digital outputs on one drop read point numbers 5, 6 and
7 — and a supervisor, queried independently, reports the third of them as
**FLN 3, drop 1, point 7**, which is an authority outside the corpus, the
structure library and the enum alike. [W][D]

The fifth byte of the digital form is a per-point flag, not padding: it is set
on 4 distinct points of 51, never on any of 184 digital *input* frames, and the
supervisor marks those points **inverted**. **[OPEN]** — the same points are
also configured with an initial value of ON, so *inverted* and *initial value*
are not yet separated. [W][D]

**The point number is per application, not per name.** On one device point 24 is
the fourth digital input; on another it is the second. Which name a number maps
to is a property of the TEC's loaded application — the same application the
`0x42xx` family selects with `application_number` (§9.5.1). A client must not
assume a point number means the same thing on two devices.

> **This refines §3.3.** That section says the LAN/Drop/Address 3-tuple "is not
> the wire routing key", which is true and stays true — you address a point by
> **name**, never by tuple. But the tuple is not merely a database concept: it
> **is** on the wire, as the physical-address field of every point that has one.
> The distinction is that the tuple is how a panel *reports where a point lives*,
> not how a client *asks for it*.

**What comes after the point is not part of the point.** Almost every structure
that carries `All_points` declares two more fields immediately after it, and
mistaking them for the point's own tail is the specific error that produced the
"eight-byte address" above: [S][W]

```
<structure> :  … | point : All_points | lenum_address : Physical_address_Lenum
                                      | point_extension2 : Point_extension2
```

`Physical_address_Lenum` inverts the arm order of the others in its family —
**tag 0 = `not_present : NULL_`, tag 1 = `present : present_`**, one byte — so a
decoder that assumes tag 0 means "has an address" is wrong here.

Note which way round the exception runs, because it is the opposite of what the
family suggests: measured across all 73 CHOICEs (§10.4.1), `NULL_`-first is the
**majority** convention at 34 of 42, and `Physical_address_Lenum` follows it. It
is `_AI`, `_AO`, `_DI`, `_DO` and `_PA` that are unusual. [S]

`Point_extension2` is **not a fixed-width field**, and it is not a length-
prefixed blob either. It is a **counted array of self-describing entries**,
exactly as the type system declares it: [S][W]

```
Point_extension2
    nrOftypes         : u16 BE          <- a COUNT of entries, not a byte length
    types             : Point_extension2_type[]

Point_extension2_type
    tag_              : 1 byte          <- Extension2_actuator
    size_of_extension : u16 BE          <- bytes of payload that follow
    payload           : <size_of_extension> bytes
```

Three readings, measured over the whole body corpus by the only figure that
settles it — bodies that consume to **exactly** zero remainder: [W]

| reading | bodies consuming exactly |
|---|---:|
| fixed 2 bytes | far short; desynchronises on every non-empty extension |
| u16 byte length + payload | 3,359 of 4,063 |
| **u16 entry count + entries** | **3,401 of 4,063** |

The count reading wins **42 bodies and loses none**. The two coincide whenever
the count is zero, which it is on 290 of the 396 extensions in this corpus, and
that is why the wrong one survived three editions — together with a second rule
invented to absorb its shortfall, retracted in §10.4.1.

**What is actually in one.** Every non-empty extension here carries exactly one
entry with `tag_` = `1`, which `Point_extension2_type` names
`LAO_actuator_type_extension`, and a payload of 1 or 2 bytes. They appear on
`lao` points and on no other type — which is what the names say: an *actuator*
extension on an analog output. Two of the six distinct blocks observed:

```
00 01 │ 01 00 02 │ 00 06      count 1 │ tag 1, size 2 │ payload
00 01 │ 01 00 01 │ 01         count 1 │ tag 1, size 1 │ payload
```

**A decoder does not need to know what the payload means.** `size_of_extension`
is on the wire in front of it, so an unknown extension type is skippable — which
is why this is the one CHOICE in the type system that blocks nothing despite
having no complete tag map (§10.9). **89 structures carry a `Point_extension2`**,
so getting this wrong desynchronises a large part of the catalog. [S][W]

#### 10.4.3 Do not read the supervisor's point object as the wire model

The supervisor keeps its own logical-point class, and it is much larger than
`Point_base` — on the order of 200 accessors against the twelve fields above.
It is tempting to treat that as a fuller description of the protocol's point.
**It is not, and the difference is not merely one of detail: the class is a
merge of two protocols.** Alongside genuine P2 attributes it carries BACnet
ones, and nothing in a method name distinguishes them:

| Accessor | Actually belongs to |
|---|---|
| `GetInitialPriority`, `IsNormClosed`, `HasProof` / `GetProofNum`, `GetProofDelay` | P2 point configuration |
| `GetTimeDelay` | BACnet — the `TO-OFFNORMAL` / `TO-NORMAL` dwell against `High_Limit`/`Low_Limit` |
| `GetRelinquishDefault` | BACnet — the value taken when priorities 1–16 are all empty |
| `Get/SetBACnet*` (a dozen of them), `LogicalPt2BacMap` | BACnet mapping, explicitly |

An implementer mining that class for P2 field names will import BACnet
semantics without noticing. Only accessors corroborated against P2-side
documentation or the wire belong in a P2 decoder. [S][D]

What the class *is* good for is confirming that the static configuration
attributes live in the point-definition record rather than in `Point_base` or
in the COV push (§13.1): **initial priority** (the priority a point holds at
start-up; pre-APOGEE panels accept only `NONE` or `OPER`), **normally-closed**
(a physical-DI wiring sense — whether the contacts are closed with no energy
applied), and **proof present / proof point address / proof delay** (the
monitored input that verifies a commanded output actually moved, §11.3). These
are point-definition fields, not value-frame fields. [D]

Two method names on the same class are worth noting for a different reason:
`FormatDefinePointRequest` and `FormatReadTotalizedVal` are request *builders*.
The supervisor's encoder layer names its operations after the operation, not
after the opcode — which is the CPI tier of §9.1.1 seen from above. [S]

#### 10.4.4 The `Alarm_object` arms

`Point_base`'s last field is `alarm_object : Alarm_object`, a CHOICE over nine
arms (§10.4.1). The zero arm `no_alarming` is `NULL_`, which is why bodies from
a lightly-alarmed site decode without it; **every point that actually has an
alarm configured takes one of the other eight**, and none of them is declared.

Three are wire-measured, and the measurement is anchored rather than fitted. The
`0x0508 ALARM_PRINT` request is the one structure that carries alarmed points
*and* pins their end without an assumed width:

```
user_profile : User_profile │ point : All_points │ alarm_message_node u8
│ alarm_message_number u16 │ alarm_message TEXT_ │ lenum_address
│ nrOfalarm_buffer u16 │ alarm_buffer[] │ point_extension2
```

A `TEXT_` declares its own length, so the message pins the end of the point
three bytes before it and everything after must consume the body exactly.
Searching for the arm width that satisfies both: **54 of 54 bodies admit exactly
one width — none admits two, none admits none.** [W]

| arm | width | observed on | how confirmed |
|---|---:|---|---|
| `no_alarming` | 0 | all types | `NULL_` |
| `std_digital_` | **38 B** | `ldi`, `l2sl` | anchor; and independently `ldo` alarmed tail 44 − unalarmed 6 |
| `std_analog_` | **47 B** | `lai` | anchor, 44 bodies |
| `enhanced_analog_` | **55 B** | `lai` | anchor, 3 bodies |
| `enhanced_digital_` | **48 B** | digital | solved on the alarm-mode uploads, then **independently confirmed** — see below |
| `std_single_analog_` | 42 B | — | type system only |
| `enhanced_lenum_` | 50 B | — | type system only |
| `bacnet_alarm_analog_` | 16 B | — | type system only |
| `bacnet_alarm_digital_` | 7 B | — | type system only |

**All nine arms are pinned, and the last four came free with a validation
attached.** The arm types are declared *inside* `Alarm_object` and were lost by
the catalog's flattening (§10.1); read back out of the type system they size to
`0, 38, 42, 47, 48, 55, 50, 16, 7` in tag order. What makes that usable rather
than merely available is that **every one of the five widths already measured on
the wire reproduces exactly** — including `enhanced_digital_` at 48, which had
rested on four bodies and a subtraction and was labelled thin here for that
reason. Five agreements out of five, and the four remaining arms follow from the
same source. [W][S]

**A fourth arm, and it is not anchored the way the first three are.** The
`0x0982 UPL_ALL_ALARM_SETUP` and `0x0983 UPL_ALL_ALARM_MODE` responses both end
in `alarm_object`, so once every other field in them is pinned (see
`Alarm_mode_type` in §10.1, settled in the same pass) the arm width follows by
subtraction. Two distinct bodies in each carry tag `4`:

| solved from | widths giving an exact consume on every body |
|---|---|
| `0x0982 Upl_All_Alarm_Setup_Response` | **48** — unique |
| `0x0983 Upl_All_Alarm_Mode_Response` | 48 **or** 55 |
| intersection | **48** |

The two structures have different field lists, so a compensating error would
have to survive both — but it rested on **four bodies**, against 54 for the arms
above, and `0x0983` alone would not distinguish 48 from 55. It was published as
pinned-but-thin for that reason.

**It is no longer thin.** The type system, read directly (§10.1), declares
`enhanced_digital_` and it sizes to **48** — an independent source agreeing with
a value derived by subtraction from four bodies. The same read supplies the four
arms that were never observed here. [W][S]

The size is at least coherent with its neighbours — `std_digital_` 38 →
`enhanced_digital_` 48 is +10, against `std_analog_` 47 → `enhanced_analog_` 55
at +8, so "enhanced" costs 8–10 bytes in both families.

**Inside an arm.** The first 24 bytes of all three are three `DATE_TIME` (§8.3.4)
— `time_of_current_state`, `time_of_first_alarm`, `time_of_acknowledgment` — and
each carries the weekday its own date falls on, which is a free alignment check
(§10.8). Bytes 24–36 are `Alarm_object_data` exactly as the library declares it:
`state_changes` u16 then eleven `BOOLEAN_` (`ack_pending`,
`return_to_normal_acks`, `inalarm`, `introuble`, `inalarm_by_command`,
`operator_disabled`, `program_disabled`, `proofing`, `is_enhanced`,
`print_alarms`, `enable_almcnt2`).

The alignment is confirmed by a field no byte count could have forced — the
library names the ninth boolean `is_enhanced`, and it reads:

| byte 34 | `std_digital` | `std_analog` | `enhanced_analog` |
|---|---|---|---|
| observed | CONST `00` | CONST `00` | CONST `01` |

```
std_digital_      38 = Alarm_object_data 37 + 1
std_analog_       47 = Alarm_object_data 37 + 1 + f32 high limit + f32 low limit + 1
enhanced_analog_  55 = Alarm_object_data 37 + 18
```

The analog pair reads as the alarm band §13.3 describes: a chilled-water
temperature at 150 / 35, a discharge-air point at 120 / 35, mixed-air at 75 / 45,
supply-air sensors at 85 / 40 and 85 / 50.

**Every arm's interior, named.** An earlier edition left the enhanced arm's extra
18 bytes open and guessed from three samples that they "begin with two `u16`
delays and contain two `f32`". They do not: they begin with a one-byte priority,
and there is one `f32`. The catalog names all of them, and the same read supplies
the six arms this corpus never produced. Offsets are from the start of the arm;
the seven arms above the rule open with `Alarm_object_data` (0–36) and the two
BACnet arms do not carry it at all: [S]

| arm | total | fields after `Alarm_object_data` |
|---|---:|---|
| `std_digital_` | 38 | +37 `alarm_priority` |
| `std_single_analog_` | 42 | +37 `alarm_priority`, +38 `high_limit` f32 |
| `std_analog_` | 47 | +37 `alarm_priority`, +38 `high_limit` f32, +42 `low_limit` f32, +46 `high_alarm_if_in_alarm` |
| `enhanced_digital_` | 48 | +37 `alarm_priority`, +38 `mode_delay` u16, +40 `level_delay` u16, +42 `alarm_mode_type`, +43…+47 `category0`–`category3` and `extracategory` |
| `enhanced_lenum_` | 50 | as `enhanced_digital_`, then +48 `current_level` u16 |
| `enhanced_analog_` | 55 | as `enhanced_lenum_`, then +50 `differential` f32, +54 `above_setpoint` |
| `bacnet_alarm_analog_` | 16 | **no `Alarm_object_data`** — +0 `inalarm`, `introuble`, `inalarm_by_command`, `proofing`, +4 `high_limit` f32, +8 `low_limit` f32, +12 `alarm_priority`, +13 `msg_no` u16, +15 `high_alarm` |
| `bacnet_alarm_digital_` | 7 | **no `Alarm_object_data`** — +0 `inalarm`, `introuble`, `inalarm_by_command`, `proofing`, +4 `alarm_priority`, +5 `msg_no` u16 |

Three of these were measured from the wire before the catalog was read —
`std_digital_` 38, `std_analog_` 47, `enhanced_analog_` 55 — and the catalog
computes the same three, field by field, with the decomposition this section
already published: `47 = 37 + 1 + f32 + f32 + 1` is exactly `alarm_priority`,
`high_limit`, `low_limit`, `high_alarm_if_in_alarm`. Three agreements out of
three, from sources that could have disagreed. [W][S]

The family also reads as a progression rather than a list: every non-BACnet arm
opens with `alarm_priority`; the analog arms add limits; the enhanced arms drop
the limits for the alarm-mode machinery (`mode_delay`, `level_delay`,
`alarm_mode_type`, five category bytes), and `enhanced_lenum_` and
`enhanced_analog_` extend that by two and seven bytes respectively. [S]

**Taken together with §10.4.1–§10.4.3 the point body is closed: 5,795 of 5,807
walked points (99.8%) consume with zero remainder.** [W]

#### 10.4.5 `Point_totalizer` — the accumulator arm

`Point_base`'s `point_totalizer` is the other CHOICE, and like `Alarm_object`
its zero arm (`disabled`) is `NULL_`. The `enabled` arm is **43 bytes**: [W]

```
Total_rate                1 B     observed 1 and 2
u16                       2 B     reads 2 in every sample -- a count: 3 + 2x20 = 43
  f32 | f32 | f32 | DATE_TIME     20 B, twice
```

The running total is the second `f32` of the first record. `Total_rate` selects
magnitude as well as units — points at rate 1 carry totals near 973,000 with a
second value near 2,244, while rate-2 points carry 20,000–48,000 with a second
near zero. Two same-shaped records behind a count is the protocol's ordinary
counted-array convention (§10.1), and it matches the pair of accumulators the
structure library implies with `includeInCount2` and `enable_almcnt2`.

Both `DATE_TIME` positions are confirmed the cheap way: **all 34 stamps across
the two offsets carry the weekday their own date falls on, 34 of 34** (§10.8).

**The record is declared, and the array is not a fit.** An earlier edition left
this open because the count reads `2` in all 17 samples, which cannot demonstrate
a counted array, and because the three `f32` per record had no names. The catalog
supplies both: [S]

```
Point_totalizer.enabled_
    total_rate              : Total_rate            1
    nrOfstage_totalization  : UNSIGNED_16           2
    stage_totalization      : Stage_totalization[]  20 each

Stage_totalization
    stage       : FLOAT_       4
    total_value : FLOAT_       4
    reset_value : FLOAT_       4
    reset_time  : DATE_TIME    8
```

`nrOfstage_totalization` is a declared u16 count in front of a declared array,
which is §10.1's counted-array convention stated rather than inferred, and
`1 + 2 + 2 × 20 = 43` is the arm width independently derived elsewhere. The three
`f32` are `stage`, `total_value` and `reset_value`, which names the reading this
section already had — the running total is the second — and adds the two it did
not: the first is the stage the accumulator belongs to, and the value near 2,244
on rate-1 points is `reset_value`, the total at the last reset. The 8 bytes after
them are a `DATE_TIME`, `reset_time`. [S][W]

What the corpus still cannot show is a totalizer with a count other than 2, or
any point type other than a supply fan. Neither is needed to read the record.
[W]

#### 10.4.6 CHOICE tags in general — the rule and its exceptions

§10.4.1 shows that `All_points`' tag is an enum value and not a position. The
obvious next question is whether that is peculiar to point types or true of every
CHOICE in the protocol, and it is answerable: the vendor's codec selects an arm
by branching on the tag, so the numbering is stated in the code for every CHOICE
it codes. It states it in four different shapes, and it took all four to finish
the job:

| where the selection is compiled | complete maps |
|---|---:|
| the CHOICE's own decoder, as a jump table | 13 |
| the decoder of the **parent** that holds it — for a CHOICE the compiler inlined into its only user | 11 |
| an **encoder** — which writes the tag its decoder reads, and is the only place three CHOICEs compile the selection at all | 4 |
| a **compare chain** rather than a jump table, in the CHOICE's own decoder or its parent's | 43 |

**72 of the 73 CHOICE types yield a map and 71 are complete** — complete meaning
every declared arm has a tag, which is the only kind a reader can use, since a
map missing an arm cannot select the arm it is missing. The two without a
complete map, `NetworkVariable_` and `Point_extension2_type`, are named as a
field type by **no structure in the catalog**: nothing can reach them, so nothing
is blocked by them. [C]

Each reader was checked against the ones already known before being believed. The
encoder route reproduced the decoder map on **twelve of twelve** CHOICEs where
both exist, with no contradiction and one superset (`BAC_Point_Base`'s ninth arm,
which its `Decode` never lays out). The compare-chain route agreed **twenty**
times with no contradiction, and its 38 new two-armed maps agree with the 38
partial maps the jump-table reader had already produced — **38 of 38 on the tag
they share**. And one of the 38 is checkable against the wire rather than against
the codec: `Physical_address_AI` comes back `0` = `real_addr`, which §10.4.2
established from captured bytes long before. [C][W]

**The rule: the tag is the position in the declared arm list — unless the arm set
mirrors an external enumeration, in which case it carries that enumeration's
values.** Sixty-six of the seventy-one complete maps are positional. Five are
not, and every one of the five is a case where the arms are really something
else's type codes: [C]

| CHOICE | tag values | the numbering |
|---|---|---|
| `All_points` | 1, 2, 3, 4, 6, 7, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24 | the `Point_type` enum (§10.4.1) |
| `BAC_Point_Base` | 0, 1, 2, 3, 4, 5, 13, 14, 19 | the **BACnet object-type** enumeration |
| `BAC_propertystatetype_Choice` | 3, 5, 13, 19 | the same |
| `event_parameter_Tag_` | 1, 3, 4, 5 | the **BACnet event-type** enumeration |
| `Pdl_display_data` | 1, 2 | positional but **1-based** |

Three of these five can be checked against a public standard rather than taken on
trust, and all three hold exactly. The object-type cases: 0 analog-input, 1
analog-output, 2 analog-value, 3 binary-input, 4 binary-output, 5 binary-value,
13 multi-state-input, 14 multi-state-output, 19 multi-state-value — arm names
matching one-for-one, all nine of `BAC_Point_Base`'s arms among them. The
event-type case is sharper still, because it is the *gap* that agrees:
`event_parameter_Tag_` numbers its four arms 1 change-of-state, 3
command-failure, 4 floating-limit, 5 out-of-range, skipping 2 — and ASHRAE 135
numbers change-of-value 2, an event type this CHOICE declares no arm for. The
encoder sends tag 2 to the default label. An implementer decoding a BACnet-side
CHOICE should treat the tag as the BACnet code and not count arms. [C][I]

**A trap worth naming, because it nearly went into this document.** The tag is
not the index into the arm list as the codec writes it: the generated selector
switches on `tag - base`, with `base` the lowest tag value, so a reader that
takes the jump-table index for the tag is off by `base` for the whole type.
`All_points` has base 1 and `event_parameter_Tag_` has base 1, and read naively
`All_points`' sixteen tags all came back one too low — a self-consistent, entirely wrong map that only failed against the
independently wire-derived values of §10.4.1. Where a decoder derives arm
selection from any generated artifact, it must account for that offset. [C]

**Three CHOICEs looked as though the codec never coded them, and it did.**
`localStateText_`, `event_parameter_Tag_` and `scale_` carry a constructor and
nothing else — no `Decode`, no `Encode` — and each blocked operations in §10.9
for that reason. In every case the selection is compiled into the one type that
holds the CHOICE: `scale_` into `Analog_Team_Scale`'s decoder (§11.5.1),
`localStateText_` into `BACnet_MSTP_Extension`'s **encoder**, and
`event_parameter_Tag_` into `BAC_EEO_Object`'s. A CHOICE having no methods says
nothing about whether its numbering is recoverable; it says only that the
compiler had a single call site to inline into. All three are read values, and
none needed a capture. [C]

One caution for anyone repeating this. A parent can hold **several** CHOICEs —
`BAC_EEO_Object` holds two — and a reader that looks for "a switch preceded by a
load of `tag_`" will attribute the first one it finds to whichever CHOICE it was
asked about. Done that way this document would have carried a five-tag map for a
two-arm CHOICE with every tag selecting the same arm. Two guards: match the load
pair `<field>` then `tag_`, and discard any map that sends two tags to one arm
rather than publishing it. The same two guards catch the mirror-image error
inside a CHOICE's own decoder, where **decoding an arm loads that arm's own
sub-CHOICE tag** — take the last `tag_` in the method and you read a nested
selection as the outer one. [C]

**Two-armed CHOICEs, and why an earlier edition of §10.9 assumed instead of
reading.** Fifty-six of the seventy-three CHOICEs have exactly two arms, and for
those the compiler emits no jump table — a compare and a branch is enough:

```
ldfld tag_
brfalse  L0            <- tag == 0, and NO constant is emitted for it
ldc.i4.1 ; beq  L1     <- tag == 1
  ...fall-through is the default/error path...
L0: <first declared arm>
L1: <second declared arm>
```

A reader keyed on "a constant, then a branch" sees the `tag == 1` arm and is
blind to the `tag == 0` arm, which is why 38 of these came back half-read and
§10.9 covered the gap with a modelling assumption. The other half of the problem
is that an arm of type `NULL_` **emits no code at all**, so the search for its
arm name runs past its empty body into the next arm's — bound the search at the
next branch target, and with two arms one resolved arm determines the other.

Read properly, **all 38 are `0` = first declared arm, `1` = second**. So a
two-armed CHOICE is positional, with one exception in the whole type system:
`Pdl_display_data` numbers its two arms 1 and 2. That exception matters more than
it looks — it is the counterexample to the reasoning the register used to justify
the assumption, which was that with only two arms an ordinal reading cannot go
wrong. It can. [C]

### 10.5 CABINET_DISPLAY — firmware / identity block (0x010C)

`AP2_CABINET_DISPLAY` response (0x010C) is the panel's full firmware-and-identity block — the single richest unauthenticated read in the protocol (230/231 B on the wire; observed returning a firmware string such as `PME1252 / PXME V<rev> APOGEE / <link date>`). Field order is the wire order, and the layout below is now wire-confirmed — the on-wire field order matches the struct in this section exactly. [W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | revstring | TEXT_ | firmware revision string |
| 2 | firmwaretype | TEXT_ | firmware type / platform (e.g. PXME) |
| 3 | linktime | TEXT_ | firmware link/build timestamp |
| 4 | firmware_checksum | UNSIGNED16 | firmware checksum |
| 5–35 | config_byte1 … config_byte31 | UNSIGNED8 (byte8/byte9 BOOLEAN_) | 31 configuration bytes; byte10=alarm_config, byte11=report_config (`Cabinet_report_config` enum) |
| 36 | config_checksum | UNSIGNED8 | config-block checksum |
| 37 | battery_state | UNSIGNED16 | backup-battery state |
| 38 | node_name | TEXT_ | this panel's node name |
| 39 | site_name | TEXT_ | site name |
| 40 | bln_name | TEXT_ | BLN name |
| 41 | ip_addr_settings | IP_Address_Settings | DHCP/DNS flags, app-port list, multicast list, SMTP, telnet-enabled, dynamic-DNS |
| 42 | configured_mii_data | MII_Data | configured link speed/duplex |
| 43 | negotiated_mii_data | MII_Data | negotiated link speed/duplex |
| 44 | link_status | Link_Status (enum) | Up / Down |
| 45 | configured_mac_address | Mac_Address | configured MAC |
| 46 | hardware_mac_address | Mac_Address | burned-in MAC |
| 47 | bacnetSettings | BACnet_Settings | BACnet/IP config |
| 48 | BACnetMSTPLANSettings | BACnet_MSTP_LAN_Settings | MSTP LAN config |
| 49 | bacnet_ip_aln_choice | BOOLEAN_ | IP vs MSTP ALN selection |
| 50 | ip_network_number | UNSIGNED16 | BACnet IP network number |
| 51 | BACnetMSTPALNSettings | BACnet_MSTP_ALN_Settings | MSTP ALN config |

Sub-types referenced: `IP_Address_Settings { dhcp, dns, nrOfapp_ports:u16, app_ports:u16[], nrOfmulticast:u16, multicast:Multicast_Entry[], smtp_server, telnet_enabled:bool, dynamic_dns }`; `MII_Data { mii_speed:Mii_Speed, mii_duplex:Mii_Duplex }`; `Mac_Address { nrOfaddress:u16, address:u8[] }`. This single response enumerates firmware revision, build time, node/site/BLN identity, IP/MII/MAC, and BACnet settings — the entire device fingerprint. [S]

**Annotated wire example (sanitized).** A 230-byte `0x010C` response decodes leading TLVs in the field order above: [W]

```
01 00 08 "PME1252 "                       -> revstring     (field 1, TEXT_ len 8)
01 00 13 "PXME V2.8.10 APOGEE"            -> firmwaretype  (field 2, TEXT_ len 0x13)
01 00 14 "Oct 28 2013 12:31:01"           -> linktime      (field 3, TEXT_ len 0x14)
<firmware_checksum u16> <31 config bytes> <config_checksum> <battery_state u16>
                                          -> fields 4–37 (checksum / config block)
01 00 05 <node-name>                      -> node_name     (field 38, TEXT_)
01 00 03 <site>                           -> site_name     (field 39, TEXT_)
01 00 07 <BLN-name>                       -> bln_name      (field 40, TEXT_)
<ip_addr_settings> <configured/negotiated MII> <link_status>
<configured/hardware MAC> <BACnet settings>
                                          -> fields 41–51 (IP / MII / MAC / BACnet)
```

The leading three TLVs (revstring / firmwaretype / linktime) and the trailing node/site/BLN TLVs followed by the IP/MII/MAC/BACnet settings match the struct field order one-for-one. [W]

**Fleet fingerprinting — and it predicts the wire dialect.** The banner's first three TLVs are a
**firmware revision string** (e.g. `PME1252`, `PME1300` — firmware-build identifiers, *not* hardware
model numbers), a **hardware-platform + firmware-version string** (e.g. `PXME V2.8.10 APOGEE`, where
`PXME` is the modular-cabinet platform code and `V2.8.10` the firmware version), and the **build date**.
Because the request body is empty and the response carries all of this plus identity in one round-trip,
`0x010C` is the canonical way to inventory a BLN: issue it to each known node and read back the firmware
generation. Across a nine-panel fleet — **all the same hardware platform** — the split was purely by
firmware: eight on a 2013-era revision (`V2.8.10`) and one on a 2019-era revision (`V2.8.18`). **That
split is exactly the legacy/modern message-class split (§6.2/§6.6):** the older-firmware panels speak
legacy `0x33`/`0x2E`, the newer-firmware panel speaks modern `0x34`/`0x2F`. So a client can read a
panel's firmware generation from `0x010C` and **select the correct dialect before sending any
data-class frame**, rather than blind-probing `{0x33, 0x34}`. The build date / version string is the
reliable generation discriminator. [W]

> **Reading the hardware model (informative).** These modular panels carry a printed model such as
> `PXC100-PE96.A` (Siemens APOGEE part number; per the public *PXC Modular Series* datasheet, "PXC
> Modular, P2, TX-I/O, 96-node"). The part number decodes as: `PXC` = Programmable Controller (Modular
> class) · `100`/`00` = with / without the TX-I/O island bus · **`PE` vs `E` = protocol firmware
> ordered on the box: `PE` = P2/APOGEE, `E` = BACnet** · `96` = FLN-node capacity · `.A` = hardware
> revision. The same physical platform thus ships as either a **P2** controller or a **BACnet**
> controller depending on the firmware it is ordered/loaded with — the protocol is a firmware property,
> not a different chassis. The CABINET_DISPLAY `PXME …` platform string is the firmware's internal name
> for this modular hardware. So `0x010C` gives you both the firmware generation (legacy vs modern P2)
> and, via the version/`APOGEE`-vs-`BACnet` banner text, which protocol stack the box is running. [D]

### 10.6 Session / EBLN node block (0x4640)

`AP2_eBLN_Ping` request and response (0x4640) both carry the `eBLN_Node` block — the peer-identity and liveness/replication state exchanged on session establish and on the ~10 s keepalive. [S][W]

**`eBLN_Node`** [S][W]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | node_name | TEXT_ | the peer's node name |
| 2 | site_name | TEXT_ | site name |
| 3 | bln_name | TEXT_ | BLN name (the access-gate identity; §3.4.1, §17.2) |
| 4 | failed | BOOLEAN_ | peer failed |
| 5 | ready | BOOLEAN_ | peer ready |
| 6 | replication_online | BOOLEAN_ | replication active |
| 7 | reresolve_all | BOOLEAN_ | request full re-resolve |
| 8 | reresolve_unresolved | BOOLEAN_ | request partial re-resolve |
| 9 | spare1 | UNSIGNED32 | reserved |
| 10 | baseTime | UNSIGNED32 | time base (clock-sync) |
| 11 | offset | UNSIGNED16 | DST/zone offset |
| 12 | dst_flag | BOOLEAN_ | daylight-saving active |

**Wire-confirmed, field by field.** [W] The block above was struct-derived; a
16.7-hour panel-side capture decodes it with nothing left over. The three
`TEXT_` fields are TLVs (`<textType> <len:u16> <bytes>`, usually `01 00 <len> …`) and the nine that follow are a
**fixed 16-byte tail**:

| offset in tail | field | width |
|---:|---|---:|
| 0–4 | `failed`, `ready`, `replication_online`, `reresolve_all`, `reresolve_unresolved` | 1 each |
| 5–8 | `spare1` | 4 |
| 9–12 | `baseTime` | 4 |
| 13–14 | `offset` | 2 |
| 15 | `dst_flag` | 1 |

So the body is **three TLVs then exactly 16 bytes**, and that — not an
arithmetic constant — is how to frame it. Where a length is needed without
parsing, `body_length = 25 + len(node_name) + len(site_name) + len(bln_name)`,
in which only the 25 is protocol (three TLV headers plus the tail); see §7.1. `baseTime` decodes as a
**seconds-since-1970 epoch**; a sampled ping gives `1787673637` =
2026-08-25 16:00:37 UTC. The last three fields are the same triple that
constitutes the whole of `AP2_eBLN_Time_Set_Request` (`0x0302`, §10.x): the ping
*advertises* a node's clock state and `0x0302` *sets* it.

Two consequences worth stating for a monitoring implementation. The body
describes the **sender**, not the addressee — confirmed across 56,475 pings by
the cases where the two names differ in length. And `failed`, `ready` and
`replication_online` are therefore broadcast by every peer on every keepalive,
which makes the liveness heartbeat a complete health feed: a passive listener
learns each node's readiness and replication state every interval without
issuing a single request.

The `bln_name` field here is the same value the access gate checks: a peer presenting the wrong BLN is rejected at the network layer. [W]

**The triple is not one identity — two thirds of it is shared and one third is
the sender's.** Measured across 60 `0x4640` requests, 60 responses and 60
`CABINET_DISPLAY` responses: [W]

| | node name | site name | BLN name |
|---|---|---|---|
| `0x4640` **request** (supervisor → panel) | the **supervisor's** | shared | shared |
| `0x4640` **response** (panel → supervisor) | the **answering panel's** | shared | shared |
| `CABINET_DISPLAY` (§10.5) | the **responding panel's** | shared | shared |

The site and BLN names are identical in **60 of 60** bodies of all three kinds —
they are properties of the BLN, so every node on it emits the same pair. The
node name is not: the request's and the response's differ from each other, and
the request's node name appears in **0 of 60** `CABINET_DISPLAY` bodies while the
response's appears in exactly the ones that came from that panel.

So an implementer must **not** read the session block's node name as "the peer's
name". It names whoever *emitted* that frame, and direction decides who that is.
Only the site and BLN names can be compared across nodes.

### 10.7 Node / BLN management bodies

**`Node_Choice`** (target selector for node-management ops) — CHOICE: `all_nodes : NULL_` or `single_node : UNSIGNED8` (node number). Used by the `SET_NODE_STATE` / cabinet online-offline family. [S]

**`Cov_data`** (BLN COV-share table entry) — `destination_panel : UNSIGNED16` + `cov_mask : Cov_mask`. Defines which panel receives which change classes (the cross-BLN COV share). [S]

The EBLN host-table, MII, IP, and MAC display/configure ops (0x462D–0x463E) carry the corresponding `IP_Address_Settings` / `MII_Data` / `Mac_Address` sub-types from §10.5, and the host-table entry add/remove ops carry a host name + IP. The replication family (0x4633–0x4636, 0x464C) carries `Repl_Cmd_Type` (unknown/add/delete) records and node-roster grains (`Grain_Type` enum: node_list_entry, storage_node_db, user_acc_entry, hosttbl_entry, addresstbl_entry, …). [S]

### 10.8 Upload / PPCL / TEC / trend / alarm representatives

**`AP2_UPL_ALL_POINT` request (0x0981)** — bulk point upload; body is a single `name_search : Name_search` (the class/range selector). Response reuses the `POINT_LOG_VALUE` response shape (§10.3), iterated. The whole `UPL_ALL_*` family (0x0982–0x09C3) follows the same pattern: a `Name_search`/`*_search` request, a per-record response paged via the `last_*` resume keys. [S][W]

**`AP2_Ppcl_Program_Display` response (0x410A)** — a single `PPCL_data` record (programs are returned line-by-line). [S]

**`PPCL_data`** (one PPCL line) [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | name_space | Name_space (enum) | program namespace |
| 2 | name | TEXT_ | program name |
| 3 | line_status | TEXT_ | rendered status |
| 4 | line_text | TEXT_ | the PPCL source line |
| 5 | line_number | UNSIGNED16 | line number |
| 6 | line_enabled | BOOLEAN_ | line enabled |
| 7 | line_traced | BOOLEAN_ | trace flag |
| 8 | line_unresolved | BOOLEAN_ | has unresolved reference |
| 9 | line_failed | BOOLEAN_ | line failed |
| 10 | line_looped | BOOLEAN_ | in a loop |

PPCL statement keywords (the `PPCL_statement_type` enum, 71 members: WHOPLOOP/WHOPON/WHOPOFF/WHOPGOTO/WHOPGOSUB/WHOPIF/WHOPTHEN/WHOPELSE/WHOPALARM/WHOPENALM/WHOPHLIMIT/WHOPLLIMIT/WHOPTOD/WHOPHOLIDAY/…) are the token vocabulary of the line text. [S]

**`AP2_TREND_DATA_DISPLAY` request (0x0295)** [S]

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | user_profile | User_profile | requester |
| 2 | name_search | Name_search | target trend point |
| 3 | trend_specifier | Trend_specifier | `{ number_of_samples:u16, trend_type:Trend_type }` |
| 4 | last_sequence_number | UNSIGNED32 | resume key (paging) |
| 5 | last_date_time | DATE_TIME | resume key |
| 6 | max_samples | UNSIGNED16 | cap on returned samples |

**`AP2_TREND_DATA_DISPLAY` response (0x0295)** — `name_response` + `point : All_points` + `nrOftrend_data:u16` + `trend_data : Trend_data[]` + `lenum_address` + `nrOftrend_dst:u16` + `trend_dst : Trend_dst[]`. Each **`Trend_data`** sample: `sequence_number:u32, time:DATE_TIME, point_value:Point_value, point_priority, out_of_service:bool, failed:bool, control_status, alarm_priority, acked:bool, in_alarm:bool, in_trouble:bool, commanded_to_alarm:bool, operator_disabled:bool, program_disabled:bool, proof_pending:bool`. [S]

**`AP2_TEC_REMOTE_INIT_VALUE_LOG` (0x4221)** and the TEC family carry a `TEC_body` plus `TEC_valid` (no/yes/maybe) and the FLN-device init-value records — the FLN/Terminal-Equipment-Controller application init-value model. (1,776 frames observed; one of the routine FLN reads.) [S][W]

**Alarm representative — `AP2_POINT_LOG_ALARM` response (0x0221)** reuses the `name_response` + `point : All_points` + `lenum_address` + `point_extension2` shape; the alarm configuration itself is the `Alarm_object` CHOICE (tagged by `Alarm_object_type`: no_alarming / std_digital / std_single_analog / std_analog / enhanced_* / bacnet_alarm_*), each alternative carrying `Alarm_level[]` records (`offset:FLOAT_, alarm_priority, category:u8, msg_number:u16`). [S]

**`AP2_UPL_ALL_ALARM_MODE` response (0x0983) — an enhanced-alarm definition, on
the wire.** The alarm-mode upload returns one complete definition per record, and
its tail is self-validating: the last field is a count and exactly `count × 8`
bytes follow. [W]

```
u16                 name space
TLV                 point name
TLV                 point suffix
TLV                 mode point name        (enhanced alarming requires a mode point)
TLV                 mode point suffix
TLV                 engineering units      "PSI", "DEG F", or empty
5 B                 a flag plus four destination category bytes
8 B * 3             three DATE_TIME stamps (§8.3.4); two are equal in most records
...                 level_delay / mode_delay (u16 each), differential (f32), flags
f32                 set point
u16                 level count
count * 8 B         Alarm_level: f32 offset | u8 priority | u8 category | u16 msg
```

`Alarm_level` on the wire is byte-for-byte the catalog structure above, and the
level count never exceeds **six** for an analog point — which is the documented
maximum. (Enumerated points allow up to 64 levels, so a parser must read the
count rather than assume six.) The `f32` before the count is the **set point**;
each level's `offset` is relative to it, so a definition reads as *set point
64 °F, levels at +10 / +9 / +8 with priorities 6 / 5 / 3* — the alarm escalating
as the deviation grows, each level able to carry its own message number and
routing category. Single-level definitions in the corpus use **priority 3**,
the "standard alarming" default. [W][D]

Two decoding notes. The three timestamps are ordinary `DATE_TIME` (§8.3.4):
`year-1900, month, day, weekday (1=Mon…7=Sun), hour, minute, second,
centiseconds`. The weekday is redundant with the date, which makes it a free
alignment check — every stamp in the corpus carries the weekday its date
actually falls on, so a mismatch means the parse has drifted rather than that
the panel is wrong. And the block between the
timestamps and the set point carries the documented `level_delay`, `mode_delay`
and `differential` fields, but **its byte alignment shifts between records**, so
anchor on the count-validated tail and work backwards rather than assuming a
fixed offset. [W]

**Equipment scheduling — three records that compose.** The EQS uploads carry a
zone's schedule, and decoding all three shows one mechanism rather than three
tables. [W]

**`AP2_UPL_ALL_EQS_CMD_TABLE` (0x0988)** — what a mode does:

```
u16 name space | TLV zone | u16 name space | TLV point | TLV suffix
u16 mode index | f32 value | 8 B fixed tail
```

The mode index runs **0–7**, with 0 and 1 carrying the bulk of the rows; the
value is `1.0` or `0.0` and nothing else, so these are digital commands. The
suffix is overwhelmingly the **day/night** subpoint. One row reads: *in mode 0
drive this point to 1; in mode 1 drive it to 0.*

**`AP2_UPL_ALL_EQS_MODE_SCHED` (0x0989)** — when a mode starts. Eleven fields,
and the record consumes its body exactly:

```
u16 name_space | TLV zone name              -- Team_response
u32 entry_ID
u8  entry_enabled        (0/1)
u16 mode
u8  occurrence           0 one_time | 1 weekly | 2 replacement
u32 scheduled_days       bitmask, bit0 = Sunday .. bit6 = Saturday,
                         bits 7..13 = Replacement1..Replacement7
4 B start_date | 4 B end_date               -- y-1900, month, day, ISO weekday
4 B start_time | 4 B stop_time              -- hour, minute, second, centiseconds
u8  days_spanned
u8  exclusive            (0/1)
u16 state_text_id                           -- see below
```

**The layout is self-checking, and it was checked.** Both `DATE_` groups carry a
weekday byte that must equal the weekday their own year/month/day actually falls
on; both `TIME_` groups must be a real time of day; the booleans must be 0 or 1;
`occurrence` must be in 0–2; and the eleven fields must consume the body with
nothing left over. **All thirty captured records hold.** A month/day of zero is
the "no date" sentinel, and effective-until dates sit far in the future when a
schedule has no end. [W]

Two fields are worth calling out because a byte pattern alone would not reveal
them:

- **`scheduled_days` is a bitmask, not an ordinal.** The corpus settles it
  without appeal to anything else: `0x3E` is Mon+Tue+Wed+Thu+Fri, `0x41` is
  Sun+Sat, `0x7E` is Mon–Sat. A weekday mask and a weekend mask falling out of a
  bit test is not a coincidence. [W]
- **`occurrence` reads `weekly` on 28 records and `replacement` on 2** — and the
  two `replacement` records are exactly the ones whose `scheduled_days` lands in
  the `Replacement` band and whose start and end dates are the no-date sentinel.
  Three fields agreeing on the same semantics is the check. [W]

The `u32 entry_ID` after the zone name is the record's own index and is the
resume key of §10.2.3: the request's ten-byte tail is `u32 0 | u32 last index |
u16 0`. Indexes are **sparse**, so the walk must echo the key rather than count.
[W]

**`AP2_UPL_ALL_EQS_ZONE` (0x0987)** — the zone. The lead `u16` is a **count of
names**, and what an earlier edition of this document called "the name again
after a two-byte separator" is not a separator at all: it is the second entry of
a `Team_response[]` array, whose own `name_space` field supplies those two bytes.
**In all ten captured records the count is 2 and it predicts exactly two
names.** The pair is not a duplicate: the two entries carry **different name
spaces** — `system` (0) then `user` (1), in that order in every record — so a
zone is named once in each space. At this site both strings happen to be
equal, which is what made the second look like a repetition; a decoder must
read the `name_space` of each entry rather than assume. [W]

```
u16 nrOfnames | { u16 name_space | TLV name } x nrOfnames
u8  zone_enabled | TLV descriptor
4 B access_class | u16 min_off_time | u8 recmd_after_warmstart
u16 warmstart_delay | u16 state_text_table | u16 default_mode
u8  english_units | u8 optimization_osv | u16 nrOfrecharacterization_values | ...
```

`warmstart_delay` takes the values 0, 7 and 10 across the corpus — minutes. [W]

**The trailing `u16` on both records is a state-text-table id** — and, per §11.5, a **signed** one. Earlier editions
listed it as an unexplained two-valued field, and four readings of it were wrong
— an object id, the answering panel, a checksum, and a correlation with some
other decoded field. What settles it is position and behaviour together: in the
zone record it sits at the offset the type system calls `state_text_table`, the
sibling `UPL_*_EQS_MODE_SCHED` request carries an explicit `state_text_ID`, and
**the value is constant per zone and identical across both opcodes** — six zones,
forty records, `0x0987` and `0x0989`, no exceptions, with several zones sharing a
value. That is a reference to the text group naming the zone's modes. What is
still unknown is the numbering itself: two distinct values from one site is not a
range. [W][S]

**How they compose.** A mode schedule says *at this time on this weekday, the
zone enters mode M*; the command table says *in mode M, command these points to
these values* — typically the day/night point; and a point's **mode point** then
selects which alarm levels are in force (§10.8, alarm-mode record). Scheduling,
commanding and alarming are one chain, and the mode point is the joint. [W][D]

**`AP2_EMS_PRINT` (0x0368) — the panel announcing an operator session.** When
someone logs into a panel's Telnet console, the panel reports it to the
supervisor, unsolicited, on the second channel. [W]

```
u8 event code | 01 00 00 | TLV(node name) | TLV(account) | TLV(account description)
```

| Code | Meaning | Account field carries |
|---:|---|---|
| `0x07` | **logon** | the name **as typed** at the prompt |
| `0x08` | **logoff** | the account's **canonical** name |
| `0x09` | an attempt that resolved to no account | the name as typed, and no description |

The reading comes from a capture in which an operator logged into one panel
twice: `0x09` with a typed name and no description, then `0x07`/`0x08` pairs
bracketing each session — 127 seconds for the first, 301 for the second, with
that operator's own request (a TEC definition read) falling inside the second
pair and carrying the same account name in its `User_profile` prologue (§8.2).
Two older captures carry codes `0x03` and `0x04` with the node name only, so the
code space is wider than these three. [W]

Three consequences worth stating plainly. The **account name and the account's
own description travel in clear** on an ordinary data connection, so anyone who
can see the traffic learns which named accounts exist on a panel and when they
are used. A **failed or unresolved login is distinguishable on the wire** from a
successful one by the event code, which makes login activity observable to a
passive monitor — useful defensively, and equally useful to an attacker who is
already on the segment. And because the same account name reappears in the
`User_profile` of every request that session issues, **operator actions are
attributable on the wire** to the account that made them.

### 10.9 Buildability register — what a reader can and cannot decode

The standard this document is held to is that a reader with **nothing but this
page** can turn bytes into named fields. That is testable rather than a matter
of opinion: walk each operation's request and response structures transitively
and collect every type whose width the document never states. An operation with
none is decodable; an operation with any is not, however well the rest of it is
described.

Of the **455 operations** that have a request and/or response structure:

| | operations |
|---|---:|
| **Decodable** from widths and tag maps this document pins | **455 (100%)** |
| Blocked on an unpinned width or CHOICE | **0** |

**The table of blockers is empty, and that is the claim: every operation in the
catalog that declares a request or a response can be turned into named fields
from this document alone.** The register read 274 in its first edition and 384 in
the edition before this one.

The last eleven operations were blocked by three CHOICEs — `localStateText_` (7
operations, and the only thing missing from all 7), `BAC_Point_Base` (2) and
`event_parameter_Tag_` (2) — and a previous edition of this section named the
capture each one needed: a `MEMBER_DESC_UPLOAD` response for the first, a BACnet
event-enrollment object for the third. **Neither was taken.** All three were read
out of the vendor codec's *encoder* methods, a place the earlier recovery passes
had not looked because they read decoders (§10.4.6). Two of the three can be
checked against ASHRAE 135 rather than against the vendor, and both hold.

Read that against the paragraph immediately below, which withdraws the same kind
of claim about the enum widths. **Twice now a "needs new evidence" verdict in
this register has fallen to evidence already in hand**, and in both cases what
was missing was not data but a place in the existing material that nothing had
read.

**And the figure now rests on no assumption, which it did not when it first
reached 455.** The first version of this paragraph said so honestly: forty-four
two-armed CHOICEs had no tag map, and the register counted them decodable on the
reasoning that with only two arms the body distinguishes them. Testing that
sentence broke it twice over. `Set_point_type` and `Setpoint_type` have **two
`NULL_` arms** — zero bytes either way, so no body distinguishes anything. And
`Pdl_display_data` numbers its two arms **1 and 2**, so the ordinal reading the
assumption relied on is wrong for it.

The fix was not to qualify the assumption but to remove it. Two-armed selections
are compiled as a compare and a branch rather than a jump table, and the reader
that could not see them was looking for a constant before the branch — which the
compiler does not emit for `tag == 0` (§10.4.6). Handling that closes 38 of the
39, and the register reaches the same 455 with the two-arm fallback deleted from
its code. **Every CHOICE reachable from an operation now has a tag map read from
the codec.** Two CHOICEs still have no complete map, `NetworkVariable_` and
`Point_extension2_type`, and no structure in the catalog names either as a field
type.

**A claim this section used to make, withdrawn.** Earlier editions reported
forty blockers, of which thirty-one were enum widths, and said of them: *"the
rest cannot be closed by looking harder at this capture set, only by a capture
from a system that exercises those features."* That was wrong, and the way it
was wrong is worth more than the correction. **All thirty-one are now pinned,
and no new capture was involved.**

They were closed by one edge in the vendor's own type graph that nothing had
followed. A type that states no width of its own states a **base type**, and
following that chain ends at a primitive whose width this document has stated
all along: `Device_type` → `ENUMERATED8` → `UNSIGNED_8`, one byte;
`Baud_rate` → `ENUMERATED16` → `UNSIGNED_16`, two; `Node_complete_state` →
`BITSTRING16`, two. The information was in the type system from the beginning;
what was missing was the step from an enum to its base. [S]

Four checks were run before adopting it, because a result that convenient
deserves suspicion. **Thirty-seven** of the types the chain resolves are also
pinned independently elsewhere in this document — thirty-seven agreements and
**zero** disagreements, each tested with its own value withheld. `Baud_rate` = 2
and `Sensor_type` = 1 come back at the values the wire and the panel firmware
gave them separately (§16.1.3). The vendor's generated encoder reserves exactly
these widths before writing each field, which states the leaf widths in code
rather than in a name. [C] And over the whole body corpus the parse outcome is
**unchanged** — no body that parsed before fails now. That last one cannot
*confirm* the widths, because the corpus does not exercise these types (which is
why they were blocked in the first place); it can only falsify them, and it does
not.

The lesson generalises past this table: **a claim that something needs new
evidence should be tested against the evidence already in hand before it is
written down.** This one survived three editions.

`Baud_rate` topped this table at 11 operations until §16.1.3 measured it, and
how it fell is worth more than the twelve operations it took with it — see the
warning at the end of this section.

**What is no longer here is the point of the table.** Its first two editions
were topped by `use_proof_` at 48 operations and the `All_points` arms at 41
each, and those are gone — not measured, but *recovered*: the vendor type system
declares them and the extraction that built §10.1's catalog had flattened them
away (§10.4.1, §10.4.2). `LON_extension_` topped the third edition at 10 and
went the same way, along with `name_suffix_`, `xfixed_`, `address_`,
`alarm_info_` and `Fln_type_`: **all six are declared inside a parent type, and
one name means different things under different parents** — exactly the
`real_addr_` situation of §10.4.2, which turned out to be a general pattern
rather than a special case. Nothing left blocks more than 8 operations, and the
remaining families are peripheral to the point model: user accounts, calendars,
duct geometry, LonWorks and MSTP team extensions.

**The register predicts its own gains, which is the check that it works.** Its
first run named `Alarm_mode_type` as blocking 19 operations and being the *only*
thing missing from all 19. Pinning it (§10.1, 1 byte) moved the total from 274
to **293 — exactly the 19 predicted**. Recovering the flattened nested types
then moved it to **352**, and closed the whole `All_points` arm family at once.
Through all of it the reference implementation went 3,838 → 3,856 bodies and
never regressed — which matters, because a "decodable" verdict that quietly
broke a working parse would be worse than no register at all. Treat the table
as a work queue, not a scoreboard.

**Read this against the parse rate, not instead of it.** A reference
implementation consumes 96.9% of the bodies in the corpus, and the two figures
measure different things — the parse rate measures *this site*, the register
measures *the document*. Where they disagree, the disagreement is the useful
part, and every case falls into one of two kinds:

- **Blocked, yet every observed body parses (15 opcode-sides).** The blocking
  arm simply does not occur here. `POINT_LOG_VALUE`'s response is blocked on
  `ldao_`, `lfmsl_`, `lfmsp_` and `ppcl_lai_`, and parses 60 of 60 — because
  this site has no points of those four types. **A site that has one would break
  a decoder built to the same standard**, which is exactly what a parse rate
  cannot tell you.
- **Decodable, yet some bodies fail (22 opcode-sides).** Every one of these is
  our own probe traffic: a bare scope tag `01 00 04 "SYST" 23 3F FF FF FF` sent
  to a run of consecutive opcodes, one frame each, carrying none of the fields
  the operation declares. All 33 such frames originate from two research hosts
  and none from a supervisor or panel. They say nothing about the document.

**A "blocked" verdict was about the whole body, and that could mislead.** The
register asks whether *every* field of an operation can be turned into named
bytes; it could not express "the part you need is fine." `CABINET_DISPLAY`
(`0x010C`) was the clearest case — its response was listed as blocked on BACnet
and port-configuration sub-blocks near the end, while `revstring` is **field 1**
and the whole point of the read for most clients (§7.3.1, §10.5). Nothing is
blocked now, so the caution is historical for this register — but keep it for
any register built the same way: read a blocked verdict as "do not assume you
can walk this body generically", not as "this operation is undocumented", and
where a section of §10 describes an opcode in prose, that description is the
authority.

**Do not guess a width from an enum's value range.** This is the one shortcut
that looks safe and is not, and it is recorded here because it very nearly went
into this document as a rule. Twenty-one enum widths had been measured
individually; nineteen were 1 byte and two were 2, and the obvious rule — *one
byte while every member fits in a byte, two when one does not* — reproduced all
twenty-one. `Application_family` tops out at 257, exactly the case that forces
two. Twenty-one chances to fail and none taken; applying it moved this table
from 366 operations to 416.

**It is wrong.** The first structure in the corpus able to test it on a fresh
enum killed it: `Baud_rate` has thirteen members topping out at 12, so the rule
says one byte, and it is **two** — 0 of 60 bodies consume exactly at width 1,
60 of 60 at width 2, with the decoded rate matching an oracle inside the message
itself (§16.1.3). Fifty were 83, not 91, and the difference was entirely
imaginary.

The twenty-one agreements were a **selection effect**, and the shape of it
generalises past enums: a field gets measured when someone finds a structure
tight enough to pin it, and the structures tight enough to pin anything are the
densely packed point records — which are packed to the byte. The sample was
never "enums"; it was "enums that live in point bodies". [W][I]

**And the reason the shortcut fails is now visible, which is the useful part.**
Width is not derived from an enum's value range because the type system
*declares* it: every enum extends either `ENUMERATED8` or `ENUMERATED16`, and
the choice between them is the vendor's, made once per type. `Baud_rate` is the
case that killed the rule and it is also the demonstration — thirteen members
topping out at 12, comfortably a byte, and declared `ENUMERATED16`. No amount of
looking at its values could have told you that; its declaration says it outright.
So enum width in P2 is a property of the **declared type**, not of the value
range and not of the field — and reading the declaration is the fast way that
the earlier text, which said every remaining blocker "has to be measured the slow
way", wrongly ruled out. [S]

### 10.10 The full structure set is enumerable

The ~30 structures above cover the read/command/COV core, the firmware/identity block, the session block, and one representative of each remaining major family (upload, PPCL, trend, TEC, alarm, node-management). The remaining ~1,110 structures follow the same conventions — ordered typed fields, the shared sub-types of §10.2, counted arrays, and CHOICE unions — and each maps one-to-one to a `*_Request` / `*_Response` pair for an opcode in the §9 catalog. For any opcode not detailed here, its body is the like-named ASDU structure (e.g. `AP2_<name>_Request` / `AP2_<name>_Response`), readable from the structure library with the §10.1 type mapping. [S]

**On "the exact byte offsets of an `All_points` arm", which an earlier edition left open.** The question has no answer, and not for want of evidence: **no arm of `All_points` has a fixed width.** Every one of the sixteen contains at least one variable-length string, so absolute byte offsets do not exist for any of them, on any panel, in any capture. What exists is field order plus a width for every scalar — and since the enum-base pass pinned the last 31 of those (§10.9), order-plus-widths *is* the packing. A decoder walks the fields and arrives at the right byte; it cannot index to a constant offset, and no capture would let it. State that as a property of the encoding rather than as a gap. [S]

The two things the earlier text asked for both arrived, which is worth recording next to the retraction. **Codec-level evidence**: the vendor's own encoders give width, byte order and string mode for 120 layouts (§10.4.6, §6.8). **Measured interiors**: §8.5 confirms six of the sixteen arms to the byte from the wire, and §10.4.4 now gives all nine `Alarm_object` arms field by field from the catalog, with the three that were independently wire-measured agreeing. What remains genuinely unmeasured is narrower and is stated where it belongs — ten `All_points` arms this site does not run (§8.5), and the alarm band's asserted values (§12.3.3). [W][S][C]
## 11. Point Model

The point is the atomic data object of a P2 system. Every value an operator reads or commands, every input a control program references, every quantity a trend logs, resolves to a point. This section specifies the logical point taxonomy, how a logical point decomposes into physical hardware terminations, how the FLN device layer self-describes its points, and the analog/enumerated scaling model. The runtime value carried for a point on the wire is specified in §12 (COV); the alarm attributes are specified in §13.

### 11.1 The three point layers

A point exists at one of three layers; an implementer must not conflate them. [I]

- **Logical point.** The unit an operator commands and a control program references. Identified by a name (the routing key, §9), it has a single present value, a single condition, and a single command priority. A logical point is composed of one to four **physical subpoints** — the hardware terminations that implement it; the count and kind are fixed by the logical point's type (§11.2). [D]
- **Physical point (subpoint).** A single hardware termination: one analog or digital input channel, or one analog or digital output channel. It has a raw digitized value (an ADC count for analog channels, a 0/1 state for digital channels) and a hardware/sensor type that fixes its signal range and linear calibration (§11.5). Physical subpoints are commanded only through the logical point that owns them, never directly. [D]
- **Virtual point.** A logical point with no hardware termination — it occupies no physical channel. Virtual points hold computed values, setpoints, intermediate control-program results, and software flags. A virtual point carries the same attribute set and the same runtime value payload (§12) as a hardware-backed logical point. [D] In the object hierarchy the panel exposes, the containment is `BLN → CEC (panel) → Point`, and a point-team's default member is the logical point. [S]

### 11.2 Logical point types

P2 defines a fixed taxonomy of logical point types. Each type has a numeric type code (the panel's own `Point_type` enumeration) and fixes how many commandable outputs it drives, whether it monitors an input, and the total physical-subpoint count. [S]

| Code | Mnemonic | Meaning | Commandable outputs | Monitored input | Physical subpoints | Tag |
|---|---|---|---|---|---|---|
| 1 | **LDI** | Logical Digital Input | — | 1 latched DI | 1 | [S/D] |
| 2 | **LDO** | Logical Digital Output | 1 latched **or** pulsed DO | — | 1 | [S/D] |
| 3 | **LAI** | Logical Analog Input | — | 1 AI | 1 | [S/D] |
| 4 | **LAO** | Logical Analog Output | 1 AO | — | 1 | [S/D] |
| 6 | **L2SL** | Logical Two-State Latched | 1 latched DO | 1 latched DI | 2 | [S/D] |
| 7 | **LOOAP** | Logical On/Off/Auto Pulsed | 2 pulsed DO (ON/OFF) + 1 latched (AUTO) | 1 latched DI (proof) | 4 | [S/D] |
| 11 | **LPACI** | Logical Pulse Accumulator (Counter) Input | — | 1 DI (pulse counter) | 1 | [S/D] |
| 12 | **L2SP** | Logical Two-State Pulsed | 2 pulsed DO | 1 latched DI | 3 | [S/D] |
| 13 | **LOOAL** | Logical On/Off/Auto Latched | 2 latched DO | 1 latched DI | 3 | [S/D] |
| 14 | **LFSSL** | Logical Fast/Slow/Stop Latched | 2 latched DO | 1 latched DI | 3 | [S/D] |
| 15 | **LFSSP** | Logical Fast/Slow/Stop Pulsed | 3 pulsed DO | 1 latched DI | 4 | [S/D] |
| 19 | **LCTLR** | Logical Controller (control-loop point) | per loop output | loop input | varies | [S/I] |
| 20 | **LDAO** | Logical Digital-Actuated Analog Output | analog driven by digital pulses | optional | varies | [S] |
| 21 | **LENUM** | Logical Enumerated (multistate) | per state | optional | 1 (value → state-text set) | [S/D] |
| 22 | **LFMSSL** | Logical Fast/Medium/Slow/Stop (3-speed) Latched | 3 latched DO | 1 latched DI | 4 | [S/D] |
| 23 | **LFMSSP** | Logical Fast/Medium/Slow/Stop (3-speed) Pulsed | 4 pulsed DO | 1 latched DI | 5 | [S/D] |
| 24 | **PPCL_LAI** | PPCL-referenced analog input (control-program-visible analog) | — | 1 AI | 1 | [S] |

**Twelve of these are point types an engineer can create; the rest are not.**
The vendor's own Point Editor documentation enumerates the types available when
adding a point, and lists exactly: **LAI, LAO, LDI, LDO, L2SP, L2SL, LFSSL,
LFSSP, LOOAL, LOOAP, LPACI, LENUM.** [D] Absent from it are **LCTLR** (19),
**LDAO** (20), **LFMSSL** (22), **LFMSSP** (23) and **PPCL_LAI** (24).

That is worth stating because those five are precisely the arms this document
has had the most trouble with, and it explains why: they are not types a site
can contain unless something other than the point editor creates them.
`PPCL_LAI` reuses `LAI_type` outright and `LDAO_type` is declared with no fields
at all (§10.4.1), which is consistent with both being internal rather than
user-facing. A decoder must still handle all sixteen tags — the wire can carry
them — but an implementer should not expect to find examples.

**The same documentation independently confirms the proof model.** It describes
the proof input, for every type that has one, as *"the status of one latched
digital input point (proof)"* — which is exactly the recovered
`use_proof_ = physical_address_DI + point_proof_delay` of §10.4.1. And its
wording tracks the type system's structure precisely: the five types it calls
**optional** proof (L2SP, LFSSL, LFSSP, LOOAL, LOOAP) are the five whose
structures wrap it in the `Proof_option` CHOICE, while **L2SL**, the one type
whose proof it describes without "optional", carries `physical_address_DI` and
`point_proof_delay` as **direct fields with no CHOICE around them**. Two
independent sources, agreeing down to which types get the optional wrapper.
[D][S]

Type code `0` is `point_type_undef` (no point). The codes are the `Point_type` enumeration values that travel as a `Point_type` tag wherever a typed point body appears in an ASDU. [S] The decimal codes are not contiguous (5, 8, 9, 10 and 16–18 are unused), so an implementer must dispatch on the explicit code, never on ordinal position. [S]

**A point type's default enumeration is the negation of its type code.** The enum library that supplies state text (§11.5) keys its per-type defaults as `-1` LDI, `-2` LDO, `-6` L2SL, `-7` LOOAP, `-12` L2SP, `-13` LOOAL, `-14` LFSSL, `-15` LFSSP, `-19` LCTLR, `-21` LENUM — every one the negation of the code above. Nine of the ten negate a code this table already carried; the tenth is why `19` is listed as LCTLR rather than unused. **This is now wire-confirmed, and it confirms the field's signedness at the same time:** every point in the corpus whose `state_text_table` reads a small negative number is the matching type — `-1` on LDI points and nothing else, `-2` on LDO points and nothing else — and a supervisor queried independently labels one of those points' text group as the default for its type, with the same signed id in the group's own name. Read unsigned the two values are 65535 and 65534 and bear no relation to the point type. [S][W][D] The analog types (LAI, LAO, LPACI) have no default entry, which is consistent: an analog point has no enumerated states. A decoder can therefore derive a point's default state-text set from its type code alone, and only needs an explicit enum reference when the point overrides the default with a named group.

> Implementation caution, a second one. The vendor's commissioning-report definition carries a table of the same mnemonics numbered `LDO`=2, `LDI`=3, `LAO`=4, `LAI`=5, `L2SL`=6, `L2SP`=7, `LOOAL`=8, `LOOAP`=9, `LFSSL`=10, `LFSSP`=11, `LPACI`=12, `LCTLR`=13, `LENUM`=14. Its own comment identifies these as **procedure numbers matching a help file**, not point types — a third numbering of the same taxonomy, alongside the `PTYPE` field noted above. It is a document index. Do not cross-map it either. [D]

> Implementation caution, a third one, and the most dangerous of the three. A
> current supervisor product carries **two point-type enumerations side by side**
> in the same install. One reproduces the wire codes of §11.2 exactly — sparse,
> with 5, 8, 9, 10 and 16–19 unused. The other renumbers the identical mnemonics
> **densely, 1..16**, so `L2SL` is 5 rather than 6, `L2SP` is 8 rather than 12,
> `LDAO` is 12 rather than 20, `LENUM` is 13 rather than 21, and `LFMSSL` /
> `LFMSSP` are 14 / 15 rather than 22 / 23. Six of the fifteen shared members
> disagree. Unlike the `PTYPE` field and the commissioning-report index above,
> this one spells its members exactly as the wire does — `LDI`, `LDO`, `LAI`,
> `LAO`, `L2SL` … — so a value lifted from it will look correct and decode six
> point types wrongly. **The sparse numbering of §11.2 is the wire one.** [S]

The on/off/auto and fast/slow/stop families (LOOAL, LOOAP, LFSSL, LFSSP, LFMSSL, LFMSSP) are **digital-only**: their commandable outputs are digital outputs, and they are not interchangeable with analog types. [D] The "latched" (`...L`) variants drive maintained digital outputs; the "pulsed" (`...P`) variants drive momentary outputs and require one additional subpoint to express the auto/stop state — so a pulsed variant always carries one more physical subpoint than its latched counterpart. [D]

### 11.3 Physical-subpoint composition

A logical point's address list contains exactly as many physical subpoints as its type prescribes (the "Physical subpoints" column above). A record claiming type LFSSL but carrying other than three addresses is malformed. [D] In a digital multi-address record the output addresses appear first, in command order, and the monitored/proof input address appears last. [D] This is why one logical point spans multiple subpoint indices: a single operator-facing on/off/auto command point (LOOAP) is implemented underneath as two pulsed command outputs, one latched auto output, and one proof input — four physical terminations — but the operator sees, commands, and alarms a single point. [D]

Each physical subpoint is one of four base hardware classes; analog classes are further divided by signal type. [D]

| Physical class | Subtypes | Signal | Tag |
|---|---|---|---|
| **AI** (analog input) | AI-I, AI-V, AI-P, AI-T | 4–20 mA, 0–10 Vdc, 3–15 psi, thermistor/RTD | [D] |
| **AO** (analog output) | AO-I, AO-V, AO-P | 4–20 mA, 0–10 Vdc, 3–18 psig | [D] |
| **DI** (digital input) | — | energized / de-energized | [D] |
| **DO** (digital output) | — | energized / de-energized; latched (maintained) or pulsed (momentary) | [D] |

The wire/ASDU representation of a subpoint's address is one of the `Physical_address_{AI,AO,DI,DO,PA}` variants, each a tagged union of `real_addr` (a hardware-terminated channel) versus `virtual_addr` (NULL — no hardware), plus the `Physical_address_Lenum` variant (`not_present` versus `present`) carried alongside LENUM points. [S] The tag byte selects the variant; an implementer reads the tag first, then the variant body.

#### 11.3.1 Hand/Off/Auto — a point can be taken away from the panel at the terminal

A physical termination may carry a **manual override switch**, and when an
operator throws it the point stops being controlled by the panel. P2 exposes
this in three connected places, and a client that ignores it will report a
commanded value the equipment is not following.

**On a point.** `Control_status` (§10.3) carries the state directly:

| value | meaning |
|---|---|
| 0 | `remote` — normal, panel-controlled |
| 1 | `tool_override` |
| 2 | `by_priority` |
| 3 | `config_only` |
| 4 | `input_only` |
| **5** | **`manual_override`** — the termination's own switch is in control |
| 6 | `undefined` |

The language exposes the same condition as the **`HAND`** status indicator,
which a control program tests to ask *"is this point currently being controlled
through a manual override switch?"* — so `HAND` in a program and
`manual_override` on the wire are the same fact. [D][S]

**As a panel-wide map.** The switch positions are also readable as a table in
their own right, through a small opcode family: [S]

| Opcode | Operation |
|---|---|
| `0x5354` | `HOA_MAP_LOOK` — read the map |
| `0x5355` / `0x5351` | `HOA_MAP_ADD` / `HOA_MAP_MODIFY` |
| `0x5356` | `DBCHANGE_HOA_MAP` — replication notification |

`Hoa_Map` is a `u16` count followed by `Hoa_Map_Entry` pairs. **Two structures
describe an entry and they transpose the field types** — `Hoa_Map_Entry` is
`switch_number : UNSIGNED8` + `point_number : CHAR_`, while `HOA_assignment` is
`point_number : UNSIGNED8` + `switch_number : CHAR_`. Both are two bytes, so the
framing is unaffected and a decoder cannot detect the difference; only the
labels swap. Which is authoritative for a given opcode is **[OPEN]**, and a tool
that reports switch and point the wrong way round will do so silently. [S]

**What the corpus shows, which is mostly absence.** `HOA_MAP_LOOK` is
wire-observed — 27 requests, every one a bare scope tag with no parameters, so
the read takes no arguments — but **no response was captured**, and across 5,807
walked points **`manual_override` occurs zero times**. Nothing here is in HAND.
`tool_override` does occur, on 15 points, so the neighbouring states are real.
The map's response layout is therefore `[S]` only. [W]

### 11.4 Point teams (.ptd) and the FLN subpoint model

#### 11.4.1 Point-team descriptors

The panel side carries a declarative template called a **point team**: a named team keyed by a `(family, type, revision)` triple, containing one **member** per subpoint. [S/D] The team header is the `Team_description_base` record: `team_family` (an `Application_family` code — e.g. 7 = `ppcl_program`, 16 = `tec_na`, 17 = `uc`, 18 = `tcu`, 19 = `lon`, 20 = `p1_pxc`, 21 = `bacnet_mstp`, 257 = `tec_eu`), `team_type` (u16), `team_revision` (u16). [S] Each member is a `Member_description_base`: `member_number` (u16 — the subpoint slot index), a list of `team_suffix` strings, a free-text `member_desc` descriptor, `point_type` (the §11.2 L-code), and the boolean attributes `virtual_pt`, `alarmable`, `reference_type` (INPUT / OUTPUT / not_allowed), `totalize`, `print_alarms`, plus `total_scale` (seconds/minutes/hours/days). [S]

The on-disk **point-team descriptor file (.ptd)** is the serialized form of this model. It is **XML**, in two serialization variants, carrying the same logical model: [D]

- WCIS variant: **UTF-16 XML**, element nesting `PointTeamDefinition > Application > PointTeam > Point`. [D]
- DataMate variant: **ASCII XML** validating against `ptd.xsd`, root `TEAM_DESCRIPTION`, with member elements `ANALOG_PHYSICAL_MEMBER` / `ANALOG_MEMBER` / `DIGITAL_MEMBER` / `ENUM_MEMBER`, each keyed by `SUBPOINT_NUMBER`. [D]

An implementer parsing a .ptd must not assume a flat line-oriented text grammar; the descriptor is structured XML. [D] The logical member model is consistent across both variants: each member declares `{ SUBPOINT_NUMBER, REFERENCE (INPUT/OUTPUT), TYPE (L-code), SI and ENG slope, SI and ENG intercept, units, enumeration / state-text group }`. [D] The `SUBPOINT_NUMBER` in a team member occupies the same index space as the FLN application roster (§11.4.2), tying the panel-side template to the field device. [D]

| Member kind | Use | Carries | Tag |
|---|---|---|---|
| analog-physical | physical LAI/LAO subpoint | descriptor, reference (direction), L-type, SI/ENG units, SI/ENG slope, SI/ENG intercept | [S/D] |
| analog | virtual/computed analog | descriptor, reference, L-type, SI/ENG units, SI/ENG initial value | [S/D] |
| digital | LDI/LDO subpoint | descriptor, reference, L-type, state-text set, initial value, [alarmable, print-alarm] | [S/D] |
| enum | enumerated/mode subpoint | descriptor, reference, L-type, state-text set, initial value, [alarmable, print-alarm] | [S/D] |

#### 11.4.2 FLN application roster and self-identification

A panel hosts one or more **Field Level Networks (FLNs)** — RS-485 fieldbus sub-buses (P1, §4.4) carrying field controllers (TEC, UC, TCU, PXM, P1DXR, VFD; `FLN_Device_Type` enumerates the families). [S/D] Each FLN device runs an **application**, identified by an **application number**, that fixes the device's roster of points. [D]

The subpoint index space is fixed by the controller class, and three slots have reserved meaning: [D]

| Subpoint | Meaning | Tag |
|---|---|---|
| 0 | **Bundled controller point** — the device-level point representing the controller as a whole | [D] |
| 1 | **CTLR ADDRESS** — the controller's FLN drop number (its position on the fieldbus); factory default **99** | [D] |
| 2 | **APPLICATION** — the application number the device self-reports at runtime; reading it selects which point-team / roster map applies | [D] |

Resolution of a live FLN device's points is therefore: read subpoint 2 (APPLICATION) to learn the application number, look up that number's roster (the ordered `(subpoint number, object type)` rows), and for each subpoint the pair `(application number, subpoint number)` yields the object type. [D] A point team keyed by the device's `(family, type)` supplies the panel-side template for the same subpoint indices (§11.4.1). [D] A team whose type key is the "undefined/failed device" sentinel is the fallback template applied to a device that does not return a recognized application. [D]

#### 11.4.3 Bundled vs unbundled subpoints

By default an FLN device's subpoints are **bundled** — they exist only inside the controller's own point and are not individually addressable as first-class BLN points. The `{NN}` bracket convention denotes a bundled subpoint NN. [D] **Unbundling** a subpoint registers it as a standalone point so it can be read and commanded over the BLN like any panel-resident point; whether a given subpoint may be unbundled is itself an attribute (the export CSV labels it "Unbundlable Status"). [D] Bundled subpoints reduce BLN point count and replication load; unbundling trades that for network visibility of an individual field value. [I]

### 11.5 Analog scaling, sensor types, and enumerations

#### 11.5.1 Linear scaling

An analog subpoint converts a raw digitized count to an engineering value by a linear transform: [D]

```
EngValue = (DigitizedValue × Slope) + Intercept
```

`Slope` and `Intercept` are 32-bit big-endian floats fixed by the physical point's sensor/hardware type. [D] `DigitizedValue` is the raw ADC count. [D] The ASDU `Analog_scale` record is exactly `{ slope: f32, intercept: f32 }`. [S]

**Where the two constants come from — and why nothing else is applied at run
time.** They are not measured per reading and not derived by the decoder. They
are computed once, when the point is defined, from five inputs: the **signal
range** (the electrical span the device presents — 4–20 mA, 0–10 Vdc,
3–15 psig), the **device range** (the engineering span that signal represents —
0–100 %, 0–0.5 in w.c.), the **sensor type** (§11.5.2), the **field panel or FLN
device type**, and the **unit system** being calculated for. The vendor's
engineering tooling takes exactly those five and emits the pair, from a lookup
table keyed by `(device type, sensor type, unit system)` that carries the signal
and device spans and the resulting slope and intercept together. [D] So every
range, span and live-zero is already folded into `slope` and `intercept` before
they reach the wire, and the transform above is the whole of the run-time
arithmetic — see §11.5.1.1, where applying an offset a second time is the
specific trap.

**A point carries two pairs, and the pair sits behind a CHOICE.** The same
digitized reading renders in engineering or SI units, so the scale record is
doubled, each half with its own COV limit: [S]

```
scale_                     CHOICE, u8 tag
  virtual_pt   NULL_       0 B     <- carries no scale record at all
  physical_pt  20 B
       eng_units      Analog_scale     slope f32 | intercept f32
       eng_cov_limit  f32
       si_units       Analog_scale     slope f32 | intercept f32
       si_cov_limit   f32
```

Two cautions, both of which produce a decoder that looks correct on the bench:

- **The `NULL_` arm is not decoration.** A reader that always consumes 20 bytes
  here desynchronises on the first virtual member it meets, and a virtual member
  is the common case in a team carrying computed values.
- **Which tag selects which arm — settled, and the two conventions really are
  opposite.** Declaration order puts `virtual_pt` first, which would make tag
  `0` the empty arm, while the `Physical_address_*` CHOICEs pair the same two
  concepts the other way round (§10.4.2: there tag `0` is the arm that *has* an
  address). Both are now attested rather than assumed: [C]

  | CHOICE | tag `0` | tag `1` |
  |---|---|---|
  | `scale_` | `virtual_pt` — empty | `physical_pt` — the 20-byte scaling arm |
  | `Physical_address_AI/AO/DI/DO/PA` | `real_addr` — the address | `virtual_addr` — empty |

  So **each follows its own declaration order**, and the inversion is in the
  declarations themselves, not in one of them breaking a convention. A decoder
  cannot carry an assumption from one to the other: in `scale_` the *virtual*
  case is tag `0`, and in a physical address the *physical* case is. [C][S]

  This was `[OPEN]` for want of a capture — `scale_`'s only carrier,
  `AP2_MEMBER_DESC_ADD_ANALOG` (0x4002), appears nowhere in the corpus and
  0x4010 is present as 19 requests with no reply. It did not need one. The
  vendor's codec selects the arm by branching on the tag, and while `scale_` has
  no encoder of its own, its parent inlines the selection: `tag == 0` branches to
  the `virtual_pt` arm and `tag == 1` to the block that reads `eng_units`,
  `eng_cov_limit`, `si_units` and `si_cov_limit` — the physical arm's four
  fields, in the declared order. [C]

The units *strings* are not in this record. A point's own type (`LAI_type`,
`LAO_type`, `LPACI_type`) carries a single `Analog_units = { eng_units: TEXT_,
cov_limit }`, and the analog point-definition body carries the English and SI
unit strings alongside initial values and alarm limits for both systems. Three
structures, three scopes — an earlier revision of this section described them as
one. [S]

The FLN raw-count form is distinct from the BLN f32 value form: on the fieldbus an analog value is a raw integer whose register width is the point's `P1MaxRange` (most commonly 0–255, i.e. an 8-bit count), while the value seen at the BLN layer and in the COV payload is the scaled `f32` (§12.3). [D] Worked example: a digitized count of 1954 with slope 0.03125 and intercept −5.0 yields `1954 × 0.03125 + (−5.0) = 56.0625`, displayed as 56.06. [D]

#### 11.5.1.1 The raw count range is a property of the controller family, and neither end of it is 0

§11.5.1 gives the transform and notes that FLN raw counts are commonly 8-bit.
Panel-resident analog points are different, and the constants are unobvious:
[D/S]

**The count range is a property of the controller family and the signal class
together**, and neither end of it is 0 or a power of two. These are the raw
digitized ranges an analog **input** is defined against: [D]

| Controller family | current | voltage | pneumatic |
|---|---|---|---|
| MBC | 3,584 … 29,184 → 4–20 mA | 3,584 … 29,184 → 0–10 V | — |
| MEC | 0 … 30,720 → **0–20 mA** | 3,584 … 29,184 → 0–10 V | — |
| AHUC | 0 … 30,720 → **0–20 mA** | 3,584 … 29,184 → 0–10 V | — |
| RCU (P2) | 4,200 … 21,000 → 4–20 mA | 0 … 21,000 → 0–10 V | — |
| SCU | 800 … 4,000 → 4–20 mA | 0 … 4,000 → 0–10 V | 1,120 … 2,400 → 3–15 psi / 21–103 kPa |

and for an analog **output**: [D]

| Controller family | current | voltage | pneumatic | resistive |
|---|---|---|---|---|
| MBC | 0 … 30,720 → 4–20 mA | 0 … 30,720 → 0–10 V | 0 … 30,720 → 0–20 psi / 0–138 kPa | — |
| MEC, AHUC | 0 … 30,720 → **0–20 mA** | 0 … 30,720 → 0–10 V | — | — |
| RCU (P2) | 0 … 1,023 → 4–20 mA | 0 … 1,023 → 0–10 V | 42 … 211 → 3–15 psi / 21–103 kPa | — |
| SCU | 0 … 255 → 4–20 mA | 0 … 255 → **0–16 V** | 0 … 255 → 0–18 psi / 0–124 kPa | 0 … 135 → 0–135 (×1 kΩ) |

A **virtual** point on every family is `0 … 32,767`, identity — no signal, no
span, and (§11.5.1) no scale record on the wire at all.

**An earlier revision of this section had this wrong in a way worth naming**,
because the same mistake is easy to make from the conversion constants alone: it
listed "full-scale count 25,600, zero offset 3,584". **25,600 is the *span*, not
the full scale.** The MBC current input runs 3,584 … 29,184, and 29,184 − 3,584
= 25,600. The figure was right, the label was wrong, and the difference matters
the moment anyone tries to bound a count field: a decoder that rejects counts
above 25,600 rejects the top 12 % of every MBC analog input. The span is the
quantity that appears in the generation-conversion ratios of §11.5.1.2, which is
how it came to be recorded as if it were the maximum.

Three consequences an implementer should carry:

- **Live zero is per family, not per signal.** A 4–20 mA input starts at 3,584
  counts on an MBC but at 4,200 on an RCU and 800 on an SCU — and at **0** on an
  MEC or AHUC, whose current inputs are 0–20 mA and have no live zero to encode.
- **Voltage inputs carry the same 3,584 offset as current on MBC/MEC/AHUC**,
  even though 0–10 V has no live zero. The offset is a property of the input
  circuit, not of the 4 mA floor.
- **The SCU is an 8-bit-class device throughout** — 0…255 on every output,
  0…4,000 on inputs — and its voltage output spans **16 V**, not 10. That single
  fact is the whole of the `AOV16` sub-type below.

So a 4–20 mA input spans a raw count of 3,584…25,600 rather than 0…full-scale:
the zero offset **is** the live-zero of the 4 mA floor, expressed in counts.

**These constants do not belong in the run-time transform, and putting them
there is a bug.** §11.5.1's single line is complete on its own: `slope` and
`intercept` were derived from the signal range when the point was defined, so
the live-zero is already inside `intercept`. A decoder that reads the table
above and helpfully "corrects" for the offset —
`(count − 3584) × slope + intercept` — subtracts the live-zero a second time.
The result is not wrong by a little at one end: it is low by a **constant**
`zero_offset × slope` at every count in the range, full scale included, which
for the common 3,584…25,600 span is **16.3 % of the device range**. A 0–100 %
point built this way reads −16.3 at 4 mA and 83.7 at 20 mA and is internally
consistent the whole way, so nothing about the numbers looks broken unless
someone knows what the reading ought to be.

What the counts in the table are actually for is the other direction — reading a
raw count when you do *not* have the point's slope and intercept, and
sanity-checking a pair you do have. A count of 3,584 on a current input is 4 mA
and therefore the bottom of the device range whatever the engineering units are;
and a slope that does not satisfy
`slope ≈ (dev_high − dev_low) / (count_high − count_low)` for its sub-type's
counts belongs to a different sub-type or a different hardware generation
(§11.5.1.2).

Analog points carry a **sub-type** finer than the `LAI`/`LAO` distinction of
§11.2, and the sub-type — not the point type — selects the transform:

| Input | | Output | |
|---|---|---|---|
| `AII` | current | `AOI` | current |
| `AIV` | voltage | `AOV` | voltage |
| `AIP` | pneumatic | `AOP` | pneumatic |
| `AI100K` | 100 kΩ thermistor | `AOV16` | voltage, 16-unit span |
| | | `AOR` | resistive / floating |

#### 11.5.1.2 Slope and intercept are hardware-generation-relative

A point's slope and intercept are **not portable between hardware
generations**. Moving a point from one termination generation to another
requires re-deriving both from the originals, and the vendor's own tooling
carries a conversion table keyed by `(source sub-type, target sub-type,
generation)` to do it. Five generations are covered. [S] The controller families
the scaling data distinguishes are **MBC**, **SCU**, **MEC**, **AHUC**, **RCU**
(the P2 variant), **FLNC**, and the **MPU**, the last with a table of its own
(§11.5.2.1). [D]

The conversions have three shapes:

- **Identity** — `slope' = slope`, `intercept' = intercept`. The majority, and
  what the most recent generations use among themselves.
- **Span rescale** — `slope' = (a/b) × slope` where `a/b` is the ratio of the
  two full-scale counts, e.g. `3200/25600` or `25600/24576`.
- **Span rescale with offset correction** — the same, plus an intercept term
  that re-references the live zero:
  `intercept' = intercept + (z − (a/b) × o) × slope`, where `z` is the target
  engineering zero and `o` the source zero offset in counts.

The pneumatic and resistive outputs carry their own fixed ratios
(`20/18 × 255/30720` for `AOP`, `135/30720` for `AOR`, `10/16 × 255/30720` for
`AOV16`), and current output additionally shifts the intercept by −4 on one
generation — the 4 mA live zero again, this time in engineering units rather
than counts.

**Those are not five magic numbers; they are one rule.** Every ratio above falls
out of the count and device spans in §11.5.1.1:

```
ratio = (device span, source / device span, target)
      × (count  span, target / count  span, source)
```

Check each against the table: [I]

| Constant | Source span | Target span | Reads as |
|---|---|---|---|
| `255/30720` | MBC out, 0–20 mA over 30,720 | SCU out, 0–20 mA over 255 | device spans equal → count ratio alone |
| `10/16 × 255/30720` (`AOV16`) | MBC out, **0–10 V** over 30,720 | SCU out, **0–16 V** over 255 | the SCU voltage output really does span 16 V |
| `20/18 × 255/30720` (`AOP`) | MBC out, **0–20 psi** over 30,720 | SCU out, **0–18 psi** over 255 | two different pneumatic spans |
| `135/30720` (`AOR`) | MBC out over 30,720 | SCU resistive, 0–135 over 135 counts | resistive is count-identical, so only the count ratio survives |
| `3200/25600` | MBC **input**, 3,584…29,184 = 25,600 | SCU input, 800…4,000 = 3,200 | both 4–20 mA, so device spans cancel |

and the `−4` intercept shift is the same reconciliation one level up: **MEC and
AHUC current channels are 0–20 mA where MBC, SCU and RCU are 4–20 mA**, so
moving a point between those two groups moves the engineering zero by exactly
4 mA. It is not a per-generation fudge factor; it is the live zero appearing in
engineering units because the two families disagree about whether there is one.

The one constant this does not account for is **`25600/24576`**. No family in
§11.5.1.1's tables has a 24,576-count span, so a sixth input generation exists
that those tables do not cover — `24,576 = 24 × 1024`, against MBC's
`25,600 = 25 × 1024`, which makes it look like a near neighbour of the MBC
rather than a different class. **[OPEN]**

The practical consequence for anyone reading a point database: **a slope and
intercept are only meaningful alongside the sub-type and the termination
generation that produced them.** Two points with identical slope/intercept on
different generations do not represent the same transfer function. [S]

#### 11.5.2 Sensor types

An analog **input** carries a sensor type fixing its physical signal class; an analog output does not. The `Sensor_type` enumeration: [S]

| Code | Sensor | Code | Sensor |
|---|---|---|---|
| 0 | voltage | 7 | rtd1k |
| 1 | current | 8 | rtd1k_385 |
| 2 | resistance | 9 | nickel1000 |
| 3 | pneumatic | 10 | nickeljci |
| 4 | thermister10k | 11 | nickeldin |
| 5 | thermister100k | 12 | thermister10type3 |
| 6 | ltype | | |

The physical signal each class presents: **current** 4–20 mA, **voltage**
0–10 Vdc, **pneumatic** 3–15 psig. [D] `ltype` is not a sensor technology at
all — it marks **an analog input terminated on an FLN device rather than on the
panel**, which is why it has no signal range of its own and why its scaling is
the FLN device's business (§11.4). [D]

**Do not read a code off a pick-list position.** The codes above are the values
that appear in the address record on the wire. Engineering tooling presents the
same sensor set ordered for a human — current first, then thermistor, then
voltage — and with slightly different granularity: it offers a generic
*Thermistor* alongside the 10 kΩ, 100 kΩ and 10 k Type-3 entries, and it does
not offer `resistance` at all. Only `current` happens to land on the same
number in both. A value transcribed from a configuration screen is not a wire
code. [D][I]

**Most temperature inputs are already linearised, and §11.5.1.1's count ranges
do not apply to them.** This is the single most consequential thing in §11.5 and
it is invisible from the wire, because a linearised input and a raw one carry
the same `f32`:

| Sensor class on MBC / SCU / MEC / AHUC | eng (°F) pair | SI (°C) pair |
|---|---|---|
| thermistor, MEC RTD, nickel (all variants) | slope **1**, intercept **0** | slope 0.5556, intercept −17.7778 |
| series-1000 (MEC, AHUC) | slope 1, intercept **−0.6** | slope 0.5556, intercept −17.4445 |
| **RTD on an MBC** — the exception | slope 0.03984, intercept −501.453 | slope 0.02205, intercept −296.3628 |

The first row's engineering pair is the identity, and its SI pair is
`0.5556 x − 17.7778`, which is exactly `(°F − 32) × 5/9` and nothing else. **For
these sensors the panel has already done the linearisation and the "raw count"
is degrees Fahrenheit**; the two `Analog_scale` records are doing unit
conversion, not signal conversion. Only the MBC's RTD channel — and the
current/voltage/pneumatic classes generally — carry a genuine count-to-
engineering transform. A decoder that reasons about the 3,584 live-zero on a
thermistor input is reasoning about a number that is not there. [D]

**`intercept_adjustment` is lead-wire compensation, not a general trim.**
`Analog_sensor = { sensor_type, intercept_adjustment: f32 }` (5 B, §10.4.2), and
the adjustment exists for one purpose: on a resistance sensor the resistance of
the sensor *leads* adds to the resistance of the sensor, and on a long run that
is a real temperature error. It is computed from the **wire gauge and the run
length**, using a per-AWG coefficient: [D]

| AWG | 14 | 16 | 18 | 20 | 22 |
|---|---|---|---|---|---|
| coefficient, per foot | 0.03292 | 0.02070 | 0.01302 | 0.00818 | 0.00516 |
| coefficient, per metre | 0.10798 | 0.06789 | 0.04271 | 0.02683 | 0.01692 |

Two internal checks confirm the reading: each column is **3.280×** the one above
it, which is feet per metre; and each gauge step is **1.59×** the next, which is
the resistance ratio of a two-size AWG step. The MEC uses a slightly different
set for the three heaviest gauges (0.02932 / 0.01844 / 0.01289 per foot),
converging on the same values at 20 and 22 AWG. The coefficient's *unit* is not
stated anywhere and is not raw ohms per foot — it is ~13× copper's — so treat it
as a vendor-calibrated constant rather than a physical one. **[OPEN]** [D]

#### 11.5.2.1 Standard input ranges, and the MPU's two

A sensor's signal range is usually not typed in. The tooling offers a fixed set
of **standard input ranges**, and picking one fills in both the signal and the
device span; these nine are the whole set: [D]

| # | Engineering (°F) | SI (°C) | Quantity |
|---|---|---|---|
| 1 | 20 … 120 | −6.7 … 48.9 | temperature |
| 2 | 70 … 220 | 21.1 … 104.4 | temperature |
| 3 | −30 … 120 | −34.4 … 48.9 | temperature |
| 4 | −30 … 212 | −34.4 … 100 | temperature |
| 5 | 200 … 350 | 93.3 … 176.7 | temperature |
| 6 | −58 … 122 | −50 … 50 | temperature |
| 7 | −20.2 … 50.1 | −29.2 … 10.1 | dewpoint (`FDP` / `CDP`) |
| 8 | −55.3 … 114.7 | −48.5 … 45.9 | dewpoint |
| 9 | 0 … 100 | 0 … 100 | relative humidity (`% RH`) |

The **MPU** is the one controller with a scaling table of its own, and it has
exactly two ranges, both on `ltype` inputs: [D]

```
narrow    °F:  0.5    × count            °C:  0.2778 × count − 17.7778
wide      °F:  1.098  × count − 40       °C:  0.61   × count − 40
```

The narrow transform reproduces the documented **34–117 °F** span exactly, at
counts 68 and 234. The wide transform gives −40 °F at count 0 as documented, but
reaches only 240 °F at count 255 against a documented top of 260 — so either the
wide range runs past 8 bits or the published figure is the sensor's rating
rather than the channel's. **[OPEN]** [D]

#### 11.5.3 Enumerated and digital state decoding

For digital and enumerated points the wire/value field carries a small integer **state index**, not a string. The index is resolved for display against a named **text group / state-text set** (the `State_text_table`), stored once per panel as a shared catalog and referenced by name from the point or team member. [S/D] Example sets: 2000 = {Off, On}; 2001 = {Normal, Alarm}; generic sets like {Clean, Dirty}. [D] **On the wire the id is a *signed* 16-bit integer and every observed value is negative** — the per-type defaults `-1`/`-2` of §11.2, then two bands of named groups at `-1002`…`-1018` and `-2003`…`-2018`. A decoder that reads the field unsigned turns every one of them into a meaningless number in the 63,500s. The distribution is not a clean split by point type: LDI points draw exclusively from the `-20xx` band, LDO points predominantly from `-10xx` but from both, and enumerated points from both — so the bands are not "digital versus enumerated". **Nor is anything else**: see "the bands are allocation blocks" below, where three candidate rules are tested and all three fail. [W] The signedness is corroborated from a second direction: this id is the `enum_type_id` the **ENUM family (0x0401–0x040E)** creates and edits (§9.4), and every one of those bodies types it `i16` — `enum_type : { type_id:i16, type_name, nrOfelements:u16, elements:{ value:i16, value_text }[] }` is the state-text table itself, id and all its value→text pairs. A client that wants the display strings reads them with `AP2_ENUM_TYPE_DISPLAY` (0x0404) or `_LOOK` (0x0405) against the id the point carries. [S] A digital point's present value is encoded as the float `0.0` (OFF) or `1.0` (ON) in the value field (§12.3); an enumerated point's present value is the integer state index carried in that same float field. [D] An implementer renders the value by taking the index and looking it up in the referenced state-text group; the wire never carries the display string for **a value**. [D] **It does carry the whole table, and a client can therefore render points without any vendor file.** The ENUM family transfers them, and one of its opcodes is wire-observed: [W]

```
0x040A AP2_ENUM_TYPE_DB_GET
  request   last_enum_type_id : SHORT_        <- a resume key
  response  enum_type : Enum_type
            Enum_type : type_id : SHORT_ | type_name : TEXT_
                      | nrOfelements : UNSIGNED_16
                      | elements : (value : SHORT_, value_text : TEXT_)[]
```

All 28 exchanges in the corpus decode with zero remainder. Two distinct tables
appear — a two-state occupancy group at id `-1005` and a twelve-state zone-mode
group at `-2005` — and the resume keys presented (`-2006`, `-1006`) return
`-2005` and `-1005`, so the catalogue walk is **ascending in signed order**. An
unsigned reader also sees an ascending sequence and so appears to work, while
ordering the catalogue wrongly the moment it crosses zero: the same
plausible-wrong-answer failure as a sparse-enum lookup (§10.1). `0x0404
ENUM_TYPE_DISPLAY` and `0x0405 ENUM_TYPE_LOOK` fetch a single table by pattern
or by name. So the full render path for a digital or enumerated point is: read
the point's `state_text_table` id (§10.4.1), fetch that table, index it with the
value. [W][S]

**The catalogue itself, and the two things about it that break decoders.** The
shipped state-text catalogue holds **346 types and 2,060 levels**. Two
properties of it are load-bearing: [D]

- **A level's display text is at most 8 characters.** No exception in 2,060
  levels; the distribution runs 1–8 with a pronounced spike at both ends (325
  one-character names, 310 eight-character). A renderer can size a state column
  at 8 and a generator can reject anything longer.
- **One type in three is sparse.** `VALUE` is drawn from 0…255 but only 93
  distinct values are ever used, and **118 of the 346 types do not number their
  levels `0…n−1`** — `CR_CONTROLMODE1` is `{0, 2, 3, 15}`, `MC_HP_FAULTS` is
  `{187, 188, 189, 204, 205, 206, 207, 255}`. **Index a state-text table by
  `value`, never by array position.** Position-indexing is correct for the 2-level
  majority and silently wrong for a third of the catalogue — and wrong in the
  worst way, because it returns *some* other legitimate state name rather than
  failing. This is §10.1's sparse-enum rule again, and here it is quantified.

Type sizes are mostly small — 184 of 346 have exactly two levels — but the tail
is long, up to **77 levels** in one type, so a fixed-size table is not safe
either.

**The bands are allocation blocks, not a typed namespace.** It is tempting to
read meaning into `-10xx` versus `-20xx`, and three natural rules were tested
against the catalogue. All three fail: [I]

| Candidate rule | Result |
|---|---|
| `-10xx` is two-state, `-20xx` is multi-state | 74 % vs 61 % two-level — no split |
| `-10xx` ships every vocabulary in both polarities (`OFF_ON` / `ON_OFF`) | only 46 of 194 have a reversed twin; 2 of 31 in `-20xx` — a tendency, not a rule |
| `-20xx` exists because a name-length limit was lifted | both bands top out at 16 characters |

There is one real class boundary, and it is at **`-3xxx`**: those 107 types are
the LonMark/BACnet standard vocabularies, distinguishable by lowercase `name_t`
spelling, and they are the only band containing types flagged as *not* supported
on APOGEE. Everything from `-1000` to `-2999` is one flat, APOGEE-supported
vocabulary that happens to have been allocated in two sittings. **Treat the id
as opaque and resolve it through the catalogue; nothing about the band is
decodable.**

> Implementation caution: the TEC-template "PTYPE" field is a **template-local** taxonomy, NOT the §11.2 `Point_type` L-codes and NOT priority values. The 1–4 alignment with LDI/LDO/LAI/LAO is coincidental for those four only. Do not cross-map PTYPE to L-codes. [D]
>
> Censused rather than sampled, because the value set depends on where you look and on the controller family: [W]
>
> | Source | PTYPE values observed | Population |
> |---|---|---|
> | DataMate P1 point table | 1, 2, 3, 4; rarely 10, 11, 12, 34 | 76,355 rows / 1,021 applications |
> | DataMate **MSTP** point table | 1, 2, 3, 4 | 26,539 rows / 227 applications |
> | Point-team descriptors, P1 family | 1, 2, 3, 4 | 71,306 points / 714 applications |
> | Point-team descriptors, two outlier applications | 1, 2, 3, **16, 17, 20** | 268 points / **2** applications |
>
> **The overwhelmingly common set is 1–4 everywhere**, including across all 227 MSTP applications in the vendor's own MSTP point table. The values 16/17/20 occur in exactly **two** applications, whose numbers sit far outside the range every other source uses and which appear in no point table, no application table and no shipped catalog. Treat 16/17/20 as an outlier encoding tied to those two definitions, not as a family-wide alternative — an earlier revision of this document generalised them to "the MSTP family" and that was wrong. [W]
>
> The four rare DataMate values are all confined to drive/VFD applications and are legible from their own rows: **12** marks the application-number subpoint (`PTNUM 2`, "APPLICATION") and drive parameter-number/limit points; **10** and **34** are momentary command points carrying action labels rather than states (`RST ON`/`RSTOFF`, `RESET`/`NO`) — which is why `PTYPE 34` is `RESET FAULT` and has nothing to do with command-priority 34 = smoke; **11** occurs once, on a parameter-data read. Twenty rows in total. [W]

#### 11.5.4 Logical type → BACnet object type (optional cross-reference)

Where a P2 point is exposed on a BACnet/IP interface, its logical type maps to a BACnet object type; the physical/virtual flag selects the I/O-object versus value-object form. [D] (BACnet exposure is a separate stack; this map is provided only for implementers bridging the two.)

| P2 L-type | Physical | Virtual | Tag |
|---|---|---|---|
| LAI | AI | AV | [D] |
| LAO | AO | AV | [D] |
| LDI | BI | BV | [D] |
| LDO | BO | BV | [D] |
| L2SL / L2SP | BO | BV | [D] |
| LOOAL / LOOAP | BO (or MO/MV) | BV/MV | [D] |
| LFSSL / LFSSP / LFMSSL / LFMSSP | MO | MV | [D] |
| LPACI | AI (accumulator) | AV | [D] |
| LENUM | MO | MV | [D] |

---

## 12. Change-of-Value (COV)

COV is the mechanism by which a panel reports a point's value change to interested peers without being polled. It is a **subscription** service: a peer enables COV on points it cares about, the panel thereafter pushes a report (`COV_ANNUNCIATE`) whenever a subscribed point changes by at least its COV resolution, and the peer disables or deletes the subscription when done. COV is the highest-volume P2 operation in steady state. [W]

### 12.1 The subscription opcode set

The four COV opcodes are `AP2 Function Code` values (names and numbers from the function-code enumeration, cross-checked against the wire). [S/W]

| AP2 function code | Decimal | Name | Direction | Role | Tag |
|---|---|---|---|---|---|
| `0x0271` | 625 | `AP2_COV_ENABLE` | subscriber → panel | open a COV subscription on a point | [S/W] |
| `0x0272` | 626 | `AP2_COV_DELETE_STUB` | subscriber → panel | delete a subscription stub | [S/W] |
| `0x0273` | 627 | `AP2_COV_DISABLE` | subscriber → panel | close a COV subscription | [S/W] |
| `0x0274` | 628 | `AP2_COV_ANNUNCIATE` | panel → subscriber | the actual change-of-value report (unsolicited push) | [S/W] |

> Correction of an earlier reading: these opcodes were previously read as "ReadExtended / ReadDescriptorOnly / WriteNoValue-ExistenceProbe" against `0x0271/0x0272/0x0273`. The function-code enumeration shows they are the COV subscription register/delete/cancel/report quartet. The `00 FF` vs `00 00` mode trailer that earlier analysis treated as read-mode versus command-mode is the enable-vs-disable selector of the subscription. [S] This register/cancel-subscription model — rather than a one-shot read — is consistent with that enable/disable trailer. [S/I]

The `AP2_COV_ENABLE` request body (`AP2_COV_Enable_Request`) is `{ name_response, cov_mask }` — the addressed point plus the subscription's class mask; the response (`AP2_COV_Enable_Response`) is `{ point: All_points, lenum_address, point_extension2 }`, i.e. the panel returns the full current point object as the subscription's first report. [S] `AP2_COV_DISABLE` is `{ name_response, cov_mask }`; `AP2_COV_DELETE_STUB` is `{ name_response }`. [S] `AP2_COV_ANNUNCIATE` carries a count-prefixed array of `Annunciate_request` records (§12.3). [S] An annunciate push uses the request encoding (direction byte `0x00`, §6.3) because it is unsolicited; the peer acknowledges with a direction-`0x01` empty success. [W]

### 12.1.1 When subscriptions are registered — concentrated at session establishment

A subscriber registers its COV subscriptions **in the opening seconds of a
session**, not continuously. This is measured rather than inferred: a 16.7-hour
capture on a panel's own switch port holds **48 `COV_ENABLE` requests, every one
of them within the first 8.9 seconds**, and none across the remaining sixteen
hours. Subscriptions that succeed are not renewed, and — importantly — **a
subscription that fails is not re-attempted for the life of the session.** [W]

**Corpus-wide the concentration is real but the tail is longer, and the
difference matters to a publisher.** Across the 159 connections that
demonstrably *began* during their capture — 1,917 `COV_ENABLE` requests — the
offset from the connection's first frame is: [W]

| | |
|---|---:|
| median | **11.0 s** |
| within 10 s | 45.6% |
| within 60 s | 73.6% |
| p90 | 299 s |
| max | 721 s |

So "at session establishment" is right about where the mass is and wrong as an
absolute: roughly one subscription in eleven arrives more than five minutes in.
A publisher must keep accepting `COV_ENABLE` for the life of the session, and a
diagnostic tool that samples only the opening seconds will miss some.

> **Why this is not simply measured over the whole corpus.** Most connections
> were already open when their capture began, and an offset measured from a
> mid-stream join is meaningless — including all of them drags the median to
> 155.8 s and says nothing. Excluding every connection whose first frame sits at
> capture start is *also* wrong, because installing an inline tap tears down
> every session on the port, so in those captures the sessions genuinely did
> start there: 59 of the 121 captures show that pattern and 62 are staggered.
> The figures above take only the unambiguous case — a connection whose first
> frame is more than 30 s after its capture's — and no reading of this corpus
> settles the rest. [W]

Three consequences an implementer needs:

- **A subscription's lifetime is bounded by its TCP session.** There is no
  renewal or lease traffic to maintain, and none to expect from a peer. A
  subscriber that reconnects must re-register everything it wants; a publisher
  must not assume a prior session's subscriptions survive.
- **A failed subscription is silent thereafter.** `not_found` on `COV_ENABLE`
  ends the matter until the next reconnect. Nothing on the wire will indicate,
  minutes or hours later, that a subscriber is missing values it asked for — so
  a diagnostic tool must capture the session's opening seconds to see the
  failure at all.
- **Do not read `COV_ENABLE` volume as a health signal.** A burst of
  subscription traffic means sessions are being established, not that anything
  is wrong or busy. Sustained bursts mean sustained reconnection, which is a
  transport-layer symptom rather than a COV one.

> A caution for anyone measuring this, learned the hard way: an inline tap has
> to break the link to be installed, which tears down every session on the port.
> The first minutes of such a capture are the segment re-establishing, and they
> are dense with subscription registrations that are an artifact of the
> measurement. Take steady-state readings from a capture long enough to leave
> that window behind.

### 12.2 The COV class mask and subscription type

A subscription names a **COV mask** selecting which classes of change generate a report. The `Cov_mask` is a bitfield; the bit positions are the panel's own `Cov_mask` enumeration: [S]

| Bit | Class | Meaning | Tag |
|---|---|---|---|
| 0 | `data` | present-value change (the ordinary COV) | [S] |
| 1 | `failure` | transition into/out of the failed condition | [S] |
| 2 | `alarm` | transition into/out of an alarm condition | [S] |
| 3 | `service` | out-of-service / in-service change | [S] |
| 4 | `priority` | command-priority (ownership) change | [S] |
| 5 | `TCU` | terminal-control-unit-related change | [S] |
| 6 | `temp_all` | a temporary all-class subscription | [S] |
| 7 | `proof_on` | proof-status change | [S] |

A `Point_cov_type` enumeration also exists in the type system, nominally selecting the granularity of what is reported: `0 = all_types`, `1 = point_values`, `2 = point_priorities`, `3 = point_status`. [S]

**Do not try to send it — it has no wire field.** Of the 459 distinct field types used across the 1,144-structure library, **none** is a `Point_cov_type`, and the two subscription requests are two fields each with no room for one:

```
AP2_COV_Enable_Request  =  name_response : Name_response ,  cov_mask : Cov_mask
AP2_COV_Disable_Request =  name_response : Name_response ,  cov_mask : Cov_mask
```

`Cov_mask` is carried by exactly three structures — those two and `Cov_data`, the cross-reference record below. So on the P2 wire a subscription is defined by the **mask alone**: which transitions generate a report. The granularity enum is declared but unreachable through these opcodes, and is most likely a supervisor-internal or BACnet-side concept (the library does carry a separate `Bacnet_COV_Destination`). An implementer building a subscriber sets mask bits and nothing else. [S]

The panel also maintains a **COV cross-reference** (which peers are subscribed to which points), readable via `AP2_Xref_COV_Display` — its response is a count-prefixed array of `Cov_data = { destination_panel: u16, cov_mask }` rows, i.e. for each subscribing panel the mask it holds. [S]

### 12.3 The annunciate / value payload

#### 12.3.1 Field model

The body the panel pushes for each changed point is the `Annunciate_request` record. Its fields are the **complete dynamic state** of a point (the static definition attributes — name, descriptor, limits, slope/intercept, units, proof delay — are not carried; they come from the point-definition record, §11.4/§11.5). [S]

| # | Field | Type | Meaning | Tag |
|---|---|---|---|---|
| 1 | `name_response` | `{name_space, name, suffix}` | the point being reported | [S] |
| 2 | `value` | `FLOAT_` (f32 BE) | present value: eng units (analog/pulse), 0.0/1.0 (digital), state index (enum) | [S/W] |
| 3 | `point_priority` | `Point_priority` | command-ownership holder (§12.4) | [S] |
| 4 | `control_status` | `Control_status` | remote / tool-override / by-priority / config-only / input-only / manual-override / undefined | [S] |
| 5 | `out_of_service` | bool | point taken out of service | [S] |
| 6 | `failed` | bool | hardware-failed | [S] |
| 7 | `proof_on` | bool | within proof window | [S] |
| 8 | `operator_disabled` | bool | operator-disabled (frozen) | [S] |
| 9 | `program_disabled` | bool | control-program-disabled | [S] |
| 10 | `commanded_to_alarm` | bool | forced (alarm-by-command) | [S] |
| 11 | `alarm_state` | `Alarm_state` | normal / alarm / high_alarm / low_alarm / trouble | [S] |
| 12 | `alarm_priority` | `Alarm_priority` | priority_0 … priority_6 (§13.2) | [S] |

#### 12.3.2 Operating-state taxonomy

The boolean and enum status fields (#4–#12 above) encode the point's **operating state**. The semantic taxonomy an implementer must render is: [S/D]

- **Normal** — no status bit set, `alarm_state = normal`. [S/D]
- **Failed** — `failed` true; the point cannot be commanded or examined. [S/D]
- **Out-of-Service** — `out_of_service` true; value and condition frozen against the field. [S/D]
- **Proofing** — `proof_on` true; transient state during the proof-delay window after a command, before proof confirms. [S/D]
- **Alarm-by-Command** — `commanded_to_alarm` true; a forced alarm asserted by operator or program, treated as an alarm. [S/D]
- **Program-Disabled** — `program_disabled` true; control program prevented from acting on the point. [S/D]
- **Operator-Disabled** — `operator_disabled` true; value and condition frozen against operator and program (the point may still transition to failed). [S/D]

These are the semantic meaning of the per-point status the COV report conveys; `alarm_state` (normal/alarm/high/low/trouble) and `alarm_priority` ride alongside for points that are in alarm. [S]

#### 12.3.3 Wire layout and the open offsets

The `COV_ANNUNCIATE` (`0x0274`) body is now wire-confirmed. The body opens with a `count` (u16) of points reported, then, **per point**, a `name_response` (its three sub-fields, §8.5) followed by the value and condition block: a 2-byte `name_space` (observed constant `00 00` = system), the **name TLV** `01 00 <len> <point-name>`, an **empty `suffix` TLV** `01 00 00` (the §8.1 empty-string TLV — *not* a "value marker"; it is non-empty only for FLN subpoints, e.g. `01 00 09 "ROOM TEMP"`), then the present-value **`f32` big-endian**, then a **fixed 10-byte condition/priority block** carrying fields #3–#12 one byte each. The name TLV therefore begins at body offset **+4** (after `count` + `name_space`), not +2. [W]

```
<count u16>                               -> number of points in this push
  per point (a name_response + value + condition):
    00 00                                 -> name_space (u16; 0 = system)   [+0 of record]
    01 00 <len> "<point-name>"            -> name TLV   (e.g. "OATEMP.BN")
    01 00 00                              -> suffix TLV (empty; non-empty only for FLN subpoints)
    <f32 BE>                              -> present value (e.g. 42 9b 62 3a ≈ 77.69)
    -- 10-byte condition/priority block = fields #3..#12, one byte each, in order:
    +0  point_priority        (§12.4 ladder; 0 = NONE)
    +1  control_status        (0x04 observed on normal analog points)
    +2  out_of_service  (bool)
    +3  failed          (bool)
    +4  proof_on        (bool)
    +5  operator_disabled    (bool)
    +6  program_disabled     (bool)
    +7  commanded_to_alarm   (bool)
    +8  alarm_state           (normal/alarm/high/low/trouble)
    +9  alarm_priority        (priority_0..6)
```

Worked examples (sanitized): a normal sensor `OATEMP.BN`, value `42 9b 62 3a` (≈ 77.69), block all-zero at NONE priority; a normal analog point with `control_status` (+1) = `0x04` and everything else zero; a point **commanded at OPER** shows the block opening `23 02 …` — `point_priority` (+0) = `0x23` (OPER) and `control_status` (+1) = `0x02`; and a **failed sensor** (`…RET AIR TEMP`, value `c2 79 ff ff` ≈ −62.5) shows non-zero bytes deeper in the block (a flag byte in the +7..+8 region asserted). A reader needing only the present value takes the `f32` and may ignore the block. [W]

> **[W/F — values pinned; the alarm band is declared but unobserved here]** The 10-byte trailing block's **position, size, and field order are established** (the `Annunciate_request` ASDU defines fields #3–#12, exactly ten one-byte fields follow the value, and that fits the wire bit-for-bit). **The controller's own encoder confirms it independently:** the function that serialises this body emits `u16 | TEXT_ | TEXT_ | f32 | ` and then **exactly ten calls to the one-byte write primitive**, consecutively, with nothing between them — so "ten one-byte fields after the value" is not an inference reconciling a schema against a byte count, it is what the panel is compiled to write. [F] Newer command/abnormal-state captures confirm the **first two bytes' asserted values**: `point_priority` (+0) ∈ {`0x00` NONE, `0x20` EMER, `0x23` OPER} tracking who holds the point (`0x20`/emer seen on BACnet-integration points commanded to 1.0), and `control_status` (+1) observed taking `{0x00, 0x02, 0x03, 0x04, 0x06}` (e.g. `0x02` when the point is under an active operator command, `0x04` on a normal analog input). A failed sensor asserts a flag byte in the OOS/failed region (+2..+8). [W]

**`control_status` (+1) can be read, and the reading checks itself.** The type system names this byte's enumeration `0 remote / 1 tool_override / 2 by_priority / 3 config_only / 4 input_only / 5 manual_override / 6 undefined` (Appendix A; §11.3.1 for what `manual_override` means to an operator). Set that against the two values this corpus characterises *from the wire alone* — `0x02` on a point under an active operator command, `0x04` on a normal analog input — and both land on the name that describes exactly that condition: `by_priority` for a point held by a command priority, `input_only` for an input. The wire reading and the vendor's name for it were arrived at separately and agree, which is worth more than either alone. The other three observed values follow: `0x00` `remote` on a normal panel-controlled output, `0x03` `config_only`, `0x06` `undefined`. [W][S]

**`alarm_state` (+8) and `alarm_priority` (+9) are declared, and this corpus does not exercise them.** Those are two different statements and an earlier edition of this section ran them together, calling the *encoding* open when only the *observation* was missing:

| byte | enumeration | values |
|---|---|---|
| +8 `alarm_state` | `Alarm_state` | `0` normal, `1` alarm, `2` high_alarm, `3` low_alarm, `4` trouble |
| +9 `alarm_priority` | `Alarm_priority` | `0`–`6` = `priority_0`–`priority_6`; §13.2 shows `priority_0` is *unassigned*, not a seventh band, so render it as none |

Both are tabulated in full in Appendix A. What is still open is narrower than it was: **no point in this corpus was in a true hi/lo-limit alarm, so neither byte has been seen non-zero on the wire.** A single `0x0274` push from a point sitting in a limit alarm would confirm the mapping; nothing about it is unknown in the meantime. [S][OPEN]

### 12.4 Command priority (carried in the COV payload)

`point_priority` is the command-ownership holder — which class of command source last successfully commanded the point. The `Point_priority` / `User_command_priority` ladder, lowest to highest acceptance, with the byte value that encodes it on the wire: [S]

| Value | Name | Tag |
|---|---|---|
| 0 | `none` (default; most control-program output) | [S] |
| 1 | `tec_ovrd` (TEC local override) | [S] |
| 5 | `pdl` (peak-demand-limiting) | [S] |
| 10 | `host_2` | [S] |
| 15 | `host_3` | [S] |
| 20 | `host_4` | [S] |
| 25 | `host_5` | [S] |
| 30 | `host_6` | [S] |
| 32 | `emer` (emergency) | [S] |
| 34 | `smoke` (smoke control / life safety) | [S] |
| 35 | `oper` (operator command, highest) | [S] |

The familiar operator-facing ladder is **OPER (35) > SMOKE (34) > EMER (32) > PDL (5) > NONE (0)**; the `host_2..host_6` band (10–30) and `tec_ovrd` (1) fill the intermediate rungs, and a later band (BACnet priorities 101–116) maps the 16 BACnet command-priority slots. [S] A command at a given priority overrides only equal-or-lower holders; a release lowers the holder to NONE so a control program can reacquire. [D] This same priority byte is the `scope_byte` of a scoped command request (§8.2) and the command-priority field of the point-definition header. [W] At the codec layer command priority is a single byte (`GetPriority → BYTE`). [S]

### 12.5 COV behavior and tuning

- **EU deadband (COV limit / resolution).** An analog point reports a change only when the value moves by at least one **COV limit** — the engineering-units resolution of the subscription. The COV limit is floored at the point's slope: it cannot be finer than one raw count mapped through the slope (a smaller configured value is clamped up). For a pulse accumulator (LPACI) the floor is one pulse. [D] The COV limit is expressed in dual form — engineering value and equivalent raw count — because it maps through the slope to a raw-count resolution; "1.0 (32)" means one engineering unit = 32 raw counts. [D]
- **Digital / enum points.** Any state transition is a change of value; there is no deadband. [D]
- **Dynamic COV.** A panel may auto-tune a point's effective COV resolution to hold the report rate near a target — roughly **one report per 100 seconds** — widening the deadband for a noisy point so it does not flood the network. [D]
- **Alarm deadband linkage.** The alarm-limit deadband (§13.3) is automatically set to one COV limit at each limit, so the COV resolution and the anti-nuisance alarm hysteresis are the same quantity. [D]

> Implementation caution: a field/application document's "COV limit" or "DISPLAY RES" describes the **local operator-display deadband** of a TEC, which explicitly does NOT affect networked values. Do not treat that local display setting as the network COV subscription resolution specified here. [D]

---

## 13. Alarming

Alarming is the panel's autonomous evaluation of points against limits and proof, and the reporting of alarm transitions to operators and destinations. Alarm reporting reaches the network either as a dedicated unsolicited alarm report or as a COV with the `alarm` mask bit set (§12.2); a subscriber may learn of an alarm by either path. [D]

### 13.1 Standard vs Enhanced alarms

A point's alarming behavior is selected by its **alarm object** type. The `Alarm_object` is a tagged union over the `Alarm_object_type` enumeration: [S]

| Code | Alarm object | Tag |
|---|---|---|
| 0 | `no_alarming` (point does not alarm) | [S] |
| 1 | `std_digital` | [S] |
| 2 | `std_single_analog` | [S] |
| 3 | `std_analog` | [S] |
| 4 | `enhanced_digital` | [S] |
| 5 | `enhanced_analog` | [S] |
| 6 | `enhanced_lenum` | [S] |
| 7 | `bacnet_alarm_analog` | [S] |
| 8 | `bacnet_alarm_digital` | [S] |

**Standard** alarms are the base form (limit-crossing or digital-state alarm, single destination set). **Enhanced** alarms add the richer alarm-mode machinery — multiple alarm modes, per-mode limits and setpoints, and enhanced-count behavior — and exist for digital, analog, and enumerated points. [S/D] **The nine arms' wire widths are in §10.4.4**, where four of them are measured; this section is the model, that section is the bytes.

The runtime alarm state of a point is the `Alarm_object_data` record: timestamps for current-state / first-alarm / acknowledgment, a `state_changes` counter, and the boolean condition set `{ ack_pending, return_to_normal_acks, inalarm, introuble, inalarm_by_command, operator_disabled, program_disabled, proofing, is_enhanced, print_alarms, enable_almcnt2 }`. [S]

**`enable_almcnt2` is not a display flag.** A panel keeps **two resident points
that count how many of its points are in alarm** — `ALMCNT`, the standard
counter, and `ALMCT2`, a second one. Every point alarm increments `ALMCNT`; a
point with this flag set increments **both**. The second counter exists so a
site can count a functional subset separately — smoke-control points monitoring
door alarms is the vendor's own example — and because they are ordinary
panel-resident points, they can be read, trended, and referenced from PPCL like
any other. A client that wants "how many alarms does this panel have" reads
`ALMCNT` rather than counting reports. [D]

**The alarm mode is selected by another point, and its values are fixed.**
Enhanced alarming does not carry a mode field; it carries a **mode point**, and
that point's current value selects which mode's setpoint, levels, destinations
and messages apply: [D]

| Mode value | Mode | Notes |
|---:|---|---|
| 0 | night | |
| 1 | day | |
| 2 … 5 | special modes | e.g. warm-up, cool-down |

On pre-APOGEE firmware the mode point is a **virtual LAO** carrying 0–5; on
APOGEE firmware it should be an **LENUM or LDO**, and in practice is often a
zone-mode point or a TEC's day/night point. Anything that can command a point
can therefore change an alarm mode — a time-of-day schedule, a PPCL program, or
a physical switch. **A mode must additionally be enabled** before the panel will
report alarms while in it; a configured mode that was never enabled is silent,
which is not the same as a point that does not alarm. [D]

### 13.2 Alarm priority is distinct from command priority

An alarm carries an **alarm priority** that classifies the urgency of the *event*, which is a completely separate axis from the **command priority** (§12.4) that classifies the *ownership* of a command. An implementer must keep the two apart. [D] The `Alarm_priority` enumeration is `priority_0 … priority_6`; the operational severity bands these represent: [S/D]

| Value | Severity class | Tag |
|---:|---|---|
| 1 | Life Safety | [D] |
| 2 | Fire | [D] |
| 3 | Critical | [D] |
| 4 | Security | [D] |
| 5 | Trouble | [D] |
| 6 | Maintenance | [D] |

**Those six names are a site's configuration, not the protocol's.** The labels
are defined per system in a profile an engineer edits, and the wire carries only
the number. The set above is the vendor's own example and the one almost
everybody uses, which is exactly why it is worth stating that a decoder must
**not** hard-code it: two sites can disagree about what `3` means, and both are
correct. The same applies to the 4-character short labels an alarm report may
carry (`URGT`, `MAIN`, `TROB`) — those are the site's abbreviations of its own
band names. Render the number; render a label only if you have that site's
profile. [D] An earlier revision of this table merged Life Safety and Fire into
one row, which left five bands against six values and no way to tell which value
was missing.

The alarm report carries this priority as a 1-byte value (1–6) and may append a 4-character class label (e.g. `URGT`, `MAIN`, `TROB`). [W] The type system's `Alarm_priority_enum` has **seven** members, `priority_0` through `priority_6`, and the extra one reconciles cleanly: the control language's `ALMPRI` function — which reads a point's alarm priority from inside a program — is documented as returning **1 through 6**, the same range the report carries. `priority_0` is therefore the unassigned value, not a seventh severity, and a decoder should render it as "none" rather than inventing a band for it. [D][S] The point's runtime `alarm_state` (§12.3.1) is one of `normal / alarm / high_alarm / low_alarm / trouble`. [S]

### 13.3 Analog limits, transitions, and deadband

An analog or pulse point carries a **high limit** and a **low limit** in engineering units. A value crossing a limit asserts the alarm condition (and, for analog, distinguishes `high_alarm` vs `low_alarm`). [S/D] An **alarm deadband** equal to one COV limit (§12.5) is automatically applied at each limit to suppress nuisance re-alarming as the value dithers across the threshold. [D] The point-definition record carries both English and SI limit pairs alongside the dual scaling (`english_low_alarm` / `english_high_alarm` / `si_low_alarm` / `si_high_alarm`). [S]

Alarm transitions follow the standard three-transition model — **to-off-normal**, **to-fault**, **to-normal** (the `BAC_Transitions` set: `to_offnormal`, `to_fault`, `to_normal`) — and a point may be configured to **annunciate** on each transition independently ("Annunciate to Normal / Off-Normal / Fault Transitions"). [S/D] The standard-alarm time delay is the BACnet one: the value must stay outside the high/low band for that long before a to-off-normal event, or back inside it *including the deadband* before a to-normal. [D]

**`level_delay` and `mode_delay` are both `u16` and they are not in the same
unit.** They are adjacent in the alarm-setup record and describe superficially
similar waits, which makes this the easiest field pair in the section to get
wrong: [D]

| Field | Unit | What it waits for |
|---|---|---|
| `level_delay` | **seconds** | how long the value must stay inside an alarm level's range before the panel reports at that level — the anti-chatter delay for a door opening |
| `mode_delay` | **minutes** | how long the system is given to *reach and stabilise at* a new setpoint after a mode change, before the panel starts checking it at all |

A decoder rendering both as seconds is wrong by 60× on one of them, and wrong in
the forgiving direction — a 15-minute mode delay shown as 15 seconds looks like
a plausible debounce rather than an obvious error. The two also differ in kind:
`level_delay` suppresses a transient, `mode_delay` suppresses the *expected*
excursion that a setpoint change itself causes.

**`differential` is a return-to-normal hysteresis, applied on one side only.**
It is not a symmetric band around the limit: a point in alarm stays in alarm
until its value crosses back past the limit *by* the differential. A point that
alarms at 74 °F with a differential of 2.0 does not report normal until it drops
below 72 °F. This is distinct from the automatic one-COV-limit deadband of the
paragraph above, which applies at the limit itself; a point can carry both. [D]

An **enhanced** definition as it actually arrives on the wire — mode point,
units, set point, and the level table with each level's offset, priority,
category and message number — is decoded in §10.8 (`AP2_UPL_ALL_ALARM_MODE`
response). [W]

**What an `offset` in that level table means depends on the point type, and the
two readings are not related.** [D]

- **On an analog point** it is a *displacement from the mode's setpoint*, above
  or below, that the value must cross to enter that alarm level. The levels are
  therefore concentric bands around a setpoint that itself changes with the
  mode — which is the whole reason enhanced alarming exists, and why an analog
  enhanced alarm cannot be flattened into a fixed high/low pair.
- **On an LENUM point** it is a *state index* from that point's state-text
  table (§11.5.3), and the levels partition the index range. **A level's
  priority applies from its own offset up to the next assigned one**, so the
  table is sparse by design: assigning `0`→normal, `2`→PRI1, `4`→PRI6 on a
  six-state point means `0–1` normal, `2–3` PRI1, `4–5` PRI6. If the *lowest*
  offset carries no priority, the first assigned priority reaches downward and
  covers everything below it — so omitting the bottom entry does not create an
  unalarmed floor, it extends the first alarm level over it. **Up to 64 offsets
  per LENUM point.**

One operational consequence worth carrying into any tool that writes these:
**changing an LENUM point's state-text table resets every offset**, because the
offsets are indices into the table that is being replaced. [D]

### 13.4 Alarm destinations and routing

An alarm-setup record (`AP2_Alarm_Setup_Request` / `_Modify` / `_Copy`) configures, per alarm point and per alarm mode: `mode_name` + `mode_suffix`, `normal_acks` (require ack on return-to-normal), `alarmcnt2` (second alarm count), `level_delay`, `mode_delay`, `differential` (f32 hysteresis), and **four destination category bytes** `category0 … category3`. [S] These four categories are the alarm's routing destinations; a system **default destination (000)** receives alarms not otherwise routed, so the effective routing is up to four configured destinations plus the default. [D] A destination is a category container that nodes append themselves to (`AP2_Category_Nodes_Append` / `_Remove`), so an alarm routed to a category reaches every node currently in that category. [S]

**The category record itself, and a clean external check on it.** The structure
is five fields: [S]

```
Category = category_id   : UNSIGNED8      -- the destination number
           description   : TEXT_          -- its descriptor
           dial_enabled  : BOOLEAN_
           printing_enabled : BOOLEAN_
           nrOfnodes_bits : u16 + nodes_bits[]   -- which nodes are in it
```

A panel's own local destination editor asks an engineer for exactly those five
things, in that order — destination number, descriptor, printing enabled,
dialing enabled, and the list of field panels — so the MMI screen and this wire
record are the same object seen from two sides. [D][S] `dial_enabled` is why
§3.9 carries a dial-up BLN limit at all: a destination can be a modem.

**And the membership field comes in two forms, which is the addressing split of
§3.3.1 showing through.** `Category` carries `nodes_bits` — a bitmap, which works
only where nodes are *numbered*. Its Ethernet counterpart `ECategory` is field-
for-field identical except that membership is `node_name_list : TEXT_[]`, a list
of names. A client must pick the form that matches the BLN it is talking to;
they are not interchangeable and the bitmap has no meaning on an EBLN. [S]

### 13.5 Controller alarms as digital points

A field controller's own health and discrete fault conditions are surfaced to the BLN as **digital points** carrying the alarm attributes above: an alarmable LDI whose state is the fault, with a proof/debounce window so a momentary glitch does not alarm, and network reporting via COV (`alarm` mask bit, §12.2) or by inclusion in an alarm poll. [D] This is how a controller-level event (a comm-fault, a hardware fault, a returning/failed device state) reaches an operator through the same alarm path as a process-point limit alarm: it is modeled as a digital point and rides the standard alarm and COV machinery rather than a separate channel. [D] The device-level liveness states themselves (`Failed_status`: normal / returning / unknown / failed) drive these point states. [S]

### 13.6 Alarm report and acknowledgment opcodes

| AP2 function code | Decimal | Name | Direction | Role | Tag |
|---|---|---|---|---|---|
| `0x0508` | 1288 (class) | AlarmReport / `AP2_ALARM_PRINT` family | panel → operator (unsolicited) | deliver an alarm notification | [W] |
| `0x0509` | 1289 | `AP2_ALARM_ACK` / CommandRead | operator → panel | acknowledge an alarm and read the addressed command object (wire-observed, census count 11) | [W] |

The unsolicited alarm report (`0x0508`) body, as wire-decoded from captured reports, carries the `"CC"` scope, the point `name_response`, then **three consecutive 8-byte timestamps** (§8.3.4) — an **event** time, a **reference** time, and a **created/configured** time (located after the point name/descriptor TLVs and the value block; their absolute byte offset shifts with the name lengths, so a parser anchors on the preceding fields rather than a fixed offset; the created stamp's base recurs across captures and points) — followed by the point's runtime **`Alarm_object_data`** record: a 2-byte `state_changes` counter (`UNSIGNED16`), the boolean condition set (`ack_pending, return_to_normal_acks, inalarm, introuble, inalarm_by_command, operator_disabled, program_disabled, proofing, is_enhanced, print_alarms, enable_almcnt2`), the point's **high/low alarm limits** (two `f32` BE — e.g. 85.0 / 50.0), and an **engineering-units TLV** (e.g. `DEG F`); the alarm condition is conveyed by these boolean flags (e.g. `inalarm`) together with the present value vs. the limits (e.g. a failed return-air sensor reading ≈ −62.5 below its low limit). [W] In the captured bodies there is **no separate 1-byte alarm-state enum, no 1-byte priority field, and no 4-character class label** — those (priority_0..6 and labels such as `URGT`/`MAIN`/`TROB`) are documented for the alarm *model* (§13.2) but were not present as discrete fields in these wire reports; treat them as `[D]`/`[S]` until a capture shows them. [W] An alarm may be duplicated across two transport channels or pushed inside a fresh `0x2E`/`0x2F` carrier connection; the body bytes are identical regardless of envelope, so de-duplicate by `sequence` or by the `(device, point, timestamp)` tuple. [W]

The acknowledgment (`0x0509`) uses the `"CC"` scope and read-style framing; it acknowledges an alarm and reads the addressed command object, the response echoing the addressed name. [W] For an acknowledgment the body additionally carries acknowledgment markers, an operator-identity TLV, and an 8-byte acknowledgment timestamp. [W] A `0x0273` (COV disable) frame is sometimes observed immediately before a `0x0509` as a precursor. [W] Error path: `0x0003` (not found) when the named target does not exist or the alarm cleared between the operator action and the arrival of the acknowledgment. [W]

Enhanced-alarm configuration uses the broader alarm-mode and category opcode families (`AP2_ALARM_MODE_*` 1312–1328, `AP2_CATEGORY_*` 1344–1357, `AP2_ALARM_MESSAGE_*` 1376–1386) — the setup/management surface for the runtime behavior described above. [S]
## 14. PPCL over the Wire

PPCL — Powers Process Control Language — is the on-board control language a field panel (PXC/MEC/CEC) executes. A panel runs one or more PPCL programs locally; the supervisor never executes PPCL — it only edits, uploads, and reports it across P2. PPCL is therefore a *language layer carried by* P2, not part of the P2 framing itself: a program is a body payload inside the program-management opcodes of §14.5, in exactly the same TLV/frame envelope as every other operation (§6, §8). This section specifies the language as far as an implementer needs to read a program out of a panel, write one back, and understand how a program's runtime point commands interact with the priority ladder of §8. [D/S]

### 14.1 Program model

A PPCL program is an ordered set of **line-numbered statements** resident in one panel. [D]

| Property | Value | Tag |
|---|---|---|
| Line number range | 1–32767, integer; conventionally assigned in multiples of 10 to leave insertion room | [D] |
| Execution order | ascending line number from the lowest, unless redirected by GOTO/GOSUB/IF | [D] |
| Line length | short, ~80 characters | [D] |
| Per-line state | enabled/disabled, traced/untraced, resolved/unresolved, failed, looped — see the per-line record §14.4 | [S] |
| Point references | by dotted logical system name (§14.2); referenced point must exist in the panel point DB or the line is marked **unresolved** | [D] |
| Restart behavior | after any interruption (power failure, warmstart) execution resumes at the first line; the lowest line runs every pass | [D] |
| Time-based statements | LOOP, SAMPLE, TOD, WAIT must be evaluated every pass | [D] |

A program is identified on the wire by its **program-name string** (operator tools append a `.PCL` extension; the wire identifier is the bare name). The program name and program-family are scoped under `Application_family = ppcl_program` (value 7) in the controller application catalog (§16.4). [S]

### 14.2 Point references, names, and macros

A PPCL statement references points by **dotted logical system name** (the modern named form of §3/§11, e.g. `AHU1.SAT`), never by the legacy numeric `TCCDSSPP` address. Point names used inside PPCL must not contain parentheses (parentheses are reserved for the expression grammar). [D]

Two name-length limits apply, and they are distinct:

- **Legacy 6-character system-name reference limit.** On old firmware revisions a PPCL statement could reference a system point only by a name of up to 6 characters; longer names were truncated for the reference. This is a *firmware-keyed* limit and is separate from — and stricter than — the BLN/node name limits. [D]
- **15-character node-name limit / 30-character object-name limit.** Current firmware references points by the full logical name (§3.4.2). The 6-character limit is a property of the legacy reference encoder, not of the point name itself. [D]

`DEFINE` (token `WHOPDEFINE`, §14.3) creates a **macro** — a symbolic alias substituted into later statements at compile time, used to give a readable handle to a point name or a constant. [S]

**System (resident) points.** A program has read access to panel-resident points that always exist and supply time, date, and system status. They are referenced by name like any other point: [S]

| Resident point | Meaning | Tag |
|---|---|---|
| `$LOC1`–`$LOC15` | 15 local scratch variables (program-local storage) | [S] |
| `$ARG1`–`$ARG15` | 15 subroutine argument slots (pass values into GOSUB) | [S] |
| `$PDL` | peak-demand-limiting interface point | [S] |
| `$BATT` | battery-status point | [S] |
| `TIME` | current time | [S] |
| `DAY` | day-of-week / day index | [S] |
| `ALMCNT` | current alarm count | [S] |
| `SECND1`–`SECND7` | per-second / scheduling helper points | [S] |
| `ALMCNT`, `ALMCT2` | alarm counters | [D] |
| `TIME`, `CRTIME` | current time; current real time | [D] |
| `DAY`, `DAYOFM`, `MONTH` | day-of-week, day-of-month, month | [D] |
| `HOLIDA` | holiday indicator | [D] |
| `FAILED` | failure indicator | [D] |
| `LINK` | BLN link-status point | [D] |
| **`NODE0` … `NODE99`** | per-node liveness points — one per node address, **100 names reserved** | [D] |

Both the `$`-prefixed and bare forms are reserved: `$LOC1`–`$LOC15` and
`LOC1`–`LOC15`, `$ARG1`–`$ARG15` and `ARG1`–`ARG15`, and `SECND1`–`SECND7`
alongside `SECNDS`. None may be used as a point name. [D]

**The liveness point set is `NODE0`–`NODE99` — one hundred names — and that is
the only hard node-count figure in this document.** It runs from zero, not one,
which matters for a reserved-name check: `NODE0` is a resident point and must
not be used as a point name. The vendor's own description is that *"all devices
or CPUs on the network occupy a node corresponding to its address"*, so the set
is one name per address across the full 0–99 range of §3.4.4. [D]

It bounds the *liveness model* — a program cannot reference a hundredth node's
point because no such reserved name exists. It does **not** by itself establish
the capacity of the host/node-name table of §5.3, which is a separate structure;
treat 100 as the ceiling on liveness-addressable nodes and the table's own limit
as **[OPEN]**.

### 14.3 Statement / keyword vocabulary

PPCL statements fall into functional categories; the panel stores each statement with a **token byte** identifying the statement type. The complete token set is the 71-entry statement-type table (vendor enum `PPCL_statement_type`, members prefixed `WHOP*` = "what-opcode"); it is reproduced in full in the appendix (cross-ref Appendix — PPCL statement-type token table). [S] The functional grouping: [D/S]

| Category | Statements (token name in parentheses where it differs from the keyword) | Tag |
|---|---|---|
| Program control / flow | `LOOP`, `ACT`/`DEACT` (activate/deactivate), `ENABLE`/`DISABLE`, `GOTO`, `GOSUB`, `RETURN`, `IF`/`THEN`/`ELSE`, `SAMPLE`, `WAIT`, `ONPWRT` (on-power-up), `ONERR` (on-error), `DBSWITCH` (database switch), `TABLE`, `STATE`, `LSTSQR` (least-squares), `LOCAL`, `DIM`, `COMMENT`, `DEFINE` | [S] |
| Point control | `ON`, `OFF`, `AUTO`, `FAST`, `SLOW`, `SET`, `RELEASE`, `MIN`, `MAX`, `DCR` (direct command/ratio) | [S] |
| Operational / alarm control | `ENALM` (enable alarming), `DISALM` (disable alarming), `ALARM` (force alarm), `NORMAL` (return to normal), `LLIMIT` (set low limit), `HLIMIT` (set high limit) | [S] |
| Emergency control | `EMON`/`EMOFF` (emergency on/off), `EMSET`, `EMFAST`, `EMSLOW`, `EMAUTO`, `RELTCU` (release TCU) | [S] |
| Energy management | `DAY`, `NIGHT`, `DC` (duty cycle), `TOD` / `TODMOD` / `TODSET` (time-of-day — §15), `SSTO` / `SSTOCOEF` (start-stop time optimization — §15.3), `HOLIDAY`, `ENTHAL` (enthalpy), `PDL` / `PDLDAT` / `PDLMTR` / `PDLSET` / `PDLDPG` (peak-demand limiting), `TIMAVG`, `INITTOT` (initialize totalizer) | [S] |
| COV / trend | `ENCOV` (enable COV), `DISCOV` (disable COV) — runtime COV-subscription control from within a program (cross-ref §12/§13 COV) | [S] |
| Communications | `EPHONE`/`DPHONE` (enable/disable phone — dial-up alarming), `MMI` (man-machine-interface control) | [S] |
| Special function / math | `ASSIGN` (expression assignment), `LSTSQR`, plus the arithmetic and logical operators of §14.4 | [S] |

#### The reserved word set

The complete set of names a program may not use as a point name, grouped by
role. This is the language's actual surface, and it is the authority for
spelling — the token names of the table above are identifiers, not syntax. [D]

| Role | Words |
|---|---|
| Flow | `IF` `THEN` `ELSE` `GOTO` `GOSUB` `RETURN` `LOOP` `WAIT` `SAMPLE` `ONPWRT` `TABLE` `DBSWIT` |
| Point command | `ON` `OFF` `AUTO` `SET` `RELEAS` `FAST` `SLOW` `MIN` `MAX` `DCR` `ACT` `DEACT` |
| Enable / alarm | `ENABLE` `DISABL` `ENALM` `DISALM` `ALARM` `NORMAL` `LLIMIT` `HLIMIT` |
| Emergency | `EMON` `EMOFF` `EMSET` `EMFAST` `EMSLOW` `EMAUTO` |
| Energy / time | `DAY` `NIGHT` `DAYMOD` `NGTMOD` `TOD` `TODMOD` `TODSET` `HOLIDA` `DC` `SSTO` `SSTOCO` `PDL` `PDLDAT` `PDLDPG` `PDLMTR` `PDLSET` `TIMAVG` `INITTO` `TOTAL` `PRFON` |
| Comms | `EPHONE` `DPHONE` `OIP` |
| Comparison, word form | `EQ` `NE` `LT` `LE` `GT` `GE` `EQUAL` `LESS` |
| Logical, word form | `AND` `OR` `NAND` `XOR` |
| Operators, dotted form | `.EQ.` `.NE.` `.LT.` `.LE.` `.GT.` `.GE.` `.AND.` `.OR.` `.NAND.` `.XOR.` `.ROOT.` |
| Math | `SIN` `COS` `TAN` `ATN` `LOG` `EXP` `SQRT` `ROOT` `COM` |
| Command priority | `@NONE` `@OPER` `@PDL` `@EMER` `@SMOKE`, and the bare `NONE` `OPER` `PDL` `EMER` `SMOKE` |

Two things an implementer should take from this. **Every comparison and logical
operator has two spellings** — a bare word and a dot-delimited form — and both
are reserved, so a tokenizer must accept `.GT.` and `GT` as the same operator.
And **the dotted forms include `.ROOT.`**, an operator with no bare-word
comparison analogue, which a grammar derived only from the word list will miss.

#### `OIP` — a program can execute operator functions

§14.3's frequency table shows `OIP` used 152 times across the corpus and absent
from the statement-type enum. It is a reserved word, and its role is specific:
[D]

```
OIP (Trigger, Sequence)
```

It **mimics an operator sequence normally typed at a terminal**, executing most
operator functions from inside a control program. `Trigger` is a point; the
sequence runs once on its OFF→ON transition and will not run again until the
trigger is cycled. It does not run on the first pass after a power failure, an
enable, or a database load — only on a fresh transition. A malformed sequence
makes the statement report `FAILED` at execution time rather than at edit time.

The consequence is worth stating plainly, because it changes what "PPCL is
writable" means. Adding a program line is an ordinary wire operation
(`0x4100 AP2_PPCL_ADD_LINE`, wire-observed), and a line may contain `OIP`.
**A peer that can write a PPCL line can therefore execute operator console
functions on the panel**, gated only by getting a trigger point to transition.
Editing control logic and issuing operator commands are not separate
capabilities. See §17. [W][D]

#### The token names are not the source spelling

The table above and the 71-entry token set are **enum member names**. Program
source does not spell them that way, and a parser built from the enum will fail
on real program text. Measured over **64 control programs, 10,451 lines, of
which 4,731 are statements**: [W]

| Enum token | Spelling in source | Occurrences of each |
|---|---|---|
| `WHOPDBSWITCH` | `DBSWIT` | `DBSWITCH` **0**, `DBSWIT` 101 |
| `WHOPINITTOT` | `INITTO` | `INITTOT` **0**, `INITTO` 19 |
| `WHOPRELEASE` | `RELEAS` | `RELEAS` 51 as a statement |
| `WHOPDISABLE` | `DISABL` | `DISABL` 3 as a statement |

**No statement keyword in the corpus exceeds six characters.** The length
distribution of the leading keyword over all 4,731 statement lines is
2 ×2,132, 3 ×637, 4 ×745, 5 ×297, **6 ×480, and nothing longer**. Six is a hard
ceiling, not a tendency — the same six-character limit §14.2 describes for
legacy point references applies to the keyword field itself. An implementer
should match on the six-character form and treat the enum names as identifiers,
not syntax. [W]

#### Statement frequency, and one statement the enum does not name

What programs actually use, by count: [W]

```
IF     1872   GOTO    530   ON      260   SET     195   TIMAVG  169
GOSUB   166   OFF     161   OIP     152   WAIT    139   SAMPLE   93
TABLE    89   DBSWIT   78   LOOP     62   MIN      47   MAX      44
RETURN   38   DAY      38   NIGHT    36   RELEAS   31   DEFINE   18
INITTO   15   LSTSQR   14   EMON     12   ONPWRT   11   ENABLE    8
LOCAL     6   DISABL    3   TODMOD    2   SSTO      2
```

Twenty-nine distinct statements account for all 4,731 lines. The long tail of
the token set — the emergency, PDL, phone, alarm-limit and COV-control families
— appears in none of these programs, which says something about what production
control logic is made of but nothing about what the language supports.

**`OIP` is used 152 times and is not in the vendor statement-type enum.** Its
form is `OIP (<identifier>, "<point name>")` — independently confirmed by the
compiler's own error text, which names *"syntax error in OIP statement,
parenthesis or quotes"* and so attests both delimiters. The enum has exactly two unnamed
members, `WHOPUNKNOWN1` and `WHOPUNKNOWN2` (values 61 and 62), so the token set
itself records that not every statement is named in it.

This is the same situation as the EBLN opcodes of §5.3.1 and resolves the same
way: **absence from a vendor enum is not evidence that something is not real.**
A statement appearing 152 times across a production corpus is real; a parser
that rejects it because the enum lacks it will fail on ordinary programs. What
`OIP` *does* is not established here and is not guessed. [W] **[OPEN]**

### 14.4 Expressions, operator precedence, and the command parameter array

**Operator precedence**, highest to lowest (a conformant compiler/decompiler must honor this chain): [D]

```
( )                         parentheses                       (highest)
functions                   built-in functions (MIN, MAX, ROOT-class, etc.)
ROOT                        square-root operator
*  /                        multiply, divide
+  -                        add, subtract
EQ NE GT GE LT LE           relational comparison
AND  NAND                   logical AND / NAND
OR  XOR                     logical OR / XOR             (lowest)
```

**The relational operators are mnemonics, not symbols, and a decompiler that
emits symbols produces source that will not compile.** The vendor's precedence
table spells them `EQ`, `NE`, `GT`, `GE`, `LT`, `LE`; no symbolic form (`<`,
`>=`, `<>`) appears anywhere in the language's own documentation. An earlier
edition of this table listed the symbols. [D]

`ROOT` is likewise not a prefix function but a **dotted infix operator**,
written `(value1.ROOT.value2)` — a form worth noting because it is unlike
everything around it, and a tokenizer that treats `.` as a decimal point or a
name separator will mis-lex it. [D]

**Built-in functions.** The language provides a small fixed set of numeric functions, callable in any
expression: the arithmetic/transcendental set **`ROOT`** (square root, also written `SQRT`), **`LN`**
(natural log), and the trigonometric **`SIN`** / **`COS`** / **`TAN`** / **`ATN`** (arctangent); an
accumulator function **`TOTAL`**; and a regression/adaptive group — **`LSTSQR`** (least-squares fit),
its helpers **`LSQ2`** / **`LSQDAT`**, and the adaptive-control functions **`ADAPTM`** / **`ADAPTS`**.
The point-selection operators **`MIN`** / **`MAX`** (and the point-command statements `MIN`/`MAX` of
§14.3) round out the math vocabulary. A function binds tighter than the arithmetic operators (it sits
just below parentheses in the precedence chain above). [S/D]

**The 16-slot command parameter array.** A point-command statement (ON/OFF/SET/AUTO/etc.) carries an ordered parameter array of up to **16 slots**. Each of the following consumes exactly one slot:

- a target-point reference,
- a `SET` value (numeric or expression result),
- an `@`-priority indicator (see below).

An implementer building a command line must count parameters against the 16-slot ceiling; a 17th parameter is rejected. [D]

**There is a second, larger ceiling that is easy to miss: 32 operators.** The
compiler enforces both, and they count different things — *"a total of 16
operands can be used in one PPCL statement"* and *"a total of 32 operators can
be used in one PPCL statement."* An operand is a point reference or a constant;
an operator is each arithmetic, relational or logical operation the expression
performs. A statement can therefore exceed neither, and a generator that checks
only the operand count will emit lines a panel rejects. [D]

**Three more constraints a program writer has to satisfy, from the compiler's
own error set:** [D]

- **No backward `GOTO`, except the last one in the program.** Any other `GOTO`
  referring to an earlier line number is rejected — so a program is essentially
  a forward flow with at most one loop back, and a naive code generator that
  emits loops will not compile.
- **A `GOTO`/`GOSUB` target must be an integer line number that exists.** Both
  the non-integer and the dangling-reference cases are distinct errors.
- **A statement may not reference a point in another panel.** Cross-panel
  references are a compile error, not a runtime failure — which is what the
  Cross Trunk feature of §3.5 exists to work around, and why it carries the
  restrictions it does.

Line numbering itself is `1`–`32,767`, conventionally assigned in multiples of
ten to leave insertion room, and each must be unique — the compiler rejects a
duplicate or out-of-range number outright. [D]

**Priority `@`-indicators.** A PPCL command may specify the command priority at which it acts using an `@`-prefixed indicator. These map one-to-one onto the command-priority ladder of §8: [S]

| `@`-indicator | Priority name | scope_byte (§8.2) / `User_command_priority` value | Tag |
|---|---|---|---|
| `@OPER` | OPER (operator) | 0x23 (35) | [S] |
| `@SMOKE` | SMOKE | 0x22 (34) | [S] |
| `@EMER` | EMER (emergency) | 0x20 (32) | [S] |
| `@PDL` | PDL (peak-demand limiting) | 0x05 (5) | [S] |
| `@NONE` | **PPCL** — the level a control program owns (also the release / lowest level) | 0x00 (0) | [S/D] |

**`@NONE` is the PPCL priority, not the absence of one.** The five levels
answer *who owns this point* — the control program, the operator, peak-demand
limiting, emergency, or smoke control — and `@NONE` names the control program.
It is simultaneously the lowest rung and the level at which every ordinary PPCL
command lands, which is why a program's writes are the first thing any operator
action displaces. Reading it as "no priority" makes the ladder's bottom look
empty when it is in fact the default owner of most points. [D]

An `@`-indicator is also a **test**, not only a command: a statement may ask
whether a point currently sits at a given priority as well as drive it there.
And a PPCL statement admits **at most 16 parameters**, with the `@`-indicator
consuming one of them — a limit worth knowing before generating statements
programmatically. [D]

A PPCL program that commands a point at, say, `@EMER` overrides any standard NONE-priority sequence and holds the point until a `RELEASE` (or `@NONE`) at an equal-or-higher priority frees it. Exactly these five `@` levels exist; the intermediate host levels (`host_2`..`host_6`, values 10/15/20/25/30) and `tec_ovrd` (1) appear in the full `User_command_priority` enum but are not exposed as PPCL `@`-indicators. (Cross-ref §8 for the full priority ladder and the read-vs-write `scope_byte` dispatch.) [S]

### 14.5 PPCL program-management opcodes

All PPCL operations are AP2 function codes. The enumerate/upload family lives in the `0x09xx` upload block; the editor family lives in the `0x41xx` block. The editor opcodes carry the 12-byte SYST scope footer `01 00 04 "SYST" 23 3F FF FF FF` at the end of the body — required, not padding; a body without it is rejected. (Cross-ref §7 for the directory-byte/error model and §6/§8 for the TLV envelope.) [S/W]

| Opcode | AP2 name | Operation | Status / class | Tag |
|---|---|---|---|---|
| `0x0985` | `AP2_UPL_ALL_PPCL` | upload **all** PPCL lines of a program (the bulk reader) | upload, read-only | [W] |
| `0x0975` | `AP2_UPL_ADDED_PPCL` | upload only lines added since the last sync | upload, read-only | [S] |
| `0x0965` | `AP2_UPL_DEL_PPCL` | report lines deleted since the last sync | upload, read-only | [S] |
| `0x0955` | `AP2_DBCHANGE_PPCL` | DB-change notification for PPCL (replication trigger) | replication push | [S] |
| `0x030A` | `AP2_PPCL_SAVE` | persist program changes to non-volatile store | state-changing | [S] |
| `0x4100` | `AP2_PPCL_ADD_LINE` | add/create one program line | **write (state-changing)** | [W] |
| `0x4101` | `AP2_PPCL_EDIT_LINE` | edit one line | write | [S] |
| `0x4103` | `AP2_PPCL_REMOVE_LINES` | remove a line range | **destructive** | [S] |
| `0x4104` | `AP2_PPCL_ENABLE_LINES` | enable a line range | write | [S] |
| `0x4105` | `AP2_PPCL_DISABLE_LINES` | disable a line range | write | **[W]** |
| `0x4106` | `AP2_PPCL_CLEAR_TRACE` | clear all trace bits for a program | state-changing | [S] |
| `0x4107` | `AP2_PPCL_PROGRAM_LOG` | report program execution log | read | **[W]** |
| `0x4108` | `AP2_PPCL_SEARCH_NAME_TYPE` | find lines by statement type / referenced name | read | [S] |
| `0x4109` | `AP2_PPCL_QUERY_PROGRAM` | query program metadata/state | read | [S] |
| `0x410A` | `AP2_PPCL_PROGRAM_DISPLAY` | display (decompiled) program source | read | [S] |
| `0x410B` | `AP2_PPCL_MODIFY_LINE` | modify one line in place | write | [S] |
| `0x410C` | `AP2_PPCL_COPY_LINE` | copy a line | write | [S] |

**A line range is at most sixteen lines, and that is a different sixteen from
§14.4's.** The language-level statements these opcodes serve — `ACT` to enable
and `DEACT`/`DISABL` to disable — each act on *"from 1 to 16 lines of PPCL
code"*, so `0x4104` and `0x4105` carry a bounded range rather than an arbitrary
one, and enabling a 40-line block takes three calls. Do not conflate this with
the 16-slot **parameter** array of a single command statement (§14.4): one
bounds how many lines an operation may touch, the other how many operands a line
may carry. Both are 16 and they are unrelated. [D]
| `0x410E` | `AP2_PPCL_LOOK_LINES` | look at a line range (read interior) | read | [S] |
| `0x412A` | `AP2_PPCL_PROGRAM_DISPLAY_UNRESOLVED` | display only the unresolved lines | read | [S] |
| `0x410F`–`0x4111` | `AP2_PPCL_PDL_RESET/INIT/DISPLAY` | peak-demand-limiting control/init/display | mixed | [S] |

> **Note on opcode polymorphism.** Several opcodes select different operations by body shape, scope tag, and direction, so a robust dispatcher keys on `(opcode, body shape)` together, never on the opcode alone. The canonical example is the `00 FF` read trailer versus the `00 00` command trailer carried on the same addressing grammar (see §6.4). [W]

#### 14.5.1 Enumerating a program — `0x0985` (`AP2_UPL_ALL_PPCL`)

Request carries the system scope, the target program name, and a cursor; response carries program metadata, the source-text lines as TLVs, and a 1-byte has-more flag (`0x01` more / `0x00` last). The client re-issues with the advanced cursor until has-more is `0x00`, yielding the full line-numbered source. [W]

```
09 85  00 00  01 00 04 "SYST"  01 00 <len> "<program-name>"  00 <cursor>  00 00 00
```

The response body is a sequence of `PPCL_data` records (one per line). The `PPCL_data` structure, field order: [S]

| Field | Type | Meaning | Tag |
|---|---|---|---|
| name_space | Name_space | program name-space container | [S] |
| name | TEXT_ (TLV) | program name | [S] |
| line_status | TEXT_ (TLV) | rendered line-status text | [S] |
| line_text | TEXT_ (TLV) | the source text of the line | [S] |
| line_number | UNSIGNED16 | line number (1–32767) | [S] |
| line_enabled | BOOLEAN | enabled flag | [S] |
| line_traced | BOOLEAN | trace bit | [S] |
| line_unresolved | BOOLEAN | references an undefined point | [S] |
| line_failed | BOOLEAN | execution-failed flag | [S] |
| line_looped | BOOLEAN | loop-detected flag | [S] |

#### 14.5.2 Writing a program — `0x4100` (`AP2_PPCL_ADD_LINE`)

Body: the program-name TLV, a positional separator, the line-number/line-text payload, the line's encoded attributes, and the trailing 12-byte SYST footer. [W]

```
01 00 <len> "<program-name>"  00 00 00  01 00 <len> "<line-text>"  00 0A 00 00 00 00  01 00 04 "SYST"  23 3F FF FF FF
```

The request body decodes to `PPCL_data` + a `User_profile` block (`user_logon` TEXT_, `point_priority`, `access_class`); the `User_profile` carries the priority at which the writing user is authorized to act. A successful line write is acknowledged with an empty success (dir `0x01`). [S/W]

**Range operations** (`0x4103` remove, `0x4104` enable, `0x4105` disable, `0x4106` clear-trace) carry a `PPCL_range` body: [S]

| Field | Type | Tag |
|---|---|---|
| name_space | Name_space | [S] |
| name | TEXT_ (TLV) | [S] |
| first_line | UNSIGNED16 | [S] |
| last_line | UNSIGNED16 | [S] |

`AP2_Ppcl_Search_Name_Type_Request` carries a `Statement_types : PPCL_statement_type[]` array (the WHOP* token values of §14.3), so a client can ask "give me every line whose statement type is one of {…}". [S]

#### 14.5.3 Safe program-transfer procedure (destructive-operation guidance)

`0x4100`/`0x4101`/`0x410B`/`0x410C` (writes), `0x4103` (remove), and `0x030A`/`0x4106` (save/clear-trace) **modify panel runtime state and can restart program execution.** A read-only client MUST NOT emit them. A client that does write programs MUST: [I]

1. Snapshot the existing program first (walk `0x0985`).
2. Transfer all lines in the **disabled** state, then enable them once the full program is resident (a panel may begin executing a partially transferred program — `line_enabled = false` prevents premature execution).
3. Persist with `0x030A` (`AP2_PPCL_SAVE`) only after the complete program is present and validated.

A line that references a point not yet in the DB is retained as `line_unresolved` and does not execute correctly until the point exists. [D]

---

## 15. Scheduling (TOD / EQS)

P2 carries two related scheduling subsystems: **TOD** (time-of-day point/command scheduling, the simpler per-point schedule) and **EQS** (equipment scheduling — zone-based occupancy command tables with start-stop time optimization). Both are edited and uploaded over P2 in the `0x09xx`/`0x45xx`/`0x50xx` opcode blocks, and both interact with PPCL (§14): a PPCL program reads/sets schedule state with the `TOD`/`TODMOD`/`TODSET`/`SSTO`/`HOLIDAY` statements. [D/S]

### 15.1 Time-of-day mode bitmask

A point's (or zone's) **time-of-day mode** is an **additive bitmask** of day-class bits, combined by the PPCL `TODMOD` statement. The standard bit weights are powers of two: [D]

| Bit weight | Day class | Tag |
|---|---|---|
| 1 | (schedule class 1) | [D] |
| 2 | (schedule class 2) | [D] |
| 4 | (schedule class 3) | [D] |
| 8 | (schedule class 4) | [D] |
| 16 | HOLIDA (holiday) | [D] |

Mode semantics: **DAY = occupied**, **NIGHT = the complement** (unoccupied). `TODSET` re-evaluates the schedule after a power failure and carries a **recommand flag** controlling whether the schedule re-issues its current command on restart. [D]

The schedule day index that selects which day-class applies is the `Schedule_days` enum: `Sunday`=0 … `Saturday`=6, then `Replacement1`–`Replacement7` (values 7–13) for special/replacement (e.g. holiday-override) days. [S]

### 15.2 TOD opcodes (per-point time-of-day scheduling)

| Opcode | AP2 name | Operation | Tag |
|---|---|---|---|
| `0x4500` | `AP2_TOD_POINT_ADD` | add a TOD-scheduled point | [S] |
| `0x4501` | `AP2_TOD_POINT_REMOVE` | remove | [S] |
| `0x4502` / `0x4503` | `AP2_TOD_POINT_ENABLE` / `DISABLE` | enable/disable schedule | [S] |
| `0x450E` | `AP2_TOD_POINT_DISPLAY` | display the scheduled point | [S] |
| `0x4504` | `AP2_TOD_CMD_ADD` | add a TOD command (a timed action) | [S] |
| `0x4505` / `0x4506` | `AP2_TOD_CMD_REMOVE` / `DISABLE` | remove/disable | [S] |
| `0x450F` | `AP2_TOD_CMD_DISPLAY` | display the command | [S] |
| `0x09B0`–`0x09B3` | `AP2_{DBCHANGE,UPL_DEL,UPL_ADDED,UPL_ALL}_TOD_POINT` | replication / upload of TOD point definitions | [S] |
| `0x09B4`–`0x09B7` | `AP2_{DBCHANGE,UPL_DEL,UPL_ADDED,UPL_ALL}_TOD_CMD` | replication / upload of TOD commands | [S] |

The supervisor↔panel TOD-define path (`AP2_UC_Define_TOD_Request`, `AP2_UC_Define_TOD_Ovrd_Request`) is structured as `name : TEXT_`, `p1_command : UNSIGNED8`, then an opaque `tx_buffer : Data_byte[]` (length-prefixed by `nrOftx_buffer : UNSIGNED16`); the upload form (`AP2_UC_Upload_TOD_Response`) returns `nrOfrx_bytes : UNSIGNED16` + `rx_bytes : Rx_byte[]`. The `tx_buffer`/`rx_bytes` payload is a P1/FLN-device command stream tunneled through the panel — its interior byte layout is FLN-device-specific and is **not** decoded at the P2 layer. [S] [OPEN — interior of the TOD `tx_buffer`/`rx_bytes` blobs is opaque at the P2 layer; needs an FLN-scoped capture to map.]

### 15.3 EQS — equipment scheduling

EQS schedules a **zone** (a group of points) into occupancy **modes**, each mode driving a **command table** of point setpoints, with optional **start-stop time optimization (SSTO)** to pre-start equipment so the zone reaches setpoint by the occupied time. [D] All three record types are decoded from captured responses in §10.8 — the zone, the per-mode command table, and the mode schedule with its effective dates and start time — and they compose with the alarm model of §13: the schedule drives a mode point, and the mode point selects which alarm levels are in force. [W]

**EQS opcode families:**

| Block | Opcodes | Purpose | Tag |
|---|---|---|---|
| Zone edit | `0x5000`–`0x5005` (`AP2_EQS_ZONE_ADD/REMOVE/MODIFY/LOOK/ENABLE/DISABLE`) | create/modify/query an EQS zone | [W] for `0x5000`/`0x5001`, else [S] |
| Command-table edit | `0x5018`–`0x501B` (`AP2_EQS_CMD_TABLE_ENTRY_ADD/MODIFY/REMOVE/LOOK`) | per-mode command entries | [S] |
| Mode edit | `0x5020`–`0x5025` (`AP2_EQS_MODE_ENTRY_ADD/MODIFY/REMOVE/LOOK/ENABLE/DISABLE`) | occupancy-mode entries | [S] |
| Override edit | `0x5028`–`0x502B` (`AP2_EQS_OVERRIDE_ADD/MODIFY/REMOVE/LOOK`) | timed/manual overrides | [S] |
| Display / log | `0x5035`–`0x5039` (`AP2_EQS_DISPLAY_ZONE/MODE_ENTRY/CMD_TABLE`, `ZONE_LOG`, `DISPLAY_OVERRIDES`) | read-only reports | [S] |
| SSTO setup | `0x503A`–`0x503D` (`AP2_EQS_SSTO_SETUP_GENERAL/START/STOP/NIGHT`) | configure optimization | **[W], all four** |
| SSTO look/control | `0x503E`–`0x5044` (`AP2_EQS_SSTO_LOOK_*`, `SSTO_RESET/ENABLE/DISABLE`) | query/control optimization | [S] |
| SSTO display | `0x5050`–`0x5053` (`AP2_EQS_SSTO_DISPLAY_GENERAL/START/STOP/NIGHT`) | display optimization state | [S] |
| Member log | `0x5054` (`AP2_EQS_MEMBER_LOG`) | per-member status log | [S] |
| Replication / upload | `0x0957`–`0x0959`, `0x0967`–`0x0969`, `0x0977`–`0x0979`, `0x0987`–`0x0989` (`AP2_{DBCHANGE,UPL_DEL,UPL_ADDED,UPL_ALL}_EQS_{ZONE,CMD_TABLE,MODE_SCHED}`); `0x09A4`–`0x09A7` (EQS_OVERRIDE); `0x095C`–`0x095F`, `0x097C`–`0x097F`, `0x098C`–`0x098F` (SSTO_GENERAL/START/STOP/NIGHT) | DB-change + upload of all EQS sub-objects | **[W]** for `0x0957`, `0x095C`–`0x095F`, `0x0967`, `0x0977`, `0x097C`–`0x097F`, `0x0988`; else [S] |

**EQS zone definition** (`AP2_EQS_Zone_Add_Request` = `User_profile` + `Eqs_zone_definition`): [S]

| Field | Type | Meaning | Tag |
|---|---|---|---|
| nrOfnames + names[] | UNSIGNED16 + Team_response[] | the member points of the zone | [S] |
| eqs_zone_data | Eqs_zone_data | the zone's scheduling attributes (below) | [S] |
| nrOfrecharacterization_values + recharacterization_values[] | UNSIGNED16 + Recharacterization_value[] | per-member command overrides | [S] |

`Eqs_zone_data` fields: `zone_enabled` (BOOLEAN), `description` (TEXT_), `access_class`, `min_off_time` (UNSIGNED16 — minimum off time, equipment-protection), `recmd_after_warmstart` (BOOLEAN — re-command after warmstart, mirrors TODSET recommand), `warmstart_delay` (UNSIGNED16), `state_text_table`, `default_mode` (SHORT_), `english_units` (BOOLEAN), `optimization_osv` (BOOLEAN — SSTO enable). [S]

`Eqs_cmd_table_data` (one command-table entry): `mode` (SHORT_) + `command_value` (FLOAT_, big-endian f32 on the wire per §8.3.2) + `command_offset` (UNSIGNED16). A command-table *sequence* (`Eqs_cmd_table_sequence`) is `name_team` + `name_name` + `nrOfcmd_table_entries` (UNSIGNED16) + the entry array. [S]

`Recharacterization_value` (per-member override): `member_number` (UNSIGNED16) + `logical_value` (FLOAT_) + `point_priority` (Point_priority — the §8 ladder) + `control_status`. So an EQS zone commands each member at an explicit priority, exactly like a PPCL `@`-command. [S]

### 15.3.1 SSTO — start-stop time optimization

SSTO is referenced both by PPCL (`SSTO`, `SSTOCOEF` statements, §14.3) and by the EQS SSTO opcode family above. SSTO computes an optimized equipment start time (and night-setback strategy) from learned coefficients so the zone reaches occupied setpoint by the scheduled occupancy time. The `SSTO_GENERAL/START/STOP/NIGHT` four-way split (visible across the setup/look/display opcode rows) corresponds to the four configuration blocks: general parameters, optimized-start, optimized-stop, and night-cycle. [D/S]

**SSTO is adaptive, and that is why it has stored coefficients at all.** The
vendor describes it as starting heating or cooling as late as possible before
occupancy and stopping it as early as possible before the zone empties — and,
crucially, that when it starts or stops too early or too late **the logic
remembers the error and adjusts**. So the coefficient blocks a client reads or
writes are not static tuning constants: they are the panel's learned state, and
overwriting them discards what the zone has learned about its own thermal
response. A tool that round-trips an SSTO configuration must preserve them
byte-for-byte rather than re-deriving them from the setpoints. [D]

**The zone model those blocks hang off.** An EQS **zone** is a schedulable
building resource — typically a room or a floor — and is composed of points plus
three things: its **operating modes** (the mode states the zone runs in), a
**command table** (simple on/off control of points scheduled together, optional
when defining a zone), and the **optimization parameters** above. An **event** is
an activity — a meeting, a weekday schedule, a cleaning shift — that names the
zones it affects and the operating mode each must be in. A **schedule** is the
calendar entry saying when a zone or event starts and stops. That is the
hierarchy the `0x50xx` opcode families of §15.3 operate on, and it explains why
zone, command-table, mode-entry and override each get their own
add/modify/remove/look family. [D]

#### 15.3.2 An EQS zone being created, on the wire

A capture taken simultaneously from both a panel and the supervisor contains a
complete EQS zone-and-SSTO configuration transaction, which pins the opcode
taxonomy above to observed behaviour. Read in timestamp order (supervisor
`SUP`, panel `PNL`, times in seconds from the start of the exchange): [W]

```
200.49  SUP -> PNL   EQS_ZONE_ADD  (0x5000)          User_profile(SYST) + zone name
200.51  PNL -> SUP   DBCHANGE_EQS_ZONE (0x0957)      body EMPTY        -> SUP answers OK
200.51  SUP -> PNL   UPL_DEL_EQS_ZONE  (0x0967)      selector '*', resume ""
200.52  PNL -> SUP   DBCHANGE_SSTO_GENERAL (0x095C)  body EMPTY        -> SUP answers OK
   ...                 START / STOP / NIGHT likewise, all empty
200.64  SUP -> PNL   UPL_ADDED_EQS_ZONE (0x0977)     resume ""         -> OK, record returned
200.81  SUP -> PNL   UPL_ADDED_EQS_ZONE (0x0977)     resume <last name> -> ERR 0x0003
200.82  SUP -> PNL   UPL_ADDED_SSTO_GENERAL (0x097C) resume ""         -> OK, record returned
   ...                 START / STOP / NIGHT likewise
202.67  SUP -> PNL   EQS_SSTO_SETUP_GENERAL (0x503A) -> OK, zone name echoed
202.69  SUP -> PNL   EQS_SSTO_SETUP_START/STOP/NIGHT (0x503B/C/D) -> OK each
```

Three things an implementer needs, each counted rather than read off one
exchange:

**1. The four-way `{GENERAL, START, STOP, NIGHT}` split is real on the wire, and
it repeats across all three tiers** — setup (`0x503A`–`0x503D`), database-change
(`0x095C`–`0x095F`), and upload-added (`0x097C`–`0x097F`). This is the operand
model of §9.1.1 in its clearest form: one operation with a four-valued
record-type parameter folded into the opcode, three times over. [W]

**2. A `DBCHANGE_*` notification carries no data.** In this exchange, **20 of
20** `DBCHANGE_*` frames have a **zero-length body** and travel **panel →
supervisor**, each answered with a bare success. The panel does not push what
changed; it pushes *that* its `<section>` changed, and the supervisor then reads
the content back with the matching `UPL_ADDED_<section>`. This is not particular
to equipment scheduling — it holds for **every** `DBCHANGE_*` opcode in the
corpus, across ten database sections (§16.1.2). This is why the `DBCHANGE`/`UPL_ADDED` opcode pairs exist
at all, and it means a client that wants change notification must implement a
**server** role for these opcodes, not merely a reader. [W]

**3. Enumeration terminates with `0x0003`.** The `UPL_*` body is the paging idiom
of §10.2.3 — a `'*'` wildcard selector and a resume key. Feeding back the name
just returned ends the walk:

| resume key | outcome | observed |
|---|---|---:|
| empty TLV (`01 00 00`) | success, record returned | 20 |
| the name just returned | **error `0x0003`** | 20 |

Twenty for twenty across five distinct opcodes, without exception. Note that
`0x0003` is the *object-not-found* code of §7.2.2 doing double duty as normal
control flow: **a client that treats `0x0003` as a fault will log an error at the
end of every successful enumeration.** [W]

---

## 16. Database, Bulk Transfer, On-Disk (.P2) Format, Application Catalog & Firmware

### 16.1 Bulk database transfer

A panel database is moved across P2 **record-by-record**, not as a single monolithic blob. Each record is its own request that returns either a success (dir `0x01`) or a 2-byte fault/error code (dir `0x05`), corroborating the directory-byte/error model of §7. The transfer is organized into sections gated by firmware revision — a section unsupported by a panel's firmware is skipped or rejected per-record rather than aborting the whole transfer. [D/W]

The transfer surface is the `UPL_*` / `DBCHANGE_*` / `*_DB_GET` / `*_DB_REPLACE` opcode families: the `0x09xx` `UPL_ALL_*`/`UPL_ADDED_*`/`UPL_DEL_*` block enumerates each object class (points, PPCL, TEC, trend, EQS, SSTO, TOD), and per-domain `*_DB_GET`/`*_DB_REPLACE` pairs move whole sub-databases (e.g. `0x0337/0x0338` `USER_ACCT_DB_GET/REPLACE`, `0x0357/0x0358` `ACCESS_GROUPS_DB_*`, `0x0362/0x0363` `EMS_DB_*`, `0x040A/0x040B` `ENUM_TYPE_DB_GET/REPLACE`, the `0x06xx` `CAL_DB_*`/`DST_DB_*` calendar blocks). `0x0950 AP2_DOWNLOAD_ME` initiates a download *to* a panel. [S]

The replication-direction mechanics (notify/pull/changes push) live in the `0x46xx` EBLN family and are specified in §5.3 (replication). [S]

#### 16.1.1 The supervisor uploads the whole database as one ordered sweep

What §16.1 describes as a surface, the supervisor drives as a **single periodic
sweep**. On the busiest connection in the corpus it issues **611 requests in
about 8 seconds** and repeats the whole thing every **90–135 seconds**, always
in the same order: [W]

```
UPL_ALL_PORT -> UPL_ALL_PROGRAM -> TEAM_DESC_UPLOAD -> MEMBER_DESC_UPLOAD
-> REPORT_DESC_UPLOAD -> UPL_ALL_TEC xN -> UPL_ALL_UC -> UPL_ALL_LON
-> UPL_ALL_POINT xN                       <- the bulk of the sweep
-> UPL_ALL_ALARM_SETUP -> UPL_ALL_ALARM_MODE -> UPL_ALL_ALARM_MESSAGE
-> UPL_ALL_TREND xN -> UPL_ALL_PPCL xN
-> UPL_ALL_EQS_ZONE xN -> UPL_ALL_EQS_CMD_TABLE xN
-> UPL_ALL_EQS_MODE_SCHED xN -> UPL_ALL_EQS_OVERRIDE
-> UPL_ALL_SSTO_GENERAL xN -> _START xN -> _STOP xN -> _NIGHT xN
-> UPL_ALL_PARTNER -> HOA_MAP_LOOK -> CAL_DB_GET_OTHER
```

Each `xN` is the cursor pagination of §6.7 — the opcode is re-issued carrying
the previous record's name until the panel signals end-of-list — which is why
the point and TEC sections dominate the frame count.

**Do not read a per-opcode cadence off this.** Every `UPL_ALL_*` opcode shows
the *same* inter-burst interval (90 s for those at the head of the sweep, 102 s
for those after the long `UPL_ALL_POINT` run) because they are not independently
scheduled; those numbers are their positions in one sweep. The schedulable unit
is the sweep.

For an implementer building a panel: it must answer a ~600-request burst within
seconds **while** continuing to meet its 10-second `EPing` obligation on every
peer connection (§5.0). The two run concurrently on separate connections. [W]

#### 16.1.2 `DBCHANGE_*` is a data-less notification, and the reader pulls

The `DBCHANGE_*` family is not a change *feed*. It carries no payload at all.

Across the corpus, **ten distinct `DBCHANGE_*` opcodes are wire-observed, 93
requests in total, and every single one has a zero-length body**. Every one is
answered with a success. Every one rides the **second channel** (`0x2E`, and
`0x2F` in the modern dialect) — never the data dialect. [W]

| Opcode | Section | Requests | Body |
|---|---|---:|---|
| `0x0951` | `POINT` | 19 | 0 B |
| `0x0954` | `TREND` | 14 | 0 B |
| `0x0955` | `PPCL` | 13 | 0 B |
| `0x0956` | `CONTROLLER` | 11 | 0 B |
| `0x0957` | `EQS_ZONE` | 4 | 0 B |
| `0x0959` | `EQS_MODE_SCHED` | 16 | 0 B |
| `0x095C`–`0x095F` | `SSTO_{GENERAL,START,STOP,NIGHT}` | 4 each | 0 B |

So the notification's entire content is **its own opcode**: the opcode names
which database section changed, and there is nothing else to parse. The node
holding the changed data then waits, and the interested party **pulls** the new
records with the matching `UPL_ADDED_<section>` / `UPL_DEL_<section>` opcode,
using the selector-and-resume-key paging idiom of §10.2.3.

Two consequences for an implementer, neither obvious from the opcode names:

- **A client that wants change notification must implement a server role.** The
  `DBCHANGE_*` frames arrive *inbound*, as requests, and must be answered with a
  success. A read-only client that only ever initiates will never see them.
- **Do not wait for data in the notification.** There is none, and the pull is a
  separate exchange against a different opcode. §15.3.2 traces a complete cycle —
  command, notification, pull, end-of-enumeration — for an equipment-schedule
  change.

This is what §6.2 means in calling the second channel the "announce + DB-sync"
band: the announce carries the fact, the data channel carries the data. [W]

#### 16.1.3 `UPL_ALL_PORT` (0x099F) — the panel's port table, and where `Baud_rate` was measured

The sweep's first operation is also one of its most completely decoded. `0x099F`
returns one record per port, and **60 of 60 bodies in the corpus consume
exactly**: [W]

```
Port_log      port_number : Port_number            u8
              port_status : Port_status
Port_status   descriptor              TEXT_        (empty in all 60)
              baud_rate               Baud_rate    u16 BE      <- TWO bytes
              highlight_enabled       BOOLEAN_
              autobye_enabled         BOOLEAN_
              alarm_printing_enabled  BOOLEAN_
              report_printing_enabled BOOLEAN_
              port_type               Port_type    u8
              my_site_id              TEXT_
              AdvancedPortString      TEXT_
              AdvancedSystemString    TEXT_
              DiagPortString          TEXT_
              DiagSystemString        TEXT_
              PortName                TEXT_
```

The request is three bare bytes — `begin_port_number`, `end_port_number`,
`last_port_number`, all `UNSIGNED8` — which is a range plus the cursor of §6.7.
That the request types a port number as `UNSIGNED8` is the independent
corroboration that `Port_number` is one byte in the response too. [S]

**`Baud_rate` is two bytes, and this body is what settles it.** At width 1 not a
single body consumes exactly; at width 2 all 60 do. Better than that, the record
carries its own oracle: `DiagPortString` is an ASCII settings string of the form
`;bd=9600;pa=0;mk=0.`, and **the decoded `Baud_rate` enum equals the `bd=` value
in all 60 records** — `6` decoding to `baud9600` against a literal `9600` in the
same message. `pa=` likewise tracks the record's own port number. A width that
is right about the byte count *and* right about the number is not a coincidence.
[W] The consequence for the enum-width shortcut is in §10.9.

**The ports a panel exposes.** The five records repeat identically across the
twelve sweeps captured: [W]

| Port | `PortName` |
|---:|---|
| 0 | USB Modem port |
| 1 | HMI port |
| 2 | Telnet port |
| 3 | USB Tool port |
| 4 | USB Printer port |

**What this body does *not* establish, stated plainly.** Every one of the 60
records carries `baud_rate` 9600, `port_type` 0, all four booleans clear, and an
empty `descriptor`. So the **widths** are pinned by exact consumption but the
**value spaces** are not exercised at all: `Port_type` has a second member that
never appears, and no port on this panel runs at any other rate. A decoder built
from this will walk any port record correctly and has been shown nothing about
what the fields mean when they are non-zero. **[OPEN]** [W]

**Two of the four booleans are not fields at all.** The panel's port encoder
writes `highlight_enabled` and `autobye_enabled` as **literal zero** — not read
from the port record, written as a constant — while `alarm_printing_enabled` and
`report_printing_enabled` are fetched from the object. So those two reading zero
in all 60 captures is not a sample of a quiet site; **this firmware cannot emit
anything else**. A decoder should carry them as reserved-zero rather than as
state, and a virtual panel should write zero. [F]

One thing worth noting for §17: this is an **unauthenticated read that
enumerates a panel's console and management ports by name** — the Telnet port
among them — and returns the site identifier in `my_site_id` and again inside
`DiagSystemString`. It is a small disclosure on its own and a useful one to an
attacker enumerating a plant. [W]

### 16.2 On-disk (.P2) panel-database format

A panel database serialized to disk (file extension `.P2`, e.g. `P2_Archive` snapshots) uses **TLV record framing persisted to a file** — broadly the same style of encoding the panel exchanges on the wire, written to disk. This subsection is observed from **panel database exports and controller backups** (not from wire traffic) and is included only to help an operator read their own database exports; treat it as indicative rather than exhaustive. [I]

Record framing (observed across **36 distinct panel databases** — Insight `.P2` archives plus Desigo CC device backups, spanning MBC-10 / SCU / PXCC / PXCM platforms and 2018–2025 — **31,823 records**): [W]

> The corpus is deduplicated on **decoded content**, not on filename and size. Insight keeps a timestamped copy of every `.P2` under `P2_Archive/`, and a Desigo CC device backup ships each database twice — once raw and once compressed. Name-and-size dedup counted 16 databases twice; an earlier revision of this document reported 39,456 records on that basis and the figure is withdrawn.

| Element | Value | Tag |
|---|---|---|
| Record delimiter | **SYN `0x16`** at the start of each record — and at byte 0 of the file | [W] |
| Field encoding | **ASCII-hex text** — the record is a hex *string*; the structures below are what it decodes to, not what the file contains | [W] |
| Record terminator | **CRLF in Insight `.P2` exports; CR only in Desigo CC device backups.** A reader MUST split on the leading SYN, not on a line terminator — assuming CRLF silently yields **zero** records from a device backup rather than an error | [W] |
| Record-type byte | at offset 6 within the record. Only two values occur: **`0x02`** point record (13,365) and **`0x41`** PPCL record (9,106) | [W] |
| Format byte | `0x02` = legacy generation / `0x03` = BACnet-era generation | [I] |

**Withdrawn — the "distinct numbering" note.** An earlier revision of this document described a `.P2` "subtype byte" numbered `1`=LDI, `2`=LAI, `4`=analog, `6`=LDO, `0x15`=enum, and warned that it MUST NOT be cross-mapped to the §11.2 `Point_type` codes. Both claims were tagged as inference and **neither survives testing.** 12,670 `.P2` point records whose point name resolves to a declared point type were scanned at every byte offset — absolute, relative to the record end, and relative to the TLV block — and **no byte position discriminates point type at all**: every candidate that reached full purity did so by being constant across all types. There is no such subtype byte in the container, and therefore no rival numbering to warn about. Where a point type *is* recoverable from vendor-produced files, it carries **the same codes as §11.2** (1=LDI, 2=LDO, 3=LAI, 4=LAO, 6=L2SL, 11=LPACI, 21=LENUM), verified as a bijection over 3,123 points — see §16.2.1. [W] The format byte (`0x02`/`0x03`) is the on-disk reflection of the firmware-generation split described in §16.5, and that part stands. [I] **Record layout (per-record decode pass, 39,456 records across 38 panel databases and 7 Desigo CC device backups).** There are **two** record layouts, distinguished by where the scope preamble `01 00 04 "SYST" 23 3f ff ff ff` falls. That preamble is present in **97.9%** of records and is the same scope selector the wire uses (§8). [W]

**Hex-decode first — the layouts below are post-decode.** This is the single
easiest way to misread a `.P2`, because every offset in this subsection is an
offset into the *decoded* record and none of them is an offset into the file. A
record is a run of ASCII hex digits: unhexlify it, then apply the layout. Across
the 37 Insight `.P2` databases here — 9,092 records deduplicated on content —
**every record decodes, with zero failures**, each file begins with the SYN at
byte 0, and records are CRLF-terminated throughout (the CR-only form is the
Desigo CC device-backup variant noted above). The check that settles it: the
`01 00 04 "SYST"` preamble appears **0 times in the raw file bytes and 9,056
times after decoding**. A reader that scans the file for the preamble, or reads
`u16 length` at byte 0 of a record, finds nothing and concludes the format is
undocumented. [W]

```
Layout A   preamble at offset 8      4,886 records
  u16 length | u32 class | u16 OPCODE | 01 00 04 "SYST" 23 3f ff ff ff | body

Layout B   preamble at the end      22,471 records
  u16 length | u32 class | u8 type | u8[3] | TLVs ... | 01 00 04 "SYST" 23 3f ff ff ff
```

Only Layout A carries a u16 opcode at a fixed offset; in Layout B the two bytes preceding the preamble are body content, and reading them as an opcode manufactures spurious entries. [W]

Layout B has two record types: `0x02` point records (13,365) and **`0x41` PPCL records (9,106)** carrying program name, `Enabled` flag and source line — **3 TLVs in 6,619 records and 4 in 2,487**, so a reader must not assume three. [W]

**Layout A body shape**, common to every opcode examined: [W]

| Offset | Field | Type | Notes |
|---|---|---|---|
| +0 | flags / sub-count | u16 BE | frequently `0x0000` |
| +2 | point name | TLV | e.g. `11` bytes |
| — | descriptor | TLV | human-readable label |
| — | opcode-specific fields | mixed | see below |

Numeric fields in these bodies are **IEEE-754 big-endian `f32`**, consistent with §1.4.2. Verified by decoding both ways and comparing: of 28,160 four-byte groups whose leading byte is a float-shaped exponent, **24.7%** decode big-endian to a finite exact multiple of 0.1, against **18.3%** for the little-endian-shaped groups and a ~10% random-byte baseline. The margin is modest because this container is byte-packed rather than aligned, so a sliding scan mostly lands between fields; within the point-definition records it rises to **62–71%** (`0x503C`, `0x503B`), and the decoded values are engineering quantities — setpoints, limits, timers, deadbands. [W] The companion `ApogeeDevice_*.dat` container is aligned and gives the same test an unambiguous answer in the *opposite* direction; see §16.2.1.

**Enumerated point state.** A point-definition record references its enum type as a **signed** `int16` BE at **`body[-8:-6]`** — eight bytes from the end, followed by a 6-byte trailer, in 116 of 116 records. The identifier is **negative**, indexing an enum library keyed by point type (`LDI`/`LDO`/`LOOAP`/… in the −1…−21 band, BACnet variants near −107, application enums from −1000). A decoder that searches for positive identifiers finds nothing. [W]

Which individual `f32` slot is which named attribute is **not** determined *for this container* — the ordering is consistent within an opcode but unlabelled. It **is** determined for the aligned `ApogeeDevice_*.dat` point struct, where the same points appear under a named point model; §16.2.1 gives fourteen labelled fields. A reader wanting attribute names should decode that container.

### 16.2.1 The supervisor-side device-backup container

A supervisor that backs up a panel writes two different containers, and they do
not share a byte order. The first is the `.P2` record encoding of §16.2 — the
wire format on disk. The second is an aligned structure dump, described here.
Both appear in the same backup folder, and a reader that assumes one on the
other gets plausible-looking garbage rather than an error.

**A note on compression.** In a supervisor-produced backup set, each panel
database is commonly present twice: once as the raw `.P2` record stream and
once **zlib-compressed**. The compressed member's stream header is `58 c3` —
`CM` 8 (deflate) with `CINFO` 5, an 8 KB window — which is a perfectly valid
zlib header but not the `78 9c`/`78 da` pair that carve tools and file-type
sniffers look for. A file so encoded reads as 7.97 bits/byte and gets
classified as "compressed or encrypted, unknown". The correct test is the
zlib one: low nibble of the first byte is 8, and `(b0 << 8 | b1) % 31 == 0`.
Inflating recovers the identical `.P2` stream — verified byte-for-byte on four
of six sampled devices; on the other two the two members are snapshots taken at
different times. [W]

#### Container framing

```
'X' %08X record_count
record*:
    %08X len1 | name1        object name    (point / program / device)
    %08X len2 | name2        member name    (usually empty)
    %08X A                   record class
    %08X B                   class-dependent index
    %08X len3 | name3        group name     (one class only)
    %08X plen | <plen bytes> payload
'X'                          terminator
```

Every directory integer is **eight upper-case ASCII hex digits**; payloads are
raw binary. The count in the file header is the record count, so a reader can
validate the whole file before decoding any of it. Across ten sampled panel
backups the records **tile each file exactly** — no resynchronisation, no
trailing slack — and the declared count matches in every case. [W]

#### Record classes

Each class has exactly **one** payload length, which is what makes the framing
safe to rely on. Observed over 4,712 records: [W]

| Class | Payload | Names carried | Content |
|---:|---:|---|---|
| 1 | 9,768 | point | **point definition** |
| 5 | 728 | `PPCL_<panel>` | **PPCL program** |
| 8 | 1,664 | FLN address + member | FLN/TEC device point |
| 13 | 16,520 | point | |
| 14 | 460 | three names | schedule / command link |
| 15, 16 | 452 | point (+ group) | |
| 17–20 | 760 / 520 / 464 / 424 | point | |
| 21 | 18,596 | `R<nnnn>` | TEC application block |
| 24 | 1,008 | — | **FLN trunk configuration** |
| 2, 3 | 1,336 / 1,384 | — | |

Class 24 appears **exactly five times in every file**, with `B` running 1…5 —
the panel's five FLN trunks. Each carries the BLN name at payload `+0x1CF` and
the trunk number as an ASCII digit at `+0x1B0`. [W]

#### Byte order: little-endian, opposite to the wire

Decoding every 4-byte-aligned group both ways over the class-1 payloads:

| interpretation | groups | decode to a finite exact multiple of 0.1 |
|---|---:|---:|
| **little-endian** | 14,600 | **10,619 (72.7%)** |
| big-endian | 10,402 | 2,034 (19.6%) |

Against a ~10% random-byte baseline this is not close. Integers are
little-endian `u32` on the same evidence. This container holds the supervisor's
aligned in-memory representation, **not** the big-endian wire encoding of
§1.4.2 — the only place in the protocol's file ecosystem where that is true.
[W]

#### The point structure

Field positions below were established by matching each point's value from a
named point model against every aligned slot, then repeating the test with each
payload paired against a *different* point's values. A real field collapses
under that control; a field that only matched because its values are common
numbers does not. Verified over 3,123 points. [W]

| Offset | Field | Encoding |
|---:|---|---|
| `+4` | point name | NUL-padded text |
| `+5292`, `+5336` | point name, repeated | NUL-padded text |
| `+5380` | descriptor | NUL-padded text |
| `+5408` | last value | `f32` LE |
| `+5452` | alarm configured | `u32` flag |
| `+5464` / `+5468` | alarm high / low limit | `f32` LE |
| `+5604` | point address within the panel | `u32` LE |
| `+5656` | **point type** (§11.2 codes) | `u32` LE |
| `+5660` | **units *or* enum id** — see below | union |
| `+5692` / `+5696` | slope / intercept | `f32` LE |
| `+5700` | sensor type | `u32` LE |
| `+6436` | inverted, one per subpoint (4) | `u32` flag |

These positions are one supervisor build's layout and should be treated as
such. The **field set** is stable and named in the vendor's own class schema —
`PointType`, `EnumId` (declared `int16`, matching §11.5), `EngrUnits`,
`Alarmable`, `Inverted[4]`, `PhysAddr[4]`, and on the analog subclass `Slope`,
`Intercept`, `SensorType`, `HighAlarmLimit`, `LowAlarmLimit`, `InitialValue`,
`COVLimit`, plus the four signal/device range values. A tool should locate
fields by decoding the structure it finds, not by trusting these constants
across versions. [S]

Two structural facts matter more than the offsets, because they generalise:

**The type code is the §11.2 `Point_type` code.** `+5656` is a bijection with
declared point type over all 3,123 points: 1=LDI, 2=LDO, 3=LAI, 4=LAO, 6=L2SL,
11=LPACI, 21=LENUM. Identical to §11.2 — there is no separate on-disk
numbering. [W]

**`+5660` is a union discriminated by the type code**, with no exceptions:

| Point type | `+5660` holds |
|---|---|
| LAI / LAO / LPACI | engineering-unit string (`DEG F`, `PCT`, `PSI`, `SEC`, `HRS`) |
| LDI / LDO / L2SL / LENUM | **signed `int16`** enum id, negative, per §11.5 |

A decoder must read `+5656` before `+5660`. Read as a string on a digital
point it yields two bytes of binary; read as an enum id on an analog point it
yields the first two characters of the unit text. The enum id here is the same
identifier space as the signed `int16` at `body[-8:-6]` of a `.P2` point record
(§16.2) and the same one the default-enumeration rule of §11.2 negates — three
independent encodings of one namespace. [W]

The point's **full physical address** is stored, not just its point number.
The address is a four-element array — one entry per physical subpoint, matching
the composition of §11.3 — each entry being `{u8 physical point, i8 LAN, u8
drop, u16 point number}`. Only the point-number component is confirmable by the
value-matching method above: LAN and drop are near-constant within one panel, so
a per-point match test has no discriminating power over them (raw 86.3% against
a shuffled 84.0%). The control proves a match is real; **its failure does not
prove a field absent**, and here it does not. [W/S]

#### A trap worth naming

The analog scaling values — signal low/high, device low/high, slope,
intercept, sensor type, the alarm limits — belong to the **analog** point class
only. The digital class does not have them; its only additional member is a
proof delay. [S]

At least one vendor-produced point-model export ignores that split and prints
all four range columns for every point. On a digital point the values it prints
are the descriptor string's own bytes read as little-endian floats: a point
described `MECH COOLING` exports a signal-low of 199957.203125, which is the
ASCII bytes `4D 45 43 48`. Every such row in the sample behaves this way. The
values are not a wrong reading of a real field — they are a reading of a field
that does not exist on that point. [W/S]

The consequence for anyone writing a tool: **those four columns are not
measurements on digital points**, and they are plausible enough to pass a sanity
check. Discriminate on point type, or ignore the columns for non-analog points.
[W]

### 16.3 Application catalog (controller applications)

A controller **application** is a pre-engineered point/control template loaded into a field controller (TEC/MEC/lab/fume-hood and similar). On the network it is identified by a compact key and resolves to an ordered subpoint list: [D/S]

| Element | Form | Tag |
|---|---|---|
| Application number | numeric; the catalog runs **1,043 applications** across nine libraries — see below | [D] |
| Application revision | 4-character revision string | [D] |
| Scope | controller class (TEC / MSTP / LAB / FHOOD, etc.) | [D] |
| Resolution | application# + class → an ordered list of subpoints (each with type, reference INPUT/OUTPUT, slope/intercept/units) | [D/S] |
| Family tag | `Application_family` enum: `eqs`=5, `ppcl_program`=7, `tec_na`=16, `uc`=17, `tcu`=18, `lon`=19, `p1_pxc`=20, `bacnet_mstp`=21, `tec_eu`=257, plus `pdl_area`/`pdl_load_group`/`decision_table`/`loop` (1–4) | [S] |

**The catalog, counted.** Vendor documentation enumerates **1,043
applications** in **nine libraries**, numbered from 600 to 8102: [D]

| Library | Applications | Number range |
|---|---:|---|
| `APOGEE_INT` | 440 | 2700–6095 |
| `APOGEE_CUSTOM` | 179 | 604–8102 |
| `APOGEE_PTEC` | 108 | 6511–6727 |
| `APOGEE_LABS` | 107 | 600–6792 |
| `APOGEE_P1` | 76 | 2020–2899 |
| `APOGEE_BTEC` | 50 | 2510–2599 |
| `APOGEE_ATEC` | 38 | 2473–6637 |
| `APOGEE_LON` | 23 | 8020–8089 |
| `APOGEE_P1SEC` | 22 | 2120–2192 |

Two properties of that numbering matter to an implementer. **Numbers are
effectively unique across the whole catalog** — 1,042 distinct values across
1,043 rows, the single repeat being two similarly-named variants inside one
library, which reads as a documentation artifact rather than a real collision.
But **the library ranges interleave rather than partition**: `APOGEE_CUSTOM`
spans 604–8102 and `APOGEE_LABS` 600–6792, so several libraries occupy the same
numeric territory. A decoder can therefore resolve an application *by number*,
and must **not** try to infer its library or device class *from* the number.

A **live device advertises its application number at subpoint 2** (subpoint 0 = bundled controller point, subpoint 1 = controller address, subpoint 2 = application). A client reading subpoint 2 learns which application a controller runs, and therefore which subpoint-list template applies (cross-ref §9 — FLN/sub-device browse, and §11 — point model). [D]

The **master application/point-team library** is the set of point-team descriptor files — one ASCII/XML descriptor per controller family in the Insight/WCIS `.ptd` library, or equivalently the `Tecpnts.dbf` + `TECAppl.dbf` tables in DataMate. Both encode the same logical model: a `TEAM_DESCRIPTION` / `POINT_TEAM` with `ANALOG_MEMBER`/`DIGITAL_MEMBER`/`ENUM_MEMBER` entries keyed by `SUBPOINT_NUMBER` (the FLN subpoint index / on-wire address), each carrying type (LAI/LAO/LDI/LDO/LENUM), reference (INPUT/OUTPUT), and SI+English slope/intercept/units. The application catalog is therefore the bridge between an advertised application number and the concrete subpoint semantics a client must apply to decode that controller's points. [D/S]

The FLN device classes an application can target are the `FLN_Device_Type` enum: `DPU`=0, `MPU`=1, `TCU`=2, `TEC`=3, `UC`=4, `PXM`=5, `FSCS`=6, `GATEWAY`=7, `FLOAT_GATEWAY`=8, `P1BIM`=9 (P1 Bus Interface Module), `GLOBAL_IO`=10. [S]

#### 16.3.1 Foreign devices get the same point model, and a uniform diagnostics team

The application catalog is not limited to APOGEE field controllers. A panel
reaching a device over a gateway — Modbus serial and Modbus TCP, BACnet, KNX,
an Allen-Bradley Ethernet link, a chiller or rooftop vendor's own bus, a fire
system, a guest-room controller — represents that device with **the same
point-team model**: an application number resolving to an ordered member list,
each member typed and scaled exactly as §11 describes. Roughly seventeen device
families are carried this way. [S]

What matters to an implementer is that they are not each modelled differently.
**Sixteen of the seventeen families carry a common diagnostics team**, so a
client that understands it can report on a gateway-attached device of any
downstream protocol without knowing that protocol. The shared members group as:

| Group | Members |
|---|---|
| Identity | address, application number, licence, ready |
| Traffic counters | transmissions, responses, no-responses, good packets, bad packets, unknown packets, NAK count, bad-transmit count, bad-sequence count, overrun count |
| Link errors | framing errors, parity errors, hardware errors, break received |
| Polling | poll frequency, poll delay, poll-suppress minutes, start delay, timeout, response interval, max retries |
| Command queue | commands pending, command-queue maximum |
| Failure behaviour | comm-fail, point-fail mode, fail-on-comm-fail-off, disable-command-fail-point-off |
| Selection filters | a `SEL *` family selecting which points a diagnostic view reports on — out of service, failed, in alarm, dropped, logged, COV, commanded, command-COV, in use, FLN, character-mode |
| Controls | diagnostic control, data control, point-update control, print control |
| Units | seconds, minutes, ticks |

Two consequences worth stating. First, the counter set is **serial-link
shaped** — framing errors, parity errors, break-received, NAK counts — and it
is present even on families whose downstream transport is Ethernet, so those
members read as zero rather than as absent. Second, `TIMEOUT`,
`RESPONSE INTTICKS` and the poll timers are per-device **configuration**
exposed as points, which means gateway tuning is reachable through the ordinary
point-command path rather than through any special operation. [S]

### 16.4 Reading a controller application from a live panel

The upload opcodes for the application/team model: `0x0986 AP2_UPL_ALL_TEC` (upload all TEC application data), `0x400F AP2_TEAM_DESC_UPLOAD` (upload a point-team descriptor), `0x4015/0x4016 AP2_TEAM_DESC_DB_CHANGE / TEAM_MEMBER_DB_CHANGE` (team DB-change replication). Walking `0x0986` for a panel returns its loaded controller applications, which a client resolves against the master `.ptd`/DBF library by application number + revision. [S]

### 16.4.1 `AP2_SERVICES_RENDERED` — the capability document

Immediately after the `0x010C` identity read sit two further operations:
`0x010D` `AP2_SERVICES_RENDERED` and `0x010E`
`AP2_SERVICES_RENDERED_CHANGED`. [S] Neither appears in any capture in the
corpus, so their bodies were unknown; the response is however an **XML
document** whose template is fixed, and its shape is therefore known without a
capture: [S]

```xml
<?xml version="1.0" encoding="ASCII" standalone="yes"?>
<ServicesRendered>
  <Panel Name="...">
    <PanelBasics>
      <ID_STRING>...</ID_STRING>
      <RevString>... nnnn - ...</RevString>
      <LinkDate>...</LinkDate>
      <HardwareType>...</HardwareType>
      <BuildNumber>...</BuildNumber>
      <Platform>...</Platform>
      <VersionNumber>...</VersionNumber>
    </PanelBasics>
    <Services>
      <OperatorActivityLogging Enabled="..." />
      <AlarmBuffer Enabled="..." />
      <FLNTopology />
    </Services>
  </Panel>
</ServicesRendered>
```

`<Services>` is a variable element list, emitted through a generic
`<name attr="value" />` / `<name>value</name>` writer, so a client must parse it
as an open set rather than expect exactly the three elements above. A panel
that does not implement the operation answers with a refusal naming itself
rather than an empty document.

Two things follow for an implementer. First, this is a **richer identity read
than `0x010C`** — it adds hardware type, platform, build number and a
services list, and it is self-describing. Second, `0x010E` implies a **change
notification**: the capability set is expected to vary at runtime, not only
between models.

### 16.5 Firmware and revision identity

A panel reports its identity in the `AP2_CABINET_DISPLAY` response (opcode `0x010C`, `AP2_Cabinet_Display_Response`). The leading fields: [W/S]

| Field | Type | Meaning | Tag |
|---|---|---|---|
| revstring | TEXT_ (TLV) | firmware-revision string (wire-observed e.g. `PME1252 / PXME V2.8.10 APOGEE / Oct 28 2013`) | [W] |
| firmwaretype | TEXT_ (TLV) | hardware/platform string (separate from the firmware revision) | [S] |
| linktime | TEXT_ (TLV) | firmware build/link timestamp | [S] |
| firmware_checksum | UNSIGNED16 | firmware image checksum | [S] |
| config_byte1..31 | UNSIGNED8 / BOOLEAN | per-cabinet configuration flags (alarm_config, report_config, …) | [S] |
| config_checksum | UNSIGNED16 | config-block checksum | [S] |
| battery_state | UNSIGNED16 | battery status | [S] |
| node_name / site_name / bln_name | TEXT_ (TLV) | the cabinet's identity (cross-ref §3.4/§6) | [W/S] |
| ip_addr_settings, MII/MAC, BACnet settings | (sub-structs) | network configuration | [S] |

The panel reports a **firmware-revision string and a separate hardware string**; together they form the firmware+hardware identity. That identity selects the wire **STRING_TYPE** — whether name/string fields are encoded in **RAD-50** or **ASCII** (cross-ref §8 — the codec and the 40-character RAD-50 alphabet). A client decoding name fields must key its codec on the reported identity rather than assume one encoding. [D/W]

**The rule is narrow, and it is matchable from the identity string itself.** The
revision library is a table of `(REV_STRING, CAB_TYPE, STRING_TYPE)` in two
kinds — **836 firmware-revision entries** and **52 hardware-revision entries** —
and across all 888 of them RAD-50 appears **31 + 1 times**. Everything else is
ASCII. In full: [D]

| Identity token | Platform | Codec |
|---|---|---|
| firmware `SCU0601` … `SCU129` (29 entries, SCU firmware **6.1 – 12.9**) | SCU | **RAD-50** |
| firmware `INT02`, `INT03` (legacy supervisor 2.0 / 3.0) | supervisor | **RAD-50** |
| hardware `SCU`, hardware `RCU` | SCU, RCU_P2 | **RAD-50** |
| firmware `SV503` … `SV5111` (SCU firmware **13.0 and later**) | SCU | ASCII |
| everything else — `COMPACT`, `MBC`, `MEC`, `MODULAR`, `MXL`, `MXL-IQ`, `NCC`, `PMI-G`, `SCT`, `XLS`, `FLNC`, and the supervisor from 2.1 on | — | ASCII |

So the decision procedure is: **assume ASCII, and switch to RAD-50 only for an
SCU below firmware 13.0, an RCU, or a pre-2.1 supervisor.** The SCU is the one
platform that crosses over, and it does so cleanly at a major-revision boundary
— 12.9 is RAD-50 and 13.0 is ASCII, with no mixed revision. The identity string
observed on the wire in this corpus carries a `PXME` hardware token, which is
the MODULAR class and therefore ASCII, consistent with every name field in the
capture set decoding as plain text. [D][W]

Two smaller facts from the same table. A `CHECK_HW_STRING` flag says whether the
hardware token must be validated as well as the firmware one; it is `NO` for 43
entries, the supervisor's among them, which is consistent with a supervisor
having no panel hardware to check. And **`REV_LEVEL` is a dotted revision that
does not sort as a number** — the SCU series runs `12.4`, `12.41`, `12.5`,
`12.51` … `12.54`, `12.6`, so `12.41` is a revision *between* 12.4 and 12.5 and
not "12.41 > 12.6". Compare revisions component-wise as strings-of-digits, or a
panel at 12.9 sorts below one at 12.41. [D]

#### 16.5.1 What a panel actually runs

Useful context for anyone modelling panel behaviour, and none of it is
guessable from the wire: [F]

- **The control processor is a Motorola 68000, and the operating system is
  pSOS+** — the Integrated Systems real-time kernel, banner `PSOS+ S68000
  V2.0.E`, copyright 1988–1992, with its configuration symbols (`KC_PSOSCODE`,
  `KC_RN0SADR`) present in the image. Confirmed two ways: the banner appears in
  26 of 42 shipped images, and **28 of 42 disassemble coherently as 68000** and
  not at all as PowerPC.
- **The later generation is PowerPC.** Two of the 42 shipped images are — the
  3.2 MB `V1` and the 2.5 MB French MEC, decoding at 40% and 11% instruction
  density with `blr` rates of 0.38 and 0.42 against 0.0% for 68000 — and so are
  the **PXC-class images (PPC, PXCC, PXCM)**, which ship *inside* a supervisor
  DLL rather than as standalone files and decode at 17–27% density with `blr`
  rates of 0.30–0.39. So the lineage spans two instruction sets, which is
  exactly why §22.4's dispatch table being byte-identical across both is
  evidence that it is protocol *data* rather than compiled code.
- **A third of the images are packed** and decode as neither architecture. The
  split is not by family but by revision: `FLNC2p5`/`MBC2p5` decode at 34%,
  while `flnc2p5p2`/`MBC2p5p2` — the very next patch level, same size class —
  decode at 5%.

Why an implementer should care: a pSOS+ task model explains the panel's
observed timing more honestly than a generic "it is busy" would. The **10 s
`EPing` cadence with a 0.00 s median absolute deviation** (§5.0, §7.3.1) is a
kernel timer tick, not a polling loop; the **~600-request database sweep
answered in ~8 seconds while heartbeats continue on other connections** (§16.1.1)
is separate tasks on separate priorities rather than one loop multiplexing. A
virtual panel that services both from a single thread will pass a functional
test and fail a timing one. [F][I]

**Firmware-keyed compatibility knobs.** Two legacy compatibility settings are gated by firmware identity: [D]

- **Legacy P2 Host ID field** — an older host-identity field retained for back-compatibility with pre-IP supervisors.
- **Extended Timeout flag** — `0x003E AP2_CABINET_TIMEOUT_NORMAL` / `0x003F AP2_CABINET_TIMEOUT_EXTENDED` toggle a normal-vs-extended communications timeout; extended timeout accommodates slower links (modem/AEM-tunneled serial, cross-ref §4.2).

### 16.6 Cabinet lifecycle and destructive opcodes

The `0x00xx`/`0x01xx` cabinet block contains the panel lifecycle and restart operations. Several are **destructive and MUST be blocklisted in any read-only or scanning tool**: [S/I]

| Opcode | AP2 name | Effect | Destructive? | Tag |
|---|---|---|---|---|
| `0x010C` | `CABINET_DISPLAY` | read firmware/config/identity | no (read) | [W] |
| `0x0108` | `CABINET_BOOT_MONITOR` | enter boot monitor | **YES** | [S] |
| `0x010A` | `CABINET_COLDSTART` | cold restart (clears state) | **YES** | [S] |
| `0x010B` | `CABINET_WARMSTART` | warm restart | **YES** | [S] |
| `0x0128` | `CABINET_SET_BLN_ADDRESS` | change BLN address | **YES** (reconfig) | [S] |
| `0x0041`/`0x0042` | `CABINET_ADD` / `CABINET_REMOVE` | add/remove a cabinet from the node table | **YES** | [S] |
| `0x0046`/`0x0047` | `CABINET_ONLINE` / `CABINET_OFFLINE` | force a node online/offline | **YES** | [S] |
| `0x0120`–`0x0126` | `CABINET_SET_*_BAUDRATE` | change MMI/FLN/BLN baud (can sever a link) | **YES** (reconfig) | [S] |

> **Destructive-operation flag.** A conformant read-only client or scanner MUST refuse to emit `0x0108`, `0x010A`, `0x010B`, `0x0128`, the `CABINET_ADD/REMOVE/ONLINE/OFFLINE` set, the baud-set block, and the state-change opcodes `0x0034`/`0x0035` (`SET_NODE_STATE`/`SET_COMPLETE_NODE_STATE`) — these reboot, reconfigure, or evict a panel. Document them for completeness; never invoke them against production hardware. [I]
## 17. Security Considerations

This section states plainly what P2 does and does not protect, characterizes the
pre-authentication attack surface for defenders, and gives implementers and
owner-operators concrete guidance. It is descriptive, not an attack toolkit: no
exploit code or step-by-step intrusion procedure appears here. The intended
reader is an owner-operator securing their own legacy P2 plant.

### 17.1 P2 has no cryptographic security

P2 provides **no authentication, no integrity protection, and no encryption** at
the protocol layer. [W][I] There is no password exchange, no key, no challenge-response,
no nonce, no message authentication code, and no session token that an attacker
cannot also mint. Every byte travels in cleartext over TCP; anyone with packet
capture on the path reads point values, point names, node names, firmware
strings, control-program text, and routing tables directly. [W] Anyone who can
send TCP to a node's P2 port can speak the protocol.

The protocol's framing predates IP and carries the trust model of an isolated,
physically-secured field bus forward onto Ethernet unchanged. Treat a P2 segment
exactly as you would treat an unswitched serial trunk in a locked mechanical
room: every device on it is implicitly trusted, and the only real boundary is the
wire itself.

### 17.2 The only gate is the BLN name

The single admission check that exists at the P2 layer is the **BLN-name match**
in the routing slots and the IdentifyBlock body (see §3.4, §6.4). [W] A peer
presenting the wrong BLN name is rejected at the transport layer — a field panel
answers with a **TCP RST**, a supervisor listener with a graceful **TCP FIN** —
before any application processing occurs, and **no node-table side effect is
written** for a wrong-BLN attempt. [W] (Verified by controlled test: 24 wrong-BLN
handshakes across 8 variants produced 24 RSTs and zero table entries.)

**The vendor's own connection-failure checklist is the clearest external
confirmation of this.** Its troubleshooting for *"Ethernet BLN will not
connect"*, for *"AEM BLN will not connect"*, and for *"not receiving alarms or
COVs"* gives the same three remedies each time: make sure the panel's name
resolves via DNS or the hosts file; make sure the driver is allowed through the
management station's **host firewall**; and make sure **the BLN name in the
panel's IP-settings report is identical to the BLN name configured for the
network**. [D]

Two things follow. The firewall item is host configuration on the supervisor
machine, not a panel-side access control, so it does not add a second protocol
gate. And the checklist contains **no authentication step at all** — no
credential to check, no key to match, no account to enable — because at this
layer there is none to check. A vendor's own list of everything that can stop a
peer connecting is a good inventory of what is actually enforced.

The insistence on *identical* is also the strictness of §3.4.1 stated
operationally: the match is exact, and a near-miss is indistinguishable from an
attacker.

This makes the BLN name function as a **read-only-reject access gate**, not as a
secret:

- It is a **shared, low-entropy, network-wide identifier**, not a per-node
  credential. One value admits every node on the network. It appears in cleartext
  in every frame the network ever sends (§6.4), so a passive listener on the
  segment learns it from the first captured frame. [W]
- It is **case-significant and exact-match** (§6.4), but it is not rotated, not
  salted, and not tied to any device identity. [D][I]
- Knowing it is the **only** prerequisite for full peer participation. Once a peer
  presents the correct BLN, the node accepts the handshake and records the peer;
  acceptance of *data service* is a separate, later check (the slot-4 identity
  shape, §6.4), but **registration itself is gated only by BLN-correctness.** [W]
  A right-BLN handshake with a novel slot-4 identity writes a permanent node-table
  entry even when the panel then refuses to serve data to that identity. [W]

The practical consequence: the BLN name keeps out an attacker who has no foothold
on the segment and no capture, and nothing more. An attacker who has sniffed one
frame, or who guesses a short conventional name, is past the only gate.

Node-name acceptance behavior — what the node does with slot[1] (destination) and
slot[3] (source identity) once the BLN matches — is detailed in §6.4 and is part
of the same ungated surface; see the cross-reference there for the
silent-drop-vs-service distinction.

### 17.3 Pre-authentication information disclosure

Because there is no authentication, **every read-style operation is a
pre-authentication read** for any peer that presents the correct BLN. The
following are directly observable on the wire with no credential beyond the BLN
name. This list is for defenders sizing their exposure; each item is a normal
protocol operation, not a bug to be triggered.

| Disclosed item | Mechanism | Tag |
|---|---|---|
| Panel firmware revision, type, link/build date, firmware checksum | `0x010C` CABINET_DISPLAY returns a `revstring` / `firmwaretype` / `linktime` / `firmware_checksum` block (e.g. firmware string `PME1252 / PXME V2.8.10 APOGEE / Oct 28 2013` observed on the wire); the full response layout is wire-confirmed (§10.5) | [W] |
| Panel identity: node name, site name, BLN name | Same `0x010C` response carries `node_name`, `site_name`, `bln_name` fields (wire-confirmed, §10.5) | [W] |
| Panel network config: IP settings, MAC (configured + hardware), link/MII state, BACnet settings | Same `0x010C` response carries `ip_addr_settings`, `configured_mac_address`, `hardware_mac_address`, `link_status`, BACnet sub-structures | [S] |
| Supervisor / host name | `0x0050` (DISK_LOG-family status query) returns the supervisor name to an unauthenticated peer | [W] |
| Node roster (every peer's name, IP, and state) | The full node-name table is obtainable via `0x4634` REPL_PULL with no authentication — the body is the replicated roster (8-byte header + per-node `TLV(node-name)` then `u32` version entries, `$paneldefault` first; §5.3); `0x464C` REPL_DIAG_NODELIST returns a node list | [W] |
| **Host table — peer names and the supervisor identity** | `0x4650` returns the host table in a 217-byte body: a default-panel tag, the panel number, every peer node name, and the supervisor both by name and in its `<name>\|<port>` suffixed form. Absence from the AP2 enum is not evidence of unreality — that enum is supervisor-side. Classify by what the panel returned. An earlier revision called this probe noise; **withdrawn**. | [W] |
| Replication grain keys, origin nodes and USNs | `0x464E` returns a 117-byte body containing replication grain keys with node name and USN; `0x464D` streams the **replication data store** — see §5.3.1 | [W] |
| Point existence, names, values, descriptors, units, alarm config | Read/browse/enumerate families `0x0220` / `0x0271` / `0x0273` / `0x0981` and the `0x09xx` enumerate family | [W] |
| Complete node-state table | `0x33` GET_COMPLETE_NODE_STATE returns `node_table : Node_complete_state[]` | [S] |
| PPCL control-program source | PPCL upload family (`0x4133` and the program-report opcodes) returns program text | [W][I] |
| **Operator-function execution via control logic** | PPCL's `OIP` statement mimics an operator terminal sequence and executes most operator functions from inside a program (§14.3). Program lines are added over the wire with `0x4100 AP2_PPCL_ADD_LINE`. Writing a line and writing an operator command are therefore the **same capability**, not two — any control on program editing that assumes it is merely logic modification is mis-scoped | [W][D] |

The supervisor's TCP/5033 listener accepts arbitrary inbound connections and
parses attacker-supplied frames; it does not return data to a non-peer but is a
parser attack surface and an identity fingerprint (FIN-vs-RST close
distinguishes supervisor from panel; per-opcode close timing exposes the
supervisor's originated-handler set). [W] The supervisor's optional TCP/5034
push listener, by contrast, rejects at the accept stage (uniform fast close)
and is comparatively hardened — an asymmetric design where the read channel is
permissive and the push channel is locked down. [W] An owner should not assume
the supervisor is uniformly exposed, nor assume it is uniformly defended.

No multicast discovery beacon exists (§5.2); there is nothing to passively
"listen for" to enumerate a P2 network, and a captured frame plus a TCP/5033
connect are the realistic discovery primitives. [W]

### 17.4 Ungated destructive operations

The same absence of authentication means **state-changing and destructive
operations are ungated at the protocol layer.** A peer that clears the BLN gate
can issue them as readily as a read. These are documented here so defenders
understand the blast radius; the operations themselves are flagged **DESTRUCTIVE**
and must never be sent to production equipment.

| Operation | Opcode(s) / ASDU | Effect | Tag |
|---|---|---|---|
| **DESTRUCTIVE** — panel cold start | `0x010A` CABINET_COLDSTART (AP2 266) | Reinitializes the panel; clears volatile state; observed in census | [W][S] |
| **DESTRUCTIVE** — panel warm start | CABINET_WARMSTART (AP2 267) | Restarts panel firmware | [S] |
| **DESTRUCTIVE** — drop to boot monitor | CABINET_BOOT_MONITOR (AP2 264) | Drops the panel into its boot monitor; takes it off the network | [S] |
| **DESTRUCTIVE** — set node state | `SET_NODE_STATE` (AP2 52) — body `node_changed`, `node_table_event`, `node_complete_state` | Forces a peer's state (e.g. `offline`, `failed`, `orderly_removed`); `node_table_event` includes `node_ostracized` | [S][I] |
| **DESTRUCTIVE** — set complete node state | `SET_COMPLETE_NODE_STATE` (AP2 53) — body `node_table : Node_complete_state[]` | Overwrites the entire node-state table | [S] |
| **DESTRUCTIVE** — evict / remove node | the node-eviction / remove-node / make-offline operations | Force-evicts a peer from the BLN (node-eviction DoS) | [S][I] |
| **DESTRUCTIVE** — point write / command | `0x0240` AP2_POINT_CMD_VALUE and the `0x05xx` command family | Overrides physical outputs at a chosen command priority (§8.2) | [W][S] |
| **DESTRUCTIVE** — flash database clear / restore | CLEAR_FLASH_DBASE (AP2 21298), RESTORE_FLASH_DBASE (AP2 21297) | Erases or overwrites the panel's saved database | [S] |
| Denial of service (parser stall) | `0x46xx` replication-class (e.g. `0x4636`, `0x4647`) with a malformed/wildcard-SYST body | Panel stops responding at the TCP layer for seconds | [W] |
| Persistent node-table write | right-BLN handshake with a novel source identity | Registers that identity permanently in the node table (§17.5) | [W] |

The DoS surface is a **class**, not a single opcode: at least two `0x46xx`
replication-class opcodes have been observed to silently stall a panel, and the
silent-discard behavior spans several specific request sizes. A defender should
treat the whole replication-class opcode range as a potential availability risk
from an untrusted peer, not just one value. [W][I]

### 17.5 Registration versus impersonation

There are two distinct ways for a peer to be "accepted," with very different
forensic footprints. Both are possible at the protocol layer with only the
correct BLN. [W]

- **Registration (more invasive, leaves a trail).** Presenting a *novel* source
  identity with the correct BLN causes the node to write a **persistent
  (Permanent) entry** into its NODE NAME TABLE binding that identity to the
  sender's IP — the node-table-entry write. [W][S] This happens
  even if the panel subsequently refuses to serve data to that identity. [W]
  Every distinct identity tried accumulates its own permanent entry (and, at the
  observed site, orphan site-grouping containers as well), so a careless scanner
  or an attacker iterating identities **bloats the node table** and can leave
  stale entries that persist after IP/name changes. The footprint is real but
  bounded: one entry per distinct identity, and **wrong-BLN attempts write
  nothing.** [W]
- **Impersonation (less invasive, leaves no new trail).** Presenting an
  *existing* table identity (e.g. the real supervisor's name) serves full data
  with **no new table entry and no IP rebind** — the permanent entry already
  exists and does not auto-update to the impostor's IP. [W] This is the stealthier
  path: an attacker who has learned a legitimate node name (trivial, given §17.3)
  reads as that node with zero forensic residue.

The asymmetry matters for both defenders and tool authors. Registration is
detectable after the fact by auditing the node table for unexpected entries;
impersonation is not. Adding a node table entry is the more invasive write
(persistent state change); impersonating an existing one is the quieter read.

### 17.6 Guidance for implementers and owner-operators

The following is the read-only-by-default discipline appropriate to a protocol
with no authentication. It applies to anyone writing P2 tooling for, or operating,
their own hardware. [I]

**For tool authors:**

1. **Read-only by default.** A client SHOULD implement only read, browse, and
   enumerate operations. Write, command, node-state, coldstart/warmstart, node
   add/remove/ostracize, and flash operations SHOULD NOT be implemented in
   general-purpose tooling, and SHOULD be refused in code (a hard blocklist, not
   a comment) even behind a flag. An attacker pays the same cost to add a write
   path whether or not read tooling exists; the asymmetry favors legitimate
   owners.
2. **Rate-limit.** Inter-request delays on the order of seconds, back-off on
   consecutive errors, single persistent connection per peer (§7), no broadcast
   storms. The replication-class DoS surface (§17.4) means even read-shaped
   traffic can stall a panel; pace accordingly.
3. **Never send destructive or node-state opcodes to production.** Test only
   against an isolated lab panel or a mock. Coldstart, warmstart, boot-monitor,
   set-node-state, ostracize/remove, and flash operations are out of scope for any
   tool that may touch a live building.
4. **Prefer passive discovery and impersonation-free identity.** Passive capture
   inventories a network without writing anything. If active discovery is
   unavoidable, understand it writes a permanent node-table entry per novel
   identity (§17.5) and that the only footprint-free read path is impersonating an
   existing peer — which is precisely the path a tool should *not* normalize.
5. **Validate lengths before buffering.** Reject frames whose declared
   `total_len` exceeds a sane ceiling (§6.1) and guard against malformed routing
   headers (slot-walk misalignment fabricates phantom opcodes, see §6.4).

**For owners:**

6. **P2 is not safe to expose to any untrusted network.** It carries the trust
   model of an isolated field bus. Do not route it to the Internet, to tenant
   VLANs, to guest Wi-Fi, or to any segment an attacker might reach.
7. **Segment P2 networks.** Place panels and supervisors on a dedicated,
   firewalled automation VLAN. Permit TCP/5033 (and 5034 where used) only between
   known supervisor and panel addresses. Block everything else at the segment
   boundary.
8. **Do not treat the BLN name as a secret.** It is on every frame in cleartext.
   It is an access label, not a password. Choosing an obscure BLN name buys almost
   nothing against an attacker with capture access and is not a control.
9. **Audit the node table.** Unexpected permanent entries indicate a peer (tool or
   attacker) registered against the BLN. Impersonation leaves no such trace, so a
   clean table is not proof of no access.
10. **Restrict the management plane.** Telnet/serial firmware consoles, SNMP, and
    the supervisor host itself are higher-value targets than any single panel;
    lock them down independently of the P2 segment.

---

### 17.7 Detecting BLN-name enumeration

§17.2 establishes that the BLN name is the only admission gate, and §6.4 that a
wrong name draws a TCP RST while a right one does not. That asymmetry is a
discovery oracle: an unauthenticated client can learn the BLN name by guessing,
and read the answer off the TCP layer without ever completing an exchange. This
section is how an owner-operator sees that happening on their own network. [W]

**What the traffic looks like.** Enumeration produces a distinctive shape that
legitimate traffic does not:

- **Many short-lived connections to TCP/5033 from one source**, each carrying a
  single frame and then ending. A real supervisor holds a long-lived connection
  and pipelines many operations over it.
- **A high proportion terminated by RST from the panel**, typically 50–250 ms
  after the client's PSH. A healthy client population produces almost none.
- **A different slot-3 value on nearly every connection.** This is the strongest
  single indicator, and it is decisive: a legitimate device knows its own BLN
  name and sends the same one every time. A stream of distinct slot-3 values from
  one source is enumeration and nothing else.
- **Sequence numbers that do not advance** across those connections, because
  each attempt is a fresh session that never gets far enough to establish one.
- **Slot-4 values that are structurally plausible but varied** — a client
  sweeping candidate supervisor identities alongside candidate BLN names.

**A detection rule.** On a span or tap carrying the automation VLAN:

```
# Connections to 5033 that were reset by the panel
tcp.port == 5033 && tcp.flags.reset == 1

# Count distinct BLN names presented per source. p2.bln2 is the enforced slot.
# One source presenting more than a handful is enumeration.
tshark -r capture.pcapng -X lua_script:p2.lua -Y 'p2.bln2' \
       -T fields -e ip.src -e p2.bln2 | sort -u | cut -f1 | uniq -c | sort -rn
```

Worked example, from a capture of the enumeration described above:

```
     14  192.0.2.101  SITEBLN      <- the panel: one name, always the same
      1  192.0.2.50   CORPBLN      <- client: wrong guess
      1  192.0.2.50   BLDGBLN      <- client: wrong guess
      1  192.0.2.50   ACMEBLN      <- client: wrong guess
     23  192.0.2.50   SITEBLN      <- client: correct, and now used for everything
```

The shape is unmistakable and needs no threshold tuning to read by eye: a run of
single-frame wrong guesses from one source, then sustained traffic on one name.
The transition between those two states is the discovery succeeding.
A threshold of **more than three distinct BLN names from one source in an hour**
is generous and has no legitimate explanation on a commissioned site. The dissector registers the four routing slots as `p2.bln1`, `p2.dst`,
`p2.bln2` and `p2.src`; `p2.bln2` is the one the panel actually checks.

**Why the silent case matters more than the RST case.** Detection tuned only to
resets will miss the moment that matters. A *correct* guess does not draw a RST —
the panel accepts the connection, stays silent, and the attacker learns the
answer from the absence of a reset. So the meaningful alert is not "many resets"
but "many resets from a source, **then a connection that was not reset**." That
transition is the discovery succeeding, and it is the last moment at which the
event is still only reconnaissance. [I]

**What detection cannot do.** None of this prevents the enumeration; the oracle
is a property of the protocol's admission check and there is no configuration
that removes it. Detection buys the operator notice, and notice is worth having,
because the interval between a successful BLN discovery and a registered peer
(§17.5) can be a single further connection. Segmenting TCP/5033 so that only
known supervisor and panel addresses can reach it is the actual mitigation;
detection is what tells you the segmentation has a hole in it. [I]

## 18. Appendices

### Appendix A — Value-enum reference

These tables are the spec-relevant value enumerations of the protocol, reproduced
in full. They are **[S] struct/metadata-derived**: every value and name comes from
the AP2 function-code enumeration, which is definitional truth for the protocol's vocabulary. The
underlying-storage type of each enum is `Int32` unless noted. Where the on-wire
representation of a field is narrower than `Int32` (for example a single command-
priority byte, §8.2), the enum value still gives the meaning of the byte. Source
enum stem shown in backticks after each title.

These tables are generated programmatically from `AP2_all_enums.txt` by
`gen_enum_tables.py` (co-located with this section), so they can be regenerated
verbatim if the source enum dump is updated.

#### User_command_priority  `User_command_priority_enum`

The command-priority ladder for operator/host commands. The same ladder is the
`scope_byte` of the scope tag (§8.2): a command acts at this priority, a read uses
`0` (NONE). The five named wire levels are `none`/`pdl`/`emer`/`smoke`/`oper`;
`oper` = `0x23`, the system-scope write selector.

| Value | Name |
|---|---|
| 0 | `none` |
| 1 | `tec_ovrd` |
| 5 | `pdl` |
| 10 | `host_2` |
| 15 | `host_3` |
| 20 | `host_4` |
| 25 | `host_5` |
| 30 | `host_6` |
| 32 | `emer` |
| 34 | `smoke` |
| 35 | `oper` |

#### Point_priority  `Point_priority_enum`

The full priority array a point arbitrates over (the command ladder above plus the
16 BACnet priority-array levels).

| Value | Name |
|---|---|
| 0 | `none` |
| 1 | `tec_ovrd` |
| 5 | `pdl` |
| 10 | `host_2` |
| 15 | `host_3` |
| 20 | `host_4` |
| 25 | `host_5` |
| 30 | `host_6` |
| 32 | `emer` |
| 34 | `smoke` |
| 35 | `oper` |
| 101 | `bacnet_1` |
| 102 | `bacnet_2` |
| 103 | `bacnet_3` |
| 104 | `bacnet_4` |
| 105 | `bacnet_5` |
| 106 | `bacnet_6` |
| 107 | `bacnet_7` |
| 108 | `bacnet_8` |
| 109 | `bacnet_9` |
| 110 | `bacnet_10` |
| 111 | `bacnet_11` |
| 112 | `bacnet_12` |
| 113 | `bacnet_13` |
| 114 | `bacnet_14` |
| 115 | `bacnet_15` |
| 116 | `bacnet_16` |

#### Point_type  `Point_type_enum`

The logical point types (§11.2). `ldi`/`ldo`/`lai`/`lao` are the four basic digital/
analog input/output kinds; `looal`/`looap` are On/Off/Auto latched/pulsed;
`lfssl`/`lfssp` Fast-Slow-Speed; `lpaci` pulse-accumulator/counter input; `lenum`
enumerated; `l2sl`/`l2sp` two-state latched/pulsed.

| Value | Name |
|---|---|
| 0 | `point_type_undef` |
| 1 | `ldi` |
| 2 | `ldo` |
| 3 | `lai` |
| 4 | `lao` |
| 6 | `l2sl` |
| 7 | `looap` |
| 11 | `lpaci` |
| 12 | `l2sp` |
| 13 | `looal` |
| 14 | `lfssl` |
| 15 | `lfssp` |
| 20 | `ldao` |
| 21 | `lenum` |
| 22 | `lfmssl` |
| 23 | `lfmssp` |
| 24 | `ppcl_lai` |

#### Cov_mask  `Cov_mask_enum`

Change-of-value subscription mask bits — which classes of change trigger a COV
report (§12).

| Value | Name |
|---|---|
| 0 | `data` |
| 1 | `failure` |
| 2 | `alarm` |
| 3 | `service` |
| 4 | `priority` |
| 5 | `TCU` |
| 6 | `temp_all` |
| 7 | `proof_on` |

#### Point_cov_type  `Point_cov_type_enum`

The aspect of a point a COV subscription tracks.

| Value | Name |
|---|---|
| 0 | `all_types` |
| 1 | `point_values` |
| 2 | `point_priorities` |
| 3 | `point_status` |

#### Native_type  `Native_type_enum`

The native value-type tags used inside point/attribute encodings.

| Value | Name |
|---|---|
| 0 | `NVT_TYPE_UNKNOWN` |
| 1 | `NVT_TYPE_SIGNED_CHAR` |
| 2 | `NVT_TYPE_UNSIGNED_CHAR` |
| 3 | `NVT_TYPE_SIGNED_SHORT` |
| 4 | `NVT_TYPE_UNSIGNED_SHORT` |
| 5 | `NVT_TYPE_SIGNED_LONG` |
| 6 | `NVT_TYPE_UNSIGNED_LONG` |
| 7 | `NVT_TYPE_ENUM` |
| 8 | `NVT_TYPE_ARRAY` |
| 9 | `NVT_TYPE_STRUCT` |
| 10 | `NVT_TYPE_UNION` |
| 11 | `NVT_TYPE_BITF` |
| 12 | `NVT_TYPE_FLOAT` |
| 13 | `NVT_TYPE_SIGNED_QUAD` |
| 14 | `NVT_TYPE_REFERENCE` |
| 15 | `NVT_TYPE_UNSIGNED_QUAD` |

#### Sensor_type  `Sensor_type_enum`

Input-conditioning / sensor type for analog input points (selects the panel's raw-
to-engineering-units curve, applied with the point's slope/intercept, §11.5).

| Value | Name |
|---|---|
| 0 | `voltage` |
| 1 | `current` |
| 2 | `resistance` |
| 3 | `pneumatic` |
| 4 | `thermister10k` |
| 5 | `thermister100k` |
| 6 | `ltype` |
| 7 | `rtd1k` |
| 8 | `rtd1k_385` |
| 9 | `nickel1000` |
| 10 | `nickeljci` |
| 11 | `nickeldin` |
| 12 | `thermister10type3` |

#### Node_complete_state  `Node_complete_state_enum`

The full node-state value set as reported/set in node-state tables (§10). This is
the value carried by GET/SET_COMPLETE_NODE_STATE and SET_NODE_STATE (§17.4), and
it is the one to decode against — the local and global sub-enums below are
**classifications of these values, not separate wire fields**; no structure
declares a field of either sub-enum type.

They are disjoint but **not exhaustive**: local takes 6 values and global 3, and
the remaining two — `2 unknown_protocol` and `7 p3_protocol_detected` — belong to
neither, which is consistent with their being protocol-detection outcomes rather
than a node condition. A decoder that consults only the two sub-enums will fail
to name those two. [S]

| Value | Name |
|---|---|
| 2 | `unknown_protocol` |
| 3 | `no_cov_links` |
| 7 | `p3_protocol_detected` |
| 8 | `TIU_cabinet` |
| 9 | `remote` |
| 10 | `failed` |
| 11 | `extended_timeout` |
| 12 | `offline` |
| 13 | `ready` |
| 14 | `defined` |
| 15 | `orderly_removed` |

#### Node_local_state  `Node_local_state_enum`

| Value | Name |
|---|---|
| 3 | `no_cov_links` |
| 8 | `TIU_cabinet` |
| 10 | `failed` |
| 12 | `offline` |
| 13 | `ready` |
| 15 | `orderly_removed` |

#### Node_global_state  `Node_global_state_enum`

| Value | Name |
|---|---|
| 9 | `remote` |
| 11 | `extended_timeout` |
| 14 | `defined` |

#### Alarm_priority  `Alarm_priority_enum`

| Value | Name |
|---|---|
| 0 | `priority_0` |
| 1 | `priority_1` |
| 2 | `priority_2` |
| 3 | `priority_3` |
| 4 | `priority_4` |
| 5 | `priority_5` |
| 6 | `priority_6` |

#### Alarm_state  `Alarm_state_enum`

| Value | Name |
|---|---|
| 0 | `normal` |
| 1 | `alarm` |
| 2 | `high_alarm` |
| 3 | `low_alarm` |
| 4 | `trouble` |

#### Alarm_object_type  `Alarm_object_type_enum`

The alarm-object kind associated with a point — standard vs enhanced, digital vs
analog vs enumerated, plus BACnet-mapped variants.

| Value | Name |
|---|---|
| 0 | `no_alarming` |
| 1 | `std_digital` |
| 2 | `std_single_analog` |
| 3 | `std_analog` |
| 4 | `enhanced_digital` |
| 5 | `enhanced_analog` |
| 6 | `enhanced_lenum` |
| 7 | `bacnet_alarm_analog` |
| 8 | `bacnet_alarm_digital` |

#### Scope_Type  `Scope_Type_enum`

The abstract scope-level enumeration. Distinct from the scope-name TLV strings
(`"SYST"`/`"NONE"`/`"CC"`) and the command-priority `scope_byte` of §8.2; this
enum names the levels of the addressing hierarchy abstractly.

| Value | Name |
|---|---|
| 0 | `SCOPE_UNDEFINED` |
| 1 | `SCOPE_1` |
| 2 | `SCOPE_2` |
| 3 | `SCOPE_3` |
| 4 | `SCOPE_4` |
| 5 | `SCOPE_5` |
| 6 | `SCOPE_6` |

#### Baud_rate  `Baud_rate_enum`

Serial baud-rate codes for FLN/MMI/BLN trunk baud settings (relevant to the
SET_*_BAUDRATE cabinet operations and to serial/MSTP-side configuration).

| Value | Name |
|---|---|
| 0 | `baud150` |
| 1 | `baud300` |
| 2 | `baud600` |
| 3 | `baud1200` |
| 4 | `baud2400` |
| 5 | `baud4800` |
| 6 | `baud9600` |
| 7 | `baud19200` |
| 8 | `baud38400` |
| 9 | `baud57600` |
| 10 | `baud115p2k` |
| 11 | `baud230p4k` |
| 12 | `baud76800` |

#### Application_family  `Application_family_enum`

The application/control-object family a definition belongs to (PPCL, EQS, loop,
PDL, TEC, UC, LON, P1, BACnet-MSTP).

| Value | Name |
|---|---|
| 0 | `any` |
| 1 | `pdl_area` |
| 2 | `pdl_load_group` |
| 3 | `decision_table` |
| 4 | `loop` |
| 5 | `eqs` |
| 7 | `ppcl_program` |
| 16 | `tec_na` |
| 17 | `uc` |
| 18 | `tcu` |
| 19 | `lon` |
| 20 | `p1_pxc` |
| 21 | `bacnet_mstp` |
| 256 | `rwi` |
| 257 | `tec_eu` |
| 258 | `rwp` |

#### FLN_Device_Type  `FLN_Device_Type_enum`

The kinds of device on a Field Level Network beneath a panel (§11.4.2). `TEC` =
terminal-equipment controller, `UC` = unitary controller, `PXM` = operator
display, `P1BIM` = a P1 BACnet interface module, `GLOBAL_IO` = a TXM I/O module.

| Value | Name |
|---|---|
| 0 | `FLN_DEVICE_DPU` |
| 1 | `FLN_DEVICE_MPU` |
| 2 | `FLN_DEVICE_TCU` |
| 3 | `FLN_DEVICE_TEC` |
| 4 | `FLN_DEVICE_UC` |
| 5 | `FLN_DEVICE_PXM` |
| 6 | `FLN_DEVICE_FSCS` |
| 7 | `FLN_DEVICE_GATEWAY` |
| 8 | `FLN_DEVICE_FLOAT_GATEWAY` |
| 9 | `FLN_DEVICE_P1BIM` |
| 10 | `FLN_DEVICE_GLOBAL_IO` |
| 65535 | `FLN_DEVICE_UNKNOWN` |

#### PPCL_statement_type  `PPCL_statement_type_enum`

The statement/keyword tokens of PPCL (Powers Process Control Language) as carried
in compiled program records over the wire (§14). The `WHOP` prefix is an
artifact of the vendor's token-name convention; the meaningful token is the suffix
(e.g. `WHOPGOTO` = the `GOTO` statement, `WHOPIF`/`WHOPTHEN`/`WHOPELSE` = the
conditional, `WHOPSET` = setpoint assignment, `WHOPALARM`/`WHOPNORMAL` = alarm/
normal commands).

| Value | Name |
|---|---|
| 1 | `WHOPLOOP` |
| 2 | `WHOPON` |
| 3 | `WHOPOFF` |
| 4 | `WHOPACT` |
| 5 | `WHOPDEACT` |
| 6 | `WHOPEMON` |
| 7 | `WHOPEMOFF` |
| 8 | `WHOPWAIT` |
| 9 | `WHOPEPHONE` |
| 10 | `WHOPDC` |
| 11 | `WHOPENCOV` |
| 12 | `WHOPDISCOV` |
| 13 | `WHOPMIN` |
| 14 | `WHOPMAX` |
| 15 | `WHOPDCR` |
| 16 | `WHOPSET` |
| 17 | `WHOPEMSET` |
| 18 | `WHOPPDL` |
| 19 | `WHOPPDLDAT` |
| 20 | `WHOPONPWRT` |
| 21 | `WHOPONERR` |
| 22 | `WHOPTABLE` |
| 23 | `WHOPDBSWITCH` |
| 24 | `WHOPRELEASE` |
| 25 | `WHOPENALM` |
| 26 | `WHOPDISALM` |
| 27 | `WHOPALARM` |
| 28 | `WHOPNORMAL` |
| 29 | `WHOPLLIMIT` |
| 30 | `WHOPHLIMIT` |
| 31 | `WHOPPDLMTR` |
| 32 | `WHOPPDLSET` |
| 33 | `WHOPPDLDPG` |
| 34 | `WHOPDPHONE` |
| 35 | `WHOPTIMAVG` |
| 36 | `WHOPINITTOT` |
| 37 | `WHOPFAST` |
| 38 | `WHOPSLOW` |
| 39 | `WHOPAUTO` |
| 40 | `WHOPDAY` |
| 41 | `WHOPNIGHT` |
| 42 | `WHOPTODMODE` |
| 43 | `WHOPTOD` |
| 44 | `WHOPTODSET` |
| 45 | `WHOPSSTO` |
| 46 | `WHOPSSTOCOEF` |
| 47 | `WHOPHOLIDAY` |
| 48 | `WHOPENTHAL` |
| 49 | `WHOPMMI` |
| 50 | `WHOPGOTO` |
| 51 | `WHOPGOSUB` |
| 52 | `WHOPRETURN` |
| 53 | `WHOPIF` |
| 54 | `WHOPSAMPLE` |
| 55 | `WHOPEMFAST` |
| 56 | `WHOPEMSLOW` |
| 57 | `WHOPEMAUTO` |
| 58 | `WHOPENABLE` |
| 59 | `WHOPDISABLE` |
| 60 | `WHOPRELTCU` |
| 61 | `WHOPUNKNOWN1` |
| 62 | `WHOPUNKNOWN2` |
| 63 | `WHOPTHEN` |
| 64 | `WHOPELSE` |
| 65 | `WHOPASSIGN` |
| 66 | `WHOPLSTSQR` |
| 67 | `WHOPLOCAL` |
| 68 | `WHOPDIM` |
| 69 | `WHOPCOMMENT` |
| 70 | `WHOPDEFINE` |
| 71 | `WHOPSTATE` |

#### Enumerations completed from the type system
The tables above were transcribed from an earlier enum dump that did not carry
every enumeration the type system declares. These are the remaining **41**,
reproduced in full and ordered by value, because a reader holds a byte and wants
a name. Where §10.9's register pins the field's wire width, it is given with the
table — the width and the values are what a decoder needs together, and looking
them up in two places is how they get combined wrongly. [S]

#### AP2_Racs_Partner_Add_Error  `AP2_Racs_Partner_Add_Error_enum`
**2 bytes on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `no_ram_available` |
| 2 | `invalid_partner_number` |
| 9 | `partner_already_here` |

#### AP2_Racs_Partner_Modify_Error  `AP2_Racs_Partner_Modify_Error_enum`
**2 bytes on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `no_ram` |
| 2 | `invalid_partner_number` |
| 3 | `partner_not_found` |

#### Alarm_mode_type  `Alarm_mode_type_enum`
**1 byte on the wire.** The alarm-mode set a point can be in. [S]

| Value | Name |
|---|---|
| 0 | `night` |
| 1 | `day` |
| 2 | `special2` |
| 3 | `special3` |
| 4 | `special4` |
| 5 | `special5` |

#### BAC_Application_ID  `BAC_Application_ID_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `ppcl` |
| 5 | `pdl` |
| 10 | `schedule` |
| 30 | `tec_config` |
| 32 | `emer` |
| 34 | `smoke` |
| 35 | `oper` |

#### BAC_Baud_rate  `BAC_Baud_rate_enum`
**2 bytes on the wire.** MS/TP line speeds on a BACnet trunk. [S]

| Value | Name |
|---|---|
| 6 | `baud9600` |
| 7 | `baud19200` |
| 8 | `baud38400` |
| 10 | `baud115p2k` |
| 12 | `baud76800` |

#### BAC_DaysOfWeek  `BAC_DaysOfWeek_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `monday` |
| 1 | `tuesday` |
| 2 | `wednesday` |
| 3 | `thursday` |
| 4 | `friday` |
| 5 | `saturday` |
| 6 | `sunday` |

#### BAC_Transitions  `BAC_Transitions_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `to_offnormal` |
| 1 | `to_fault` |
| 2 | `to_normal` |

#### Bln_global_data_changemask  `Bln_global_data_changemask_enum`
**2 bytes on the wire.** Bit positions in the BLN global-data change mask. [S]

| Value | Name |
|---|---|
| 0 | `change_password_high` |
| 1 | `change_password_low` |
| 2 | `change_mass_primary` |
| 3 | `change_mass_secondary` |
| 4 | `change_alarm_node1` |
| 5 | `change_alarm_node2` |
| 6 | `change_alarm_node3` |
| 7 | `change_node_to_call_host` |
| 8 | `change_report_node` |

#### Cabinet_report_config  `Cabinet_report_config_enum`
**1 byte on the wire.** Which port a cabinet's reports are sent to. [S]

| Value | Name |
|---|---|
| 0 | `reports_to_port0` |
| 1 | `reports_to_port1` |
| 2 | `reports_to_port2` |
| 3 | `reports_to_port3` |
| 4 | `reports_to_port4` |

#### Control_status  `Control_status_enum`
**1 byte on the wire.** How a point's current command is being held. [S]

| Value | Name |
|---|---|
| 0 | `remote` |
| 1 | `tool_override` |
| 2 | `by_priority` |
| 3 | `config_only` |
| 4 | `input_only` |
| 5 | `manual_override` |
| 6 | `undefined` |

#### Date_type  `Date_type_enum`
**1 byte on the wire.** How a calendar date entry behaves: a special day, a shift of the schedule to a named weekday, or one of seven replacement slots. [S]

| Value | Name |
|---|---|
| 0 | `special` |
| 1 | `spare` |
| 2 | `shift_to_SUN` |
| 3 | `shift_to_MON` |
| 4 | `shift_to_TUE` |
| 5 | `shift_to_WED` |
| 6 | `shift_to_THU` |
| 7 | `shift_to_FRI` |
| 8 | `shift_to_SAT` |
| 9 | `replacement1` |
| 10 | `replacement2` |
| 11 | `replacement3` |
| 12 | `replacement4` |
| 13 | `replacement5` |
| 14 | `replacement6` |
| 15 | `replacement7` |

#### Device_type  `Device_type_enum`
**1 byte on the wire.** The RACS device kinds a partner record can name. [S]

| Value | Name |
|---|---|
| 1 | `insight` |
| 2 | `primary_printer` |
| 3 | `secondary1_printer` |
| 4 | `secondary2_printer` |
| 5 | `secondary3_printer` |
| 6 | `report_printer` |
| 7 | `other_device` |

#### Failed_status  `Failed_status_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `normal` |
| 1 | `returning` |
| 2 | `unknown` |
| 3 | `failed` |

#### Global_IO_Module_Info  `Global_IO_Module_Info_enum`
**2 bytes on the wire.** Termination-module kinds a panel reports. [S]

| Value | Name |
|---|---|
| 0 | `TXM1_8D` |
| 1 | `TXM1_16D` |
| 2 | `TXM1_8U` |
| 3 | `TXM1_8U_ML` |
| 4 | `TXM1_8X` |
| 5 | `TXM1_8X_ML` |
| 6 | `TXM1_6R` |
| 7 | `TXM1_6R_M` |
| 65535 | `TXM1_UNKNOWN` |

#### Grain_Type  `Grain_Type_enum`
**1 byte on the wire.** The replication grain kinds (cross-ref 5.3). [S]

| Value | Name |
|---|---|
| 0 | `unknown` |
| 1 | `node_list_entry` |
| 2 | `storage_node_db` |
| 3 | `rpt_printer_db` |
| 4 | `user_acc_entry` |
| 5 | `access_grp_db` |
| 6 | `categ_entry` |
| 7 | `error_msg_entry` |
| 8 | `dst_cal_db` |
| 9 | `holiday_cal_db` |
| 10 | `txt_tbl_entry` |
| 11 | `dr_trnk_set_db` |
| 12 | `hosttbl_entry` |
| 13 | `addresstbl_entry` |
| 14 | `appl_pri_entry` |

#### Language_ID  `Language_ID_enum`
**2 bytes on the wire.** Windows locale identifiers (LCIDs), not an index. [S]

| Value | Name |
|---|---|
| 1030 | `DANISH` |
| 1031 | `GERMAN` |
| 1033 | `ENGLISH_AMERICAN` |
| 1034 | `SPANISH` |
| 1035 | `FINNISH_FINNISH` |
| 1036 | `FRENCH` |
| 1039 | `ICELANDIC` |
| 1040 | `ITALIAN` |
| 1043 | `DUTCH_DUTCH` |
| 1044 | `NORWEGIAN_BOKMAL` |
| 1046 | `PORTUGUESE_BRAZILIAN` |
| 1053 | `SWEDISH` |
| 2055 | `GERMAN_SWISS` |
| 2057 | `ENGLISH_BRITISH` |
| 2058 | `SPANISH_MEXICAN` |
| 2060 | `FRENCH_BELGIAN` |
| 2064 | `ITALIAN_SWISS` |
| 2067 | `DUTCH_BELGIAN` |
| 2068 | `NORWEGIAN_NYNORSK` |
| 2070 | `PORTUGUESE` |
| 3079 | `GERMAN_AUSTRIAN` |
| 3081 | `ENGLISH_AUSTRALIAN` |
| 3082 | `SPANISH_MODERN` |
| 3084 | `FRENCH_CANADIAN` |
| 4105 | `ENGLISH_CANADIAN` |
| 4108 | `FRENCH_SWISS` |
| 5129 | `ENGLISH_NEWZEALAND` |
| 6153 | `ENGLISH_IRELAND` |

#### LonDeviceStatus  `LonDeviceStatus_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `Normal` |
| 1 | `Returning` |
| 2 | `Unknown` |
| 3 | `Failed` |

#### Mii_Duplex  `Mii_Duplex_enum`
**1 byte on the wire.** Ethernet duplex as the panel reports it. [S]

| Value | Name |
|---|---|
| 0 | `auto_detect` |
| 1 | `half` |
| 2 | `full` |

#### Mii_Speed  `Mii_Speed_enum`
**1 byte on the wire.** Ethernet link speed as the panel reports it (0 = auto-negotiate). [S]

| Value | Name |
|---|---|
| 0 | `auto_detect` |
| 1 | `tenMBit` |
| 2 | `hundredMBit` |
| 3 | `thousandMBit` |

#### Name_space  `Name_space_enum`
**2 bytes on the wire.** The namespace selector that precedes a name (3.6). [S]

| Value | Name |
|---|---|
| 0 | `system` |
| 1 | `LAO_actuator` |
| 1 | `user` |
| 2 | `HOA` |
| 65535 | `any` |

#### Node_table_event  `Node_table_event_enum`
**1 byte on the wire.** What changed in a node table, on a routing push. [S]

| Value | Name |
|---|---|
| 0 | `node_added` |
| 1 | `remote_removed` |
| 2 | `node_removed` |
| 3 | `node_failed` |
| 4 | `node_ostracized` |
| 5 | `node_in_service` |
| 6 | `node_coldstarted` |
| 7 | `node_made_online` |
| 8 | `node_made_offline` |
| 9 | `node_made_ext_timeout` |
| 10 | `node_made_normal_timeout` |
| 11 | `node_multi_status_change` |
| 12 | `node_make_ready` |
| 13 | `node_enable_TIU_cabinet` |
| 14 | `node_disable_TIU_cabinet` |

#### Occurrence  `Occurrence_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `one_time` |
| 1 | `weekly` |
| 2 | `replacement` |

#### Pattern_type  `Pattern_type_enum`
**1 byte on the wire.** LonWorks object patterns on an FLN device. [S]

| Value | Name |
|---|---|
| 1 | `LONMARK_SENSOR_OBJECT` |
| 2 | `LONMARK_ACTUATOR_OBJECT` |
| 3 | `NV_IO_PAIR` |
| 4 | `NV_INPUT` |
| 5 | `NV_OUTPUT` |
| 6 | `UNASSOCIATED_CP` |
| 7 | `NV_IO_PAIR_TIME` |
| 8 | `NV_INPUT_TIME` |
| 9 | `NV_OUTPUT_TIME` |
| 10 | `UNASSOCIATED_CP_TIME` |

#### Port_number  `Port_number_enum`
**1 byte on the wire.** The panel's five physical ports. [S]

| Value | Name |
|---|---|
| 0 | `port0` |
| 1 | `port1` |
| 2 | `port2` |
| 3 | `port3` |
| 4 | `port4` |

#### Reference_Type  `Reference_Type_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `input` |
| 1 | `output` |
| 2 | `not_allowed` |

#### Repl_Cmd_Type  `Repl_Cmd_Type_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `unknown_cmd` |
| 1 | `add_cmd` |
| 2 | `delete_cmd` |

#### Representation  `Representation_enum`
**1 byte on the wire.** How an analog value is to be displayed, not how it is encoded. [S]

| Value | Name |
|---|---|
| 0 | `float_repr` |
| 1 | `integer_repr` |
| 2 | `time_of_day_repr` |
| 3 | `date_repr` |
| 4 | `date_time_repr` |

#### Schedule_days  `Schedule_days_enum`
**4 bytes on the wire.** Day selectors; these are **bit positions**, not values (cross-ref 10.1's warning about sizing a field from an enum maximum). [S]

| Value | Name |
|---|---|
| 0 | `Sunday` |
| 1 | `Monday` |
| 2 | `Tuesday` |
| 3 | `Wednesday` |
| 4 | `Thursday` |
| 5 | `Friday` |
| 6 | `Saturday` |
| 7 | `Replacement1` |
| 8 | `Replacement2` |
| 9 | `Replacement3` |
| 10 | `Replacement4` |
| 11 | `Replacement5` |
| 12 | `Replacement6` |
| 13 | `Replacement7` |

#### Ssto_amd  `Ssto_amd_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `neither_heatg_or_coolg` |
| 1 | `heating_only` |
| 2 | `cooling_only` |
| 3 | `heating_or_cooling` |
| 4 | `use_virtual_time` |

#### Ssto_desop_value  `Ssto_desop_value_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `neither_heatg_or_coolg` |
| 1 | `heating_only` |
| 2 | `cooling_only` |
| 3 | `heating_or_cooling` |

#### Ssto_zo_mod_cl  `Ssto_zo_mod_cl_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `fix_time_shift_estmtr` |
| 1 | `basic_estmtr` |
| 2 | `adv_estmtr` |

#### Ssto_zo_mod_ht  `Ssto_zo_mod_ht_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `fix_time_shift_estmtr` |
| 1 | `basic_estmtr` |
| 2 | `adv_estmtr` |

#### TEC_valid  `TEC_valid_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `no` |
| 1 | `yes` |
| 2 | `maybe` |

#### TextType  `TextType`
The string encoding selector (8.4). [S]

| Value | Name |
|---|---|
| 0 | `UNICODE` |
| 1 | `ASCII` |
| 2 | `DBCS` |

#### Total_rate  `Total_rate_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `seconds` |
| 1 | `minutes` |
| 2 | `hours` |
| 3 | `days` |

#### Uc_failed_status  `Uc_failed_status_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `normal` |
| 1 | `returning` |
| 2 | `unknown` |
| 3 | `failed` |

#### Uc_is_valid  `Uc_is_valid_enum`
**1 byte on the wire.** [S]

| Value | Name |
|---|---|
| 0 | `no` |
| 1 | `yes` |
| 2 | `maybe` |

#### User_access_functions  `User_access_functions_enum`
**1 byte on the wire.** The per-account function permissions. [S]

| Value | Name |
|---|---|
| 0 | `POINT` |
| 1 | `ALARM` |
| 3 | `TREND` |
| 4 | `APPLICATION` |
| 5 | `APPL_PPCL` |
| 6 | `APPL_FLN` |
| 7 | `APPL_EQS` |
| 8 | `APPL_PDL` |
| 9 | `APPL_LOOP` |
| 19 | `SYSTEM` |
| 20 | `SYS_DIAGNOSTICS` |
| 21 | `SYS_USERS` |
| 22 | `SYS_HARDWARE` |

#### User_access_priority  `User_access_priority_enum`
**1 byte on the wire.** The account's command-authority band. [S]

| Value | Name |
|---|---|
| 0 | `NONE` |
| 1 | `VIEW` |
| 2 | `COMMAND` |
| 3 | `CONFIGURE` |

#### Variable_type  `Variable_type_enum`
**1 byte on the wire.** LonWorks network-variable classes. [S]

| Value | Name |
|---|---|
| 0 | `LON_ELEMENT_TYPE_UNKNOWN` |
| 1 | `LON_ELEMENT_TYPE_NVI` |
| 2 | `LON_ELEMENT_TYPE_NVO` |
| 3 | `LON_ELEMENT_TYPE_NCI` |
| 4 | `LON_ELEMENT_TYPE_CP` |

#### license_error  `license_error_enum`
**2 bytes on the wire.** The failure reasons the licence-manager operations return. The five `LM_MV_*` members are 0xFFD6-0xFFFE - small negative numbers as they would be written in source, stored and matched as unsigned; a decoder compares the bytes, not the sign. [S]

| Value | Name |
|---|---|
| 0 | `LM_SUCCESS` |
| 1 | `LM_BADCODE_ERR` |
| 2 | `LM_HOSTTEXT_ERR` |
| 3 | `LM_PARAM_ERR` |
| 4 | `LM_EXPIRED_ERR` |
| 5 | `LM_VERSION_ERR` |
| 6 | `LM_SERIALNO_ERR` |
| 7 | `LM_VENDORNAME_ERR` |
| 8 | `LM_GENERAL_ERR` |
| 9 | `LM_NON_FEATURE_OVERWRITE` |
| 10 | `LM_EXTRA_PARAM_ERR` |
| 11 | `LM_TOO_MANY_LICENSES_ERR` |
| 12 | `LM_SERVICEDEMO_ERR` |
| 65494 | `LM_MV_BADPARAM` |
| 65515 | `LM_MV_OLD_VERSION` |
| 65526 | `LM_MV_EXPIRED` |
| 65528 | `LM_MV_BAD_KEY` |
| 65534 | `LM_MV_BADFILE` |

### Appendix B — Opcode-family index

The 2-byte AP2 function code (§9.1) groups by its high byte/range into operation
families. This index gives the prefix and its meaning; the full per-opcode body
grammar is in §9 (Function-Code / Opcode Catalog). Families are derived from the
the AP2 function-code enumeration and corroborated by wire census. [S][W]

| Prefix / range | Family | Representative opcodes | Tag |
|---|---|---|---|
| `0x00xx` | Cabinet / system control, node-state, license, revision | `0x010C` CABINET_DISPLAY, `0x010A` COLDSTART, `0x0050` status/disk-log, SET_NODE_STATE, REMOTE_NODE_CHECK | [S][W] |
| `0x02xx` | Point data: read, write/command, add/define, log, COV | `0x0220` POINT_LOG_VALUE (read), `0x0240` POINT_CMD_VALUE (write), `0x0271` COV_ENABLE, `0x0273` COV_DISABLE, `0x0274` COV_ANNUNCIATE (COV value push), `0x0263` PointRemove | [W][S] |
| `0x04xx` | Enum-type, alarm-setup, alarm-mode, category, calendar/DST, language | alarm-mode add/modify, category add/remove, calendar DB ops | [S] |
| `0x05xx` | Command/control and alarm report/ack, alarm-message | `0x0508` AlarmPrint, `0x0509` AlarmAck, `0x0540`-`0x054D` category family, `0x0560`-`0x0568` alarm-message family | [W][S] |
| `0x09xx` | Bulk enumerate / upload (point, PPCL, TEC, trend, EQS, SSTO, port, partner, UC, LON, MSTP) and FLN browse | `0x0981` UplAllPoint, `0x0985` UplAllPPCL, `0x0986` UplAllTEC, `0x0988`/`0x0989` EQS, `0x098C`-`0x098F` SSTO | [W][S] |
| `0x40xx` | Team/application, member, report descriptors | `0x400F` TeamDescUpload, `0x4010` MemberDescUpload, `0x4011` ReportDescUpload | [W][S] |
| `0x41xx` | PPCL program lines and program ops | `0x4100` PPCL AddLine, `0x4103` RemoveLines, `0x4104` EnableLines, `0x4133` UplAllProgram | [W][S] |
| `0x42xx` | Controller/TEC and init-value ops | `0x4200` ControllerLog/TECLog, `0x4220`/`0x4221` TEC init-value log, `0x4222` SetInitValue | [W][S] |
| `0x45xx` | Time-of-day point/command (TOD) | `0x4500` TODPointAdd | [W][S] |
| `0x46xx` | Session, EBLN, replication, discovery, panel/node enumeration | `0x4640` IdentifyBlock (session establish + heartbeat), `0x4633` REPL_NOTIFY, `0x4634` REPL_PULL (roster), `0x4635` REPL_PULL_MORE, `0x4636` REPL_CHANGES, `0x4644` TELNET_ENABLE, `0x464C` REPL_DIAG_NODELIST | [W][S] |
| `0x50xx` | EQS zone / mode / SSTO equipment scheduling | `0x5003` EQSZoneLook, `0x5020`/`0x5022` mode-entry, `0x5038` ZoneLog | [W][S] |
| `0x53xx` | Status / HOA-map / string queries | `0x5354` HOA_MAP_LOOK | [W][S] |

Note on encoding: a wire opcode's two bytes are the big-endian AP2 function code.
Where a §9 entry and the AP2 enum name differ cosmetically, both denote the same
function code. Some opcodes are polymorphic (the same code selects different
operations by body shape, scope tag, and direction); dispatch on opcode plus body
shape, never opcode alone (§6.4).

### Appendix C — Glossary

| Term | Meaning |
|---|---|
| **AEM** | APOGEE Ethernet Microserver — an Ethernet front-end / serial-to-IP front for legacy panels. |
| **AP2 function code** | The 2-byte wire opcode (§9.1); Siemens' internal name for the operation selector. A separate **CPI function code** exists with an AP2↔CPI mapping in the stack. |
| **ALN** | Automation Level Network — the current name for the tier P2 runs on; synonymous with BLN. |
| **ASDU** | Application Service Data Unit — the typed operation body carried after the opcode (request/indication/response/confirm service model). |
| **BBLN** | BACnet BLN — a BLN reached over the BACnet side of discovery (uses I-Am). |
| **BIM** | (P1) BACnet Interface Module — an FLN-side device bridging P1 to BACnet. |
| **BLN** | Building Level Network — the peer trunk P2 operates on; identified by the BLN System Name, the protocol's only admission gate (§3.4, §17.2). Newer name: ALN. |
| **CEC** | Controller / panel exec — the panel's executive (the cabinet/node firmware). |
| **COV** | Change of Value — an unsolicited report (opcode `0x0274`) pushed when a subscribed point changes; subscriptions are register/cancel (§12). |
| **CPI** | The internal function-code namespace the AP2 function code maps to/from inside the stack. |
| **EBLN** | Ethernet BLN — a BLN running over Ethernet/IP (the P2/IP case this spec covers). |
| **EPing** | Ethernet Ping — the discovery/liveness probe used on Ethernet BLNs (optional multicast; §5.1, §5.2). |
| **EQS** | Equipment Scheduling — the panel's equipment-scheduling subsystem (`0x50xx`). |
| **FLN** | Field Level Network — the sub-bus beneath a panel carrying field controllers (separate namespace from the BLN; §3.8, §5.5). |
| **MEC** | Modular Equipment Controller — a field-panel platform. |
| **MLN** | Management Level Network — the top tier, where supervisory workstations reside. |
| **P1** | Protocol I — the FLN/fieldbus protocol beneath a panel (master/slave). |
| **P2** | Protocol II — the BLN/backbone peer protocol this document specifies ("APOGEE PII protocol"). |
| **PPCL** | Powers Process Control Language — the panel's control-program language; carried over the wire as compiled statement records (§14, Appendix A `PPCL_statement_type`). |
| **PXC** | A field-panel controller platform (e.g. PXC/PME family). |
| **PXM** | An operator-display / man-machine-interface device (also an FLN device type). |
| **RACS** | Remote Access / Communications Subsystem — partner/port/system remote-access ops (`0x46xx`/RACS family). |
| **RAD-50** | A 40-symbol character packing (3 chars per 16-bit word) used by pre-IP revisions for names; P2/IP revisions use plain ASCII (§8.4). Alphabet: space, A–Z, `$`, `.`, `?`, 0–9. |
| **SSTO** | Start/Stop Time Optimization — the optimal-start/stop scheduling subsystem within EQS. |
| **TEC** | Terminal Equipment Controller — an FLN field controller. |
| **TOD** | Time Of Day — scheduled point/command operations (`0x45xx`). |
| **UC** | Unitary Controller — an FLN field controller class. |

### Appendix D — Open-questions register

The honest gap list. Every item here is **[OPEN]**: not yet confirmed to the byte
level by capture or test. Each gives what is known, what is missing, and the
specific test that would confirm or falsify it.

1. **COV condition/priority block — asserted values.** *Known:* `0x0274` is the
   COV value push; its body is wire-confirmed (§12.3.3) — `count`, then per point a
   u16 `name_space` (observed `00 00`), the name TLV, an (empty for top-level points)
   `01 00 00` suffix TLV, the `f32` present value, and a **fixed
   10-byte trailing condition/priority block**. The block's **field order is now
   pinned**: the `Annunciate_request` ASDU defines exactly ten status fields after
   the value (`point_priority, control_status, out_of_service, failed, proof_on,
   operator_disabled, program_disabled, commanded_to_alarm, alarm_state,
   alarm_priority`) and the wire block is exactly ten bytes, so it is **one byte per
   field in schema order** [W position/size; S field order] — wire-consistent (the
   only non-zero byte in the normal-state corpus is `control_status` at +1).
   *Missing:* the *asserted values* — exactly what each alarm/flag/priority byte
   reads when a point is actually in alarm / failed / out-of-service / held under
   command (all captured pushes were normal-state, so those bytes never asserted).
   *Test:* capture a `0x0274` push for a point in alarm and one commanded at a
   non-default priority; the bytes that go non-zero confirm the per-field values.
   *Narrowed:* the **definition** side of the same question is now answered —
   `Alarm_object_data` inside the point body is decoded field-for-field
   (§10.4.4), and `is_enhanced` is confirmed by reading `01` on the enhanced arm
   and `00` on both standard arms. But the same scoping applies there: across all
   73 alarm-configured points in the corpus, `inalarm`, `introuble`,
   `inalarm_by_command`, `program_disabled` and `proofing` are **constant zero** —
   the site's alarms were quiet throughout. Their positions are established; their
   asserted values are not.

2. **Heartbeat-miss count for failed-node transition.** *Known:* there is **no
   application-layer ACK frame** — the `dir == 0x01` success (or `dir == 0x05`
   error) response, matched by the echoed `sequence`, *is* the acknowledgment
   (§7.2) [W]; P2 relies on TCP for delivery/retransmit and has no app-layer
   retransmit (§7.2) [W]; the ~10 s heartbeat cadence is observed. The
   request→response latency distribution is now **measured** — median round-trips
   range ≈ 6 ms (ping/COV) to ≈ 53 ms (trend), p95 < ~2× median, up to 14 requests
   pipelined (§7.2, §6.5) [W]. *Missing:* the exact heartbeat-miss count /
   ACK-timeout that declares a peer failed is not pinned. *Test:* on a controlled
   peer, count the heartbeat misses that trigger a failed-node transition.

3. **Error-code value↔class meanings.** *Known:* all seven wire error tails the
   corpus exercises are now **named** (§7.2.2) — `0x0003` not-found, `0x00AC`
   not-supported, `0x0002` invalid-operation, `0x0009` already-exists, `0x0E11`
   FLN-invalid-drop-number, `0x0E12` FLN-device-failed, `0x0E15`
   physical-point-not-commandable — and `0x0E10`–`0x0E17` is the FLN band. The
   AP2 error-**class** names also exist (not-supported, bad-tag-value,
   bad-packet-length, …). *Missing:* the mapping between the two, i.e. which
   named class emits which code, and whether per-opcode error namespaces exist.
   *Test:* drive each error-class condition deliberately on a lab panel
   (malformed length, bad tag, wrong element count) and record the returned code.

4. **FLN / P1 and serial-AEM frame bytes.** *Known:* FLN points are a separate
   namespace reached via the `0x09xx` browse family over an established node
   session (§5.5); P1 is the fieldbus beneath the panel; an AEM fronts serial
   panels. *Missing:* the on-wire byte layout of P1/FLN frames themselves and of
   the serial-AEM encapsulation — this spec covers the BLN/P2-over-IP frame, not
   the fieldbus frame. *Test:* capture FLN-scoped browse/enumerate traffic and, if
   accessible, the serial side of an AEM, to pin the P1/FLN and AEM frame formats.

5. **Sub-opcode byte structure.** *Known:* some opcodes carry a 2-byte sub-field
   immediately after the opcode (e.g. `00 01` / `00 00`) before the body, and the
   presence/value is opcode-specific; `0x4640` carries none (§6.4). *Missing:* a
   complete per-opcode catalog of which opcodes have a sub-field and what each
   sub-field value selects (it appears to be a request-variant/mode discriminator
   in some, a reserved constant in others). *Test:* for each opcode that shows a
   non-trivial sub-field in capture, vary it on a lab panel and observe the
   behavioral change to determine whether it is a mode selector or a constant.

6. **Polymorphic-opcode full dispatch map.** *Known:* several opcodes select
   different operations by body shape, scope tag, and direction; the spec advises
   dispatching on opcode plus body. *Missing:* the exhaustive enumeration of body
   shapes per polymorphic opcode and which operation each selects. *Test:* for
   each known-polymorphic opcode, capture every distinct body shape against a lab
   panel and label the operation produced.

7. **CHOICE tag→arm assignment — ANSWERED for every CHOICE a decode depends
   on.**
   *Was:* declaration order is a hypothesis, not a rule, and reading it the wrong
   way round parses cleanly whenever the two arms are a `NULL_` and a fixed-width
   record — the decoder consumes the wrong number of bytes only on the *other*
   tag value, which a single-valued corpus never produces. The sharpest case was
   `scale_` (§11.5.1), whose only carrier appears nowhere in the corpus, and the
   test asked for was a `MEMBER_DESC_UPLOAD` response.
   *Now:* the numbering is read directly for **72 of the 73 CHOICEs**, complete
   for **71**, and complete for **every CHOICE a decode depends on** — §10.9's
   register is at 455 of 455 with nothing blocked and no modelling assumption
   left in it (§10.4.6). Sixty-six of the seventy-one are positional; five are
   not, and each of the five numbers its
   arms by an external enumeration — the `Point_type` enum for `All_points`, the
   BACnet object-type enumeration for the two BACnet point CHOICEs, and the
   BACnet event-type enumeration for `event_parameter_Tag_`, which check against
   a public standard rather than against the vendor. `scale_` is settled with
   them: **tag `0` = `virtual_pt`, tag `1` = `physical_pt`**, so it and
   `Physical_address_*` each follow their own declaration order and the
   inversion is in the declarations, not in one of them breaking a convention
   (§11.5.1).
   **No capture was needed for any of it**, and two editions of this register
   asked for two specific ones — a `MEMBER_DESC_UPLOAD` response for
   `localStateText_`, a BACnet event-enrollment object for
   `event_parameter_Tag_`. Both were answered by reading the vendor codec's
   *encoders*, which write the same tag their decoders read and which the
   earlier passes had not looked at. `BAC_Point_Base`'s ninth arm went the same
   way: `multi_value` = **19** is now read rather than inferred from the
   pattern.
   *What is left:* two CHOICEs have no complete map — `NetworkVariable_`, which
   has no decoder and no encoder, and `Point_extension2_type`, whose three-armed
   compare chain yields only its middle arm. **No structure in the catalog names
   either one as a field type**, so nothing can reach them and nothing is
   blocked. Neither is worth a capture.

### Appendix E — Evidence-tag legend and lineage pointer

Every non-trivial claim in this document carries an inline evidence tag so a
reader can weigh provenance. The tags are:

| Tag | Meaning |
|---|---|
| **[W]** | Wire-verified — observed directly in a packet capture or the opcode census. Ground truth for wire-format claims. |
| **[S]** | Struct/metadata-derived — from the AP2 function-code enumeration or the ASDU structure definitions. Definitional truth for field names, types, and order, but not by itself proof of the on-wire byte offset. |
| **[F]** | Firmware-attested — the value or behavior is carried in the controller firmware itself, in a panel image rather than in a supervisor-side binary. Stronger than [S] for the question *does a panel actually implement this*, because [S] describes only what a supervisor knows how to ask for. |
| **[C]** | Codec-attested — read out of the vendor's own compiled P2 codec, the encoder or decoder that lays the bytes down, supervisor side. Definitive for field width, byte order, padding and string encoding, because the arithmetic is in the instruction stream. Weaker than [F] for *does a panel implement this*; weaker than [W] because a link the codec serves may never have been captured. |
| **[D]** | Doc-sourced — a behavioral, topology, or semantic statement from vendor documentation/help. Never presented as a byte-level wire fact. |
| **[I]** | Inferred / synthesis — reasoned from [W], [S], and/or [D] above. |
| **[OPEN]** | Not yet confirmed; needs a capture or test. Collected in Appendix D. |

Precedence rule (consistent with §1): when a [W] wire observation and an [S]/[D]
source disagree, **the wire wins** for what bytes actually appear; the [S]/[D]
source still defines the intended meaning of those bytes. A field-layout table is
tagged **[S]** when it derives from the ASDU structures and **[W]** when its
offsets are confirmed on the wire; the two are distinct levels of confidence and
this document keeps them separate rather than presenting a struct field order as a
proven byte offset.

For the lineage of the protocol itself — Powers Protocol II → Landis & Gyr →
Siemens APOGEE, and the System 600 / "PII" heritage that explains the point-type,
priority, and PPCL vocabulary reproduced in Appendix A — see **§1** (Overview and
Architecture) and the informative lineage discussion there.
