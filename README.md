# PacketSentry

PacketSentry is a Python-based deep packet inspection (DPI) project that reads PCAP files, parses network flows, identifies application traffic from packet contents, applies blocking rules, and writes a filtered PCAP output.

The goal of this repository is educational and practical: it shows how packet parsing, flow tracking, SNI extraction, and rule-based filtering work together in a readable Python codebase.

## Table of Contents

1. [What PacketSentry Does](#what-packetsentry-does)
2. [Repository Layout](#repository-layout)
3. [Architecture at a Glance](#architecture-at-a-glance)
4. [Theory Primer](#theory-primer)
5. [TLS Handshake Architecture](#tls-handshake-architecture)
6. [Packet Anatomy](#packet-anatomy)
7. [Flow and Blocking Theory](#flow-and-blocking-theory)
8. [How It Works](#how-it-works)
9. [Entry Points](#entry-points)
10. [Running PacketSentry](#running-packetsentry)
11. [Windows PowerShell](#windows-powershell)
12. [Output Overview](#output-overview)
13. [Project Notes](#project-notes)
14. [Troubleshooting](#troubleshooting)
15. [Summary](#summary)

## What PacketSentry Does

- Reads packets from a PCAP file
- Parses Ethernet, IP, TCP, and UDP headers
- Groups packets into flows using a five-tuple
- Extracts SNI from TLS and Host headers from HTTP when available
- Classifies traffic into application types such as YouTube, Facebook, Google, and DNS
- Applies blocking rules by source IP, application, or domain substring
- Supports allowlist domains (higher priority than block rules)
- Supports regex-based domain blocking rules
- Stores explainable flow decisions (detection method and block reason)
- Tracks flow analytics (packet count, byte count, first/last seen, duration, average packet size)
- Flags suspicious flows using heuristic detection
- Exports JSON flow intelligence reports
- Writes allowed packets to a new PCAP file

## Repository Layout

```text
PacketSentry/
├── main_working.py      # Primary single-threaded DPI workflow
├── main_dpi.py          # Modular engine entrypoint
├── dpi_mt.py            # Standalone multi-threaded DPI runner
├── main_simple.py       # Lightweight packet/SNI inspection example
├── main.py              # Packet viewer and parser demo
├── generate_test_pcap.py
├── test_dpi.pcap
├── output.pcap
├── README.md
└── python_dpi/
    ├── pcap_reader.py
    ├── packet_parser.py
    ├── sni_extractor.py
    ├── thread_safe_queue.py
    ├── types.py
    ├── reporting.py
    ├── dpi_engine.py
    └── __init__.py
```

## Architecture at a Glance

PacketSentry is easiest to understand as a pipeline. The single-threaded engine follows one direct path, while the multi-threaded runner breaks the same work into separate stages.

### Single-Threaded Pipeline

```text
+------------------+      +------------------+      +------------------+
|    Input PCAP    | ---> |    PcapReader    | ---> |  PacketParser    |
|  raw capture     |      |  read records    |      |  parse headers   |
+------------------+      +------------------+      +------------------+
                                                           |
                                                           v
                                                 +------------------+
                                                 |  Flow Tracking   |
                                                 |  five-tuple map  |
                                                 +------------------+
                                                           |
                                                           v
                                                 +------------------+
                                                 | SNI / Host check |
                                                 |  inspect payload |
                                                 +------------------+
                                                           |
                                                           v
                                                 +------------------+
                                                 |   Rule Manager   |
                                                 | IP/app/domain    |
                                                 +------------------+
                                                      /            \
                                                     v              v
                                           +----------------+  +----------------+
                                           |  Forward packet |  |   Drop packet   |
                                           +----------------+  +----------------+
                                                     \              /
                                                      v            v
                                                 +------------------+
                                                 |   Output PCAP    |
                                                 +------------------+
```

### Multi-Threaded Pipeline

```text
+------------------+
|    Input PCAP    |
+------------------+
         |
         v
+------------------+      +------------------+      +------------------+
|   Reader thread  | ---> | Load balancers   | ---> |  Fast path pool  |
| reads packets    |      | hash by flow     |      | per-flow inspect |
+------------------+      +------------------+      +------------------+
                                                              |
                                                              v
                                                  +------------------------+
                                                  |   Per-FP flow tables   |
                                                  |   SNI / Host detect    |
                                                  |   Rules check          |
                                                  +------------------------+
                                                              |
                                         +--------------------+--------------------+
                                         |                                         |
                                         v                                         v
                               +------------------+                      +------------------+
                               |  Output queue    |                      |  Drop packet     |
                               +------------------+                      +------------------+
                                         |
                                         v
                               +------------------+
                               |   Writer thread  |
                               | writes output    |
                               +------------------+
                                         |
                                         v
                               +------------------+
                               |    Output PCAP   |
                               +------------------+
```

The single-threaded workflow in [main_working.py](main_working.py) follows the first diagram directly. The modular engine in [main_dpi.py](main_dpi.py) uses the same logic through reusable components in [python_dpi](python_dpi/). The multi-threaded runner in [dpi_mt.py](dpi_mt.py) keeps the same processing model but spreads work across reader, load balancer, fast path, and writer threads.

## Theory Primer

This project is built around a few network concepts that make DPI possible.

### Packet Layers

Network traffic is nested. Ethernet carries IP, IP carries TCP or UDP, and TCP or UDP carries application payload. PacketSentry reads the outer layers first, then inspects the payload only when it has enough context to do something useful.

### Five-Tuple Flow Identity

A flow is identified by source IP, destination IP, source port, destination port, and protocol. That five-tuple matters because packets from the same connection do not always arrive back-to-back, so the engine needs a stable key to keep related packets together.

### Why SNI Matters

HTTPS encrypts the payload, but the TLS Client Hello often still exposes the server name before encryption starts. PacketSentry uses that hostname to classify traffic such as YouTube, Facebook, Google, or GitHub. For plain HTTP, it can also inspect the Host header.

### Why Blocking Works

The engine usually cannot know the application immediately on the first packet. It may need to wait until the TLS handshake or HTTP request reveals enough metadata. Once a flow matches a blocking rule, PacketSentry marks the flow and drops later packets for the same connection.

## TLS Handshake Architecture

The most important inspection path in PacketSentry is the TLS handshake, because that is where the hostname often appears before encryption takes over.

### The TLS Handshake (Why SNI Is Visible)

```text
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
         │                                         │
         │ ──── Client Hello ─────────────────────►│
         │      (includes SNI: www.youtube.com)    │
         │                                         │
         │ ◄─── Server Hello ───────────────────── │
         │      (includes certificate)             │
         │                                         │
         │ ──── Key Exchange ─────────────────────►│
         │                                         │
         │ ◄═══ Encrypted Data ══════════════════► │
         │      (from here on, everything is       │
         │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello.**

### TLS Client Hello Layout

PacketSentry only needs the early handshake fields to classify most encrypted flows:

```text
+--------------------------------------------------------------+
| TLS Record Layer                                             |
+--------------------------------------------------------------+
| Content Type        | Handshake                              |
| Protocol Version    | TLS 1.x                                |
| Record Length       | Total bytes in the TLS record          |
+--------------------------------------------------------------+
| Handshake Layer                                              |
+--------------------------------------------------------------+
| Handshake Type      | Client Hello                           |
| Handshake Length    | Bytes in the handshake message         |
+--------------------------------------------------------------+
| Client Hello Body                                            |
+--------------------------------------------------------------+
| Random              | 32 bytes of client randomness          |
| Session ID          | Optional session identifier            |
| Cipher Suites       | Supported encryption methods           |
| Compression Methods | Usually none in modern traffic          |
| Extensions          | Optional handshake extensions          |
| SNI Extension       | Hostname for the target server         |
| Server Name         | example.com                            |
+--------------------------------------------------------------+
```

### Why This Works

- The TLS handshake happens before the encrypted application payload begins.
- The SNI extension is normally sent in plaintext inside the Client Hello.
- That makes domain-based classification possible even when the rest of the traffic is encrypted.

### Where PacketSentry Uses It

- `main_working.py` extracts SNI during the single-threaded flow walk.
- `dpi_mt.py` performs the same inspection in each fast-path worker.
- `python_dpi/sni_extractor.py` contains the reusable parsing logic used by the modular engine.

### SNI Extraction Architecture

```text
+------------------+      +------------------+      +------------------+
| TLS Client Hello | ---> | SNI Extractor    | ---> |   Hostname       |
| record payload   |      | parse extensions |      |  example.com     |
+------------------+      +------------------+      +------------------+
         |                          |                         |
         v                          v                         v
+------------------+      +------------------+      +------------------+
| Validate record  |      | Find SNI type    |      | Map to AppType   |
| type/length      |      | (0x0000)         |      | YouTube, Google  |
+------------------+      +------------------+      +------------------+
         |                          |                         |
         v                          v                         v
+------------------+      +------------------+      +------------------+
| Extract hostname | ---> | Store in flow    | ---> | Apply rules      |
| string bytes     |      | state            |      | allow / drop     |
+------------------+      +------------------+      +------------------+
```

## Packet Anatomy

PacketSentry reads packets layer by layer. A single network packet usually looks like this:

```text
Ethernet Header
└── IP Header
    └── TCP or UDP Header
        └── Application Payload
            └── TLS Client Hello or HTTP Request
```

The reason the code separates parsing from inspection is simple: the engine first needs to know what protocol it is looking at before it can safely inspect deeper fields. That is why the parser extracts MAC addresses, IP addresses, ports, transport flags, and payload offsets before the classifier looks for SNI or HTTP Host values.

## Flow and Blocking Theory

PacketSentry is flow-oriented, not just packet-oriented.

- A connection is represented by a five-tuple.
- The first few packets may not reveal the application yet.
- Once a flow is classified, the decision is reused for later packets in the same connection.
- If a rule blocks the flow, all later packets from that flow are dropped.

This design is useful because encrypted traffic often hides the payload but still exposes enough metadata at the start of the session to make a policy decision.

## How It Works

PacketSentry follows a simple pipeline:

1. Read a raw packet from the PCAP file.
2. Parse the packet headers to recover source and destination addresses, ports, protocol, and payload.
3. Build a five-tuple so packets from the same connection stay grouped together.
4. Inspect the payload for clues such as TLS SNI or an HTTP Host header.
5. Map the detected domain to an application category.
6. Check the packet against blocking rules.
7. Forward the packet to the output file or drop it.

### Flow Tracking

A flow is identified by:

- Source IP
- Destination IP
- Source port
- Destination port
- Protocol

That combination keeps packets from the same connection together, even when many connections are interleaved in the capture.

### SNI and Host Detection

For HTTPS traffic, PacketSentry looks for the TLS Client Hello and extracts the SNI value when present. For HTTP traffic, it searches for the Host header.

That is the main reason the project can classify encrypted traffic early in the connection: the hostname is often visible before the payload becomes encrypted.

## Entry Points

### `main_working.py`

This is the best place to start. It is the main single-threaded DPI workflow with flow tracking and blocking support.

Supported options:

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`
- `--json-output <file>`

### `main_dpi.py`

This is the modular engine entrypoint built on `python_dpi/dpi_engine.py`.

Supported options:

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`
- `--allow-domain <domain>`
- `--block-regex <pattern>`
- `--rules <file>`
- `--json-output <file>`
- `--lbs <n>`
- `--fps <n>`
- `--verbose`

### `dpi_mt.py`

This is the standalone multi-threaded runner. It demonstrates the load-balancer and fast-path design with separate reader, worker, and writer stages.

Supported options:

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`
- `--json-output <file>`
- `--lbs <n>`
- `--fps <n>`

### `main_simple.py`

This is a lightweight packet inspection example that prints packet counts and extracts SNI values from TLS traffic.

### `main.py`

This is a packet viewer and parser demo. It prints per-packet summaries, including Ethernet, IP, TCP, UDP, and payload details.

## Running PacketSentry

### Requirements

- Python 3.10 or newer
- No external packages are required

### Quick Start

Run the primary single-threaded workflow:

```bash
python main_working.py test_dpi.pcap output.pcap

# writes report.json by default
```

### Blocking Examples

Block traffic by IP, application, and domain substring:

```bash
python main_working.py test_dpi.pcap output.pcap --block-ip 192.168.1.50 --block-app YouTube --block-domain facebook

# allowlist and regex examples (modular engine)
python main_dpi.py test_dpi.pcap output.pcap --block-domain youtube --allow-domain youtube.com --block-regex ".*tracking.*"
```

### Multi-Threaded Examples

Run the standalone multi-threaded engine:

```bash
python dpi_mt.py test_dpi.pcap output.pcap --lbs 2 --fps 2
```

Run the modular engine with rules and thread settings:

```bash
python main_dpi.py test_dpi.pcap output.pcap --block-app YouTube --rules rules.txt --lbs 2 --fps 2 --verbose

# explicit JSON report target
python main_dpi.py test_dpi.pcap output.pcap --json-output report.json
```

### Viewer and Inspection Examples

Inspect packets one by one:

```bash
python main.py test_dpi.pcap 10
```

Extract SNI values from a capture:

```bash
python main_simple.py test_dpi.pcap
```

### Generate Test Data

Create or refresh the sample capture used by the examples:

```bash
python generate_test_pcap.py
```

## Windows PowerShell

Use one-line commands in PowerShell. Do not use Unix-style line continuation.

```powershell
python .\main_working.py test_dpi.pcap output.pcap --block-ip 192.168.1.50 --block-app YouTube --block-domain facebook
python .\dpi_mt.py test_dpi.pcap output.pcap --lbs 2 --fps 2 --json-output report.json
python .\generate_test_pcap.py
```

## Output Overview

The exact banner and counts depend on the script you run, but the output usually includes:

- The selected engine name and configuration
- Rules that were loaded or applied
- Packet counts and byte counts
- Non-IP/Unparsed packet totals
- Forwarded versus dropped packet totals
- Suspicious flow totals
- Application breakdown
- Detected domains or SNIs
- JSON report location and generated flow intelligence
- Output file location

### Rules File Format (Modular Engine)

The modular engine accepts `--rules <file>` entries in the format `<rule> <value>`.

Supported rules:

- `block-ip <ipv4>`
- `block-app <AppName>`
- `block-domain <substring>`
- `allow-domain <domain>`
- `block-regex <regex_pattern>`

Evaluation order:

1. `allow-domain` (allow immediately)
2. `block-ip`
3. `block-app`
4. `block-domain` (substring)
5. `block-regex`

Example output from the multi-threaded runner:

```text
DPI ENGINE v2.0 (Multi-threaded)
Load Balancers:  2    FPs per LB:  2    Total FPs:  4

[Rules] Blocked app: YouTube
[Reader] Processing packets...
[Reader] Done reading 77 packets

PROCESSING REPORT
Total Packets: 77
Forwarded: 69
Dropped: 8

APPLICATION BREAKDOWN
HTTPS     39
Unknown   16
YouTube    4 (BLOCKED)
DNS        4
Facebook   3

[Detected Domains/SNIs]
    - www.youtube.com -> YouTube
    - www.facebook.com -> Facebook
```

## Project Notes

- `main_working.py` is the recommended starting point if you want to understand the full flow with the least amount of code.
- `main_dpi.py` is the best choice if you want the modular engine with reusable components and rules-file support.
- `dpi_mt.py` is useful if you want to study the multi-threaded architecture directly.
- `python_dpi/` contains the reusable engine pieces used by the modular workflow.

## Troubleshooting

- If a PCAP will not open, confirm the file exists and is a valid capture.
- If PacketSentry does not classify a site, it may be encrypted in a way that does not expose SNI or Host information.
- If no packets appear in the output, check whether your blocking rules are too broad.
- If you are on Windows, prefer the PowerShell examples above and avoid Unix shell syntax.

## Summary

PacketSentry demonstrates how a Python DPI engine can:

- Parse real network traffic
- Track connections with a five-tuple
- Classify traffic from visible protocol metadata
- Apply block rules consistently across a flow
- Write a filtered capture for later analysis

If you want to explore the implementation, start with `main_working.py`, then compare it with `dpi_mt.py` and `python_dpi/dpi_engine.py`.
