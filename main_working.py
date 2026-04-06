from __future__ import annotations

import argparse
import struct
from collections import defaultdict
import sys

from python_dpi.packet_parser import parse
from python_dpi.pcap_reader import PcapReader
from python_dpi.sni_extractor import extract_http_host, extract_sni
from python_dpi.types import AppType, FiveTuple, app_type_to_string, ip_str_to_uint32, sni_to_app_type


class Flow:
    def __init__(self, tuple_value: FiveTuple) -> None:
        self.tuple = tuple_value
        self.app_type = AppType.UNKNOWN
        self.sni = ""
        self.packets = 0
        self.bytes = 0
        self.blocked = False


class BlockingRules:
    def __init__(self) -> None:
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(ip_str_to_uint32(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_name: str) -> None:
        for app in AppType:
            if app == AppType.APP_COUNT:
                continue
            if app_type_to_string(app) == app_name:
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {app_name}")
                return
        print(f"[Rules] Unknown app: {app_name}")

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        return any(domain in sni for domain in self.blocked_domains)


def print_usage() -> None:
    print(
        """
DPI Engine - Deep Packet Inspection System
==========================================

Usage: python main_working.py <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
"""
    )


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("input_file", nargs="?")
    parser.add_argument("output_file", nargs="?")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    args = parser.parse_args()

    if not args.input_file or not args.output_file:
        print_usage()
        return 1

    rules = BlockingRules()
    for value in args.block_ip:
        rules.block_ip(value)
    for value in args.block_app:
        rules.block_app(value)
    for value in args.block_domain:
        rules.block_domain(value)

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader()
    if not reader.open(args.input_file):
        return 1

    try:
        output = open(args.output_file, "wb")
    except OSError:
        print("Error: Cannot open output file")
        return 1

    gh = reader.global_header
    output.write(struct.pack("<IHHiIII", gh.magic_number, gh.version_major, gh.version_minor, gh.thiszone, gh.sigfigs, gh.snaplen, gh.network))

    flows: dict[FiveTuple, Flow] = {}
    app_stats: dict[AppType, int] = defaultdict(int)
    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    forwarded = 0
    dropped = 0

    print("[DPI] Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break
        total_packets += 1
        total_bytes += len(raw.data)
        parsed = parse(raw)
        if parsed is None:
            continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        if parsed.has_tcp:
            tcp_packets += 1
        elif parsed.has_udp:
            udp_packets += 1

        tuple_value = FiveTuple(
            src_ip=ip_str_to_uint32(parsed.src_ip),
            dst_ip=ip_str_to_uint32(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        flow = flows.get(tuple_value)
        if flow is None:
            flow = Flow(tuple_value)
            flows[tuple_value] = flow

        flow.packets += 1
        flow.bytes += len(raw.data)

        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
            sni = extract_sni(parsed.payload_data)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)

        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
            host = extract_http_host(parsed.payload_data)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)

        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS

        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_value.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                msg = f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}"
                if flow.sni:
                    msg += f": {flow.sni}"
                msg += ")"
                print(msg)

        app_stats[flow.app_type] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            output.write(struct.pack("<IIII", raw.header.ts_sec, raw.header.ts_usec, len(raw.data), len(raw.data)))
            output.write(raw.data)

    reader.close()
    output.close()

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:10d}                             ║")
    print(f"║ Total Bytes:        {total_bytes:10d}                             ║")
    print(f"║ TCP Packets:        {tcp_packets:10d}                             ║")
    print(f"║ UDP Packets:        {udp_packets:10d}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Forwarded:          {forwarded:10d}                             ║")
    print(f"║ Dropped:            {dropped:10d}                             ║")
    print(f"║ Active Flows:       {len(flows):10d}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda kv: kv[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets else 0
        bar = "#" * int(pct / 5)
        print(f"║ {app_type_to_string(app):<15}{count:>8d} {pct:5.1f}% {bar:<20}  ║")

    print("╚══════════════════════════════════════════════════════════════╝")
    print("\n[Detected Applications/Domains]")
    unique_snis = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type
    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {args.output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
