from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import struct

from .packet_parser import parse
from .pcap_reader import PcapReader
from .reporting import write_json_report
from .sni_extractor import extract_http_host, extract_sni
from .types import AppType, DetectionMethod, FiveTuple, Flow, app_type_to_string, ip_str_to_uint32, sni_to_app_type


@dataclass(slots=True)
class EngineConfig:
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    rules_file: str = ""
    verbose: bool = False


class _Rules:
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
        self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def evaluate(self, src_ip: int, dst_ip: int, app: AppType, sni: str) -> tuple[bool, str]:
        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return True, "Blocked by IP rule"
        if app in self.blocked_apps:
            return True, f"Blocked by App rule: {app_type_to_string(app)}"
        host = sni.lower()
        for domain in self.blocked_domains:
            if domain in host:
                return True, f"Blocked by Domain rule: {domain}"
        return False, ""


class DPIEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self.rules = _Rules()
        self.filtered_nonip_or_unparsed_count = 0

    def initialize(self) -> bool:
        total_fps = self.config.num_load_balancers * self.config.fps_per_lb
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0                            ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {self.config.num_load_balancers:2d}    FPs per LB: {self.config.fps_per_lb:2d}    Total FPs: {total_fps:2d}     ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")
        return True

    def load_rules(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split(None, 1)
                    if len(parts) != 2:
                        continue
                    rule, value = parts[0].lower(), parts[1].strip()
                    try:
                        if rule in {"block-ip", "ip"}:
                            self.block_ip(value)
                        elif rule in {"block-app", "app"}:
                            self.block_app(value)
                        elif rule in {"block-domain", "domain"}:
                            self.block_domain(value)
                    except (ValueError, OSError) as exc:
                        print(f"[Rules] Skipping invalid rule on line {line_number}: {stripped} ({exc})")
        except OSError:
            print(f"Error: Cannot read rules file: {path}")
            return False
        return True

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)

    def process_file(self, input_file: str, output_file: str, json_output_file: str = "report.json") -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        if reader.global_header is None:
            reader.close()
            return False

        gh = reader.global_header
        if gh.magic_number in (0xA1B2C3D4, 0xA1B2C34D):
            endian = "<"
        elif gh.magic_number in (0xD4C3B2A1, 0x4DC3B2A1):
            endian = ">"
        else:
            print(f"Error: Unrecognized pcap magic number: 0x{gh.magic_number:08x}")
            reader.close()
            return False

        flows: dict[FiveTuple, Flow] = {}
        app_stats: dict[AppType, int] = defaultdict(int)
        total_packets = 0
        total_bytes = 0
        forwarded = 0
        dropped = 0

        try:
            with open(output_file, "wb") as output:
                output.write(struct.pack(endian + "IHHiIII", gh.magic_number, gh.version_major, gh.version_minor, gh.thiszone, gh.sigfigs, gh.snaplen, gh.network))

                print("[DPI] Processing packets...")

                while True:
                    raw = reader.read_next_packet()
                    if raw is None:
                        break
                    total_packets += 1
                    total_bytes += len(raw.data)

                    parsed = parse(raw)
                    if parsed is None:
                        self.filtered_nonip_or_unparsed_count += 1
                        if self.config.verbose:
                            print(f"[Warn] Could not parse packet {total_packets}")
                        continue
                    if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                        self.filtered_nonip_or_unparsed_count += 1
                        continue

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

                    flow.packet_count += 1
                    flow.byte_count += len(raw.data)
                    if flow.packet_count == 1:
                        flow.first_seen_timestamp = raw.header.ts_sec
                    flow.last_seen_timestamp = raw.header.ts_sec

                    if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
                        sni = extract_sni(parsed.payload_data)
                        if sni:
                            flow.sni = sni
                            flow.app_type = sni_to_app_type(sni)
                            flow.detection_method = DetectionMethod.TLS_SNI

                    if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
                        host = extract_http_host(parsed.payload_data)
                        if host:
                            flow.sni = host
                            flow.app_type = sni_to_app_type(host)
                            flow.detection_method = DetectionMethod.HTTP_HOST

                    if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
                        flow.app_type = AppType.DNS
                        flow.detection_method = DetectionMethod.DNS

                    if flow.app_type == AppType.UNKNOWN:
                        if parsed.dest_port == 443:
                            flow.app_type = AppType.HTTPS
                            flow.detection_method = DetectionMethod.PORT_BASED
                        elif parsed.dest_port == 80:
                            flow.app_type = AppType.HTTP
                            flow.detection_method = DetectionMethod.PORT_BASED
                        elif flow.detection_method == DetectionMethod.UNKNOWN:
                            flow.detection_method = DetectionMethod.UNKNOWN

                    if not flow.blocked:
                        blocked, reason = self.rules.evaluate(tuple_value.src_ip, tuple_value.dst_ip, flow.app_type, flow.sni)
                        flow.blocked = blocked
                        if blocked:
                            flow.block_reason = reason
                        if flow.blocked:
                            msg = f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}"
                            if flow.sni:
                                msg += f": {flow.sni}"
                            if flow.block_reason:
                                msg += f" | {flow.block_reason}"
                            msg += ")"
                            print(msg)

                    app_stats[flow.app_type] += 1

                    if flow.blocked:
                        dropped += 1
                    else:
                        forwarded += 1
                        output.write(
                            struct.pack(
                                endian + "IIII",
                                raw.header.ts_sec,
                                raw.header.ts_usec,
                                raw.header.incl_len,
                                raw.header.orig_len,
                            )
                        )
                        output.write(raw.data)
        finally:
            reader.close()

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {total_packets:10d}                             ║")
        print(f"║ Total Bytes:        {total_bytes:10d}                             ║")
        print(f"║ Forwarded:          {forwarded:10d}                             ║")
        print(f"║ Dropped:            {dropped:10d}                             ║")
        print(f"║ Non-IP/Unparsed:    {self.filtered_nonip_or_unparsed_count:10d}                             ║")
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
        unique_snis: dict[str, AppType] = {}
        for flow in flows.values():
            if flow.sni:
                unique_snis[flow.sni] = flow.app_type
        for sni, app in unique_snis.items():
            print(f"  - {sni} -> {app_type_to_string(app)}")

        if json_output_file:
            write_json_report(
                json_output_file,
                flows,
                {
                    "total_packets": total_packets,
                    "total_bytes": total_bytes,
                    "forwarded": forwarded,
                    "dropped": dropped,
                    "non_ip_or_unparsed": self.filtered_nonip_or_unparsed_count,
                },
            )
            print(f"JSON report written to: {json_output_file}")

        print(f"\nOutput written to: {output_file}")
        return True
