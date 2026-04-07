from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
import struct
import sys

from .packet_parser import parse
from .pcap_reader import PcapReader
from .anomaly_detection import apply_ai_scoring
from .reporting import write_html_report, write_json_report
from .sni_extractor import extract_http_host, extract_sni
from .types import AppType, DetectionMethod, FiveTuple, Flow, app_type_to_string, ip_str_to_uint32, sni_to_app_type


@dataclass(slots=True)
class EngineConfig:
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    rules_file: str = ""
    verbose: bool = False
    suspicious_packet_threshold: int = 100
    suspicious_unknown_bytes_threshold: int = 1500
    suspicious_src_connection_threshold: int = 12
    suspicious_short_connection_duration_threshold: int = 1
    suspicious_short_connection_packets_threshold: int = 2
    suspicious_short_connection_repeat_threshold: int = 5


class _Rules:
    def __init__(self) -> None:
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.allow_domains: list[str] = []
        self.blocked_domains: list[str] = []
        self.blocked_regex: list[tuple[str, re.Pattern[str]]] = []

    @staticmethod
    def _normalize_host(value: str) -> str:
        host = value.strip().lower().rstrip(".")
        if host.count(":") == 1 and not host.startswith("["):
            host = host.split(":", 1)[0]
        return host

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

    def allow_domain(self, domain: str) -> None:
        self.allow_domains.append(domain.lower())
        print(f"[Rules] Allowed domain: {domain}")

    def block_regex(self, pattern: str) -> None:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            print(f"[Rules] Invalid regex pattern '{pattern}': {exc}")
            return
        self.blocked_regex.append((pattern, compiled))
        print(f"[Rules] Blocked regex: {pattern}")

    def evaluate(self, src_ip: int, dst_ip: int, app: AppType, sni: str) -> tuple[bool, str]:
        host = self._normalize_host(sni)

        # 1) Allowlist has highest priority.
        for domain in self.allow_domains:
            normalized_domain = self._normalize_host(domain)
            if not normalized_domain:
                continue
            if host == normalized_domain or host.endswith("." + normalized_domain):
                return False, ""

        # 2) Block by IP.
        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return True, "Blocked by IP rule"

        # 3) Block by app.
        if app in self.blocked_apps:
            return True, f"Blocked by App rule: {app_type_to_string(app)}"

        # 4) Block by domain substring.
        for domain in self.blocked_domains:
            normalized_domain = self._normalize_host(domain)
            if not normalized_domain:
                continue
            if host == normalized_domain or host.endswith("." + normalized_domain):
                return True, f"Blocked by Domain rule: {domain}"

        # 5) Block by regex pattern.
        for pattern_text, pattern in self.blocked_regex:
            if pattern.search(host):
                return True, f"Blocked by Regex rule: {pattern_text}"

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
                        elif rule in {"allow-domain", "allow", "allowlist-domain"}:
                            self.allow_domain(value)
                        elif rule in {"block-regex", "regex"}:
                            self.block_regex(value)
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

    def allow_domain(self, domain: str) -> None:
        self.rules.allow_domain(domain)

    def block_regex(self, pattern: str) -> None:
        self.rules.block_regex(pattern)

    def _mark_flow_suspicious(self, flow: Flow, reason: str) -> None:
        if flow.is_suspicious:
            if reason and reason not in flow.suspicious_reason:
                flow.suspicious_reason = f"{flow.suspicious_reason}; {reason}" if flow.suspicious_reason else reason
            return
        flow.is_suspicious = True
        flow.suspicious_reason = reason

    def _parse_dns_name(self, payload: bytes, offset: int, max_depth: int = 8) -> tuple[str, int] | None:
        labels: list[str] = []
        cursor = offset
        jumped = False
        next_offset = offset
        depth = 0

        while cursor < len(payload):
            length = payload[cursor]
            if length == 0:
                if not jumped:
                    next_offset = cursor + 1
                return ".".join(labels).lower(), next_offset

            # DNS name compression pointer.
            if (length & 0xC0) == 0xC0:
                if cursor + 1 >= len(payload):
                    return None
                pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
                if pointer >= len(payload):
                    return None
                if not jumped:
                    next_offset = cursor + 2
                cursor = pointer
                jumped = True
                depth += 1
                if depth > max_depth:
                    return None
                continue

            cursor += 1
            if cursor + length > len(payload):
                return None
            label_bytes = payload[cursor : cursor + length]
            try:
                labels.append(label_bytes.decode("ascii", errors="ignore"))
            except UnicodeDecodeError:
                labels.append("")
            cursor += length
            if not jumped:
                next_offset = cursor

        return None

    def _extract_dns_a_records(self, payload: bytes) -> list[tuple[int, str]]:
        if len(payload) < 12:
            return []

        flags = (payload[2] << 8) | payload[3]
        qdcount = (payload[4] << 8) | payload[5]
        ancount = (payload[6] << 8) | payload[7]

        # Process only DNS responses.
        if (flags & 0x8000) == 0:
            return []

        offset = 12
        question_domain = ""

        # Parse first question to recover requested domain.
        if qdcount > 0:
            parsed_name = self._parse_dns_name(payload, offset)
            if parsed_name is None:
                return []
            question_domain, offset = parsed_name
            if offset + 4 > len(payload):
                return []
            offset += 4  # qtype + qclass

            # Skip extra questions if present.
            for _ in range(1, qdcount):
                parsed_extra = self._parse_dns_name(payload, offset)
                if parsed_extra is None:
                    return []
                _, offset = parsed_extra
                if offset + 4 > len(payload):
                    return []
                offset += 4

        mappings: list[tuple[int, str]] = []
        for _ in range(ancount):
            parsed_answer_name = self._parse_dns_name(payload, offset)
            if parsed_answer_name is None:
                break
            answer_name, offset = parsed_answer_name

            if offset + 10 > len(payload):
                break
            rtype = (payload[offset] << 8) | payload[offset + 1]
            rclass = (payload[offset + 2] << 8) | payload[offset + 3]
            rdlength = (payload[offset + 8] << 8) | payload[offset + 9]
            offset += 10

            if offset + rdlength > len(payload):
                break

            rdata = payload[offset : offset + rdlength]
            offset += rdlength

            # IPv4 A record.
            if rtype == 1 and rclass == 1 and rdlength == 4:
                ip_uint = int.from_bytes(rdata, "big")
                domain = question_domain or answer_name
                if domain:
                    mappings.append((ip_uint, domain))

        return mappings

    def _detect_suspicious_flows(self, flows: dict[FiveTuple, Flow]) -> tuple[int, dict[str, int]]:
        src_conn_counts: dict[int, int] = defaultdict(int)
        src_short_conn_counts: dict[int, int] = defaultdict(int)

        for flow in flows.values():
            src_conn_counts[flow.tuple.src_ip] += 1
            if (
                flow.duration_seconds <= self.config.suspicious_short_connection_duration_threshold
                and flow.packet_count <= self.config.suspicious_short_connection_packets_threshold
            ):
                src_short_conn_counts[flow.tuple.src_ip] += 1

        suspicious_count = 0
        for flow in flows.values():
            if flow.packet_count > self.config.suspicious_packet_threshold:
                self._mark_flow_suspicious(flow, "High packet volume")

            if src_conn_counts[flow.tuple.src_ip] > self.config.suspicious_src_connection_threshold:
                self._mark_flow_suspicious(flow, "Too many connections from same source IP")

            if src_short_conn_counts[flow.tuple.src_ip] > self.config.suspicious_short_connection_repeat_threshold:
                if (
                    flow.duration_seconds <= self.config.suspicious_short_connection_duration_threshold
                    and flow.packet_count <= self.config.suspicious_short_connection_packets_threshold
                ):
                    self._mark_flow_suspicious(flow, "Frequent short connections")

            if (
                flow.app_type == AppType.UNKNOWN
                and flow.byte_count > self.config.suspicious_unknown_bytes_threshold
            ):
                self._mark_flow_suspicious(flow, "Unknown app with high traffic")

            if flow.is_suspicious:
                suspicious_count += 1

        reason_counts: dict[str, int] = defaultdict(int)
        for flow in flows.values():
            if not flow.is_suspicious or not flow.suspicious_reason:
                continue
            for reason in (segment.strip() for segment in flow.suspicious_reason.split(";")):
                if reason:
                    reason_counts[reason] += 1

        sorted_reason_counts = dict(sorted(reason_counts.items(), key=lambda item: item[1], reverse=True))
        return suspicious_count, sorted_reason_counts

    def process_file(
        self,
        input_file: str,
        output_file: str,
        json_output_file: str = "report.json",
        html_output_file: str = "",
    ) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        if reader.global_header is None:
            reader.close()
            return False

        gh = reader.global_header
        if gh.magic_number in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif gh.magic_number in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            print(f"Error: Unrecognized pcap magic number: 0x{gh.magic_number:08x}")
            reader.close()
            return False

        flows: dict[FiveTuple, Flow] = {}
        dns_map: dict[int, str] = {}
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

                    if parsed.has_udp and parsed.src_port == 53:
                        for resolved_ip, resolved_domain in self._extract_dns_a_records(parsed.payload_data):
                            dns_map[resolved_ip] = resolved_domain

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

                    if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
                        correlated_domain = dns_map.get(tuple_value.dst_ip)
                        if correlated_domain:
                            flow.sni = correlated_domain
                            flow.app_type = sni_to_app_type(correlated_domain)
                            flow.detection_method = DetectionMethod.DNS_CORRELATED

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

        suspicious_count, suspicious_reason_counts = self._detect_suspicious_flows(flows)
        ai_meta = apply_ai_scoring(flows)
        print(f"║ Suspicious Flows:   {suspicious_count:10d}                             ║")
        for reason, count in list(suspicious_reason_counts.items())[:3]:
            truncated_reason = reason[:32]
            print(f"║   {truncated_reason:<32}{count:>10d}                             ║")
        print(f"║ AI Model Enabled:   {str(bool(ai_meta['ai_enabled'])):<10}                             ║")
        risk_dist = ai_meta["risk_distribution"]
        print(f"║ Risk (L/M/H):       {risk_dist['Low']:>3d}/{risk_dist['Medium']:<3d}/{risk_dist['High']:<3d}                             ║")
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

        report_stats = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "forwarded": forwarded,
            "dropped": dropped,
            "non_ip_or_unparsed": self.filtered_nonip_or_unparsed_count,
            "suspicious_flows": suspicious_count,
            "suspicious_by_reason": suspicious_reason_counts,
            "risk_distribution": risk_dist,
            "ai_model_enabled": bool(ai_meta["ai_enabled"]),
        }

        if json_output_file:
            try:
                write_json_report(json_output_file, flows, report_stats)
                print(f"JSON report written to: {json_output_file}")
            except Exception as exc:
                print(f"Error writing JSON report '{json_output_file}': {exc}", file=sys.stderr)

        if html_output_file:
            try:
                write_html_report(html_output_file, flows, report_stats)
                print(f"HTML report written to: {html_output_file}")
            except Exception as exc:
                print(f"Error writing HTML report '{html_output_file}': {exc}", file=sys.stderr)

        print(f"\nOutput written to: {output_file}")
        return True
