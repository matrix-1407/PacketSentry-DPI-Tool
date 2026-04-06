from __future__ import annotations

import argparse
import struct
import threading
import time
from collections import defaultdict
import sys

from python_dpi.packet_parser import parse
from python_dpi.pcap_reader import PcapReader
from python_dpi.reporting import write_json_report
from python_dpi.sni_extractor import extract_http_host, extract_sni
from python_dpi.thread_safe_queue import ThreadSafeQueue
from python_dpi.types import AppType, DetectionMethod, FiveTuple, Flow, PacketJob, app_type_to_string, ip_str_to_uint32, sni_to_app_type


class Rules:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        with self._lock:
            self.blocked_ips.add(ip_str_to_uint32(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_name: str) -> None:
        with self._lock:
            for app in AppType:
                if app == AppType.APP_COUNT:
                    continue
                if app_type_to_string(app) == app_name:
                    self.blocked_apps.add(app)
                    print(f"[Rules] Blocked app: {app_name}")
                    return
        print(f"[Rules] Unknown app: {app_name}")

    def block_domain(self, domain: str) -> None:
        with self._lock:
            self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def evaluate(self, src_ip: int, app: AppType, sni: str) -> tuple[bool, str]:
        with self._lock:
            if src_ip in self.blocked_ips:
                return True, "Blocked by IP rule"
            if app in self.blocked_apps:
                return True, f"Blocked by App rule: {app_type_to_string(app)}"
            host = sni.lower()
            for domain in self.blocked_domains:
                if domain in host:
                    return True, f"Blocked by Domain rule: {domain}"
            return False, ""


class Stats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self._lock = threading.Lock()
        self.app_counts: dict[AppType, int] = defaultdict(int)
        self.detected_snis: dict[str, AppType] = {}

    def record_app(self, app: AppType, sni: str) -> None:
        with self._lock:
            self.app_counts[app] += 1
            if sni:
                self.detected_snis[sni] = app


class FastPath:
    def __init__(self, fp_id: int, rules: Rules, stats: Stats, output_queue: ThreadSafeQueue[PacketJob]) -> None:
        self.id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self.flows: dict[FiveTuple, Flow] = {}
        self.running = False
        self.thread: threading.Thread | None = None
        self.processed_count = 0

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.input_queue.shutdown()
        if self.thread is not None:
            self.thread.join()

    def run(self) -> None:
        while self.running:
            pkt = self.input_queue.pop_with_timeout(0.1)
            if pkt is None:
                continue
            self.processed_count += 1

            flow = self.flows.get(pkt.tuple)
            if flow is None:
                flow = Flow(pkt.tuple)
                self.flows[pkt.tuple] = flow
            flow.packet_count += 1
            flow.byte_count += len(pkt.data)
            if flow.packet_count == 1:
                flow.first_seen_timestamp = pkt.ts_sec
            flow.last_seen_timestamp = pkt.ts_sec

            self.classify_flow(pkt, flow)

            if not flow.blocked:
                blocked, reason = self.rules.evaluate(pkt.tuple.src_ip, flow.app_type, flow.sni)
                flow.blocked = blocked
                if blocked:
                    flow.block_reason = reason

            self.stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self.stats.dropped += 1
            else:
                self.stats.forwarded += 1
                self.output_queue.push(pkt)

    def classify_flow(self, pkt: PacketJob, flow: Flow) -> None:
        if flow.app_type not in (AppType.UNKNOWN, AppType.HTTP, AppType.HTTPS) and flow.sni:
            return

        payload = pkt.data[pkt.payload_offset : pkt.payload_offset + pkt.payload_length]

        if pkt.tuple.dst_port == 443 and len(payload) > 5:
            sni = extract_sni(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.detection_method = DetectionMethod.TLS_SNI
                return

        if pkt.tuple.dst_port == 80 and len(payload) > 10:
            host = extract_http_host(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.detection_method = DetectionMethod.HTTP_HOST
                return

        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.detection_method = DetectionMethod.DNS
            return

        if flow.app_type == AppType.UNKNOWN and pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
            flow.detection_method = DetectionMethod.PORT_BASED
        elif flow.app_type == AppType.UNKNOWN and pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP
            flow.detection_method = DetectionMethod.PORT_BASED


class LoadBalancer:
    def __init__(self, lb_id: int, fps: list[FastPath]) -> None:
        self.id = lb_id
        self.fps = fps
        self.num_fps = len(fps)
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self.running = False
        self.thread: threading.Thread | None = None
        self.dispatched_count = 0

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.input_queue.shutdown()
        if self.thread is not None:
            self.thread.join()

    def run(self) -> None:
        while self.running:
            pkt = self.input_queue.pop_with_timeout(0.1)
            if pkt is None:
                continue
            fp_idx = hash(pkt.tuple) % self.num_fps
            self.fps[fp_idx].input_queue.push(pkt)
            self.dispatched_count += 1


class DPIEngine:
    def __init__(self, num_lbs: int = 2, fps_per_lb: int = 2) -> None:
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        total_fps = num_lbs * fps_per_lb
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║              DPI ENGINE v2.0 (Multi-threaded)                 ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {num_lbs:2d}    FPs per LB: {fps_per_lb:2d}    Total FPs: {total_fps:2d}     ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        self.rules = Rules()
        self.stats = Stats()
        self.output_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self.fps: list[FastPath] = [FastPath(i, self.rules, self.stats, self.output_queue) for i in range(total_fps)]
        self.lbs: list[LoadBalancer] = []
        for lb in range(num_lbs):
            start = lb * fps_per_lb
            self.lbs.append(LoadBalancer(lb, self.fps[start : start + fps_per_lb]))

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)

    def process(self, input_file: str, output_file: str, json_output_file: str = "report.json") -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        try:
            output = open(output_file, "wb")
        except OSError:
            print("Cannot open output file")
            return False

        gh = reader.global_header
        output.write(struct.pack("<IHHiIII", gh.magic_number, gh.version_major, gh.version_minor, gh.thiszone, gh.sigfigs, gh.snaplen, gh.network))

        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_running = True

        def output_thread_func() -> None:
            while output_running or not self.output_queue.empty():
                pkt = self.output_queue.pop_with_timeout(0.05)
                if pkt is None:
                    continue
                output.write(struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec, len(pkt.data), len(pkt.data)))
                output.write(pkt.data)

        output_thread = threading.Thread(target=output_thread_func, daemon=True)
        output_thread.start()

        print("[Reader] Processing packets...")
        pkt_id = 0
        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break
            parsed = parse(raw)
            if parsed is None:
                continue
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            tuple_value = FiveTuple(
                src_ip=ip_str_to_uint32(parsed.src_ip),
                dst_ip=ip_str_to_uint32(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )
            payload_offset = len(raw.data) - parsed.payload_length if parsed.payload_length > 0 else len(raw.data)
            pkt = PacketJob(
                packet_id=pkt_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=tuple_value,
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=payload_offset,
                payload_length=parsed.payload_length,
            )
            pkt_id += 1

            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            lb_idx = hash(tuple_value) % len(self.lbs)
            self.lbs[lb_idx].input_queue.push(pkt)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        time.sleep(0.5)
        for lb in self.lbs:
            lb.stop()
        for fp in self.fps:
            fp.stop()

        output_running = False
        self.output_queue.shutdown()
        output_thread.join()
        output.close()

        all_flows: dict[FiveTuple, Flow] = {}
        for fp in self.fps:
            all_flows.update(fp.flows)

        if json_output_file:
            write_json_report(
                json_output_file,
                all_flows,
                {
                    "total_packets": self.stats.total_packets,
                    "total_bytes": self.stats.total_bytes,
                    "forwarded": self.stats.forwarded,
                    "dropped": self.stats.dropped,
                    "non_ip_or_unparsed": 0,
                },
            )
            print(f"JSON report written to: {json_output_file}")

        self.print_report()
        return True

    def print_report(self) -> None:
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.stats.total_packets:12d}                           ║")
        print(f"║ Total Bytes:        {self.stats.total_bytes:12d}                           ║")
        print(f"║ TCP Packets:        {self.stats.tcp_packets:12d}                           ║")
        print(f"║ UDP Packets:        {self.stats.udp_packets:12d}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {self.stats.forwarded:12d}                           ║")
        print(f"║ Dropped:            {self.stats.dropped:12d}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                             ║")
        for i, lb in enumerate(self.lbs):
            print(f"║   LB{i} dispatched:   {lb.dispatched_count:12d}                           ║")
        for i, fp in enumerate(self.fps):
            print(f"║   FP{i} processed:    {fp.processed_count:12d}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                       ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        total = self.stats.total_packets
        for app, count in sorted(self.stats.app_counts.items(), key=lambda kv: kv[1], reverse=True):
            pct = (100.0 * count / total) if total else 0
            bar = "#" * int(pct / 5)
            print(f"║ {app_type_to_string(app):<15}{count:>8d} {pct:5.1f}% {bar:<20}  ║")
        print("╚══════════════════════════════════════════════════════════════╝")

        if self.stats.detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in self.stats.detected_snis.items():
                print(f"  - {sni} -> {app_type_to_string(app)}")


def print_usage(prog: str) -> None:
    print(
        f"""
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection
========================================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
    --json-output <file>   Write JSON report (default: report.json)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
"""
    )


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("input", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--json-output", default="report.json")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    args = parser.parse_args()

    if not args.input or not args.output:
        print_usage("python dpi_mt.py")
        return 1

    engine = DPIEngine(args.lbs, args.fps)
    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for dom in args.block_domain:
        engine.block_domain(dom)

    ok = engine.process(args.input, args.output, json_output_file=args.json_output)
    if not ok:
        return 1
    print(f"\nOutput written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
