from __future__ import annotations

import argparse
import sys
import textwrap

from python_dpi.dpi_engine import DPIEngine, EngineConfig


SUSPICIOUS_PROFILES = {
    "balanced": {
        "suspicious_packet_threshold": 100,
        "suspicious_unknown_bytes_threshold": 1500,
        "suspicious_src_connection_threshold": 12,
        "suspicious_short_connection_duration_threshold": 1,
        "suspicious_short_connection_packets_threshold": 2,
        "suspicious_short_connection_repeat_threshold": 5,
    },
    "strict": {
        "suspicious_packet_threshold": 60,
        "suspicious_unknown_bytes_threshold": 900,
        "suspicious_src_connection_threshold": 8,
        "suspicious_short_connection_duration_threshold": 1,
        "suspicious_short_connection_packets_threshold": 3,
        "suspicious_short_connection_repeat_threshold": 3,
    },
    "relaxed": {
        "suspicious_packet_threshold": 160,
        "suspicious_unknown_bytes_threshold": 2800,
        "suspicious_src_connection_threshold": 20,
        "suspicious_short_connection_duration_threshold": 1,
        "suspicious_short_connection_packets_threshold": 2,
        "suspicious_short_connection_repeat_threshold": 9,
    },
}


def resolve_suspicious_thresholds(args: argparse.Namespace) -> dict[str, int]:
    thresholds = dict(SUSPICIOUS_PROFILES[args.suspicious_profile])

    overrides = {
        "suspicious_packet_threshold": args.suspicious_packet_threshold,
        "suspicious_unknown_bytes_threshold": args.suspicious_unknown_bytes_threshold,
        "suspicious_src_connection_threshold": args.suspicious_src_connection_threshold,
        "suspicious_short_connection_duration_threshold": args.suspicious_short_connection_duration_threshold,
        "suspicious_short_connection_packets_threshold": args.suspicious_short_connection_packets_threshold,
        "suspicious_short_connection_repeat_threshold": args.suspicious_short_connection_repeat_threshold,
    }

    for key, value in overrides.items():
        if value is not None:
            thresholds[key] = value

    return thresholds


def print_usage(prog: str) -> None:
        print(
                textwrap.dedent(
                        f"""
                        Usage: {prog} <input.pcap> <output.pcap> [options]

                        Options:
                            --block-ip <ip>
                            --block-app <app>
                            --block-domain <dom>
                            --allow-domain <dom>
                            --block-regex <pattern>
                            --rules <file>
                            --json-output <file>
                            --lbs <n>
                            --fps <n>
                            --suspicious-profile <balanced|strict|relaxed>
                            --suspicious-packet-threshold <n>
                            --suspicious-unknown-bytes-threshold <n>
                            --suspicious-src-connection-threshold <n>
                            --suspicious-short-connection-duration-threshold <n>
                            --suspicious-short-connection-packets-threshold <n>
                            --suspicious-short-connection-repeat-threshold <n>
                            --verbose
                        """
                ).strip()
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
    parser.add_argument("--allow-domain", action="append", default=[])
    parser.add_argument("--block-regex", action="append", default=[])
    parser.add_argument("--rules", default="")
    parser.add_argument("--json-output", default="report.json")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("--suspicious-profile", choices=sorted(SUSPICIOUS_PROFILES.keys()), default="balanced")
    parser.add_argument("--suspicious-packet-threshold", type=int)
    parser.add_argument("--suspicious-unknown-bytes-threshold", type=int)
    parser.add_argument("--suspicious-src-connection-threshold", type=int)
    parser.add_argument("--suspicious-short-connection-duration-threshold", type=int)
    parser.add_argument("--suspicious-short-connection-packets-threshold", type=int)
    parser.add_argument("--suspicious-short-connection-repeat-threshold", type=int)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--help", "-h", action="store_true")
    args = parser.parse_args()

    if args.help or not args.input_file or not args.output_file:
        print_usage("python main_dpi.py")
        return 0 if args.help else 1

    thresholds = resolve_suspicious_thresholds(args)
    for threshold_name, threshold_value in thresholds.items():
        if threshold_value <= 0:
            print(f"Invalid value for {threshold_name}: {threshold_value} (must be > 0)")
            return 1

    config = EngineConfig(
        num_load_balancers=args.lbs,
        fps_per_lb=args.fps,
        rules_file=args.rules,
        verbose=args.verbose,
        suspicious_packet_threshold=thresholds["suspicious_packet_threshold"],
        suspicious_unknown_bytes_threshold=thresholds["suspicious_unknown_bytes_threshold"],
        suspicious_src_connection_threshold=thresholds["suspicious_src_connection_threshold"],
        suspicious_short_connection_duration_threshold=thresholds["suspicious_short_connection_duration_threshold"],
        suspicious_short_connection_packets_threshold=thresholds["suspicious_short_connection_packets_threshold"],
        suspicious_short_connection_repeat_threshold=thresholds["suspicious_short_connection_repeat_threshold"],
    )

    engine = DPIEngine(config)
    if not engine.initialize():
        print("Failed to initialize DPI engine")
        return 1

    if args.rules:
        engine.load_rules(args.rules)

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)
    for domain in args.allow_domain:
        engine.allow_domain(domain)
    for pattern in args.block_regex:
        engine.block_regex(pattern)

    if not engine.process_file(args.input_file, args.output_file, json_output_file=args.json_output):
        print("Failed to process file")
        return 1

    print("\nProcessing complete!")
    print(f"Output written to: {args.output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

