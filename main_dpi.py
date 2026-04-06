from __future__ import annotations

import argparse
import sys

from python_dpi.dpi_engine import DPIEngine, EngineConfig


def print_usage(prog: str) -> None:
    print(
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
  --verbose
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
    parser.add_argument("--allow-domain", action="append", default=[])
    parser.add_argument("--block-regex", action="append", default=[])
    parser.add_argument("--rules", default="")
    parser.add_argument("--json-output", default="report.json")
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--help", "-h", action="store_true")
    args = parser.parse_args()

    if args.help or not args.input_file or not args.output_file:
        print_usage("python main_dpi.py")
        return 0 if args.help else 1

    config = EngineConfig(
        num_load_balancers=args.lbs,
        fps_per_lb=args.fps,
        rules_file=args.rules,
        verbose=args.verbose,
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

