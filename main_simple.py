from __future__ import annotations

import argparse

from python_dpi.packet_parser import parse
from python_dpi.pcap_reader import PcapReader
from python_dpi.sni_extractor import extract_sni


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file")
    args = parser.parse_args()

    reader = PcapReader()
    if not reader.open(args.pcap_file):
        return 1

    count = 0
    tls_count = 0
    print("Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break
        count += 1
        parsed = parse(raw)
        if parsed is None or not parsed.has_ip:
            continue

        print(f"Packet {count}: {parsed.src_ip}:{parsed.src_port} -> {parsed.dest_ip}:{parsed.dest_port}", end="")

        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            sni = extract_sni(parsed.payload_data)
            if sni:
                print(f" [SNI: {sni}]", end="")
                tls_count += 1

        print()

    print(f"\nTotal packets: {count}")
    print(f"SNI extracted: {tls_count}")
    reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
