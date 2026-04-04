from __future__ import annotations

import argparse
from datetime import datetime

from python_dpi.packet_parser import EtherType, parse, protocol_to_string, tcp_flags_to_string
from python_dpi.pcap_reader import PcapReader


def print_packet_summary(pkt, packet_num: int) -> None:
    ts = datetime.fromtimestamp(pkt.timestamp_sec)
    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {ts.strftime('%Y-%m-%d %H:%M:%S')}.{pkt.timestamp_usec:06d}")

    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    etype_label = ""
    if pkt.ether_type == EtherType.IPv4:
        etype_label = " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        etype_label = " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        etype_label = " (ARP)"
    print(f"  EtherType:       0x{pkt.ether_type:04x}{etype_label}")

    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")

    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {tcp_flags_to_string(pkt.tcp_flags)}")

    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview = pkt.payload_data[:32]
        hex_preview = " ".join(f"{b:02x}" for b in preview)
        suffix = " ..." if pkt.payload_length > 32 else ""
        print(f"  Preview: {hex_preview}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file")
    parser.add_argument("max_packets", nargs="?", type=int, default=-1)
    args = parser.parse_args()

    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    reader = PcapReader()
    if not reader.open(args.pcap_file):
        return 1

    print("\n--- Reading packets ---")

    packet_count = 0
    parse_errors = 0
    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break
        packet_count += 1
        parsed = parse(raw)
        if parsed is None:
            print(f"Warning: Failed to parse packet #{packet_count}")
            parse_errors += 1
        else:
            print_packet_summary(parsed, packet_count)

        if args.max_packets > 0 and packet_count >= args.max_packets:
            print(f"\n(Stopped after {args.max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
