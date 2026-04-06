from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class EtherType(IntEnum):
    IPv4 = 0x0800
    ARP = 0x0806
    VLAN = 0x8100
    IPv6 = 0x86DD


@dataclass(slots=True)
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    tcp_flags: int = 0
    payload_data: bytes = b""
    payload_length: int = 0


def protocol_to_string(protocol: int) -> str:
    if protocol == 6:
        return "TCP"
    if protocol == 17:
        return "UDP"
    if protocol == 1:
        return "ICMP"
    if protocol == 58:
        return "ICMPv6"
    return str(protocol)


def tcp_flags_to_string(flags: int) -> str:
    names = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    parts = [name for bit, name in names if flags & bit]
    return ",".join(parts) if parts else "NONE"


def _mac_to_str(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _ipv4_to_str(data: bytes) -> str:
    return ".".join(str(byte) for byte in data)


def parse(packet) -> ParsedPacket | None:
    data = packet.data if hasattr(packet, "data") else packet
    timestamp_sec = getattr(getattr(packet, "header", None), "ts_sec", 0)
    timestamp_usec = getattr(getattr(packet, "header", None), "ts_usec", 0)

    if len(data) < 14:
        return None

    parsed = ParsedPacket(timestamp_sec=timestamp_sec, timestamp_usec=timestamp_usec)
    parsed.dest_mac = _mac_to_str(data[0:6])
    parsed.src_mac = _mac_to_str(data[6:12])
    ether_type = int.from_bytes(data[12:14], "big")
    offset = 14

    if ether_type == EtherType.VLAN and len(data) >= 18:
        ether_type = int.from_bytes(data[16:18], "big")
        offset = 18

    parsed.ether_type = ether_type

    if ether_type == EtherType.IPv4:
        if len(data) < offset + 20:
            return parsed
        version_ihl = data[offset]
        parsed.ip_version = version_ihl >> 4
        ihl_words = version_ihl & 0x0F
        if ihl_words < 5:
            return parsed
        ihl = ihl_words * 4
        if len(data) < offset + ihl:
            return parsed

        parsed.has_ip = True
        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]
        parsed.src_ip = _ipv4_to_str(data[offset + 12 : offset + 16])
        parsed.dest_ip = _ipv4_to_str(data[offset + 16 : offset + 20])

        transport_offset = offset + ihl
        if parsed.protocol == 6 and len(data) >= transport_offset + 20:
            parsed.has_tcp = True
            parsed.src_port = int.from_bytes(data[transport_offset : transport_offset + 2], "big")
            parsed.dest_port = int.from_bytes(data[transport_offset + 2 : transport_offset + 4], "big")
            parsed.seq_number = int.from_bytes(data[transport_offset + 4 : transport_offset + 8], "big")
            parsed.ack_number = int.from_bytes(data[transport_offset + 8 : transport_offset + 12], "big")
            data_offset_words = data[transport_offset + 12] >> 4
            if data_offset_words < 5:
                parsed.has_tcp = False
                parsed.tcp_flags = data[transport_offset + 13]
                return parsed
            data_offset = data_offset_words * 4
            parsed.tcp_flags = data[transport_offset + 13]
            payload_offset = transport_offset + data_offset
            if payload_offset <= len(data):
                parsed.payload_data = data[payload_offset:]
                parsed.payload_length = len(parsed.payload_data)
        elif parsed.protocol == 17 and len(data) >= transport_offset + 8:
            parsed.has_udp = True
            parsed.src_port = int.from_bytes(data[transport_offset : transport_offset + 2], "big")
            parsed.dest_port = int.from_bytes(data[transport_offset + 2 : transport_offset + 4], "big")
            payload_offset = transport_offset + 8
            if payload_offset <= len(data):
                parsed.payload_data = data[payload_offset:]
                parsed.payload_length = len(parsed.payload_data)
        else:
            parsed.payload_data = data[transport_offset:]
            parsed.payload_length = len(parsed.payload_data)

    elif ether_type == EtherType.IPv6:
        parsed.ip_version = 6
        parsed.has_ip = True

    return parsed
