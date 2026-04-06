from __future__ import annotations

import re


_HOST_RE = re.compile(r"(?im)^host:\s*([^\r\n]+)")


def extract_http_host(payload: bytes) -> str:
    if not payload:
        return ""
    text = payload.decode("latin1", errors="ignore")
    match = _HOST_RE.search(text)
    if not match:
        return ""
    return match.group(1).strip().split(":", 1)[0].lower()


def extract_sni(payload: bytes) -> str:
    if len(payload) < 5 or payload[0] != 0x16:
        return ""

    record_length = int.from_bytes(payload[3:5], "big")
    record_end = min(5 + record_length, len(payload))
    if record_end <= 5:
        return ""

    offset = 5
    if offset + 4 > record_end or payload[offset] != 0x01:
        return ""

    handshake_length = int.from_bytes(payload[offset + 1 : offset + 4], "big")
    handshake_end = min(offset + 4 + handshake_length, record_end)
    offset += 4

    if offset + 2 + 32 > handshake_end:
        return ""
    offset += 2 + 32

    if offset >= handshake_end:
        return ""
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > handshake_end:
        return ""
    cipher_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2 + cipher_length

    if offset >= handshake_end:
        return ""
    compression_length = payload[offset]
    offset += 1 + compression_length

    if offset + 2 > handshake_end:
        return ""
    extensions_length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    extensions_end = min(offset + extensions_length, handshake_end)

    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(payload[offset : offset + 2], "big")
        extension_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4
        extension_data = payload[offset : offset + extension_length]
        if extension_type == 0x0000:
            if len(extension_data) < 2:
                return ""
            list_length = int.from_bytes(extension_data[0:2], "big")
            inner = 2
            limit = min(2 + list_length, len(extension_data))
            while inner + 3 <= limit:
                name_type = extension_data[inner]
                name_length = int.from_bytes(extension_data[inner + 1 : inner + 3], "big")
                inner += 3
                name = extension_data[inner : inner + name_length].decode("ascii", errors="ignore").strip().lower()
                if name_type == 0 and name:
                    return name
                inner += name_length
        offset += extension_length

    return ""
