from __future__ import annotations

from dataclasses import dataclass
import struct


@dataclass(slots=True)
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass(slots=True)
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass(slots=True)
class PcapPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self) -> None:
        self._file = None
        self._endian = "<"
        self.global_header: PcapGlobalHeader | None = None
        self.snaplen: int = 0

    def open(self, path: str) -> bool:
        self._file = None
        self.global_header = None
        self.snaplen = 0
        try:
            self._file = open(path, "rb")
        except OSError:
            self._file = None
            self.global_header = None
            self.snaplen = 0
            print(f"Error: Cannot open input file: {path}")
            return False

        magic = self._file.read(4)
        if len(magic) != 4:
            print("Error: Invalid PCAP file")
            self.close()
            self.global_header = None
            self.snaplen = 0
            return False

        magic_number = int.from_bytes(magic, "little")
        if magic_number in (0xA1B2C3D4, 0xA1B23C4D):
            self._endian = "<"
        elif magic_number in (0xD4C3B2A1, 0x4D3CB2A1):
            self._endian = ">"
        else:
            print("Error: Unsupported PCAP magic number")
            self.close()
            self.global_header = None
            self.snaplen = 0
            return False

        rest = self._file.read(20)
        if len(rest) != 20:
            print("Error: Truncated PCAP header")
            self.close()
            self.global_header = None
            self.snaplen = 0
            return False

        version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(self._endian + "HHiIII", rest)
        self.global_header = PcapGlobalHeader(
            magic_number=magic_number,
            version_major=version_major,
            version_minor=version_minor,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=network,
        )
        self.snaplen = snaplen
        return True

    def read_next_packet(self) -> PcapPacket | None:
        if self._file is None:
            return None

        header_bytes = self._file.read(16)
        if len(header_bytes) == 0:
            return None
        if len(header_bytes) != 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self._endian + "IIII", header_bytes)
        if incl_len < 0 or incl_len > self.snaplen:
            return None
        data = self._file.read(incl_len)
        if len(data) != incl_len:
            return None

        return PcapPacket(PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len), data)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
