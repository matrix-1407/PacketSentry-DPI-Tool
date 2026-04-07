from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import ipaddress


class DetectionMethod:
    UNKNOWN = "UNKNOWN"
    TLS_SNI = "TLS_SNI"
    HTTP_HOST = "HTTP_HOST"
    DNS = "DNS"
    DNS_CORRELATED = "DNS_CORRELATED"
    PORT_BASED = "PORT_BASED"


class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    YOUTUBE = 4
    FACEBOOK = 5
    GOOGLE = 6
    GITHUB = 7
    INSTAGRAM = 8
    TWITTER = 9
    AMAZON = 10
    NETFLIX = 11
    DISCORD = 12
    ZOOM = 13
    TELEGRAM = 14
    TIKTOK = 15
    SPOTIFY = 16
    CLOUDFLARE = 17
    MICROSOFT = 18
    APPLE = 19
    APP_COUNT = 20


_APP_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.YOUTUBE: "YouTube",
    AppType.FACEBOOK: "Facebook",
    AppType.GOOGLE: "Google",
    AppType.GITHUB: "GitHub",
    AppType.INSTAGRAM: "Instagram",
    AppType.TWITTER: "Twitter",
    AppType.AMAZON: "Amazon",
    AppType.NETFLIX: "Netflix",
    AppType.DISCORD: "Discord",
    AppType.ZOOM: "Zoom",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.CLOUDFLARE: "Cloudflare",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
}


def app_type_to_string(app: AppType) -> str:
    return _APP_NAMES.get(app, "Unknown")


def ip_str_to_uint32(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def _host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _host_matches_any(host: str, domains: tuple[str, ...]) -> bool:
    return any(_host_matches(host, domain) for domain in domains)


def sni_to_app_type(hostname: str) -> AppType:
    host = hostname.strip().lower().rstrip(".")

    if _host_matches_any(host, ("youtube.com", "youtu.be")):
        return AppType.YOUTUBE
    if _host_matches_any(host, ("facebook.com", "fbcdn.net", "fbsbx.com")):
        return AppType.FACEBOOK
    if _host_matches_any(host, ("google.com", "gstatic.com", "googleapis.com", "googleusercontent.com")):
        return AppType.GOOGLE
    if _host_matches_any(host, ("github.com", "githubusercontent.com")):
        return AppType.GITHUB
    if _host_matches_any(host, ("instagram.com",)):
        return AppType.INSTAGRAM
    if (
        _host_matches_any(host, ("twitter.com", "x.com", "t.co"))
    ):
        return AppType.TWITTER
    if _host_matches_any(host, ("amazon.com", "amazonaws.com", "aws.amazon.com")):
        return AppType.AMAZON
    if _host_matches_any(host, ("netflix.com",)):
        return AppType.NETFLIX
    if _host_matches_any(host, ("discord.com",)):
        return AppType.DISCORD
    if _host_matches_any(host, ("zoom.us",)):
        return AppType.ZOOM
    if _host_matches_any(host, ("telegram.org",)):
        return AppType.TELEGRAM
    if _host_matches_any(host, ("tiktok.com",)):
        return AppType.TIKTOK
    if _host_matches_any(host, ("spotify.com",)):
        return AppType.SPOTIFY
    if _host_matches_any(host, ("cloudflare.com",)):
        return AppType.CLOUDFLARE
    if _host_matches_any(host, ("microsoft.com", "live.com", "office.com", "msftconnecttest.com")):
        return AppType.MICROSOFT
    if _host_matches_any(host, ("apple.com", "icloud.com")):
        return AppType.APPLE
    if host.startswith("dns") or host.endswith(".dns"):
        return AppType.DNS
    if host:
        return AppType.HTTPS
    return AppType.UNKNOWN


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int


@dataclass(slots=True)
class PacketJob:
    packet_id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int = 0
    payload_offset: int = 0
    payload_length: int = 0


@dataclass(slots=True)
class Flow:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    blocked: bool = False
    block_reason: str = ""
    detection_method: str = DetectionMethod.UNKNOWN
    packet_count: int = 0
    byte_count: int = 0
    first_seen_timestamp: int = 0
    last_seen_timestamp: int = 0
    is_suspicious: bool = False
    suspicious_reason: str = ""
    anomaly_score: float = 0.0
    risk_score: float = 0.0

    @property
    def duration_seconds(self) -> int:
        if self.packet_count == 0:
            return 0
        if self.last_seen_timestamp < self.first_seen_timestamp:
            return 0
        return self.last_seen_timestamp - self.first_seen_timestamp

    @property
    def avg_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / self.packet_count
