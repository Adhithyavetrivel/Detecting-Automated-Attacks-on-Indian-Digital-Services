"""
Packet capture collector.

Uses Scapy to sniff live traffic on a configured interface and extract
METADATA ONLY (source/destination IP, ports, protocol, size, timestamp).
Payloads are never inspected or stored — this keeps the tool privacy-
respecting and keeps the database small, and it means NetSentinel cannot
be misused to read the content of anyone's traffic, only its shape.

Requires elevated privileges (root on Linux) because raw packet capture
uses a raw socket / libpcap under the hood — the same reason `tcpdump`
needs sudo.
"""

import logging
import time
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger("netsentinel.collectors.packet_capture")


@dataclass
class PacketMeta:
    """Metadata extracted from a single captured packet. No payload."""

    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str  # "TCP" | "UDP" | "ICMP" | "OTHER"
    size_bytes: int
    tcp_syn: bool = False


@dataclass
class TrafficWindow:
    """Aggregated stats for one capture window — this is what gets persisted."""

    window_start: float
    window_seconds: float
    packet_count: int = 0
    byte_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    other_count: int = 0
    src_ip_counts: Counter = field(default_factory=Counter)
    dst_ip_counts: Counter = field(default_factory=Counter)
    dst_port_counts: Counter = field(default_factory=Counter)
    packet_sizes: list[int] = field(default_factory=list)
    # Per-source-IP set of distinct destination ports contacted — this is
    # the specific structure the port-scan rule needs (fan-out per host),
    # as opposed to dst_port_counts above which is aggregated across all
    # sources and only useful for the "top ports" dashboard chart.
    unique_dst_ports_by_src: dict[str, set[int]] = field(default_factory=dict)

    @property
    def packets_per_second(self) -> float:
        return self.packet_count / self.window_seconds if self.window_seconds else 0.0

    @property
    def bytes_per_second(self) -> float:
        return self.byte_count / self.window_seconds if self.window_seconds else 0.0

    @property
    def avg_packet_size(self) -> float:
        return sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0.0

    def top(self, counter: Counter, n: int = 5) -> list[dict]:
        return [{"key": k, "count": c} for k, c in counter.most_common(n)]


PROTOCOL_FILTERS = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "dns": "udp port 53",
    "http": "tcp port 80",
    "https": "tcp port 443",
}


def _extract_metadata(packet) -> PacketMeta | None:
    """Pull metadata fields out of a Scapy packet. Never touches payload bytes."""
    from scapy.layers.inet import ICMP, TCP, UDP, IP

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    protocol = "OTHER"
    src_port = dst_port = None

    tcp_syn = False

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport

        # Count only initial TCP SYN packets for port-scan detection.
        # SYN/ACK and ACK response traffic must not be treated as scans.
        flags = int(packet[TCP].flags)
        tcp_syn = bool(flags & 0x02) and not bool(flags & 0x10)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return PacketMeta(
        timestamp=float(packet.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size_bytes=len(packet),
        tcp_syn=tcp_syn,
    )


def capture_window(
    interface: str,
    duration_seconds: float = 5.0,
    bpf_filter: str | None = None,
) -> TrafficWindow:
    """
    Capture live traffic on `interface` for `duration_seconds` and return
    aggregated statistics.

    `bpf_filter` is a Berkeley Packet Filter expression (the same syntax
    tcpdump uses), e.g. "tcp" or "udp port 53" — see PROTOCOL_FILTERS for
    the presets this project exposes via the API.
    """
    from scapy.all import sniff

    window = TrafficWindow(window_start=time.time(), window_seconds=duration_seconds)

    def _on_packet(packet):
        meta = _extract_metadata(packet)
        if meta is None:
            return
        window.packet_count += 1
        window.byte_count += meta.size_bytes
        window.packet_sizes.append(meta.size_bytes)
        if meta.src_ip:
            window.src_ip_counts[meta.src_ip] += 1
        if meta.dst_ip:
            window.dst_ip_counts[meta.dst_ip] += 1
        if meta.dst_port:
            window.dst_port_counts[meta.dst_port] += 1
        # Port-scan detection uses only initial TCP SYN packets.
        # Response packets such as SYN/ACK must not inflate the scan count.
        if meta.src_ip and meta.dst_port and meta.tcp_syn:
            window.unique_dst_ports_by_src.setdefault(
                meta.src_ip, set()
            ).add(meta.dst_port)

        if meta.protocol == "TCP":
            window.tcp_count += 1
        elif meta.protocol == "UDP":
            window.udp_count += 1
        elif meta.protocol == "ICMP":
            window.icmp_count += 1
        else:
            window.other_count += 1

    logger.info(
        "Capturing on %s for %.1fs (filter=%s)", interface, duration_seconds, bpf_filter
    )
    sniff(
        iface=interface,
        timeout=duration_seconds,
        filter=bpf_filter,
        prn=_on_packet,
        store=False,  # critical: do not retain raw packets/payloads in memory
    )
    logger.info(
        "Capture window complete: %d packets, %d bytes",
        window.packet_count,
        window.byte_count,
    )
    return window
