"""
Rule-based security detection engine.

Each function here implements one explainable, deterministic rule from
the design spec. "Explainable" is the operative word: every alert raised
includes the exact numbers that triggered it (evidence field), so a
human reviewing the dashboard never has to take a verdict on faith.

These rules run against a `TrafficWindow` (aggregated packet metadata —
see app/collectors/packet_capture.py) plus, for connection-based rules,
raw per-source connection counts gathered separately via `psutil`/`ss`.
"""

import logging

from sqlalchemy.orm import Session

from app.collectors.packet_capture import TrafficWindow
from app.config import get_settings
from app.detection.rules import raise_alert_if_new
from app.models.alert import AlertType, Severity

logger = logging.getLogger("netsentinel.detection.security_rules")
settings = get_settings()

# Services that are reasonable to run inside a controlled lab but are
# risky to expose more broadly — flagged for visibility, never blocked.
SUSPICIOUS_SERVICE_PORTS = {
    21: "FTP",
    23: "Telnet",
    139: "SMB (NetBIOS)",
    445: "SMB",
    3389: "RDP",
    22: "SSH",  # flagged as INFO severity only — SSH itself is normal,
                # this just surfaces that it's reachable for awareness.
}


def detect_port_scan(db: Session, window: TrafficWindow) -> None:
    """
    PORT_SCAN_SUSPECTED: one source IP contacts an unusually large number
    of distinct destination ports within the capture window.

    Networking/security note: a port scan (e.g. `nmap -p-`) works by
    probing many ports quickly to find open services. A single host
    legitimately talking to many *ports* (as opposed to many *services on
    one port*, which is normal, like many browser tabs hitting port 443)
    in a short window is the classic scanning signature.
    """
    # window.dst_port_counts aggregates across all sources; for real
    # per-source-IP port fan-out we'd track {src_ip: set(dst_ports)}.
    # This simplified per-window version below approximates that using
    # the counters the capture layer already produces per window, and is
    # extended to true per-source tracking once persisted (see traffic
    # service). Documented here so the simplification is explicit.
    if window.unique_dst_ports_by_src is None:
        return

    for src_ip, port_set in window.unique_dst_ports_by_src.items():
        if len(port_set) >= settings.port_scan_port_threshold:
            raise_alert_if_new(
                db,
                alert_type=AlertType.PORT_SCAN_SUSPECTED,
                severity=Severity.HIGH,
                source_ip=src_ip,
                description=(
                    f"{src_ip} contacted {len(port_set)} distinct destination "
                    f"ports within a {window.window_seconds:.0f}s window."
                ),
                evidence=(
                    f"unique_destination_ports={len(port_set)} "
                    f"threshold={settings.port_scan_port_threshold} "
                    f"window_seconds={window.window_seconds:.0f}"
                ),
                detection_method="rule:port_scan",
                dedupe_window_seconds=120,
            )


def detect_excessive_connections(db: Session, src_ip: str, connection_count: int) -> None:
    """
    EXCESSIVE_CONNECTIONS: a host has an unusually high number of active
    connections (gathered via `psutil.net_connections()` or `ss -tn`).

    A high connection count from one source can indicate a SYN-flood-
    style DoS attempt, a misbehaving client, or (benignly) a busy proxy —
    the alert flags it for a human to interpret with context.
    """
    if connection_count >= settings.excessive_connections_threshold:
        raise_alert_if_new(
            db,
            alert_type=AlertType.EXCESSIVE_CONNECTIONS,
            severity=Severity.MEDIUM,
            source_ip=src_ip,
            description=(
                f"{src_ip} has {connection_count} active connections, above "
                f"the {settings.excessive_connections_threshold} threshold."
            ),
            evidence=f"connection_count={connection_count}",
            detection_method="rule:excessive_connections",
            dedupe_window_seconds=120,
        )


def detect_icmp_anomaly(
    db: Session, window: TrafficWindow, baseline_icmp_per_second: float
) -> None:
    """
    ICMP_ANOMALY: ICMP traffic volume is far above its recent baseline.

    Networking note: ICMP (Internet Control Message Protocol) carries
    diagnostic messages like ping (echo request/reply). A normal network
    has a low, steady trickle of it; a sudden spike can indicate an ICMP
    flood (a simple DoS technique) or an aggressive network sweep.
    """
    icmp_per_second = window.icmp_count / window.window_seconds if window.window_seconds else 0
    if baseline_icmp_per_second <= 0:
        return  # no baseline yet — nothing to compare against

    ratio = icmp_per_second / baseline_icmp_per_second
    if ratio >= 5.0 and icmp_per_second > 5:
        raise_alert_if_new(
            db,
            alert_type=AlertType.ICMP_ANOMALY,
            severity=Severity.MEDIUM,
            description=(
                f"ICMP traffic is {ratio:.1f}x higher than the recent "
                f"baseline ({icmp_per_second:.1f}/s vs baseline "
                f"{baseline_icmp_per_second:.1f}/s)."
            ),
            evidence=(
                f"icmp_per_second={icmp_per_second:.1f} "
                f"baseline={baseline_icmp_per_second:.1f} ratio={ratio:.1f}"
            ),
            detection_method="rule:icmp_anomaly",
            dedupe_window_seconds=180,
        )


def detect_suspicious_services(db: Session, ip_address: str, open_ports: list[int]) -> None:
    """
    SUSPICIOUS_SERVICE: a device exposes a service commonly associated
    with higher risk (Telnet, FTP, SMB, RDP) or worth surfacing (SSH).

    This ONLY reports exposure — it never attempts to connect further,
    authenticate, or exploit anything on the flagged port.
    """
    for port in open_ports:
        if port in SUSPICIOUS_SERVICE_PORTS:
            service_name = SUSPICIOUS_SERVICE_PORTS[port]
            severity = Severity.INFO if port == 22 else Severity.LOW
            raise_alert_if_new(
                db,
                alert_type=AlertType.SUSPICIOUS_SERVICE,
                severity=severity,
                source_ip=ip_address,
                description=f"{ip_address} exposes {service_name} on port {port}.",
                evidence=f"port={port} service={service_name}",
                detection_method="rule:suspicious_service",
                dedupe_window_seconds=3600,
            )


def detect_bandwidth_anomaly(
    db: Session, window: TrafficWindow, baseline_bytes_per_second: float
) -> None:
    """
    BANDWIDTH_ANOMALY: total traffic volume is far above its recent
    historical baseline for this network.
    """
    if baseline_bytes_per_second <= 0:
        return

    ratio = window.bytes_per_second / baseline_bytes_per_second
    if ratio >= 3.0:
        raise_alert_if_new(
            db,
            alert_type=AlertType.BANDWIDTH_ANOMALY,
            severity=Severity.MEDIUM,
            description=(
                f"Traffic volume is {ratio:.1f}x higher than the recent "
                f"baseline ({window.bytes_per_second / 1024:.1f} KB/s vs "
                f"baseline {baseline_bytes_per_second / 1024:.1f} KB/s)."
            ),
            evidence=(
                f"bytes_per_second={window.bytes_per_second:.0f} "
                f"baseline={baseline_bytes_per_second:.0f} ratio={ratio:.1f}"
            ),
            detection_method="rule:bandwidth_anomaly",
            dedupe_window_seconds=180,
        )
