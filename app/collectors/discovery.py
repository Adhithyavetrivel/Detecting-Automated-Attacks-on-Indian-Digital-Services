"""
Network device discovery.

CCNA/Networking note:
    ARP (Address Resolution Protocol) maps an IPv4 address to a MAC
    address on a local (same-subnet) network. When you send a broadcast
    "who has 192.168.1.5?" ARP request, the device owning that IP replies
    with its MAC address. This only works within a single broadcast
    domain (i.e. it does not cross routers) — which is exactly why ARP
    scanning is the fast, accurate way to discover devices on YOUR local
    subnet, but not devices behind a router elsewhere.

Two discovery methods are implemented:

1. ARP scan (primary) — sends a broadcast ARP request via Scapy and
   collects replies. Fast and gets MAC addresses directly, but requires
   raw-socket privileges (root on Linux), since it crafts packets at
   Layer 2.

2. ICMP ping sweep (fallback) — sends an ICMP echo request (ping) to
   every host in the subnet. Works without root. MAC addresses are then
   recovered from the OS's own ARP cache (populated automatically by the
   OS as a side effect of the ping) via `ip neigh`, rather than by
   crafting ARP packets ourselves.
"""

import ipaddress
import logging
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ping3 import ping

from app.schemas.device import DiscoveredDevice

logger = logging.getLogger("netsentinel.collectors.discovery")


def _resolve_hostname(ip_address: str) -> str | None:
    """
    Reverse-DNS lookup.

    Networking note: this queries DNS's PTR record for the IP, the
    opposite direction of a normal A-record lookup. Many home/lab
    devices won't have one configured, so None is an expected result,
    not an error.
    """
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _mac_from_arp_cache(ip_address: str) -> str | None:
    """
    Read the MAC address for an IP from the OS's ARP cache using
    `ip neigh show <ip>`.

    Networking note: `ip neigh` is the modern replacement for the older
    `arp -a` command. The OS populates this cache automatically whenever
    it communicates with a device on the local subnet (e.g. right after
    we ping it) — we're reading state the kernel already maintains, not
    performing our own ARP resolution here.
    """
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip_address],
            capture_output=True,
            text=True,
            timeout=2,
        )
        # Example line: "192.168.56.10 dev eth0 lladdr 08:00:27:aa:bb:cc STALE"
        for token_group in result.stdout.split():
            if token_group.count(":") == 5:
                return token_group
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return None


def _ping_host(ip_address: str, timeout: float) -> DiscoveredDevice:
    """Ping a single host and build a DiscoveredDevice from the result."""
    try:
        rtt_seconds = ping(ip_address, timeout=timeout, unit="s")
    except Exception:  # noqa: BLE001 - ping3 can raise various OS-level errors
        rtt_seconds = None

    if rtt_seconds:
        return DiscoveredDevice(
            ip_address=ip_address,
            mac_address=_mac_from_arp_cache(ip_address),
            hostname=_resolve_hostname(ip_address),
            status="online",
            response_time_ms=round(rtt_seconds * 1000, 2),
            discovery_method="ping",
        )

    return DiscoveredDevice(
        ip_address=ip_address,
        mac_address=None,
        hostname=None,
        status="offline",
        response_time_ms=None,
        discovery_method="ping",
    )


def discover_via_ping_sweep(
    subnet: str, timeout: float = 1.0, max_workers: int = 32
) -> list[DiscoveredDevice]:
    """
    Ping every host address in `subnet` concurrently.

    A ThreadPoolExecutor is used because ping3 is a blocking (synchronous)
    call — running the sweep concurrently is what keeps a /24 (254 hosts)
    scan from taking over four minutes at a 1-second timeout each.

    Only devices that respond ("online") are returned — offline hosts
    are not worth reporting for a discovery scan.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    logger.info("Starting ping sweep of %s (%d hosts)", subnet, len(hosts))

    discovered: list[DiscoveredDevice] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_ping_host, str(ip), timeout): ip for ip in hosts
        }
        for future in as_completed(futures):
            device = future.result()
            if device.status == "online":
                discovered.append(device)

    logger.info("Ping sweep of %s found %d online device(s)", subnet, len(discovered))
    return discovered


def discover_via_arp(subnet: str, interface: str, timeout: float = 2.0) -> list[DiscoveredDevice]:
    """
    Broadcast an ARP request across `subnet` on `interface` and collect
    replies.

    Requires raw-socket privileges (root on Linux). Raises PermissionError
    if not run with sufficient privileges, so the caller can fall back to
    the ping sweep.
    """
    from scapy.all import ARP, Ether, srp  # imported lazily: requires libpcap

    logger.info("Starting ARP scan of %s on interface %s", subnet, interface)

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=timeout, iface=interface, verbose=False)
    except PermissionError as exc:
        raise PermissionError(
            "ARP scan requires raw-socket privileges (run with sudo/root)."
        ) from exc

    discovered: list[DiscoveredDevice] = []
    for _, received in answered:
        ip_address = received.psrc
        discovered.append(
            DiscoveredDevice(
                ip_address=ip_address,
                mac_address=received.hwsrc,
                hostname=_resolve_hostname(ip_address),
                status="online",
                response_time_ms=None,  # ARP replies don't carry timing info
                discovery_method="arp",
            )
        )

    logger.info("ARP scan of %s found %d device(s)", subnet, len(discovered))
    return discovered


def discover_devices(
    subnet: str,
    interface: str,
    ping_timeout: float = 1.0,
) -> tuple[list[DiscoveredDevice], str, float]:
    """
    Run device discovery, preferring ARP and falling back to a ping sweep.

    Returns (devices, method_used, duration_seconds).
    """
    start = time.monotonic()

    try:
        devices = discover_via_arp(subnet, interface)
        method = "arp"
    except (PermissionError, OSError) as exc:
        logger.warning("ARP scan unavailable (%s); falling back to ping sweep", exc)
        devices = discover_via_ping_sweep(subnet, timeout=ping_timeout)
        method = "ping"

    duration = time.monotonic() - start
    return devices, method, duration
