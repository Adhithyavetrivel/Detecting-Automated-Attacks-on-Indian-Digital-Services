"""
SNMP collector.

CCNA/Networking note:
    SNMP (Simple Network Management Protocol) lets a manager station
    (NetSentinel) query an "agent" running on a device for standardized
    values identified by OIDs (Object Identifiers) — a dotted-numeric
    address into a tree of manageable data (MIB: Management Information
    Base). SNMPv2c (used here) authenticates with a plaintext "community
    string" (commonly "public" for read-only access) — it is NOT
    encrypted, which is exactly why it should only ever be used on a
    trusted lab/management network, never exposed to the internet.

This module is written as a small abstraction (`SNMPCollector`) so that
swapping the underlying library, or later adding SNMPv3 (which supports
authentication + encryption) for real Cisco IOS devices, doesn't require
changing any calling code in app/monitoring/.

We use the well-known standard OIDs from the IF-MIB and SNMPv2-MIB, which
are implemented identically on essentially all SNMP-capable equipment,
including Cisco IOS — this is what "the abstraction can later extend to
Cisco devices" means in practice: same OIDs, same code path, just pointed
at a router's management IP instead of a lab VM's.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("netsentinel.collectors.snmp")

# Standard MIB-II / IF-MIB OIDs — identical across virtually all
# SNMP-compliant devices (Cisco IOS, Linux net-snmp, etc.)
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"       # + .<ifIndex>
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"  # + .<ifIndex>  (1=up, 2=down)
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"  # + .<ifIndex>
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"   # + .<ifIndex>
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"  # + .<ifIndex>
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"   # + .<ifIndex>
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"  # + .<ifIndex>

_OPER_STATUS_MAP = {1: "up", 2: "down", 3: "testing"}


@dataclass
class SNMPInterfaceResult:
    if_index: int
    name: str
    oper_status: str
    admin_status: str
    in_octets: int | None
    out_octets: int | None
    in_errors: int | None
    out_errors: int | None


@dataclass
class SNMPDeviceResult:
    reachable: bool
    sys_descr: str | None = None
    uptime_ticks: int | None = None
    interfaces: list[SNMPInterfaceResult] = field(default_factory=list)
    error: str | None = None


class SNMPCollector:
    """
    Thin wrapper around an SNMP GET/WALK implementation.

    The actual network calls are isolated in `_get` / `_walk` so that
    (a) the polling logic above them is easy to read and test, and
    (b) swapping SNMP libraries later only touches these two methods.
    """

    def __init__(self, community: str, port: int = 161, timeout: float = 2.0):
        self.community = community
        self.port = port
        self.timeout = timeout

    def _get(self, host: str, oid: str) -> str | None:
        """Perform a single SNMP GET. Returns the value as a string, or None."""
        try:
            from pysnmp.hlapi import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                getCmd,
            )
        except ImportError:
            logger.warning("pysnmp is not installed; SNMP polling disabled")
            return None

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(self.community, mpModel=1),  # mpModel=1 -> SNMPv2c
            UdpTransportTarget((host, self.port), timeout=self.timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, _, var_binds = next(iterator)

        if error_indication or error_status:
            return None

        return str(var_binds[0][1])

    def _walk(self, host: str, base_oid: str) -> dict[int, str]:
        """
        SNMP WALK: retrieve every value under `base_oid` (a table column,
        e.g. every interface's ifOperStatus). Returns {index: value}.
        """
        try:
            from pysnmp.hlapi import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                nextCmd,
            )
        except ImportError:
            logger.warning("pysnmp is not installed; SNMP polling disabled")
            return {}

        results: dict[int, str] = {}
        iterator = nextCmd(
            SnmpEngine(),
            CommunityData(self.community, mpModel=1),
            UdpTransportTarget((host, self.port), timeout=self.timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        )
        for error_indication, error_status, _, var_binds in iterator:
            if error_indication or error_status:
                break
            for name, value in var_binds:
                # The last dotted component of the OID is the table index
                # (e.g. ifIndex) — this is how SNMP tables are addressed.
                index = int(str(name).split(".")[-1])
                results[index] = str(value)
        return results

    def poll_device(self, host: str) -> SNMPDeviceResult:
        """
        Poll one device for system info + per-interface stats.

        Any failure (timeout, wrong community string, device doesn't
        speak SNMP) is caught and returned as `reachable=False` with an
        `error` message, rather than raising — the monitoring loop polls
        many devices in a batch and one bad device shouldn't crash it.
        """
        try:
            sys_descr = self._get(host, OID_SYS_DESCR)
            if sys_descr is None:
                return SNMPDeviceResult(reachable=False, error="No SNMP response")

            uptime_raw = self._get(host, OID_SYS_UPTIME)
            uptime_ticks = int(uptime_raw) if uptime_raw and uptime_raw.isdigit() else None

            descrs = self._walk(host, OID_IF_DESCR)
            oper = self._walk(host, OID_IF_OPER_STATUS)
            admin = self._walk(host, OID_IF_ADMIN_STATUS)
            in_octets = self._walk(host, OID_IF_IN_OCTETS)
            out_octets = self._walk(host, OID_IF_OUT_OCTETS)
            in_errors = self._walk(host, OID_IF_IN_ERRORS)
            out_errors = self._walk(host, OID_IF_OUT_ERRORS)

            interfaces = []
            for if_index, name in descrs.items():
                interfaces.append(
                    SNMPInterfaceResult(
                        if_index=if_index,
                        name=name,
                        oper_status=_OPER_STATUS_MAP.get(
                            int(oper.get(if_index, 0)), "unknown"
                        ),
                        admin_status=_OPER_STATUS_MAP.get(
                            int(admin.get(if_index, 0)), "unknown"
                        ),
                        in_octets=int(in_octets[if_index]) if if_index in in_octets else None,
                        out_octets=int(out_octets[if_index]) if if_index in out_octets else None,
                        in_errors=int(in_errors[if_index]) if if_index in in_errors else None,
                        out_errors=int(out_errors[if_index]) if if_index in out_errors else None,
                    )
                )

            return SNMPDeviceResult(
                reachable=True,
                sys_descr=sys_descr,
                uptime_ticks=uptime_ticks,
                interfaces=interfaces,
            )
        except Exception as exc:  # noqa: BLE001 - SNMP libs raise varied errors
            logger.debug("SNMP poll of %s failed: %s", host, exc)
            return SNMPDeviceResult(reachable=False, error=str(exc))
