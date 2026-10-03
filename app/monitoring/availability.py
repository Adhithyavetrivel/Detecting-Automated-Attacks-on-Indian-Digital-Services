"""
Device availability monitoring.

Periodically pings every known device, records a MonitoringMetric sample,
updates the device's cached latency/status, and raises alerts when a
device goes unreachable or crosses a latency/packet-loss threshold.

This runs as a background asyncio task started from the FastAPI lifespan
handler (see app/main.py) — it shares the same event loop as the API
server rather than needing a separate process, which is fine at this
project's scale (a handful to a few dozen lab devices).
"""

import asyncio
import logging
import statistics
from datetime import datetime

from ping3 import ping
from sqlalchemy.orm import Session

from app.config import get_settings
from app.detection.rules import raise_alert_if_new
from app.models.alert import AlertType, Severity
from app.models.device import Device, DeviceStatus
from app.models.metric import MonitoringMetric

logger = logging.getLogger("netsentinel.monitoring.availability")
settings = get_settings()

# Multiple pings per check let us compute a real packet-loss percentage,
# not just a binary up/down — "1 loss out of 4" is meaningfully different
# from "4 losses out of 4" for alerting purposes.
_PINGS_PER_CHECK = 4


def _check_device(ip_address: str, timeout: float) -> tuple[bool, float | None, float]:
    """
    Ping a device `_PINGS_PER_CHECK` times.

    Returns (is_reachable, avg_latency_ms_or_None, packet_loss_percent).
    """
    latencies_ms: list[float] = []
    for _ in range(_PINGS_PER_CHECK):
        try:
            rtt = ping(ip_address, timeout=timeout, unit="s")
        except Exception:  # noqa: BLE001
            rtt = None
        if rtt:
            latencies_ms.append(rtt * 1000)

    loss_percent = 100.0 * (1 - len(latencies_ms) / _PINGS_PER_CHECK)
    is_reachable = len(latencies_ms) > 0
    avg_latency = statistics.mean(latencies_ms) if latencies_ms else None
    return is_reachable, avg_latency, loss_percent


def check_all_devices(
    db: Session,
    latency_threshold_ms: float = 200.0,
    packet_loss_threshold_percent: float = 25.0,
) -> None:
    """
    Run one monitoring pass over every device in the database.

    Called on a fixed interval (`settings.ping_interval_seconds`) by
    `availability_monitor_loop` below. Kept as a plain synchronous
    function (rather than async) so it can also be invoked directly from
    tests or a one-off script without an event loop.
    """
    devices = db.query(Device).all()
    logger.debug("Running availability check on %d device(s)", len(devices))

    for device in devices:
        is_reachable, latency_ms, loss_percent = _check_device(
            device.ip_address, timeout=settings.ping_timeout_seconds
        )

        previous_status = device.status
        device.status = DeviceStatus.ONLINE if is_reachable else DeviceStatus.OFFLINE
        device.latency_ms = latency_ms
        device.packet_loss_percent = loss_percent
        if is_reachable:
            device.last_seen = datetime.utcnow()

        db.add(
            MonitoringMetric(
                device_id=device.id,
                is_reachable=is_reachable,
                latency_ms=latency_ms,
                packet_loss_percent=loss_percent,
            )
        )

        # --- Alerting -------------------------------------------------
        if previous_status != DeviceStatus.OFFLINE and not is_reachable:
            raise_alert_if_new(
                db,
                alert_type=AlertType.DEVICE_UNREACHABLE,
                severity=Severity.HIGH,
                source_ip=device.ip_address,
                description=f"Device {device.ip_address} became unreachable.",
                evidence=f"{_PINGS_PER_CHECK}/{_PINGS_PER_CHECK} pings lost.",
                detection_method="rule:availability",
                dedupe_window_seconds=300,
            )
        elif is_reachable and latency_ms is not None and latency_ms > latency_threshold_ms:
            raise_alert_if_new(
                db,
                alert_type=AlertType.HIGH_LATENCY,
                severity=Severity.MEDIUM,
                source_ip=device.ip_address,
                description=(
                    f"Latency to {device.ip_address} is {latency_ms:.1f}ms, "
                    f"above the {latency_threshold_ms:.0f}ms threshold."
                ),
                evidence=f"avg_latency_ms={latency_ms:.1f}",
                detection_method="rule:latency_threshold",
                dedupe_window_seconds=300,
            )
        elif is_reachable and loss_percent >= packet_loss_threshold_percent:
            raise_alert_if_new(
                db,
                alert_type=AlertType.HIGH_PACKET_LOSS,
                severity=Severity.MEDIUM,
                source_ip=device.ip_address,
                description=(
                    f"Packet loss to {device.ip_address} is {loss_percent:.0f}%, "
                    f"above the {packet_loss_threshold_percent:.0f}% threshold."
                ),
                evidence=f"packet_loss_percent={loss_percent:.0f}",
                detection_method="rule:packet_loss_threshold",
                dedupe_window_seconds=300,
            )

    db.commit()


async def availability_monitor_loop(session_factory) -> None:
    """
    Background asyncio task: call `check_all_devices` on a fixed interval
    forever, until cancelled at application shutdown.

    `session_factory` is passed in (rather than imported) so this
    function stays easily testable with a fake/mock session factory.
    """
    logger.info(
        "Availability monitor loop starting (interval=%ss)",
        settings.ping_interval_seconds,
    )
    while True:
        try:
            db = session_factory()
            try:
                check_all_devices(db)
            finally:
                db.close()
        except asyncio.CancelledError:
            logger.info("Availability monitor loop cancelled")
            raise
        except Exception:  # noqa: BLE001
            logger.exception("Unhandled error in availability monitor loop")

        await asyncio.sleep(settings.ping_interval_seconds)
