"""
Device model.

Represents a single network host discovered or manually registered in
NetSentinel (e.g. a router, PC, VM, or server on the monitored subnet).
"""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DeviceStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


class Device(Base):
    """
    A discovered or manually-added network device.

    Networking note: `mac_address` is filled in from ARP replies during
    discovery, since ARP (Address Resolution Protocol) maps an IPv4
    address to a MAC address on the local network segment — it only works
    for devices on the same subnet/broadcast domain as the scanner.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus), default=DeviceStatus.UNKNOWN
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_discovered: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # Latest known availability metrics, updated by the monitoring loop.
    # Full history lives in MonitoringMetric; these are a cheap "current
    # value" cache so the dashboard's device table doesn't need a join.
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_percent: Mapped[float | None] = mapped_column(Float, nullable=True)

    is_snmp_enabled: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)

    interfaces: Mapped[list["Interface"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    metrics: Mapped[list["MonitoringMetric"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Device {self.ip_address} ({self.status})>"
