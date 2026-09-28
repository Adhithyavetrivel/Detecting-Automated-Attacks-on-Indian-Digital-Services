"""
Pydantic schemas for device discovery.

Kept separate from the (future) SQLAlchemy model in app/models/ — schemas
define what the API sends/receives, models define what the database
stores. They often look similar but serve different layers and will
diverge once the DB model gains relationship fields in Phase 5.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class DiscoveredDevice(BaseModel):
    """A single device found during a discovery scan."""

    ip_address: str = Field(..., description="IPv4 address of the device")
    mac_address: Optional[str] = Field(
        None, description="MAC address, if resolvable (ARP or system ARP cache)"
    )
    hostname: Optional[str] = Field(
        None, description="Reverse-DNS hostname, if resolvable"
    )
    status: Literal["online", "offline"] = Field(
        ..., description="Reachability at scan time"
    )
    response_time_ms: Optional[float] = Field(
        None, description="Round-trip time in milliseconds, if the device responded"
    )
    discovery_method: Literal["arp", "ping"] = Field(
        ..., description="Technique used to find this device"
    )


class ScanResult(BaseModel):
    """Result of a full subnet discovery scan."""

    subnet: str
    method: Literal["arp", "ping"]
    devices_found: int
    scan_duration_seconds: float
    devices: list[DiscoveredDevice]


# --- Persisted-device schemas (Phase 5: DB-backed, distinct from the
# raw scan-result schemas above, which describe a single scan's output
# before anything is written to the database) ---

from datetime import datetime as _datetime  # noqa: E402

from app.models.device import DeviceStatus as _DeviceStatus  # noqa: E402


class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    notes: Optional[str] = None


class DeviceCreate(DeviceBase):
    """Payload for manually registering a device: POST /api/devices."""

    is_snmp_enabled: bool = False


class DeviceUpdate(BaseModel):
    """Partial-update payload: PATCH /api/devices/{id}."""

    hostname: Optional[str] = None
    vendor: Optional[str] = None
    notes: Optional[str] = None
    is_snmp_enabled: Optional[bool] = None


class DeviceRead(DeviceBase):
    model_config = {"from_attributes": True}

    id: int
    status: _DeviceStatus
    last_seen: Optional[_datetime]
    first_discovered: _datetime
    latency_ms: Optional[float]
    packet_loss_percent: Optional[float]
    is_snmp_enabled: bool
