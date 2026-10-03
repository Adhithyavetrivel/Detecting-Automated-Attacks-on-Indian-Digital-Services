"""
Device API routes.

Two concerns live here:
  1. Discovery (POST /api/devices/scan) — runs a live ARP/ping sweep and
     UPSERTS results into the database (insert new devices, update
     last_seen/status for existing ones).
  2. Persisted device management (GET/POST/PATCH /api/devices) — plain
     CRUD-style access against the Device table.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.collectors.discovery import discover_devices
from app.config import get_settings
from app.database import get_db
from app.models.device import Device, DeviceStatus
from app.schemas.device import (
    DeviceCreate,
    DeviceRead,
    DeviceUpdate,
    ScanResult,
)
from app.security.deps import get_current_user, require_admin

router = APIRouter(prefix="/api/devices", tags=["devices"])
logger = logging.getLogger("netsentinel.api.devices")
settings = get_settings()


@router.post("/scan", response_model=ScanResult, dependencies=[Depends(get_current_user)])
async def scan_network(db: Session = Depends(get_db)) -> ScanResult:
    """
    Run a discovery scan of the configured MONITOR_SUBNET and upsert
    results into the database.

    Tries an ARP scan first (fast, gets MAC addresses, needs root); falls
    back to an ICMP ping sweep if ARP isn't available.
    """
    discovered, method, duration = discover_devices(
        subnet=settings.monitor_subnet,
        interface=settings.monitor_interface,
        ping_timeout=settings.ping_timeout_seconds,
    )

    for found in discovered:
        existing = db.query(Device).filter(Device.ip_address == found.ip_address).first()
        if existing:
            existing.status = DeviceStatus.ONLINE
            existing.last_seen = datetime.utcnow()
            if found.mac_address:
                existing.mac_address = found.mac_address
            if found.hostname:
                existing.hostname = found.hostname
            if found.response_time_ms is not None:
                existing.latency_ms = found.response_time_ms
        else:
            db.add(
                Device(
                    ip_address=found.ip_address,
                    mac_address=found.mac_address,
                    hostname=found.hostname,
                    status=DeviceStatus.ONLINE,
                    last_seen=datetime.utcnow(),
                    latency_ms=found.response_time_ms,
                )
            )
    db.commit()

    return ScanResult(
        subnet=settings.monitor_subnet,
        method=method,
        devices_found=len(discovered),
        scan_duration_seconds=round(duration, 2),
        devices=discovered,
    )


@router.get("", response_model=list[DeviceRead], dependencies=[Depends(get_current_user)])
async def list_devices(db: Session = Depends(get_db)) -> list[Device]:
    """Return all known devices (from prior scans or manual registration)."""
    return db.query(Device).order_by(Device.ip_address).all()


@router.get("/{device_id}", response_model=DeviceRead, dependencies=[Depends(get_current_user)])
async def get_device(device_id: int, db: Session = Depends(get_db)) -> Device:
    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.post("", response_model=DeviceRead, status_code=201, dependencies=[Depends(require_admin)])
async def create_device(payload: DeviceCreate, db: Session = Depends(get_db)) -> Device:
    """Manually register a device (e.g. one that can't be discovered automatically)."""
    if db.query(Device).filter(Device.ip_address == payload.ip_address).first():
        raise HTTPException(status_code=409, detail="Device with this IP already exists")

    device = Device(**payload.model_dump(), status=DeviceStatus.UNKNOWN)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.patch("/{device_id}", response_model=DeviceRead, dependencies=[Depends(require_admin)])
async def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)) -> Device:
    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(device, field, value)

    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_device(device_id: int, db: Session = Depends(get_db)) -> None:
    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
