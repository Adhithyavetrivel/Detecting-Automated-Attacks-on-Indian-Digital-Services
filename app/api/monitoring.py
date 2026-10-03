"""
Monitoring control API routes.

Lets an admin start/stop the background availability-monitor and traffic-
capture loops without restarting the whole server, and trigger a single
capture cycle on demand (useful for the manual test scenarios in
docs/testing_scenarios.md).
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal, get_db
from app.monitoring.availability import availability_monitor_loop
from app.schemas.traffic import TrafficRead
from app.security.deps import require_admin
from app.services.traffic_service import run_capture_cycle

router = APIRouter(
    prefix="/api/monitoring", tags=["monitoring"], dependencies=[Depends(require_admin)]
)
logger = logging.getLogger("netsentinel.api.monitoring")
settings = get_settings()


@router.post("/start")
async def start_monitoring(request: Request) -> dict:
    """Start the background availability-monitor loop, if not already running."""
    task: asyncio.Task | None = getattr(request.app.state, "monitor_task", None)
    if task is not None and not task.done():
        return {"status": "already_running"}

    request.app.state.monitor_task = asyncio.create_task(
        availability_monitor_loop(SessionLocal)
    )
    logger.info("Availability monitoring started via API")
    return {"status": "started"}


@router.post("/stop")
async def stop_monitoring(request: Request) -> dict:
    """Cancel the background availability-monitor loop, if running."""
    task: asyncio.Task | None = getattr(request.app.state, "monitor_task", None)
    if task is None or task.done():
        return {"status": "not_running"}

    task.cancel()
    logger.info("Availability monitoring stopped via API")
    return {"status": "stopped"}


@router.get("/status")
async def monitoring_status(request: Request) -> dict:
    task: asyncio.Task | None = getattr(request.app.state, "monitor_task", None)
    return {"running": task is not None and not task.done()}


@router.post("/capture", response_model=TrafficRead)
async def capture_once(duration_seconds: float = 5.0, db: Session = Depends(get_db)) -> TrafficRead:
    """
    Run a single packet-capture-and-detect cycle synchronously and return
    the resulting TrafficRecord.

    Requires the process to have raw-socket privileges on
    `settings.monitor_interface` (run with sudo on Linux) — otherwise
    Scapy raises a PermissionError, surfaced here as a 500 with a clear
    message rather than a silent empty capture.
    """
    try:
        return run_capture_cycle(db, interface=settings.monitor_interface, duration_seconds=duration_seconds)
    except PermissionError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Packet capture requires elevated privileges. "
                f"Run the server with sudo/root, or as a capable user. ({exc})"
            ),
        ) from exc
