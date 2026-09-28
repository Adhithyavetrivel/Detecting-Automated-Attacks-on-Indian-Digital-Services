"""Monitoring metric history + dashboard summary API routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import AlertStatus, SecurityAlert
from app.models.device import Device, DeviceStatus
from app.models.metric import MonitoringMetric
from app.schemas.traffic import MetricRead
from app.security.deps import get_current_user

router = APIRouter(prefix="/api/metrics", tags=["metrics"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[MetricRead])
async def list_metrics(
    db: Session = Depends(get_db),
    device_id: int | None = Query(None),
    limit: int = Query(200, le=2000),
) -> list[MonitoringMetric]:
    query = db.query(MonitoringMetric)
    if device_id is not None:
        query = query.filter(MonitoringMetric.device_id == device_id)
    return query.order_by(MonitoringMetric.timestamp.desc()).limit(limit).all()


@router.get("/summary")
async def dashboard_summary(db: Session = Depends(get_db)) -> dict:
    """
    Single aggregate endpoint for the dashboard's top-of-page tiles
    (device counts, alert counts) — avoids the frontend needing to fetch
    every device and every alert just to display three numbers.
    """
    total_devices = db.query(Device).count()
    online_devices = db.query(Device).filter(Device.status == DeviceStatus.ONLINE).count()
    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == AlertStatus.OPEN).count()

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": total_devices - online_devices,
        "open_alerts": open_alerts,
    }
