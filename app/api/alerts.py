"""Security alert API routes: list/filter/search, get one, resolve."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import AlertStatus, AlertType, SecurityAlert, Severity
from app.schemas.alert import AlertRead, AlertResolve
from app.security.deps import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[AlertRead])
async def list_alerts(
    db: Session = Depends(get_db),
    status_filter: AlertStatus | None = Query(None, alias="status"),
    severity: Severity | None = None,
    alert_type: AlertType | None = None,
    source_ip: str | None = None,
    search: str | None = Query(None, description="Free-text search over the description field"),
    limit: int = Query(100, le=1000),
) -> list[SecurityAlert]:
    query = db.query(SecurityAlert)

    if status_filter is not None:
        query = query.filter(SecurityAlert.status == status_filter)
    if severity is not None:
        query = query.filter(SecurityAlert.severity == severity)
    if alert_type is not None:
        query = query.filter(SecurityAlert.alert_type == alert_type)
    if source_ip is not None:
        query = query.filter(SecurityAlert.source_ip == source_ip)
    if search:
        query = query.filter(SecurityAlert.description.ilike(f"%{search}%"))

    return query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(alert_id: int, db: Session = Depends(get_db)) -> SecurityAlert:
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/resolve", response_model=AlertRead)
async def resolve_alert(alert_id: int, payload: AlertResolve, db: Session = Depends(get_db)) -> SecurityAlert:
    from datetime import datetime

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status
    alert.resolved_by = payload.resolved_by
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert
