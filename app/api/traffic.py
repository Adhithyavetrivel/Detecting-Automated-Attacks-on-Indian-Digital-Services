"""Traffic statistics API routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.traffic import TrafficRecord
from app.schemas.traffic import TrafficRead
from app.security.deps import get_current_user

router = APIRouter(prefix="/api/traffic", tags=["traffic"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[TrafficRead])
async def list_traffic(
    db: Session = Depends(get_db), limit: int = Query(100, le=2000)
) -> list[TrafficRecord]:
    """Most recent traffic windows, newest first — feeds the dashboard's live charts."""
    return (
        db.query(TrafficRecord)
        .order_by(TrafficRecord.window_start.desc())
        .limit(limit)
        .all()
    )
