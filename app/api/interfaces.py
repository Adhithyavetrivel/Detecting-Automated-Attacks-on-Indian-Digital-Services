"""Interface API routes — SNMP-derived per-device interface stats."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.interface import Interface
from app.schemas.traffic import InterfaceRead
from app.security.deps import get_current_user

router = APIRouter(prefix="/api/interfaces", tags=["interfaces"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[InterfaceRead])
async def list_interfaces(
    db: Session = Depends(get_db), device_id: int | None = Query(None)
) -> list[Interface]:
    query = db.query(Interface)
    if device_id is not None:
        query = query.filter(Interface.device_id == device_id)
    return query.order_by(Interface.device_id, Interface.if_index).all()


@router.get("/{interface_id}", response_model=InterfaceRead)
async def get_interface(interface_id: int, db: Session = Depends(get_db)) -> Interface:
    interface = db.query(Interface).filter(Interface.id == interface_id).first()
    if interface is None:
        raise HTTPException(status_code=404, detail="Interface not found")
    return interface
