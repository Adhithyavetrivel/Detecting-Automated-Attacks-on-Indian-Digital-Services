"""Pydantic schemas for SecurityAlert."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.alert import AlertStatus, AlertType, Severity


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    severity: Severity
    alert_type: AlertType
    source_ip: str | None
    destination_ip: str | None
    description: str
    evidence: str | None
    detection_method: str
    status: AlertStatus
    resolved_at: datetime | None
    resolved_by: str | None


class AlertResolve(BaseModel):
    """Payload for PATCH /api/alerts/{id}/resolve."""

    resolved_by: str
    status: AlertStatus = AlertStatus.RESOLVED
