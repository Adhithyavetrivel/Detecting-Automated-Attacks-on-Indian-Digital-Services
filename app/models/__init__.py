"""
Model exports.

Importing from `app.models` (rather than each submodule individually)
also guarantees every model class is registered on `Base.metadata`,
which is what Alembic's autogenerate and Base.metadata.create_all()
both rely on.
"""

from app.models.alert import AlertStatus, AlertType, SecurityAlert, Severity
from app.models.audit_log import AuditLog
from app.models.device import Device, DeviceStatus
from app.models.interface import Interface
from app.models.metric import MonitoringMetric
from app.models.traffic import TrafficRecord
from app.models.user import User, UserRole

__all__ = [
    "Device",
    "DeviceStatus",
    "Interface",
    "TrafficRecord",
    "SecurityAlert",
    "Severity",
    "AlertStatus",
    "AlertType",
    "MonitoringMetric",
    "User",
    "UserRole",
    "AuditLog",
]
