"""
SecurityAlert model.

Every finding from the detection engine (rule-based or ML) becomes one
row here. Keeping alerts as first-class, persisted, filterable/resolvable
records — rather than just log lines — is what makes this a genuine
alerting system instead of a script that prints warnings.
"""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AlertType(str, enum.Enum):
    PORT_SCAN_SUSPECTED = "PORT_SCAN_SUSPECTED"
    EXCESSIVE_CONNECTIONS = "EXCESSIVE_CONNECTIONS"
    ICMP_ANOMALY = "ICMP_ANOMALY"
    SUSPICIOUS_SERVICE = "SUSPICIOUS_SERVICE"
    BANDWIDTH_ANOMALY = "BANDWIDTH_ANOMALY"
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    HIGH_LATENCY = "HIGH_LATENCY"
    HIGH_PACKET_LOSS = "HIGH_PACKET_LOSS"
    ML_ANOMALY = "ML_ANOMALY"


class SecurityAlert(Base):
    """
    A single security or operational alert.

    `detection_method` distinguishes a deterministic rule (e.g.
    "rule:port_scan") from an ML prediction (e.g. "ml:isolation_forest") —
    this project deliberately keeps that distinction visible end-to-end,
    per the design principle of never presenting an ML score as an
    unexplained verdict.
    """

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    alert_type: Mapped[AlertType] = mapped_column(Enum(AlertType), index=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    description: Mapped[str] = mapped_column(String(500))
    evidence: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    detection_method: Mapped[str] = mapped_column(String(100))

    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus), default=AlertStatus.OPEN)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    def __repr__(self) -> str:
        return f"<SecurityAlert {self.alert_type} sev={self.severity} src={self.source_ip}>"
