"""
MonitoringMetric model.

Time-series history of per-device availability metrics (latency, packet
loss, reachability). The `Device.latency_ms` field is only the latest
value; this table is what lets the dashboard draw a latency-over-time
graph for a specific device.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class MonitoringMetric(Base):
    """One availability-check sample for one device at one point in time."""

    __tablename__ = "monitoring_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    is_reachable: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss_percent: Mapped[float | None] = mapped_column(Float, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="metrics")

    def __repr__(self) -> str:
        return f"<MonitoringMetric device={self.device_id} reachable={self.is_reachable}>"
