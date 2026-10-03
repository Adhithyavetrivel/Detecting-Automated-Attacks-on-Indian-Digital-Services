"""
Interface model.

Represents a single network interface on a device (e.g. eth0, GigabitEthernet0/1
on a Cisco router), as reported via SNMP. A device can have many interfaces.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Interface(Base):
    """
    A network interface belonging to a Device, populated by SNMP polling.

    Networking note: SNMP (Simple Network Management Protocol) lets a
    manager (NetSentinel) query an agent (the device) for standardized
    values via OIDs (Object Identifiers) — e.g. ifOperStatus tells you
    whether an interface is administratively/operationally up or down.
    """

    __tablename__ = "interfaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))

    name: Mapped[str] = mapped_column(String(100))
    if_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    oper_status: Mapped[str | None] = mapped_column(String(20), nullable=True)  # up/down
    admin_status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    in_octets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    out_octets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    in_errors: Mapped[int | None] = mapped_column(Integer, nullable=True)
    out_errors: Mapped[int | None] = mapped_column(Integer, nullable=True)

    last_polled: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    device: Mapped["Device"] = relationship(back_populates="interfaces")

    def __repr__(self) -> str:
        return f"<Interface {self.name} on device={self.device_id}>"
