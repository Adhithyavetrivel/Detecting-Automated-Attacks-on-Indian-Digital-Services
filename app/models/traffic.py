"""
TrafficRecord model.

Stores aggregated traffic statistics per time window (e.g. one row per
5-second bucket), rather than one row per raw packet. Storing every packet
would make the database enormous very quickly; aggregation is what makes
long-term traffic graphs on the dashboard feasible.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TrafficRecord(Base):
    """
    One aggregated traffic-statistics sample, produced by the packet
    capture/traffic analysis layer.

    `top_talkers_json` etc. are stored as JSON-encoded strings (via
    String) rather than separate normalized tables — appropriate here
    because they are read as a whole for a single time bucket and never
    queried by their internal fields directly.
    """

    __tablename__ = "traffic_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_seconds: Mapped[int] = mapped_column(Integer, default=5)

    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    packets_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    bytes_per_second: Mapped[float] = mapped_column(Float, default=0.0)

    tcp_count: Mapped[int] = mapped_column(Integer, default=0)
    udp_count: Mapped[int] = mapped_column(Integer, default=0)
    icmp_count: Mapped[int] = mapped_column(Integer, default=0)
    other_count: Mapped[int] = mapped_column(Integer, default=0)

    unique_src_ips: Mapped[int] = mapped_column(Integer, default=0)
    unique_dst_ips: Mapped[int] = mapped_column(Integer, default=0)
    unique_dst_ports: Mapped[int] = mapped_column(Integer, default=0)
    avg_packet_size: Mapped[float] = mapped_column(Float, default=0.0)

    # JSON-encoded lists of {"ip"/"port": ..., "count": ...} — small,
    # read-as-a-blob summaries used directly by the dashboard charts.
    top_src_ips_json: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    top_dst_ips_json: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    top_dst_ports_json: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    def __repr__(self) -> str:
        return f"<TrafficRecord {self.window_start} pps={self.packets_per_second:.1f}>"
