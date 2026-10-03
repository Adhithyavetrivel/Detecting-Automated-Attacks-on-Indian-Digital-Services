"""Pydantic schemas for TrafficRecord, Interface, and MonitoringMetric."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TrafficRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    window_start: datetime
    window_seconds: int
    packet_count: int
    byte_count: int
    packets_per_second: float
    bytes_per_second: float
    tcp_count: int
    udp_count: int
    icmp_count: int
    other_count: int
    unique_src_ips: int
    unique_dst_ips: int
    unique_dst_ports: int
    avg_packet_size: float
    top_src_ips_json: str | None
    top_dst_ips_json: str | None
    top_dst_ports_json: str | None


class InterfaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    name: str
    if_index: int | None
    oper_status: str | None
    admin_status: str | None
    in_octets: int | None
    out_octets: int | None
    in_errors: int | None
    out_errors: int | None
    last_polled: datetime


class MetricRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    timestamp: datetime
    is_reachable: bool
    latency_ms: float | None
    packet_loss_percent: float | None
