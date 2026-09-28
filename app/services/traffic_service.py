"""
Traffic service.

Orchestrates one full cycle: capture a window of packets -> persist an
aggregated TrafficRecord -> run rule-based detection -> optionally run
the ML detector -> commit. This is the module the API's
POST /api/monitoring/start background task (and a manual "capture once"
endpoint) both call into, so the capture-and-detect logic lives in one
place rather than being duplicated.
"""

import json
import logging

from sqlalchemy.orm import Session

from app.collectors.packet_capture import TrafficWindow, capture_window
from app.detection import security_rules
from app.detection.ml_detector import FEATURE_NAMES, TrafficAnomalyDetector
from app.models.alert import AlertType, Severity
from app.models.traffic import TrafficRecord
from app.detection.rules import raise_alert_if_new

logger = logging.getLogger("netsentinel.services.traffic")

# Minimum historical rows before we trust the ML model enough to fit it.
# Too few samples makes Isolation Forest's notion of "normal" meaningless.
_MIN_ROWS_FOR_ML = 30

_ml_detector = TrafficAnomalyDetector()


def _window_to_record(window: TrafficWindow) -> TrafficRecord:
    from datetime import datetime

    return TrafficRecord(
        window_start=datetime.utcfromtimestamp(window.window_start),
        window_seconds=int(window.window_seconds),
        packet_count=window.packet_count,
        byte_count=window.byte_count,
        packets_per_second=window.packets_per_second,
        bytes_per_second=window.bytes_per_second,
        tcp_count=window.tcp_count,
        udp_count=window.udp_count,
        icmp_count=window.icmp_count,
        other_count=window.other_count,
        unique_src_ips=len(window.src_ip_counts),
        unique_dst_ips=len(window.dst_ip_counts),
        unique_dst_ports=len(window.dst_port_counts),
        avg_packet_size=window.avg_packet_size,
        top_src_ips_json=json.dumps(window.top(window.src_ip_counts)),
        top_dst_ips_json=json.dumps(window.top(window.dst_ip_counts)),
        top_dst_ports_json=json.dumps(window.top(window.dst_port_counts)),
    )


def _record_to_features(record: TrafficRecord) -> list[float]:
    return [
        record.packets_per_second,
        record.bytes_per_second,
        record.unique_dst_ips,
        record.unique_dst_ports,
        record.avg_packet_size,
        record.tcp_count,
        record.icmp_count,
    ]


def _recent_baseline(db: Session, exclude_id: int, limit: int = 60) -> tuple[float, float]:
    """
    Average ICMP/s and bytes/s over the most recent `limit` records
    (excluding the one just captured) — a simple rolling baseline used
    by the ratio-based rules (ICMP anomaly, bandwidth anomaly).
    """
    rows = (
        db.query(TrafficRecord)
        .filter(TrafficRecord.id != exclude_id)
        .order_by(TrafficRecord.window_start.desc())
        .limit(limit)
        .all()
    )
    if not rows:
        return 0.0, 0.0

    avg_icmp_per_second = sum(
        r.icmp_count / r.window_seconds for r in rows if r.window_seconds
    ) / len(rows)
    avg_bytes_per_second = sum(r.bytes_per_second for r in rows) / len(rows)
    return avg_icmp_per_second, avg_bytes_per_second


def run_capture_cycle(db: Session, interface: str, duration_seconds: float = 5.0) -> TrafficRecord:
    """
    Capture one traffic window, persist it, and run the full detection
    pipeline (rules, then ML if enough history exists) against it.
    """
    window = capture_window(interface=interface, duration_seconds=duration_seconds)

    record = _window_to_record(window)
    db.add(record)
    db.flush()  # get record.id without a full commit yet

    # --- Rule-based detection ---
    security_rules.detect_port_scan(db, window)

    baseline_icmp, baseline_bytes = _recent_baseline(db, exclude_id=record.id)
    security_rules.detect_icmp_anomaly(db, window, baseline_icmp_per_second=baseline_icmp)
    security_rules.detect_bandwidth_anomaly(db, window, baseline_bytes_per_second=baseline_bytes)

    # --- ML detection (only once enough history exists) ---
    history_count = db.query(TrafficRecord).count()
    if history_count >= _MIN_ROWS_FOR_ML:
        historical_rows = (
            db.query(TrafficRecord)
            .filter(TrafficRecord.id != record.id)
            .order_by(TrafficRecord.window_start.desc())
            .limit(200)
            .all()
        )
        feature_rows = [_record_to_features(r) for r in historical_rows]
        _ml_detector.fit(feature_rows)

        result = _ml_detector.predict(_record_to_features(record))
        if result.is_anomalous:
            raise_alert_if_new(
                db,
                alert_type=AlertType.ML_ANOMALY,
                severity=Severity.MEDIUM,
                description=f"ML anomaly detector flagged this traffic window: {result.explanation}",
                evidence=(
                    f"anomaly_score={result.anomaly_score} "
                    f"features={dict(zip(FEATURE_NAMES, _record_to_features(record)))}"
                ),
                detection_method="ml:isolation_forest",
                dedupe_window_seconds=120,
            )
    else:
        logger.debug(
            "Skipping ML detection: only %d/%d required history rows",
            history_count,
            _MIN_ROWS_FOR_ML,
        )

    db.commit()
    db.refresh(record)
    return record
