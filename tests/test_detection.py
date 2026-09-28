"""Tests for rule-based security detection logic (no live network needed)."""

from app.collectors.packet_capture import TrafficWindow
from app.detection import security_rules
from app.models.alert import AlertStatus, AlertType, SecurityAlert
from app.models.device import Device, DeviceStatus


def test_port_scan_detected_above_threshold(db_session):
    window = TrafficWindow(window_start=0, window_seconds=10)
    window.unique_dst_ports_by_src["10.0.0.99"] = set(range(1000, 1020))  # 20 ports

    security_rules.detect_port_scan(db_session, window)
    db_session.commit()

    alerts = db_session.query(SecurityAlert).all()
    assert len(alerts) == 1
    assert alerts[0].alert_type == AlertType.PORT_SCAN_SUSPECTED
    assert alerts[0].source_ip == "10.0.0.99"
    assert "20" in alerts[0].evidence


def test_port_scan_not_flagged_below_threshold(db_session):
    window = TrafficWindow(window_start=0, window_seconds=10)
    window.unique_dst_ports_by_src["10.0.0.5"] = {80, 443, 22}  # only 3 ports

    security_rules.detect_port_scan(db_session, window)
    db_session.commit()

    assert db_session.query(SecurityAlert).count() == 0


def test_suspicious_service_flags_telnet(db_session):
    security_rules.detect_suspicious_services(db_session, "192.168.56.10", [23])
    db_session.commit()

    alert = db_session.query(SecurityAlert).first()
    assert alert is not None
    assert alert.alert_type == AlertType.SUSPICIOUS_SERVICE
    assert "Telnet" in alert.description


def test_alert_deduplication_within_window(db_session):
    window = TrafficWindow(window_start=0, window_seconds=10)
    window.unique_dst_ports_by_src["10.0.0.99"] = set(range(1000, 1020))

    security_rules.detect_port_scan(db_session, window)
    security_rules.detect_port_scan(db_session, window)  # same condition again
    db_session.commit()

    # The dedupe window should prevent a second identical OPEN alert.
    assert db_session.query(SecurityAlert).count() == 1


def test_bandwidth_anomaly_detected(db_session):
    window = TrafficWindow(window_start=0, window_seconds=5)
    window.byte_count = 500_000
    window.packet_count = 1000

    security_rules.detect_bandwidth_anomaly(db_session, window, baseline_bytes_per_second=10_000)
    db_session.commit()

    alert = db_session.query(SecurityAlert).filter_by(alert_type=AlertType.BANDWIDTH_ANOMALY).first()
    assert alert is not None
    assert "x higher" in alert.description
