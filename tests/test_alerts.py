"""Tests for security alert endpoints."""

from datetime import datetime

from app.models.alert import AlertStatus, AlertType, SecurityAlert, Severity


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_list_alerts_empty(client, admin_token):
    response = client.get("/api/alerts", headers=_auth_headers(admin_token))
    assert response.status_code == 200
    assert response.json() == []


def test_create_and_list_alert(client, admin_token, db_session):
    alert = SecurityAlert(
        alert_type=AlertType.PORT_SCAN_SUSPECTED,
        severity=Severity.HIGH,
        source_ip="10.0.0.5",
        description="Test port scan",
        evidence="ports=15",
        detection_method="rule:port_scan",
    )
    db_session.add(alert)
    db_session.commit()

    response = client.get("/api/alerts", headers=_auth_headers(admin_token))
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.5"


def test_filter_alerts_by_status(client, admin_token, db_session):
    open_alert = SecurityAlert(
        alert_type=AlertType.PORT_SCAN_SUSPECTED,
        severity=Severity.HIGH,
        source_ip="10.0.0.1",
        description="Open alert",
        evidence="test",
        detection_method="rule:test",
        status=AlertStatus.OPEN,
    )
    resolved_alert = SecurityAlert(
        alert_type=AlertType.BANDWIDTH_ANOMALY,
        severity=Severity.MEDIUM,
        source_ip="10.0.0.2",
        description="Resolved alert",
        evidence="test",
        detection_method="rule:test",
        status=AlertStatus.RESOLVED,
    )
    db_session.add_all([open_alert, resolved_alert])
    db_session.commit()

    response = client.get(
        "/api/alerts?status=OPEN", headers=_auth_headers(admin_token)
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["status"] == "OPEN"


def test_search_alerts_by_description(client, admin_token, db_session):
    alert1 = SecurityAlert(
        alert_type=AlertType.PORT_SCAN_SUSPECTED,
        severity=Severity.HIGH,
        source_ip="10.0.0.1",
        description="Malicious port scan detected",
        evidence="test",
        detection_method="rule:test",
    )
    alert2 = SecurityAlert(
        alert_type=AlertType.DEVICE_UNREACHABLE,
        severity=Severity.MEDIUM,
        source_ip="10.0.0.2",
        description="Device is down",
        evidence="test",
        detection_method="rule:test",
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    response = client.get(
        "/api/alerts?search=malicious", headers=_auth_headers(admin_token)
    )
    assert len(response.json()) == 1
    assert "malicious" in response.json()[0]["description"].lower()


def test_resolve_alert(client, admin_token, db_session):
    alert = SecurityAlert(
        alert_type=AlertType.HIGH_LATENCY,
        severity=Severity.MEDIUM,
        source_ip="10.0.0.1",
        description="Latency detected",
        evidence="test",
        detection_method="rule:test",
        status=AlertStatus.OPEN,
    )
    db_session.add(alert)
    db_session.commit()
    alert_id = alert.id

    response = client.patch(
        f"/api/alerts/{alert_id}/resolve",
        headers=_auth_headers(admin_token),
        json={"resolved_by": "test_user"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "RESOLVED"
    assert response.json()["resolved_by"] == "test_user"
