"""
Shared helper for raising alerts from any detector (rule-based or ML),
with basic deduplication so a persistent condition (e.g. a device that
stays down for an hour) doesn't create a new alert row every monitoring
cycle.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.alert import AlertStatus, AlertType, SecurityAlert, Severity

logger = logging.getLogger("netsentinel.detection")


def raise_alert_if_new(
    db: Session,
    alert_type: AlertType,
    severity: Severity,
    description: str,
    detection_method: str,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    evidence: str | None = None,
    dedupe_window_seconds: int = 60,
) -> SecurityAlert | None:
    """
    Insert a new SecurityAlert unless an OPEN alert of the same type and
    source_ip was already raised within `dedupe_window_seconds`.

    Returns the new alert, or None if suppressed as a duplicate.
    """
    cutoff = datetime.utcnow() - timedelta(seconds=dedupe_window_seconds)

    existing = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.alert_type == alert_type,
            SecurityAlert.source_ip == source_ip,
            SecurityAlert.status == AlertStatus.OPEN,
            SecurityAlert.timestamp >= cutoff,
        )
        .first()
    )
    if existing:
        return None

    alert = SecurityAlert(
        alert_type=alert_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        description=description,
        evidence=evidence,
        detection_method=detection_method,
        status=AlertStatus.OPEN,
    )
    db.add(alert)
    db.flush()
    logger.info("Alert raised: %s severity=%s src=%s", alert_type, severity, source_ip)
    return alert
