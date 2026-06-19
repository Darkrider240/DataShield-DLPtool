"""
Alert engine: evaluates incoming DLP events, deduplicates alerts,
broadcasts via WebSocket, and dispatches SMTP email notifications.
"""
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from server.models.alert import Alert
from server.models.employee import Employee
from server.models.event import DLPEvent
from server.config import get_settings

settings = get_settings()


def _determine_severity(event: DLPEvent, employee: Employee) -> str | None:
    """
    Returns severity string or None if no alert should be created.
    """
    if event.risk_level == "HIGH":
        return "CRITICAL" if event.channel in ("EMAIL", "WEBMAIL") else "HIGH"
    if event.risk_level == "MEDIUM" and employee.high_violations_7d >= 3:
        return "HIGH"
    return None


async def evaluate_event(event: DLPEvent, db: AsyncSession, ws_manager=None) -> Alert | None:
    """
    Main entry point: given a freshly ingested event, decide whether to
    raise, escalate, or ignore an alert. Returns the Alert if created/escalated.
    """
    emp_result = await db.execute(select(Employee).where(Employee.id == event.employee_id))
    employee = emp_result.scalar_one_or_none()
    if not employee:
        return None

    # Check employee risk threshold
    if employee.risk_score > 20.0 and not employee.is_flagged:
        employee.is_flagged = True
        employee.flag_reason = "Risk score threshold exceeded"
        employee.flagged_at = datetime.now(timezone.utc)
        await _raise_or_escalate(
            db, employee.id, event.id,
            "Employee risk threshold exceeded",
            f"Employee {employee.email} risk score {employee.risk_score:.1f} exceeded threshold.",
            "CRITICAL", "",
            ws_manager
        )

    severity = _determine_severity(event, employee)
    if not severity:
        return None

    top_pattern = event.pattern_names[0] if event.pattern_names else ""
    title = f"{severity} DLP violation: {top_pattern or event.channel}"
    description = (
        f"Channel: {event.channel} | Action: {event.action_taken} | "
        f"Risk: {event.risk_level} ({event.risk_score:.1f}) | "
        f"Pattern: {top_pattern}"
    )

    alert = await _raise_or_escalate(
        db, event.employee_id, event.id,
        title, description, severity, top_pattern,
        ws_manager
    )
    return alert


async def _raise_or_escalate(
    db: AsyncSession,
    employee_id: str,
    event_id: str | None,
    title: str,
    description: str,
    severity: str,
    top_pattern: str,
    ws_manager=None,
) -> Alert:
    """
    Checks for an existing OPEN alert for the same employee + pattern in the
    last 4 hours. If found, increments escalation_count. Otherwise creates a new Alert.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
    existing_result = await db.execute(
        select(Alert).where(
            and_(
                Alert.employee_id == employee_id,
                Alert.top_pattern == top_pattern,
                Alert.status == "OPEN",
                Alert.created_at >= cutoff,
            )
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.escalation_count += 1
        existing.updated_at = datetime.now(timezone.utc)
        alert = existing
    else:
        alert = Alert(
            employee_id=employee_id,
            event_id=event_id,
            title=title,
            description=description,
            severity=severity,
            status="OPEN",
            top_pattern=top_pattern,
            escalation_count=1,
        )
        db.add(alert)

    await db.flush()

    if ws_manager:
        await ws_manager.broadcast({
            "type": "ALERT",
            "id": alert.id,
            "severity": alert.severity,
            "title": alert.title,
            "employee_id": employee_id,
        })

    await _dispatch_email(alert, severity)
    return alert


async def _dispatch_email(alert: Alert, severity: str):
    """Send an SMTP email if the severity warrants it and recipients are configured."""
    recipients = settings.alert_email_recipient_list
    if not recipients:
        return
    if severity not in ("CRITICAL", "HIGH"):
        return

    subject = f"[DataShield] {severity} Alert: {alert.title}"
    body = (
        f"DataShield Enterprise — Automated Alert Notification\n\n"
        f"Severity : {alert.severity}\n"
        f"Title    : {alert.title}\n"
        f"Detail   : {alert.description}\n"
        f"Alert ID : {alert.id}\n\n"
        f"Please log in to the DataShield dashboard to review and acknowledge this alert."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5) as server:
            if settings.SMTP_USER:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[alert_engine] SMTP dispatch failed: {e}")
