"""
Alert engine: evaluates incoming DLP events, deduplicates alerts,
broadcasts via WebSocket, and dispatches SMTP email notifications
to BOTH the admin and the affected employee.
"""
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from server.models.alert import Alert
from server.models.employee import Employee
from server.models.event import DLPEvent
from server.config import get_settings

settings = get_settings()


def _determine_severity(event: DLPEvent, employee: Employee) -> str | None:
    if event.risk_level == "HIGH":
        return "CRITICAL" if event.channel in ("EMAIL", "WEBMAIL") else "HIGH"
    if event.risk_level == "MEDIUM" and employee.high_violations_7d >= 3:
        return "HIGH"
    return None


async def evaluate_event(event: DLPEvent, db: AsyncSession, ws_manager=None) -> Alert | None:
    emp_result = await db.execute(select(Employee).where(Employee.id == event.employee_id))
    employee = emp_result.scalar_one_or_none()
    if not employee:
        return None

    # Risk threshold flag
    if employee.risk_score > 20.0 and not employee.is_flagged:
        employee.is_flagged = True
        employee.flag_reason = "Risk score threshold exceeded"
        employee.flagged_at = datetime.now(timezone.utc)
        await _raise_or_escalate(
            db, employee, event.id,
            "Employee risk threshold exceeded",
            f"Employee {employee.email} risk score {employee.risk_score:.1f} exceeded threshold of 20.0.",
            "CRITICAL", "", ws_manager
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

    return await _raise_or_escalate(
        db, employee, event.id,
        title, description, severity, top_pattern, ws_manager
    )


async def _raise_or_escalate(
    db: AsyncSession,
    employee: Employee,
    event_id: str | None,
    title: str,
    description: str,
    severity: str,
    top_pattern: str,
    ws_manager=None,
) -> Alert:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
    existing_result = await db.execute(
        select(Alert).where(
            and_(
                Alert.employee_id == employee.id,
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
            employee_id=employee.id,
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
            "employee_id": employee.id,
            "employee_email": employee.email,
        })

    # Send email to BOTH admin and the affected employee
    await _dispatch_email(alert, severity, employee_email=employee.email, employee_name=employee.full_name or employee.email)
    return alert


async def _dispatch_email(alert: Alert, severity: str, employee_email: str = "", employee_name: str = ""):
    """Send SMTP alert to admin recipients AND the affected employee."""
    if severity not in ("CRITICAL", "HIGH"):
        return
    if not settings.SMTP_HOST:
        return

    admin_recipients = settings.alert_email_recipient_list or []

    # Build full recipient list: admin(s) + the employee (avoid duplicates)
    all_recipients = list(admin_recipients)
    if employee_email and employee_email not in all_recipients:
        all_recipients.append(employee_email)

    if not all_recipients:
        return

    is_employee_included = employee_email in all_recipients

    # Admin-facing body
    admin_body = (
        f"DataShield Enterprise — Security Alert\n"
        f"{'='*50}\n\n"
        f"Severity  : {alert.severity}\n"
        f"Title     : {alert.title}\n"
        f"Employee  : {employee_name} <{employee_email}>\n"
        f"Detail    : {alert.description}\n"
        f"Alert ID  : {alert.id}\n\n"
        f"Action required: Log in to the DataShield dashboard to review and acknowledge this alert.\n"
        f"Dashboard : http://localhost:5173"
    )

    # Employee-facing body (less technical, more human)
    employee_body = (
        f"Hi {employee_name or 'there'},\n\n"
        f"DataShield has detected a potential data policy violation on your account.\n\n"
        f"Severity  : {alert.severity}\n"
        f"What      : {alert.title}\n"
        f"Detail    : {alert.description}\n\n"
        f"If this was intentional and authorised, no action is needed.\n"
        f"If you did not perform this action, please contact your IT administrator immediately.\n\n"
        f"— DataShield Security System"
    )

    subject = f"[DataShield] {alert.severity} Alert: {alert.title}"

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5) as server:
            if settings.SMTP_USER:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

            # Send admin email (all admin recipients together)
            if admin_recipients:
                msg = MIMEText(admin_body)
                msg["Subject"] = subject
                msg["From"] = settings.SMTP_FROM
                msg["To"] = ", ".join(admin_recipients)
                server.send_message(msg)

            # Send separate, friendlier email to the employee
            if employee_email and is_employee_included and employee_email not in admin_recipients:
                emp_msg = MIMEText(employee_body)
                emp_msg["Subject"] = f"[DataShield] Security Notice — Action on your account detected"
                emp_msg["From"] = settings.SMTP_FROM
                emp_msg["To"] = employee_email
                server.send_message(emp_msg)

    except Exception as e:
        print(f"[alert_engine] SMTP dispatch failed: {e}")
