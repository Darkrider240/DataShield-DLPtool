"""
Behaviour engine: risk score recalculation and anomaly detection.
Runs on-demand (per new event) and on a 15-minute APScheduler cron.
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from server.models.employee import Employee
from server.models.event import DLPEvent
from server.models.alert import Alert


async def recalculate_risk(employee_id: str, db: AsyncSession) -> float:
    """
    Recomputes the employee risk score based on events in the last 7 days,
    applying volume, time-of-day, and repeat-pattern multipliers.
    """
    now = datetime.now(timezone.utc)
    window_7d = now - timedelta(days=7)
    window_30d = now - timedelta(days=30)

    ev_result = await db.execute(
        select(DLPEvent).where(
            and_(DLPEvent.employee_id == employee_id, DLPEvent.occurred_at >= window_7d)
        )
    )
    events_7d = ev_result.scalars().all()

    high_count = sum(1 for e in events_7d if e.risk_level == "HIGH")
    medium_count = sum(1 for e in events_7d if e.risk_level == "MEDIUM")
    low_count = sum(1 for e in events_7d if e.risk_level == "LOW")

    base_score = (high_count * 4.0) + (medium_count * 1.5) + (low_count * 0.3)

    # Volume multiplier — compare with 30-day average
    count_30d_result = await db.execute(
        select(func.count(DLPEvent.id)).where(
            and_(DLPEvent.employee_id == employee_id, DLPEvent.occurred_at >= window_30d)
        )
    )
    total_30d = count_30d_result.scalar_one() or 0
    daily_avg_30d = total_30d / 30.0
    weekly_expected = daily_avg_30d * 7
    volume_multiplier = 1.5 if (len(events_7d) > weekly_expected * 2 and weekly_expected > 0) else 1.0

    # Time-of-day multiplier — events between 22:00 and 06:00
    off_hours = any(
        e.occurred_at.hour >= 22 or e.occurred_at.hour < 6
        for e in events_7d
    )
    time_multiplier = 1.3 if off_hours else 1.0

    # Repeat-pattern multiplier — same pattern > 3× in last 24h
    window_24h = now - timedelta(hours=24)
    recent = [e for e in events_7d if e.occurred_at >= window_24h]
    pattern_counts: dict[str, int] = {}
    for ev in recent:
        for p in (ev.pattern_names or []):
            pattern_counts[p] = pattern_counts.get(p, 0) + 1
    repeat_multiplier = 1.4 if any(v > 3 for v in pattern_counts.values()) else 1.0

    final_score = base_score * volume_multiplier * time_multiplier * repeat_multiplier

    # Update employee record
    emp_result = await db.execute(select(Employee).where(Employee.id == employee_id))
    emp = emp_result.scalar_one_or_none()
    if emp:
        emp.risk_score = round(final_score, 2)
        emp.high_violations_7d = high_count
        emp.medium_violations_7d = medium_count
        emp.total_events_30d = total_30d
        emp.risk_level = (
            "HIGH" if final_score >= 10.0
            else "MEDIUM" if final_score >= 4.0
            else "LOW" if final_score >= 1.0
            else "CLEAN"
        )
        if final_score >= 10.0 and not emp.is_flagged:
            emp.is_flagged = True
            emp.flag_reason = "Risk score threshold exceeded"
            emp.flagged_at = now
        await db.flush()

    return final_score


async def detect_anomalies(db: AsyncSession, ws_manager=None):
    """
    Periodic anomaly check — run every 15 minutes via APScheduler.
    Creates alerts for unusual behaviour patterns.
    """
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)
    window_30d = now - timedelta(days=30)

    emp_result = await db.execute(select(Employee))
    employees = emp_result.scalars().all()

    for emp in employees:
        # 1. Volume spike: last 24h count > 3× baseline
        count_24h_r = await db.execute(
            select(func.count(DLPEvent.id)).where(
                and_(DLPEvent.employee_id == emp.id, DLPEvent.occurred_at >= window_24h)
            )
        )
        count_24h = count_24h_r.scalar_one() or 0

        count_30d_r = await db.execute(
            select(func.count(DLPEvent.id)).where(
                and_(DLPEvent.employee_id == emp.id, DLPEvent.occurred_at >= window_30d)
            )
        )
        daily_avg = (count_30d_r.scalar_one() or 0) / 30.0

        if daily_avg > 0 and count_24h > daily_avg * 3:
            await _maybe_create_anomaly_alert(
                db, emp.id, None,
                "Unusual volume spike",
                f"Employee {emp.email} had {count_24h} events in 24h (baseline avg {daily_avg:.1f}/day).",
                "HIGH", ws_manager
            )

        # 2. First-ever USB event
        usb_result = await db.execute(
            select(func.count(DLPEvent.id)).where(
                and_(DLPEvent.employee_id == emp.id, DLPEvent.channel == "USB")
            )
        )
        usb_count = usb_result.scalar_one() or 0
        if usb_count == 1:
            ev_r = await db.execute(
                select(DLPEvent).where(
                    and_(DLPEvent.employee_id == emp.id, DLPEvent.channel == "USB")
                ).limit(1)
            )
            first_usb = ev_r.scalar_one_or_none()
            if first_usb:
                await _maybe_create_anomaly_alert(
                    db, emp.id, first_usb.id,
                    "First USB drive event",
                    f"Employee {emp.email} plugged in a USB drive for the first time.",
                    "MEDIUM", ws_manager
                )

        # 3. Rapid bulk scan: > 50 FILE events in < 10 minutes
        window_10m = now - timedelta(minutes=10)
        bulk_r = await db.execute(
            select(func.count(DLPEvent.id)).where(
                and_(
                    DLPEvent.employee_id == emp.id,
                    DLPEvent.channel == "FILE",
                    DLPEvent.occurred_at >= window_10m,
                )
            )
        )
        bulk_count = bulk_r.scalar_one() or 0
        if bulk_count > 50:
            await _maybe_create_anomaly_alert(
                db, emp.id, None,
                "Rapid bulk file scan detected",
                f"Employee {emp.email} scanned {bulk_count} files in the last 10 minutes.",
                "HIGH", ws_manager
            )

    await db.commit()


async def _maybe_create_anomaly_alert(
    db, employee_id, event_id, title, description, severity, ws_manager
):
    from server.services.alert_engine import _raise_or_escalate
    await _raise_or_escalate(db, employee_id, event_id, title, description, severity, "ANOMALY", ws_manager)
