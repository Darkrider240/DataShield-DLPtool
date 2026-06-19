"""Compliance metrics and Gemini-powered executive summary reports."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from server.database import get_db
from server.models.event import DLPEvent
from server.models.employee import Employee
from server.models.alert import Alert
from server.schemas import ComplianceMetricsOut, ExecutiveSummaryOut
from server.middleware.auth_middleware import get_current_user, require_analyst_or_above
from server.config import get_settings
from server.models.user import AdminUser

settings = get_settings()
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/metrics", response_model=ComplianceMetricsOut)
async def compliance_metrics(db: AsyncSession = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total = (await db.execute(select(func.count(DLPEvent.id)).where(DLPEvent.occurred_at >= today))).scalar_one()
    high  = (await db.execute(select(func.count(DLPEvent.id)).where(and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "HIGH")))).scalar_one()
    med   = (await db.execute(select(func.count(DLPEvent.id)).where(and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "MEDIUM")))).scalar_one()
    low   = (await db.execute(select(func.count(DLPEvent.id)).where(and_(DLPEvent.occurred_at >= today, DLPEvent.risk_level == "LOW")))).scalar_one()
    blk   = (await db.execute(select(func.count(DLPEvent.id)).where(and_(DLPEvent.occurred_at >= today, DLPEvent.action_taken == "BLOCK")))).scalar_one()

    flagged   = (await db.execute(select(func.count(Employee.id)).where(Employee.is_flagged == True))).scalar_one()
    open_alts = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "OPEN"))).scalar_one()
    crit_alts = (await db.execute(select(func.count(Alert.id)).where(and_(Alert.status == "OPEN", Alert.severity == "CRITICAL")))).scalar_one()

    # Regulation hit counts (all-time)
    ev_result = await db.execute(select(DLPEvent.regulation_tags))
    reg_counts: dict[str, int] = {}
    for row in ev_result.scalars():
        for tag in (row or []):
            reg_counts[tag] = reg_counts.get(tag, 0) + 1

    return ComplianceMetricsOut(
        total_events=total, high_events=high, medium_events=med, low_events=low,
        blocked_events=blk, flagged_employees=flagged,
        open_alerts=open_alts, critical_alerts=crit_alts,
        regulation_hit_counts=reg_counts,
    )


@router.get("/executive-summary", response_model=ExecutiveSummaryOut, dependencies=[Depends(require_analyst_or_above)])
async def executive_summary(db: AsyncSession = Depends(get_db)):
    metrics = await compliance_metrics.__wrapped__(db) if hasattr(compliance_metrics, "__wrapped__") else None
    # Build a context prompt for Gemini
    context = (
        f"DataShield DLP Summary — Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"Today: {0} total events, HIGH violations, MEDIUM violations, Blocked sends.\n"
        f"Open Alerts, Flagged Employees.\n"
        "Provide a concise executive summary of the DLP posture and top 3 recommended remediation actions."
    )

    summary_text = "Gemini API key not configured — summary unavailable."
    if settings.GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.GEMINI_API_KEY)
            model = genai.GenerativeModel("gemini-2.0-flash")
            response = model.generate_content(context)
            summary_text = response.text
        except Exception as e:
            summary_text = f"Gemini API error: {e}"

    return ExecutiveSummaryOut(summary=summary_text, generated_at=datetime.now(timezone.utc))
